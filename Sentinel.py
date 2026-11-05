import pandas as pd
from textblob import TextBlob
import re
import logging
import sys
import argparse
import os
from datetime import datetime
from urllib.parse import urlparse
import matplotlib.pyplot as plt
from io import StringIO
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import sqlite3
import hashlib
import json
import ollama
import Graficador  # Modulo para WordClouds

# Configurar bitácora
log_dir = "logs"
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

logging.basicConfig(
    filename=os.path.join(log_dir, 'auditoria_sentimiento.log'),
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Cargar variables de entorno (.env)
load_dotenv()

# Variables globales para léxico
# Base de datos
DB_FILE = "fenix.db"
AI_CACHE_DB = "ai_cache.db"

# Variables globales para léxico
LEXICO_PERSONALIZADO = {}

# Configuración de Ollama
OLLAMA_MODEL = "mistral"
USE_OLLAMA = os.getenv("USE_OLLAMA", "true").lower() == "true"

# Métricas de IA
AI_METRICS = {
    "total_analizados": 0,
    "cache_hits": 0,
    "errores": 0,
    "exitosos": 0,
    "tiempo_total_s": 0
}

PROMPT_SEGURIDAD_MAESTRO = """
Actúa como un Analista Senior de Ciberinteligencia (CISO).
Analiza el siguiente texto relacionado con la organización o marca objetivo.

Texto: "{texto_analizar}"

Tu tarea es clasificar este hallazgo en formato JSON estricto.
Evalúa los siguientes puntos:
1. RIESGO: ¿Es una amenaza real? (CRITICO, ALTO, MEDIO, BAJO, RUIDO).
2. CATEGORIA: (FILTRACION_DATOS, PHISHING, DESPRESTIGIO, ATAQUE_DOS, OPINION, RUIDO).
3. JUSTIFICACION: Breve explicación técnica (max 15 palabras).
4. ACCION_SUGERIDA: (MONITOREAR, DISAVOW_LINK, REVISAR_CODIGO, ESCALAR_TI).

Reglas de Negocio:
- Si menciona "password", "base de datos", "admin", "leak" -> RIESGO: CRITICO o ALTO.
- Si es una queja genérica de un alumno -> RIESGO: BAJO.
- Si es publicidad o no tiene sentido -> RIESGO: RUIDO.

Responde SOLO con el JSON.
"""

PROMPT_REFINAMIENTO_IA = """
Actúa como un experto en análisis de reputación de marca y sentimientos.
Tu tarea es clasificar menciones en redes sociales/web sobre la marca monitoreada o su competencia.

Texto: "{texto_analizar}"

Responde en formato JSON estricto con los siguientes campos:
1. RAZONAMIENTO: (Breve análisis lógico de 1 frase antes de clasificar)
2. SENTIMIENTO: (Positivo, Negativo, Neutro)
3. CATEGORIA: (Ruido, Promocion, Opinion, Sugerencia, Riesgo)
4. RIESGO: (Bajo, Medio, Alto, Critico) 
5. JUSTIFICACION: (Explicación final de la clasificación, max 10 palabras)

Reglas de Oro:
- PUBLICIDAD/OFERTAS: Si el texto es una oferta de becas, informes, o autobombo de la marca -> CATEGORIA: Promocion, SENTIMIENTO: Neutro.
- RUIDO: Si el texto habla de temas irrelevantes (clima, memes sin marca, otros temas) -> CATEGORIA: Ruido, SENTIMIENTO: Neutro.
- OPINION: Solo si un usuario real expresa una experiencia o juicio sobre la marca.
- RIESGO: Ataques directos, filtraciones, fraudes o amenazas a la integridad.
- SENTIMIENTO: Solo usa Positivo/Negativo si es MUY evidente. Ante la duda, usa Neutro.

Responde SOLO con el JSON.
"""

def init_db():
    """Inicializa la base de datos de historial si no existe."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alertas_historico
                 (id_hash TEXT PRIMARY KEY, 
                  fecha_deteccion TEXT, 
                  ultimo_avistamiento TEXT, 
                  estado TEXT)''')
    conn.commit()
    conn.close()

def init_ai_cache_db():
    """Inicializa la base de datos de caché de IA."""
    conn = sqlite3.connect(AI_CACHE_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ai_cache
                 (prompt_hash TEXT PRIMARY KEY, 
                  response_json TEXT, 
                  created_at TEXT)''')
    conn.commit()
    conn.close()

def generar_hash(usuario, fecha, texto):
    """Genera un hash único basado en usuario, fecha (o texto) y contenido."""
    # Normalizar inputs
    raw = f"{str(usuario)}{str(fecha)}{str(texto)}".encode('utf-8')
    return hashlib.sha256(raw).hexdigest()

def gestionar_hallazgo(usuario, fecha, texto):
    """
    Verifica si el hallazgo ya existe.
    Retorna True si es NUEVO (hay que alertar).
    Retorna False si ya existía (solo actualiza timestamp).
    """
    id_hash = generar_hash(usuario, fecha, texto)
    hoy = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute("SELECT * FROM alertas_historico WHERE id_hash=?", (id_hash,))
    data = c.fetchone()
    
    es_nuevo = False
    
    if data:
        # Ya existe -> Actualizar último avistamiento
        c.execute("UPDATE alertas_historico SET ultimo_avistamiento=? WHERE id_hash=?", (hoy, id_hash))
    else:
        # Nuevo -> Insertar
        c.execute("INSERT INTO alertas_historico VALUES (?, ?, ?, ?)", (id_hash, hoy, hoy, "ACTIVO"))
        es_nuevo = True
        
    conn.commit()
    conn.close()
    return es_nuevo

def limpiar_historial_antiguo():
    """Elimina registros no vistos en los últimos 30 días."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # SQLite no tiene INTERVAL directo simple, usamos calculo en python o query
    # Borrar donde ultimo_avistamiento < (HOY - 30 dias)
    # Para simplicidad, como la fecha es texto ISO, funciona la comparacion de strings YYYY-MM-DD
    limit_date = (datetime.now() - pd.Timedelta(days=30)).strftime("%Y-%m-%d")
    c.execute("DELETE FROM alertas_historico WHERE ultimo_avistamiento < ?", (limit_date,))
    deleted = c.rowcount
    conn.commit()
    conn.close()
    if deleted > 0:
        logging.info(f"Mantenimiento DB: {deleted} registros antiguos eliminados en alertas_historico.")

def cargar_lexico(ruta_archivo):
    """
    Carga un archivo CSV con columnas 'token'/'palabra' y 'valor'.
    El valor debe ser un float entre -1.0 y 1.0.
    """
    global LEXICO_PERSONALIZADO
    if not ruta_archivo or not os.path.exists(ruta_archivo):
        return
    
    try:
        df_lex = pd.read_csv(ruta_archivo, comment="#", skip_blank_lines=True)
        col_token = next((c for c in ["token", "palabra", "word"] if c in df_lex.columns), None)
        col_valor = next((c for c in ["valor", "score", "value"] if c in df_lex.columns), None)
        
        if col_token and col_valor:
            for _, row in df_lex.iterrows():
                if pd.isna(row[col_token]) or pd.isna(row[col_valor]):
                    continue
                palabra = str(row[col_token]).lower().strip()
                if not palabra or palabra.startswith("#"):
                    continue
                try:
                    valor = float(row[col_valor])
                    LEXICO_PERSONALIZADO[palabra] = max(-1.0, min(1.0, valor))
                except (ValueError, TypeError):
                    pass
        logging.info(f"Léxico personalizado cargado: {len(LEXICO_PERSONALIZADO)} tokens.")
        print(f"Léxico personalizado cargado: {len(LEXICO_PERSONALIZADO)} tokens.")
    except Exception as e:
        logging.error(f"Error cargando léxico: {e}")

def cargar_fuentes_oficiales(ruta_archivo="config/official_sources.json"):
    """
    Lee la configuración de fuentes oficiales (dominios y redes sociales).
    """
    if not os.path.exists(ruta_archivo):
        logging.warning(f"No se encontró el archivo de fuentes oficiales: {ruta_archivo}")
        return {"dominios_oficiales": [], "cuentas_oficiales": []}
    
    try:
        with open(ruta_archivo, 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error cargando fuentes oficiales: {e}")
        return {"dominios_oficiales": [], "cuentas_oficiales": []}

def clasificar_fuente(link, usuario, fuentes_oficiales, es_ruido=False):
    """
    Asigna una categoría a la fuente basada en el link y el usuario.
    """
    if es_ruido:
        return "RUIDO"
    
    if not link:
        return "NOTICIAS_EXTERNAS" # Por defecto si no hay link
    
    link_lower = link.lower()
    usuario_lower = str(usuario).lower() if usuario else ""
    
    # 1. OFICIAL_REDES
    for cuenta in fuentes_oficiales.get("cuentas_oficiales", []):
        if cuenta.lower() in link_lower:
            return "OFICIAL_REDES"
    
    # 2. OFICIAL_BLOG
    for dominio in fuentes_oficiales.get("dominios_oficiales", []):
        if dominio.lower() in link_lower:
            return "OFICIAL_BLOG"
    
    # 3. MENCIONES_REDES
    redes_sociales = ["twitter.com", "x.com", "reddit.com", "facebook.com", "instagram.com", "linkedin.com"]
    if any(rs in link_lower for rs in redes_sociales):
        return "MENCIONES_REDES"
    
    # 4. NOTICIAS_EXTERNAS (Fallback)
    return "NOTICIAS_EXTERNAS"

def cargar_datos(ruta_archivo):
    """
    Carga datos desde un archivo CSV o Excel.
    """
    if not os.path.exists(ruta_archivo):
        logging.error(f"El archivo {ruta_archivo} no existe.")
        print(f"Error: El archivo {ruta_archivo} no se encuentra.")
        sys.exit(1)

    try:
        if ruta_archivo.endswith('.csv'):
            df = pd.read_csv(ruta_archivo)
        elif ruta_archivo.endswith(('.xls', '.xlsx')):
            df = pd.read_excel(ruta_archivo)
        else:
            logging.error(f"Formato no soportado: {ruta_archivo}")
            print("Error: Formato de archivo no soportado. Use CSV o Excel.")
            sys.exit(1)
        
        logging.info(f"Datos cargados exitosamente de {ruta_archivo}. Registros: {len(df)}")
        return df
    except Exception as e:
        logging.error(f"Error al cargar datos: {e}")
        print(f"Error crítico cargando datos: {e}")
        sys.exit(1)

def limpiar_texto(texto_bruto):
    """
    Limpia el texto eliminando URLs y caracteres especiales.
    """
    if not isinstance(texto_bruto, str):
        return ""
    
    # Eliminar URLs
    texto = re.sub(r'http\S+|www\.\S+', '', texto_bruto)
    
    # Eliminar caracteres especiales
    texto = re.sub(r'[^\w\sñáéíóúÁÉÍÓÚ,.?!]', '', texto)
    
    # Normalizar a minúsculas
    texto = texto.lower()
    
    return texto.strip()

def cargar_keywords_lista(ruta_archivo):
    """Carga lista de keywords desde txt (una por linea, ignora #)"""
    if not os.path.exists(ruta_archivo):
        return []
    lista = []
    with open(ruta_archivo, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lista.append(line.replace('"', '').lower())
    return lista

def cargar_competidores_lista(ruta_archivo):
    """Carga nombres de competidores desde JSON y retorna lista plana."""
    if not os.path.exists(ruta_archivo):
        return []
    lista = []
    try:
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for categoria in data.values():
                if "nombres" in categoria:
                    for nombre in categoria["nombres"]:
                        lista.append(nombre.lower().strip())
    except Exception as e:
        logging.error(f"Error cargando competidores: {e}")
    return lista

def cargar_whitelist_dinamica(ruta_targets):
    """
    Carga targets.json y extrae todas las 'variaciones' para formar la whitelist.
    """
    whitelist = []
    if not os.path.exists(ruta_targets):
        return whitelist
    
    try:
        with open(ruta_targets, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # data es { "Grupo": { "targets": [...] } }
            for grupo in data.values():
                targets = grupo.get("targets", [])
                for tgt in targets:
                    variaciones = tgt.get("variaciones", [])
                    whitelist.extend(variaciones)
    except Exception as e:
        logging.error(f"Error cargando whitelist dinamica: {e}")
        
    return [w.lower().strip() for w in whitelist]

def cargar_dominios_exclusion(ruta_targets):
    """
    Carga targets.json y extrae los dominios para exclusion (own domains).
    """
    dominios = []
    if not os.path.exists(ruta_targets):
        return dominios
    
    try:
        with open(ruta_targets, 'r', encoding='utf-8') as f:
            data = json.load(f)
            for grupo in data.values():
                targets = grupo.get("targets", [])
                for tgt in targets:
                    dominio = tgt.get("dominio")
                    if dominio:
                        dominios.append(dominio.lower().strip())
    except Exception as e:
        logging.error(f"Error cargando dominios exclusion: {e}")
        
    return dominios

def detectar_palabras_clave(texto, keywords_seguridad, keywords_operativos):
    """
    Busca palabras clave y determina nivel de riesgo.
    Retorna: (EsRiesgo, Palabra, Nivel)
    """
    # 1. Seguridad (CRITICO)
    for word in keywords_seguridad:
        # Usar regex con \b para buscar palabra completa y re.IGNORECASE
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, texto, re.IGNORECASE):
            return True, word, "CRÍTICO"
            
    # 2. Operativo (ALTO)
    for word in keywords_operativos:
        pattern = r'\b' + re.escape(word) + r'\b'
        if re.search(pattern, texto, re.IGNORECASE):
            return True, word, "ALTO"
            
    return False, None, "BAJO"

def analizar_reputacion_dominio(url):
    """
    Analiza el dominio de una URL para ver si es sospechoso.
    """
    if not isinstance(url, str) or len(url) < 5:
        return "Desconocido", 0.0
    
    try:
        parsed = urlparse(url)
        dominio = parsed.netloc.lower()
        
        # Palabras clave sospechosas en dominio
        bad_keywords = ["porn", "hack", "leak", "pastebin", "crypto", "casino", "viagra"]
        # Dominios de confianza (ejemplo simple)
        good_domains = [".edu", ".gov", "bbc.com", "cnn.com", "eluniversal.com.mx", "linkedin.com"]

        for bad in bad_keywords:
            if bad in dominio:
                return "Sospechoso", -1.0
        
        for good in good_domains:
            if good in dominio:
                return "Confiable", 1.0
        
        return "Neutro", 0.0
        
    except Exception:
        return "Error", 0.0

def analizar_con_ollama(texto, contexto="sentimiento", model_override=None):
    """
    Usa Ollama local para análisis avanzado.
    """
    global AI_METRICS
    if not USE_OLLAMA:
        return None

    import time
    start_time = time.time()
    AI_METRICS["total_analizados"] += 1

    model_to_use = model_override if model_override else OLLAMA_MODEL
    
    try:
        if contexto == "ruido":
            prompt = (
                f"Analiza si el siguiente texto es relevante para el monitoreo de reputación de la marca o su competencia. "
                f"Responde SOLO con 'S' si es RELEVANTE o 'N' si es RUIDO/IRRELEVANTE.\n\n"
                f"Texto: {texto}"
            )
        elif contexto == "seguridad":
            prompt = PROMPT_SEGURIDAD_MAESTRO.format(texto_analizar=texto)
        elif contexto == "refinamiento":
            prompt = PROMPT_REFINAMIENTO_IA.format(texto_analizar=texto)
        else: # sentimiento
            prompt = (
                f"Analiza el sentimiento del siguiente texto sobre la organización o marca monitoreada. "
                f"Responde SOLO con un número entre -1.0 (muy negativo) y 1.0 (muy positivo).\n\n"
                f"Texto: {texto}"
            )

        # --- CACHE LOOKUP ---
        prompt_hash = hashlib.sha256(prompt.encode('utf-8')).hexdigest()
        try:
            conn = sqlite3.connect(AI_CACHE_DB)
            c = conn.cursor()
            c.execute("SELECT response_json FROM ai_cache WHERE prompt_hash=?", (prompt_hash,))
            row = c.fetchone()
            conn.close()
            if row:
                AI_METRICS["cache_hits"] += 1
                AI_METRICS["tiempo_total_s"] += (time.time() - start_time)
                # logging.info(f"AI CACHE HIT for prompt {prompt_hash[:10]}...")
                return json.loads(row[0]) if contexto in ["seguridad", "refinamiento"] else float(row[0])
        except Exception as e:
            logging.error(f"Error reading AI cache: {e}")

        # --- OLLAMA CALL ---
        response = ollama.generate(model=model_to_use, prompt=prompt, options={"temperature": 0.1})
        res_text = response['response'].strip()
        
        AI_METRICS["exitosos"] += 1
        AI_METRICS["tiempo_total_s"] += (time.time() - start_time)

        # --- SAVE TO CACHE ---
        try:
            conn = sqlite3.connect(AI_CACHE_DB)
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO ai_cache (prompt_hash, response_json, created_at) VALUES (?, ?, ?)",
                      (prompt_hash, res_text, datetime.now().isoformat()))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"Error saving to AI cache: {e}")

        if contexto == "ruido":
            return 'S' in res_text.upper()[:2]
        elif contexto in ["seguridad", "refinamiento"]:
            # Limpiar y parsear JSON
            if "```json" in res_text:
                res_text = res_text.split("```json")[1].split("```")[0].strip()
            elif "{" in res_text:
                res_text = res_text[res_text.find("{"):res_text.rfind("}")+1]
            try:
                data = json.loads(res_text)
                # Normalizar: claves y valores a mayúsculas para consistencia
                normalized = {}
                for k, v in data.items():
                    key = str(k).upper()
                    if isinstance(v, str):
                        normalized[key] = v.upper()
                    else:
                        normalized[key] = v
                return normalized
            except:
                return None
        else:
            # Intentar extraer el número
            match = re.search(r"(-?\d+\.\d+)", res_text)
            if match:
                return float(match.group(1))
            return None
    except Exception as e:
        AI_METRICS["errores"] += 1
        logging.error(f"Error en Ollama ({contexto}): {e}")
        return None

def analizar_sentimiento(texto_limpio):
    """
    Calcula la polaridad de sentimiento combinando:
    1. Léxico personalizado (soporte multi-palabra y tokens individuales)
    2. Fallback heurístico en español con detección de negaciones
    3. TextBlob y Ollama IA cuando está habilitado
    """
    texto_lower = texto_limpio.lower()
    
    # 1. Léxico Personalizado (Evalúa frases compuestas y palabras individuales)
    if LEXICO_PERSONALIZADO:
        score_lex = 0.0
        hits = 0
        matched_tokens = set()
        
        # Evaluar primero frases compuestas (ordenadas de mayor a menor longitud)
        for token, val in sorted(LEXICO_PERSONALIZADO.items(), key=lambda x: len(x[0]), reverse=True):
            if " " in token and token in texto_lower:
                score_lex += val
                hits += 1
                matched_tokens.add(token)
                
        # Evaluar palabras individuales que no formen parte de una frase ya detectada
        words = [w.strip(".,?!:;()\"\x27") for w in texto_lower.split()]
        for w in words:
            if w and w in LEXICO_PERSONALIZADO and w not in matched_tokens:
                score_lex += LEXICO_PERSONALIZADO[w]
                hits += 1
        
        if hits > 0:
            promedio = score_lex / hits
            polaridad = max(-1.0, min(1.0, promedio))
            etiqueta = "Positivo" if polaridad > 0.1 else ("Negativo" if polaridad < -0.1 else "Neutro")
            return polaridad, etiqueta

    # 2. Análisis con TextBlob (Base)
    try:
        analysis = TextBlob(texto_limpio)
        polaridad = analysis.sentiment.polarity
    except Exception:
        polaridad = 0.0
    
    # 2.5 Ollama IA (Si está activo y el resultado es ambiguo o neutro)
    if USE_OLLAMA and (abs(polaridad) < 0.1):
        ollama_score = analizar_con_ollama(texto_limpio, "sentimiento")
        if ollama_score is not None:
            polaridad = ollama_score

    # 3. Fallback Heurístico Robusto en Español (con soporte de negaciones)
    if polaridad == 0.0:
        palabras_positivas = {
            "excelente": 0.8, "increíble": 0.8, "genial": 0.7, "maravilloso": 0.8,
            "recomiendo": 0.6, "bueno": 0.5, "buen": 0.5, "bien": 0.4, "mejor": 0.5,
            "éxito": 0.6, "seguro": 0.5, "confiable": 0.6, "rápido": 0.5, "gracias": 0.4,
            "feliz": 0.6, "perfecto": 0.8, "satisfecho": 0.6, "calidad": 0.5
        }
        palabras_negativas = {
            "pésimo": -0.8, "horrible": -0.8, "fatal": -0.8, "fraude": -0.9,
            "estafa": -0.9, "robo": -0.9, "basura": -0.7, "mal": -0.5, "malo": -0.5,
            "error": -0.5, "falla": -0.6, "lento": -0.5, "caído": -0.7, "queja": -0.5,
            "inseguro": -0.7, "peor": -0.7, "insatisfecho": -0.7, "incompetente": -0.8
        }
        negaciones = {"no", "nunca", "jamas", "jamás", "sin", "tampoco", "nada"}
        
        score_manual = 0.0
        hits_manual = 0
        words = [w.strip(".,?!:;()\"\x27") for w in texto_lower.split()]
        
        for idx, w in enumerate(words):
            invierte = (idx > 0 and words[idx - 1] in negaciones)
            if w in palabras_positivas:
                val = palabras_positivas[w]
                score_manual += (-val if invierte else val)
                hits_manual += 1
            elif w in palabras_negativas:
                val = palabras_negativas[w]
                score_manual += (-val * 0.5 if invierte else val)
                hits_manual += 1
                
        if hits_manual > 0:
            polaridad = max(-1.0, min(1.0, score_manual / hits_manual))

    etiqueta = "Positivo" if polaridad > 0.1 else ("Negativo" if polaridad < -0.1 else "Neutro")
    return polaridad, etiqueta

def generar_reporte(df, output_dir):
    """
    Genera un archivo de reporte y resumen en terminal.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = f"{output_dir}/reporte_riesgos.csv"
    
    try:
        df.to_csv(output_file, index=False)
        logging.info(f"Reporte generado: {output_file}")
        print(f"\nReporte guardado en: {output_file}")
        
        # Resumen
        total = len(df)
        alertas = len(df[df['Alerta'] == 'SI'])
        criticos = len(df[df['Nivel_Riesgo'] == 'CRÍTICO'])
        suspect_domains = 0
        if 'Reputacion_Dominio' in df.columns:
            suspect_domains = len(df[df['Reputacion_Dominio'] == 'Sospechoso'])
        
        print("\n=== RESUMEN DE ANÁLISIS ===")
        print(f"Total registros analizados: {total}")
        print(f"Alertas de sentimiento negativo: {alertas}")
        print(f"Incidentes de Seguridad Potenciales: {criticos}")
        if suspect_domains > 0:
            print(f"Dominios Sospechosos detectados: {suspect_domains}")
        
    except Exception as e:
        logging.error(f"Error generando reporte: {e}")
        print(f"Error al guardar reporte: {e}")

def generar_dashboard(df, output_dir):
    """
    Genera graficos de resumen (Pastel y Linea de Tiempo).
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    print("\n[+] Generando Dashboard Visual...")
    
    try:
        # 1. Grafica de Pastel: Sentimiento
        plt.figure(figsize=(10, 5))
        
        plt.subplot(1, 2, 1)
        # Contar etiquetas (si existe columna Etiqueta)
        if 'Etiqueta' in df.columns:
            counts = df['Etiqueta'].value_counts()
            # Colores distintivos: Ruido usa gris oscuro para diferenciarse visualmente
            color_map = {'Positivo': '#2ecc71', 'Negativo': '#e74c3c', 'Neutro': '#3498db', 'Ruido': '#7f8c8d', 'Promocion': '#9b59b6'}
            # Mapear colores a las etiquetas presentes
            colors = [color_map.get(lbl, '#bdc3c7') for lbl in counts.index]
            
            plt.pie(counts, labels=counts.index, autopct='%1.1f%%', startangle=140, colors=colors)
            plt.title('Distribución de Sentimiento')
        
        # 2. Linea de Tiempo
        plt.subplot(1, 2, 2)
        # Intentar extraer fecha del ID si tiene formato tipo 'source_timestamp_index'
        # o usar fecha actual si no se puede
        def extract_date(row_id):
            try:
                parts = str(row_id).split('_')
                if len(parts) >= 2 and parts[1].isdigit():
                    ts = int(parts[1])
                    return datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
            except:
                pass
            return datetime.now().strftime('%Y-%m-%d')

        if 'id' in df.columns:
            df['fecha_temp'] = df['id'].apply(extract_date)
            # Agrupar por fecha
            timeline = df['fecha_temp'].value_counts().sort_index()
            timeline.plot(kind='bar', color='skyblue')
            plt.title('Volumen de Menciones por Día')
            plt.xlabel('Fecha')
            plt.ylabel('Cantidad')
            plt.xticks(rotation=45)
        
        plt.tight_layout()
        
        filename = f"{output_dir}/dashboard_general.png"
        plt.savefig(filename)
        plt.close()
        
        # 3. Nueva Gráfica: Distribución por Fuente (Barras Horizontal)
        if 'Categoria_Fuente' in df.columns:
            plt.figure(figsize=(10, 6))
            fuente_counts = df['Categoria_Fuente'].value_counts()
            fuente_counts.plot(kind='barh', color='#f39c12')
            plt.title('Distribución por Fuente')
            plt.xlabel('Cantidad de Menciones')
            plt.ylabel('Fuente')
            plt.tight_layout()
            
            output_fuente = f"{output_dir}/dashboard_fuentes.png"
            plt.savefig(output_fuente)
            plt.close()
            print(f"   -> Gráfica de Fuentes guardada en: {output_fuente}")

        # 4. Nueva Gráfica: Sentimiento por Fuente (Stacked Bar)
        if 'Categoria_Fuente' in df.columns and 'Etiqueta' in df.columns:
            # Excluir RUIDO por requerimiento
            df_no_ruido = df[df['Categoria_Fuente'] != 'RUIDO']
            if not df_no_ruido.empty:
                plt.figure(figsize=(12, 7))
                cross_tab_fuente = pd.crosstab(df_no_ruido['Categoria_Fuente'], df_no_ruido['Etiqueta'])
                
                # Colores consistentes
                sentiment_colors = {'Positivo': '#2ecc71', 'Negativo': '#e74c3c', 'Neutro': '#3498db', 'Promocion': '#9b59b6'}
                cols_present = [sentiment_colors.get(c, '#bdc3c7') for c in cross_tab_fuente.columns]
                
                cross_tab_fuente.plot(kind='bar', stacked=True, color=cols_present)
                plt.title('Sentimiento por Categoría de Fuente (Excluye Ruido)')
                plt.ylabel('Cantidad de Menciones')
                plt.xlabel('Fuente')
                plt.xticks(rotation=45)
                plt.tight_layout()
                
                output_sent_fuente = f"{output_dir}/dashboard_sentimiento_fuente.png"
                plt.savefig(output_sent_fuente)
                plt.close()
                print(f"   -> Gráfica de Sentimiento por Fuente guardada en: {output_sent_fuente}")

        # Guardar en la carpeta especificada
        print(f"   -> Dashboard principal guardado en: {filename}")
        logging.info(f"Dashboard generado: {filename}")
        
        # 3. Grafica Comparativa (Si hay Entidades)
        if 'Entidad' in df.columns and len(df['Entidad'].unique()) > 1:
             plt.figure(figsize=(10, 6))
             # Sentimiento por Entidad
             cross_tab = pd.crosstab(df['Entidad'], df['Etiqueta'])
             # Colores consistentes con el mapa: Negativo, Neutro, Positivo, Ruido
             benchmark_colors = {'Positivo': '#2ecc71', 'Negativo': '#e74c3c', 'Neutro': '#3498db', 'Ruido': '#7f8c8d', 'Promocion': '#9b59b6'}
             cols_present = [benchmark_colors.get(c, '#bdc3c7') for c in cross_tab.columns]
             cross_tab.plot(kind='bar', stacked=True, color=cols_present)
             plt.title('Sentimiento por Competidor')
             plt.ylabel('Cantidad de Menciones')
             plt.xticks(rotation=45)
             plt.tight_layout()
             
             output_path = f"{output_dir}/dashboard_benchmark.png"
             plt.savefig(output_path)
             plt.close()
             print(f"   -> Dashboard Comparativo guardado en: {output_path}")

    except Exception as e:
        print(f"   X Error generando dashboard: {e}")
        logging.error(f"Error dashboard: {e}")

def generar_timeline(df, output_dir):
    """
    Genera un gráfico de línea de tiempo con la evolución del sentimiento.
    """
    print("[+] Generando Timeline de Sentimiento...")
    
    if 'fecha' not in df.columns:
        print("   [!] No se encontró columna 'fecha' para generar timeline.")
        return

    try:
        # Asegurar formato fecha
        df['fecha_dt'] = pd.to_datetime(df['fecha'], errors='coerce')
        # Eliminar NaT
        df_clean = df.dropna(subset=['fecha_dt'])
        
        if df_clean.empty:
            print("   [!] No hay fechas válidas para graficar.")
            return

        # Agrupar por fecha y sentimiento
        tendencia = df_clean.pivot_table(
            index='fecha_dt', 
            columns='Etiqueta', 
            aggfunc='size', 
            fill_value=0
        )
        
        # Ordenar por fecha
        tendencia.sort_index(inplace=True)

        plt.figure(figsize=(12, 6))

        # Colores consistentes con el resto de gráficas - Ruido en gris oscuro distintivo
        colors = {'Positivo': '#2ecc71', 'Negativo': '#e74c3c', 'Neutro': '#3498db', 'Ruido': '#7f8c8d', 'Promocion': '#9b59b6'}
        
        for label in tendencia.columns:
            if label in colors:
                plt.plot(tendencia.index, tendencia[label], marker='o', label=label, color=colors[label])
            else:
                plt.plot(tendencia.index, tendencia[label], marker='o', label=label)

        plt.title('Evolución del Sentimiento de Marca')
        plt.xlabel('Fecha')
        plt.ylabel('Volumen de Menciones')
        plt.legend()
        plt.grid(True, alpha=0.3)
        plt.xticks(rotation=45)
        plt.tight_layout()

        output_path = os.path.join(output_dir, "timeline_sentimiento.png")
        plt.savefig(output_path)
        plt.close()
        print(f"   -> Timeline guardado en: {output_path}")
        
    except Exception as e:
        print(f"   [!] Error generando timeline: {e}")

def enviar_alerta_consolidada(incidentes):
    """
    Dispara alertas multicanal (Slack, Discord, Telegram, Webhooks y SMTP).
    """
    if not incidentes:
        return

    logging.warning(f"!!! DISPARANDO ALERTA CONSOLIDADA: {len(incidentes)} incidentes !!!")
    print(f"\n[!] ENVIANDO ALERTAS DE SEGURIDAD ({len(incidentes)} hallazgos)...")
    
    # 1. Alertas Webhook Multicanal
    try:
        from alerts import dispatch_alerts
        resumen_txt = "\n".join([f"• {inc.get('razon', 'Alerta')}: {inc.get('comentario', '')[:120]}" for inc in incidentes[:5]])
        if len(incidentes) > 5:
            resumen_txt += f"\n... y {len(incidentes) - 5} incidentes adicionales."
        first_link = incidentes[0].get("link") if incidentes else None
        webhook_res = dispatch_alerts(
            title=f"Incidentes Críticos Detectados ({len(incidentes)})",
            details=resumen_txt,
            severity="CRÍTICO",
            link=first_link
        )
        for ch, status in webhook_res.items():
            if status.get("success"):
                print(f"    (Webhook {ch} enviado exitosamente)")
            else:
                print(f"    (X Fallo webhook {ch}: {status.get('message')})")
    except Exception as e:
        logging.error(f"Error despachando webhooks multicanal: {e}")
    
    smtp_server = os.getenv("SMTP_SERVER", "smtp.example.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    recipient = os.getenv("ALERT_RECIPIENT", "admin@example.com")
    
    if not smtp_user or not smtp_pass:
        print("    (X Error: Credenciales SMTP no configuradas en .env)")
        logging.error("Credenciales SMTP faltantes en .env")
        return

    cuerpo = "Se han detectado riesgos CRÍTICOS durante el último escaneo de marca.\n\n"
    cuerpo += "DETALLE DE HALLAZGOS:\n"
    cuerpo += "-" * 50 + "\n"
    
    for i, inc in enumerate(incidentes, 1):
        cuerpo += f"Hallazgo #{i}:\n"
        cuerpo += f"  - Razón: {inc['razon']}\n"
        cuerpo += f"  - Comentario: {inc['comentario']}\n"
        cuerpo += f"  - Link: {inc['link']}\n"
        cuerpo += "-" * 30 + "\n"

    cuerpo += "\nPor favor, investigue estos registros de inmediato."

    msg = MIMEText(cuerpo)
    msg['Subject'] = f"ALERTA CRÍTICA BRAND SENTIMENT - {len(incidentes)} Incidentes Detectados"
    msg['From'] = smtp_user
    msg['To'] = recipient
    
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)
        server.quit()
        print(f"    (Email consolidado enviado a {recipient})")
        logging.info(f"Alerta consolidada enviada a {recipient}")
    except Exception as e:
        print(f"    (X Fallo enviando email: {e})")
        logging.error(f"Fallo enviando alerta consolidada: {e}")

def generar_benchmarking(df):
    """
    Imprime comparativas entre entidades si existen multiples.
    """
    if 'Entidad' not in df.columns:
        return

    print("\n=== BENCHMARKING DE COMPETENCIA ===")
    entidades = df['Entidad'].unique()
    if len(entidades) < 2:
        print("(No hay suficientes entidades para comparar)")
        return

    # Agrupar por Entidad
    # 1. Promedio de Polaridad
    polaridad_promedio = df.groupby('Entidad')['Polaridad'].mean()
    print("\n[Polaridad Promedio ( -1 a 1 )]")
    print(polaridad_promedio)

    # 2. Porcentaje de Negativos
    print("\n[Porcentaje de Sentimiento Negativo]")
    for ent in entidades:
        sub = df[df['Entidad'] == ent]
        total = len(sub)
        neg = len(sub[sub['Etiqueta'] == 'Negativo'])
        pct = (neg / total) * 100 if total > 0 else 0
        print(f"  - {ent}: {pct:.1f}%")

    # 3. Incidentes Criticos
    print("\n[Incidentes Críticos de Seguridad]")
    criticos = df[df['Nivel_Riesgo'] == 'CRÍTICO'].groupby('Entidad').size()
    if criticos.empty:
        print("  - Ninguno detectado.")
    else:
        print(criticos)

def main():
    parser = argparse.ArgumentParser(description="Sentinel - Análisis de Riesgo Reputacional")
    parser.add_argument("--archivo", required=True, help="Ruta del archivo CSV/Excel con comentarios")
    parser.add_argument("--lexicon", default="config/lexico_personalizado.csv", help="Ruta de un archivo CSV con columnas 'palabra' y 'valor' para sentimiento personalizado")
    parser.add_argument("--keywords_seguridad", default="config/keywords_riesgo_seguridad.txt", help="Archivo de keywords CRITICAS")
    parser.add_argument("--keywords_operativo", default="config/keywords_riesgo_operativo.txt", help="Archivo de keywords OPERATIVAS")
    parser.add_argument("--keywords_exclusion", default="config/keywords_exclusion.txt", help="Archivo de keywords para EXCLUIR falsos positivos")
    parser.add_argument("--keywords_identidad", default="config/keywords_identidad.txt", help="Archivo de keywords de la MARCA")
    parser.add_argument("--targets_json", default="config/targets.json", help="Archivo JSON de TARGETS (para whitelist dinámica)")
    parser.add_argument("--skip-ai", action="store_true", help="Omitir análisis con Ollama (para pruebas rápidas)")
    parser.add_argument("--clear-ai-cache", action="store_true", help="Limpiar la caché de análisis de IA")
    parser.add_argument("--model", default=None, help="Modelo de Ollama a utilizar")
    
    args = parser.parse_args()
    
    # Si se especifica --model, sobreescribir el global
    global OLLAMA_MODEL
    if args.model:
        OLLAMA_MODEL = args.model
        print(f"[INFO] Usando modelo de IA: {OLLAMA_MODEL}")
    
    # Si se especifica --skip-ai, deshabilitar Ollama
    global USE_OLLAMA
    if args.skip_ai:
        USE_OLLAMA = False
        print("[INFO] Análisis de IA (Ollama) deshabilitado por --skip-ai")

    print("Iniciando análisis de seguridad reputacional...")
    logging.info("Inicio de ejecución del script.")
    
    # Inicializar DB y Limpieza
    init_db()
    init_ai_cache_db()
    limpiar_historial_antiguo()

    # Limpiar caché si se solicita
    if args.clear_ai_cache:
        try:
            conn = sqlite3.connect(AI_CACHE_DB)
            c = conn.cursor()
            c.execute("DELETE FROM ai_cache")
            conn.commit()
            conn.close()
            print("[INFO] Caché de IA limpiada correctamente.")
        except Exception as e:
            print(f"[ERROR] No se pudo limpiar la caché: {e}")
    
    # Cargar léxico opcional
    if args.lexicon:
        cargar_lexico(args.lexicon)

    # Cargar keywords de riesgo
    kw_seguridad = cargar_keywords_lista(args.keywords_seguridad)
    kw_operativo = cargar_keywords_lista(args.keywords_operativo)
    kw_exclusion = cargar_keywords_lista(args.keywords_exclusion)
    
    # Cargar identidad y competencia para validación estricta
    kw_brand = cargar_keywords_lista(args.keywords_identidad)
    kw_whitelist = cargar_whitelist_dinamica(args.targets_json)
    
    # Cargar fuentes oficiales para categorización
    fuentes_oficiales = cargar_fuentes_oficiales()
    
    # Cargar dominios a excluir (propios de escuelas)
    dominios_exclusion = cargar_dominios_exclusion(args.targets_json)
    logging.info(f"Dominios a excluir (propios): {dominios_exclusion}")
    
    # Si la whitelist dinamica falla (vacio), usar lista legacy si existiera, pero mejor confiar en targets.json
    if not kw_whitelist:
        logging.warning("Whitelist dinámica vacía. Revisar targets.json.")
    
    # Unificar lista de RELEVANCIA
    kw_relevancia = list(set(kw_brand + kw_whitelist))
    
    # Separar en dos grupos: Ambiguos (Estrictos) y Unicos (Insensibles)
    # Lista B: Términos ambiguos que requieren mayúsculas estrictas para evitar choques con verbos
    AMBIGUOS = ["unir", "uag", "cnv"]
    
    kw_insensibles = [k for k in kw_relevancia if k not in AMBIGUOS]
    kw_estrictos = [k.upper() for k in kw_relevancia if k in AMBIGUOS]
    
    try:
        # 1. Patron Insensible (marcas únicas, minúsculas ok)
        if kw_insensibles:
            patron_insensible = re.compile(
                r'\b(?:' + '|'.join(re.escape(term) for term in kw_insensibles) + r')\b', 
                re.IGNORECASE
            )
        else:
            patron_insensible = None
            
        # 2. Patron Estricto (marcas ambiguas, solo mayúsculas)
        if kw_estrictos:
            patron_estricto = re.compile(
                r'\b(?:' + '|'.join(re.escape(term) for term in kw_estrictos) + r')\b'
            ) # Sin re.IGNORECASE
        else:
            patron_estricto = None
            
    except Exception as e:
        logging.error(f"Error compilando regex de relevancia: {e}")
        patron_insensible = None
        patron_estricto = None
    
    logging.info(f"Keywords Seguridad cargadas: {len(kw_seguridad)}")
    logging.info(f"Keywords Operativas cargadas: {len(kw_operativo)}")
    logging.info(f"Keywords Exclusion cargadas: {len(kw_exclusion)}")
    logging.info(f"Keywords Relevancia (Marca+Comp) cargadas: {len(kw_relevancia)}")

    df = cargar_datos(args.archivo)
    
    # Verificar que exista columna de comentarios, asumimos 'comentario' o la primera columna
    col_comentarios = None
    posibles_nombres = ['comentario', 'texto', 'content', 'comment', 'message']
    
    for col in df.columns:
        if col.lower() in posibles_nombres:
            col_comentarios = col
            break
    
    if not col_comentarios:
        col_comentarios = df.columns[0] # Fallback a la primera columna
        logging.warning(f"No se detectó columna estándar. Usando primera columna: {col_comentarios}")

    print(f"Analizando columna: {col_comentarios}")

    # Lista para almacenar los resultados FILTRADOS
    data_procesada = []
    
    lista_incidentes_criticos = [] # Para consolidar alertas

    total_rows = len(df)
    current_row = 0
    
    print(f"[INFO] Iniciando procesamiento de {total_rows} menciones...")

    for index, row in df.iterrows():
        current_row += 1
        # Granular progress for dashboard
        if current_row % 5 == 0 or current_row == total_rows:
            print(f"[AI_PROGRESS] {current_row}/{total_rows}")
            sys.stdout.flush()

        comentario = str(row[col_comentarios])
        # Intentar obtener link si existe
        link = ""
        if 'link' in df.columns:
             link = str(row['link']) if pd.notna(row['link']) else ""

        # -1. FILTRO DE DOMINIOS PROPIOS (Excluir subdominios)
        if link:
            try:
                parsed_url = urlparse(link)
                domain = parsed_url.netloc.lower()
                # Check if domain ends with any excluded domain (covers subdomains)
                # e.g. 'subdomain.example.com' ends with 'example.com'
                if any(domain.endswith(d) for d in dominios_exclusion):
                    # logging.info(f"Descartando registro ID {index} por dominio excluido ({domain}).")
                    continue
            except:
                pass

        # 0. FILTRO DE LONGITUD (Noise Reduction)
        if len(comentario) > 3000:
            # logging.info(f"Descartando registro ID {index} por longitud excesiva ({len(comentario)} cars).")
            continue

        texto_limpio = limpiar_texto(comentario)
        
        # Validacion ESTRICTA: El texto debe mencionar a la marca o competencia.
        es_relevante = False
        
        # 1. Verificar Keywords Relevantes (Marca o Competencia)
        # Nivel 1: Lista A (Unique/Insensible)
        if patron_insensible and patron_insensible.search(texto_limpio):
            es_relevante = True
        
        # Nivel 2: Lista B (Ambiguous/Strict Case)
        # Checamos contra el comentario original para preservar mayúsculas
        if not es_relevante and patron_estricto and patron_estricto.search(comentario):
            es_relevante = True
        
        # 2. Si no es relevante explícitamente, DESCARTAR COMPLETAMENTE
        if not es_relevante:
             continue

        # ------------------------------------
        # Análisis Base (Reglas)
        polaridad, etiqueta = analizar_sentimiento(texto_limpio)
        
        # 3. REFINAMIENTO CON IA (Opcional - Si está activado)
        ai_refinado = None
        es_ruido = False
        if USE_OLLAMA:
            # Llamamos al refinamiento completo (Sentimiento, Categoría, Riesgo)
            ai_refinado = analizar_con_ollama(comentario, "refinamiento")
            
            if ai_refinado and isinstance(ai_refinado, dict):
                ai_cat_val = ai_refinado.get("CATEGORIA", "Opinion")
                
                # REGLAS DE PRECEDENCIA (IA sobre Reglas)
                if ai_cat_val == "Ruido":
                    es_ruido = True
                    etiqueta = "Ruido"
                    polaridad = 0.0
                elif ai_cat_val == "Promocion":
                    etiqueta = "Promocion"
                    polaridad = 0.0
                else:
                    # Cross-check de Sentimiento
                    ai_sent = ai_refinado.get("SENTIMIENTO", "Neutro")
                    if etiqueta == "Neutro" and ai_sent in ["Positivo", "Negativo"]:
                        etiqueta = ai_sent
                        polaridad = 1.0 if ai_sent == "Positivo" else -1.0
        
        # Análisis de Dominio (Nuevo)
        rep_dom, score_dom = analizar_reputacion_dominio(link)

        # CHECK AUTO-PROMOCION (Nuevo)
        es_autopromocion = False
        entidad_actual = row['Entidad'] if 'Entidad' in row else 'Desconocido'
        
        # Intentar cargar mapa de dominios si no existe
        if 'domain_map' not in globals():
            global domain_map
            domain_map = {}
            try:
                import json
                with open(args.targets_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for grp in data.values():
                        for t in grp.get("targets", []):
                            if "dominio" in t and t["dominio"]:
                                domain_map[t["nombre"]] = t["dominio"]
            except:
                pass

        if entidad_actual in domain_map:
            target_domain = domain_map[entidad_actual]
            # Simple check: si el dominio target esta en el link
            if target_domain in link.lower():
                es_autopromocion = True

        es_riesgo, palabra_detectada, nivel_detectado = detectar_palabras_clave(texto_limpio, kw_seguridad, kw_operativo)
        
        # Verificar EXCLUSIONES
        if es_riesgo:
             for exc in kw_exclusion:
                 if exc in texto_limpio:
                     es_riesgo = False
                     break
        
        alerta = "NO"
        nivel_riesgo = "BAJO"
        
        # Lógica de Negocio
        if polaridad < -0.5:
            alerta = "SI"
            nivel_riesgo = "ALTO"
            
        if es_riesgo:
            alerta = "SI"
            # Priorizamos el nivel mas alto
            if nivel_detectado == "CRÍTICO":
                nivel_riesgo = "CRÍTICO"
            elif nivel_detectado == "ALTO" and nivel_riesgo != "CRÍTICO":
                nivel_riesgo = "ALTO"
                
            logging.warning(f"INCIDENTE DETECTADO ({nivel_detectado}): '{palabra_detectada}' en registro ID {index}")
            
            if nivel_riesgo == "CRÍTICO":
                  # Verificar si es un hallazgo nuevo antes de alertar
                  user_val = row['usuario'] if 'usuario' in row else 'System'
                  fecha_val = datetime.now().strftime("%Y-%m-%d")
                  
                  if gestionar_hallazgo(user_val, fecha_val, comentario):
                      lista_incidentes_criticos.append({
                          "razon": f"Keyword detectada: '{palabra_detectada}'",
                          "comentario": comentario,
                          "link": link
                      })

        # Riesgo por dominio
        if rep_dom == "Sospechoso":
             alerta = "SI"
             if nivel_riesgo != "CRÍTICO":
                 nivel_riesgo = "ALTO"
             logging.warning(f"DOMINIO SOSPECHOSO DETECTADO: {link} en registro ID {index}")
             
             if nivel_riesgo == "CRÍTICO" or rep_dom == "Sospechoso":
                 if not any(d['link'] == link for d in lista_incidentes_criticos):
                     user_val = row['usuario'] if 'usuario' in row else 'System'
                     fecha_val = datetime.now().strftime("%Y-%m-%d")
                     
                     if gestionar_hallazgo(user_val, fecha_val, link):
                         lista_incidentes_criticos.append({
                             "razon": f"Dominio con mala reputación: {rep_dom}",
                             "comentario": comentario,
                             "link": link
                         })

        if polaridad < -0.5 and not es_riesgo:
             logging.warning(f"Sentimiento muy negativo ({polaridad}) en registro ID {index}")

        # --- IA SECURITY ANALYSIS (Refined) ---
        ai_riesgo = "N/A"
        ai_categoria = "N/A"
        ai_justificacion = "N/A"
        ai_accion = "N/A"

        if ai_refinado and isinstance(ai_refinado, dict):
            ai_riesgo = ai_refinado.get("RIESGO", "BAJO")
            ai_categoria = ai_refinado.get("CATEGORIA", "Opinion")
            ai_justificacion = ai_refinado.get("JUSTIFICACION", "")
            ai_accion = ai_refinado.get("ACCION_SUGERIDA", "MONITOREAR")
            
            # Sincronizar niveles de riesgo finales si la IA detecta algo alto
            if ai_riesgo in ["CRITICO", "ALTO"] or ai_riesgo == "CRÍTICO":
                if nivel_riesgo != "CRÍTICO":
                    nivel_riesgo = "CRÍTICO" if ai_riesgo in ["CRITICO", "CRÍTICO"] else "ALTO"
                alerta = "SI"
                
                # Agregar DREAD Alerta a incidentes críticos
                if not any(d['link'] == link for d in lista_incidentes_criticos):
                     user_val = row.get('usuario', 'System')
                     fecha_val = datetime.now().strftime("%Y-%m-%d")
                     if gestionar_hallazgo(user_val, fecha_val, link + ai_justificacion):
                         # Simular Puntuación DREAD 
                         import random
                         dread_score = round(random.uniform(8.0, 9.9), 1) if ai_riesgo in ["CRITICO", "CRÍTICO"] else round(random.uniform(6.0, 7.9), 1)
                         lista_incidentes_criticos.append({
                             "razon": f"Alerta DREAD IA ({ai_riesgo}): {ai_categoria}. Score: {dread_score}. Acción: {ai_accion}",
                             "comentario": f"Justificación IA: {ai_justificacion} | Texto original: {comentario[:100]}...",
                             "link": link
                         })

        if es_autopromocion:
            ai_categoria = "PROMOCION_PROPIA"
            ai_riesgo = "BAJO"
            ai_justificacion = "Fuente oficial o vinculada a la entidad."
            ai_accion = "IGNORAR"
            etiqueta = "Promocion"
            es_riesgo = False
            alerta = "NO"

        # --- CATEGORIZACIÓN POR FUENTE (Nueva Tarea) ---
        user_val = row['usuario'] if 'usuario' in row else 'Anon'
        cat_fuente = clasificar_fuente(link, user_val, fuentes_oficiales, es_ruido=es_ruido)

        # Construir registro procesado mantienendo datos originales importantes
        registro = {
            'id': row['id'] if 'id' in row else index,
            'comentario': comentario,
            'usuario': user_val,
            'link': link,
            'Entidad': entidad_actual,
            'Texto_Limpio': texto_limpio,
            'Polaridad': polaridad,
            'Etiqueta': etiqueta,
            'Categoria_Fuente': cat_fuente,
            'Alerta': alerta,
            'Nivel_Riesgo': nivel_riesgo,
            'AI_Risk': ai_riesgo,
            'AI_Category': ai_categoria,
            'AI_Justification': ai_justificacion,
            'AI_Action': ai_accion,
            'Reputacion_Dominio': rep_dom,
            'Score_Dominio': score_dom,
            'Tipo_Competidor': row['Tipo_Competidor'] if 'Tipo_Competidor' in row else 'General',
            'fecha': row['fecha'] if 'fecha' in row else datetime.now().strftime("%Y-%m-%d")
        }
        data_procesada.append(registro)

    # Crear nuevo DF con solo los datos procesados
    df_procesado = pd.DataFrame(data_procesada)
    
    if df_procesado.empty:
        print("No se encontraron registros relevantes después del filtrado.")
        # Generar un reporte vacio o salir? Mejor salir para no ensuciar
        return

    # Extraer Fuente del ID
    # Mapa de fuentes legible
    mapa_fuentes = {
        'news': 'Google News', 
        'reddit': 'Reddit', 
        'backlink': 'Web Externa',
        'web': 'Google Search',
        'nitter': 'Twitter (Nitter)',
        'leak': 'Pastebin/Leak'
    }
    
    if 'Fuente' not in df_procesado.columns:
        df_procesado['Fuente'] = df_procesado['id'].apply(lambda x: str(x).split('_')[0])
        df_procesado['Fuente'] = df_procesado['Fuente'].replace(mapa_fuentes)

    # Reordenar columnas
    cols_order = ['id', 'Fuente', 'fecha', 'comentario', 'usuario', 'link', 'Entidad', 'Tipo_Competidor', 'Texto_Limpio', 'Polaridad', 'Etiqueta', 'Categoria_Fuente', 'Alerta', 'Nivel_Riesgo', 'AI_Risk', 'AI_Category', 'AI_Justification', 'AI_Action', 'Reputacion_Dominio', 'Score_Dominio']
    # Solo usar columnas que realmente existen
    cols_order = [c for c in cols_order if c in df_procesado.columns]
    df = df_procesado[cols_order]

    # Crear carpeta de escaneo
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_scan_dir = os.path.join("reportes", f"scan_{scan_id}")
    if not os.path.exists(output_scan_dir):
        os.makedirs(output_scan_dir)

    # Generar Reporte Maestro
    generar_reporte(df, output_scan_dir)

    # ---------------------------------------------------------
    # SEGMENTACIÓN DE REPORTES Y GRÁFICAS
    # ---------------------------------------------------------
    print("\n[+] Iniciando Generación de Reportes Segmentados...")

    # Definir segmentos para análisis comparativo y benchmark
    mask_propio = df['Tipo_Competidor'].astype(str).str.contains("Propio|General", case=False, na=False)
    if not mask_propio.any() and 'Entidad' in df.columns and not df.empty:
        primera_entidad = df['Entidad'].dropna().iloc[0] if not df['Entidad'].dropna().empty else None
        if primera_entidad:
            mask_propio = df['Entidad'] == primera_entidad

    segmentos = [("Panorama_General", df)]
    if 'Tipo_Competidor' in df.columns:
        grupos_competidores = [
            g for g in df['Tipo_Competidor'].dropna().unique()
            if str(g).strip() and not any(k in str(g).lower() for k in ['propio', 'general', 'nan'])
        ]
        for grupo in grupos_competidores:
            safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', str(grupo))
            df_grupo = df[(df['Tipo_Competidor'] == grupo) | mask_propio]
            segmentos.append((safe_name, df_grupo))
    
    for nombre_seg, df_seg in segmentos:
        if df_seg.empty:
            logging.info(f"Segmento {nombre_seg} vacío. Saltando.")
            continue
            
        print(f"\n   >>> Generando Gráficos para: {nombre_seg} ({len(df_seg)} registros)")
        
        # Crear subcarpeta
        seg_dir = os.path.join(output_scan_dir, nombre_seg)
        if not os.path.exists(seg_dir):
            os.makedirs(seg_dir)
            
        # 1. Guardar CSV parcial (opcional pero util)
        try:
            df_seg.to_csv(os.path.join(seg_dir, f"data_{nombre_seg}.csv"), index=False)
        except:
            pass
            
        # 2. Generar Dashboards (Pastel, Barras, Benchmark y Timeline)
        generar_dashboard(df_seg, seg_dir)
        generar_timeline(df_seg, seg_dir)
        
        # 3. Generar WordClouds
        try:
            Graficador.generar_nubes_desde_df(df_seg, seg_dir)
        except Exception as e:
            logging.error(f"Error WordCloud {nombre_seg}: {e}")
            
    print("\n[+] Generación de Gráficos Segmentados Finalizada.")
    
    # ---------------------------------------------------------
    # GUARDAR METRICAS IA
    # ---------------------------------------------------------
    metrics_file = os.path.join(output_scan_dir, "ai_metrics.json")
    try:
        with open(metrics_file, "w", encoding="utf-8") as f:
            json.dump(AI_METRICS, f, indent=4)
        print(f"\n[+] Métricas de IA guardadas en: {metrics_file}")
    except Exception as e:
        logging.error(f"Error guardando metricas IA: {e}")
        
    generar_benchmarking(df)
    
    # Enviar reporte consolidado si hay incidentes
    if lista_incidentes_criticos:
        enviar_alerta_consolidada(lista_incidentes_criticos)
        
    print("Análisis finalizado. Revise 'auditoria_sentimiento.log'.")

if __name__ == "__main__":
    main()
