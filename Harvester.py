import pandas as pd
import feedparser
import time
from googlesearch import search
from datetime import datetime, timedelta
import logging
import os
import argparse
from urllib.parse import quote
import requests
import random
import sqlite3
import hashlib
import hashlib
import unicodedata
from dotenv import load_dotenv
from ddgs import DDGS
import concurrent.futures

# Cargar variables de entorno
load_dotenv()

# Configuración de logs
if not os.path.exists('logs'): os.makedirs('logs')
logging.basicConfig(filename='logs/auditoria_recoleccion.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# === CONFIGURACIÓN DE DELAYS ===
DELAY_BETWEEN_SOURCES = 3  # Reducido gracias a proxies
DELAY_MIN = 1
DELAY_MAX = 3

# === CONFIGURACIÓN DE PROXY (Bright Data) ===
PROXY_HOST = os.getenv("BRIGHTDATA_HOST", "brd.superproxy.io")
PROXY_PORT = os.getenv("BRIGHTDATA_PORT", "33335")
PROXY_USER = os.getenv("BRIGHTDATA_USER", "")
PROXY_PASS = os.getenv("BRIGHTDATA_PASS", "")

USE_PROXY = False # bool(PROXY_USER and PROXY_PASS) - Desactivado por bloqueos

def get_proxy_url():
    """Retorna la URL del proxy configurada."""
    if USE_PROXY:
        return f"http://{PROXY_USER}:{PROXY_PASS}@{PROXY_HOST}:{PROXY_PORT}"
    return None

def get_proxies():
    """Retorna dict de proxies para requests."""
    proxy_url = get_proxy_url()
    if proxy_url:
        return {"http": proxy_url, "https": proxy_url}
    return None

# === CONFIGURACIÓN DE CACHÉ ===
CACHE_DB = "cache_harvester.db"
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "48"))

def init_cache():
    """Inicializa la base de datos de caché."""
    conn = sqlite3.connect(CACHE_DB)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS search_cache (
        query_hash TEXT PRIMARY KEY,
        query_term TEXT,
        source TEXT,
        results TEXT,
        created_at TEXT,
        expires_at TEXT
    )''')
    conn.commit()
    conn.close()

def get_cache_key(term, source):
    """Genera hash único para una búsqueda."""
    raw = f"{term}:{source}".encode('utf-8')
    return hashlib.sha256(raw).hexdigest()

def get_cached_results(term, source):
    """Busca resultados en caché. Retorna None si no existe o expiró."""
    try:
        conn = sqlite3.connect(CACHE_DB)
        c = conn.cursor()
        key = get_cache_key(term, source)
        now = datetime.now().isoformat()
        
        c.execute("SELECT results FROM search_cache WHERE query_hash=? AND expires_at > ?", (key, now))
        row = c.fetchone()
        conn.close()
        
        if row:
            import json
            logging.info(f"[CACHE HIT] {source}: {term}")
            return json.loads(row[0])
    except Exception as e:
        logging.error(f"Error leyendo caché: {e}")
    return None

def save_to_cache(term, source, results):
    """Guarda resultados en caché."""
    try:
        import json
        conn = sqlite3.connect(CACHE_DB)
        c = conn.cursor()
        key = get_cache_key(term, source)
        now = datetime.now()
        expires = now + timedelta(hours=CACHE_TTL_HOURS)
        
        c.execute('''INSERT OR REPLACE INTO search_cache 
                     (query_hash, query_term, source, results, created_at, expires_at)
                     VALUES (?, ?, ?, ?, ?, ?)''',
                  (key, term, source, json.dumps(results), now.isoformat(), expires.isoformat()))
        conn.commit()
        conn.close()
        logging.info(f"[CACHE SAVE] {source}: {term} ({len(results)} resultados)")
    except Exception as e:
        logging.error(f"Error guardando en caché: {e}")

def clean_expired_cache():
    """Limpia entradas expiradas del caché."""
    try:
        conn = sqlite3.connect(CACHE_DB)
        c = conn.cursor()
        now = datetime.now().isoformat()
        c.execute("DELETE FROM search_cache WHERE expires_at < ?", (now,))
        deleted = c.rowcount
        conn.commit()
        conn.close()
        if deleted > 0:
            logging.info(f"[CACHE CLEAN] {deleted} entradas expiradas eliminadas")
    except Exception as e:
        logging.error(f"Error limpiando caché: {e}")

# Inicializar caché al importar
init_cache()

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1'
]

def proxied_request(url, headers=None, timeout=15):
    """Hace una petición HTTP usando proxy si está disponible."""
    if headers is None:
        headers = {'User-Agent': random.choice(USER_AGENTS)}
    
    proxies = get_proxies()
    try:
        if proxies:
            # Bright Data requiere verificación SSL deshabilitada
            resp = requests.get(url, headers=headers, proxies=proxies, timeout=timeout, verify=False)
        else:
            resp = requests.get(url, headers=headers, timeout=timeout)
        return resp
    except Exception as e:
        logging.error(f"Error en request: {e}")
        # Fallback sin proxy
        if proxies:
            try:
                return requests.get(url, headers=headers, timeout=timeout)
            except:
                pass
        return None

def validar_contenido(texto, keywords):
    if globals().get('RELAXED_MODE', False):
        return True
    texto_norm = texto.lower()
    for termino in keywords:
        if termino.lower() in texto_norm:
            return True
    return False

# === FILTRADO ESTRICTO PARA REDES SOCIALES ===
STRICT_SOURCES = ["reddit"] # Twitter eliminado de estricto, ahora va por Dorks
MIN_CONTENT_LENGTH = 3  # Reducido de 25 a 3 para capturar quejas cortas ("Estafa", "Pésimo")

def normalize_text(text):
    """Elimina acentos y normaliza texto."""
    return ''.join(c for c in unicodedata.normalize('NFD', text) if unicodedata.category(c) != 'Mn').lower()

def validar_contenido_estricto(texto, keywords):
    if globals().get('RELAXED_MODE', False):
        return True
    texto_norm = normalize_text(texto)
    
    for termino in keywords:
        termino_norm = normalize_text(termino)
        
        # Búsqueda permisiva (substring)
        if termino_norm in texto_norm:
            return True
        # Tambien probamos variantes sin espacios
        if termino_norm.replace(" ", "") in texto_norm.replace(" ", ""):
            return True
            
    return False
    


def validar_calidad_contenido(texto, fuente=""):
    """
    Valida la calidad del contenido para fuentes con mucho ruido.
    Retorna (es_valido, razon).
    """
    if not texto or not isinstance(texto, str):
        return False, "Contenido vacío"
    
    # Longitud mínima
    if len(texto.strip()) < MIN_CONTENT_LENGTH:
        return False, "Contenido muy corto"
    
    # Detectar contenido genérico/spam
    # (Filtros de palabras de spam eliminados por solicitud del usuario)
    
    # Demasiados emojis/caracteres especiales (más del 30%)
    special_chars = sum(1 for c in texto if not c.isalnum() and not c.isspace())
    if len(texto) > 0 and special_chars / len(texto) > 0.30:
        return False, "Exceso de caracteres especiales"
    
    return True, "OK"

def es_fuente_estricta(fuente):
    """Determina si una fuente requiere validación estricta."""
    fuente_lower = fuente.lower()
    return any(src in fuente_lower for src in STRICT_SOURCES)

def recolectar_noticias_google(termino, keywords_validacion):
    """
    Usa RSS de Google News para obtener noticias recientes.
    """
    time.sleep(random.uniform(1, 3)) # Jitter anti-bot
    print(f"[*] Buscando noticias sobre: {termino}...")
    logging.info(f"Iniciando búsqueda RSS para {termino}")
    
    # URL codificada
    search_query = quote(termino)
    url_rss = f"https://news.google.com/rss/search?q={search_query}&hl=es-419&gl=MX&ceid=MX:es-419"
    
    feed = feedparser.parse(url_rss)
    data = []
    
    for entry in feed.entries:
        titulo = entry.title
        descripcion = entry.description
        texto_completo = f"{titulo}. {descripcion}"
        
        # 1. Validación Pre-Guardado usando las keywords proporcionadas
        if not validar_contenido(texto_completo, keywords_validacion):
            continue
            
        # Intentar extraer fecha
        fecha_pub = datetime.now().strftime("%Y-%m-%d")
        if hasattr(entry, 'published_parsed') and entry.published_parsed:
             try:
                 fecha_pub = time.strftime("%Y-%m-%d", entry.published_parsed)
             except:
                 pass

        data.append({
            "id": f"news_{int(time.time())}_{len(data)}",
            "comentario": texto_completo,
            "usuario": entry.source.title if 'source' in entry else "GoogleNews",
            "link": entry.link,
            "fuente": "Google News",
            "fecha": fecha_pub
        })
        
    print(f"   -> {len(data)} noticias relevantes encontradas para '{termino}'.")
    return data

def recolectar_busqueda_web(termino, keywords_validacion):
    """
    Usa DuckDuckGo y Google Dorks para encontrar menciones en redes sociales.
    Prioriza DDGS para evitar bloqueos 429 de Google.
    """
    time.sleep(random.uniform(1, 3)) # Jitter anti-bot
    print(f"[*] Realizando Social Listening (OSINT) para: {termino}...")
    logging.info(f"Iniciando búsqueda web para {termino}")
    
    data = []
    # Segmentación de Búsquedas (Dorks Expandidos)
    # Incluimos LinkedIn, Facebook, Twitter, Instagram, TikTok
    sites = [
        "linkedin.com", 
        "facebook.com", 
        "twitter.com", 
        "x.com",
        "reddit.com",
        "instagram.com",
        "tiktok.com"
    ]
    
    # 1. Intentar con DuckDuckGo (Más robusto contra bloqueos)
    print(f"    - Usando DuckDuckGo Search para barrido inicial...")
    try:
        with DDGS() as ddgs:
            for site in sites:
                # Query simple para DDG: site:twitter.com "termino"
                query = f'site:{site} "{termino}"'
                
                # Queries específicas de quejas para X/Twitter
                if site in ["twitter.com", "x.com"]:
                    # Buscamos también sin comillas para mas amplitud
                    # Y con keywords de quejas
                    pass 

                print(f"      > Buscando en {site} via DDG...")
                
                # Pequeño delay aleatorio
                time.sleep(random.uniform(2, 4))
                
                try:
                    # Traer hasta 30 resultados por sitio
                    results = ddgs.text(query, max_results=30)
                    
                    count = 0
                    for res in results:
                        try:
                            titulo = res.get('title', '')
                            desc = res.get('body', '')
                            url = res.get('href', '')
                            
                            texto_completo = f"{titulo}: {desc}"
                            
                            # Validación Suave
                            found_keyword = False
                            for k in keywords_validacion:
                                if k.lower() in texto_completo.lower():
                                    found_keyword = True
                                    break
                            
                            if not found_keyword:
                                continue

                            data.append({
                                "id": f"ddg_{int(time.time())}_{len(data)}",
                                "comentario": texto_completo, 
                                "usuario": f"Anonimo_{site.split('.')[0]}",
                                "link": url, 
                                "fuente": f"DuckDuckGo ({site})",
                                "fecha": datetime.now().strftime("%Y-%m-%d")
                            })
                            count += 1
                        except Exception as e:
                            continue
                            
                    print(f"      -> {count} resultados encontrados en {site}.")
                    
                except Exception as e:
                    logging.error(f"Error DDG en {site}: {e}")
                    # Si falla DDG, no abortamos todo, seguimos con el siguiente sitio
                    pass
                    
    except Exception as e:
        logging.error(f"Error general en módulo DuckDuckGo: {e}")

    # 2. Fallback a Google Search para complementar (si DDG trajo poco)
    # Solo si tenemos muy pocos datos (< 5) intentamos Google para no quemar la IP por gusto
    if len(data) < 5:
        print(f"    - Pocos resultados con DDG. Intentando Google Dorks (con precaución)...")
        for site in sites:
            query = f'site:{site} "{termino}"'
            try:
                sleep_time = random.uniform(10, 15) # Delay mayor
                print(f"    - Esperando {sleep_time:.2f}s para Google...")
                time.sleep(sleep_time)
                
                resultados_gen = search(query, num_results=10, advanced=True) # Pocos resultados
                
                count_g = 0
                for res in resultados_gen:
                    try:
                        titulo = res.title
                        desc = res.description
                        url = res.url
                    except:
                        continue

                    # Verificar duplicados por URL
                    if any(d['link'] == url for d in data):
                        continue

                    texto_completo = f"{titulo}: {desc}"
                    
                    # Validación
                    found_keyword = False
                    for k in keywords_validacion:
                        if k.lower() in texto_completo.lower():
                            found_keyword = True
                            break
                    
                    if not found_keyword:
                        continue

                    data.append({
                        "id": f"goog_{int(time.time())}_{len(data)}",
                        "comentario": texto_completo, 
                        "usuario": f"Anonimo_{site.split('.')[0]}",
                        "link": url, 
                        "fuente": f"Google Search ({site})",
                        "fecha": datetime.now().strftime("%Y-%m-%d")
                    })
                    count_g += 1
                    
                if count_g > 0:
                    print(f"      -> {count_g} resultados extra via Google en {site}.")
                    
            except Exception as e:
                # 429 Too Many Requests es común
                pass
            
    print(f"   -> TOTAL: {len(data)} resultados filtrados encontrados para '{termino}'.")
    return data

def recolectar_fugas(dominio, custom_keywords=None):
    """
    Busca indicios de fugas de informacion o credenciales en sitios de pegado.
    """
    time.sleep(random.uniform(1, 3)) # Jitter anti-bot
    print(f"[*] Buscando posibles fugas de datos (Leaks) para: {dominio}...")
    logging.info(f"Iniciando busqueda de fugas para {dominio}")
    
    data = []
    # Sitios comunes de leaks
    sites = ["pastebin.com", "justpaste.it", "github.com"]
    
    # Palabras clave de leak
    if custom_keywords:
        # Usamos las primeras 5 para no hacer la query gigante
        leak_keywords = custom_keywords[:5]
    else:
        leak_keywords = ["password", "contraseña", "leak", "db_dump", "credenciales"]
    
    # Construir OR de keywords
    # DuckDuckGo soporta OR pero es mejor consultas simples a veces. 
    # Haremos query simple.
    or_clause = " OR ".join([f'"{k}"' for k in leak_keywords])
    
    # DDG Query
    query = f'site:pastebin.com OR site:justpaste.it OR site:github.com "{dominio}" AND ({or_clause})'
    
    print(f"    - Usando DuckDuckGo para evitar bloqueo Google 429...")
    
    try:
        # Usamos DDGS
        with DDGS() as ddgs:
            # DDG returns generator
            results = ddgs.text(query, max_results=10)
            
            for res in results:
                try:
                    titulo = res.get('title', '')
                    desc = res.get('body', '')
                    url = res.get('href', '')
                
                    texto_completo = f"POSIBLE LEAK: {titulo}. {desc}"
                    
                    data.append({
                        "id": f"leak_{int(time.time())}_{len(data)}",
                        "comentario": texto_completo,
                        "usuario": "LeakHunter",
                        "link": url,
                        "fuente": "Google Dorks (Leaks)",
                        "fecha": datetime.now().strftime("%Y-%m-%d")
                    })
                except AttributeError:
                    pass
                
    except Exception as e:
        logging.error(f"Error en busqueda de fugas: {e}")
        pass
        
    print(f"   -> {len(data)} posibles fugas encontradas para '{dominio}'.")
    return data

def recolectar_dorks_y_shadow_it(dominio):
    """
    Busca archivos sensibles y subdominios expuestos (Shadow IT) usando DuckDuckGo.
    """
    time.sleep(random.uniform(1, 4)) # Jitter
    print(f"[*] Buscando Dorks y Shadow IT para: {dominio}...")
    logging.info(f"Iniciando busqueda Dorks/Shadow IT para {dominio}")
    
    data = []
    
    # 1. Dorks de archivos sensibles
    dorks_archivos = f'site:{dominio} ext:pdf OR ext:php OR ext:env OR ext:sql OR ext:bak OR ext:log'
    # 2. Shadow IT (subdominios como dev.*, test.*, admin.*)
    shadow_it = f'site:*.{dominio} -site:www.{dominio} -site:{dominio}'
    
    queries = {
        "Dorks Archivos": dorks_archivos,
        "Shadow IT": shadow_it
    }
    
    try:
        with DDGS() as ddgs:
            for tipo, query in queries.items():
                print(f"    - Ejecutando {tipo}...")
                results = ddgs.text(query, max_results=15)
                
                count = 0
                for res in results:
                    try:
                        titulo = res.get('title', '')
                        desc = res.get('body', '')
                        url = res.get('href', '')
                    
                        texto_completo = f"HALLAZGO {tipo}: {titulo}. {desc}"
                        
                        data.append({
                            "id": f"dork_{int(time.time())}_{len(data)}",
                            "comentario": texto_completo,
                            "usuario": "OSINT_Dorker",
                            "link": url,
                            "fuente": tipo,
                            "fecha": datetime.now().strftime("%Y-%m-%d")
                        })
                        count += 1
                    except AttributeError:
                        pass
                print(f"      -> {count} resultados encontrados para {tipo}.")
                time.sleep(random.uniform(2, 4))
                
    except Exception as e:
        logging.error(f"Error en busqueda de Dorks/Shadow IT: {e}")
        pass
        
    print(f"   -> {len(data)} hallazgos totales de OSINT Avanzado para '{dominio}'.")
    return data

def recolectar_reddit(termino, keywords_validacion=None):
    """
    Busca en Reddit usando la API JSON no documentada.
    Usa proxy si está disponible y cachea resultados.
    Incluye filtrado estricto para reducir ruido.
    """
    time.sleep(random.uniform(1, 3)) # Jitter anti-bot
    print(f"[*] Buscando en Reddit: {termino}...")
    logging.info(f"Iniciando busqueda Reddit para {termino}")
    
    # Verificar caché primero
    cached = get_cached_results(termino, "reddit")
    if cached:
        print(f"   -> [CACHE] {len(cached)} resultados desde caché")
        return cached
    
    data = []
    rechazados = 0
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    url = f"https://www.reddit.com/search.json?q={quote(termino)}&sort=new&limit=50"
    
    try:
        delay = random.uniform(DELAY_MIN, DELAY_MAX)
        print(f"    - Esperando {delay:.1f}s antes de consultar Reddit...")
        time.sleep(delay)
        
        resp = proxied_request(url, headers=headers, timeout=15)
        
        if resp and resp.status_code == 200:
            try:
                json_data = resp.json()
                children = json_data.get('data', {}).get('children', [])
                for child in children:
                    kind = child.get('data', {})
                    titulo = kind.get('title', '')
                    texto = kind.get('selftext', '')
                    if not texto: texto = kind.get('url', '')
                    
                    full_text = f"{titulo}. {texto}"
                    
                    # === FILTRADO ESTRICTO ===
                    # 1. Validar calidad del contenido
                    es_valido, razon = validar_calidad_contenido(full_text, "Reddit")
                    if not es_valido:
                        rechazados += 1
                        continue
                    
                    # 2. Validar coincidencia (Usando lista amplia si existe)
                    kv = keywords_validacion if keywords_validacion else [termino]
                    if not validar_contenido_estricto(full_text, kv):
                        rechazados += 1
                        continue
                    
                    fecha_pub = datetime.now().strftime("%Y-%m-%d")
                    utc_ts = kind.get('created_utc')
                    if utc_ts:
                        fecha_pub = datetime.fromtimestamp(utc_ts).strftime("%Y-%m-%d")
                    
                    data.append({
                        "id": f"reddit_{kind.get('id', int(time.time()))}",
                        "comentario": full_text[:5000], 
                        "usuario": f"u/{kind.get('author', 'unknown')}",
                        "link": f"https://reddit.com{kind.get('permalink')}",
                        "fuente": "Reddit",
                        "fecha": fecha_pub
                    })
            except Exception as e:
                 logging.error(f"Error parseando JSON Reddit: {e}")
        elif resp:
            logging.warning(f"Reddit retorno status {resp.status_code}")
    except Exception as e:
        logging.error(f"Error conexion Reddit: {e}")
    
    if data:
        save_to_cache(termino, "reddit", data)
    
    print(f"   -> {len(data)} resultados válidos ({rechazados} rechazados por filtro estricto)")
    logging.info(f"Reddit: {len(data)} válidos, {rechazados} rechazados")
    return data

def recolectar_twitter(termino):
    """
    DEPRECATED: El scraping directo a Twitter/X está bloqueado o es ineficiente.
    Ahora usamos Google Dorks en recolectar_busqueda_web para obtener contenido de Twitter.
    """
    print(f"[*] (Saltando módulo Twitter Directo) - Usando Google Dorks en su lugar.")
    return []



# Alias para compatibilidad
recolectar_nitter = recolectar_twitter

def cargar_keywords_desde_archivo(ruta):
    """Carga lista de keywords desde txt (una por linea, ignora #)"""
    if not os.path.exists(ruta):
        print(f"Error: El archivo {ruta} no existe.")
        return []
    lista = []
    with open(ruta, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                lista.append(line.replace('"', '').lower())
    return lista

def main():
    parser = argparse.ArgumentParser(description="Harvester - Recolección de datos OSINT")
    parser.add_argument("--keywords", nargs="+", help="Lista de palabras clave para buscar (separadas por espacio)")
    parser.add_argument("--archivo_keywords", help="Archivo de texto con palabras clave (una por línea)")
    parser.add_argument("--entidad", default="Desconocido", help="Nombre de la entidad (e.g. MiMarca, Competencia)")
    parser.add_argument("--dominio", default=None, help="Dominio objetivo para búsqueda de fugas")
    parser.add_argument("--keywords_seguridad", default="config/keywords_riesgo_seguridad.txt", help="Archivo de keywords de seguridad")
    parser.add_argument("--tipo", default="General", help="Tipo de Competidor (Grupo_A, Grupo_B, etc.)")
    parser.add_argument("--no-cache", action="store_true", help="Ignorar caché y forzar búsquedas frescas")
    parser.add_argument("--relaxed", action="store_true", help="Bypass validation/filtering (for AI-driven scans)")
    
    args = parser.parse_args()
    
    # Store relaxed mode in a global for easy access in functions if needed,
    # though passing it would be cleaner. For now, let's use it directly in loop.
    RELAXED_MODE = args.relaxed
    if RELAXED_MODE:
        logging.info("Modo RELAXED activo: Se omitirá el filtrado por keywords para maximizar captura para IA.")
        print("[INFO] Modo RELAXED activo: Capturando todo para análisis posterior con IA.")
    
    # Limpiar caché expirado al inicio
    clean_expired_cache()
    
    # Mostrar estado de proxy
    if USE_PROXY:
        print(f"[+] Proxy habilitado: {PROXY_HOST}:{PROXY_PORT}")
    else:
        print("[!] Sin proxy configurado - usando conexión directa")
    
    terminos_busqueda = []
    
    # 1. Cargar desde argumentos
    if args.keywords:
        terminos_busqueda.extend(args.keywords)
        
    # 2. Cargar desde archivo
    if args.archivo_keywords:
        terminos_busqueda.extend(cargar_keywords_desde_archivo(args.archivo_keywords))
        
    # Default si no hay nada
    if not terminos_busqueda:
        print("No se proporcionaron palabras clave. Usando valor por defecto.")
        terminos_busqueda = [args.entidad if args.entidad != "Desconocido" else "MiMarca"]

    # Eliminar duplicados
    terminos_busqueda = list(set(terminos_busqueda))
    
    print(f"Iniciando recolección para: {terminos_busqueda}")
    
    all_data = []
    
    # Concurrencia: Ejecutar fuentes en paralelo por cada término
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        for termino in terminos_busqueda:
            kw_validacion = terminos_busqueda + [termino] 
            
            # Lanzar tareas
            futures = {
                executor.submit(recolectar_noticias_google, termino, kw_validacion): "Google News",
                executor.submit(recolectar_busqueda_web, termino, kw_validacion): "Busqueda Web",
                executor.submit(recolectar_reddit, termino, kw_validacion): "Reddit",
                executor.submit(recolectar_twitter, termino): "Twitter (Mock)"
            }
            
            for future in concurrent.futures.as_completed(futures):
                fuente_nombre = futures[future]
                try:
                    results = future.result()
                    if results:
                        all_data.extend(results)
                except Exception as e:
                    logging.error(f"Skip {fuente_nombre} por bloqueo o error: {e}")
                    print(f"   [!] Error en {fuente_nombre}: {e}")

    # Búsqueda de Fugas (Solo una vez por ejecución)
    if terminos_busqueda:
        dominio_fugas = args.dominio if args.dominio else (terminos_busqueda[0].replace(" ", "").lower() + ".com")
        
        kw_fugas = []
        if args.keywords_seguridad:
            kw_fugas = cargar_keywords_desde_archivo(args.keywords_seguridad)

        try:
            fugas = recolectar_fugas(dominio_fugas, kw_fugas)
            if fugas:
                all_data.extend(fugas)
                
        except Exception as e:
            logging.error(f"Skip Leaks por error: {e}")

        try:
            dorks_shadow = recolectar_dorks_y_shadow_it(dominio_fugas)
            if dorks_shadow:
                all_data.extend(dorks_shadow)
        except Exception as e:
            logging.error(f"Skip Dorks/Shadow IT por error: {e}")
    
    if not all_data:
        print("No se encontraron datos relevantes para ninguno de los términos.")
        return

    # 3. Guardado en CSV
    output_dir = "recoleccion"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    df = pd.DataFrame(all_data)
    
    # Eliminar duplicados exactos (mismo ID o mismo link si existe)
    if 'link' in df.columns:
        df.drop_duplicates(subset=['link'], keep='first', inplace=True)
    
    if 'link' not in df.columns:
         df['link'] = ''
         
    # Add Entidad column
    df['Entidad'] = args.entidad
    df['Tipo_Competidor'] = args.tipo

    df = df[['id', 'comentario', 'usuario', 'link', 'Entidad', 'Tipo_Competidor', 'fecha']]
    
    ENTIDAD_CLEAN = args.entidad.replace(" ", "_")
    nombre_archivo = f"{output_dir}/input_{ENTIDAD_CLEAN}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    df.to_csv(nombre_archivo, index=False, encoding='utf-8')
    
    print(f"\n[SUCCESS] Datos recolectados guardados en: {nombre_archivo}")
    print(f"Total registros únicos: {len(df)}")
    print(f"Ahora puedes ejecutar Sentinel.py con este archivo.")
    logging.info(f"Archivo generado: {nombre_archivo} con {len(df)} registros.")

if __name__ == "__main__":
    main()
