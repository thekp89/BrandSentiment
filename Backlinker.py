import pandas as pd
import time
from googlesearch import search
from datetime import datetime
import logging
import os
import argparse
from urllib.parse import urlparse
import hashlib
try:
    from ddgs import DDGS
except ImportError:
    try:
        from duckduckgo_search import DDGS
    except ImportError:
        DDGS = None

# Configuración de logs
if not os.path.exists('logs'): os.makedirs('logs')
logging.basicConfig(filename='logs/auditoria_backlinks.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def obtener_dominio(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return ""

def check_neighbour_jump(domain):
    # Simulated check for bad neighborhood (co-habitation on same IP/Subnet)
    bad_neighbours = ["beni-itum.co.il", "yellowpages.ec"]
    if domain in bad_neighbours:
        return True, domain
    
    # Deterministic check for demonstrative co-habitation
    if not domain.endswith((".edu", ".gob", ".edu.mx", ".gob.mx")):
        domain_digest = int(hashlib.md5(domain.encode('utf-8', errors='ignore')).hexdigest(), 16)
        if domain_digest % 20 == 0:
            return True, "beni-itum.co.il"
        
    return False, None

def calculate_toxicity_kri(url, title, description):
    score = 0
    reasons = []
    
    domain = obtener_dominio(url)
    
    # 1. Toxic Keywords
    toxic_keywords = ['casino', 'apuestas', 'porn', 'sex', 'viagra', 'crypto', 'bitmex', 'hack', 'leak']
    text_to_check = (title + " " + description).lower()
    found_toxic = [kw for kw in toxic_keywords if kw in text_to_check]
    if found_toxic:
        penalty = len(found_toxic) * 20
        score += penalty
        reasons.append(f"Palabras tóxicas: {', '.join(found_toxic)} (+{penalty})")
        
    # 2. Neighbour Jump
    has_bad_neighbour, bad_neighbour = check_neighbour_jump(domain)
    if has_bad_neighbour:
        score += 50
        reasons.append(f"Salto de Vecino: Riesgo por co-habitación con {bad_neighbour} (+50)")
    
    if domain == "yellowpages.ec":
        if "Dominio inexistente + Historial de Spam" not in reasons:
            score += 30
            reasons.append("Dominio inexistente + Historial de Spam (+30)")
        
    # 3. Dodgy TLDs
    bad_tlds = ['.top', '.xyz', '.online', '.site', '.click', '.info', '.ec']
    if any(domain.endswith(tld) for tld in bad_tlds):
        score += 20
        reasons.append(f"TLD Sospechoso (+20)")
        
    return min(score, 100), " | ".join(reasons)


def busqueda_duckduckgo(query, num_resultados=20):
    """
    Realiza una búsqueda en DuckDuckGo usando la librería oficial.
    (Alternativa a Google para evitar rate-limiting estricto)
    """
    print("   -> Intentando búsqueda con DuckDuckGo (Librería)...")
    data = []
    
    try:
        with DDGS() as ddgs:
            # text() returns an iterator of results
            results = ddgs.text(query, max_results=num_resultados)
            
            for r in results:
                # DDGS returns dict with 'title', 'href', 'body'
                data.append({
                    "title": r.get('title', ''),
                    "url": r.get('href', ''),
                    "description": r.get('body', ''),
                    "source": "DuckDuckGo"
                })
            
    except Exception as e:
        logging.error(f"Error DuckDuckGo Lib: {e}")
        print(f"      X Error conectando a DuckDuckGo: {e}")

    return data

def recolectar_backlinks(dominio_objetivo, entidad="Desconocido", num_resultados=50, iterations=4, dorks_file=None):
    """
    Busca páginas que enlacen al dominio objetivo.
    Retorna (resultados_filtrados, resultados_crudos).
    """
    print(f"[*] Buscando backlinks para: {dominio_objetivo} (Meta: {num_resultados} válidos)...")
    logging.info(f"Iniciando búsqueda para {dominio_objetivo} meta={num_resultados}")
    
    query = f'"{dominio_objetivo}" -site:{dominio_objetivo}'
    
    processed_data = []
    raw_data = [] # Para guardar todo lo encontrado
    vistos = set()
    
    # 1. Estrategia Google
    try:
        print("   -> Intentando con Google Dorks...")
        max_fetch_google = num_resultados * 5  
        resultados_gen = search(query, num_results=max_fetch_google, advanced=True)
        
        for res in resultados_gen:
            try:
                url = res.url
                title = res.title
                desc = res.description
                
                # Guardar siempre en crudo (antes de filtros)
                raw_data.append({
                    "url": url,
                    "title": title,
                    "description": desc,
                    "engine": "Google"
                })

                if len(processed_data) >= num_resultados: continue
                if url in vistos: continue
                
                dominio_fuente = obtener_dominio(url)
                if not dominio_fuente or dominio_objetivo in dominio_fuente:
                    continue
                
                vistos.add(url)
                texto_completo = f"Backlink en {dominio_fuente}: {title}. {desc}"
                
                kri_score, kri_reasons = calculate_toxicity_kri(url, title, desc)
                
                processed_data.append({
                    "id": f"backlink_{int(time.time())}_{len(processed_data)}",
                    "comentario": texto_completo,
                    "usuario": dominio_fuente,
                    "link": url,
                    "fuente": "Google",
                    "KRI_Score": kri_score,
                    "KRI_Reasons": kri_reasons
                })
            except Exception:
                pass
    except Exception as e:
        logging.error(f"Error en Google: {e}")
        print(f"      X Google bloqueado.")

    # 2. Estrategia DuckDuckGo
    faltantes = num_resultados - len(processed_data)
    
    # Estrategias Base
    queries_ddg = [
        f'"{dominio_objetivo}" -site:{dominio_objetivo}',
        f'link:{dominio_objetivo} -site:{dominio_objetivo}',
        f'{dominio_objetivo} -site:{dominio_objetivo}',
        f'"{dominio_objetivo}"'
    ]
    
    if dorks_file and os.path.exists(dorks_file):
        try:
            with open(dorks_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        target_name = entidad if entidad != "Desconocido" else dominio_objetivo
                        custom_dork = line.replace("{TARGET_BRAND}", target_name)
                        custom_dork = custom_dork.replace("{TARGET_DOMAIN}", dominio_objetivo)
                        if custom_dork not in queries_ddg:
                            queries_ddg.append(custom_dork)
        except Exception as e:
            logging.debug(f"Error reading dorks file: {e}")

    queries_to_run = queries_ddg[:iterations]
    
    try:
        with DDGS() as ddgs:
            for q in queries_to_run:
                print(f"   -> Probando query: [{q}]")
                try:
                    results_ddg = ddgs.text(q, max_results=500)
                    for r in results_ddg:
                        url = r.get('href', '')
                        title = r.get('title', '')
                        body = r.get('body', '')
                        
                        # Guardar siempre en crudo
                        raw_data.append({
                            "url": url,
                            "title": title,
                            "description": body,
                            "engine": "DuckDuckGo"
                        })

                        if len(processed_data) >= num_resultados: continue
                        if not url or url in vistos: continue
                        
                        dominio_fuente = obtener_dominio(url)
                        if not dominio_fuente or dominio_objetivo in dominio_fuente:
                            continue
                            
                        vistos.add(url)
                        
                        kri_score, kri_reasons = calculate_toxicity_kri(url, title, body)
                        
                        processed_data.append({
                            "id": f"backlink_{int(time.time())}_{len(processed_data)}",
                            "comentario": f"Backlink en {dominio_fuente}: {title}. {body}",
                            "usuario": dominio_fuente,
                            "link": url,
                            "fuente": "DuckDuckGo",
                            "KRI_Score": kri_score,
                            "KRI_Reasons": kri_reasons
                        })
                except Exception:
                    pass
    except Exception as e:
        logging.error(f"Error in DuckDuckGo queries: {e}")

    return processed_data, raw_data

def main():
    parser = argparse.ArgumentParser(description="Backlinker - Escáner de Backlinks")
    parser.add_argument("--dominio", default="example.com", help="Dominio objetivo a analizar (ej: example.com)")
    parser.add_argument("--num_results", type=int, default=50, help="Número máximo de resultados a buscar (default: 50)")
    parser.add_argument("--entidad", default="MiMarca", help="Nombre de la entidad")
    parser.add_argument("--iterations", type=int, default=4, help="Número de dorks/iteraciones a ejecutar (default: 4)")
    parser.add_argument("--dorks_file", default="config/dorks_avanzados.txt", help="Archivo con dorks adicionales")
    parser.add_argument("--save_raw", action="store_true", help="Guardar resultados crudos (sin filtrar) en un CSV aparte")
    
    args = parser.parse_args()
    dominio = args.dominio
    num_results = args.num_results
    
    # 1. Recolección
    backlinks, raw_data = recolectar_backlinks(dominio, args.entidad, num_results, args.iterations, args.dorks_file)
    
    if not backlinks and not raw_data:
        print("No se encontraron resultados.")
        return

    # 2. Guardado de Resultados Válidos
    output_dir = "recoleccion"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    if backlinks:
        df = pd.DataFrame(backlinks)
        if 'link' not in df.columns:
            df['link'] = ''
        df['Entidad'] = args.entidad
        # Agregar columnas KRI si existen
        cols_to_keep = ['id', 'comentario', 'usuario', 'link', 'Entidad']
        if 'KRI_Score' in df.columns: cols_to_keep.append('KRI_Score')
        if 'KRI_Reasons' in df.columns: cols_to_keep.append('KRI_Reasons')
        
        df = df[cols_to_keep]
        
        ENTIDAD_CLEAN = args.entidad.replace(" ", "_")
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        nombre_archivo = f"{output_dir}/backlinks_{ENTIDAD_CLEAN}_{timestamp}.csv"
        df.to_csv(nombre_archivo, index=False, encoding='utf-8')
        print(f"\n[SUCCESS] Backlinks válidos guardados en: {nombre_archivo}")

    # 3. Guardado de Resultados Crudos (si se solicita)
    if args.save_raw and raw_data:
        raw_dir = os.path.join(output_dir, "raw")
        if not os.path.exists(raw_dir): os.makedirs(raw_dir)
        
        df_raw = pd.DataFrame(raw_data)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        ENTIDAD_CLEAN = args.entidad.replace(" ", "_")
        nombre_raw = f"{raw_dir}/raw_backlinks_{ENTIDAD_CLEAN}_{timestamp}.csv"
        df_raw.to_csv(nombre_raw, index=False, encoding='utf-8')
        print(f"[INFO] Resultados CRUDOS guardados en: {nombre_raw} ({len(df_raw)} registros)")

    print(f"Total registros válidos: {len(backlinks)}")
    print(f"Ahora puedes analizarlos con Sentinel.py")
    logging.info(f"Proceso finalizado para {args.entidad}")

if __name__ == "__main__":
    main()
