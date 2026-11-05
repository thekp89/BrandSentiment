import subprocess
import os
import glob
import argparse
import time
import logging
import sys
import json
import pandas as pd
import zipfile
import shutil
from datetime import datetime


# Configuración de logs para el Manager
if not os.path.exists('logs'): os.makedirs('logs')
logging.basicConfig(filename='logs/auditoria_manager.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

def setup_directories():
    if not os.path.exists("recoleccion"):
        os.makedirs("recoleccion")
    if not os.path.exists("reportes"):
        os.makedirs("reportes")

def get_latest_file(pattern):
    files = glob.glob(pattern)
    if not files:
        return None
    return max(files, key=os.path.getctime)

def get_latest_scan_folder():
    folders = glob.glob('reportes/scan_*')
    if not folders:
        return None
    return max(folders, key=os.path.getctime)

def estimate_dread_score(risk_level, category):
    base_scores = {
        "FILTRACION_DATOS": (9, 8, 9, 9, 8),
        "ATAQUE_DOS": (8, 9, 8, 9, 7),
        "PHISHING": (8, 7, 8, 8, 8),
        "DESPRESTIGIO": (6, 6, 7, 7, 7),
        "RIESGO": (7, 7, 7, 7, 6),
        "OPINION": (3, 4, 3, 3, 4),
        "RUIDO": (1, 1, 1, 1, 1)
    }
    cat_upper = str(category).upper()
    d, r, e, a, disc = base_scores.get(cat_upper, (7, 6, 7, 7, 6))
    if str(risk_level).upper() in ["CRITICO", "CRÍTICO"]:
        d = max(d, 9)
        a = max(a, 9)
    elif str(risk_level).upper() == "ALTO":
        d = max(d, 7)
    score = (d + r + e + a + disc) / 5.0
    return round(score, 1)

def generar_reporte_v2():
    import random
    print("\n[+] Generando Reporte Sentinel V2...")
    latest_scan = get_latest_scan_folder()
    if not latest_scan:
        print("   X No se encontró carpeta de escaneo para generar reporte.")
        return
        
    reporte_csv_path = os.path.join(latest_scan, "reporte_riesgos.csv")
    ai_metrics_path = os.path.join(latest_scan, "ai_metrics.json")
    
    if not os.path.exists(reporte_csv_path):
        print(f"   X No se encontró {reporte_csv_path}")
        return
        
    try:
        df = pd.read_csv(reporte_csv_path)
    except Exception as e:
        print(f"   X Error leyendo {reporte_csv_path}: {e}")
        return
        
    ai_metrics = {}
    if os.path.exists(ai_metrics_path):
        try:
            with open(ai_metrics_path, "r", encoding="utf-8") as f:
                ai_metrics = json.load(f)
        except:
            pass
            
    # 1. Resumen de Ciberinteligencia
    kri_general = 0
    total_menciones = len(df)
    alertas_count = len(df[df['Alerta'] == 'SI'])
    kri_general = (alertas_count / total_menciones * 100) if total_menciones > 0 else 0
    salud_digital = max(0, 100 - kri_general)
    
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_content = []
    report_content.append(f"# Reporte Sentinel V2")
    report_content.append(f"**ID:** RPT-{timestamp_str}")
    report_content.append(f"**Estado del Pipeline:** Full Auto / Escaneo Completado")
    report_content.append(f"**KRI General de la Institución:** {salud_digital:.1f}/100 (Salud Digital)\n")
    
    # 2. Hallazgos Críticos de OSINT
    report_content.append("## 2. Hallazgos Críticos de OSINT")
    df_dorks = df[df['Fuente'].astype(str).str.contains("Dorks Archivos", case=False, na=False)]
    df_shadow = df[df['Fuente'].astype(str).str.contains("Shadow", case=False, na=False)]
    
    report_content.append("### Resultados de Dorks (Archivos Sensibles)")
    if df_dorks.empty:
         report_content.append("- Ninguno detectado.")
    else:
         for _, row in df_dorks.iterrows():
             report_content.append(f"- {row['link']} : {row['comentario'][:100]}")
             
    report_content.append("\n### Shadow IT (Subdominios Expuestos)")
    if df_shadow.empty:
         report_content.append("- Ninguno detectado.")
    else:
         for _, row in df_shadow.iterrows():
             report_content.append(f"- {row['link']} : {row['comentario'][:100]}")
             
    # 3. Análisis de Sentimiento e IA
    report_content.append("\n## 3. Análisis de Sentimiento e Inteligencia Artificial")
    report_content.append("### Métricas de IA:")
    tot_ia = ai_metrics.get("total_analizados", 0)
    cache = ai_metrics.get("cache_hits", 0)
    success = ai_metrics.get("exitosos", 0)
    
    precision = (success / tot_ia * 100) if tot_ia > 0 else 0
    report_content.append(f"- Menciones analizadas por IA local: {tot_ia}")
    report_content.append(f"- Cache Hits (ahorro computacional): {cache}")
    report_content.append(f"- Tasa de precisión estructural (JSON parse): {precision:.1f}%\n")
    
    report_content.append("### Alertas DREAD:")
    if 'AI_Risk' in df.columns:
        df_critico = df[df['AI_Risk'].isin(['CRITICO', 'CRÍTICO', 'ALTO'])]
        if df_critico.empty:
            report_content.append("- No se detectaron alertas críticas.")
        else:
            for i, row in df_critico.iterrows():
                ai_riesgo = row.get('AI_Risk', 'ALTO')
                dread_score = estimate_dread_score(ai_riesgo, row.get('AI_Category', ''))
                report_content.append(f"**Hallazgo {i+1}:** {row.get('comentario', '')[:100]}...")
                report_content.append(f"**Puntuación DREAD:** {dread_score} ({ai_riesgo}) - {row.get('AI_Category', 'N/A')}")
                report_content.append(f"**Acción:** {row.get('AI_Action', 'N/A')}\n")
    else:
        report_content.append("- Análisis IA no disponible en este reporte.")
            
    # 4. Auditoría de Reputación Técnica y Enlaces
    report_content.append("\n## 4. Auditoría de Reputación Técnica y Enlaces (Backlinker)")
    # Enlaces
    df_links = df[df['Fuente'].astype(str).str.contains("DuckDuckGo|Google", case=False, na=False)]
    report_content.append(f"### Resumen de Toxicidad (KRI)")
    report_content.append(f"- Total de enlaces analizados: {len(df_links)}")
    
    nj_count = 0
    if 'KRI_Reasons' in df.columns:
        nj_count = len(df[df['KRI_Reasons'].astype(str).str.contains("Salto de Vecino", na=False)])
    report_content.append(f"- Análisis de 'Salto de Vecino': {nj_count} enlaces con riesgo por co-habitación (identificado).")
    
    report_content.append(f"\n### Top Enlaces de Riesgo")
    if 'KRI_Score' in df.columns:
        df_risk = df[df['KRI_Score'].notna()].copy()
        if not df_risk.empty:
            df_risk['KRI_Score'] = pd.to_numeric(df_risk['KRI_Score'], errors='coerce')
            top_links = df_risk.sort_values(by='KRI_Score', ascending=False).head(5)
            for _, row in top_links.iterrows():
                report_content.append(f"- **{row.get('link', 'N/A')}**: KRI {row.get('KRI_Score', '0')} ({row.get('KRI_Reasons', '')})")
    else:
        report_content.append("- No hay datos KRI disponibles.")
        
    # 5. Benchmarking Competitivo
    report_content.append("\n## 5. Benchmarking Competitivo")
    if 'Entidad' in df.columns:
        entidades = df['Entidad'].unique()
        if len(entidades) > 1:
            report_content.append("Comparativa de Sentimiento:")
            for ent in entidades:
                sub = df[df['Entidad'] == ent]
                neg = len(sub[sub['Etiqueta'].astype(str).str.lower() == 'negativo'])
                total = len(sub)
                pct = (neg/total*100) if total > 0 else 0
                report_content.append(f"- **{ent}**: {pct:.1f}% negatividad ({total} menciones)")
        else:
            report_content.append("- Sólo se analizó una entidad. No hay benchmarking disponible.")
            
    # 6. Recomendaciones y Remediación
    report_content.append("\n## 6. Recomendaciones y Remediación")
    criticos_count = len(df_critico) if 'AI_Risk' in df.columns else 0
    if criticos_count > 0 or nj_count > 0:
        report_content.append("- **Inmediato**: Revisar las alertas DREAD detectadas por la IA y ejecutar las acciones sugeridas (Ej. Escalar a TI, Revisar código).")
        report_content.append("- **Red**: Solicitar delisting o aplicar disavow en GSC para los dominios tóxicos en el top de KRI.")
    else:
        report_content.append("- Mantener monitoreo regular. No se requieren acciones críticas inmediatas.")
        
    report_str = "\n".join(report_content)
    
    report_filename = os.path.join(latest_scan, f"Reporte_V2_Sentinel_{timestamp_str}.md")
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report_str)
        
    print(f"   -> Reporte Sentinel V2 Guardado en: {report_filename}")

def run_harvester(keywords=None, entidad="Desconocido", keywords_file=None, tipo_competidor="General", relaxed=False, dominio=None):
    print(f"\n[+] Ejecutando Harvester para {entidad} ({tipo_competidor})...")
    logging.info(f"Iniciando Harvester para {entidad}")
    cmd = [sys.executable, "Harvester.py", "--entidad", entidad, "--tipo", tipo_competidor]
    if dominio:
        cmd.extend(["--dominio", dominio])
    
    if relaxed:
        cmd.append("--relaxed")
    
    if keywords:
        cmd.extend(["--keywords"] + keywords)
    
    if keywords_file:
        cmd.extend(["--archivo_keywords", keywords_file])
    
    try:
        subprocess.run(cmd, check=True)
        # Buscar el archivo más reciente generado para esta entidad
        # El harvester ahora usa input_{ENTIDAD}_*.csv
        clean_entidad = entidad.replace(" ", "_")
        latest = get_latest_file(f"recoleccion/input_{clean_entidad}_*.csv")
        print(f"   -> Harvester finalizado. Archivo: {latest}")
        return latest
    except subprocess.CalledProcessError as e:
        print(f"   X Error en Harvester: {e}")
        logging.error(f"Error Harvester: {e}")
        return None

def run_backlinker(domain="example.com", entidad="Desconocido", num_results=50, iterations=4, save_raw=False):
    print(f"\n[+] Ejecutando Backlinker para {entidad} ({domain})...")
    logging.info(f"Iniciando Backlinker para {entidad} con {iterations} iteraciones")
    cmd = [
        sys.executable, "Backlinker.py", 
        "--dominio", domain, 
        "--num_results", str(num_results), 
        "--entidad", entidad,
        "--iterations", str(1) # Forzamos 1 iteracion para no saturar en modo masivo
    ]
    if save_raw:
        cmd.append("--save_raw")
    
    try:
        subprocess.run(cmd, check=True)
        # Buscar el archivo más reciente generado para esta entidad
        clean_entidad = entidad.replace(" ", "_")
        latest = get_latest_file(f"recoleccion/backlinks_{clean_entidad}_*.csv")
        print(f"   -> Backlinker finalizado. Archivo: {latest}")
        return latest
    except subprocess.CalledProcessError as e:
        print(f"   X Error en Backlinker: {e}")
        logging.error(f"Error Backlinker: {e}")
        return None

def run_sentinel(input_file, lexicon_file=None, skip_ai=False, model=None):    
    if not input_file:
        print("   X No se proporcionó archivo de entrada para Sentinel.")
        return

    print(f"\n[+] Ejecutando Sentinel (Análisis) sobre {input_file}...")
    logging.info(f"Iniciando Sentinel sobre {input_file}")
    cmd = [sys.executable, "Sentinel.py", "--archivo", input_file]
    if lexicon_file:
        cmd.extend(["--lexicon", lexicon_file])
    if skip_ai:
        cmd.append("--skip-ai")
    if model:
        cmd.extend(["--model", model])
    try:
        subprocess.run(cmd, check=True)
        print("   -> Sentinel finalizado exitosamente.")
        return True # Success
    except subprocess.CalledProcessError as e:
        print(f"   X Error en Sentinel: {e}")
        logging.error(f"Error Sentinel: {e}")
        return False

def run_full_sentiment_scan(include_backlinks=False, targets_file="config/targets.json", relaxed=False):
    """
    Ejecuta el ciclo completo: Harvest -> (Optional Backlink) -> Sentinel
    Para todos los targets configurados.
    """
    print("\n=== INICIANDO ESCANEO DE SENTIMIENTO DE MARCA (AUTOMATIZADO) ===")
    logging.info("Iniciando escaneo completo de sentimiento")
    
    try:
        with open(targets_file, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Error leyendo targets: {e}")
        return False

    all_harvested_files = []
    
    # 1. Iterar Grupos y Targets
    for group_name, group_data in config.items():
        print(f"\n>>> Procesando Grupo: {group_name}")
        for target in group_data.get('targets', []):
            nombre = target['nombre']
            entidad = nombre # Usamos nombre como entidad
            dominio = target.get('dominio', '')
            
            # A. Harvester
            # Usamos 'variaciones' como keywords si existen, sino 'busqueda'
            keywords = target.get('variaciones', []) + target.get('busqueda', [])
            # Limpiamos duplicados
            keywords = list(set(keywords))
            
            # Ejecutar Harvester (solo un set basico por target para no tardar mucho)
            # Pasamos las keywords como argumento (Manager run_harvester soporta esto)
            # Nota: run_harvester espera lista de keywords, pero aqui modificamos la llamada
            # para pasarle argumentos directos construidos.
            
            # Hack: run_harvester usa subprocess. Podemos llamarlo.
            # Pero run_harvester actual espera "entidad" y usa un archivo keywords o lista.
            # Vamos a simplificar: usaremos un archivo temporal de keywords o pasaremos las primeras.
            
            # Note: We don't have relaxed flag in run_full_sentiment_scan args yet, 
            # but let's assume if it were there or auto-calculate.
            # For simplicity, I'll update run_full_sentiment_scan arg later.
            
            csv_harvest = run_harvester(keywords=keywords[:5], entidad=entidad, tipo_competidor=group_name, relaxed=relaxed)
            if csv_harvest:
                all_harvested_files.append(csv_harvest)
            
            # B. Backlinker (Opcional)
            if include_backlinks and dominio:
                csv_backlink = run_backlinker(domain=dominio, entidad=entidad, num_results=30, iterations=1)
                if csv_backlink:
                    all_harvested_files.append(csv_backlink)

    # 2. Merge de Resultados (Opcional, o se lo pasamos a Sentinel uno por uno)
    # Sentinel procesa un archivo a la vez y genera un reporte.
    # Para un dashboard unificado, lo ideal seria unificar CSVs.
    
    if not all_harvested_files:
        print("No se generaron archivos para analizar.")
        return False
        
    print(f"\n[+] Unificando {len(all_harvested_files)} archivos para análisis...")
    
    master_csv = "recoleccion/master_scan_temp.csv"
    dfs = []
    for f in all_harvested_files:
        try:
            # Detectar si es backlinker (cols diferentes) o harvester
            # Harvester tiene: id, comentario, usuario, link, palabra_clave, fuente, sentimiento_base...
            # Backlinker tiene: id, comentario, usuario, link, Entidad
            
            df = pd.read_csv(f)
            # Normalizar columnas
            if 'Entidad' in df.columns: # Es Backlinker
                df['palabra_clave'] = 'Backlink'
                df['fuente'] = 'BacklinkSearch'
                # Renombrar si es necesario para matchear lo que espera Sentinel
                # Sentinel espera 'comentario', 'usuario', 'link', 'id'
            
            dfs.append(df)
        except Exception as e:
            print(f"Error leyendo {f}: {e}")
            
    if dfs:
        full_df = pd.concat(dfs, ignore_index=True)
        # Guardar master
        full_df.to_csv(master_csv, index=False)
        print(f"   -> Archivo maestro creado: {master_csv} ({len(full_df)} registros)")
        
        # 3. Ejecutar Sentinel sobre el master
        run_sentinel(master_csv, skip_ai=False)
        
        # Limpieza
        # os.remove(master_csv) # Dejarlo por si acaso debug
        return True
    
    return False

def load_targets(targets_file="config/targets.json"):
    try:
        with open(targets_file, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error cargando {targets_file}: {e}")
        return []

def maintenance_routine():
    """
    Rutina de limpieza: Comprime y mueve archivos antiguos de recoleccion/.
    Antiguedad > 30 dias.
    """
    print("\n[+] Ejecutando rutina de mantenimiento...")
    data_dir = "recoleccion"
    backup_dir = "backup"
    
    if not os.path.exists(data_dir): return
    if not os.path.exists(backup_dir): os.makedirs(backup_dir)
    
    now = time.time()
    cutoff = 30 * 86400 # 30 dias en segundos
    
    files_to_archive = []
    
    for f in os.listdir(data_dir):
        if not f.endswith(".csv"): continue
        full_path = os.path.join(data_dir, f)
        
        try:
            mtime = os.path.getmtime(full_path)
            if (now - mtime) > cutoff:
                files_to_archive.append(f)
        except:
            pass
            
    if not files_to_archive:
        print("   -> No hay archivos antiguos para archivar.")
        return
        
    # Crear ZIP
    zip_name = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    zip_path = os.path.join(backup_dir, zip_name)
    
    try:
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for f in files_to_archive:
                full_path = os.path.join(data_dir, f)
                zipf.write(full_path, arcname=f)
        
        print(f"   -> Archivo histórico creado: {zip_path}")
        logging.info(f"Backup creado: {zip_path} con {len(files_to_archive)} archivos")
        
        # Eliminar originales
        for f in files_to_archive:
            os.remove(os.path.join(data_dir, f))
        print("   -> Archivos originales eliminados.")
        
    except Exception as e:
        print(f"   X Error en mantenimiento: {e}")
        logging.error(f"Error mantenimiento: {e}")

def full_scan_workflow(num_results, lexicon_file, backlink_iterations=4, save_raw=False, targets_file="config/targets.json", delay_between_targets=10, skip_ai=False, include_backlinks=True, relaxed=False):
    print("="*60)
    print(f" INICIANDO FLUJO DE TRABAJO COMPETITIVO - {time.asctime()}")
    print("="*60)
    
    # 0. Mantenimiento
    maintenance_routine()
    
    targets = load_targets(targets_file)
    if not targets:
        print(f"No se encontraron objetivos en {targets_file}")
        return

    collected_files = []
    
    # 1. Recolección Multi-Target
    # 1. Recolección Multi-Target Modular
    # targets es un dict { "Grupo": { ... }, ... }
    for grupo_nombre, grupo_data in targets.items():
        desc = grupo_data.get("descripcion", "")
        print(f"\n>>> Procesando {grupo_nombre}: {desc}")
        
        lista_targets = grupo_data.get("targets", [])
        
        # Cargar keywords especificas del grupo
        # Asumimos que keywords_competencia.json tiene la misma estructura de claves si quisieramos
        # Pero aqui las pasaremos dinamicamente si el harvester lo soporta.
        # Por ahora usaremos las keywords de busqueda de cada target + keywords genericas del grupo si las hubiera.
        
        for tgt in lista_targets:
            nombre = tgt.get("nombre", "Desconocido")
            busqueda = tgt.get("busqueda", [])
            
            # Harvester
            dominio = tgt.get("dominio")
            h_out = run_harvester(keywords=busqueda, entidad=nombre, tipo_competidor=grupo_nombre, relaxed=relaxed, dominio=dominio)
            if h_out: collected_files.append(h_out)

            # Backlinker
            if include_backlinks and dominio:
                # Ejecutamos backlinker si hay dominio definido y se solicitó
                b_out = run_backlinker(domain=dominio, entidad=nombre, num_results=num_results, iterations=backlink_iterations)
                if b_out: collected_files.append(b_out)
        
        # Delay entre targets/grupos si fuera necesario (no implementado en bucle interno para velocidad)
    
    # 2. Consolidación de Datos
    print("\n[+] Consolidando datos de todas las entidades...")
    
    if not collected_files:
        print("No se generaron archivos para analizar.")
        return

    master_df = pd.DataFrame()
    for f in collected_files:
        try:
            temp_df = pd.read_csv(f)
            master_df = pd.concat([master_df, temp_df], ignore_index=True)
        except Exception as e:
            logging.error(f"Error merging {f}: {e}")
            
    if not master_df.empty:
        # Robust Deduplication
        initial_count = len(master_df)
        
        # 1. Deduplicate by link if available
        if 'link' in master_df.columns:
            master_df.drop_duplicates(subset=['link'], keep='first', inplace=True)
            
        # 2. Deduplicate by content hash (comentario)
        # We normalize content slightly to catch near-duplicates
        def get_content_hash(text):
            if not isinstance(text, str): return ""
            # Basic normalization: lowercase and remove extra whitespace
            norm = " ".join(text.lower().split())
            return hashlib.sha256(norm.encode('utf-8')).hexdigest()
        
        import hashlib
        master_df['_content_hash'] = master_df['comentario'].apply(get_content_hash)
        master_df.drop_duplicates(subset=['_content_hash'], keep='first', inplace=True)
        master_df.drop(columns=['_content_hash'], inplace=True)
        
        final_count = len(master_df)
        print(f"   -> Consolidación finalizada. Filas: {initial_count} -> {final_count} (Eliminados {initial_count - final_count} duplicados)")
        
        # Guardar master
        master_file = f"recoleccion/master_input_{int(time.time())}.csv"
        master_df.to_csv(master_file, index=False)
        print(f"   -> Archivo Maestro generado: {master_file}")
        
        # 3. Sentinel (Análisis Benchmarking)
        run_sentinel(master_file, lexicon_file, skip_ai=skip_ai)
        
        # 4. Generar Reporte V2
        generar_reporte_v2()
        
    else:
        print("El archivo maestro está vacío.")

    print("\n" + "="*60)
    print(" FLUJO COMPETITIVO COMPLETADO")
    print("="*60)

def print_menu():
    print("\n--- SENTINEL MANAGER ---")
    print("1. Ejecutar Escaneo Completo (Harvester + Backlinker + Análisis)")
    print("2. Ejecutar solo Harvester")
    print("3. Ejecutar solo Backlinker")
    print("4. Ejecutar solo Análisis (Sentinel)")
    print("5. Salir")
    return input("Seleccione una opción: ")

def main():
    parser = argparse.ArgumentParser(description="Gestor de Procesos Sentinel")
    parser.add_argument("--mode", choices=["interactive", "full_auto"], default="interactive", help="Modo de ejecución")
    parser.add_argument("--dominio", default="example.com", help="Dominio para backlinker")
    parser.add_argument("--num_results", type=int, default=50, help="Num resultados backlinker")
    parser.add_argument("--iterations", type=int, default=4, help="Iteraciones para backlinker")
    parser.add_argument("--save_raw", action="store_true", help="Guardar resultados crudos del backlinker")
    parser.add_argument("--keywords_file", default=None, help="Archivo de keywords para Harvester")
    parser.add_argument("--lexicon_file", default="config/lexico_personalizado.csv", help="Archivo de lexico para Sentinel")
    parser.add_argument("--targets-file", default="config/targets.json", help="Archivo JSON de targets a analizar")
    parser.add_argument("--delay-between-targets", type=int, default=10, help="Segundos de espera entre cada target")
    parser.add_argument("--skip-ai", action="store_true", help="Omitir análisis con Ollama en Sentinel")
    parser.add_argument("--include-backlinks", action="store_true", help="Incluir búsqueda de backlinks en escaneo completo")
    parser.add_argument("--relaxed", action="store_true", help="Modo relajado de recolección para análisis posterior con IA")
    
    args = parser.parse_args()
    
    setup_directories()
    
    if args.mode == "full_auto":
        full_scan_workflow(args.num_results, args.lexicon_file, args.iterations, args.save_raw,
                          getattr(args, 'targets_file', 'config/targets.json'),
                          getattr(args, 'delay_between_targets', 10),
                          args.skip_ai,
                          args.include_backlinks)
    else:
        while True:
            choice = print_menu()
            
            if choice == "1":
                full_scan_workflow(args.num_results, args.lexicon_file, args.iterations, args.save_raw,
                                  getattr(args, 'targets_file', 'config/targets.json'),
                                  getattr(args, 'delay_between_targets', 10),
                                  args.skip_ai,
                                  args.include_backlinks,
                                  relaxed=args.relaxed)
            elif choice == "2":
                # Ejecución interactiva por defecto
                run_harvester(keywords_file=args.keywords_file, entidad="MiMarca", keywords=["MiMarca"])
            elif choice == "3":
                run_backlinker(domain=args.dominio, entidad="MiMarca", num_results=args.num_results, iterations=args.iterations, save_raw=args.save_raw)
            elif choice == "4":
                # En modo interactivo, intentamos adivinar el último archivo o pedirlo
                latest_harvester = get_latest_file("recoleccion/input_auto_*.csv")
                latest_backlink = get_latest_file("recoleccion/backlinks_*.csv")
                
                print(f"Archivos recientes encontrados:")
                print(f"A. Harvester (Input Auto): {latest_harvester}")
                print(f"B. Backlinker: {latest_backlink}")
                print(f"M. Master File Reciente: {get_latest_file('recoleccion/master_input_*.csv')}")
                print("C. Especificar ruta manual")
                
                sub = input("¿Qué archivo analizar? (A/B/C): ").upper()
                file_to_analyze = None
                
                if sub == "A": file_to_analyze = latest_harvester
                elif sub == "B": file_to_analyze = latest_backlink
                elif sub == "M": file_to_analyze = get_latest_file('recoleccion/master_input_*.csv')
                elif sub == "C": file_to_analyze = input("Ingrese ruta del archivo: ")
                
                if file_to_analyze:
                    run_sentinel(file_to_analyze, args.lexicon_file)
                else:
                    print("No se seleccionó un archivo válido.")
                    
            elif choice == "5":
                print("Saliendo...")
                break
            else:
                print("Opción inválida.")

if __name__ == "__main__":
    main()
