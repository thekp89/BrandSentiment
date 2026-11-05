import pandas as pd
import matplotlib.pyplot as plt
from wordcloud import WordCloud, STOPWORDS
import os
import glob
import sys

# Definición de Stopwords Global
STOPWORDS_ES = set([
    "de", "la", "que", "el", "en", "y", "a", "los", "del", "se", "las", "por", "un", "para", 
    "con", "no", "una", "su", "al", "lo", "como", "más", "pero", "sus", "le", "ya", "o", 
    "fue", "este", "ha", "sí", "porque", "esta", "son", "entre", "está", "cuando", "muy", 
    "sin", "sobre", "ser", "tiene", "también", "me", "hasta", "hay", "donde", "quien", 
    "desde", "todo", "nos", "durante", "todos", "uno", "les", "ni", "contra", "otros", 
    "ese", "eso", "ante", "ellos", "e", "esto", "mí", "antes", "algunos", "qué", "unos", 
    "yo", "otro", "otras", "otra", "él", "tanto", "esa", "estos", "mucho", "quienes", 
    "nada", "muchos", "cual", "poco", "ella", "estar", "estas", "algunas", "algo", 
    "nosotros", "mi", "mis", "tú", "te", "ti", "tu", "tus", "ellas", "nosotras", "vosotros", 
    "vosotras", "os", "mío", "mía", "míos", "mías", "tuyo", "tuya", "tuyos", "tuyas", 
    "suyo", "suya", "suyos", "suyas", "nuestro", "nuestra", "nuestros", "nuestras", 
    "vuestro", "vuestra", "vuestros", "vuestras", "es", "soy", "eres", "somos", "sois", 
    "estoy", "estás", "estamos", "estáis", "están", "https", "co", "t", "co", "com", "www", 
    "reddit", "font", "color", "href", "target", "blank", "nbsp", "amp", "click", "here",
    "rt", "dm", "retweet", "fav"
])

def generar_wordcloud(texto, titulo, ruta_salida):
    """
    Genera y guarda una nube de palabras a partir de un texto dado.
    """
    if not texto or len(texto.strip()) == 0:
        print(f"[INFO] No hay suficiente texto para generar la nube: {titulo}")
        return

    try:
        # Configuración visual de la Nube
        wordcloud = WordCloud(
            width=1600, 
            height=800,
            background_color='white',
            stopwords=STOPWORDS_ES,
            min_font_size=10,
            colormap='viridis', # Esquema de colores profesional
            collocations=False  # Evita duplicar palabras compuestas para limpieza
        ).generate(texto)

        # Generar la gráfica
        plt.figure(figsize=(20, 10), facecolor=None)
        plt.imshow(wordcloud)
        plt.axis("off")
        plt.tight_layout(pad=0)
        plt.title(titulo, fontsize=20, pad=20)
        
        # Guardar imagen
        plt.savefig(ruta_salida, dpi=300)
        print(f"[EXITO] Nube de palabras guardada en: {ruta_salida}")
        plt.close()
    except Exception as e:
        print(f"[ERROR] Falló la generación de wordcloud '{titulo}': {e}")

def procesar_texto_desde_df(df, columna='Texto_Limpio'):
    """
    Concatena el texto de la columna especificada del DataFrame.
    Si 'Texto_Limpio' no existe, intenta con 'comentario'.
    """
    col_uso = columna
    if columna not in df.columns:
        if 'comentario' in df.columns:
            col_uso = 'comentario'
        else:
            return ""
            
    # Aseguramos que los valores sean string y eliminamos vacíos
    return " ".join(str(val) for val in df[col_uso].dropna())

def generar_nubes_desde_df(df, output_dir):
    """
    Función principal para integración con el workflow.
    Recibe un DataFrame y genera las nubes en output_dir.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print("--- Iniciando Generación de WordClouds ---")
    
    # Separar MARCA PROPIA de COMPETENCIA
    if "Tipo_Competidor" in df.columns:
        mask_propio = df["Tipo_Competidor"].astype(str).str.contains("Propio|General", case=False, na=False)
        df_marca = df[mask_propio]
        df_competencia = df[~mask_propio]
    elif "Entidad" in df.columns and not df.empty:
        primera_entidad = df["Entidad"].dropna().iloc[0] if not df["Entidad"].dropna().empty else None
        if primera_entidad:
            df_marca = df[df["Entidad"] == primera_entidad]
            df_competencia = df[df["Entidad"] != primera_entidad]
        else:
            df_marca = df
            df_competencia = pd.DataFrame()
    else:
        df_marca = df
        df_competencia = pd.DataFrame()

    # 1. Generar Nube de Marca Propia
    texto_marca = procesar_texto_desde_df(df_marca)
    if texto_marca:
        ruta = os.path.join(output_dir, "Wordcloud_Marca.png")
        generar_wordcloud(texto_marca, "Narrativa Digital - Marca", ruta)

    # 2. Generar Nube de Competencia
    if not df_competencia.empty:
        texto_competencia = procesar_texto_desde_df(df_competencia)
        if texto_competencia:
            ruta = os.path.join(output_dir, "Wordcloud_Competencia.png")
            generar_wordcloud(texto_competencia, "Narrativa Digital - Competencia", ruta)
    
    print("--- WordClouds Finalizados ---")

def encontrar_ultimo_reporte():
    """Busca el archivo reporte_riesgos.csv más reciente en reportes/scan_*"""
    search_path = os.path.join("reportes", "scan_*", "reporte_riesgos.csv")
    files = glob.glob(search_path)
    if not files:
        return None
    # Ordenar por fecha de modificación
    return max(files, key=os.path.getmtime)

if __name__ == "__main__":
    # Modo Standalone
    print("Modo Standalone: Buscando último reporte disponible...")
    
    archivo_input = None
    
    # Si se pasa archivo por argumento
    if len(sys.argv) > 1:
        archivo_input = sys.argv[1]
    else:
        archivo_input = encontrar_ultimo_reporte()

    if archivo_input and os.path.exists(archivo_input):
        print(f"Procesando archivo: {archivo_input}")
        try:
            df = pd.read_csv(archivo_input)
            # El directorio de salida es el mismo donde está el reporte
            output_dir = os.path.dirname(archivo_input)
            generar_nubes_desde_df(df, output_dir)
        except Exception as e:
            print(f"[ERROR] No se pudo procesar el archivo: {e}")
    else:
        print("[ERROR] No se encontró ningún archivo 'reporte_riesgos.csv'. Ejecute el workflow principal primero.")
