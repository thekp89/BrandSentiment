# Brand Sentiment & Cyber Intelligence Sentinel

Plataforma unificada de Inteligencia y Reputación de Marca. Este sistema automatizado no solo monitorea la presencia y el sentimiento de marca en múltiples canales, sino que también detecta riesgos de seguridad mediante OSINT, realiza auditorías de superficie de ataque y rastrea enlaces tóxicos (backlinks), ofreciendo un Dashboard Web avanzado con reportes analíticos para la toma de decisiones.

---

## 🚀 Características Principales

### 1. Dashboard Web y Entorno Gráfico (Flask + Chart.js)
El corazón visual de la plataforma. Permite gestionar y monitorear los diferentes escaneos sin depender exclusivamente de la consola.
*   **Visión General**: Métricas de polaridad de marca, distribución en tiempo real y detección de ruido.
*   **Módulo de Ciberinteligencia (SpiderFoot)**: Comparativa de escaneos históricos, visualización de nodos de red (D3.js) y tablas interactivas de riesgos y vulnerabilidades.
*   **Módulo Forense (Backlinks)**: Dashboard tipo *Heatmap* para visualizar Key Risk Indicators (KRI) de enlaces entrantes, Autoridad de Dominio e indicadores de toxicidad en directorios y sitios externos.
*   **Motor de Reportes PDF Profesionales**: Permite seleccionar módulos activos (Sentimiento, Forense, OSINT) agregando *Objetivos de Análisis Individuales* para compilar y generar reportes confidenciales para la gerencia listos para imprimir.

### 2. Harvester & Sentinel (Motor de OSINT y Sentimiento)
*   **Recolección Extensiva**: Busca menciones en Google News, Reddit y diversas redes sociales. Emplea *Google Dorks* para buscar fugas de información.
*   **IA Local Integrada**: Se apoya en agentes locales como **Mistral 7B / Llama** (mediante Ollama) para clasificar con precisión menciones ambiguas, distinguir qué es ruido, qué es promoción y cuál es el sentimiento real.
*   **Framework DREAD**: Aplicado a menciones que denotan incidentes críticos de seguridad.

### 3. Backlinker y Mantenimiento Automatizado
*   Búsqueda iterativa para mapear la huella profunda y generar alertas sobre dominios sospechosos.
*   Gestión automática de almacenamiento: compresión automática de datos históricos (ZIP en `backup/`) tras 30 días de antigüedad, asegurando optimización en el disco.

---

## 🛠️ Requisitos e Instalación

### Requisitos del Sistema
1.  **Python 3.10+** (Recomendado 3.11).
2.  **Ollama**: Instalado localmente y en ejecución. Debes descargar los modelos previstos en el código (ej. Mistral o el que estés utilizando): `ollama run mistral`.
3.  **WeasyPrint (Generador de PDFs)**: Esta librería requiere dependencias a nivel sistema operativo. En sistemas basados en Debian/Ubuntu:
    ```bash
    sudo apt-get install build-essential python3-dev python3-pip python3-setuptools python3-wheel python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
    ```
    *Para otros sistemas (macOS/Windows) consulta la [documentación oficial de WeasyPrint](https://weasyprint.org/).*

### Instalación Paso a Paso
1.  **Clonar este repositorio:**
    ```bash
    git clone https://github.com/tu-usuario/BrandSentiment.git
    cd BrandSentiment
    ```
2.  **Crear y activar el Entorno Virtual:**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    # En Windows: .venv\Scripts\activate
    ```
3.  **Instalar las dependencias de Python:**
    ```bash
    pip install -r requirements.txt
    ```

---

## ⚙️ Configuración del Entorno (`config/`)

Antes de correr el sistema, configura los archivos necesarios según la marca o entidad a monitorear:

*   **`.env`**: Crea este archivo (puedes basarte en `.env.example`) y define las variables principales:
    ```env
    USE_OLLAMA=true
    ALERT_RECIPIENT=admin@example.com
    # Otras variables como SMTP si fuera necesario
    ```
*   `config/targets.json`: Archivo maestro donde defines qué marcas/instituciones y competidores se van a monitorear.
*   `config/keywords_identidad.txt`: Palabras específicas para filtrar falsos positivos. Define aquí sinónimos de la marca propia.
*   `config/keywords_riesgo_seguridad.txt`: Palabras que detonarán alertas críticas (leak, hacker, vulnerable).
*   `config/dorks_avanzados.txt`: Consultas especializadas con placeholders `{TARGET_BRAND}` y `{TARGET_DOMAIN}` para detectar información expuesta.

---

## 💻 Uso de la Plataforma

### 1. Iniciar el Dashboard Web (Interfaz Gráfica)
Es la manera más fácil de gestionar los reportes y visualizaciones.
```bash
# Asegúrate de tener tu entorno activado
python3 web/app.py
```
> Accede desde tu navegador a: **https://localhost:5000** (O http si ejecutas sin certificados SSL).
> *Usuario por defecto: admin / sentinel2026 (Consulta web/app.py para modificar esto).*

### 2. Ejecución Global del Pipeline Automático (CLI)
Para recolectar y analizar datos masivos en el backend antes de visualizarlos, usa el Manager.
```bash
python3 Manager.py --mode full_auto --iterations 5 --save_raw
```
*   `--mode full_auto`: Ejecuta los módulos Harvester (Búsqueda), Backlinker (Enlaces) y Sentinel (Análisis IA).
*   `--save_raw`: Crea una copia de las menciones directas sin procesar en la carpeta `recoleccion/raw`.

### 3. Ejecución Modular (Avanzado)
Puedes invocar módulos de forma individual si solo necesitas datos específicos:
*   **Solo OSINT/Sentimiento**:
    ```bash
    python3 Harvester.py --entidad MiMarca
    python3 Sentinel.py --archivo recoleccion/archivo_x.csv
    ```
*   **Solo Backlinks**:
    ```bash
    python3 Backlinker.py --dominio mimarca.com --entidad MiMarca
    ```

## 📁 Estructura del Proyecto

*   `Manager.py`: Orquestador principal del pipeline de recolección y análisis.
*   `Harvester.py`: Módulo de recolección de menciones y OSINT en redes y motores de búsqueda.
*   `Sentinel.py`: Motor de clasificación de sentimiento y análisis de riesgo con IA local.
*   `Backlinker.py`: Módulo de auditoría de enlaces entrantes y cálculo de KRI.
*   `Forensics.py`: Procesador forense y base de datos para análisis de enlaces y amenazas.
*   `Graficador.py`: Generador de visualizaciones y nubes de palabras (WordClouds).
*   `web/`: Dashboard interactivo (Flask, Jinja2, Chart.js, Vis.js).
*   `config/`: Archivos de configuración de objetivos, palabras clave y fuentes oficiales.
*   `recoleccion/` y `reportes/`: Directorios generados dinámicamente donde se consolidan archivos CSV e informes generados.
*   `uploads/`: Directorio temporal para la subida de datos manuales hacia el módulo Forense.
*   `logs/`: Registro de auditoría y ejecución de scripts.
