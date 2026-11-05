---
description: Ciclo completo de Inteligencia y Monitoreo de Marca con IA
---

Sigue estos pasos para realizar un escaneo completo de reputación y seguridad:

1. **Preparar el Entorno**:
   Asegúrate de que Ollama esté corriendo con el modelo Mistral:
   ```bash
   ollama serve
   # En otra terminal verifica con:
   ollama list
   ```

2. **Limpiar Datos Previos (Opcional)**:
   Si deseas empezar un escaneo desde cero:
   ```bash
   python3 -c "import shutil, os; [shutil.rmtree(os.path.join(d, f)) for d in ['reportes', 'recoleccion'] for f in os.listdir(d) if os.path.isdir(os.path.join(d, f))]"
   ```

// turbo
3. **Ejecutar Escaneo Inteligente**:
   Inicia el orquestador en modo automático. La IA filtrará el ruido y analizará riesgos de seguridad automáticamente.
   ```bash
   ./venv/bin/python Manager.py --mode full_auto --iterations 1
   ```

4. **Monitorear Decisiones de la IA**:
   Observa en tiempo real cómo Mistral descarta ruido o identifica amenazas:
   ```bash
   tail -f logs/auditoria_sentimiento.log
   ```

5. **Revisar Inteligencia Generada**:
   Los reportes finales con categorización DREAD (Riesgo, Categoría, Acción Sugerida) se encuentran en:
   `reportes/scan_YYYYMMDD_HHMMSS/reporte_riesgos.csv`
   
   También se genera evidencia visual (Nubes de Palabras) de la narrativa digital en:
   - `Wordcloud_Marca.png`
   - `Wordcloud_Competencia.png`

6. **Protocolo de Escalada**:
   Si el archivo contiene registros con `AI_Risk` en `CRÍTICO` o `ALTO`, revisa la columna `AI_Action` y escala al equipo de TI si es necesario.
