#!/bin/bash

# Obtener el directorio donde reside el script
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Activar entorno virtual si existe
if [ -d "$SCRIPT_DIR/venv" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

# Ejecutar el Manager en modo automático
# Se puede personalizar el dominio o keywords aquí si se desea
echo "Iniciando escaneo diario: $(date)" >> "$SCRIPT_DIR/auditoria_manager.log"
python3 "$SCRIPT_DIR/Manager.py" --mode full_auto --num_results 50

echo "Escaneo diario finalizado: $(date)" >> "$SCRIPT_DIR/auditoria_manager.log"
