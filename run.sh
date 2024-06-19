#!/bin/bash

TOOL=""
ARGS=()

if [ $# -eq 0 ]; then
    echo "Uso: $0 <TOOL> <ARGUMENTOS>"
    exit 1
fi

# Primer argumento es la herramienta
TOOL="$1"
shift

# Los argumentos restantes son los argumentos para la herramienta
ARGS=("$@")

# Verificar si la herramienta es ejecutable
if ! command -v "$TOOL" > /dev/null 2>&1; then
    echo "Error: La herramienta '$TOOL' no existe o no es ejecutable."
    exit 1
fi

# Ejecutar la herramienta con los argumentos
$TOOL "${ARGS[@]}"
