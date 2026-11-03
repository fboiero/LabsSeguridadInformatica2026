#!/usr/bin/env bash
# Verificación de integridad y cadena de custodia (Lab 11 - Parte 1).
# Uso: ./verificar_custodia.sh [DIRECTORIO_CASO]
set -euo pipefail
CASO_DIR="${1:-labs/lab11-forensia/caso}"

echo "=== Verificando integridad de la evidencia en $CASO_DIR ==="
cd "$CASO_DIR"

if [ ! -f evidencia.sha256 ]; then
    echo "[!] No se encontró evidencia.sha256 en $CASO_DIR"
    exit 1
fi

# Ejecutar verificación de hashes
sha256sum -c evidencia.sha256 || true
echo
echo "=== Análisis del archivo que falló la custodia ==="
if [ -f logs/auth.log ]; then
    echo "Líneas de alerta y marcador recuperado en logs/auth.log:"
    grep -E 'FAILED|alterad|marcador|FLAG' logs/auth.log || true
fi
