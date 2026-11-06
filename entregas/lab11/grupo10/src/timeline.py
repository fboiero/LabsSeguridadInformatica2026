#!/usr/bin/env python3
"""Genera una vista filtrada del access.log del caso Lab 11.

Esta ampliacion solo lee el log. La salida es una ayuda para ordenar eventos;
no reemplaza la correlacion manual con evidencia de disco y memoria.
"""

import argparse
import re
import sys
from pathlib import Path


LOG_RE = re.compile(r'^([^ ]+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3})')


def parsear_linea(linea: str):
    """Devuelve los campos relevantes de nginx combined o None."""
    match = LOG_RE.match(linea)
    if not match:
        return None
    ip, timestamp, metodo, ruta, status = match.groups()
    return {
        "ip": ip,
        "ts": timestamp,
        "metodo": metodo,
        "ruta": ruta,
        "status": int(status),
    }


def construir_timeline(path: str, ip: str | None = None) -> list[dict]:
    """Lee un access.log, descarta comentarios y opcionalmente filtra por IP."""
    eventos = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as log:
        for linea in log:
            evento = parsear_linea(linea)
            if evento is not None and (ip is None or evento["ip"] == ip):
                eventos.append(evento)
    return eventos


def clasificar_fase(ruta: str) -> str:
    """Asigna una etiqueta orientativa según la ruta observada."""
    ruta_lower = ruta.lower()
    if "/portal-rrhh/login" in ruta_lower:
        return "EXPLOIT"
    if "/api/reporte" in ruta_lower and "cmd=" in ruta_lower:
        if "wget" in ruta_lower or "shell.php" in ruta_lower:
            return "WEBSHELL"
        return "RCE"
    if "shell.php" in ruta_lower:
        if "clientes.db.txt" in ruta_lower:
            return "ACCESO/EXFIL"
        return "WEBSHELL"
    if ruta_lower == "/" or "robots.txt" in ruta_lower:
        return "RECON"
    if any(fragmento in ruta_lower for fragmento in ("/admin", "/login", "/backup", "/portal-rrhh", "/uploads")):
        return "ENUM"
    if "clientes" in ruta_lower or "upload" in ruta_lower:
        return "ACCESO/EXFIL"
    return "OTRO"


def main() -> int:
    parser = argparse.ArgumentParser(description="Vista cronologica de un access.log")
    parser.add_argument("log", help="ruta al access.log")
    parser.add_argument("--ip", default=None, help="filtrar por la IP investigada")
    args = parser.parse_args()

    try:
        eventos = construir_timeline(args.log, args.ip)
    except OSError as error:
        print(f"Error al leer el log: {error}", file=sys.stderr)
        return 2

    sufijo = f" de {args.ip}" if args.ip else ""
    print(f"[+] {len(eventos)} eventos{sufijo}")
    for evento in eventos:
        print(
            f"{evento['ts']}  {evento['ip']:<15} {evento['metodo']:<5} "
            f"{evento['ruta']:<75} [{evento['status']}] [{clasificar_fase(evento['ruta'])}]"
        )
    print("\nNota: esto ordena el access.log; correlaciona manualmente con disco y memoria.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
