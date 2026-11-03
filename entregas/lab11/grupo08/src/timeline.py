#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
timeline.py — Ampliación del Lab 11. Reconstruí la línea de tiempo del ataque
automáticamente, en vez de leer el log a ojo. Solo biblioteca estándar.

Analizar a mano 20 líneas se puede; analizar 200.000 no. Por eso el forense
scriptea. Desde este directorio:

    python3 timeline.py ../../../../labs/lab11-forensia/caso/logs/access.log --ip 185.220.101.42
"""
import argparse
import re
import sys

# Formato nginx combined:  IP - - [fecha] "METODO ruta HTTP/x" status ...
LOG_RE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3})')

def parsear_linea(linea: str):
    """Devuelve {ip, ts, metodo, ruta, status} o None si la línea no matchea
    (comentarios, tráfico raro). YA IMPLEMENTADA."""
    m = LOG_RE.match(linea)
    if not m:
        return None
    ip, ts, metodo, ruta, status = m.groups()
    return {"ip": ip, "ts": ts, "metodo": metodo, "ruta": ruta, "status": int(status)}


def construir_timeline(path: str, ip: str = None) -> list:
    """Recorre el log, parsea cada línea y devuelve la lista de eventos.
    Si `ip` no es None, filtra SOLO los eventos de esa IP (la del atacante).
    El log ya viene en orden cronológico; no hace falta reordenar."""
    eventos = []
    with open(path, encoding="utf-8", errors="replace") as log:
        for linea in log:
            evento = parsear_linea(linea)
            if evento is None:
                continue
            if ip is not None and evento["ip"] != ip:
                continue
            eventos.append(evento)
    return eventos


def clasificar_fase(ruta: str) -> str:
    """Mapea una petición a la fase del ataque, para etiquetar la timeline.
    Devuelve RECON · ENUM · EXPLOIT · RCE · WEBSHELL · EXFIL, u OTRO si la ruta
    no corresponde a ninguna fase.

    El orden importa: va de la fase más específica a la más general. El `wget`
    que baja shell.php viaja por /api/reporte?cmd=, y /portal-rrhh/login contiene
    a /portal-rrhh. Solo mira la ruta: "/" es RECON también para un usuario
    legítimo, así que la etiqueta tiene sentido filtrando con --ip.
    """
    if "clientes" in ruta:
        return "EXFIL"
    if "shell.php" in ruta:
        return "WEBSHELL"
    if "cmd=" in ruta:
        return "RCE"
    if "/portal-rrhh/login" in ruta or "/backup/rrhh.conf" in ruta:
        return "EXPLOIT"
    if ruta in ("/robots.txt", "/admin", "/login", "/backup", "/portal-rrhh", "/uploads"):
        return "ENUM"
    if ruta == "/":
        return "RECON"
    return "OTRO"


def main() -> int:
    ap = argparse.ArgumentParser(description="Timeline forense de un access.log.")
    ap.add_argument("log")
    ap.add_argument("--ip", default=None, help="filtrar por la IP del atacante")
    a = ap.parse_args()
    eventos = construir_timeline(a.log, a.ip)
    print(f"[*] {len(eventos)} eventos" + (f" de {a.ip}" if a.ip else ""))
    for e in eventos:
        print(f"  {e['ts']}  {e['metodo']:4s} {e['ruta']:40s} [{clasificar_fase(e['ruta'])}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
