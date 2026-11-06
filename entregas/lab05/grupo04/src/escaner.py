#!/usr/bin/env python3
"""
escaner.py — Ampliación OPCIONAL del Lab 05.

Uso previsto (desde la consola del atacante, con el lab levantado):

    python3 escaner.py phantomcorp --puertos 1-1000
    python3 escaner.py phantomcorp --puertos 21,80,8080,31337 --banner
"""
import argparse
import socket
import sys


def probar_puerto(host: str, puerto: int, timeout: float = 0.5) -> bool:
    """Devuelve True si el puerto TCP está ABIERTO (aceptó la conexión).

    'connect': un socket, un connect con timeout, y la respuesta del sistema operativo. Si connect_ex devuelve 0,
    hubo three-way handshake completo → puerto abierto.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, puerto)) == 0


# ── B.1 — Parsear el rango de puertos. TODO ─────────────────────────────────
def parsear_puertos(spec: str) -> list[int]:
    """Convierte '21,80,8080' o '1-1000' (o mezcla) en una lista de ints.

    Ejemplos:
        '21,80,8080'  -> [21, 80, 8080]
        '1-3'         -> [1, 2, 3]
        '80,100-102'  -> [80, 100, 101, 102]

    Requisitos:
      - Aceptar puertos sueltos separados por coma y rangos con guion.
      - Validar que estén en 1..65535; si no, error claro y salir con código 2.
      - Sin duplicados y ordenados.
    """
    puertos: set[int] = set()
    for parte in spec.split(","):
        parte = parte.strip()
        if not parte:
            continue
        try:
            if "-" in parte:
                ini_s, fin_s = parte.split("-", 1)
                ini, fin = int(ini_s), int(fin_s)
                if ini > fin:
                    raise ValueError(f"rango invertido: '{parte}'")
                rango = range(ini, fin + 1)
            else:
                rango = range(int(parte), int(parte) + 1)
        except ValueError as e:
            print(f"[!] Especificación de puertos inválida ('{parte}'): {e}",
                  file=sys.stderr)
            sys.exit(2)
        for p in rango:
            if not 1 <= p <= 65535:
                print(f"[!] Puerto fuera de rango (1..65535): {p}",
                      file=sys.stderr)
                sys.exit(2)
            puertos.add(p)
    if not puertos:
        print("[!] No se especificó ningún puerto.", file=sys.stderr)
        sys.exit(2)
    return sorted(puertos)


# ── B.2 — Banner grabbing. TODO ──────────────────────────────────────────────
def leer_banner(host: str, puerto: int, timeout: float = 1.0) -> str:
    """Conecta al puerto y devuelve hasta 256 bytes que el servicio envíe.
    """
    try:
        with socket.create_connection((host, puerto), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                datos = s.recv(256)
            except OSError:  # incluye socket.timeout: el servicio no habla primero
                return ""
    except OSError:
        return ""
    return datos.decode(errors="replace").strip()


def main() -> int:
    ap = argparse.ArgumentParser(description="Mini escáner TCP connect (Lab 05).")
    ap.add_argument("host", help="host o IP objetivo (ej: phantomcorp)")
    ap.add_argument("--puertos", default="1-1024",
                    help="lista/rango de puertos. Ej: 21,80 o 1-1000")
    ap.add_argument("--banner", action="store_true",
                    help="intentar leer el banner de cada puerto abierto")
    ap.add_argument("--timeout", type=float, default=0.5)
    args = ap.parse_args()

    puertos = parsear_puertos(args.puertos)
    print(f"[*] Escaneando {args.host} — {len(puertos)} puertos...")
    abiertos = []
    for p in puertos:
        if probar_puerto(args.host, p, args.timeout):
            abiertos.append(p)
            linea = f"  {p:>5}/tcp  ABIERTO"
            if args.banner:
                b = leer_banner(args.host, p)
                if b:
                    linea += f"   banner: {b!r}"
            print(linea)
    print(f"[*] Listo. {len(abiertos)} puerto(s) abierto(s): {abiertos}")
    # Código de salida: 0 si no se encontró nada abierto, 1 si sí (útil en scripts).
    return 1 if abiertos else 0


if __name__ == "__main__":
    sys.exit(main())