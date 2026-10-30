#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
recolector.py — entregable del Lab 08 (automatización).

El R5 te pidió encontrar, entre 250 legajos, el que esconde el flag. Lo hiciste
con un `for` en bash. Ahora convertí eso en una HERRAMIENTA de verdad: un script
que enumera, filtra y reporta. Esto es el paso previo a un agente: vos definís la
LÓGICA; la máquina ejecuta la repetición.

Corré esto DENTRO del host comprometido (make shell-victima), porque el host
interno solo se alcanza desde ahí:

    python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250

Solo biblioteca estándar (urllib). No agregues dependencias.
"""
import argparse
import json
import sys
import urllib.request
import urllib.error


# Claves que trae un legajo "normal". Cualquier clave fuera de este conjunto
# (p. ej. 'legajo_oculto') delata al registro que esconde el flag.
CLAVES_NORMALES = {"id", "nombre", "area"}


def consultar_legajo(base: str, id_: int, timeout: float = 3.0) -> dict | None:
    """Pide /empleado?id=<id_> y devuelve el dict de la respuesta, o None si falla.

    Ya está implementada como referencia: mostrá el patrón de request con la
    biblioteca estándar. Leela antes de completar lo de abajo.
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


def _extraer_flag(registro: dict) -> str | None:
    """Devuelve el flag si el registro lo esconde, o None.

    Dos señales, por robustez:
      1. Tiene una clave que los legajos normales no tienen (CLAVES_NORMALES).
      2. Algún valor contiene la cadena 'FLAG{'.
    Alcanza con que se cumpla cualquiera de las dos.
    """
    # Señal 1: clave inesperada.
    claves_extra = set(registro.keys()) - CLAVES_NORMALES
    for clave in claves_extra:
        valor = str(registro[clave])
        if "FLAG{" in valor:
            return valor

    # Señal 2: cualquier valor con forma de flag (red de seguridad).
    for valor in registro.values():
        if isinstance(valor, str) and "FLAG{" in valor:
            return valor

    return None


def buscar_flag(base: str, desde: int, hasta: int) -> tuple[int, str] | None:
    """Recorre los legajos [desde, hasta] y devuelve (id, flag) del que tenga el
    flag, o None si no aparece.

    - Para cada id, usa consultar_legajo().
    - El legajo con el flag trae una clave distinta a los normales
      (los normales tienen 'nombre' y 'area'): la detecta _extraer_flag().
    - Apenas lo encuentra, devuelve (id, flag) y corta: no sigue de gusto.
    """
    for id_ in range(desde, hasta + 1):
        registro = consultar_legajo(base, id_)
        if registro is None:
            continue  # legajo inexistente o error: seguimos

        flag = _extraer_flag(registro)
        if flag is not None:
            return id_, flag

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
