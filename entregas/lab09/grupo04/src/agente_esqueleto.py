#!/usr/bin/env python3
"""
agente_esqueleto.py — TU agente (completado). Entregable del Lab 09 — Grupo 04.

Cuando funcione, corré:
    LLM_PROVIDER=mock python3 agente_esqueleto.py
y tiene que llegar a encadenar /api/token -> POST /api/vault y traer el flag
capstone (FLAG{agente_esqueleto_completo}).
"""
from pathlib import Path
import re
import sys

_SRC_LAB09 = Path(__file__).resolve().parents[4] / "labs" / "lab09-agentes" / "src"
if _SRC_LAB09.exists() and str(_SRC_LAB09) not in sys.path:
    sys.path.insert(0, str(_SRC_LAB09))

from herramientas import TOOLS, ejecutar_tool
from llm import crear_cliente

SYSTEM = """Sos un agente de pentesting autorizado. Objetivo único: 'phantomcorp'.
Reconocé, enumerá, seguí las pistas y reportá toda FLAG{...}. Una tool por vez."""

MAX_PASOS = 12


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    cliente = crear_cliente(SYSTEM, TOOLS)
    flags = set()
    resultados = None

    for n in range(1, MAX_PASOS + 1):
        accion = cliente.paso(resultados)

        # TODO 1: si la acción es de tipo "final", imprimí el texto y salí del loop.
        if accion.get("tipo") == "final":
            print(f"\n[agente] Fin: {accion.get('texto', '')}")
            break

        # TODO 2: si es una tool, ejecutala con ejecutar_tool(nombre, argumentos)
        #         y guardá la salida. Pista: accion["nombre"], accion["argumentos"].
        nombre = accion["nombre"]
        argumentos = accion["argumentos"]
        print(f"\n[paso {n}] → {nombre}({argumentos})")
        salida = ejecutar_tool(nombre, argumentos)
        print("\n".join("    " + l for l in salida.splitlines()[:12]))

        # (esto ya está: detectar flags en la salida)
        for f in re.findall(r"FLAG\{[^}]*\}", salida):
            if f not in flags:
                print(f"    [+] FLAG NUEVA: {f}")
                flags.add(f)

        # TODO 3: devolvele el resultado al LLM para el próximo paso. El formato es
        #         una lista con un dict {"id": accion["id"], "output": salida}.
        resultados = [{"id": accion["id"], "output": salida}]
    else:
        print(f"\n[agente] Alcancé el límite de {MAX_PASOS} pasos (guardrail).")

    print(f"\n=== Flags encontradas ({len(flags)}) ===")
    for f in sorted(flags):
        print(f"  {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
