#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
agente_esqueleto.py — TU agente (completado por Grupo 12). Entregable del Lab 09.

El agente de referencia (agente_pentest.py) ya funciona. Este es el TUYO: tiene
el andamiaje y el LOOP de tool-use completo para entender el mecanismo desde
adentro. Un agente no es magia: es este loop.

Cuando funcione, corré:
    LLM_PROVIDER=mock python3 agente_esqueleto.py
y llega a encadenar /api/token -> POST /api/vault y traer el flag capstone que
devuelve el vault.
"""
from pathlib import Path
import re
import sys

# Permitir importar 'herramientas' y 'llm' tanto al ejecutarse desde
# labs/lab09-agentes/src/ como desde entregas/lab09/grupo12/src/
_LAB_SRC = Path(__file__).resolve().parents[4] / "labs" / "lab09-agentes" / "src"
if _LAB_SRC.is_dir() and str(_LAB_SRC) not in sys.path:
    sys.path.insert(0, str(_LAB_SRC))

from herramientas import TOOLS, ejecutar_tool  # noqa: E402
from llm import crear_cliente  # noqa: E402

SYSTEM = """Sos un agente de pentesting autorizado. Objetivo único: 'phantomcorp'.
Reconocé, enumerá, seguí las pistas y reportá toda FLAG{...}. Una tool por vez."""

MAX_PASOS = 12


def main() -> int:
    cliente = crear_cliente(SYSTEM, TOOLS)
    flags = set()
    resultados = None

    for n in range(1, MAX_PASOS + 1):
        accion = cliente.paso(resultados)

        # TODO 1: si la acción es de tipo "final", imprimí el texto y salí del loop.
        if accion.get("tipo") == "final":
            print(f"\n[agente] Fin ({n} pasos): {accion.get('texto', '')}")
            break

        # TODO 2: si es una tool, ejecutala con ejecutar_tool(nombre, argumentos)
        #         y guardá la salida. Pista: accion["nombre"], accion["argumentos"].
        nombre = accion["nombre"]
        argumentos = accion["argumentos"]
        print(f"\n[paso {n}/{MAX_PASOS}] -> {nombre}({argumentos})")
        salida = ejecutar_tool(nombre, argumentos)
        for linea in salida.splitlines()[:12]:
            print(f"    {linea}")

        # (esto ya está: detectar flags en la salida)
        for f in re.findall(r"FLAG\{[^}]*\}", salida):
            if f not in flags:
                print(f"    [+] Flag detectada: {f}")
            flags.add(f)

        # TODO 3: devolvele el resultado al LLM para el próximo paso. El formato es
        #         una lista con un dict {"id": accion["id"], "output": salida}.
        resultados = [{"id": accion["id"], "output": salida}]
    else:
        print(f"\n[agente] Se alcanzó el límite máximo de {MAX_PASOS} pasos (guardrail).")

    print(f"\n=== Flags encontradas ({len(flags)}) ===")
    for f in sorted(flags):
        print(f"  {f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
