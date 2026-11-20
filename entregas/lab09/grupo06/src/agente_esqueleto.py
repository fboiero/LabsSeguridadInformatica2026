#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
# Modificado por el Grupo 06 (octubre 2026): implementación del loop de tool-use
# (ejecución de tools, realimentación al LLM, detección de flags y corte).
# Se distribuye bajo la misma licencia.
"""
agente_esqueleto.py — agente propio del grupo 06. Entregable del Lab 09.

Implementa el loop de tool-use: pide una acción al cliente LLM, la ejecuta con
ejecutar_tool (que aplica el guardrail de alcance), detecta flags en la salida y
devuelve el resultado al cliente. Corta ante una acción "final" o al llegar a
MAX_PASOS.

Uso:
    LLM_PROVIDER=mock python3 agente_esqueleto.py
Con el cliente mock encadena /api/token -> POST /api/vault y trae el flag R5.
"""
import re
import sys
from herramientas import TOOLS, ejecutar_tool
from llm import crear_cliente

SYSTEM = """Sos un agente de pentesting autorizado. Objetivo único: 'phantomcorp'.
Reconocé, enumerá, seguí las pistas y reportá toda FLAG{...}. Una tool por vez."""

MAX_PASOS = 12

def main() -> int:
    cliente = crear_cliente(SYSTEM, TOOLS)
    flags = set()
    resultados = None

    for n in range(1, MAX_PASOS + 1):
        accion = cliente.paso(resultados)

        if accion["tipo"] == "final":
            print(f"[FINAL] {accion['texto']}")
            break

        salida = ejecutar_tool(accion["nombre"], accion["argumentos"])
        print(f"\n[Paso {n}] Tool: {accion['nombre']}")
        print(f"Argumentos: {accion['argumentos']}")
        print(f"Resultado:\n{salida}")

        # Detectar flags en la salida de la tool
        for f in re.findall(r"FLAG\{[^}]*\}", salida):
            flags.add(f)

        # Realimentar al cliente con el resultado para el próximo paso
        resultados = [{"id": accion["id"], "output": salida}]
    else:
        print(f"\n[CORTE] Se alcanzó MAX_PASOS ({MAX_PASOS}) sin acción final.")

    print(f"\n=== Flags encontradas ({len(flags)}) ===")
    for f in sorted(flags):
        print(f"  {f}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
