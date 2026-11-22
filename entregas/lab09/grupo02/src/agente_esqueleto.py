#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Fernando Boiero — CyberLab UTN FRVM
"""
agente_esqueleto.py — TU agente (a completar). Entregable del Lab 09.

El agente de referencia (agente_pentest.py) ya funciona. Este es el TUYO: tiene
el andamiaje, pero el LOOP de tool-use está a medio hacer. Completá los TODO para
entender el mecanismo desde adentro. Un agente no es magia: es este loop.

Cuando funcione, corré:
    LLM_PROVIDER=mock python3 agente_esqueleto.py
y tiene que llegar a encadenar /api/token -> POST /api/vault y traer el flag
capstone que devuelve el vault.
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

        # TODO 1 resuelto: si la acción es "final", imprimimos y cortamos el loop.
        if accion["tipo"] == "final":
            print(f"\n[agente] Fin: {accion['texto']}")
            break

        # TODO 2 resuelto: ejecutamos la tool que el LLM decidió usar.
        nombre, args = accion["nombre"], accion["argumentos"]
        print(f"\n[paso {n}] → {nombre}({args})")
        salida = ejecutar_tool(nombre, args)
        print("\n".join("    " + l for l in salida.splitlines()[:12]))

        for f in re.findall(r"FLAG\{[^}]*\}", salida):
            if f not in flags:
                print(f"    [+] FLAG NUEVA: {f}")
                flags.add(f)

        # TODO 3 resuelto: le devolvemos el resultado al LLM para el próximo paso.
        resultados = [{"id": accion["id"], "output": salida}]
    else:
        print(f"\n[agente] Alcancé el límite de {MAX_PASOS} pasos (guardrail).")

    print(f"\n=== Flags encontradas ({len(flags)}) ===")
    for f in sorted(flags):
        print(f"  {f}")
    return 0

if __name__ == "__main__":
    sys.exit(main())