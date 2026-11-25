"""Corrida complementaria de C: referencia autorizada, resultados completos aparte.

Ejecutar desde la raíz del repo. No modifica los módulos de la cátedra.
"""
import json
import os
from pathlib import Path
import sys

RAIZ = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(RAIZ / "labs/lab09-agentes/src"))
import agente_pentest


def main():
    os.environ["LLM_PROVIDER"] = "mock"
    ejecutar_original = agente_pentest.ejecutar_tool
    with open(sys.argv[1], "w", encoding="utf-8") as archivo:
        def registrar(nombre, argumentos):
            salida = ejecutar_original(nombre, argumentos)
            archivo.write(json.dumps({"tool": nombre, "argumentos": argumentos,
                                      "output": salida}, ensure_ascii=False) + "\n")
            archivo.flush()
            return salida
        agente_pentest.ejecutar_tool = registrar
        return agente_pentest.main()


if __name__ == "__main__":
    raise SystemExit(main())
