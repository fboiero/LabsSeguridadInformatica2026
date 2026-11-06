#!/usr/bin/env python3
"""
riesgo.py — Laboratorio 04. Riesgo cuantitativo. Solo biblioteca estándar.

La gestión de la seguridad no es opinión: se mide. Este script da el
vocabulario cuantitativo (ALE, SLE, ARO) para PRIORIZAR con números.

Uso (desde la carpeta del grupo):
    python src/riesgo.py ale --sle 50000 --aro 0.4
    python src/riesgo.py roi --antes 20000 --despues 5000 --costo 8000
    python src/riesgo.py priorizar --archivo riesgos.json
    python src/riesgo.py              # sin argumentos: demo + autoverificación
"""
import argparse, json, sys
from pathlib import Path

try:  # evita errores de acentos en consolas de Windows
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass


def ale(sle: float, aro: float) -> float:
    """Annualized Loss Expectancy = SLE (pérdida por evento) x ARO (eventos/año)."""
    if sle < 0 or aro < 0:
        raise ValueError("SLE y ARO no pueden ser negativos")
    return sle * aro


def roi_control(ale_antes: float, ale_despues: float, costo_anual: float) -> float:
    """ROI de un control = (pérdida evitada - costo) / costo.
    pérdida evitada = ale_antes - ale_despues. >0 significa que el control se paga."""
    if costo_anual <= 0:
        raise ValueError("El costo anual del control debe ser mayor que 0")
    perdida_evitada = ale_antes - ale_despues
    return (perdida_evitada - costo_anual) / costo_anual


def priorizar(riesgos: list) -> list:
    """Recibe una lista de dicts {nombre, sle, aro}, agrega su 'ale' y los devuelve
    ordenados por ALE descendente (el riesgo más costoso primero)."""
    resultado = []
    for r in riesgos:
        faltan = [k for k in ("nombre", "sle", "aro") if k not in r]
        if faltan:
            raise ValueError(f"Riesgo {r!r}: faltan los campos {faltan}")
        item = dict(r)  # copia: no mutamos la entrada
        item["ale"] = ale(float(r["sle"]), float(r["aro"]))
        resultado.append(item)
    return sorted(resultado, key=lambda x: x["ale"], reverse=True)


def mostrar_ranking(archivo) -> None:
    with open(archivo, encoding="utf-8") as f:
        datos = json.load(f)
    ordenados = priorizar(datos)
    total = sum(r["ale"] for r in ordenados)
    for i, r in enumerate(ordenados, 1):
        print(f"{i:>2}. {r['ale']:>12.2f}  {r['nombre']}")
    print(f"    {total:>12.2f}  TOTAL (ALE anual de la organización)")


def demo() -> int:
    """Sin argumentos: muestra ejemplos y verifica los resultados esperados."""
    print("== Autoverificación (valores del enunciado) ==")
    assert abs(ale(50000, 0.4) - 20000.0) < 1e-9
    print("ale(50000, 0.4)                  = 20000.00  OK")
    assert abs(roi_control(20000, 5000, 8000) - 0.875) < 1e-9
    print("roi_control(20000, 5000, 8000)   = 0.875     OK")
    try:
        roi_control(1, 0, 0)
        raise AssertionError("debió fallar con costo 0")
    except ValueError:
        print("roi_control con costo 0          -> ValueError  OK")

    archivo = Path(__file__).resolve().parent.parent / "riesgos.json"
    print(f"\n== Ranking de {archivo.name} ==")
    if archivo.exists():
        mostrar_ranking(archivo)
    else:
        print("(no se encontró riesgos.json junto a la carpeta src/)")
    print("\nTambién podés usar: ale | roi | priorizar  (ver --help)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Riesgo cuantitativo (Lab 04).")
    sub = ap.add_subparsers(dest="cmd")  # opcional: sin cmd corre la demo
    p = sub.add_parser("ale"); p.add_argument("--sle", type=float, required=True); p.add_argument("--aro", type=float, required=True)
    p = sub.add_parser("roi"); p.add_argument("--antes", type=float, required=True); p.add_argument("--despues", type=float, required=True); p.add_argument("--costo", type=float, required=True)
    p = sub.add_parser("priorizar"); p.add_argument("--archivo", required=True, help="JSON con lista de {nombre,sle,aro}")
    a = ap.parse_args()
    try:
        if a.cmd is None:
            return demo()
        if a.cmd == "ale":
            print(f"{ale(a.sle, a.aro):.2f}")
        elif a.cmd == "roi":
            print(f"{roi_control(a.antes, a.despues, a.costo):.3f}")
        elif a.cmd == "priorizar":
            mostrar_ranking(a.archivo)
    except (ValueError, OSError, json.JSONDecodeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())