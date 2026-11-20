"""Avance documental local, no prueba de que el curso o la plataforma estén completos."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    changes = ROOT / "openspec" / "changes"
    missing = []
    for tasks in sorted(changes.glob("*/tasks.md")):
        marks = re.findall(r"^- \[([ xX])\]", tasks.read_text(encoding="utf-8"), re.MULTILINE)
        print(f"{tasks.parent.name}: {sum(mark.lower() == 'x' for mark in marks)}/{len(marks)} tareas")
    for spec in sorted(changes.glob("*/specs/*/spec.md")):
        text = spec.read_text(encoding="utf-8")
        tests = re.findall(r"`(tests/[^`]+\.py)`", text)
        scenarios = len(re.findall(r"^### Scenario:", text, re.MULTILINE))
        absent = [path for path in tests if not (ROOT / path).is_file()]
        if not tests or absent:
            missing.append(str(spec.relative_to(ROOT)))
        print(f"{spec.parent.name}: {scenarios} escenarios, {len(tests)} archivos de tests, faltantes={len(absent)}")
    print("Esto verifica referencias documentales; ejecutar tests y evals por separado.")
    print("004-007: cobertura parcial; no equivalen a un recorrido docente integrado.")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
