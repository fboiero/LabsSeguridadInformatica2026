# Archivado — Change 007

Fecha de consolidación: 2026-11-18. Archivó: P5, a pedido de P1 (task 3.6).

**Revisión cruzada (1.3): no realizada.** El diseño y el delta los redactó P5 en
reemplazo de P1; la revisión la tiene que hacer otro integrante. Si pide
cambios, se abren en un change nuevo.

Se incorporaron a `openspec/specs/reporting/spec.md`, después de los requisitos
vigentes, que se conservaron:

- los Requirements de `p3/proposal.md` (P3, tasks 2.3 y 2.4: CVSS v4.0 estricto
  junto a EPSS, estructura PTES §7);
- el delta `specs/reporting/spec.md` (P5: estado respaldado por la bitácora,
  referencias verificables, versionado, entrega con aprobación registrada, datos
  sensibles, exportación a DefectDojo, procedencia de etapas, divulgación y
  recorrido de un comando).

La línea `Tests:` suma `tests/test_reporting_p3.py` y `tests/test_reporting_e2e.py`.

## Quién hizo qué

| Tasks | Responsable |
|---|---|
| 1.1, 1.2, 3.2, 3.4, 3.6 | P5, en reemplazo de P1 y con su acuerdo |
| 2.3, 2.4 | P3 |
| 3.1, 3.3 | P2 |
| 2.1, 2.2, 2.5, 2.6, 3.5 | P5 |
| 1.3 | Pendiente: otro integrante |

## Verificación ejecutada

- Suite completa en el runner del lab (Python 3.12): ver `P5-007-final.txt`.
- Mutaciones M18 a M29: todas detectadas (`entrega/mutaciones.md`).
- Recorrido real contra el lab (`entrega/evidencia/salidas/P5-recorrido-02/`),
  ejecutado por P5 con dos terminales y aprobaciones registradas por la CLI:
  - recon real: `STOPPED` por grafo estabilizado, activos `dvwa.lab.test` y
    `juiceshop.lab.test`;
  - validación real en el sandbox: DVWA-HDR, DVWA-CSP y DVWA-COOKIE validados
    en los dos intentos; JUICE-HDR no validado (no se observó la debilidad);
  - informe DEMO porque el análisis es `fixture`: la entrega quedó `BLOCKED` y
    no se exportó a DefectDojo;
  - `python -m harness.pipeline verify`: las dos bitácoras exportadas `ok`.

## Límites conocidos

- El análisis es simulado hasta que exista el change 005 (P4). Hasta entonces
  ningún informe del recorrido se puede entregar ni exportar, por diseño.
- La exportación a DefectDojo se probó con tests y con una **prueba de formato**
  en una instancia local: los 4 hallazgos del informe DEMO, marcados `[DEMO]`, se
  importaron con *Generic Findings Import* y al re-importar no se duplicaron
  (`P5-defectdojo-prueba-formato.txt`). Todavía no se importó un informe
  entregado, porque el recorrido solo entrega cuando el análisis es real.
- `deliver(report, reviewer_approved)` con booleano sigue existiendo por
  compatibilidad; el recorrido usa solo la entrega con aprobación registrada.
- La bitácora persistente (SQLite) depende del change 002 (P1). El recorrido
  exporta sus bitácoras en JSON verificable.
