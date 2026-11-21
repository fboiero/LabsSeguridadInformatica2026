# Archivado — Change 008

Fecha: 2026-11-19. Responsable: P5.

**Revisión cruzada: no realizada.** La tiene que hacer otro integrante.

El delta `specs/reporting/spec.md` se incorporó al final de
`openspec/specs/reporting/spec.md`; la línea `Tests:` suma
`tests/test_analisis_real.py`.

## Verificación ejecutada

- Suite completa: `448 passed, 1 skipped` (Python 3.11 en el host; ver
  `P5-008-final.txt`).
- Mutaciones M30–M35 detectadas. M33 sobrevivió en la primera corrida y llevó a
  corregir un test débil (ver `entrega/mutaciones.md`).
- Tabla de mapeo `harness/zap_mapping.yaml` revisada y firmada por P5 el
  2026-11-19.
- Corridas reales contra el lab, ejecutadas por P5 con aprobaciones por la CLI:
  - `P5-recorrido-03`: frenada en el gate de entrega. P5 detectó dos errores del
    informe (alertas unificadas por error y `NINGUNA vNone`); no se entregó.
  - `P5-recorrido-04`: recon, análisis (ZAP sobre DVWA y Juice Shop) y validación
    reales. 8 hallazgos: 5 validados en el sandbox y 3 sin verificación en el
    catálogo. Informe entregado con aprobación registrada para su hash y
    exportado a DefectDojo. Las dos bitácoras exportadas verifican.

## Límites conocidos

- La correlación por CVE del 005 no se usa: no hay snapshot de NVD y el formato
  de tecnologías del recon no coincide con el del correlador.
- ZAP puede encontrar alertas distintas entre corridas (la 10023 apareció en la
  `-03` y no en la `-04`): el spider no recorre siempre las mismas páginas.
- Los vectores CVSS son evaluación del analista, no datos de NVD; el informe lo
  declara.
