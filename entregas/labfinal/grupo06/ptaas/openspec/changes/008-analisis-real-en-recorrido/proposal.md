# Change 008 — Análisis real en el recorrido de un comando

Responsable: P5. Depende de 005 (P4), 006 y 007.

## Por qué
El recorrido de un comando (007 · 3.5) usa un análisis simulado, por lo que el
informe sale DEMO y no se puede entregar ni exportar. El change 005 dejó un loop B
real (`run_detection_p4`) y un adaptador ZAP baseline que pasa por el harness.

## Qué cambia
- La etapa de análisis del recorrido ejecuta el loop B de P4 con ZAP baseline
  sobre cada activo que confirmó el recon, a través de `Harness.invoke`, con token
  de fase `analyze` y un gate humano propio (`active_analysis`).
- Las alertas de ZAP se convierten en hallazgos con CWE y remediación de ZAP. El
  vector CVSS v4.0 y la verificación del catálogo salen de una tabla de mapeo
  aprobada por una persona (`harness/zap_mapping.yaml`).
- Con el análisis real, el informe deja de ser DEMO: se entrega con aprobación
  registrada y se exporta a DefectDojo.

## Fuera de alcance
- La correlación por CVE del 005: no hay snapshot de NVD en el repositorio y el
  formato de tecnologías del recon (`producto:versión`) no coincide con el que
  espera el correlador (`producto/versión`). Queda documentado como pendiente.
- Nuclei: sus templates siguen sin aprobar (005 · 3.2).

## Criterios de aceptación
1. Sin aprobación del gate `active_analysis`, ZAP no se ejecuta.
2. Una alerta sin mapeo aprobado no entra al informe y su descarte queda en la bitácora.
3. Una tabla de mapeo sin aprobación humana se rechaza.
4. Un reporte de ZAP que menciona un host que no es el objetivo se rechaza.
5. Con análisis real y todas las aprobaciones, el informe se entrega y se exporta.
