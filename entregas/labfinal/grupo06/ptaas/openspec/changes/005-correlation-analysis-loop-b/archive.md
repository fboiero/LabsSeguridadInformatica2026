# Archivado — Change 005

Fecha: 2026-11-19.

| Parte | Responsable |
|---|---|
| Diseño, deltas, clientes NVD/EPSS, mapeo CWE, correlador, adaptador ZAP, loop B, evals, 5 templates y corrida real de ZAP (1.1–3.1, 3.4, 4.1–4.5) | P4 (Maria Belen Benito) |
| Adaptador de Nuclei por el harness, allow-list verificable, segunda aprobación de templates, corrida real de Nuclei y archivado (3.2, 3.3, 4.6) | P5 (Martin Beccereca) |
| Revisión cruzada (1.3) | Martin Beccereca (P5), 2026-11-19 |

## Revisión cruzada: APROBADO CON OBSERVACIONES

Revisor: Martin Beccereca (P5), no autor del change. El ciclo del plan asignaba la
revisión a P3; la hizo otro integrante que no es autor (plan, sección 4.3).

| Control | Resultado |
|---|---|
| 1.1 Diseño: datos offline, antigüedad, confianza, contradicciones | Aprobado. Observación 1 |
| 1.2 Deltas de `correlation` y `vuln-analysis` | Aprobado. Observación 2 |
| Tests negativos y trazabilidad | Aprobado: 84 tests del change en verde |
| Acciones activas vía `Harness.invoke` y bitácora | Aprobado con observación 3 |
| Loop B: dos rondas sin evidencia, tope, anomalías | Aprobado (`decide_detection` con tests; corrió contra el lab en el change 008) |

**Observaciones**
1. Los umbrales de antigüedad de los snapshots (NVD 30 días, EPSS 7 días) quedaron como
   propuesta; el código usa 30 días para NVD. Falta aprobarlos formalmente.
2. Los deltas usaban un nivel de título de más (`### Requirement`, `#### Scenario`):
   `progress.py` los habría contado como 0 Scenarios. Se normalizaron al archivar, sin
   cambiar el texto.
3. (a) El adaptador real de Nuclei no podía pasar por el harness (recibía URL; el Guard
   evalúa host). Corregido por P5 con test (`tests/test_nuclei_harness.py`).
   (b) La corrida real de ZAP de P4 aprobó el gate con `--approved`, sin registrar quién
   aprobó. Las corridas posteriores (008 y Nuclei) usan la CLI de aprobación.
4. La correlación por CVE no produce candidatos hoy: no hay snapshot de NVD en el
   repositorio y el correlador espera `producto/versión` mientras el recon informa
   `producto:versión`. El código y sus tests son correctos; la integración queda pendiente.

## Archivado
Los deltas `specs/correlation/spec.md` y `specs/vuln-analysis/spec.md` se incorporaron
al final de las specs vigentes, con los títulos normalizados. `correlation` pasó de 5 a
17 Scenarios y `vuln-analysis` de 6 a 22. La línea `Tests:` suma los archivos de tests
del change. Los borradores de `propuesta-archivo/` quedan como historial.

## Evidencia
- ZAP real (P4): `evidencia/zap/`. ZAP dentro del recorrido: `P5-recorrido-04/`.
- Nuclei real por el harness: `entrega/evidencia/salidas/P5-nuclei-01/` (2 hallazgos,
  bitácora verificada contra su ancla, digest de la imagen registrado).
- Allow-list: `templates/allowlist/MANIFEST.md` (5 templates, hash y segunda aprobación).
