# Archivado local — Change 004

Fecha de consolidación: 2026-11-13.
Revisión cruzada de P2: aceptada.

Los deltas de `specs/asset-discovery/spec.md` y `specs/tool-adapters/spec.md`,
incluida la verificación real de `runtime-verification.md`, se incorporaron a
`openspec/specs/asset-discovery/spec.md` y `openspec/specs/tool-adapters/spec.md`.
Se conservaron los requisitos previos y el directorio del change como historial.
El archivado es local y no implica commit ni merge.

## Verificación ejecutada

- Suite local: 251 tests aprobados.
- Evaluaciones golden: 10/10 aprobadas.
- `audit verify` sobre `P3-real-04/audit.json`: `ok: true`.
- Archivos de `P3-real-04`: hashes SHA-256 idénticos antes y después del archivado.
- Revisión técnica de seguridad del archivado: sin hallazgos bloqueantes.

La evidencia real conserva Subfinder como `UNAVAILABLE` por ausencia de fuentes
locales y los sondeos HTTP sobre semillas autorizadas. Los subdominios,
exclusiones y resultados vacíos de los fixtures se validaron mediante simulación;
no se presentan como descubrimientos reales.
