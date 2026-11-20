# Archivado — Change 002

Fecha: 2026-11-19.

| Parte | Responsable |
|---|---|
| Contrato, fake en memoria, `design.md` y delta (1.1, 1.2) | P1 |
| Tests, implementación SQLite, CLI, integración, mutaciones y archivado (2.1–3.6) | P5, a pedido de P1 |
| Revisión del delta (1.3) | Martin Beccereca (P5), 2026-11-19: de acuerdo, sin cambios. P5 no es autor del delta (lo escribió P1) |

El delta `specs/audit-log/spec.md` se incorporó al final de
`openspec/specs/audit-log/spec.md`; la línea `Tests:` suma
`tests/test_audit_persistence.py`. Con esto queda cubierto el Scenario "sin datos
sensibles" que el enunciado marcaba como faltante.

## Desvío del diseño, documentado
El diseño de P1 proponía columnas fijas (`agent`, `action`, `target`, …). Se guardó
el evento como JSON canónico en una columna (`data`), con el mismo hash que el
contrato en memoria (`hash_de(prev, data)`), para que una sola implementación sirva
para las decisiones del harness y para la bitácora de evidencia del recorrido. Todo
lo demás sigue el diseño: archivo por engagement, `GENESIS`, triggers, verificación
al abrir y por CLI, ancla de cabeza, `BEGIN IMMEDIATE`, rechazo de campos sensibles.
Se agregó `UNIQUE(prev)`: la base impide dos registros con el mismo antecesor.

## Verificación
- `tests/test_audit_persistence.py`: 20 tests (5 de P1 + 15 de P5).
- Suite completa: 463 passed, 1 skipped (Python 3.12 en el runner y 3.11 en el host).
- Mutaciones M36–M41 detectadas (`entrega/mutaciones.md`).
- El recorrido de un comando persiste sus dos bitácoras en SQLite y guarda el ancla
  de cada una en el manifiesto; `python -m harness.pipeline verify` las comprueba.

## Límites
- Los `.db` de las corridas no se versionan (`.gitignore` del kit); se versionan
  sus exportaciones JSON verificables.
- Un administrador con acceso al disco puede reescribir el archivo entero y
  recalcular la cadena: solo el ancla guardada fuera lo hace visible (límite ya
  previsto en el diseño de P1).
