# Archivado — Change 006

Fecha de consolidación: 2026-11-18. Responsable: P5.

**Revisión cruzada (1.3): no realizada.** El integrante asignado (P4) no estuvo
disponible y el change se archivó sin revisión de otra persona, por decisión de
P5. Queda pendiente; si la revisión pide cambios, se abren en un change nuevo.

Los deltas de `specs/validation/spec.md` y `specs/poc-catalog/spec.md` se
incorporaron al final de `openspec/specs/validation/spec.md` y
`openspec/specs/poc-catalog/spec.md`, después de los requisitos previos, que se
conservaron. El directorio del change queda como historial.

## Verificación ejecutada

- Suite completa en el runner del lab (Python 3.12): `313 passed, 1 skipped`.
  El salteado es `test_real_sandbox_no_alcanza_internet`, que solo corre con
  `PTAAS_SANDBOX_DOCKER=1`; la misma prueba la ejecutó una persona por separado.
- `tests/test_traceability.py` y `tests/test_evals.py`: verdes.
- Evals golden: 17/17; los 7 casos nuevos de validación rechazan la respuesta
  incorrecta correspondiente (`P5-006-evals-validacion.txt`).
- Sandbox sin salida a internet: `probe_egress(..., ('1.1.1.1', 80))` devolvió
  `False`, y el control positivo contra `dvwa.lab.test:80` devolvió `True`
  (`P5-006-sandbox-sin-salida.txt`).
- Mutaciones M10 a M17: todas detectadas (`entrega/mutaciones.md`).

## Commits

| Paso | Commit |
|---|---|
| Design (1.1) | `f936ed7` |
| Deltas (1.2) | `67b1293`, corrección `edb9dfc` |
| Tests en rojo (2.1) | `cfdd3a0`, corrección de un test contradictorio `d7c457a` |
| Controles del catálogo y límites (2.3) | `77bc330` |
| Sandbox, loop C y CLI (2.2–2.6) | `b7f24a3` |
| Mutaciones | `e671821`, `cd85e67` |

## Límites conocidos

- La evidencia y las decisiones del Reviewer se escriben en el contrato de
  bitácora de P1 (`InMemoryAuditStore`). La persistencia SQLite llega con el
  change 002; la CLI guarda además las decisiones en el archivo de aprobaciones.
- El loop C se probó con hallazgos de fixture: los hallazgos reales dependen del
  change 005.
- `AGENT_APPROVERS` es una barrera por nombre: no impide declarar un nombre de
  persona falso.
