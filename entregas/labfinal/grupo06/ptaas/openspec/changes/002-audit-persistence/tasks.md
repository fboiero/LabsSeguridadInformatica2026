# Tasks — Change 002

## Spec y diseño
- [x] 1.1 Escribir `design.md` (esquema SQLite, política de integridad, concurrencia)
- [x] 1.2 Delta de `audit-log` con ≥ 4 Requirements nuevos y Scenarios negativos
- [x] 1.3 Revisión del delta por otro integrante — Martin Beccereca (P5), 2026-11-19: de acuerdo con el delta de P1

## Implementación
- [x] 2.1 Tests que fallan para persistencia y recuperación tras reinicio
- [x] 2.2 `harness/audit.py`: almacenamiento append-only con hash encadenado
- [x] 2.3 Impedir UPDATE/DELETE (trigger o capa de acceso) y probarlo
- [x] 2.4 Verificador: `python -m harness.audit verify <archivo>`
- [x] 2.5 Integrar con `Harness` sin cambiar su contrato público

## Verificación
- [x] 3.1 Test: alterar una fila → el verificador falla
- [x] 3.2 Test: borrar una fila intermedia → el verificador falla
- [x] 3.3 Test: dos engagements no comparten registros
- [x] 3.4 Test: escrituras concurrentes conservan la cadena
- [x] 3.5 Mutation check del verificador y registro del resultado
- [x] 3.6 Archivar el delta en `openspec/specs/audit-log/spec.md`
