# Tasks — Change 006

## Spec y diseño
- [x] 1.1 `design.md`: ciclo de vida del sandbox, límites, evidencia, timeout del Reviewer
- [x] 1.2 Deltas de `validation` y `poc-catalog`
- [x] 1.3 Revisión cruzada (aprobado con observaciones, P1: ver revision-p1.md)

## Implementación
- [x] 2.1 Tests que fallan para el `Sender` aislado (sin red externa, sin estado)
- [x] 2.2 Sandbox efímero: contenedor en red interna que implementa `Sender`
- [x] 2.3 Límites de tiempo, tamaño y cantidad de solicitudes
- [x] 2.4 Orquestación del loop C con `decide_validation`
- [x] 2.5 CLI de aprobación: listar hallazgos pendientes, aprobar o rechazar con motivo
- [x] 2.6 Registrar aprobación, verificación elegida y resultado en bitácora

## Verificación
- [x] 3.1 Test: sin aprobación no se invoca el `Sender`
- [x] 3.2 Test: verificación inexistente en catálogo → "no validado"
- [x] 3.3 Test: el sandbox no alcanza hosts fuera del lab
- [x] 3.4 Test: el sandbox se destruye aunque falle la verificación
- [x] 3.5 Evals de validación ampliadas con casos donde la respuesta correcta es no actuar
- [x] 3.6 Archivar deltas en `openspec/specs/`
