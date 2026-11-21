# Tasks — Change 002

Las marcas completas reflejan el trabajo verificado de esta primera integración.
No implican que la revisión independiente o el práctico completo estén terminados.

## Propuesta

- [x] 1.1 Escribir el diseño: SQLite, integridad, concurrencia y límites.
- [x] 1.2 Proponer el delta de audit-log con escenarios positivos y negativos.
- [x] 1.3 Proponer el delta de tool-adapters para intentos y fallos.
- [x] 1.4 Declarar uso de IA y procedencia del kit.
- [x] 1.5 Aprobación humana: el usuario informa el acuerdo de los integrantes.

## Preparación

- [x] 2.1 Preparar subconjunto ejecutable adaptado del kit en el espacio del grupo, sin editar labs/.
- [x] 2.2 Crear entorno aislado e instalar dependencias de desarrollo.
- [x] 2.3 Ejecutar tests, evals golden y reporte de avance de la base; guardar resultados.

## Tests e implementación (solo después de aprobar la propuesta)

- [x] 3.1 Escribir tests antes del código; documentar fallo inicial por módulos ausentes y correspondencia de escenarios.
- [x] 3.2 Implementar almacenamiento y recuperación con SQLite.
- [x] 3.3 Implementar triggers, transacciones y espera acotada.
- [x] 3.4 Implementar verificación al abrir y comando offline de solo lectura.
- [x] 3.5 Integrar ATTEMPT, DECISION y TOOL_ERROR sin cambiar firmas existentes.
- [x] 3.6 Implementar suspensión por fallo de auditoría y recuperación sin reintentos.
- [x] 3.7 Validar lista de campos y saneamiento; probar secretos sintéticos.
- [x] 3.8 Conservar controles de autorización, gates y kill switch en la adaptación.

## Integración de agentes aprobada

- [x] 3.9 Mandatos y schemas separados para cuatro especialistas.
- [x] 3.10 Proveedor OpenCode stateless y proveedor fixture explícito, sin fallback.
- [x] 3.11 Demo con IA real: cinco generaciones y una consulta simulada.
- [x] 3.12 Presupuesto global, escalado por schema y borrador pendiente de entrega humana.

## Verificación y cierre

- [x] 4.1 Probar persistencia entre procesos, aislamiento y escrituras concurrentes.
- [x] 4.2 Probar corrupción, fallos de commit y fallo posterior a ejecutar la herramienta.
- [x] 4.3 Probar y documentar que truncamiento final sin ancla no se detecta.
- [x] 4.4 Suite y evals en verde; tabla Scenario → test real.
- [x] 4.5 Mutación controlada: quitar el registro previo hace fallar un test.
- [x] 4.6 Revisión de seguridad y revisión de otro integrante. Carolina informó que Juan revisó el cambio y no dejó observaciones.
- [ ] Registrar el commit o enlace de la versión que revisó Juan.
- [ ] 4.7 Archivar los deltas al integrar por PR, no antes.

La [nota de revisión](../../reviews/20261121-revision-tecnica.md) distingue la
revisión de Juan, informada por Carolina, de la revisión asistida por IA.
