# Design — Change 010 (propuesto)

Las referencias a los estándares se dan por tema y por sección general, como las usa el
marco teórico del kit (`docs/marco-teorico.md`, tabla de estándares). Antes de
implementar, el grupo debe confirmar las cláusulas exactas contra las versiones
vigentes de cada documento.

## 1. Controles propuestos

| # | Control | Estándar que lo justifica | Hueco hoy | Cómo se probaría |
|---|---|---|---|---|
| C1 | Gate de divulgación: no se entrega un informe con receptor o canal `unknown` | ISO/IEC 29147 — divulgación coordinada a un receptor identificado y por un canal acordado | La sección de divulgación del 007 admite `unknown` y aun así se entrega | Test: informe con receptor `unknown` → la entrega se rechaza |
| C2 | Aviso por hallazgo con contenido mínimo (activo afectado, impacto, remediación, estado de validación, plazo) y prohibición de publicar antes del plazo | ISO/IEC 29147 — contenido de un aviso y coordinación de los tiempos | El informe es un único documento; no hay aviso por hallazgo ni plazo de publicación | Test: aviso sin plazo o sin remediación → se rechaza |
| C3 | Estados del hallazgo después de la entrega: recibido → verificado → en remediación → retest → cerrado | ISO/IEC 30111 — proceso de manejo: recepción, verificación, remediación, liberación y seguimiento | Después de la entrega no hay estados; DefectDojo recibe la exportación pero el harness no registra nada más | Test: transición inválida (de "recibido" a "cerrado") → se rechaza y queda en bitácora |
| C4 | El cierre exige un retest con la **misma** verificación del catálogo y la misma versión | ISO/IEC 30111 — verificar la corrección antes de cerrar | No existe el retest | Test: cerrar sin retest, o con otra verificación → se rechaza |
| C5 | Retención y destrucción de la evidencia definidas en el RoE (plazo y responsable), con constancia de destrucción en la bitácora | NIST SP 800-115 — tratamiento de los datos de la prueba (recolección, almacenamiento, transmisión y destrucción) | La evidencia (`.db`, salidas) queda indefinidamente; el RoE no fija retención | Test: RoE sin plazo de retención → se rechaza; cierre sin constancia → se rechaza |
| C6 | Verificación de limpieza al cerrar el engagement: sin contenedores con la etiqueta del engagement, sin archivos temporales | NIST SP 800-115 — actividades posteriores a la prueba | El sandbox limpia huérfanos al iniciar el loop C, pero no hay verificación al cerrar | Test con `FakeRuntime`: contenedor huérfano al cerrar → el cierre se rechaza |
| C7 | Contacto de emergencia operativo: un aviso del contacto del RoE activa el kill switch y queda registrado | NIST SP 800-115 — planificación y reglas de compromiso (comunicación y detención de la prueba) | El RoE exige contactos, pero no hay vía para que activen el kill switch | Test: aviso del contacto → `ABORTED` en bitácora y ninguna acción posterior |

## 2. Matriz de cumplimiento (desafío D1, parcial)

Prácticas de NIST SP 800-115 que el sistema **ya** cumple, para que la propuesta parta
de lo existente. Las de ISO/IEC 27001 quedan para la revisión del grupo (exige cláusulas
exactas que no se verificaron).

| Invariante | Práctica de NIST SP 800-115 que cubre |
|---|---|
| I1 Único camino, I2 Guard determinista | Planificación: alcance y técnicas acordadas antes de ejecutar |
| I3 Bitácora total | Ejecución: registro de las actividades de la prueba |
| I4 Menor privilegio | Planificación: reglas de compromiso por fase y ventana |
| I5 HITL | Planificación y ejecución: autorización explícita antes de cada actividad intrusiva |
| I6 Kill switch | Reglas de compromiso: capacidad de detener la prueba |
| I7 Sandbox efímero | Tratamiento de datos: no conservar contenido del objetivo |
| I8 Sin armas nuevas | Ejecución: técnicas no destructivas y aprobadas |

## 3. Plantilla de divulgación (desafío D2)
`docs/plantilla-divulgacion-29147.md`, completada con un hallazgo real de la corrida
entregada (`P5-recorrido-04`).

## 4. Plan de implementación (cuando se apruebe)
1. Delta de `reporting` (C1, C2) y de `engagement-lifecycle` (C3–C7) — borrador en
   `specs/reporting/spec.md`.
2. Tests en rojo por control, código mínimo, mutaciones, archivado.
3. Agregar al RoE: `disclosure` (receptor, canal, plazo) y `evidence_retention_days`.

## 5. Riesgos
- Más campos obligatorios en el RoE: un RoE viejo deja de validar. Mitigación: valores
  por defecto explícitos solo en el laboratorio, nunca en un engagement real.
- El retest vuelve a enviar tráfico al objetivo: pasa por los mismos gates que la
  validación original.
