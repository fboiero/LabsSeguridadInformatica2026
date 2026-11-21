# Revisión técnica asistida por IA — 2026-11-21

**Versión revisada:** `b142597`. Alcance: autorización, bitácora, frontera de
adaptadores e importación de informes. Esta revisión no acredita la firma de
otro integrante ni la aprobación docente.

## Verificación local

Pasaron 57 pruebas seleccionadas de RoE, auditoría, adaptadores, DefectDojo y
entrega. No se ejecutaron comprobaciones activas ni se contactó DefectDojo.

## Hallazgos

1. **La importación automática no está validada.** `runtime/defectdojo.py`
   envía JSON directo a `/api/v2/import-scan/`; para Generic Findings Import,
   el flujo documentado requiere el archivo de reporte, el tipo de importación
   y el engagement destino. Las pruebas de `test_defectdojo.py` cubren rechazos,
   no una importación exitosa. Se recomienda validar primero el archivo exportado
   en la interfaz, con un informe sintético en un engagement de prueba.
2. **Una etiqueta local no acredita aprobación docente.** El catálogo publicado
   usa `pending_teacher_review`. No debe tratarse un cambio de estado en YAML
   como firma o evidencia de revisión. Para la entrega, mantener las propuestas
   no inertes fuera del catálogo ejecutable.

La validación real de DefectDojo y el cierre formal de los changes no se dan
por realizados en esta revisión.

## Seguimiento de revisión humana

Carolina informó que Juan revisó el change `002` y no dejó observaciones. No
se informó qué commit revisó. El `b142597` indicado arriba corresponde solo
a la revisión asistida por IA, no a la de Juan.

Carolina también informó que el grupo revisó el change `003`. Este registro
no acredita por separado una aprobación formal de cierre, un acuerdo con la
cátedra ni la integración y el archivado por PR.

## Seguimiento técnico

Se atendió el hallazgo sobre DefectDojo: el publicador envía multipart y se
validó por HTTP con un token temporal contra la instancia local. El [registro
de la prueba](../../docs/entrega-defensiva.md#publicador-por-api-prueba-http-local)
no implica que se haya publicado el informe de entrega.
