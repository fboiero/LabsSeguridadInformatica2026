# Revisión cruzada — Change 007

**Revisora:** María Belén Benito (P4)
**Fecha:** 2026-11-20
**Resultado:** Pide cambios

## Verificaciones

- 49 tests aprobados en tests/test_reporting_e2e.py.
- Revisión de design.md, report_builder.py,
  defectdojo_export.py y reporting.py.
- Se revisaron los controles de bitácora,
  aprobación de entrega y bloqueo DEMO.

## Observación

En harness/report_builder.py, build_report() comprueba
datos sensibles en los campos originales del hallazgo
y en scope, pero no comprueba el campo reason
obtenido de validation.result.

El motivo podría incorporarse al informe Markdown
y a la exportación a DefectDojo sin pasar por el filtro.

## Corrección solicitada

1. Validar reason antes de generar el informe.
2. Agregar un test con un token ficticio en reason.
3. Comprobar que se rechaza el informe.
4. Ejecutar nuevamente los tests de reporting.

La observación surge de la revisión estática.
No se detect? una filtración real.

**Estado:** pendiente de corrección y nueva revisión.

## Respuesta de P5 (2026-11-20)

Observación aceptada: el motivo (`reason`) de `validation.result` no pasaba por el
filtro de datos sensibles. Se resolvió en el orden pedido:

1. Test en rojo `test_dato_sensible_en_el_motivo_de_la_bitacora_se_rechaza`, con un
   encabezado `Authorization`, un token JWT y una cookie de sesión en `reason`
   (commit `234fde2`; evidencia `P5-007-revision-p4-rojo.txt`).
2. `_from_log` aplica `_check_sensitive` al motivo; el informe se rechaza indicando el
   hallazgo (commit `a2dd6a6`).
3. `tests/test_reporting_e2e.py`: 52 passed; suite completa: 480 passed, 1 skipped.
4. Mutación M42 (quitar el filtro del motivo): los 3 tests nuevos fallan.

**Verificación de la corrección:** `entrega/evidencia/salidas/P5-007-correccion-verificada.txt` (52 tests de reporting y 480 de la suite en verde).

## Cierre

**Revisión de la corrección:** Alejo De Miguel (P1), 2026-11-20, no autor del change.
Confirmó por WhatsApp que la corrección (`a2dd6a6`: filtro de datos sensibles sobre el
motivo de la bitácora, con su test) atiende lo pedido por P4. 1.3 cerrada.

