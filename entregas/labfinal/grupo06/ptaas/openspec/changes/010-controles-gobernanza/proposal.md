# Change 010 — Controles adicionales de gobernanza (ISO/IEC 29147, ISO/IEC 30111, NIST SP 800-115)

Estado: **propuesto** (no implementado). Responsable de la propuesta: P5. Fecha: 2026-11-20.
Requiere revisión del grupo antes de implementarse.

## Por qué
El sistema controla bien **cómo** se prueba (alcance, tokens, gates, sandbox) y **qué**
se entrega (informe desde la bitácora, entrega ligada al hash). Pero termina en la
entrega: no gobierna qué pasa con un hallazgo **después** de entregado, ni qué pasa con
la **evidencia** cuando termina el engagement. El marco teórico del kit asigna esas
etapas a tres estándares: ISO/IEC 29147 (cómo comunicar un hallazgo), ISO/IEC 30111
(qué pasa después del hallazgo) y NIST SP 800-115 (planificación, ejecución y
actividades posteriores a la prueba). Este change propone los controles que faltan.

## Qué cambia (propuesta)
1. **Divulgación coordinada (ISO/IEC 29147):** el informe no se puede entregar con la
   sección de divulgación incompleta, y cada hallazgo se comunica con un aviso de
   contenido mínimo y un plazo acordado antes de cualquier publicación.
2. **Ciclo de vida del hallazgo después de la entrega (ISO/IEC 30111):** cada hallazgo
   entregado pasa por estados explícitos hasta el cierre, y el cierre exige un retest
   con la misma verificación del catálogo.
3. **Tratamiento de la evidencia y cierre del engagement (NIST SP 800-115):** retención
   y destrucción de la evidencia definidas en el RoE, y una verificación de limpieza al
   cerrar.
4. **Matriz de cumplimiento (desafío D1) y plantilla de divulgación (desafío D2).**

## Criterios de aceptación (cuando se implemente)
1. Un informe con receptor o canal de divulgación `unknown` no se entrega.
2. Un hallazgo no pasa a "cerrado" sin un retest registrado con la misma verificación.
3. Un engagement no se cierra sin la constancia de destrucción de la evidencia vencida
   y sin verificar que no quedan contenedores ni archivos temporales.

## Fuera de alcance
Cifrado de la bitácora en reposo (ya excluido en el diseño del 002) y la publicación
efectiva de avisos: el laboratorio no tiene un proveedor real a quien notificar.
