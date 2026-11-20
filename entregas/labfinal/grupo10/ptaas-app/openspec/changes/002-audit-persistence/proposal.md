# Change 002 — Persistencia de la bitácora

Estado: **aprobado para implementar por el usuario, quien informa el acuerdo del grupo**.
La revisión de seguridad del código y el archivo del change siguen pendientes.

## Por qué

El kit conserva el historial solo mientras vive el proceso. Además, registra el
éxito después de ejecutar la herramienta: si el adaptador falla, ese camino no
deja evidencia. Necesitamos persistencia y un registro previo a la ejecución.

Esta propuesta desarrolla el change 002 del profesor; no presenta ese código
de base como trabajo original del grupo.

## Qué cambia

- SQLite, un archivo por auditoría, con registros encadenados y transacciones.
- Verificación al abrir y mediante un comando offline.
- API de solo agregado y triggers contra UPDATE/DELETE ordinarios.
- Registro confirmado del intento antes de ejecutar cualquier adaptador.
- Registro de errores sin copiar salidas, credenciales ni mensajes arbitrarios.
- Bloqueo de nuevas ejecuciones cuando no se pueda registrar o verificar.

El delta abarca `audit-log` y, por el registro previo y los fallos, `tool-adapters`.
No modifica las decisiones de autorización ni los gates humanos.

## Decisiones adoptadas

1. **Sin falsa garantía de completitud.** Esta versión verifica la estructura de
   la cadena, pero no detecta un truncamiento final consistente ni una reescritura
   completa por quien controla el archivo. Se documenta y se informa esa limitación.
   El anclaje externo confiable queda para otro change: otro archivo editable por
   el mismo usuario no sería una raíz de confianza independiente.
2. **Fallar cerrado.** Sin persistir el intento, no se ejecuta la herramienta.
   Un error posterior detiene la invocación; si tampoco puede registrarse, el
   coordinador suspende nuevas acciones y no informa éxito ni reintenta solo.

## Fuera de alcance

Anclaje externo, firmas, almacenamiento WORM, orquestación con modelos reales,
escaneos, sandbox, cambios de alcance, exploits y nuevas reglas de autorización.
La primera prueba de integración usa modelos reales con datos exclusivamente
sintéticos; no habilita herramientas reales sobre el laboratorio.

## Revisión necesaria

El usuario informó que los integrantes están de acuerdo con la propuesta.
También aprobó mediante confirmación explícita una demo con su OpenCode
configurado, un máximo de seis llamadas al modelo, herramientas simuladas,
bitácora persistente y controles de autorización. El delta de `agent-contracts`
detalla esa integración. No se inventan nombres, firmas ni una revisión de código
que todavía no ocurrió; deberá realizarse antes del cierre.
