# Diseño: piloto MITRE de solo lectura

La CLI separada envía los tres fixtures locales y un extracto congelado del
catálogo en una sola solicitud stateless. Sin ingesta de logs externos, MCP,
terminal, adaptadores de seguridad ni conexión al laboratorio. La salida
tipada exige una fila por caso; se rechazan en bloque referencias ajenas y
asociaciones no permitidas. El modelo aporta la explicación y sugerencias de
telemetría, no decide qué casos son elegibles para la técnica. Esto es un
ejercicio de clasificación, no una medición del rendimiento de detección.

El `result.json` conserva resultado preliminar y referencias, no la respuesta
cruda rechazada. El campo `model` identifica el modelo solicitado. La aprobación
humana queda pendiente; el piloto no escribe en la bitácora de un engagement
porque no hay engagement ni acción contra un activo. El contenedor ejecuta solo
las pruebas del validador con fixtures; la corrida OpenCode se hace por separado.
