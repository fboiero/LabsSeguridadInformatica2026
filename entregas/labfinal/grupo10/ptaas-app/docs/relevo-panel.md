# Relevo: panel local

Desde esta carpeta, ejecutar `python -m runtime.relevo` y abrir
`http://127.0.0.1:8765`. La ventana de PowerShell debe seguir abierta; Ctrl+C
detiene el servidor. Los casos pendientes y las respuestas se guardan en
`runs/relevo.sqlite`; se recuperan con «Ver historial».

«Iniciar agentes reales» abre una sesión vacía de Juice Shop y requiere OpenCode
configurado. Inventario formula una pregunta. Validación (`openai/gpt-5.6-luna`)
elige el siguiente control no ejecutado del catálogo; el coordinador rechaza IDs
repetidos o fuera del catálogo. Validación también puede proponer una `ruta`
nueva del dominio autorizado; Python la valida y el panel muestra el ID y la URL
exacta antes de pedir permiso. «Aprobar y ejecutar una vez» lanza
`tools/juice-poc-session.ps1`: crea una instancia efímera una sola vez por
sesión y reutiliza su red y objetivo para los controles siguientes. «Omitir esta
prueba» no envía la consulta y deja disponible la siguiente. «Finalizar y
redactar» limpia la instancia y pasa al borrador.

El selector «Catálogo automático» está activado por defecto en las sesiones
nuevas. En ese modo, una comprobación que ya pertenece al catálogo y usa su ruta
por defecto se ejecuta después de la decisión del agente, sin abrir un gate
repetitivo por cada control; la aprobación queda registrada como «Aprobación de
sesión (catálogo)». Si Validación propone una ruta distinta, la ejecución vuelve
a requerir aprobación humana explícita. Validación recibe la pregunta, la
cobertura y las observaciones previas, y puede concluir el objetivo actual
cuando ya está respondido. Entonces el turno vuelve a Inventario para formular
el siguiente objetivo usando la cobertura acumulada. La sesión solo pasa a
Correlación cuando no quedan controles disponibles o el flujo se cierra
explícitamente; no se detiene tras la primera pregunta respondida.
En la primera aprobación, si no existe `ptaas-attack-pilot-test:local`, el
script la construye con la imagen base fijada y las dependencias mínimas; el
objetivo sigue siendo la imagen de Juice Shop del laboratorio. Si no está local,
la primera sesión descarga `bkimminich/juice-shop:latest`; podés fijar otra
imagen autorizada mediante `$env:PTAAS_JUICESHOP_IMAGE`. Si Docker falla, el
error concreto queda en el historial y la sesión no se presenta como evidencia válida.
«Revisión guiada» usa pasos predefinidos sin llamar modelos y sigue disponible
para los tres casos. Ningún modo hace escaneos generales. No hay carga de
archivos. Una recomendación nueva puede quedar registrada para revisión; una
acción ejecutable debe corresponder a una entrada versionada del catálogo y
conservar el gate humano. No se ejecutan comandos inventados por el modelo.
El hash vincula la decisión a los bytes del archivo local elegido; no autentica
al revisor ni acredita la procedencia de la evidencia. Si los bytes cambian,
se requiere una sesión nueva. La base no es la bitácora encadenada del harness.
PhantomCorp y DVWA requieren sus archivos históricos locales; si faltan se
bloquea la revisión, sin inventar evidencia.

Los fallos recuperables del modelo o de la revisión documental ya no terminan
la sesión en `BLOCKED`: quedan como `RETRY_TURN` o `RETRY_REVIEW` y aparece
«Reintentar turno». La cobertura y los recibos se conservan, y reintentar no
repite consultas HTTP. Las sesiones antiguas que quedaron en `BLOCKED` también
pueden recuperarse desde el historial cuando tienen cobertura o un último turno
identificable. Un fallo del sandbox se marca como «Sin recibo válido» y permite
continuar con la evidencia disponible.
### Cobertura después de una decisión

Después de la primera decisión, el coordinador ofrece los controles restantes
del catálogo ejecutable: CSP, framing, cookies, indicador de listado, errores
detallados, listado `/ftp`, configuración administrativa, métricas, Swagger,
CAPTCHA, productos, reseñas, autorización administrativa y catálogo de retos. La
prueba de reflexión requiere una entrada adicional y queda fuera del perfil. Cada consulta exige su
propia aprobación y su propia URL. Al agotar la lista, finalizar o terminar sin
recibo, toman el turno Correlación y Redacción. Ambas trabajan sobre un resumen
persistido del catálogo del laboratorio y la observación de esa sesión. El panel
distingue consultas con resultado, omitidas, sin recibo válido y sin evidencia.
Un control pendiente no es un hallazgo. El resumen generado es un borrador. Si
cerrás la pestaña entre turnos, abrí la sesión desde el historial y pulsá
«Continuar revisión documental».

### Comprobaciones activas

La casilla **Comprobaciones activas** es opt-in y solo para el laboratorio
efímero. Registra una autorización de la persona que opera; el estado de revisión
docente sigue pendiente y cada intento exige aprobación, incluso con catálogo
automático. Hoy se ejecutan el bypass de login y la detección de error SQL en
búsqueda, ambos con carga fija; las propuestas que necesitan navegador, multipart
o ya están cubiertas quedan visibles como declaradas y no envían tráfico. El botón
**Profundizar** encola la próxima comprobación activa ejecutable sin depender de que
el modelo la proponga, y mantiene la aprobación por intento.

### Consulta opcional de Correlación

Durante la interpretación de resultados, Correlación puede pedir contexto a la
persona cuando lo considere útil; no es una pausa obligatoria. La sesión queda
guardada y puede retomarse desde el historial, respondiendo o indicando que no hay
más contexto. La respuesta se identifica como no verificada y no autoriza ni repite
consultas. Sin evidencia suficiente, corresponde conservar la observación y sus
límites, sin presentarla como hallazgo confirmado. Redacción no agrega un gate.
