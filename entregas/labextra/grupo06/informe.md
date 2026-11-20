# Informe — Laboratorio Extra SSRF

**Grupo:** 06
**Fecha:** 2026-10-28

| Nombre y apellido    | Usuario de GitHub |
| -------------------- | ----------------- |
| Martín Beccereca     | martinbeccereca   |
| Belén Benito         | belubenito603     |
| Alejo José De Miguel | AlejoDM           |
| Tomás Giudici        | TomasGiudici      |
| Carolina Suppo       | carosuppo         |

## 0. Declaración de uso de IA

**Herramienta:** Codex (OpenAI).

**Finalidad y partes asistidas:** apoyo para la ejecución de R1 y R3, el ordenamiento de evidencias y la redacción técnica inicial.
**Verificación realizada:** Se ejecutaron los comandos en el entorno autorizado del laboratorio y se analizaron las respuestas obtenidas para comprobar que el acceso al recurso interno se realizó mediante la vulnerabilidad SSRF. Se verificó la presencia de la información expuesta y se validó la flag mediante el sistema oficial de retos.

**Herramienta:** ChatGPT (OpenAI)

- **Finalidad del uso:** asistencia para comprender los riesgos de SSRF en entornos cloud, redactar la pregunta P5 y revisar la integración de la entrega grupal.
- **Partes asistidas:** respuesta P5 sobre servicios de metadatos y revisión preliminar del informe.
- **Verificación:** se contrastó la respuesta con el alcance del laboratorio, diferenciando los accesos internos efectivamente observados de los riesgos teóricos de SSRF en servicios cloud. No se realizaron consultas contra servicios de metadatos reales.

- **Herramienta:** Claude (Anthropic), vía Claude Code.
- **Finalidad y partes asistidas:** redacción de la respuesta a la pregunta P4 y del research.md.
- **Verificación:** Las afirmaciones del caso Capital One se contrastaron contra el aviso judicial del caso (justice.gov), la nota técnica de Krebs on Security/TechTarget y la documentación oficial de AWS sobre IMDSv2 antes de incluirlas.

**Herramienta:** Opencode.

**Finalidad y partes asistidas:** apoyo para documentar R2 y redactar la respuesta P2 sobre el oráculo de escaneo.
**Verificación realizada:** se comparó la respuesta `502` con `Connection refused` en `127.0.0.1:1` con la respuesta `200` y el panel interno en `127.0.0.1:9000`, usando las salidas crudas de P1. También se contrastó el fallo de resolución directa de la intranet con la respuesta obtenida por preview. Tras detectar que el manifiesto local tenía finales CRLF, se presentó la misma cadena de R2 usando una copia temporal normalizada a LF; el verificador la aceptó. Se validaron las tres flags y el estado final mostró 3/3.

## 1. Cadena de explotación

### R1 — Panel interno en localhost

La home pública de `http://phantomcorp/` expuso una herramienta con formulario GET hacia `/preview` e input `url`; el texto de la propia página aclara que la previsualización la genera el servidor. Esto justificó comprobar que el destino indicado se consulta desde PhantomCorp y no desde la consola atacante. La home y el formulario constan en la [salida original](evidencia/salidas/01-home.txt).

Se probaron por `/preview` destinos `127.0.0.1` limitados a una lista breve de puertos HTTP y de administración habituales. El contraste inicial contra el puerto 1 devolvió `HTTP/1.0 502 Bad Gateway` y `Connection refused`, por lo que la aplicación reveló que intentó abrir una conexión local pero no obtuvo listener. La [salida original](evidencia/salidas/08-r1-oraculo-puertos.txt) conserva ese caso. Los puertos 8080, 8000, 3000, 5000, 8888, 8008, 8081 y 9090 presentaron el mismo resultado; el registro de comandos detalla la secuencia completa.

El puerto 9000 produjo una respuesta diferente: el portal devolvió `HTTP/1.0 200 OK` y envolvió el contenido de «PhantomCorp — Panel interno (solo localhost)», que incluía la flag. La consulta reproducible fue:

```bash
curl -sS -i --max-time 10 --get --data-urlencode 'url=http://127.0.0.1:9000/' http://phantomcorp/preview
```

La respuesta completa está en la [evidencia del panel local](evidencia/salidas/09-r1-panel-local.txt). Desde la raíz del repositorio se presentó `FLAG{ssrf_localhost_panel_interno}` mediante `./ctf submit extra R1 'FLAG{ssrf_localhost_panel_interno}'`; el verificador la aceptó, como acredita la [salida de presentación](evidencia/salidas/10-r1-submit.txt).

### R2 — Intranet en la red interna

Desde `cyberlab-attacker`, la solicitud directa a `http://phantomcorp-intra/` devolvió `curl: (6) Could not resolve host: phantomcorp-intra`; esto confirma que el nombre no se resolvió desde la consola, no que se haya observado un timeout o una conexión bloqueada por IP. En la topología del Compose del laboratorio, la consola atacante está en `labnet` y la intranet solo en `internalnet`, por lo que no hay acceso directo desde la consola. [Salida original](evidencia/salidas/08-p2-directo.txt).

Luego se envió `http://phantomcorp-intra/` como destino de `/preview` en `phantomcorp`. La respuesta HTTP 200 incluyó la página «Intranet PhantomCorp» y el contenido `FLAG{ssrf_intranet_descubierta}`, prueba de acceso indirecto a través del servidor web conectado a ambas redes. [Salida original](evidencia/salidas/09-p2-intranet-preview.txt).

La primera presentación de `FLAG{ssrf_intranet_descubierta}` devolvió `[FAIL]`. Al revisar los finales de línea se confirmó que el manifiesto local tenía cinco líneas CRLF y ninguna LF sola: el lector del verificador conservaba el `\r` final junto al hash esperado. Se normalizó a LF una copia temporal del manifiesto, sin modificar el archivo fuente, y se volvió a presentar exactamente la misma cadena mediante `ctf_submit`; esta vez el verificador respondió `[ OK ]` y marcó R2 resuelto. El estado inmediato mostró 1/3 porque R1 y R3 aún no estaban registrados en el progreso local; se presentaron también esas dos flags con otra copia temporal LF y ambas fueron aceptadas. [Primer intento](evidencia/salidas/11-p2-submit.txt) · [Aceptación de R2](evidencia/salidas/17-p2-submit-lf-normalized.txt) · [Revalidación de R1 y R3](evidencia/salidas/19-p1-r3-submit-lf-recheck.txt) · [Estado final 3/3](evidencia/salidas/20-status-all-flags.txt).

La segunda presentación directa contra el manifiesto CRLF también fue rechazada; esa salida se conserva en [la revalidación](evidencia/salidas/16-p2-submit-recheck.txt). La aceptación posterior con la copia LF confirma que el problema era el final de línea del hash esperado, no el valor de la flag.

Para buscar más pistas sin adivinar rutas, se siguieron los dos enlaces publicados en la home. `/salud` devolvió únicamente el estado del servicio; `backups/clientes.json` devolvió la flag de R3 ya documentada, no otra flag para R2. [Home](evidencia/salidas/13-p2-intranet-home-recheck.txt) · [Salud](evidencia/salidas/14-p2-salud-recheck.txt) · [Backup enlazado](evidencia/salidas/15-p2-backup-link.txt). La flag R2 válida fue el valor observado en la home; el ajuste necesario fue normalizar a LF el manifiesto usado por el verificador.

### R3 — Exfiltración del backup

Las pruebas se ejecutaron desde `cyberlab-attacker`, mediante `docker exec ... bash -c`, equivalente no interactivo a la consola de `make shell`. El host utilizó PowerShell y Git Bash para el verificador. Se comprobó el comando Compose contra el Makefile porque `make` no estaba disponible. Los comandos exactos y sus redirecciones se encuentran en [evidencia/comandos.txt](evidencia/comandos.txt).

1. **Descubrimiento de la interfaz.** `curl -sS -i --max-time 10 http://phantomcorp/` mostró un formulario GET con `action="/preview"` e `input name="url"`. La propia página indica que el servidor genera la previsualización. [Salida original](evidencia/salidas/01-home.txt).
2. **Contraste directo.** `curl -sS -i --max-time 3 http://phantomcorp-intra/` devolvió `curl: (6) Could not resolve host: phantomcorp-intra`. Esto acredita que el acceso por ese nombre falló desde el atacante; no demuestra por sí solo un timeout ni un bloqueo de conexiones por IP. La segmentación se conoce además por la topología y Compose oficiales. [Salida original](evidencia/salidas/02-directo.txt).
3. **Línea base de preview.** Se suministró `http://phantomcorp/` al formulario. La respuesta HTTP 200 incluyó la home dentro de la previsualización, sin visitar destinos externos. [Salida original](evidencia/salidas/03-preview-base.txt).
4. **Punto de partida interno.** Se consultó `http://phantomcorp-intra/` por preview; el nombre proviene del enunciado. La respuesta HTTP 200 incluyó la página «Intranet PhantomCorp» y el enlace literal `<a href="/backups/clientes.json">backup de clientes (temporal, borrar!)</a>`. Esta pista justifica la siguiente consulta; no se adivinó la ruta. [Salida original](evidencia/salidas/04-intranet.txt).
5. **Lectura del backup.** Se resolvió el enlace relativo respecto del host de intranet y se consultó mediante la misma función:

```bash
curl -sS -i --max-time 10 --get --data-urlencode url=http://phantomcorp-intra/backups/clientes.json http://phantomcorp/preview
```

La respuesta exterior fue `HTTP/1.0 200 OK` y `Content-Type: text/html; charset=utf-8`: preview envolvió el JSON con un encabezado HTML. No se atribuyen esas cabeceras al servicio interno. El contenido incluyó un aviso de backup temporal previo a migración, dos objetos en `clientes` con campos `id`, `empresa` y `cuit`, y `"integridad": "FLAG{ssrf_backup_clientes}"`. Los registros completos se conservan en la [salida original del backup](evidencia/salidas/05-backup.txt), sin duplicar innecesariamente sus identificadores aquí.

6. **Verificación.** Desde la raíz del repositorio, Git Bash ejecutó `./ctf submit extra R3 'FLAG{ssrf_backup_clientes}'`. El verificador respondió `[ OK ] Reto R3 resuelto: Exfiltrar datos sensibles a traves del SSRF`. [Salida original](evidencia/salidas/06-submit.txt).

El recorrido observado fue: home pública → formulario `/preview?url=...` → home de intranet → enlace publicado al backup → lectura del backup mediante preview. No fue necesario consultar `/salud`, otra ruta enlazada, para localizar ni verificar R3.

## 2. Evidencia de progreso

Se obtuvieron y validaron las tres flags: R1 `FLAG{ssrf_localhost_panel_interno}`, R2 `FLAG{ssrf_intranet_descubierta}` y R3 `FLAG{ssrf_backup_clientes}`. El estado final del verificador es:

```text
✓  R1     El server fetchea por vos: panel interno en localhost
✓  R2     Descubrir la intranet en la red interna
✓  R3     Exfiltrar datos sensibles a traves del SSRF
3/3 (100%)
```

La [salida íntegra del estado final](evidencia/salidas/20-status-all-flags.txt) conserva el formato original de `./ctf status extra`.

## 3. Preguntas de análisis

### Acceso indirecto y modelo de confianza por red

La topología del laboratorio separa la consola atacante y la intranet: el atacante solo pertenece a `labnet`, mientras que `phantomcorp-intra` solo pertenece a `internalnet`. El portal `phantomcorp` está conectado a ambas redes. Por eso, una petición directa desde la consola hacia la intranet no dispone de una ruta o resolución utilizable, pero la misma petición introducida en `/preview` puede ser emitida por el portal, que sí tiene conectividad hacia la red interna.

```text
Consola atacante --labnet--> phantomcorp (/preview) --internalnet--> phantomcorp-intra
        |                         |
        |                         +-- localhost:9000 (panel interno)
        +---- sin acceso directo a la intranet ----X
```

El componente que vuelve alcanzable indirectamente a la intranet es el servidor web `phantomcorp`, en particular su función `/preview`: acepta una URL elegida por quien consulta, realiza el request con la identidad y conectividad del servidor, y devuelve el contenido. R1 también demuestra la misma pérdida de la confianza basada solo en ubicación: `127.0.0.1` significa el propio portal para la solicitud generada por el servidor, no la consola atacante. La segmentación limita el acceso directo, pero no protege por sí sola cuando un host conectado a ambas redes puede ser inducido a solicitar destinos arbitrarios.

### P2 — Oráculo de escaneo

Las salidas de R1 muestran dos respuestas distintas al probar localhost a través de `/preview`. En `http://127.0.0.1:1/`, el portal respondió `502 Bad Gateway` y el cuerpo incluyó `Connection refused` (`evidencia/salidas/08-r1-oraculo-puertos.txt`): el intento de conexión TCP fue rechazado, consistente con que no hubiera un servicio escuchando en ese puerto. En `http://127.0.0.1:9000/`, el portal respondió `200 OK` y devolvió el panel interno con su contenido (`evidencia/salidas/09-r1-panel-local.txt`), lo que demuestra que un servicio HTTP respondió allí.

La diferencia observable permite inferir desde afuera el estado de puertos del propio servidor: por eso `/preview` actúa como un oráculo de escaneo. El atacante no consulta directamente el loopback de su consola; la aplicación realiza la petición desde el host `phantomcorp` y revela el resultado. El oráculo es limitado: un timeout, un filtro, un protocolo no HTTP o un error de la propia aplicación también pueden cambiar la respuesta, por lo que un mensaje aislado no identifica de forma infalible un servicio.

En R2 se observó un fenómeno relacionado, pero distinto: la consulta directa a `phantomcorp-intra` falló con `curl: (6) Could not resolve host`, mientras que la consulta por `/preview` devolvió `200 OK` con la página interna (`evidencia/salidas/08-p2-directo.txt` y `09-p2-intranet-preview.txt`). Esto acredita el acceso indirecto mediante el servidor. La primera presentación de la flag falló por el CRLF del manifiesto; al usar la copia temporal LF, el verificador la aceptó (`evidencia/salidas/17-p2-submit-lf-normalized.txt`).

### P3 — Hallazgo profesional

**Título:** exposición de un backup de clientes de intranet mediante SSRF en la previsualización pública.

**Activo afectado:** la confidencialidad del recurso `http://phantomcorp-intra/backups/clientes.json`. El punto de entrada es el parámetro `url` de `http://phantomcorp/preview`, en el portal PhantomCorp del laboratorio.

**Vector y condiciones:** un usuario con acceso HTTP al portal suministra una URL del host interno al formulario GET. En las solicitudes registradas no se enviaron credenciales ni cookies. La aplicación consulta el destino y devuelve su contenido. La conectividad del portal a ambas redes, definida en el entorno oficial, permite usarlo como intermediario hacia la intranet. La exposición combina la aceptación del destino interno por preview y la disponibilidad del backup para esa consulta.

**Evidencia reproducible:** la home pública revela la interfaz ([01](evidencia/salidas/01-home.txt)); el acceso directo por nombre falla ([02](evidencia/salidas/02-directo.txt)); preview devuelve la home interna con la ruta del backup ([04](evidencia/salidas/04-intranet.txt)); la consulta del enlace devuelve los datos y la flag R3 ([05](evidencia/salidas/05-backup.txt)); el verificador acepta la flag ([06](evidencia/salidas/06-submit.txt)). Los comandos se conservan en orden en el registro común.

**Impacto observado:** información de dos clientes ficticios —identificadores, razones sociales y CUIT— cruza desde un recurso interno hasta la respuesta recibida por el atacante. Se demuestra lectura no autenticada mediante el portal y pérdida de confidencialidad de ese backup. El campo llamado `integridad` contiene la flag didáctica; no demuestra alteración de datos ni una verificación criptográfica del backup. No se observaron contraseñas, tokens, acceso a una base de datos completa, escritura, shell, ejecución de código ni compromiso cloud.

**Prioridad propuesta:** alta para corregir la exposición, por la lectura de datos internos desde una función pública sin credenciales en las pruebas. Es una valoración cualitativa del escenario, no una puntuación CVSS calculada ni una afirmación de compromiso total. El alcance observado se limita a dos registros de laboratorio.

**Recomendaciones:** restringir los destinos de preview a los necesarios para su función y aplicar una política de egreso que impida acceder a la intranet desde el componente que realiza las consultas. Validar el destino efectivo al resolver y conectar, y también ante redirecciones; el bloqueo literal de `localhost` no aborda el host usado aquí. Retirar backups del servicio HTTP y exigir autorización en los recursos internos como control independiente. En producción, revisar registros de acceso para determinar el alcance de lecturas previas; no se realizó esa investigación en este laboratorio.

**Criterio de corrección:** repetir la petición de la evidencia 05 debe resultar en rechazo del destino por preview, sin devolver datos internos, mientras que una URL legítima autorizada conserva su comportamiento. No se modificó el target para probar estas defensas, porque los enunciados y el entorno son de solo lectura para las entregas.

### P4 — Mitigaciones

A partir del comportamiento observado en R1 y R3 (preview acepta y resuelve cualquier destino que se le indique, tanto `127.0.0.1:9000` como `phantomcorp-intra`), se proponen tres controles ordenados de mayor a menor robustez, pensados para el escenario real de PhantomCorp, no como una lista universal:

1. **Restringir el destino por diseño y por red (allowlist + egreso).** Si `/preview` solo necesita previsualizar un conjunto acotado de sitios, la medida de mayor eficacia es que el propio componente que ejecuta la consulta no tenga conectividad de red hacia `phantomcorp-intra` ni hacia el rango de loopback/privado del host, salvo los destinos explícitamente autorizados. Esto ataca directamente las dos cadenas demostradas: ni el panel de R1 (`127.0.0.1:9000`) ni el backup de R3 (`phantomcorp-intra`) serían alcanzables aunque la aplicación aceptara la URL. **Límite:** exige mantener la allowlist actualizada y, sobre todo, imponerla a nivel de red/segmentación (firewall, NetworkPolicy, VPC) y no solo en el código de la aplicación; si el proceso de preview comparte red con otros servicios legítimos que sí necesitan llegar a la intranet, la separación de componentes se vuelve un rediseño, no un parche menor.
2. **Validar de forma robusta la URL y su destino efectivo antes y durante la conexión.** Parsear el esquema y el host de manera canónica, resolver el DNS/la dirección antes de conectar y volver a verificar esa misma dirección en el momento de abrir el socket (para evitar que una respuesta DNS cambie entre la validación y la conexión), rechazar esquemas distintos de `http`/`https` y tratar cualquier redirección (3xx) como una nueva URL a validar, no seguirla ciegamente. **Límite:** es lógica propia, compleja de mantener correcta; una representación de IP no contemplada, una redirección encadenada o un DNS que primero resuelve a una IP pública permitida y luego a una privada (DNS rebinding) puede sortear un validador incompleto. Por eso este control complementa al punto 1, no lo reemplaza.
3. **Bloquear cadenas conocidas (`localhost`, `127.0.0.1`) como filtro adicional de bajo costo.** Es la primera barrera que cualquier desarrollador agrega, y de hecho el panel de R1 usa literalmente `127.0.0.1`. Pero la evidencia de R3 ya muestra su insuficiencia: el destino que llegó al backup fue el nombre `phantomcorp-intra`, que ninguna lista de cadenas de loopback habría detectado. Además, `127.0.0.1` tiene representaciones equivalentes que un filtro por texto no cubre —decimal (`2130706433`), octal (`0177.0.0.1`), hexadecimal (`0x7f000001`), abreviada (`127.1`) o mapeada en IPv6 (`::ffff:127.0.0.1`)— y un nombre DNS cualquiera puede resolver a una IP privada sin contener ninguna de esas cadenas. **No debe presentarse como defensa autónoma**: en PhantomCorp, por sí sola, no habría bloqueado R3 y sería trivial de evadir para R1.

El orden refleja que el control de red (1) es el único que sigue funcionando aunque la validación de aplicación (2) tenga un error, mientras que el filtro de cadenas (3) ya quedó demostrado insuficiente con la propia evidencia del grupo. Los tres controles son complementarios: la defensa real combina los tres, no elige uno solo.

**Revisión cruzada de P3 sobre esta propuesta (previa a su redacción final):** restringir destinos por diseño y por red sí aborda el recorrido observado, siempre que el proceso que hace preview no pueda alcanzar `phantomcorp-intra`. La evidencia 05 proporciona una prueba concreta de regresión. Bloquear únicamente `localhost` o `127.0.0.1` no impediría esta cadena, cuyo destino usa el nombre de intranet. Si el portal necesita conectividad interna para otras funciones, conviene separar el componente de previsualización y restringir su egreso. Una allowlist debe verificar el destino efectivo, no solamente una cadena de hostname.

### P5 — Metadata service

El servicio de metadatos (_metadata service_) es un mecanismo que utilizan las plataformas de computación en la nube para proporcionar información a las máquinas virtuales sobre su entorno de ejecución. En algunas plataformas, estos servicios también permiten obtener credenciales temporales asociadas a los permisos de la instancia.

Una dirección conocida es `169.254.169.254`, utilizada por servicios de metadatos como el de Amazon EC2. Se trata de una dirección especial accesible desde determinados entornos de nube, no de un servidor público convencional.

El problema aparece cuando una aplicación tiene una vulnerabilidad SSRF, como la que analizamos en PhantomCorp. Si el servidor acepta una URL proporcionada por un usuario y realiza la consulta sin validar correctamente el destino, un atacante podría intentar utilizar esa funcionalidad para acceder al servicio de metadatos desde el propio servidor.

En un entorno cloud mal protegido, esto podría exponer información de configuración o credenciales temporales. Si esas credenciales tienen permisos importantes, el impacto puede extenderse a otros recursos de la nube, según los permisos asignados. Por eso, las consecuencias pueden ser mayores que la simple lectura de una página interna.

Para reducir este riesgo es necesario restringir los destinos que puede consultar la aplicación, bloquear accesos innecesarios a direcciones internas y servicios de metadatos, aplicar permisos mínimos y utilizar mecanismos de protección específicos de cada plataforma, como IMDSv2 en AWS.

En nuestro laboratorio comprobamos que `/preview` permitía consultar recursos internos mediante SSRF, incluyendo un panel local y un backup de clientes. Sin embargo, no intentamos acceder a un servicio de metadatos real ni obtuvimos credenciales cloud.

Como conclusión, entendimos que una vulnerabilidad SSRF puede ser especialmente peligrosa en la nube porque el servidor podría tener acceso a recursos y permisos que el usuario externo no posee. El impacto depende de la configuración, las protecciones implementadas y los privilegios disponibles.

## 4. Conclusión

La previsualización pública permitió recuperar un panel local, la página de intranet y un backup con dos registros ficticios de clientes. La evidencia demuestra una pérdida de confidencialidad por SSRF: el portal actuó como intermediario hacia recursos que la consola atacante no obtuvo directamente. No demuestra ejecución de código, escritura ni control general de la red o del sistema operativo.

La prioridad para PhantomCorp es limitar por diseño los destinos que puede consultar `/preview` y aislar su salida de red de la intranet y de servicios locales innecesarios. Esa política debe complementarse con validación del destino efectivo —incluidas redirecciones y resolución DNS— y con retirar o proteger los backups internos mediante autorización. El estado final de los retos es 3/3; las mitigaciones son recomendaciones para un entorno real y no se implementaron ni probaron contra el objetivo de este laboratorio.
