# Informe forense — Incidente PhantomCorp (phantomcorp-web)

**Grupo:** 07 · **Investigadores:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0) · **Fecha:** 2026-11-19 (America/Buenos_Aires)
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión + posible exfiltración

> Este borrador incorpora el bloque de Lorenzo (R3/R4, alcance/respuesta y P1/P4) y deja indicados los aportes pendientes de los demás. El estado actual del CTF es 2/5; no representa una entrega grupal terminada.

## 0. Declaración de uso de IA

Se usó OpenAI Codex como asistente con acceso a la terminal para extraer una copia binaria del caso desde `upstream/main`, verificar sus hashes, buscar referencias en los artefactos autorizados, enviar las flags R3/R4 observadas y redactar este bloque. La IA ejecutó el análisis y los comandos registrados. No se leyó ni ejecutó el webshell: el artefacto provisto está defangeado. La IA no realizó conexiones a la IP del C2. Lorenzo debe revisar los hallazgos y poder explicarlos antes de cerrar la entrega.

Para el bloque C, Fernando usó OpenAI Codex para redactar el análisis y preparar los comandos de lectura, decodificación y verificación. Cotejó las conclusiones con líneas concretas de la copia del caso y con los SHA-256 de las fuentes usadas. El verificador local aceptó R1 y R2 ([salida](evidencia/salidas/fernando-validacion.txt)). Fernando debe revisar personalmente el aporte antes del cierre. [Bitácora reproducible](evidencia/comandos-fernando.txt).

Lautaro Mariño (@lautaromarino0) — bloque B (línea de tiempo completa y correlación): se utilizó **Claude (Anthropic)** como asistente, en dos aspectos. **Redacción:** ayudó a redactar la fase de entrada del §3 y la sección de correlación a partir del análisis de Lautaro, que revisó y ajustó cada fila y referencia antes de commitearla. **Contraste de pruebas:** sirvió de soporte para analizar una copia del caso en un sandbox Linux, verificar la cadena de custodia con `shasum -a 256 -c evidencia.sha256` (único archivo alterado: `logs/auth.log`) y correlacionar `access.log`, `disco/listado.txt`, `memoria/*` y los hashes. **Verificación:** cada evento remite a una línea concreta de la evidencia (`archivo:línea`); no se ejecutó ni reconstruyó el webshell (está defangeado) ni se hicieron conexiones a la IP del C2. Separé lo observado (timestamps de `access.log` en UTC) de lo de precisión de minuto sin zona (`disco/listado.txt`) y del orden sin timestamp (`bash_history`).

## 1. Resumen del incidente

El 5 de septiembre de 2026, el log de acceso registra a `185.220.101.42` enviando a `/api/reporte` una solicitud cuyo parámetro `cmd` decodificado contiene un marcador después de `echo` (`logs/access.log:19`). El verificador del laboratorio clasifica R1 como SQLi → RCE; el log acredita la solicitud y el marcador, pero no permite reconstruir la consulta SQL interna. A las 02:19:02 UTC se registra la descarga de un webshell y, a las 02:19:48 UTC, un acceso a ese recurso; el listado de disco ubica `/var/www/uploads/shell.php` a las 02:19. El extracto defangeado del webshell contiene el marcador identificado como R2 (`disco/var/www/uploads/shell.php.evidencia.txt:7`); se consultó como texto y no se ejecutó. Los artefactos posteriores muestran una escalada mediante `/usr/local/bin/system-check`, una cuenta con UID 0 y persistencia por cron. Al capturar la memoria, había una conexión `nc` establecida hacia `45.13.37.7:4444`; el historial también registra la preparación y el envío de un archivo con datos de clientes. La evidencia respalda la intención y el comando de exfiltración, pero no confirma recepción en el servidor externo; `auth.log` además no coincide con la cadena de custodia. [Extracción de referencias de Fernando](evidencia/salidas/fernando-hallazgos.txt).

## 2. Cadena de custodia

La fuente es `labs/lab11-forensia/caso/` en `upstream/main@a1abb79449a68f3cae29d1e9d43a4ac4a4f53960`. Se extrajo a `.loot/lab11-grupo07/pristine/` con `git -c core.autocrlf=false archive` y `tar`; se compararon los blobs de Git con la copia usando `git hash-object --no-filters`. El resultado completo y los comandos están en `evidencia/salidas/comparacion-blobs-git.txt` y `evidencia/comandos.txt`.

`sha256sum -c evidencia.sha256` dio `OK` para ocho archivos y `FAILED` únicamente para `logs/auth.log`. El manifiesto registra para `auth.log` el valor `0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff`; el SHA-256 calculado sobre la copia exacta es `7D18039D128D0DF7A245CA02F469EA02CD1D4F205A24FB33C5BCF7041B66E9AB`. No se modificó el archivo ni el manifiesto. El fallo demuestra una diferencia respecto del hash registrado; por sí solo no prueba quién la causó ni cuándo. Las líneas de `auth.log` no se usan como cronología corroborada. La verificación de Fernando obtuvo coincidencia para las seis fuentes citadas en su bloque y también detectó la discrepancia de `auth.log` en el chequeo general ([salida](evidencia/salidas/fernando-integridad.txt)). Ver `evidencia/salidas/verificacion-custodia.txt`; Guadalupe debe integrar la explicación de R5/P2.

## 3. Línea de tiempo del ataque

> Extracto de eventos relacionados con R3/R4 y el alcance, para integrar en la cronología completa de Lautaro. Los horarios de `access.log` están en UTC (`+0000`). Los tiempos de `disco/listado.txt` no indican zona horaria; se conservan como están y no se convierten. El historial de memoria carece de timestamps por comando.

### Fase de entrada (02:14–02:18) — contexto previo

Precede a la tabla de impacto siguiente (que arranca a las 02:18:33). Mismo atacante `185.220.101.42`, todo en `access.log` (UTC):

| Hora | Evento | Evidencia (archivo:línea) |
|---|---|---|
| 02:14:03–02:14:22 UTC | Reconocimiento desde `185.220.101.42`: `zgrab` y luego `gobuster` enumeran `/`, `robots.txt`, `/admin` (404), `/login` (404), `/backup` (301), `/portal-rrhh` (200), `/uploads` (301). | `logs/access.log:4-10` |
| 02:16:40, 02:16:58 UTC | Dos intentos fallidos de login en `POST /portal-rrhh/login` (401), con `curl`. | `logs/access.log:12-13` |
| 02:17:22 UTC | **Acceso inicial por SQLi**: `POST /portal-rrhh/login` responde 200 con el payload `user=admin'--` (bypass de autenticación). | `logs/access.log:14` |
| 02:17:41 UTC | Lee `/backup/rrhh.conf` (200): se filtra configuración, incluido el token de API `phantom-api-7c1e`. | `logs/access.log:15` |
| 02:18:10 UTC | **RCE confirmado**: `GET /api/reporte?token=phantom-api-7c1e&cmd=id` (200) — el parámetro `cmd` ejecuta comandos del sistema. | `logs/access.log:16` |

> La tabla siguiente (bloque de Lorenzo) continúa desde las 02:18:33 con el marcador en `/tmp/.p`, el drop del webshell, la escalada y la exfiltración.

| Hora | Evento | Evidencia (archivo:línea) |
|---|---|---|
| 2026-09-05 02:18:33 UTC | El endpoint de reporte ejecuta el comando que escribe el marcador en `/tmp/.p`. | `logs/access.log:19`; `disco/listado.txt:3` |
| 2026-09-05 02:19:02 UTC | Se solicita descargar `s.php` desde `45.13.37.7` y guardarlo como webshell. | `logs/access.log:20`; `memoria/bash_history.txt:4`; `disco/listado.txt:4`; `memoria/netstat.txt:5` |
| 2026-09-05 02:19:48 UTC | Primera petición observada a `shell.php`, con `c=whoami`. | `logs/access.log:21` |
| 2026-09-05 02:21 (zona no indicada) | Se registra el binario SUID `/usr/local/bin/system-check`; el snapshot de procesos muestra euid 0. | `disco/listado.txt:5`; `memoria/bash_history.txt:6-7`; `memoria/pslist.txt:8` |
| 2026-09-05 02:22 (zona no indicada) | Se crea `/etc/cron.d/phantom-maint`, identificado como persistencia. | `disco/listado.txt:6`; `disco/var/www/uploads/shell.php.evidencia.txt:9` |
| 2026-09-05 02:23:15 UTC | El webshell lee `/app/priv/clientes.db.txt` y la respuesta mide 48.210 bytes. | `logs/access.log:22` |
| Antes de la captura de memoria; orden exacto desconocido | El historial registra empaquetar `clientes.db.txt` y ejecutar `curl -F` al endpoint externo. No hay respuesta del servidor externo ni captura de tráfico que confirme recepción. | `memoria/bash_history.txt:8-9`; `memoria/lsof.txt:5` |
| 2026-09-05 02:30 UTC | En la captura de memoria, PID 1490 (`nc`) mantiene conexión TCP establecida de `10.0.0.5:41022` a `45.13.37.7:4444`. | `memoria/pslist.txt:1-10`; `memoria/netstat.txt:4`; `memoria/lsof.txt:3` |

### Correlación entre fuentes

El ataque es una sola historia reconstruida cruzando los cuatro orígenes (logs, disco, memoria, custodia); ningún artefacto alcanza por sí solo:

- **Atacante único:** `185.220.101.42` aparece en `access.log` (recon → RCE → webshell → lectura de la DB) y en `auth.log` (SSH `Accepted password for www-data`, 02:19:55). El mismo origen conecta la actividad web con la de sistema.
- **Drop del webshell (02:19:02): tres fuentes, un evento.** `access.log:20` (wget de `s.php` a `/var/www/uploads/shell.php`) ↔ `memoria/netstat.txt:5` (PID 1201 `wget` → `45.13.37.7:80`, TIME_WAIT) ↔ `disco/listado.txt:4` (`shell.php`, 431 B, 02:19) ↔ `shell.php.evidencia.txt` (dropeada por wget desde `45.13.37.7`).
- **Escalada SUID:** `auth.log` (audit del kernel 02:21:04, `system-check uid=33 euid=0`) ↔ `disco/listado.txt:5` (`system-check`, copia SUID de bash, 02:21) ↔ `memoria/pslist.txt:8` (PID 1477 `system-check`, root) ↔ `memoria/bash_history.txt:5-6` (`system-check -p -c 'id'`).
- **Exfiltración — el dato que cierra el círculo.** El webshell lee `clientes.db.txt` y la respuesta mide **48.210 bytes** (`access.log:22`, 02:23:15); el `tar` preparado en `/tmp/.exfil/clientes.tar.gz` mide **48.210 bytes** (`disco/listado.txt:7`, 02:23) y está abierto por el `bash` del atacante (`memoria/lsof.txt:5`). `bash_history:8-9` registra el `tar` y el `curl -F` al C2; `netstat:4` muestra el canal `nc` establecido a `45.13.37.7:4444`. El tamaño idéntico liga la lectura de la DB con el paquete exfiltrado.
- **C2 único:** `45.13.37.7` es el mismo host para el drop del webshell (`:80`), la reverse shell/exfil (`:4444`) y el `curl -F` del historial.
- **Anti-forense:** el atacante corrió `history -c` (`bash_history:10`; por eso el historial del disco estaba vacío y este se recuperó de memoria) y **alteró `auth.log`** (su hash no coincide con la custodia — es el único archivo que falla `shasum -a 256 -c`, ver §2). Por eso la cronología no se apoya en los timestamps de `auth.log` salvo para el orden relativo de los eventos de sistema. Queda un hueco en `auth.log` entre 02:21:04 y el cierre de sesión (02:45:00).

**La historia en una línea:** recon (02:14) → SQLi y acceso al portal (02:17:22) → fuga de config con el token (02:17:41) → RCE por `cmd=` (02:18:10) → drop del webshell desde el C2 (02:19:02) → SSH como `www-data` (02:19:55) → escalada SUID a root (02:21) → persistencia (cron `phantom-maint` + backdoor `phantom-svc`, uid 0) → staging y exfiltración de `clientes.db.txt` al C2 (02:23) → borrado de rastros (`history -c`, edición de `auth.log`) → cierre de sesión (02:45).

## 4. Indicadores de compromiso

Inventario integrado a partir de las referencias de Lorenzo y Fernando. El hash del extracto defangeado no debe atribuirse al archivo original del servidor.

| Tipo | Valor | Dónde apareció |
|---|---|---|
| IP atacante | `185.220.101.42` | `logs/access.log:4-22` |
| C2 TCP | `45.13.37.7:4444` | `memoria/netstat.txt:4`; proceso `nc`, `memoria/pslist.txt:9` |
| Host de descarga/upload HTTP | `45.13.37.7:80` (puerto por defecto inferido de las URLs `http://`) | `memoria/bash_history.txt:4,9`; descarga también en `memoria/netstat.txt:5` |
| Webshell | `/var/www/uploads/shell.php` (captura defangeada) | `disco/var/www/uploads/shell.php.evidencia.txt`; `logs/access.log:20-22` |
| SHA-256 del extracto del webshell | `38f7251c9fe2f554a2a9808fea0b154f1f4e88f7b47c1e4afbd589055a22fc42` | Hash del archivo de evidencia defangeado `disco/var/www/uploads/shell.php.evidencia.txt`; no es un hash verificado del archivo original en el servidor. |
| Binario SUID anómalo | `/usr/local/bin/system-check`, descrito como copia de Bash | `disco/listado.txt:5`; `memoria/pslist.txt:8` |
| Usuario backdoor | `phantom-svc`, UID 0 | `disco/etc/passwd.snippet:4` |
| Persistencia | `/etc/cron.d/phantom-maint` | `disco/listado.txt:6`; comentario del artefacto defangeado |

## 5. Alcance del daño

- El endpoint `/api/reporte` ejecutó comandos arbitrarios y dejó un marcador en `/tmp/.p` (`logs/access.log:18-20`).
- Se descargó y usó `/var/www/uploads/shell.php`; la captura está neutralizada y no debe ejecutarse (`logs/access.log:20-21`; artefacto de disco).
- El atacante creó `/usr/local/bin/system-check`, identificado como copia SUID de Bash, y el proceso observado tenía euid 0 (`disco/listado.txt:5`; `memoria/pslist.txt:8`). También se agregó `phantom-svc` con UID 0 (`disco/etc/passwd.snippet:4`).
- Se registró `/etc/cron.d/phantom-maint` como persistencia, y el artefacto de webshell dice que se relanzaba cada cinco minutos (`disco/listado.txt:6`; `shell.php.evidencia.txt:9`).
- El comando de historial empaqueta `/app/priv/clientes.db.txt` en `/tmp/.exfil/clientes.tar.gz` y luego usa `curl -F` contra `45.13.37.7/upload`; `lsof` muestra el archivo abierto y el listado registra un tamaño de 48.210 bytes. La petición al webshell devolvió 48.210 bytes (`logs/access.log:22`). Esto sustenta acceso y un intento de exfiltración; sin telemetría del destino o confirmación del upload no puede afirmarse que el C2 recibió el archivo.
- La captura de memoria documenta una sesión C2 establecida al momento de la captura (`memoria/netstat.txt:4`). La evidencia no permite afirmar si siguió activa después de las 02:30 UTC.

## 6. Contención y erradicación (recomendaciones priorizadas)

1. **Preservar antes de limpiar:** ante una captura en vivo, adquirir RAM y estado de conexiones/procesos primero; después hacer imagen forense del disco y conservar logs originales. Calcular y registrar hashes de cada adquisición, operador, herramienta, hora y zona horaria.
2. **Contener el host y el egreso:** aislar `phantomcorp-web` de forma controlada luego de preservar la evidencia volátil; bloquear en perímetro `185.220.101.42` y el egreso a `45.13.37.7` (incluidos TCP/4444 y HTTP/80), y buscar esos indicadores en otros sistemas. No conectarse al C2.
3. **Revocar secretos:** rotar credenciales de aplicación/DB y tokens accesibles desde el host; revocar sesiones y claves potencialmente expuestas. Revisar el alcance sobre `clientes.db.txt` y notificar a los responsables de datos según el proceso de incidentes.
4. **Erradicar persistencia tras preservar:** detener procesos maliciosos, deshabilitar `phantom-svc`, retirar el cron y el webshell, y eliminar el binario SUID anómalo. Revisar otros mecanismos de persistencia y cuentas UID 0.
5. **Recuperar de forma confiable:** reconstruir desde una imagen limpia; corregir el endpoint de reporte para que no invoque un shell con datos controlables, revisar autenticación/autorización y limitar escritura/ejecución en uploads. Aplicar mínimo privilegio y revisar reglas SUID.
6. **Verificar:** buscar los IOCs en toda la infraestructura, confirmar que no quedan sesiones ni tareas programadas no autorizadas, monitorear el egreso y documentar el alcance con incertidumbres explícitas.

## 7. Preguntas de análisis

**P1 — por qué RAM antes que disco:** la RAM y el estado de procesos/conexiones se pierden al apagar o reiniciar; el disco y sus archivos suelen persistir más. En este caso, la memoria conserva el proceso `system-check` con euid 0, la conexión TCP establecida de `nc` al C2 y el archivo de exfiltración abierto (`memoria/pslist.txt:8-9`, `netstat.txt:4`, `lsof.txt:3-5`). El disco conserva el binario y el cron, pero no el socket activo ni el estado del proceso. Por eso se adquiere primero la evidencia volátil. El laboratorio proporciona artefactos ya extraídos, no un volcado RAM crudo.

**P2 — cómo se detectó la alteración:** pendiente — bloque de Guadalupe.

**P3 — correlación de tres artefactos.** `logs/access.log:20-21` registra a las 02:19:02 UTC una solicitud de descarga de `/var/www/uploads/shell.php` desde `185.220.101.42` y a las 02:19:48 UTC un acceso HTTP 200 al mismo recurso desde ese origen. `disco/listado.txt:4` registra el archivo, de 431 bytes, a las 02:19; esa hora tiene precisión de un minuto y el listado no especifica zona horaria. En la captura de memoria de las 02:30 UTC, `memoria/pslist.txt:6` asocia el PID 1201, bajo `www-data`, con la descarga, y `memoria/netstat.txt:5` vincula ese PID con `45.13.37.7:80` en estado `TIME_WAIT`.

La coincidencia de ruta, origen y proceso respalda que se descargó el webshell y luego se accedió a él. La relación temporal entre el log y el listado depende de que este último use UTC. La memoria corrobora actividad posterior; los extractos no determinan la hora exacta de inicio del proceso ni de apertura o cierre de la conexión. [Referencias y extracción](evidencia/salidas/fernando-hallazgos.txt).

**P4 — recuperación tras `history -c`:** el `bash_history` del disco fue borrado, pero la secuencia se recuperó de memoria (`memoria/bash_history.txt:1-10`). La sesión y los datos que manejaba permanecían en el estado volátil capturado; borrar el archivo de historial no elimina evidencia ya presente en la memoria del proceso o recogida antes de que desaparezca.

**P5 — por qué el forense debe entender pentesting.** Conocer la secuencia de un ataque ayuda a formular hipótesis verificables. Un HTTP 200 acredita que el servidor respondió; para establecer el efecto de la solicitud, el forense busca rastros de esa acción en otras fuentes. Aquí, la solicitud que apunta a un webshell orienta la búsqueda hacia la ruta en disco y la actividad de descarga en memoria. La cercanía de dos horas sirve para orientar la búsqueda; la coincidencia de ruta, origen y proceso aporta más evidencia.

Los labs de agentes y defensa refuerzan esa distinción. Un transcript permite seguir qué acción se propuso y qué resultado quedó registrado. Una alerta indica que se cumplieron las condiciones de una regla. El análisis forense contrasta esas señales con los artefactos y declara el grado de certeza que permiten. [Consigna del laboratorio](../../../labs/lab11-forensia/README.md).

## 8. Estado de flags (anexo de avance)

Las capturas locales corresponden a checkouts distintos: la de Lorenzo registra **2/5**, con R3/R4 resueltos; la de Fernando registra **2/5**, con R1/R2 aceptados localmente. No hay una captura consolidada desde un mismo checkout que permita afirmar **4/5**. R5 sigue pendiente en ambas. Ver [estado de Lorenzo](evidencia/salidas/status-11.txt) y [estado de Fernando](evidencia/salidas/fernando-status-11.txt); el grupo debe verificar el estado común antes de cerrar.
