# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 02
**Integrantes:**
- Romero Jimena Soledad (legajo 15377) — @Jimena-Romero
- Milanesio Hebe Del Lourdes (legajo 15343) — @hebemilanesio1
- Toranzo Juan Cruz (legajo 15308) — @JuanToranzo
- Torres Damaris (legajo 14563) — @damaris412

**Fecha:** 18/10/2026

---

## 0. Declaración de uso de IA

Se usó Claude (Anthropic) como asistente para estructurar el informe, redactar el análisis y resolver problemas del entorno (WSL, Docker, saltos de línea CRLF). Todos los comandos de recon fueron ejecutados por el grupo contra `phantomcorp`, y la evidencia y las flags salen de esas salidas. Los CVE se consultaron en NVD y fuentes de seguimiento de vulnerabilidades; los CVSS que no se pudieron confirmar figuran como "no verificado".

---

## 1. Parte práctica — flags capturadas

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 05                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Puerto oculto en rango alto (barrido completo)
   ✓  R2     Banner grabbing del servicio FTP
   ✓  R3     Fuga de informacion en headers HTTP
   ✓  R4     Enumeracion de rutas via robots.txt
   ✓  R5     Servicio dev expuesto en produccion

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 05 COMPLETO! Ponete las pilas con la próxima unidad.
```

---

## 2. Mapa de superficie de ataque

| Puerto | Servicio | Versión (evidencia) | ¿Cómo lo identificaste? | CVE relevante | CVSS | Criticidad | Justificación (contra ESTE caso) |
|---|---|---|---|---|---|---|---|
| 21 | FTP | `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)` | `nmap -sV` y banner grabbing con `ncat` | CVE-2015-3306 (`mod_copy`: lectura/escritura arbitraria con `SITE CPFR/CPTO`) | CVSS v2: 10.0 (`AV:N/AC:L/Au:N/C:C/I:C/A:C`). Un agregador reporta v3.1 de 10.0; pendiente de confirmar en NVD | Crítica (condicional) | La versión exacta figura como afectada en NVD y la falla es remota y sin autenticación. **No verificamos que `mod_copy` esté cargado**, por lo que es una vulnerabilidad probable, no confirmada. Además el banner publica producto y versión sin necesidad. |
| 80 | HTTP | `Server: PhantomServer/2.4.1`, `X-Powered-By: PhantomCMS 2.4.1` | `nmap -sV`, `curl -I`, `curl` a `robots.txt` | No encontramos CVE para PhantomServer/PhantomCMS; no pudimos clasificar por CVE | N/A | Media | Sin CVE, pero filtra información: versiones en headers, un header `X-Backend-Flag` con datos internos, un comentario HTML que pide "sacar el panel interno de producción" y un `robots.txt` que lista `/admin` y `/panel-interno-9x2f`. Esta última ruta respondió con contenido: el panel interno es accesible desde afuera. |
| 8080 | HTTP (API de desarrollo) | `Werkzeug httpd 2.0.1 (Python 3.9.2)`; `/status` devuelve `{"service":"phantom-dev-api","version":"0.9.3-DEV","debug":true,...}` | `nmap -sV`, `curl -si` a `/` y a `/status` | Werkzeug 2.0.1 está afectado por CVE-2023-23934 y CVE-2023-25577 (corregidos en 2.2.3) y CVE-2024-34069 (debugger, corregido en 3.0.3) | No verificado | Alta | Es un servicio de desarrollo (`0.9.3-DEV`, `debug:true`) expuesto sin autenticación, que revela versiones y su modo de depuración. No confirmamos que el debugger de Werkzeug esté activo, por eso no afirmamos ejecución de código. |
| 31337 | Desconocido (nmap: `Elite?`) | `PhantomCorp maintenance shell v0.1 -- acceso no autorizado prohibido` | `nmap -sV -p-` (fingerprint) y `ncat -w2` | Sin CVE; no pudimos determinar producto ni versión | N/A | Alta | Un "maintenance shell" escuchando en la red sin autenticación aparente es un acceso de administración expuesto. Solo leímos el banner y **no enviamos comandos**, así que no sabemos qué permite hacer. |

Evidencia de respaldo:

```
$ nmap -Pn -sV -p- phantomcorp
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     ProFTPD 1.3.5
80/tcp    open  http    PhantomServer/2.4.1
8080/tcp  open  http    Werkzeug httpd 2.0.1 (Python 3.9.2)
31337/tcp open  Elite?
Service Info: OS: Unix
Nmap done: 1 IP address (1 host up) scanned in 90.25 seconds

$ ncat -w2 phantomcorp 21 </dev/null
220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]

$ curl -I phantomcorp
HTTP/1.0 200 OK
Server: PhantomServer/2.4.1
X-Powered-By: PhantomCMS 2.4.1
X-Backend-Flag: (valor omitido)

$ curl -s phantomcorp/robots.txt
User-agent: *
Disallow: /admin
Disallow: /panel-interno-9x2f
# Recordatorio infra: /panel-interno-9x2f sigue accesible desde afuera. Migrar a VPN.

$ curl -si phantomcorp:8080/status
HTTP/1.0 200 OK
Server: Werkzeug/2.0.1 Python/3.9.2
{"service":"phantom-dev-api","version":"0.9.3-DEV","debug":true,...}
```

Archivos completos en `evidencia/`: `nmap_default.txt`, `nmap_full.txt`, `banner_ftp.txt`, `headers_80.txt`, `robots.txt`, `ruta_oculta.txt`, `admin.txt`, `web_8080.txt`, `banner_31337.txt`.

Fuentes de los CVE: NVD (nvd.nist.gov) para CVE-2015-3306 y CVE-2024-34069; aviso Ubuntu USN-5948-1 para CVE-2023-23934 y CVE-2023-25577.

---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**
En nuestro caso, `nmap -p-` **no encontró ningún puerto extra**: el escaneo default ya mostraba los mismos cuatro (21, 80, 8080 y 31337). Esto pasa porque el 31337 está entre los 1000 puertos más frecuentes que nmap prueba por defecto, ya que es un puerto clásico de backdoors. Lo que aportó `-p-` junto con `-sV` fue la identificación de versiones, el banner del 31337 y la certeza de que no hay nada más en los 65535 puertos. La regla operativa es escanear siempre el rango completo, porque el default es una lista de puertos populares y no dice nada del resto. Esta vez no hizo falta, pero en un caso real un servicio en un puerto alto arbitrario solo aparece con `-p-`.

**P2 — El servicio dev en producción.**
Lo muestra la respuesta de `/status` en el 8080: `"version":"0.9.3-DEV"`, `"debug":true` y el nombre `phantom-dev-api`; además la raíz responde con una pista para desarrolladores ("Probá /status"). También el comentario HTML del puerto 80 habla de sacar el panel interno antes del go-live. Es un problema aunque no tenga un CVE conocido porque un servicio de desarrollo no tiene el endurecimiento de producción: expone modo debug, versiones y estructura interna, y suele no tener autenticación. Eso reduce el esfuerzo del atacante para planear el siguiente paso.

**P3 — La ironía de `robots.txt`.**
`robots.txt` se creó para indicarle a los buscadores qué rutas no indexar. Es una convención voluntaria y pública, no un control de acceso. La ironía es que, para decirle a Google "no mires acá", hay que escribir esas rutas en un archivo que cualquiera puede leer. En PhantomCorp listaba `/admin` y `/panel-interno-9x2f`, y esta última respondió con contenido interno. El archivo pensado para ocultar rutas terminó siendo un mapa de las rutas sensibles.

**P4 — Pasivo vs. activo.**
El recon pasivo recolecta información sin interactuar con el objetivo; el activo sí interactúa y deja huella. En este lab todo lo que hicimos contra `phantomcorp` fue activo y habría quedado en sus logs: el `ping`, ambos `nmap` (el `-p-` generó conexiones a miles de puertos), los `ncat` a los puertos 21 y 31337 y los `curl` al 80 y al 8080 (incluidas las consultas a `robots.txt`, `/admin`, `/panel-interno-9x2f` y `/status`). Una acción pasiva fue buscar los CVE en NVD y otras bases públicas: no se contactó a PhantomCorp en ningún momento. `whois` y `dig` contra dominios públicos serían otros ejemplos, pero no los ejecutamos en este lab.

**P5 — Ahora sos el defensor.**
1. *Puerto 8080 (API de desarrollo):* retirarlo de producción. Si debe existir, moverlo a una red interna o detrás de VPN, desactivar `debug` y exigir autenticación. Así deja de ser alcanzable desde afuera.
2. *Puerto 21 (ProFTPD 1.3.5):* actualizar ProFTPD a una versión corregida y, mientras tanto, desactivar `mod_copy` si no se usa. Además, ocultar la versión del banner (`ServerIdent`) para que no publique producto y versión.

---

## 4. Bitácora de comandos

```bash
# Host (Ubuntu/WSL)
make setup
make lab N=05
make shell

# Consola del atacante
ping -c1 phantomcorp
nmap -Pn phantomcorp | tee /loot/nmap_default.txt
nmap -Pn -sV -p- phantomcorp | tee /loot/nmap_full.txt
ncat -w2 phantomcorp 21 </dev/null | tee /loot/banner_ftp.txt
ncat -w2 phantomcorp 31337 </dev/null | tee /loot/banner_31337.txt
curl -I phantomcorp | tee /loot/headers_80.txt
curl -s phantomcorp/robots.txt | tee /loot/robots.txt
curl -s phantomcorp/panel-interno-9x2f | tee /loot/ruta_oculta.txt
curl -s -i phantomcorp/admin | tee /loot/admin.txt
curl -si phantomcorp:8080/ | tee /loot/web_8080.txt
curl -si phantomcorp:8080/status

# Host: entrega de flags y evidencia
bash ctf submit 05 R1 'FLAG{...}'   # y R2 a R5
bash ctf status 05
cp .loot/* entregas/lab05/grupo02/evidencia/
```

Nota de entorno: en Windows/WSL los scripts del repo tenían saltos de línea CRLF y hubo que convertirlos con `sed -i 's/\r$//'` (incluido `retos.manifest`) para que `ctf` aceptara las flags.