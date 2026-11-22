# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 08
**Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919
**Fecha:** 30 de octubre de 2026

**Alcance y autorización:** únicamente el contenedor `phantomcorp` provisto por la cátedra y nuestra propia consola atacante. No se escaneó ningún sistema de terceros (Ley 26.388).

---

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Ejecución de los comandos de reconocimiento desde la consola del atacante; consulta de NVD y de fuentes primarias; borrador del mapa de superficie, de P1–P5 y del mini-research. | Secciones 1 a 4 de este informe, `research.md` y `evidencia/`. | Las flags se validaron con `./ctf submit`. Cada fila del mapa remite a una salida guardada en `evidencia/`. Los CVE y los CVSS salen de la API de NVD, no de memoria. Las fuentes citadas se abrieron para confirmar que existen y dicen lo que se les atribuye. No se leyó el código del target (`server.py`) ni `solucion.md`: todo lo observado sale de operar las tools. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Parte práctica — flags capturadas

Salida de `./ctf status 05`, en la corrida del 30/10/2026 (máquina de Thomas Koncurat; copia en [`ctf-status.txt`](evidencia/ctf-status.txt)):

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 05                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Puerto oculto en rango alto (barrido completo)
   ✓  R2     Banner grabbing del servicio FTP
   ✓  R3     Fuga de informacion en headers HTTP
   ✓  R4     Enumeracion de rutas via robots.txt
   ✓  R5     Servicio dev expuesto en produccion

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 05 COMPLETO! Ponete las pilas con la próxima unidad.
```

| Reto | Técnica | Evidencia |
|---|---|---|
| R1 | Barrido de puertos y banner del 31337 | [`nmap-sV-full.txt`](evidencia/nmap-sV-full.txt), [`banner-31337.txt`](evidencia/banner-31337.txt) |
| R2 | Banner grabbing del 21 | [`banner-21.txt`](evidencia/banner-21.txt) |
| R3 | Headers HTTP del 80 | [`headers-80.txt`](evidencia/headers-80.txt) |
| R4 | `robots.txt` y ruta oculta | [`robots-80.txt`](evidencia/robots-80.txt), [`route-panel.txt`](evidencia/route-panel.txt) |
| R5 | Endpoint de estado del 8080 | [`route-status.txt`](evidencia/route-status.txt) |

---

## 2. Mapa de superficie de ataque

Usamos **declarada** para las versiones que el servicio anuncia pero no pudimos confirmar por su comportamiento (ver notas).

| Puerto | Servicio | Versión (evidencia) | ¿Cómo lo identificaste? | CVE relevante | CVSS | Criticidad | Justificación (contra ESTE caso) |
|---|---|---|---|---|---|---|---|
| 21/tcp | FTP | **ProFTPD 1.3.5, declarada.** Banner: `220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]`. nmap: `21/tcp open ftp ProFTPD 1.3.5` | Banner grabbing con `ncat`. `nmap -sV` coincide, pero lee el mismo banner | CVE-2015-3306 (`mod_copy`). Aplica por versión declarada; no pudimos verificar si es explotable acá | 10.0 en v2 (NVD: `AV:N/AC:L/Au:N/C:C/I:C/A:C`). 10.0 en v3.1 (CISA-ADP: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) | **Crítica, a validar** | El CVE permite leer y escribir archivos sin credenciales, y este host también sirve HTTP, el escenario documentado para llegar a ejecutar código si el FTP puede escribir en un directorio web que lo interprete. Por eso es lo primero a validar. Límite: el servicio cierra la conexión tras el saludo y no respondió a `SYST`, así que no pudimos probar `SITE CPFR`. La criticidad refleja el impacto si se confirma, no una explotación demostrada. |
| 80/tcp | HTTP | **PhantomServer 2.4.1 y PhantomCMS 2.4.1, declaradas.** `Server: PhantomServer/2.4.1` y `X-Powered-By: PhantomCMS 2.4.1` | `curl -I`, `nmap -sV` y lectura de `robots.txt` | Ninguno. NVD no devuelve resultados para `PhantomServer` ni `PhantomCMS` (consulta del 30/10/2026) | Sin score oficial. Estimación propia: 5.3 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | **Media** | Confirmado: `/panel-interno-9x2f` responde `200` sin credenciales aunque su texto dice "Acceso restringido", y `robots.txt` lo publica. También filtra versiones en los headers. Queda en Media porque solo vimos contenido estático, sin datos de negocio ni funciones. Subiría si la enumeración encuentra acciones detrás del panel. |
| 8080/tcp | HTTP, API de desarrollo | **`phantom-dev-api` 0.9.3-DEV**, según `/status`: `"version":"0.9.3-DEV","debug":true`. **Werkzeug 2.0.1 y Python 3.9.2, declaradas e inconsistentes** con lo observado (nota 2) | `nmap -sV` y `curl -i` a `/` y `/status` | Ninguno aplicable confirmado (nota 3) | Sin score oficial. Estimación propia: 5.3 (mismo vector que el 80) | **Media** | Cualquier cliente obtiene, sin autenticarse, nombre interno, versión y estado de debug de un servicio de desarrollo. `debug:true` no se tradujo en un acceso mayor: no vimos trazas y `/console` devuelve el mismo texto que cualquier ruta. Por eso no es Crítica. Su riesgo es la exposición de código que no estaba pensado para producción (ver P2). |
| 31337/tcp | TCP no estándar, "maintenance shell" | **No pudimos determinar producto ni versión con nmap:** `31337/tcp open Elite?` (`Elite` es el nombre asociado al número de puerto, no una identificación). Único dato, autodeclarado: `PhantomCorp maintenance shell v0.1` | Barrido con nmap y banner grabbing con `ncat` | Ninguno. Sin producto identificable; NVD no devuelve resultados para `PhantomCorp` | Sin score: no observamos una vulnerabilidad concreta que puntuar, solo un banner | **Media, por incertidumbre** | Se anuncia como shell de mantenimiento y responde a cualquier cliente sin autenticación. Pero envía el banner y cierra: `help` no obtuvo respuesta, así que no observamos ejecución de comandos. La clasificamos Media por lo que no sabemos, no por un impacto demostrado, y subiría a Crítica si existe una forma de interacción que no encontramos. Al parecer es software propio, de modo que ningún CVE avisaría si tuviera fallas. |

**Orden de ataque propuesto:** primero el 21 por impacto potencial, empezando por determinar si detrás del banner hay un ProFTPD real, porque la sesión que vimos no atiende comandos. Después el 8080 por ser código de desarrollo con endpoints a enumerar, el 80 por el panel ya accesible y, al final, el 31337 porque no aceptó entrada.

**Notas de confiabilidad**

1. **Declarado no es confirmado.** Un banner es texto que escribe el propio servidor; en ProFTPD se cambia con la directiva `ServerIdent`. La columna `VERSION` de nmap en los puertos 21, 80 y 8080 reproduce esas cadenas, de modo que no es una segunda fuente independiente.
2. **El header del 8080 no coincide con su comportamiento.** `HEAD`, `POST` y `OPTIONS` reciben `501 Unsupported method`, el mensaje de `BaseHTTPRequestHandler`, de `http.server` de Python. El servidor de Werkzeug 2.0.1 no debería responder así: su `handle_one_request` pasa toda petición a `run_wsgi()`. El puerto 80 muestra la misma plantilla de error ante `OPTIONS`. Por eso no tomamos el header como prueba del software real, y no leímos el código del target para resolverlo. Ver [`8080-metodos.txt`](evidencia/8080-metodos.txt) y, para el 80, el fingerprint de [`nmap-sV-full.txt`](evidencia/nmap-sV-full.txt).
3. **CVE de Werkzeug evaluados y descartados.** NVD lista fallas por rango de versión que incluirían a una 2.0.1 real, pero no incluimos ninguna porque no observamos sus condiciones. CVE-2023-25577 (anterior a 2.2.3, CVSS 7.5) afecta al parser de `multipart/form-data`, y el servicio rechaza `POST` con 501. CVE-2024-34069 (anterior a 3.0.3, CVSS 7.5) requiere el debugger, y `/console` no lo muestra. Ver [`nvd-consultas.txt`](evidencia/nvd-consultas.txt).
4. **Falso positivo a tener en cuenta.** El 8080 responde `200` a cualquier ruta (`/console`, `/robots.txt`, `/no-existe-xyz`) con el mismo texto ([`8080-rutas.txt`](evidencia/8080-rutas.txt)). Un `200` no prueba que la ruta exista, algo que hay que considerar al enumerar en el Lab 06.
5. **Límites de este mapa.** Cubre solo TCP: no ejecutamos un escaneo UDP (`-sU`). `searchsploit`, mencionado en el enunciado, no está instalado en la consola ([`searchsploit.txt`](evidencia/searchsploit.txt)), así que la clasificación se hizo contra NVD ([`nvd-consultas.txt`](evidencia/nvd-consultas.txt)). El 5.3 de los puertos 80 y 8080 es una estimación nuestra del hallazgo, no un score publicado.

**Evidencia de respaldo** (salidas completas en [`evidencia/`](evidencia/)):

```
$ nmap -Pn phantomcorp
Not shown: 996 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
8080/tcp  open  http-proxy
31337/tcp open  Elite
Nmap done: 1 IP address (1 host up) scanned in 0.68 seconds

$ nmap -Pn -sV -p- phantomcorp      (recortado: se omiten los fingerprints SF)
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     ProFTPD 1.3.5
80/tcp    open  http    PhantomServer/2.4.1
8080/tcp  open  http    Werkzeug httpd 2.0.1 (Python 3.9.2)
31337/tcp open  Elite?
Nmap done: 1 IP address (1 host up) scanned in 94.73 seconds

$ ncat -w3 phantomcorp 21 </dev/null
220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]
214 FLAG{banner_grab_proftpd_135}

$ printf 'SYST\r\nQUIT\r\n' | ncat -w3 phantomcorp 21
220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]
214 FLAG{banner_grab_proftpd_135}
Ncat: Connection reset by peer.

$ ncat -w2 phantomcorp 31337 </dev/null
PhantomCorp maintenance shell v0.1 -- acceso no autorizado prohibido
FLAG{high_port_secret_service}

$ curl -sI phantomcorp
HTTP/1.0 200 OK
Server: PhantomServer/2.4.1
Content-Type: text/html; charset=utf-8
X-Powered-By: PhantomCMS 2.4.1
X-Backend-Flag: FLAG{http_headers_leak_info}

$ curl -s phantomcorp/robots.txt
User-agent: *
Disallow: /admin
Disallow: /panel-interno-9x2f
# Recordatorio infra: /panel-interno-9x2f sigue accesible desde afuera. Migrar a VPN.

$ curl -si phantomcorp/panel-interno-9x2f      (recortado)
HTTP/1.0 200 OK
<h1>Panel interno PhantomCorp</h1>
<p>Acceso restringido. [...]</p>
<pre>FLAG{recon_hidden_path}</pre>

$ curl -si phantomcorp:8080/status      (recortado)
HTTP/1.0 200 OK
Server: Werkzeug/2.0.1 Python/3.9.2
{"service":"phantom-dev-api","version":"0.9.3-DEV","debug":true,"flag":"FLAG{dev_service_exposed}"}

$ curl -sI phantomcorp:8080
HTTP/1.0 501 Unsupported method ('HEAD')
Server: Werkzeug/2.0.1 Python/3.9.2
```

---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**

**La premisa no se reprodujo en nuestra corrida.** El enunciado supone que el escaneo default pierde el 31337, pero `nmap -Pn phantomcorp` (nmap 7.95) ya lo listó: `31337/tcp open Elite`. El motivo es que el default no son los puertos 1 a 1000, sino los 1000 con mayor frecuencia en `nmap-services`, y el 31337 está entre ellos ([`top1000.txt`](evidencia/top1000.txt)). En este objetivo, `-p-` encontró los mismos cuatro puertos.

Lo que aportó `-p-` fue **cobertura**: probó los 65535 puertos, y recién entonces pudimos afirmar que no hay otro servicio TCP abierto (`Not shown: 65531 closed`). Para comprobar el principio, levantamos un listener en el 31338, que no está en la lista, dentro de nuestra propia consola atacante. El default devolvió `Not shown: 1000 closed` y `-p-` encontró `31338/tcp open unknown` ([`demo-default.txt`](evidencia/demo-default.txt), [`demo-full.txt`](evidencia/demo-full.txt)).

**Regla operativa:** "puerto alto" no significa "fuera del default", y un default limpio no prueba que no haya nada más. Siempre corremos `-p-`, porque el costo acá fue bajo: 0,68 s el default, 4,93 s con `-p-` y 94,73 s con `-sV -p-`, en una red Docker local.

**P2 — El servicio dev en producción.**

La evidencia sale del propio servicio: `/` responde `phantom-dev-api. Proba /status`, y `/status` devuelve `"version":"0.9.3-DEV"` y `"debug":true`, sin autenticación. El header `Werkzeug/2.0.1` apuntaría a un servidor de desarrollo, pero no nos apoyamos en él por la inconsistencia de la nota 2.

Un CVE describe una falla de un producto; acá el problema es de exposición y configuración (CWE-489, *Active Debug Code*), algo que un cruce de versiones contra una base de CVE no marcaría. En este caso concreto, cualquiera que alcance el puerto obtiene el nombre interno, la versión y el modo debug, que son datos útiles para el paso siguiente. Además, es razonable suponer que un build `-DEV` no pasó por el mismo control que producción, y nadie va a recibir un aviso si tiene una falla propia. No observamos trazas ni una consola de debug, así que el impacto demostrado es fuga de información y no ejecución de código.

**P3 — La ironía de `robots.txt`.**

`robots.txt` se creó para indicarles a los crawlers qué no indexar: es una convención de SEO, no un control de acceso. RFC 9309 lo dice sin vueltas: *"These rules are not a form of access authorization"*, y advierte que listar rutas *"exposes them publicly and thus makes the paths discoverable"*.

Eso pasó acá. El sufijo de `/panel-interno-9x2f` lo vuelve difícil de adivinar, pero el propio `robots.txt` lo publica, y hasta agrega el comentario `sigue accesible desde afuera`. Bastó un `curl` para obtener `200` sin credenciales. La ironía es que el archivo escrito para esconder la ruta de Google se la entregó al atacante: un control pensado para una cosa (SEO) filtró información para otra (recon). El comentario `TODO(infra)` en el HTML de la portada refuerza la misma pista.

**P4 — Pasivo vs. activo.**

- **Pasivo:** consultar en NVD `CVE-2015-3306`, `PhantomCMS` y `PhantomServer`. Ese tráfico no llega a PhantomCorp, que no tiene forma de enterarse. `whois` y `dig` no aplicaban: `phantomcorp` es un host interno sin DNS público, y no los corrimos contra terceros.
- **Activo:** todo lo que envió paquetes al objetivo: `nmap`, `ncat` y `curl`.

Deberían haber quedado en los logs de aplicación los `curl` a `/robots.txt`, `/panel-interno-9x2f` y `/status`, las conexiones de `ncat`, y sobre todo `-sV`, que es ruidoso: sus sondas (`GetRequest`, `HTTPOptions`, `RTSPRequest`, `LDAPBindReq`) quedaron visibles en el fingerprint de nmap. El barrido de puertos, en cambio, fue un SYN scan (`Initiating SYN Stealth Scan`, ejecutado como root; ver [`scan-type.txt`](evidencia/scan-type.txt)): no completa el handshake, así que la aplicación no llega a verlo, y haría falta un firewall o un IDS para registrarlo.

**Esto no pudimos confirmarlo empíricamente:** `docker logs cyberlab-phantomcorp` muestra solo la línea de arranque ([`target-logs.txt`](evidencia/target-logs.txt)), sin ninguna de nuestras peticiones. No sabemos si registra en otro lado, porque no entramos al target a mirarlo. Si no registra, el defensor no vería el reconocimiento, lo que sería otro hallazgo en sí mismo.

**P5 — Ahora sos el defensor.**

**Hallazgo 1: FTP en el 21 (CVE-2015-3306).**
- Si no hace falta FTP, apagar el servicio y cerrar el puerto. Si hace falta, limitar el 21 por firewall a las IP que lo necesitan.
- Actualizar ProFTPD a una versión mantenida: el bug se resolvió en 1.3.5a y 1.3.6rc1. Desde 1.3.6rc1 existe `CopyEngine off`, que hace que `mod_copy` ignore estos comandos.
- Dejar de anunciar la versión con `ServerIdent on "FTP Server ready."`. Esto reduce información, pero no corrige la falla.
- **Verificación:** sin hacer login, `site cpfr /etc/passwd` no debe responder `350`. Contra lo que vimos hoy esa prueba no se puede ejecutar, porque el servicio cierra la conexión tras el saludo ([`comandos-21-31337.txt`](evidencia/comandos-21-31337.txt)), así que antes hay que aclarar qué corre en el 21.

**Hallazgo 2: panel interno en `/panel-interno-9x2f`.**
- Sacarlo de la exposición externa con la migración a VPN que la propia nota de infraestructura pide.
- Mientras tanto, exigir autenticación HTTP en esa ruta, la medida que sugiere RFC 9309. Un texto que diga "Acceso restringido" no restringe nada.
- Quitar la ruta y el comentario de `robots.txt`, y el `TODO(infra)` del HTML.
- **Verificación:** desde fuera de la VPN, `curl -s -o /dev/null -w '%{http_code}' phantomcorp/panel-interno-9x2f` debe dar `401` o `403`, o no conectar, y `robots.txt` no debe mencionar la ruta.

---

## 4. Bitácora de comandos

```bash
# Entorno. Sin make en Windows: es el comando que ejecuta `make lab N=05`
docker compose -p cyberlab --project-directory . -f entorno/docker-compose.yml \
  -f labs/lab05-reconocimiento/entorno/target.compose.yml up -d --build
docker exec -it cyberlab-attacker bash

# Descubrir
nmap -Pn -oN nmap-default.txt phantomcorp
nmap -Pn -p- -oN nmap-full-noversion.txt phantomcorp
nmap -Pn -sV -p- -oN nmap-sV-full.txt phantomcorp
nmap -Pn -p80,8080 --script http-methods,http-robots.txt,http-title phantomcorp

# P1: el 31337 está en el top-1000 y el 31338 no
nmap -v --top-ports 1000 -oG - 127.0.0.1 | grep -m1 "Ports scanned" > top1000.txt
ncat -lk 127.0.0.1 31338 &          # solo en la propia consola atacante
nmap -Pn 127.0.0.1
nmap -Pn -p- 127.0.0.1

# Identificar: banners. Ambos servicios cierran tras el saludo y no atienden comandos
ncat -w3 phantomcorp 21 </dev/null
printf 'SYST\r\nQUIT\r\n' | ncat -w3 phantomcorp 21
ncat -w2 phantomcorp 31337 </dev/null
(sleep 1; printf 'help\n'; sleep 1) | ncat -w3 phantomcorp 31337

# Identificar: HTTP
curl -sI phantomcorp
curl -s phantomcorp/robots.txt
curl -si phantomcorp/admin
curl -si phantomcorp/panel-interno-9x2f
curl -sI phantomcorp:8080
curl -si phantomcorp:8080/status
curl -s -w ' [%{http_code}]\n' phantomcorp:8080/no-existe-xyz    # idem /console y /robots.txt
curl -si -X POST phantomcorp:8080/status
curl -si -X OPTIONS phantomcorp:8080/status

# Tipo de escaneo y herramientas disponibles
nmap -Pn -p80 -v phantomcorp | grep Initiating
searchsploit proftpd 1.3.5

# Clasificar, sin tocar el objetivo (desde la máquina anfitriona)
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-3306"
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=PhantomCMS"
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=PhantomServer"
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=PhantomCorp"
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=werkzeug"

# Entregar flags, desde la máquina anfitriona
./ctf submit 05 R1 'FLAG{...}'    # idem R2 a R5
./ctf status 05
docker logs cyberlab-phantomcorp
```
