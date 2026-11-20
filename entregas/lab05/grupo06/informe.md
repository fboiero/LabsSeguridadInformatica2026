# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 06
**Integrantes:**

| Nombre y apellido    | Usuario de GitHub |
| -------------------- | ----------------- |
| Martín Beccereca     | martinbeccereca   |
| Belén Benito         | belubenito603     |
| Alejo José De Miguel | AlejoDM           |
| Tomás Giudici        | TomasGiudici      |
| Carolina Suppo       | carosuppo         |

**Fecha:** 21/10/2026

## 0. Declaración de uso de IA

**Herramienta: Claude Code**

- **Finalidad del uso:** Apoyo en la ejecución del recon y en la redacción de las filas del mapa y de P1.
- **Partes generadas o asistidas:** Sección 2, P1 y carpeta `evidencia/`.
- **Verificación:** Las salidas se guardaron crudas con redirección desde la consola del atacante.

**Herramienta: ChatGPT**

- **Finalidad del uso:** Apoyo en la investigación sobre OSINT y reconocimiento pasivo, interpretación de `whois` y `dig`, redacción de P4 y revisión de consistencia del informe.
- **Partes asistidas:** Archivo `research.md`, pregunta P4 y observaciones para revisar el informe.
- **Verificación:** Las salidas crudas acreditan las observaciones de los comandos; las interpretaciones se contrastaron además con la rúbrica y las fuentes indicadas. Conservar una salida no sustituye esa revisión.

**Herramienta: Opencode**

- **Finalidad del uso:** Apoyo puntual para ejecutar y ordenar los comandos del recon del puerto 8080, y para revisar la redacción de la fila del mapa, P2 y la bitácora.
- **Partes asistidas:** R5, sección 2 (fila 8080), P2 y sección 4 de `informe.md`; el análisis de los hallazgos, las decisiones y la validación final fueron del grupo.
- **Verificación:** El grupo revisó y validó los comandos y sus salidas; se corrieron en `cyberlab-attacker` y se guardaron crudas con `tee` en `/loot`, copiadas sin edición a `evidencia/salidas/`.

**Herramienta: Codex**

- **Finalidad del uso:** Revisión de consistencia entre informe, rúbrica y evidencia; apoyo para precisar el alcance de las conclusiones.
- **Partes asistidas:** Secciones 1 y 2, P1, P2, P4, P5, bitácora y referencias técnicas.
- **Verificación:** Cada afirmación se contrastó con las salidas crudas enlazadas en este informe; se distinguieron los datos observados de las inferencias y de lo no evaluado.

## 1. Parte práctica — flags capturadas

- **R1:** `FLAG{high_port_secret_service}`, observada en el banner del puerto 31337. Evidencia: [banner de 31337](evidencia/salidas/r1-banner-31337.txt).
- **R2:** `FLAG{banner_grab_proftpd_135}`, observada en el banner FTP del puerto 21. Evidencia: [banner FTP](evidencia/salidas/r2-banner-ftp21.txt).
- **R3:** `FLAG{http_headers_leak_info}`, observada en `X-Backend-Flag` al consultar los headers HTTP. Evidencia: [headers HTTP](evidencia/salidas/http80-headers.txt).
- **R4:** `FLAG{recon_hidden_path}`, observada en el cuerpo de `/panel-interno-9x2f`, ruta publicada en `/robots.txt`. Evidencia: [respuesta del panel](evidencia/salidas/http80-panel-interno.txt).
- **R5:** `FLAG{dev_service_exposed}`, observada en la respuesta de `/status` del servicio del puerto 8080. Evidencia: [respuesta de /status](evidencia/salidas/http8080-status.txt).

La evidencia consolidada es la [salida final de `./ctf status 05`](evidencia/salidas/ctf-status-05-final.txt), que muestra las cinco flags aceptadas:

```text

  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 05                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Puerto oculto en rango alto (barrido completo)
   ✓  R2     Banner grabbing del servicio FTP
   ✓  R3     Fuga de informacion en headers HTTP
   ✓  R4     Enumeracion de rutas via robots.txt
   ✓  R5     Servicio dev expuesto en produccion

  ██████████████████████████████  5/5 (100%)
```

## 2. Mapa de superficie de ataque

| Puerto | Servicio                                                                        | Versión (evidencia)                                                                                                                                                                      | ¿Cómo lo identificaste?                                                                                                          | CVE relevante                                                                                                                                       | CVSS                                                                  | Criticidad                                                                 | Justificación (contra ESTE caso)                                                                                                                                                                                                                                                                                                                                                                   |
| ------ | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21     | FTP                                                                             | El servicio anuncia `ProFTPD 1.3.5`: banner `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)`; nmap `-sV`: `21/tcp open ftp ProFTPD 1.3.5`                                                    | Banner grabbing con `ncat -w2 phantomcorp 21`; resultado consistente con `nmap -Pn -sV -p-`                                      | CVE-2015-3306 (`mod_copy`, comandos `SITE CPFR`/`SITE CPTO`)                                                                                        | 9.8 (CVSS v3.1; NVD, ver referencias)                                 | Alta, condicionada a la configuración                                      | La versión anunciada está entre las afectadas por el CVE, cuya aplicabilidad depende de que `mod_copy` esté habilitado; no se evaluó ese módulo ni se intentó explotar el servicio. El banner también expone el nombre de la empresa y una flag mediante una respuesta `214`; el problema observado es la fuga de información, no la validez del código FTP.                                       |
| 80/tcp | HTTP                                                                            | Headers: `Server: PhantomServer/2.4.1` y `X-Powered-By: PhantomCMS 2.4.1`; respuesta `HTTP/1.0 200 OK`. Versiones anunciadas, sin verificación independiente del software.               | HEAD a `http://phantomcorp` con curl; GET a `/robots.txt` y a `/panel-interno-9x2f`, todos sobre HTTP sin puerto explícito (80). | No determinado: las respuestas no permiten vincular estos nombres/versiones con un CVE verificable. No se atribuye un CVE por similitud de nombres. | No asignado; no se calculó un vector ni se verificó un CVE aplicable. | Media, valoración cualitativa para la exposición de información observada. | Los headers revelan producto, versión y una flag. robots.txt publica una ruta interna y un comentario de infraestructura; la ruta responde 200 y entrega el panel y otra flag sin credenciales. Esto facilita reconocimiento y expone contenido interno. No se demostró ejecución de comandos, modificación de datos ni acceso a funciones administrativas.                                        |
| 8080   | HTTP / API de desarrollo (`phantom-dev-api`)                                    | Header `Server:`: `Werkzeug/2.0.1 Python/3.9.2`; nmap: `Werkzeug httpd 2.0.1 (Python 3.9.2)`. JSON de `/status`: `"service":"phantom-dev-api"`, `"version":"0.9.3-DEV"`, `"debug":true`. | `nmap -Pn -sV -p 8080 phantomcorp`; `curl -sS -i http://phantomcorp:8080/` y `curl -sS -i http://phantomcorp:8080/status`        | No determinado: no se vinculó la versión anunciada a un CVE verificado.                                                                             | N/A (sin CVE verificado)                                              | Media, valoración provisional                                              | Desde la red del laboratorio, `/status` respondió 200 sin credenciales y reveló nombre, versión, `debug:true` y una flag. El header identifica Werkzeug y la documentación desaconseja utilizar su servidor de desarrollo en producción. No se verificó que el debugger interactivo estuviera accesible, que el servicio estuviera publicado en Internet, ni sus controles de parcheo o monitoreo. |
| 31337  | Servicio no identificado; nmap lo etiqueta como `Elite` por el número de puerto | Banner: `PhantomCorp maintenance shell v0.1`; nmap `-sV`: `31337/tcp open Elite?`                                                                                                        | `nmap -sV -p-` no lo clasificó; `ncat -w2 phantomcorp 31337` permitió leer el banner directamente.                               | No identificado: el banner no permite asociarlo de forma verificable a un producto/CVE público.                                                     | N/A                                                                   | Media, valoración provisional                                              | Una conexión TCP recibió un banner que se anuncia como servicio de mantenimiento y expone una flag. No se evaluaron comandos disponibles, autenticación, controles de acceso ni impacto; por ello no se lo clasifica como backdoor ni se afirma que sea una shell utilizable. Requiere inventario y revisión de necesidad, acceso y exposición.                                                    |

Headers relevantes del puerto 80 (extracto):

```text
HTTP/1.0 200 OK
Server: PhantomServer/2.4.1
X-Powered-By: PhantomCMS 2.4.1
X-Backend-Flag: FLAG{http_headers_leak_info}
```

Evidencia completa, sin editar:

- [Escaneo de puertos predeterminado](evidencia/salidas/nmap-default.txt).
- [Escaneo completo con detección de versiones](evidencia/salidas/nmap-sV-all.txt).
- [Banner del puerto 31337](evidencia/salidas/r1-banner-31337.txt).
- [Banner FTP del puerto 21](evidencia/salidas/r2-banner-ftp21.txt).
- [Detección de versión del puerto 8080](evidencia/salidas/nmap-8080.txt).
- [Respuesta de la raíz del 8080](evidencia/salidas/http8080-root.txt).
- [Respuesta del endpoint /status del 8080](evidencia/salidas/http8080-status.txt).
- [Estado final de las cinco flags](evidencia/salidas/ctf-status-05-final.txt).

- [Headers originales de R3](evidencia/salidas/http80-headers.txt).
- [Respuesta de robots.txt](evidencia/salidas/http80-robots.txt).
- [Respuesta del panel interno](evidencia/salidas/http80-panel-interno.txt).

La identificación de la fila del puerto 80 se basa en HTTP observado con curl, no en un escaneo nmap. `HTTP/1.0` es la versión del protocolo de respuesta, no la versión del producto. Las fechas de los headers están en GMT.

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**
En nuestra corrida el escaneo default (`nmap -Pn phantomcorp`, 1000 puertos) y el
completo (`nmap -Pn -sV -p- phantomcorp`) encontraron los mismos cuatro puertos:
21, 80, 8080 y 31337. El 31337 aparece en el default porque nmap incluye en su
lista de los 1000 más frecuentes a ese puerto histórico de backdoors. Lo que el
default sí se perdió fue la **identificación**: sin `-sV` el puerto figuró como
`Elite` (un nombre que nmap deduce solo del número de puerto). El escaneo con
`-sV` tampoco clasificó formalmente el servicio: lo mostró como `Elite?`, aunque
registró su respuesta en el fingerprint. La conexión con `ncat` permitió leer
el banner directamente y observar que se anuncia como “maintenance shell”.

Entonces `-p-` no sumó un puerto nuevo en esta corrida, pero la lección
operativa es la misma: el escaneo default cubre 1000 de 65535 puertos y puede
omitir servicios fuera de esa lista. Un puerto abierto sin versión sigue siendo
un hallazgo inicial; requiere identificación adicional antes de atribuir
producto, vulnerabilidad o impacto. En próximos reconocimientos conviene
combinar `-p-`, `-sV` y verificación manual de los banners, distinguiendo el
nombre inferido por número de puerto de la identificación obtenida por sondeo.

**P2 — El servicio dev en producción.**

La evidencia concreta está en lo que devuelve el propio servicio. `nmap -Pn -sV -p 8080 phantomcorp` lo identifica como `Werkzeug httpd 2.0.1 (Python 3.9.2)`, que es el servidor de desarrollo de Flask/Werkzeug, no un servidor WSGI de producción como Gunicorn o uWSGI. El encabezado anuncia los mismos datos: `Server: Werkzeug/2.0.1 Python/3.9.2`. Al pedir la raíz, `curl -sS -i http://phantomcorp:8080/` responde `phantom-dev-api. Proba /status`, y `/status` devuelve JSON con `"version":"0.9.3-DEV"` y `"debug":true`.

Los nombres `phantom-dev-api` y `0.9.3-DEV`, junto con el campo `debug:true`,
son indicadores observados de una API de desarrollo. La documentación de
Werkzeug desaconseja usar su servidor de desarrollo para producción (ver
referencias). Sin embargo, en este laboratorio solo verificamos acceso desde
la red del laboratorio: no comprobamos publicación en Internet ni el contexto
real de despliegue.

El riesgo observado no depende de un CVE: `/status` responde 200 sin
credenciales y divulga información de producto, versión y configuración, además
de una flag. Esa información facilita reconocimiento posterior. El campo
`debug:true` es un dato anunciado por la aplicación; no se verificó que el
debugger interactivo de Werkzeug estuviera habilitado o accesible. Tampoco se
evaluaron parches, monitoreo, registros ni ejecución de comandos.

**P3 — La ironía de robots.txt.**

robots.txt permite comunicar a los rastreadores qué rutas se les pide que no rastreen. No implementa autenticación ni autorización: una directiva Disallow no impide que alguien solicite esa URL y tampoco garantiza que una dirección no aparezca indexada.

En este laboratorio, `curl -sS -i http://phantomcorp/robots.txt` devolvió `HTTP/1.0 200 OK` y el siguiente contenido:

```text
User-agent: *
Disallow: /admin
Disallow: /panel-interno-9x2f
# Recordatorio infra: /panel-interno-9x2f sigue accesible desde afuera. Migrar a VPN.
```

La ironía es que, al intentar apartar rutas de los rastreadores, el archivo público revela sus nombres exactos a quien está haciendo reconocimiento. El comentario además señala una exposición pendiente de corregir. Seguimos esa pista con `curl -sS -i http://phantomcorp/panel-interno-9x2f`: sin enviar credenciales ni cookies, recibimos `HTTP/1.0 200 OK`, el título «Panel interno PhantomCorp» y `FLAG{recon_hidden_path}`. El texto «Acceso restringido» del HTML no evitó que se entregara ese contenido.

Extracto del cuerpo HTML recibido del panel:

```html
<h1>Panel interno PhantomCorp</h1>
<p>
  Acceso restringido. Si llegaste aca por robots.txt, felicitaciones: acabas de
  hacer enumeracion de rutas. Esa es exactamente la tecnica.
</p>
<pre>FLAG{recon_hidden_path}</pre>
```

La evidencia demuestra acceso desde el contenedor atacante al panel dentro de la red del laboratorio; el comentario dice «desde afuera», pero no comprobamos exposición a Internet. `/admin` solo se observó listado y no se consultó. La conclusión es que ocultar o desaconsejar el rastreo de una ruta no protege su contenido: el acceso debe controlarse en el servidor. La evidencia de este caso está en las respuestas completas de robots.txt y del panel enlazadas arriba.

**P4 — Pasivo vs. activo.**

El reconocimiento pasivo reúne información ya publicada o recopilada por
terceros sin enviar solicitudes a la infraestructura del objetivo. El activo,
en cambio, interactúa con el objetivo para obtener información. En este lab,
`nmap` contra PhantomCorp, las conexiones `ncat` y las solicitudes `curl`
fueron reconocimiento activo: generaron tráfico hacia los servicios del target
y podrían quedar registrados por ellos.

Como práctica separada sobre dominios de prueba, ejecutamos `whois nmap.org` y
`dig scanme.nmap.org A`; no son acciones de reconocimiento sobre PhantomCorp.
La consulta WHOIS se dirigió a un servicio de registro. La salida de `dig`
indica que respondió el resolvedor Docker `127.0.0.11`; por eso, con esta
evidencia no podemos afirmar si hubo contacto con un servidor autoritativo de
`scanme.nmap.org` o si la respuesta provenía de caché. Una consulta DNS no es
automáticamente pasiva: depende de a qué servidor alcance y de qué datos se
usen. Esta distinción coincide con el análisis desarrollado en `research.md`.

**Evidencias de consultas WHOIS y DNS:**

- [Consulta WHOIS de nmap.org](evidencia/salidas/p4-whois.txt).
- [Consulta DNS de scanme.nmap.org](evidencia/salidas/p4-dig.txt).

**P5 — Ahora sos el defensor.**

1. **API de desarrollo en 8080.** Retirar el servicio de desarrollo de la red
   accesible desde el entorno de usuarios y publicar solamente la aplicación
   necesaria mediante el canal de producción definido por PhantomCorp. Si
   `/status` es indispensable para operación, limitarlo a la red de monitoreo
   o a una VPN y exigir autenticación; la respuesta no debe incluir versión,
   configuración de depuración ni datos sensibles. Como verificación, desde
   una red no autorizada el puerto 8080 no debe aparecer abierto. Desde la red
   autorizada de operación, `/status` debe requerir autenticación y devolver
   únicamente información mínima. Esta medida reduce la superficie que hoy
   expone sin credenciales el nombre, versión y estado anunciados por la API.

2. **Servicio no identificado en 31337.** Inventariar el proceso que entrega
   el banner de mantenimiento y definir si es necesario. Si no lo es, debe
   deshabilitarse; si es necesario para administración, debe quedar accesible
   únicamente desde una red administrativa o VPN, con autenticación y registro
   de accesos. Como verificación, un escaneo desde la red de usuarios no debe
   encontrar el puerto abierto y el banner no debe divulgar información interna.
   Esta medida no presupone que el servicio sea una backdoor: reduce la
   exposición de un componente cuya función y controles no se determinaron en
   el reconocimiento.

## 4. Bitácora de comandos

Dentro de `cyberlab-attacker`:

```bash
nmap -Pn phantomcorp > /loot/nmap-default.txt
nmap -Pn -sV -p- phantomcorp > /loot/nmap-sV-all.txt
ncat -w2 phantomcorp 31337 </dev/null > /loot/r1-banner-31337.txt
ncat -w2 phantomcorp 21 </dev/null > /loot/r2-banner-ftp21.txt
curl -I http://phantomcorp | tee /loot/http80-headers.txt
curl -sS -i http://phantomcorp/robots.txt | tee /loot/http80-robots.txt
curl -sS -i http://phantomcorp/panel-interno-9x2f | tee /loot/http80-panel-interno.txt
nmap -Pn -sV -p 8080 phantomcorp | tee /loot/nmap-8080.txt
curl -sS -i http://phantomcorp:8080/ | tee /loot/http8080-root.txt
curl -sS -i http://phantomcorp:8080/status | tee /loot/http8080-status.txt
```

Desde Bash de Git, en una sesión anterior del laboratorio:

```bash
./ctf submit 05 R3 'FLAG{http_headers_leak_info}'
./ctf submit 05 R4 'FLAG{recon_hidden_path}'
./ctf submit 05 R5 'FLAG{dev_service_exposed}'
./ctf status 05
```

En una sesión posterior de la consola atacante se repitieron el escaneo completo
y los banners de R1/R2, que coincidieron con las salidas ya versionadas:

```bash
nmap -Pn -sV -p- phantomcorp | tee /loot/nmap-sV-all-final.txt
ncat -w2 phantomcorp 31337 </dev/null | tee /loot/r1-banner-31337-final.txt
ncat -w2 phantomcorp 21 </dev/null | tee /loot/r2-banner-ftp21-final.txt
```

Para consolidar el registro de flags se utilizó un checkout temporal con finales
de línea LF. Allí se enviaron R1 a R5 con `./ctf submit 05 <reto> 'FLAG{...}'`
y se registró el resultado con:

```bash
./ctf status 05 | tee .loot/ctf-status-05-final.txt
```

La salida final se copió a `evidencia/salidas/ctf-status-05-final.txt`.

Ver [evidencia/comandos.txt](evidencia/comandos.txt), que registra acciones de distintas sesiones del laboratorio e identifica dónde se ejecutó cada comando. Las salidas originales permanecieron en `/loot`, montado como `.loot/` del repositorio, y se copiaron sin edición a `evidencia/salidas/` para versionarlas.

## 5. Referencias técnicas

1. NIST National Vulnerability Database. [CVE-2015-3306](https://nvd.nist.gov/vuln/detail/CVE-2015-3306).
2. Pallets. [Deploying to Production — Werkzeug Documentation](https://werkzeug.palletsprojects.com/en/stable/deployment/).
3. IETF. [RFC 959 — File Transfer Protocol](https://www.rfc-editor.org/rfc/rfc959).
4. IETF. [RFC 9309 — Robots Exclusion Protocol](https://www.rfc-editor.org/rfc/rfc9309).
5. Nmap Project. [Service and Version Detection](https://nmap.org/book/man-version-detection.html).
