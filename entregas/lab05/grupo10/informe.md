# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 10  
**Integrantes:**

- Belén Rocío Ramello — @belramello
- Carolina Paula Corazza — @carocor1
- Chiara Agustina Kordek — @chiarakordek
- Juan Pablo Saby — @JuanSaby

**Fecha:** 05/11/2026

---

## 0. Declaración de uso de IA

Se utilizó OpenCode para orientar la preparación del entorno, organizar las capturas de evidencia y revisar el formato del informe. Los comandos de reconocimiento se ejecutaron contra el contenedor `phantomcorp`; las afirmaciones sobre el entorno se cotejaron con las salidas guardadas en `evidencia/`. El grupo debe comprender y validar el análisis antes de entregar. Las referencias de CVE/CVSS se contrastaron con NVD, CVE.org y la documentación de ProFTPD.

## 1. Parte práctica — flags capturadas

**Estado registrado:** 5/5. Las cinco flags se obtuvieron de las respuestas de servicios conservadas en `evidencia/`, fechadas el 10/10/2026. El 05/11/2026 se registraron esas cadenas mediante el verificador oficial y se guardó una nueva salida de `./ctf status 05` en [lab05-ctf-status.txt](evidencia/lab05-ctf-status.txt).

El bloqueo anterior era de ejecución en Windows: los scripts del checkout tenían finales CRLF. Para verificar las capturas se utilizó Git Bash y una copia temporal LF del contenido versionado de `ctf`, sus bibliotecas y el manifiesto del lab. No se modificaron los archivos del curso ni sus hashes de verificación. Los cinco envíos fueron aceptados y los identificadores quedaron registrados en `.progreso/05.done`, que no se versiona. La transcripción está en [lab05-ctf-registro.txt](evidencia/lab05-ctf-registro.txt).

La salida real del verificador de retos fue:

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

[ OK ] ¡Lab 05 COMPLETO! Ponete las pilas con la próxima unidad.
```

---

## 2. Mapa de superficie de ataque

| Puerto    | Servicio                                                      | Versión (evidencia)                                                                   | ¿Cómo lo identificaste?                | CVE relevante                                                                              | CVSS                                                                                                                      | Criticidad            | Justificación (contra este caso)                                                                                                                                                                                                                                                                               |
| --------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------- | -------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21/tcp    | FTP / ProFTPD                                                 | ProFTPD 1.3.5; banner: `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)`                   | Nmap `-sV` y banner con `ncat`         | **Candidato: CVE-2015-3306**, asociado a `mod_copy` y los comandos `SITE CPFR`/`SITE CPTO` | **NVD CVSS 2.0: 10.0** — `AV:N/AC:L/Au:N/C:C/I:C/A:C`. NVD no informa una evaluación NIST CVSS 3.x/4.0 para este registro | **Alta, provisional** | FTP está expuesto y el banner coincide con ProFTPD 1.3.5, versión descrita en el CVE. Sin embargo, el banner no confirma que `mod_copy` esté cargado o que los comandos estén habilitados. No se comprobó la vulnerabilidad en esta instancia; la criticidad es una valoración contextual, no el CVSS del CVE. |
| 80/tcp    | HTTP / PhantomServer                                          | PhantomServer/2.4.1; `X-Powered-By: PhantomCMS 2.4.1`                                 | Nmap `-sV`, `curl -I` y respuesta HTTP | No se identificó un CVE concreto con la evidencia disponible                               | N/A                                                                                                                       | Media                 | Los headers revelan producto/versión y un header personalizado filtra información. `robots.txt` publica una ruta interna accesible; son exposiciones de información/rutas, no evidencia de ejecución de código.                                                                                                |
| 8080/tcp  | HTTP / API de desarrollo (software declarado por el servicio) | Header `Werkzeug/2.0.1 Python/3.9.2`; endpoint indica `0.9.3-DEV` y `debug:true`      | Nmap `-sV`, headers y `GET /status`    | No se atribuye CVE: no se verificó uno aplicable al servicio observado                     | N/A                                                                                                                       | Alta, contextual      | `/status` responde sin solicitar credenciales y expone nombre, versión e indicador de depuración. Es una interfaz de desarrollo accesible desde la red del laboratorio. Los headers no prueban el binario real y `debug:true` no demuestra que exista un depurador interactivo ni ejecución de código.         |
| 31337/tcp | Servicio TCP con banner de mantenimiento                      | Versión declarada `v0.1`: `PhantomCorp maintenance shell v0.1`; Nmap muestra `Elite?` | Barridos TCP y banner con `ncat`       | No determinado; no se atribuye CVE sin identificar un producto real                        | N/A                                                                                                                       | Media, provisional    | El servicio publica una función interna y su versión declarada. Solo se observó el saludo: no se demostró una shell operativa, ejecución de comandos ni acceso administrativo sin autenticación. Recibir un banner antes de autenticarse no prueba por sí solo ausencia de controles de acceso.                |

**Nota de clasificación:** las criticidades son valoraciones contextuales, distintas del CVSS. Para CVE-2015-3306, NVD publica la evaluación NIST CVSS 2.0: 10.0 (`AV:N/AC:L/Au:N/C:C/I:C/A:C`), usada en la tabla. La [API oficial de NVD](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2015-3306), consultada el 05/11/2026, incluye además CVSS 3.1: 10.0 (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H`) como evaluación secundaria de CISA-ADP, no de NIST. La procedencia se confirma en el [registro JSON oficial de CVE](https://cveawg.mitre.org/api/cve/CVE-2015-3306). La documentación indica que `mod_copy` no se compila por defecto. Como el banner no confirma su presencia/configuración y no se realizaron pruebas de explotación, se mantiene como candidato. Fuentes complementarias: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2015-3306), [documentación de mod_copy](http://ftp.proftpd.org/docs/contrib/mod_copy.html) y [aviso de Debian sobre paquetes corregidos](https://lists.debian.org/debian-security-announce/2015/msg00154.html).

### Evidencia de respaldo

Las capturas de reconocimiento se conservan sin alteraciones en `evidencia/`. Se adjuntan el registro local de las cinco flags y la salida del verificador, con sus fechas correspondientes. Los extractos siguientes facilitan la lectura y no sustituyen los archivos completos.

- `lab05-nmap-default.txt` — escaneo común: encontró 21, 80, 8080 y 31337.
- `lab05-nmap-all-ports.txt` — barrido completo `-p-`.
- `lab05-nmap-sv-all-ports.txt` — detección de versiones; 31337 quedó sin identificar.
- `lab05-banner-ftp.txt` y `lab05-banner-31337.txt` — banners TCP.
- `lab05-http-root.txt` — respuesta web y headers del puerto 80.
- `lab05-robots.txt` y `lab05-hidden-panel.txt` — enumeración y acceso a ruta anunciada por robots.
- `lab05-http-8080-headers.txt` y `lab05-http-8080-status.txt` — headers y estado del servicio dev.
- `lab05-r5-status.txt` — captura adicional del endpoint de estado.
- [lab05-ctf-registro.txt](evidencia/lab05-ctf-registro.txt) — fuente de cada flag, cinco envíos aceptados y salida final del verificador.
- [lab05-ctf-status.txt](evidencia/lab05-ctf-status.txt) — captura de `./ctf status 05`: 5/5, con fecha y contexto.
- [README de evidencia](evidencia/README.md) — relación entre retos, archivos y límites de la revisión.

Extracto del barrido completo y detección de versiones:

```text
$ nmap -Pn -sV -p- phantomcorp
PORT      STATE SERVICE VERSION
21/tcp    open  ftp     ProFTPD 1.3.5
80/tcp    open  http    PhantomServer/2.4.1
8080/tcp  open  http    Werkzeug httpd 2.0.1 (Python 3.9.2)
31337/tcp open  Elite?
```

Extracto de banner y respuesta HTTP de los servicios relevantes:

```text
$ ncat -w2 phantomcorp 21
220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]

$ ncat -w2 phantomcorp 31337
PhantomCorp maintenance shell v0.1 -- acceso no autorizado prohibido

$ curl -I http://phantomcorp/
HTTP/1.0 200 OK
Server: PhantomServer/2.4.1
X-Powered-By: PhantomCMS 2.4.1
X-Backend-Flag: FLAG{http_headers_leak_info}

$ curl -sS http://phantomcorp/robots.txt
User-agent: *
Disallow: /admin
Disallow: /panel-interno-9x2f
```

```text
$ curl -sS -i http://phantomcorp:8080/status
HTTP/1.0 200 OK
Server: Werkzeug/2.0.1 Python/3.9.2
Content-Type: application/json

{"service":"phantom-dev-api","version":"0.9.3-DEV","debug":true,"flag":"FLAG{dev_service_exposed}"}
```

Las cadenas que contienen estas respuestas y los banners se registraron con el mecanismo oficial: 5/5.

---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**  
La comparación siguiente corresponde a los barridos guardados del 10/10/2026.

La pregunta da por hecho que el escaneo por defecto omitió un servicio, pero la evidencia del grupo no lo confirma. Sin `-p`, Nmap revisa los 1.000 puertos más frecuentes según su archivo `nmap-services`; con `-p-` recorre del 1 al 65.535 [P1]. `lab05-nmap-default.txt` informa «Not shown: 996 closed tcp ports»: 1.000 puertos revisados con cuatro abiertos. `lab05-nmap-all-ports.txt` informa «Not shown: 65531 closed tcp ports»: 65.535 puertos revisados. Ambos encontraron 21, 80, 8080 y 31337; en esta ejecución, `-p-` no descubrió ningún servicio nuevo. El barrido completo amplió la cobertura de puertos TCP del host en ese momento, a cambio de un tiempo mayor (3,17 s contra 0,68 s). No acredita el estado de UDP, de otros hosts ni de otros momentos.

La lección operativa tiene dos partes. Primero, el alcance se define según la autorización y el objetivo: un escaneo común es una aproximación, no la revisión de todos los puertos posibles. Incluso un barrido completo debe interpretarse considerando filtrado, tiempos de espera y alcance del protocolo. Segundo, no hay que dar por ocurrido un resultado esperado. La guía anticipaba que un servicio estaría fuera del conjunto por defecto, pero el informe debe reflejar las salidas obtenidas, no forzar esa expectativa.

**P2 — El servicio dev en producción.**  
Hay tres evidencias concretas, todas obtenidas desde fuera del servidor:

1. **El software que anuncia la respuesta.** Nmap identificó en el 8080 `Werkzeug httpd 2.0.1 (Python 3.9.2)` (`lab05-nmap-sv-all-ports.txt`), y los headers anuncian `Server: Werkzeug/2.0.1 Python/3.9.2` (`lab05-http-8080-headers.txt`). La documentación de Werkzeug advierte que su servidor de desarrollo no debe usarse en producción [P2]. El header es un indicio declarativo, no una comprobación del binario o de su configuración real. La petición HEAD devolvió 501, mientras que GET a `/status` devolvió 200; que un método no esté implementado no significa que el servicio no responda.
2. **Lo que el servicio dice de sí mismo.** `GET /status` respondió HTTP 200 sin pedir credenciales, con `"service":"phantom-dev-api"`, `"version":"0.9.3-DEV"` y `"debug":true` (`lab05-http-8080-status.txt`; la captura `lab05-r5-status.txt`, tomada catorce minutos después, devolvió lo mismo). El nombre, el sufijo `-DEV` de la versión y el indicador de depuración activo describen una API de desarrollo.
3. **Dónde está expuesto.** El puerto no es el de la web corporativa (80): es un segundo servicio HTTP, alcanzable desde la misma red que el sitio público.

El problema no depende de encontrar un CVE aplicable. El riesgo demostrado es la exposición de información: sin autenticarse, un cliente de la red del laboratorio obtiene el nombre interno, las versiones declaradas y el indicador de depuración. Esto es coherente con la exposición de información descrita por CWE-200 [P4]. CWE-489 aporta una referencia para evaluar código de depuración activo [P3], pero `debug:true` por sí solo no demuestra esa condición ni la presencia de un depurador interactivo. La documentación de Werkzeug advierte que este último no debe publicarse [P2]; el grupo no comprobó que estuviera accesible ni que permitiera ejecutar código. Por eso se distingue la filtración observada del impacto potencial, sin presentar ejecución remota como un hecho.

#### Fuentes de P1 y P2

- **[P1] [PRIMARIA]** Lyon, G. (s. f.). _Port Specification and Scan Order_. Nmap Reference Guide. https://nmap.org/book/man-port-specification.html — Por defecto, Nmap revisa los 1.000 puertos más frecuentes de cada protocolo; `-p-` recorre del 1 al 65.535.
- **[P2] [PRIMARIA]** Pallets Projects. (s. f.). _Serving WSGI Applications_. Werkzeug Documentation. https://werkzeug.palletsprojects.com/en/stable/serving/ — El servidor de desarrollo no debe usarse en producción; el depurador interactivo no debe habilitarse en un servidor visible públicamente.
- **[P3] [PRIMARIA]** MITRE. (s. f.). _CWE-489: Active Debug Code_. Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/489.html
- **[P4] [PRIMARIA]** MITRE. (s. f.). _CWE-200: Exposure of Sensitive Information to an Unauthorized Actor_. Common Weakness Enumeration. https://cwe.mitre.org/data/definitions/200.html

**P3 — La ironía de `robots.txt`.**  
`robots.txt` comunica a los rastreadores qué rutas se les solicita que no rastreen; no controla quién puede abrirlas. RFC 9309 aclara que sus reglas no son autorización de acceso y que publicar rutas allí puede hacerlas descubribles ([RFC 9309, sección 3](https://www.rfc-editor.org/rfc/rfc9309.html#section-3)). En este laboratorio, `lab05-robots.txt` muestra `Disallow: /panel-interno-9x2f` y hasta comenta que la ruta sigue accesible desde afuera. La petición posterior a esa ruta devolvió HTTP 200 y el contenido del panel (`lab05-hidden-panel.txt`). Por eso el archivo facilitó la enumeración, pero la evidencia de la respuesta muestra que no protegía el recurso.

**P4 — Pasivo vs. activo.**  
El reconocimiento pasivo reúne información disponible sin sondear directamente al objetivo; el activo lo consulta por tráfico de red. MITRE ATT&CK diferencia la búsqueda en sitios públicos ([T1593](https://attack.mitre.org/techniques/T1593/)) del escaneo que sondea infraestructura ([T1595](https://attack.mitre.org/techniques/T1595/)). En la bitácora del grupo no hay una acción pasiva documentada: `ping`, `nmap`, `ncat` y las solicitudes `curl` se dirigieron a `phantomcorp`, así que fueron activas. Las solicitudes HTTP pudieron aparecer en los registros de la aplicación; Nmap, Ncat y ping pudieron dejar rastros en registros o sensores de red. Como no se incluyeron esos registros, no afirmamos que cada acción haya quedado efectivamente registrada.

**P5 — Ahora sos el defensor.**

1. **Panel interno publicado en el puerto 80:** exigir autenticación y autorización en la aplicación, y limitar el panel a la VPN o a una subred administrativa. Quitar la ruta de `robots.txt` elimina la pista, pero no reemplaza esos controles. Verificar desde una red externa que una solicitud sin credenciales reciba 401/403 y que el panel solo responda desde el acceso administrativo autorizado.
2. **API de desarrollo expuesta en el puerto 8080:** retirar el servicio del perímetro público, enlazarlo solo a una interfaz de administración, restringir el acceso por firewall y desactivar el modo debug. Reducir los campos de `/status` para que no publique versión y estado de debug. Verificar desde fuera de la red administrativa que el puerto no sea alcanzable y que el endpoint ya no revele esos datos.

---

## 4. Bitácora de comandos

Bitácora histórica de comandos ejecutados contra el contenedor autorizado `phantomcorp`, cuyas salidas se conservaron el 10/10/2026:

```bash
ping -c1 phantomcorp
nmap -Pn phantomcorp
nmap -Pn -p- phantomcorp
nmap -Pn -sV -p- phantomcorp
ncat -w2 phantomcorp 31337
ncat -w2 phantomcorp 21
curl -I http://phantomcorp/
curl -i http://phantomcorp/
curl -sS -i http://phantomcorp/robots.txt
curl -sS -i http://phantomcorp/panel-interno-9x2f
curl -sS -I http://phantomcorp:8080/
curl -sS -i http://phantomcorp:8080/status
```
