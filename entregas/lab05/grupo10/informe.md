# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 10  
**Integrantes:**

- Belén Rocío Ramello — @belramello
- Carolina Paula Corazza — @carocor1
- Chiara Agustina Kordek — @chiarakordek
- Juan Pablo Saby — @JuanSaby

**Fecha:** Pendiente de entrega.

---

## 0. Declaración de uso de IA

Se utilizó OpenCode para orientar la preparación del entorno, organizar las capturas de evidencia y revisar el formato del informe. Los comandos de reconocimiento se ejecutaron contra el contenedor `phantomcorp`; las afirmaciones sobre el entorno se cotejaron con las salidas guardadas en `evidencia/`. El grupo debe comprender y validar el análisis antes de entregar. Las referencias de CVE/CVSS se contrastaron con NVD, CVE.org y la documentación de ProFTPD.

## 1. Parte práctica — flags capturadas

**Estado registrado:** 0/5. El comando de envío no pudo ejecutarse porque el script `ctf` montado presenta finales CRLF (`env: 'bash\r': No such file or directory`). Por ello no se afirma que los retos estén completados. La salida de `status` que se adjunte debe ser una captura nueva, obtenida después de resolver el problema de ejecución.

---

## 2. Mapa de superficie de ataque

| Puerto    | Servicio                           | Versión (evidencia)                                                                  | ¿Cómo lo identificaste?                                   | CVE relevante                                                                              | CVSS                                                                                                                      | Criticidad            | Justificación (contra este caso)                                                                                                                                                                                                                                                                               |
| --------- | ---------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 21/tcp    | FTP / ProFTPD                      | ProFTPD 1.3.5; banner: `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)`                  | Nmap `-sV` y banner con `ncat`                            | **Candidato: CVE-2015-3306**, asociado a `mod_copy` y los comandos `SITE CPFR`/`SITE CPTO` | **NVD CVSS 2.0: 10.0** — `AV:N/AC:L/Au:N/C:C/I:C/A:C`. NVD no informa una evaluación NIST CVSS 3.x/4.0 para este registro | **Alta, provisional** | FTP está expuesto y el banner coincide con ProFTPD 1.3.5, versión descrita en el CVE. Sin embargo, el banner no confirma que `mod_copy` esté cargado o que los comandos estén habilitados. No se comprobó la vulnerabilidad en esta instancia; la criticidad es una valoración contextual, no el CVSS del CVE. |
| 80/tcp    | HTTP / PhantomServer               | PhantomServer/2.4.1; `X-Powered-By: PhantomCMS 2.4.1`                                | Nmap `-sV`, `curl -I` y respuesta HTTP                    | No se identificó un CVE concreto con la evidencia disponible                               | N/A                                                                                                                       | Media                 | Los headers revelan producto/versión y un header personalizado filtra información. `robots.txt` publica una ruta interna accesible; son exposiciones de información/rutas, no evidencia de ejecución de código.                                                                                                |
| 8080/tcp  | HTTP / Werkzeug, API de desarrollo | Werkzeug 2.0.1, Python 3.9.2; endpoint indica `0.9.3-DEV` y `debug:true`             | Nmap `-sV`, headers y `GET /status`                       | No se atribuye CVE: no se verificó uno aplicable al servicio observado                     | N/A                                                                                                                       | Alta                  | `/status` está accesible y revela nombre de servicio, versión dev y `debug:true`. La exposición brinda información operacional y confirma que una interfaz de desarrollo está accesible desde el perímetro del laboratorio; no se infiere ejecución remota no demostrada.                                      |
| 31337/tcp | Servicio de mantenimiento TCP      | Banner: `PhantomCorp maintenance shell v0.1`; Nmap no identificó producto (`Elite?`) | Barrido `nmap -p-`, `ncat` al puerto descubierto y banner | No determinado; no se atribuye CVE sin identificar producto                                | N/A                                                                                                                       | Alta                  | El puerto alto expone un servicio de mantenimiento que entrega un banner al conectarse y no muestra autenticación en la interacción observada. Nmap no pudo identificar producto/versión, así que se clasifica por exposición y función declarada, no por un CVE inventado.                                    |

**Nota de clasificación:** las criticidades son valoraciones contextuales, distintas del CVSS. Para CVE-2015-3306, NVD describe el riesgo de `mod_copy` en ProFTPD 1.3.5 y publica CVSS 2.0: 10.0 (`AV:N/AC:L/Au:N/C:C/I:C/A:C`); no presenta una evaluación NIST CVSS 3.x/4.0 en el registro consultado. La documentación del proyecto indica que `mod_copy` no se compila por defecto. Como el banner no confirma la presencia/configuración del módulo y no se realizaron pruebas de explotación, se registra como candidato, no como vulnerabilidad confirmada. Fuentes: [NVD](https://nvd.nist.gov/vuln/detail/CVE-2015-3306), [CVE.org](https://www.cve.org/CVERecord?id=CVE-2015-3306), [documentación de mod_copy](http://ftp.proftpd.org/docs/contrib/mod_copy.html).

### Evidencia de respaldo

Capturas completas seleccionadas incluidas en `evidencia/`. Se omiten deliberadamente los logs de intentos de envío fallidos; el estado real `0/5` se describe en la sección 1. Extractos relevantes también se reproducen abajo para facilitar la lectura.

- `lab05-nmap-default.txt` — escaneo común: encontró 21, 80, 8080 y 31337.
- `lab05-nmap-all-ports.txt` — barrido completo `-p-`.
- `lab05-nmap-sv-all-ports.txt` — detección de versiones; 31337 quedó sin identificar.
- `lab05-banner-ftp.txt` y `lab05-banner-31337.txt` — banners TCP.
- `lab05-http-root.txt` — respuesta web y headers del puerto 80.
- `lab05-robots.txt` y `lab05-hidden-panel.txt` — enumeración y acceso a ruta anunciada por robots.
- `lab05-http-8080-headers.txt` y `lab05-http-8080-status.txt` — headers y estado del servicio dev.
- `lab05-r5-status.txt` — captura adicional del endpoint de estado.

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

Las respuestas de servicios contienen strings identificadas como flags, pero el estado del mecanismo `ctf` no las registra todavía: los intentos de envío fallaron por el CRLF del script y `status` quedó en 0/5. No presentar esto como retos completados.

---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**  
La pregunta da por hecho que el escaneo por defecto omitió un servicio, pero la evidencia del grupo no lo confirma. Sin `-p`, Nmap revisa los 1.000 puertos más frecuentes según su archivo `nmap-services`; con `-p-` recorre todo el rango, del 1 al 65.535 [P1]. Así lo muestran las capturas. `lab05-nmap-default.txt` informa «Not shown: 996 closed tcp ports», es decir, 1.000 puertos revisados con cuatro abiertos. `lab05-nmap-all-ports.txt` informa «Not shown: 65531 closed tcp ports», es decir, 65.535 puertos revisados. Los dos escaneos encontraron los mismos cuatro puertos abiertos: 21, 80, 8080 y 31337. En esta ejecución, entonces, `-p-` no descubrió ningún servicio nuevo. El puerto 31337 ya aparecía en el escaneo común, porque figura entre los 1.000 puertos que Nmap considera frecuentes. Lo que agregó el barrido completo fue certeza: confirmó que no había otros puertos TCP abiertos fuera de ese conjunto, a cambio de un tiempo mayor (3,17 s contra 0,68 s en este contenedor).

La lección operativa tiene dos partes. Primero, el alcance del escaneo se define según la autorización y el objetivo. El escaneo común sirve como primera aproximación rápida, pero solo el barrido completo permite afirmar que no quedan servicios escondidos en puertos altos. En una red real, donde un servicio puede escucharse en cualquier puerto, conviene correr ambos. Segundo, no hay que dar por ocurrido un resultado esperado. La guía anticipaba que el servicio estaría fuera de los puertos por defecto, pero el informe tiene que reflejar lo que mostraron las salidas, no lo que se esperaba encontrar.

**P2 — El servicio dev en producción.**  
**Pendiente — responsable: Belén.** Fundamentar con la salida de Nmap para 8080 y la respuesta real de `/status`; explicar el riesgo del servicio dev expuesto incluso sin atribuir un CVE no comprobado.

#### Fuentes de P1 y P2

- **[P1] [PRIMARIA]** Lyon, G. (s. f.). *Port Specification and Scan Order*. Nmap Reference Guide. https://nmap.org/book/man-port-specification.html — Por defecto, Nmap revisa los 1.000 puertos más frecuentes de cada protocolo; `-p-` recorre del 1 al 65.535.

**P3 — La ironía de `robots.txt`.**  
`robots.txt` comunica a los rastreadores qué rutas se les solicita que no rastreen; no controla quién puede abrirlas. RFC 9309 aclara que sus reglas no son autorización de acceso y que publicar rutas allí puede hacerlas descubribles ([RFC 9309, sección 3](https://www.rfc-editor.org/rfc/rfc9309.html#section-3)). En este laboratorio, `lab05-robots.txt` muestra `Disallow: /panel-interno-9x2f` y hasta comenta que la ruta sigue accesible desde afuera. La petición posterior a esa ruta devolvió HTTP 200 y el contenido del panel (`lab05-hidden-panel.txt`). Por eso el archivo facilitó la enumeración, pero la evidencia de la respuesta muestra que no protegía el recurso.

**P4 — Pasivo vs. activo.**  
El reconocimiento pasivo reúne información disponible sin sondear directamente al objetivo; el activo lo consulta por tráfico de red. MITRE ATT&CK diferencia la búsqueda en sitios públicos ([T1593](https://attack.mitre.org/techniques/T1593/)) del escaneo que sondea infraestructura ([T1595](https://attack.mitre.org/techniques/T1595/)). En la bitácora del grupo no hay una acción pasiva documentada: `ping`, `nmap`, `ncat` y las solicitudes `curl` se dirigieron a `phantomcorp`, así que fueron activas. Las solicitudes HTTP pudieron aparecer en los registros de la aplicación; Nmap, Ncat y ping pudieron dejar rastros en registros o sensores de red. Como no se incluyeron esos registros, no afirmamos que cada acción haya quedado efectivamente registrada.

**P5 — Ahora sos el defensor.**  
1. **Panel interno publicado en el puerto 80:** exigir autenticación y autorización en la aplicación, y limitar el panel a la VPN o a una subred administrativa. Quitar la ruta de `robots.txt` elimina la pista, pero no reemplaza esos controles. Verificar desde una red externa que una solicitud sin credenciales reciba 401/403 y que el panel solo responda desde el acceso administrativo autorizado.
2. **API de desarrollo expuesta en el puerto 8080:** retirar el servicio del perímetro público, enlazarlo solo a una interfaz de administración, restringir el acceso por firewall y desactivar el modo debug. Reducir los campos de `/status` para que no publique versión y estado de debug. Verificar desde fuera de la red administrativa que el puerto no sea alcanzable y que el endpoint ya no revele esos datos.

---

## 4. Bitácora de comandos

Comandos ejecutados contra el contenedor autorizado `phantomcorp`:

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
