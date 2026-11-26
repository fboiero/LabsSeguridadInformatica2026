# **Informe — Laboratorio 05 · Reconocimiento**

**Grupo:** 09 **Integrantes:**

* Cocchi Santiago   
* Mosello Francisco   
* Torres Santiago   
* Ferraro Franco   
* Spat Tomas 

---

## **0\. Declaración de uso de IA**

Para este laboratorio se utilizó el asistente de IA **Claude (Anthropic)** con los siguientes alcances:

* **Para qué se usó:** como guía de método y acompañamiento. En concreto: (a) ayuda para montar el entorno Docker en Windows (traducción de los comandos `make` a sus equivalentes `docker compose`), (b) diagnóstico de problemas de infraestructura del entorno (finales de línea CRLF en el repositorio clonado en Windows, montaje de `/repo` en modo solo-lectura dentro del contenedor), (c) explicación conceptual de cada herramienta y técnica (nmap, ncat, curl, banner grabbing, enumeración de rutas), y (d) estructuración de este informe según la plantilla y la rúbrica de la cátedra.  
* **Qué NO hizo la IA:** no ejecutó las herramientas ni accedió al objetivo. Todos los escaneos, conexiones y pedidos contra `phantomcorp` los ejecutó el grupo desde la consola del atacante. Las 5 flags se obtuvieron operando las herramientas, no leyéndolas de ningún archivo de solución.  
* **Cómo se validó la salida:** cada comando sugerido se ejecutó manualmente y se verificó su resultado contra la evidencia real capturada (ver carpeta `evidencia/`). Los CVE y puntajes CVSS citados en el mapa de superficie se verificaron de forma independiente en las fuentes oficiales enlazadas, no se tomaron de la IA sin control.

---

## **1\. Parte práctica — flags capturadas**

Salida de `./ctf status 05` (evidencia completa en `evidencia/status-lab.txt`):

 ╭────────────────────────────────────────────────────────────╮  
  │                     PROGRESO · LAB 05                     │  
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Puerto oculto en rango alto (barrido completo)  
   ✓  R2     Banner grabbing del servicio FTP  
   ✓  R3     Fuga de informacion en headers HTTP  
   ✓  R4     Enumeracion de rutas via robots.txt  
   ✓  R5     Servicio dev expuesto en produccion

  ██████████████████████████████  5/5 (100%)

\[ OK \] ¡Lab 05 COMPLETO\!

| Reto | Técnica | Flag |
| ----- | ----- | ----- |
| R1 | Barrido completo de puertos (`-p-`) \+ banner en puerto alto | `FLAG{high_port_secret_service}` |
| R2 | Banner grabbing FTP con ncat | `FLAG{banner_grab_proftpd_135}` |
| R3 | Análisis de headers HTTP con curl | `FLAG{http_headers_leak_info}` |
| R4 | Enumeración de rutas vía robots.txt | `FLAG{recon_hidden_path}` |
| R5 | Servicio dev expuesto (endpoint /status) | `FLAG{dev_service_exposed}` |

---

## **2\. Mapa de superficie de ataque**

| Puerto | Servicio | Versión (evidencia) | ¿Cómo lo identificaste? | CVE relevante | CVSS | Criticidad | Justificación (contra ESTE caso) |
| ----- | ----- | ----- | ----- | ----- | ----- | ----- | ----- |
| 21 | FTP | ProFTPD 1.3.5 | Banner grabbing con `ncat phantomcorp 21` → `220 ProFTPD 1.3.5 Server`. Confirmado también por `nmap -sV`. | CVE-2015-3306 (módulo `mod_copy`) | 10.0 (CVSS v2) / 10.0 CRÍTICO (CVSS v3.1) | **Crítica** | La versión 1.3.5 es vulnerable a CVE-2015-3306: un atacante **remoto y sin autenticar** puede leer y escribir archivos arbitrarios vía los comandos `SITE CPFR`/`SITE CPTO` de `mod_copy`, lo que en la práctica deriva en ejecución remota de comandos. Está en el catálogo KEV de CISA (explotación activa). Es el hallazgo de mayor impacto del perímetro. |
| 80 | HTTP | PhantomServer/2.4.1 (servidor) \+ PhantomCMS 2.4.1 (backend) | Headers con `curl -I phantomcorp` → `Server: PhantomServer/2.4.1`, `X-Powered-By: PhantomCMS 2.4.1`. Header `X-Backend-Flag` filtrado. | No aplica (software ficticio del lab; sin CVE público verificable) | — | **Media** | No hay un CVE que se pueda afirmar con honestidad (producto ficticio). Pero hay **fuga de información** concreta: el header personalizado `X-Backend-Flag` expone datos internos, y el HTML trae un comentario `TODO(infra): sacar el panel interno de produccion antes del go-live`. Ambos facilitan el recon y revelan versión/estructura al atacante. La criticidad no es por un exploit, sino por la divulgación de información que reduce el esfuerzo del atacante. |
| 8080 | HTTP (API dev) | Werkzeug httpd 2.0.1 (Python 3.9.2) | `nmap -sV` identifica Werkzeug 2.0.1. `curl phantomcorp:8080/status` → JSON con `"service":"phantom-dev-api"`, `"version":"0.9.3-DEV"`, `"debug":true`. | No aplica a esta versión con certeza. (El CVE-2024-34069 de la consola de debug de Werkzeug afecta versiones posteriores; no se afirma que la 2.0.1 sea vulnerable a él sin evidencia.) | — | **Alta** | Servicio de **desarrollo expuesto en producción**: nombre `phantom-dev-api`, versión pre-release `0.9.3-DEV` y, sobre todo, `debug:true`. El modo debug de Werkzeug/Flask expone trazas de error con rutas y fragmentos de código, y habilita una consola interactiva que puede ejecutar código Python en el servidor. Es un problema grave **de configuración**, independiente de que exista o no un CVE numerado para esta versión exacta. |
| 31337 | "maintenance shell" (servicio a medida) | No determinable con certeza — nmap lo marca `Elite?` (no reconocido). | Descubierto con `nmap -Pn -p-` (no aparece en el escaneo default por ser un puerto alto). Banner leído con `ncat phantomcorp 31337`. | No aplica (servicio propio, sin fingerprint conocido) | — | **Alta** | `ncat` devuelve `PhantomCorp maintenance shell v0.1 -- acceso no autorizado prohibido`. No se pudo determinar producto/versión (respuesta honesta: nmap no lo reconoció). Aun así, un "maintenance shell" accesible sin autenticación en un puerto alto no documentado es de alto riesgo: sugiere una vía de acceso administrativo que no debería estar expuesta al perímetro. |

**Evidencia de respaldo** (salida de `nmap -Pn -sV -p- phantomcorp`, archivo completo en `evidencia/nmap.txt`):

PORT      STATE SERVICE VERSION  
21/tcp    open  ftp     ProFTPD 1.3.5  
80/tcp    open  http    PhantomServer/2.4.1  
8080/tcp  open  http    Werkzeug httpd 2.0.1 (Python 3.9.2)  
31337/tcp open  Elite?  
Service Info: OS: Unix

Banners y headers que sostienen la tabla: ver `evidencia/ftp-banner.txt`, `evidencia/http-headers.txt`, `evidencia/robots-y-panel.txt` y `evidencia/status-8080.txt`.

> **Fuentes de los CVE citados:**

> * CVE-2015-3306 (ProFTPD 1.3.5): https\://vulnerability.circl.lu/vuln/cve-2015-3306  
> * Werkzeug debug console (contexto, CVE-2024-34069, versiones posteriores): https\://access.redhat.com/security/cve/CVE-2024-34069

---

## **3\. Preguntas de análisis**

**P1 — El puerto que el escaneo default se perdió.**

En nuestro caso, el escaneo por defecto (`nmap -Pn phantomcorp`, los 1000 puertos más comunes) y el barrido completo (`nmap -Pn -p-`, los 65535\) devolvieron los **mismos cuatro** puertos: 21, 80, 8080 y 31337\. El puerto "interesante" (31337) ya caía dentro de los 1000 comunes, así que en este objetivo el `-p-` no reveló un puerto extra. Pero la lección operativa se sostiene igual: **antes de correr `-p-` era imposible saberlo**. La única forma de tener certeza de que no quedaba un servicio escuchando por encima del puerto 1000 fue escanear los 65535\. La regla que sacamos: el barrido completo no es opcional, es el que convierte un "creo que no hay nada más" en un "verifiqué que no hay nada más". Un atacante o un dev descuidado suele esconder servicios justo en puertos altos (como el ejemplo del Jenkins en 8081 del enunciado), y el escaneo default los pasaría por alto.

**P2 — El servicio dev en producción.**

La evidencia concreta de que el servicio del puerto 8080 no era para producción está en la respuesta de `curl phantomcorp:8080/status`: `{"service":"phantom-dev-api","version":"0.9.3-DEV","debug":true,...}`. Tres señales: (1) el nombre `phantom-dev-api` contiene literalmente "dev"; (2) la versión `0.9.3-DEV` es pre-release (ni siquiera 1.0) y lleva el sufijo `-DEV`; (3) `debug:true`. Además, `nmap -sV` lo identificó como **Werkzeug**, el servidor de desarrollo de Flask, que no está pensado para exponerse públicamente. Es un problema **aunque no tenga un CVE conocido** porque el modo debug es peligroso por diseño: expone trazas de error con rutas internas y fragmentos de código, y en Flask/Werkzeug puede habilitar una consola interactiva que ejecuta código Python en el servidor. La vulnerabilidad acá no es un número de CVE, es la **mala configuración**: información interna y potencial ejecución de código al alcance de cualquiera que mande un request.

**P3 — La ironía de `robots.txt`.**

`robots.txt` se creó para un fin legítimo: pedirles a los buscadores (Google, Bing) que **no indexen** ciertas rutas. El problema es que, para decir "no mires `/panel-interno-9x2f`", hay que **escribir esa ruta en un archivo público** que cualquiera puede leer pidiendo `curl phantomcorp/robots.txt`. Así, un control pensado para *ocultar* rutas termina siendo un **índice de las rutas sensibles** para el atacante: es lo primero que mira un pentester. En PhantomCorp la ironía fue doble: el `robots.txt` no solo listaba `/admin` y `/panel-interno-9x2f`, sino que incluía un comentario del propio equipo de infra admitiendo que el panel "sigue accesible desde afuera" y que habría que migrarlo a VPN. El archivo que debía esconder, terminó entregando el mapa y la confesión.

**P4 — Pasivo vs. activo.**

El **reconocimiento pasivo** recolecta información sin tocar el objetivo (whois, DNS público, Google dorks): no deja rastro en los logs de la víctima y tiene bajo riesgo legal. El **reconocimiento activo** interactúa directamente con el objetivo (lo "toca"), y por eso queda registrado y requiere autorización. En este lab, prácticamente todo lo que hicimos fue **activo**: el `ping -c1 phantomcorp`, cada escaneo de `nmap` (que envía decenas de miles de paquetes), cada conexión con `ncat` a los puertos 21 y 31337, y cada pedido con `curl` (robots.txt, el panel oculto, el endpoint /status). **Todas esas acciones habrían quedado en los logs de PhantomCorp**: el servidor FTP registraría las conexiones al 21, el servidor web registraría los GET a `/robots.txt`, `/panel-interno-9x2f` y `/status`, y un IDS podría haber detectado el escaneo de 65535 puertos como actividad anómala. No ejecutamos recon pasivo real contra PhantomCorp porque es un host interno sin DNS público (whois/dig se practican, según el enunciado, contra dominios reales de prueba) — y justamente eso refuerza el punto: en un engagement real se empieza por lo pasivo (invisible) y recién con autorización se pasa a lo activo (ruidoso).

**P5 — Ahora sos el defensor.**

Elegimos dos hallazgos:

1. **FTP ProFTPD 1.3.5 (puerto 21, CVE-2015-3306).** Medida concreta: **actualizar ProFTPD** a una versión parcheada (≥ 1.3.5a / 1.3.6) o, si no se usa el módulo, **deshabilitar `mod_copy`** en la configuración. Complementariamente, si el FTP no necesita estar expuesto al perímetro, **restringirlo por firewall** a la red interna o detrás de VPN. Esto elimina de raíz la vía de lectura/escritura de archivos remota.

2. **Servicio dev en el puerto 8080 (`debug:true`).** Medida concreta: **desactivar el modo debug** (`debug=False`) y **no usar el servidor de desarrollo Werkzeug en producción** (desplegar detrás de un servidor WSGI real como Gunicorn/uWSGI \+ un reverse proxy). Si el servicio es solo para desarrollo, **no debería estar expuesto**: bloquear el puerto 8080 en el firewall perimetral. Esto cierra la fuga de información del endpoint `/status` y la posible consola de ejecución de código.

*(Bonus defensivo aplicable a otros hallazgos: sacar el header `X-Backend-Flag` y el comentario `TODO` del HTML del puerto 80, y eliminar o autenticar el "maintenance shell" del puerto 31337.)*

---

## **4\. Bitácora de comandos**

**\# 0\. Verificar alcance al objetivo**  
ping \-c1 phantomcorp

**\# 1\. R1 — Descubrimiento de puertos (default vs completo)**  
nmap \-Pn phantomcorp                 \# 1000 puertos comunes  
nmap \-Pn \-p- phantomcorp             \# los 65535 (verificación)  
nmap \-Pn \-sV \-p- phantomcorp         \# combo: todos los puertos \+ versiones (evidencia maestra)  
ncat phantomcorp 31337               \# banner del maintenance shell → FLAG R1

**\# 2\. R2 — Banner grabbing FTP**  
ncat phantomcorp 21                  \# saludo del FTP (ProFTPD 1.3.5) → FLAG R2

**\# 3\. R3 — Headers HTTP**  
curl \-I phantomcorp                  \# header X-Backend-Flag → FLAG R3

**\# 4\. R4 — Enumeración de rutas vía robots.txt**  
curl \-s phantomcorp/robots.txt            \# lista Disallow: /panel-interno-9x2f  
curl \-s phantomcorp/panel-interno-9x2f    \# panel oculto → FLAG R4

**\# 5\. R5 — Servicio dev expuesto**  
curl \-s phantomcorp:8080                  \# phantom-dev-api, sugiere /status  
curl \-s phantomcorp:8080/status           \# JSON con debug:true → FLAG R5

\# Entrega de flags (desde /loot/ctf-home por el montaje read-only de /repo)  
./ctf submit 05 R1 'FLAG{...}'  
./ctf status 05

---

 