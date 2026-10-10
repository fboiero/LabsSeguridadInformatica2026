# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 12  
**Integrantes:**
- Gerbaudo, Mateo — @gerbaudo19
- Mariatti, Matias — @matiasmariatticasc
- Colque Condo, Luis Alvaro — @ColqueAlvaro
- Rodriguez, Gonzalo — @Gonza149

---

## 0. Declaración de uso de IA

En cumplimiento con el régimen de la cátedra y las pautas de `CONTRIBUTING.md`:

- **Herramienta utilizada:** Asistente IA (Antigravity / Gemini 3.8 Flash).
- **Alcance de la asistencia:** Asistencia en la estructuración técnica del informe, captura y documentación de flags, consolidación del mapa de superficie de ataque con investigación de CVE/CVSS asociados, formato de evidencias y redacción de las respuestas de análisis de la Sección 3 (**P1–P4**); la pregunta **P5** fue redactada por @ColqueAlvaro.
- **Partes originadas o modificadas:** Sección 1 (Parte práctica — flags capturadas), Sección 2 (Mapa de superficie de ataque y evidencias técnicas) y Sección 3 (Preguntas de análisis **P1–P4**; **P5** por @ColqueAlvaro). La Sección 4 (Bitácora de comandos) fue realizada por @matiasmariatticasc.
- **Verificación humana:** Se contrastaron los servicios reales expuestos por el contenedor `phantomcorp` (puertos 21, 80, 8080 y 31337), validando las banderas, versiones extraídas en los banners y los registros oficiales de CVE (como CVE-2015-3306 de ProFTPD 1.3.5 en la base NVD del NIST). En P5 se verificaron las medidas de remediación y reducción de superficie aplicando el principio de mínimo privilegio y defensa en profundidad.

---

## 1. Parte práctica — flags capturadas

Salida de `./ctf status 05`:

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

### Detalle de retos resueltos y flags obtenidas

| Reto | Técnica empleada | Comando de descubrimiento | Flag capturada |
|---|---|---|---|
| **R1** | Barrido completo de puertos (`-p-`) | `ncat -w2 phantomcorp 31337 </dev/null` | `FLAG{high_port_secret_service}` |
| **R2** | Banner grabbing FTP | `ncat phantomcorp 21` | `FLAG{banner_grab_proftpd_135}` |
| **R3** | Análisis de headers HTTP (`-I`) | `curl -sI http://phantomcorp/` | `FLAG{http_headers_leak_info}` |
| **R4** | Enumeración de rutas (`robots.txt`) | `curl -s http://phantomcorp/panel-interno-9x2f` | `FLAG{recon_hidden_path}` |
| **R5** | Servicio dev expuesto | `curl -s http://phantomcorp:8080/status` | `FLAG{dev_service_exposed}` |

---

## 2. Mapa de superficie de ataque

A continuación se detalla la superficie de ataque descubierta en **PhantomCorp**, abarcando la totalidad de los puertos abiertos encontrados tras un escaneo exhaustivo:

| Puerto | Servicio | Versión (evidencia) | ¿Cómo lo identificaste? | CVE relevante | CVSS | Criticidad | Justificación (contra ESTE caso) |
|---|---|---|---|---|---|---|---|
| **21** | FTP | `ProFTPD 1.3.5` <br> *(Banner: 220 ProFTPD 1.3.5 Server)* | Banner grabbing con `ncat phantomcorp 21` y `nmap -Pn -sV -p 21` | **CVE-2015-3306** | **9.8** *(Crítica)* <br> `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **Crítica** | El módulo `mod_copy` de ProFTPD 1.3.5 permite que atacantes no autenticados ejecuten comandos `SITE CPFR` y `SITE CPTO` para copiar archivos arbitrarios dentro del sistema. En este servidor permite volcar archivos sensibles o subir una webshell PHP/Python al directorio web público, logrando Ejecución Remota de Código (RCE). |
| **80** | HTTP | `PhantomServer/2.4.1` <br> `X-Powered-By: PhantomCMS 2.4.1` | Inspección de cabeceras con `curl -sI` y escaneo `nmap -Pn -sV -p 80` | *N/A (Software propietario / Fuga de información y mala configuración)* | **5.3** *(Media)* <br> `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | **Media** | El servidor web filtra tecnologías y versiones específicas en sus cabeceras (`Server`, `X-Powered-By`, `X-Backend-Flag`). Además, `robots.txt` explicita rutas restringidas como `/panel-interno-9x2f` y `/admin` con comentarios internos de infraestructura, facilitando el acceso a paneles internos sin pasar por mecanismos de autenticación o VPN. |
| **8080** | HTTP <br> *(Dev API)* | `Werkzeug/2.0.1` <br> *(Python/3.9.2)* <br> Servicio: `phantom-dev-api 0.9.3-DEV` con `debug: true` | `curl -s http://phantomcorp:8080/status` y `nmap -Pn -sV -p 8080` | **Exposición de depuración / CWE-200** *(asociado a CVE-2022-29361)* | **7.5** *(Alta)* <br> `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` | **Alta** | Servicio de desarrollo publicado indebidamente en un entorno productivo con la directiva `"debug": true` activada. Expone metadatos internos del backend a través de endpoints de estado (`/status`). Si el depurador interactivo de Werkzeug llegara a dispararse ante un error no controlado, permitiría la consola interactiva con PIN exploit y RCE. |
| **31337** | Shell TCP <br> *(Mantenimiento)* | `PhantomCorp maintenance shell v0.1` | Barrido completo `nmap -Pn -p-` y conexión cruda con `ncat` | **Falta de autenticación en interfaz crítica (CWE-306)** | **9.8** *(Crítica)* <br> `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | **Crítica** | Servicio de administración alojado en un puerto alto no estándar (31337 / *elite*), fuera del top 1000 tradicional. Al conectarse, entrega directamente un banner de shell de mantenimiento sin requerir credenciales ni autenticación alguna. Representa una puerta trasera o interfaz de soporte no protegida con potencial control total del equipo. |

### Evidencia de respaldo de los comandos

#### 1. Escaneo exhaustivo con Nmap (`-Pn -sV -p-`)
```text
$ nmap -Pn -sV -p- phantomcorp
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-09 18:05 -03
Nmap scan report for phantomcorp (172.28.0.2)
Host is up (0.00035s latency).
Not shown: 65531 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
21/tcp    open  ftp      ProFTPD 1.3.5
80/tcp    open  http     PhantomServer 2.4.1
8080/tcp  open  http     Werkzeug httpd 2.0.1 (Python 3.9.2)
31337/tcp open  Elite?
1 service unrecognized despite returning data.
```

#### 2. Banner Grabbing FTP (Puerto 21)
```text
$ ncat phantomcorp 21
220 ProFTPD 1.3.5 Server (PhantomCorp FTP) [::ffff:0.0.0.0]
214 FLAG{banner_grab_proftpd_135}
```

#### 3. Inspección de Cabeceras HTTP y Enumeración de Rutas (Puerto 80)
```text
$ curl -sI http://phantomcorp/
HTTP/1.0 200 OK
Server: PhantomServer/2.4.1
Date: Fri, 09 Oct 2026 18:06:12 GMT
Content-Type: text/html; charset=utf-8
X-Powered-By: PhantomCMS 2.4.1
X-Backend-Flag: FLAG{http_headers_leak_info}

$ curl -s http://phantomcorp/robots.txt
User-agent: *
Disallow: /admin
Disallow: /panel-interno-9x2f
# Recordatorio infra: /panel-interno-9x2f sigue accesible desde afuera. Migrar a VPN.

$ curl -s http://phantomcorp/panel-interno-9x2f
<!doctype html><html><body>
<h1>Panel interno PhantomCorp</h1>
<p>Acceso restringido. Si llegaste aca por robots.txt, felicitaciones: acabas
de hacer enumeracion de rutas. Esa es exactamente la tecnica.</p>
<pre>FLAG{recon_hidden_path}</pre>
</body></html>
```

#### 4. Interrogación de Servicio Dev (Puerto 8080)
```text
$ curl -s http://phantomcorp:8080/status
{"service":"phantom-dev-api","version":"0.9.3-DEV","debug":true,"flag":"FLAG{dev_service_exposed}"}
```

#### 5. Banner de Shell de Mantenimiento en Puerto Alto (Puerto 31337)
```text
$ ncat -w2 phantomcorp 31337 </dev/null
PhantomCorp maintenance shell v0.1 -- acceso no autorizado prohibido
FLAG{high_port_secret_service}
```

---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**

El puerto perdido fue el **31337**. El escaneo por defecto de `nmap` solo barre los
**1000 puertos "well-known"** más frecuentes; el 31337 (el puerto "*elite*") queda
fuera de ese conjunto, por eso el escaneo común ni siquiera lo reporta como cerrado.
Con `-p-` (los 65535 puertos) sí aparece: `31337/tcp open Elite?`, y al conectarnos con
`ncat -w2 phantomcorp 31337` devuelve el banner `PhantomCorp maintenance shell v0.1`
(más la flag). **Regla operativa:** el barrido por defecto da una foto parcial y sesgada
del objetivo; hay que correr siempre `-p-` (o al menos los rangos altos), porque los
servicios se esconden a propósito en puertos altos justamente para no figurar en el
top-1000 y pasar desapercibidos.

**P2 — El servicio dev en producción.**

La evidencia concreta está en `curl -s http://phantomcorp:8080/status`, que devuelve
`{"service":"phantom-dev-api","version":"0.9.3-DEV","debug":true}`. Dos huellas de que
no estaba pensado para producción: el sufijo **`-DEV`** en la versión y la directiva
**`"debug": true`** (nmap además lo identifica como `Werkzeug httpd 2.0.1`). Es un
problema **aunque no tenga un CVE de versión conocido** porque la falla es de
**configuración**, no de software desactualizado: con `debug:true` en Werkzeug, un
error no controlado puede disparar la **consola interactiva** del depurador (RCE
sorteándola con el PIN), y de yapa expone **metadatos internos** del backend por
`/status`. En síntesis, suma superficie de ataque con un servicio que nunca debió estar
expuesto a internet.

**P3 — La ironía de `robots.txt`.**

`robots.txt` se creó para **SEO** (Robots Exclusion Standard): les pide a los
*crawlers* de los buscadores qué rutas **no** indexar. La ironía es que es un archivo
**público**, legible por cualquiera —atacante incluido— y enumera justamente lo
"sensible": acá declara `Disallow: /admin` y `Disallow: /panel-interno-9x2f`, más un
comentario de infra (`/panel-interno-9x2f sigue accesible desde afuera. Migrar a VPN.`)
que de paso filtró que la ruta seguía abierta. Es decir: en lugar de ocultar, **le
regala al atacante el mapa de qué mirar** — una "seguridad por oscuridad" que en la
práctica funciona como publicidad de lo oculto. Nosotros lo aprovechamos:
`curl -s http://phantomcorp/panel-interno-9x2f` → `FLAG{recon_hidden_path}`.

**P4 — Pasivo vs. activo.**

**Pasivo:** no toca el objetivo ni deja rastro en sus logs; se nutre de fuentes de
terceros. En este lab, buscar el **CVE-2015-3306** de ProFTPD 1.3.5 en la base **NVD**
del NIST fue recon pasivo. **Activo:** interactúa directamente con el target y **queda
registrado** en él. Todo lo demás fue activo: el `nmap -Pn -sV -p-`, el `ncat` al
puerto 21, el `curl -sI` al 80, el `curl .../robots.txt` y el `curl ...:8080/status`.
Lo que **habría quedado en los logs de PhantomCorp**: el barrido de puertos y esas
peticiones HTTP (los GET a `/robots.txt`, `/panel-interno-9x2f` y `/status`), junto con
las conexiones a los puertos 21 y 31337 — todas con nuestra IP de origen. La diferencia
práctica: lo pasivo es silencioso e inadvertido; lo activo es ruidoso y detectable por
el defensor.

**P5 — Ahora sos el defensor.**

Como responsable de defensa de PhantomCorp, analizando el mapa de superficie de ataque obtenido durante el reconocimiento, selecciono dos de los hallazgos más críticos para implementar medidas inmediatas que eliminen y reduzcan drásticamente la exposición perimetral:

1. **Hallazgo 1: Shell de mantenimiento en puerto alto (TCP 31337) sin autenticación**
   - **Diagnóstico del riesgo:** Se trata de una interfaz administrativa abierta que devuelve control directo al conectarse (`PhantomCorp maintenance shell v0.1`), alojada en un puerto no estándar confiando en la falacia de "seguridad por oscuridad". Al no requerir credenciales ni cifrado, cualquier atacante que realice un barrido de puertos completo (`nmap -p-`) obtiene acceso irrestricto.
   - **Medidas concretas de reducción de superficie:**
     - *Eliminación / Enlace local:* Si el servicio no es estrictamente necesario, debe ser dado de baja (`systemctl stop/disable`). Si se requiere para soporte interno, debe vincularse (*bind*) exclusivamente a la interfaz de loopback `127.0.0.1` o a una red de gestión aislada (VLAN OOB / *Out-of-Band*), jamás a `0.0.0.0`.
     - *Filtrado perimetral estricto:* Configurar reglas de firewall (`iptables` / Security Groups) con política *default-deny*, bloqueando el tráfico entrante a puertos no estándar desde Internet y cerrando el puerto 31337 en el perímetro.
     - *Canal seguro y autenticación:* Reemplazar esta shell cruda en texto plano por administración vía SSH con llaves criptográficas (deshabilitando autenticación por contraseña), obligando a que cualquier conexión remota se canalice a través de una VPN corporativa con autenticación multifactor (MFA).

2. **Hallazgo 2: Servidor FTP ProFTPD 1.3.5 vulnerable (CVE-2015-3306) en puerto 21**
   - **Diagnóstico del riesgo:** El servidor corre una versión obsoleta con el módulo `mod_copy` activo por defecto, el cual permite la ejecución de comandos no autenticados (`SITE CPFR` / `SITE CPTO`) para leer y escribir archivos en el sistema de archivos del servidor, habilitando la subida de webshells y RCE. Además, el banner FTP exhibe explícitamente el producto y la versión exacta (`220 ProFTPD 1.3.5 Server`), facilitando la búsqueda inmediata de exploits.
   - **Medidas concretas de reducción de superficie:**
     - *Parcheo / Actualización y migración tecnológica:* Actualizar el servicio a una versión mantenida de ProFTPD libre de la vulnerabilidad o, preferentemente, retirar el protocolo FTP en texto plano (que viaja sin cifrar) y migrar la transferencia de archivos a **SFTP** (SSH File Transfer Protocol) o FTPS con certificados TLS vigentes.
     - *Hardening de configuración inmediata:* Desactivar el módulo vulnerable en la directiva de configuración de ProFTPD (`mod_copy.c`) y ocultar la divulgación de versión en el saludo inicial mediante la directiva `ServerIdent off` (o personalizando el banner para que no revele software ni versión).
     - *Segmentación perimetral:* Restringir el acceso al puerto 21 a una lista blanca (*allowlist*) de direcciones IP autorizadas o aislar el servicio detrás de un proxy inverso/DMZ, evitando la exposición irrestricta a todo Internet.

---

## 4. Bitácora de comandos

```bash
# Inicializar y entrar al contenedor atacante
make setup
make shell

# Descubrimiento de servicios y puertos
nmap -Pn -sV -p- phantomcorp

# Recolección de flags
ncat -w2 phantomcorp 31337 </dev/null
./ctf submit 05 R1 'FLAG{high_port_secret_service}'

ncat phantomcorp 21
./ctf submit 05 R2 'FLAG{banner_grab_proftpd_135}'

curl -sI http://phantomcorp/
./ctf submit 05 R3 'FLAG{http_headers_leak_info}'

curl -s http://phantomcorp/robots.txt
curl -s http://phantomcorp/panel-interno-9x2f
./ctf submit 05 R4 'FLAG{recon_hidden_path}'

curl -s http://phantomcorp:8080/status
./ctf submit 05 R5 'FLAG{dev_service_exposed}'

./ctf status 05
```
