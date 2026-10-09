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
- **Alcance de la asistencia:** Asistencia en la estructuración técnica del informe, captura y documentación de flags, consolidación del mapa de superficie de ataque con investigación de CVE/CVSS asociados y formato de evidencias.
- **Partes originadas o modificadas:** Sección 1 (Parte práctica — flags capturadas) y Sección 2 (Mapa de superficie de ataque y evidencias técnicas).
- **Verificación humana:** Se contrastaron los servicios reales expuestos por el contenedor `phantomcorp` (puertos 21, 80, 8080 y 31337), validando las banderas, versiones extraídas en los banners y los registros oficiales de CVE (como CVE-2015-3306 de ProFTPD 1.3.5 en la base NVD del NIST).

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

## 3. Preguntas de análisis *(Pendiente — a completar por el equipo)*

**P1 — El puerto que el escaneo default se perdió.**
*(A completar por el equipo)*

**P2 — El servicio dev en producción.**
*(A completar por el equipo)*

**P3 — La ironía de `robots.txt`.**
*(A completar por el equipo)*

**P4 — Pasivo vs. activo.**
*(A completar por el equipo)*

**P5 — Ahora sos el defensor.**
*(A completar por el equipo)*

---

## 4. Bitácora de comandos *(Pendiente — a completar por el equipo)*

```bash
# A completar por el equipo
```
