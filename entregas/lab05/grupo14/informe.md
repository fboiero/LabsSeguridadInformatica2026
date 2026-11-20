# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 14
**Integrantes:**
- Fede Peron — @fedeeperon
- Laureano Gomez Redondo — @Laureano-GR
- Martín Cesano — @martincesano
- Martín Gaido — @martingaidoo
- Valentina Chiapero — @valechiapero

**Fecha:** 2026-10-24

---

## 0. Declaración de uso de IA

- **Herramienta:** Claude (Anthropic), vía Claude Code.
- **Para qué:** operar las tools de recon contra el target del lab, ordenar la
  evidencia, redactar el mapa de superficie, las respuestas P1–P5 y el
  mini-research, y completar los dos TODO de `src/escaner.py`.
- **Qué partes:** todo el contenido de `informe.md`, `research.md`,
  `src/escaner.py` (funciones `parsear_puertos` y `leer_banner`) y
  `src/verificar.py`.
- **Cómo lo validamos:**
  - Las 5 flags se obtuvieron **ejecutando las herramientas** contra
    `phantomcorp` (nmap, ncat, curl), nunca leyendo `solucion.md` ni el código
    del target. La evidencia cruda está en `evidencia/`.
  - El CVE citado (CVE-2015-3306 para ProFTPD 1.3.5) se verificó contra la
    entrada oficial de NVD; su CVSS se transcribió de ahí.
  - Donde no pudimos determinar producto/versión o un CVE aplicable, lo
    declaramos explícitamente en vez de inventarlo (puertos 80 y 31337).
  - `python3 src/verificar.py` → `[OK] 7 chequeos pasaron`, y
    `escaner.py phantomcorp --puertos 21,80,8080,31337 --banner` coincide con
    los 4 puertos que reportó nmap.

---

## 1. Parte práctica — flags capturadas

```
   ✓  R1     Puerto oculto en rango alto (barrido completo)
   ✓  R2     Banner grabbing del servicio FTP
   ✓  R3     Fuga de informacion en headers HTTP
   ✓  R4     Enumeracion de rutas via robots.txt
   ✓  R5     Servicio dev expuesto en produccion

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 05 COMPLETO!
```

(Salida completa en `evidencia/ctf-status.txt`.)

| Reto | Técnica | Dónde salió la flag |
|---|---|---|
| R1 | Barrido completo `nmap -p-` + conexión al puerto alto | banner del 31337 |
| R2 | Banner grabbing con `ncat` al 21 | saludo del FTP |
| R3 | `curl -I` al 80 | header `X-Backend-Flag` |
| R4 | `robots.txt` → ruta `Disallow` | cuerpo de `/panel-interno-9x2f` |
| R5 | HTTP en puerto 8080, endpoint de estado | JSON de `/status` (`debug:true`) |

---

## 2. Mapa de superficie de ataque

| Puerto | Servicio | Versión (evidencia) | ¿Cómo lo identificamos? | CVE relevante | CVSS | Criticidad | Justificación (contra ESTE caso) |
|---|---|---|---|---|---|---|---|
| 21/tcp | FTP | **ProFTPD 1.3.5** (banner `220 ProFTPD 1.3.5 Server` + `nmap -sV`) | banner grabbing con `ncat phantomcorp 21` y confirmación con `nmap -sV` | **CVE-2015-3306** (`mod_copy`, `SITE CPFR/CPTO` → RCE sin auth) | CVSS v2 **10.0** (NVD; sin CVSS v3 asignado) | **Crítica** | Versión exacta con CVE de ejecución remota **sin autenticación**. Un atacante escribe un webshell vía `SITE CPFR/CPTO` y combina con el HTTP del 80 → compromiso total. Es el pivote más directo del perímetro. |
| 80/tcp | HTTP | **PhantomServer/2.4.1**, `X-Powered-By: PhantomCMS 2.4.1` (headers) | `curl -I phantomcorp` | — (producto ficticio del lab, sin CVE público) | n/a | **Media** | No hay CVE que clasificar: PhantomServer/PhantomCMS no existen fuera del lab, así que **no inventamos uno**. El hallazgo real es la **fuga de información**: el server publica producto y versión exacta en `Server` y `X-Powered-By`, y filtra un `X-Backend-Flag`. Revelar el stack facilita el targeting. |
| 8080/tcp | HTTP (API dev) | **Werkzeug httpd 2.0.1 (Python 3.9.2)** (`nmap -sV`); app `phantom-dev-api` **0.9.3-DEV** con `debug:true` (`/status`) | `nmap -sV` + `curl phantomcorp:8080/` y `curl phantomcorp:8080/status` | — (no aplicamos CVE; ver P2) | n/a | **Alta** | Servicio de desarrollo expuesto en el perímetro: versión `-DEV`, `debug:true` y un `/status` que filtra estado interno. Werkzeug con el debugger activo habilita, en el peor caso, ejecución de código por la consola interactiva. El riesgo no es un CVE: es **configuración de desarrollo en producción**. |
| 31337/tcp | "maintenance shell" | **No determinable** — banner `PhantomCorp maintenance shell v0.1`; sin producto ni versión fingerprinteable (`nmap` lo marca `Elite?`) | `ncat phantomcorp 31337` + fingerprint fallido de `nmap -sV` | — (no clasificable) | n/a | **Alta (por naturaleza, no por CVE)** | No pudimos identificar producto/versión, así que **no clasificamos por CVE**. Pero un puerto alto no estándar que se anuncia como "maintenance shell" es por sí mismo sospechoso: puerto 31337 ("eleet") es un clásico de backdoor. Merece investigación en la fase de enumeración. |

**Evidencia de respaldo** (crudo en `evidencia/`):

```
# nmap -Pn -p- phantomcorp   → evidencia/nmap.txt
21/tcp    open  ftp
80/tcp    open  http
8080/tcp  open  http-proxy
31337/tcp open  Elite

# nmap -Pn -sV -p21,80,8080,31337 phantomcorp
21/tcp    open  ftp     ProFTPD 1.3.5
80/tcp    open  http    PhantomServer/2.4.1
8080/tcp  open  http    Werkzeug httpd 2.0.1 (Python 3.9.2)
31337/tcp open  Elite?
```

```
# curl -I phantomcorp   → evidencia/http.txt
Server: PhantomServer/2.4.1
X-Powered-By: PhantomCMS 2.4.1
X-Backend-Flag: FLAG{http_headers_leak_info}
```

---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**
El escaneo por defecto de nmap sondea solo los ~1000 puertos más comunes, y el
servicio del **31337** cae muy por encima de ese rango. Recién con `nmap -Pn -p-`
(los 65535 puertos) apareció — y ahí estaba una de las flags. Regla operativa
que nos llevamos: **nunca cerrar el recon con el escaneo default.** Lo grave
suele esconderse en puertos altos no estándar que alguien levantó "un ratito".
Un `-p-` es más lento, pero es la diferencia entre ver el perímetro completo o
solo la parte prolija.

**P2 — El servicio dev en producción (8080).**
La evidencia concreta: la versión se identifica como `0.9.3-**DEV**`, el banner
de nmap es `Werkzeug httpd 2.0.1`, el propio root responde `phantom-dev-api` y,
sobre todo, `/status` devuelve `{"debug":true, ...}`. Werkzeug es el servidor de
desarrollo de Flask: no está pensado para exposición pública. Es un problema
**aunque no haya un CVE con nombre** porque la mala configuración *es* la
vulnerabilidad: `debug:true` activa el debugger interactivo (que puede derivar en
ejecución de código), el endpoint de estado filtra información interna, y una
versión `-DEV` no recibe el hardening de un release. El atacante no necesita un
exploit público: le alcanza con la configuración que el defensor dejó puesta.

**P3 — La ironía de `robots.txt`.**
`robots.txt` se creó para lo contrario de la seguridad: es un acuerdo de
cortesía para que los buscadores (Google, etc.) **no indexen** ciertas rutas.
Pero no es un control de acceso: no bloquea nada, solo *pide* que no se mire. Para
un atacante es un regalo, porque el defensor **lista ahí justo las rutas que
quiere esconder**. En este lab, `Disallow: /panel-interno-9x2f` nos entregó
directamente la ruta del panel interno (que seguía accesible). El archivo pensado
para ocultar al buscador terminó siendo un mapa de rutas sensibles para el recon.

**P4 — Pasivo vs. activo.**
Todo lo que hicimos en este lab fue recon **activo**: cada `nmap`, cada `ncat` al
21/31337 y cada `curl` al 80/8080 **tocó** PhantomCorp y abrió conexiones TCP
contra sus servicios. Eso deja huella: todas esas acciones habrían quedado en los
**logs** de PhantomCorp (el FTP registra la conexión, el web server registra cada
GET, incluido el de `/robots.txt` y el del panel interno). Recon **pasivo** sería
lo contrario: `whois`, DNS público, certificados, buscadores — recolectar sin
tocar el objetivo, sin generar una sola línea de log del lado de la víctima. En
un engagement real se arranca pasivo justamente para no alertar antes de tiempo.

**P5 — Ahora somos el defensor.**
Dos hallazgos y su mitigación concreta para PhantomCorp:
1. **ProFTPD 1.3.5 en el 21 (CVE-2015-3306).** Medida: **actualizar ProFTPD** a
   una versión parcheada (≥ 1.3.5a) o, si el FTP no es necesario, darlo de baja;
   y como mínimo **deshabilitar `mod_copy`** en la config. Además, no exponer el
   21 al perímetro: ponerlo detrás de VPN o restringir por IP.
2. **phantom-dev-api en el 8080 con `debug:true`.** Medida: **sacar el servicio
   de desarrollo de producción** — no desplegar Werkzeug como server público,
   poner `debug=False`, eliminar o autenticar el endpoint `/status`, y no exponer
   el 8080 hacia afuera. El recordatorio del propio `robots.txt` ("migrar a VPN")
   aplica igual acá.

Bonus defensivo transversal: **dejar de filtrar versiones** en los headers
(`Server`, `X-Powered-By`) y quitar el `X-Backend-Flag`, para no entregarle el
stack al atacante en la primera consulta.

---

## 4. Bitácora de comandos

```bash
# desde la consola del atacante (make shell), target = phantomcorp

# 1. Descubrir: barrido completo (acá aparece el 31337)
nmap -Pn -p- phantomcorp

# 2. Identificar: versiones de los puertos abiertos
nmap -Pn -sV -p21,80,8080,31337 phantomcorp

# 3. R2 — banner grabbing del FTP
ncat -w3 phantomcorp 21 </dev/null

# 4. R1 — banner del servicio en el puerto alto
ncat -w3 phantomcorp 31337 </dev/null

# 5. R3 — fuga en headers HTTP
curl -sI phantomcorp

# 6. R4 — rutas que el server pide no mirar, y entrar
curl -s phantomcorp/robots.txt
curl -s phantomcorp/panel-interno-9x2f

# 7. R5 — servicio dev en 8080 y su endpoint de estado
curl -s phantomcorp:8080/
curl -s phantomcorp:8080/status

# 8. entregar
./ctf submit 05 R1 'FLAG{...}'   # ... R2..R5
./ctf status 05
```
