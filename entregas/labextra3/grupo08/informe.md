# Informe — Lab Extra 3 · Defendé PhantomCorp (hardening)

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 12/11/2026

> **Estado:** completo.
> Parte 1 — **exposición de información y superficie** (D1, D2, D3, P2, P3).
> Parte 2 — **inyección y acceso a archivos** (D4, D5, P1, P4, P5, verificador 5/5 y conclusión).

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en los parches D1–D3 del `server.py`, en la captura de evidencia y en la redacción de las secciones 1–4 (P2, P3). | `objetivo/server.py` (D1–D3), secciones 1–4. | **Todas las salidas pegadas son ejecuciones reales** guardadas en `evidencia/salidas/` (el server y el verificador corren en la imagen `cyberlab-attacker`). Las 3 flags se validaron con `./ctf submit extra3 D1/D2/D3` → progreso **3/5** (§3). El grupo revisó el diff línea por línea y puede explicar cada cambio. |
| Claude (Anthropic), vía Claude Code | Parte 2: parches D4–D5, batería de ataques antes/después (`ataques-parte2.sh`), demo de P4 (`p4_replace_demo.py`) y redacción de P1, P4, P5 y la conclusión. | `objetivo/server.py` (D4–D5), `evidencia/scripts/` (parte 2), secciones 1–5. | Igual que en la parte 1: **todas las salidas son ejecuciones reales** en `cyberlab-attacker` (`30-…` a `52-…`). La batería corre **las mismas variantes** contra el original y contra el parche, así la comparación es 1 a 1. Verificador final **5/5** y `./ctf status extra3` **5/5** (§3). |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## Cómo se corrió

La app y el verificador se ejecutan **dentro de la imagen Linux del curso** (`cyberlab-attacker`, Python 3.13.5), no en Windows nativo, por dos motivos que encontramos en el camino:

1. El ataque D5 busca `/etc/passwd`. En Windows ese archivo no existe, así que el verificador marcaría D5 como "bloqueado" **aunque el código siga vulnerable**.
2. El verificador espera solo 1,2 s a que levante el server. En la primera corrida, desde el volumen montado de Windows, el arranque tardó más y **todas** las peticiones dieron `Connection refused`. El verificador lo contó como 4/5 bloqueados: un verde falso. Descartamos esa corrida y ahora copiamos los archivos al filesystem del contenedor antes de ejecutar (`evidencia/scripts/run.sh`).

> Lección colateral, que retomamos en el *research*: un "ataque que no funcionó" no es lo mismo que una "defensa que funciona". El verificador no distingue *bloqueado* de *caído*.

Diff completo de la parte 1: [`evidencia/salidas/10-diff-D1-D3.patch`](evidencia/salidas/10-diff-D1-D3.patch).

**Parte 2.** El verificador prueba una sola variante por defensa, y en la oral se piden otras (`%2e%2e%2f`, `....//`...). Por eso escribimos [`evidencia/scripts/ataques-parte2.sh`](evidencia/scripts/ataques-parte2.sh): levanta el server que se le indique y corre **la misma batería** (5 inyecciones SQL más un usuario legítimo con comilla, y 11 variantes de traversal más una descarga legítima). La corrimos contra el original (`30-antes-*`) y contra el parche (`40-despues-*`). Diffs: [`41-diff-D4-D5.patch`](evidencia/salidas/41-diff-D4-D5.patch) (solo la parte 2, contra el commit de la parte 1) y [`44-diff-completo-vs-original.patch`](evidencia/salidas/44-diff-completo-vs-original.patch) (D1–D5 contra el original).

---

## 1. Tabla de defensas (antes → después)

| Defensa | Ataque que funcionaba | Fix aplicado (resumen + diff) | Verificación (salida del ataque bloqueado) |
|---|---|---|---|
| **D1** | `curl -si /` → `Server: PhantomServer/2.4.1-debug ` en **todas** las respuestas, incluidos el 404 y el 501 de `HEAD` (`01-D1-antes.txt`). | `VERSION = "webserver"` y override de `version_string()` para que devuelva siempre ese valor fijo. Cubre también las páginas de error que arma `BaseHTTPRequestHandler`. | `Server: webserver` en 200, 404 y 501 (`11-D1-despues.txt`). Verificador: `✓ D1 (header Server: 'webserver')`. |
| **D2** | `GET /api/status` → 200 `{"debug": true, "env": "produccion", "db": "/tmp/phantom_hardening.db", "pid": 19}` (`02-D2-antes.txt`). | Se **eliminó** la rama `/api/status`. No se dejó una versión "con menos datos": la ruta cae en el 404 genérico. | `GET /api/status` → `404 - no existe`, **byte a byte igual** a una ruta que nunca existió (`12-D2-despues.txt`). Verificador: `✓ D2 (-> 404)`. |
| **D3** | `robots.txt` → `Disallow: /backup` + `Disallow: /api/status`; `GET /backup` → 200 `dump_pre_migracion...` sin auth (`03-D3-antes.txt`). | (a) `robots.txt` ya no lista rutas sensibles. (b) **La ruta se protege**: HTTP Basic contra credenciales de operador por entorno (`PHANTOM_BACKUP_USER/PASS`), con `hmac.compare_digest`. Sin credenciales configuradas, el endpoint queda **apagado** (fail-closed → 404). | Sin credenciales: `/backup` → 404, robots limpio (`13-…`). Con credenciales configuradas: sin header → 401, pass incorrecta → 401, header malformado → 401, credenciales correctas → 200 (`14-…`). Verificador: `✓ D3 (-> 404; robots menciona /backup: False)`. |
| **D4** | `user=admin'--` → 200 `Bienvenido, admin'--`; `pass=' OR 1=1 --` → 200; también una tautología sin comentarios y `' UNION SELECT 'inyectado' --` → 200. Una comilla suelta (`user='`) o un usuario legítimo como `O'Brien` **tiran la conexión** (`curl: (52) Empty reply from server`): la entrada rompe la sintaxis SQL (`30-antes-D4.txt`). | Consulta **parametrizada**: `db.execute("… WHERE user = ? AND password = ?", (user, pwd))`. Se usa `closing()` para que la conexión siempre se cierre, y el saludo usa el valor que devolvió la base, escapado con `html.escape` (defensa en profundidad). | Las 5 inyecciones → 401 `Credenciales inválidas`. `'` y `O'Brien` → 401: ya no rompen nada (`40-despues-D4.txt`). Verificador: `✓ D4 (bypass admin'--: bloqueado; OR 1=1: bloqueado)`. |
| **D5** | `archivo=../../../../etc/passwd` → 200 con `root:x:0:0…`. También funciona con `%2e%2e%2f` y con `..%2f`, por un directorio hermano (`../phantom_descargas_secreto/clave.txt`), por un symlink plantado en la carpeta, contra **la base de datos** (`../phantom_hardening.db` → `admin` y `sup3r-s3cr3t0` en claro) y contra **`/etc/shadow`**, porque el proceso corre como root (`30-antes-D5.txt`). | **Confinamiento por ruta canónica** (`_ruta_confinada`): `realpath(join(raiz, nombre))`, después `commonpath([raiz, ruta]) == raiz` y por último `isfile`. Cualquier rechazo devuelve el mismo 404 que un archivo inexistente. | Las 11 variantes de traversal → 404 `no encontrado`; `manual.txt` → 200 (`40-despues-D5.txt`). Verificador: `✓ D5 (traversal /etc/passwd -> 404 (bloqueado))`. |

### Detalle de los parches

**D1 — banner.** Antes de parchar miramos cómo arma el header la stdlib: `BaseHTTPRequestHandler.version_string()` devuelve `server_version + ' ' + sys_version`. Por eso el original mandaba `PhantomServer/2.4.1-debug ` con un espacio colgando, y por eso alcanza con sobrescribir ese método. Así nos aseguramos de que **ningún** camino de código (ni `send_error`, ni el 501 por método no soportado) emita otro valor. Que no aparezca `Python/3.x` es mérito de `sys_version = ""`, que ya estaba y se mantiene.

```diff
-VERSION = "PhantomServer/2.4.1-debug"   # D1: banner que canta todo
+VERSION = "webserver"
 ...
+    def version_string(self):
+        return VERSION
```

**D2 — endpoint de debug.** Un endpoint de diagnóstico que confirma `debug: true` en producción, la ruta absoluta de la base de datos y el PID no se "achica": se saca. Si la operación necesitara un healthcheck, sería otro endpoint, con otro nombre, que solo responda `{"status":"ok"}` y preferentemente atado a la red de gestión. Que el 404 sea idéntico al de cualquier ruta inexistente importa: un 403 le confirmaría al atacante que "ahí hay algo".

```diff
-        elif path == "/api/status":
-            # D2: endpoint de debug en producción
-            self._json(200, '{"debug": true, "env": "produccion", '
-                            '"db": "' + DB + '", "pid": ' + str(os.getpid()) + '}')
```

**D3 — rutas sensibles.** Dos cambios independientes, y solo el segundo es el control de acceso (ver P2):

```diff
-            self._txt(200, "User-agent: *\nDisallow: /backup\nDisallow: /api/status\n")
+            self._txt(200, "User-agent: *\nDisallow:\n")
         elif path == "/backup":
-            self._txt(200, "dump_pre_migracion: usuarios=1 OK — BORRAR ESTE ENDPOINT")
+            if not (BACKUP_USER and BACKUP_PASS):
+                self._txt(404, "404 - no existe")                     # fail-closed
+            elif not self._backup_autorizado():
+                self._send(401, b"401 - autenticacion requerida", ...,
+                           {"WWW-Authenticate": 'Basic realm="phantom-ops"'})
+            else:
+                self._txt(200, "dump_pre_migracion: usuarios=1 OK")
```

Decisiones de diseño:

- **Credenciales fuera del código.** Si estuvieran hardcodeadas, cualquiera con acceso al repo (o a un leak del repo) tendría el backup.
- **Fail-closed.** El despliegue por defecto (sin variables) deja el endpoint **inexistente**. Para habilitarlo hay que hacerlo explícitamente. Lo contrario (abierto si falta configuración) es exactamente el error original.
- **`hmac.compare_digest`** en vez de `==`, para no filtrar por tiempo de respuesta cuántos caracteres coinciden.
- **Base64 estricto** (`validate=True`) y manejo de `binascii.Error`/`UnicodeDecodeError`: un header basura da 401, no un 500 con traceback (que sería otro info leak). Verificado en `14-D3-despues-con-auth.txt`, caso "header malformado".
- **Limitación declarada:** HTTP Basic manda las credenciales en Base64, no cifradas. En producción, este endpoint solo es aceptable detrás de TLS, y mejor todavía si no está expuesto a Internet (ver P2, defensa en profundidad). Lo más sano a mediano plazo es que el dump **no lo sirva la app web**: el propio texto original decía "BORRAR ESTE ENDPOINT".

**D4 — SQLi.** El problema de fondo es que el original **arma el código SQL pegando strings con datos del usuario**: para el motor, el input del atacante y la consulta del programador son el mismo texto. El parche separa los dos canales. La sentencia viaja con placeholders `?`, y `user`/`pwd` viajan aparte como valores ligados (*binding*). El motor nunca los parsea como SQL, así que una comilla es solo un carácter más del dato.

```diff
-            db = sqlite3.connect(DB)
-            cur = db.execute(
-                "SELECT user FROM usuarios WHERE user = '" + user
-                + "' AND password = '" + pwd + "'")     # ¡NUNCA así!
-            if cur.fetchone():
-                self._html(200, "<h1>Bienvenido, " + user + "</h1>")
+            with closing(sqlite3.connect(DB)) as db:
+                fila = db.execute(
+                    "SELECT user FROM usuarios WHERE user = ? AND password = ?",
+                    (user, pwd)).fetchone()
+            if fila:
+                self._html(200, "<h1>Bienvenido, " + html.escape(fila[0]) + "</h1>")
```

Decisiones de diseño:

- **La parametrización es el fix completo.** No se agregó ningún filtro de comillas: no hace falta, y filtrar rompe datos legítimos (ver P4).
- **`closing()`.** El `with` de `sqlite3.Connection` solo hace commit o rollback de la transacción; **no** cierra la conexión. En el original, si el `execute` fallaba, `db.close()` nunca se ejecutaba.
- **El saludo ya no refleja el input crudo.** El original devolvía `Bienvenido, ' UNION SELECT …` tal cual en el HTML. Con la consulta parametrizada a esa rama solo se llega con credenciales válidas, pero igual usamos el valor que devolvió la base y lo escapamos. No reflejar input sin escapar es una regla, no algo que se decide caso por caso.
- **Riesgo residual declarado:** las contraseñas siguen guardadas en **texto plano** en la tabla. La consigna no lo pide, pero es deuda real: lo vimos en el Lab 03 (hash con sal y función de derivación lenta). Mientras D5 estuvo abierto, esto fue lo que convirtió un traversal en robo de credenciales (ver P5).

**D5 — path traversal.** El original concatenaba `DESCARGAS + "/" + nombre` y abría lo que saliera. El parche **no mira el texto** del pedido (si tiene `..`, si está codificado...). Mira **adónde apunta la ruta una vez resuelta**:

```python
raiz = os.path.realpath(DESCARGAS)
try:
    ruta = os.path.realpath(os.path.join(raiz, nombre))   # resuelve "..", "." y symlinks
except ValueError:                                         # byte nulo
    return None
if os.path.commonpath([raiz, ruta]) != raiz:               # ¿quedó DENTRO de la raíz?
    return None
if not os.path.isfile(ruta):                               # solo archivos regulares
    return None
return ruta
```

Decisiones de diseño:

- **Validar el destino, no la forma.** Hay infinitas maneras de escribir "subí un directorio" (`../`, `%2e%2e%2f`, `..%2f`, symlinks...). Hay una sola ruta canónica. Un filtro de strings pelea contra la lista infinita; el confinamiento verifica la única condición que importa.
- **`commonpath` y no `startswith`.** `"/tmp/phantom_descargas_secreto/clave.txt".startswith("/tmp/phantom_descargas")` es `True`. `commonpath` compara **por componentes de ruta**, no por caracteres. Lo probamos con un directorio hermano real (`30-antes-D5.txt` vs. `40-despues-D5.txt`).
- **La trampa de `os.path.join`.** `os.path.join("/raiz", "/etc/passwd")` devuelve `/etc/passwd`: un componente absoluto descarta todo lo anterior. El original, por concatenar, **no** era vulnerable a rutas absolutas (`/tmp/phantom_descargas//etc/passwd` no existe). Un "fix" que solo migrara a `join` sin el chequeo de contención habría **abierto un agujero nuevo**. `commonpath` lo cierra.
- **`realpath` resuelve symlinks antes de validar.** Así, un enlace plantado dentro de la carpeta pública que apunte afuera no sirve.
- **Mismo 404 para todo rechazo.** Distinguir "prohibido" de "no existe" le confirmaría al atacante qué archivos hay fuera de la raíz.
- **`except OSError` en vez de `except Exception`.** Solo se capturan los errores de E/S esperables; un bug de otro tipo no queda tapado.
- **Riesgo residual declarado:** (a) entre el `isfile` y el `open` hay una ventana de carrera (TOCTOU). Explotarla requiere poder escribir en la carpeta de descargas, que en este diseño solo controla la app. Con la stdlib se achica abriendo con `os.open(..., os.O_NOFOLLOW)` relativo a un descriptor de la raíz (`dir_fd`). El cierre completo es la syscall de Linux `openat2(RESOLVE_BENEATH)`, que Python no expone sin `ctypes`. (b) **El proceso corre como root.** El parche cierra este bug, pero el próximo traversal volvería a leer `/etc/shadow`. Correr como un usuario sin privilegios es la capa que limita el daño de los bugs que todavía no encontramos.

## 2. Regresión funcional

### Final (D1–D5 aplicados)

Contra la copia parchada completa (`42-regresion-final.txt`, headers `Date`/`Content-Type` omitidos acá):

```console
## GET /
HTTP/1.0 200 OK
Server: webserver
<h1>PhantomCorp</h1><p>Portal de empleados.</p>
## login legitimo            (curl -sSi "$U/login?user=admin&pass=sup3r-s3cr3t0")
HTTP/1.0 200 OK
<h1>Bienvenido, admin</h1>
## login incorrecto
HTTP/1.0 401 Unauthorized
<h1>Credenciales inválidas</h1>
## descarga legitima         (curl -sSi "$U/descargar?archivo=manual.txt")
HTTP/1.0 200 OK
Manual de la intranet PhantomCorp.
## descarga inexistente
HTTP/1.0 404 Not Found
no encontrado
## ruta inexistente
HTTP/1.0 404 Not Found
404 - no existe
```

Las tres funciones que exige la consigna siguen operando con D4 y D5 aplicados. Además, el parche **mejoró** la funcionalidad: en el original, un usuario legítimo con comilla (`O'Brien`) tiraba la conexión; ahora recibe un 401 normal (`30-antes-D4.txt` vs. `40-despues-D4.txt`).

### Parte 1 (D1–D3 aplicados)

Contra la copia parchada (`15-regresion-parte1.txt`):

```console
## GET /
HTTP/1.0 200 OK
Server: webserver
<h1>PhantomCorp</h1><p>Portal de empleados.</p>
## login legitimo            (curl -si "$U/login?user=admin&pass=sup3r-s3cr3t0")
HTTP/1.0 200 OK
<h1>Bienvenido, admin</h1>
## login incorrecto
HTTP/1.0 401 Unauthorized
<h1>Credenciales inválidas</h1>
## descarga legitima         (curl -si "$U/descargar?archivo=manual.txt")
HTTP/1.0 200 OK
Manual de la intranet PhantomCorp.
```

En ese momento `/login` y `/descargar` todavía no se habían tocado: por eso la regresión se volvió a correr al final (arriba).

## 3. Evidencia de progreso

**Verificador inicial: 0/5** (`00-verificador-inicial.txt`, contra el objetivo roto):

```text
  ✗ D1 — todavía vulnerable  (header Server: 'PhantomServer/2.4.1-debug ')
  ✗ D2 — todavía vulnerable  (GET /api/status -> 200 '{"debug": true, "env": "produccion", "db": "/tmp/phantom_har')
  ✗ D3 — todavía vulnerable  (GET /backup -> 200; robots menciona /backup: True)
  ✗ D4 — todavía vulnerable  (bypass admin'--: FUNCIONA (vulnerable); OR 1=1: FUNCIONA (vulnerable))
  ✗ D5 — todavía vulnerable  (traversal /etc/passwd -> 200 (FILTRADO (vulnerable)))

0/5 defensas correctas.
```

**Verificador después de la parte 1: 3/5** (`20-verificador-parte1.txt`). Los códigos HTTP son reales (404), no `-> 0`: el server estaba levantado y respondiendo.

```text
  ✓ D1 — ataque BLOQUEADO  (header Server: 'webserver')
      flag: FLAG{def_banner_neutralizado}
  ✓ D2 — ataque BLOQUEADO  (GET /api/status -> 404 '404 - no existe')
      flag: FLAG{def_debug_apagado}
  ✓ D3 — ataque BLOQUEADO  (GET /backup -> 404; robots menciona /backup: False)
      flag: FLAG{def_rutas_blindadas}
  ✗ D4 — todavía vulnerable  (bypass admin'--: FUNCIONA (vulnerable); OR 1=1: FUNCIONA (vulnerable))
  ✗ D5 — todavía vulnerable  (traversal /etc/passwd -> 200 (FILTRADO (vulnerable)))

3/5 defensas correctas.
```

**`./ctf status extra3`** (`22-ctf-status-parte1.txt`):

```text
   ✓  D1     Banner neutralizado (info leak de version)
   ✓  D2     Endpoint de debug apagado en produccion
   ✓  D3     Rutas sensibles blindadas (backup + robots)
   ·  D4     Login parametrizado (SQLi bloqueado)
   ·  D5     Path traversal bloqueado en /descargar

  ██████████████████░░░░░░░░░░░░  3/5 (60%)
```

**Verificador final: 5/5** (`50-verificador-final.txt`, contra la copia con D1–D5):

```text
  ✓ D1 — ataque BLOQUEADO  (header Server: 'webserver')
      flag: FLAG{def_banner_neutralizado}
  ✓ D2 — ataque BLOQUEADO  (GET /api/status -> 404 '404 - no existe')
      flag: FLAG{def_debug_apagado}
  ✓ D3 — ataque BLOQUEADO  (GET /backup -> 404; robots menciona /backup: False)
      flag: FLAG{def_rutas_blindadas}
  ✓ D4 — ataque BLOQUEADO  (bypass admin'--: bloqueado; OR 1=1: bloqueado)
      flag: FLAG{def_sqli_parametrizado}
  ✓ D5 — ataque BLOQUEADO  (traversal /etc/passwd -> 404 (bloqueado))
      flag: FLAG{def_traversal_bloqueado}

5/5 defensas correctas.
Objetivo endurecido. Entregá las 5 flags y escribí el informe.
```

Igual que en la parte 1, los códigos son reales (404), no `-> 0`: el verde no es un server caído. Además, la batería propia (`40-despues-*`) prueba 16 variantes de ataque, contra las 2 de D4 y la única de D5 que prueba el verificador.

**`./ctf status extra3` final** (`52-ctf-status-final.txt`). El progreso de `./ctf` se guarda por checkout, en `.progreso/` (ignorado por git), y la parte 1 se registró en la máquina de otro integrante. Por eso, en la máquina de la parte 2 se registraron las 5 flags que entregó el verificador final (`51-ctf-submit-D1-D5.txt`):

```text
   ✓  D1     Banner neutralizado (info leak de version)
   ✓  D2     Endpoint de debug apagado en produccion
   ✓  D3     Rutas sensibles blindadas (backup + robots)
   ✓  D4     Login parametrizado (SQLi bloqueado)
   ✓  D5     Path traversal bloqueado en /descargar

  ██████████████████████████████  5/5 (100%)
```

## 4. Preguntas

### P1 — Antes/después completo

Elegimos **D5 (path traversal)**: es la defensa más fácil de hacer *mal*, y la que más variantes admite en la oral.

**1. El ataque que funcionaba** (`30-antes-D5.txt`, objetivo original):

```console
$ curl -sSi "$U/descargar?archivo=../../../../etc/passwd"
HTTP/1.0 200 OK
Server: PhantomServer/2.4.1-debug
Content-Type: text/plain; charset=utf-8

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

**2. El parche** (`41-diff-D4-D5.patch`, extracto; la función `_ruta_confinada` completa está en §1):

```diff
-            ruta = DESCARGAS + "/" + nombre
-            try:
-                with open(ruta, "rb") as fh:
-                    self._txt(200, fh.read(8192).decode("utf-8", "ignore"))
-            except Exception:
+            ruta = self._ruta_confinada(nombre)
+            if ruta is None:
                 self._txt(404, "no encontrado")
+            else:
+                try:
+                    with open(ruta, "rb") as fh:
+                        self._txt(200, fh.read(8192).decode("utf-8", "ignore"))
+                except OSError:
+                    self._txt(404, "no encontrado")
```

**3. El mismo ataque, bloqueado** (`40-despues-D5.txt`, copia parchada):

```console
$ curl -sSi "$U/descargar?archivo=../../../../etc/passwd"
HTTP/1.0 404 Not Found
Server: webserver
Content-Type: text/plain; charset=utf-8

no encontrado
```

**4. Las variantes** (misma batería contra los dos servers, `30-antes-D5.txt` vs. `40-despues-D5.txt`):

| Variante (`?archivo=`) | Original | Parche | Por qué |
|---|---|---|---|
| `../../../../etc/passwd` | **200** `root:x:0:0…` | 404 | `realpath` da `/etc/passwd`, que queda fuera de la raíz. |
| `%2e%2e%2f%2e%2e%2f…etc%2fpasswd` | **200** | 404 | `parse_qs` ya decodificó: el parche valida **después** de decodificar, así que es el mismo caso que el anterior. |
| `..%2f..%2f..%2f..%2fetc%2fpasswd` | **200** | 404 | Ídem. |
| `%252e%252e%252f…` (doble encoding) | 404 | 404 | Se decodifica una sola vez y queda el nombre literal `%2e%2e%2f…`, que no existe. Solo sería peligroso si algún componente decodificara dos veces. |
| `....//....//....//....//etc/passwd` | 404 | 404 | El original no normaliza nada, así que `....` es un directorio inexistente. Esta variante ataca a los **filtros**: `replace("../", "")` convierte `....//` en `../`. Por eso no filtramos. |
| `/etc/passwd` | 404 | 404 | La concatenación daba `/tmp/phantom_descargas//etc/passwd`. Pero `os.path.join` con un componente absoluto descarta la raíz: sin `commonpath`, migrar a `join` **habría abierto** este caso. |
| `../../../../etc/passwd%00.txt` | 404 | 404 | En Python 3.13, `realpath` lanza `ValueError` ante un byte nulo, y el parche lo captura. Aunque otra versión no lo lanzara, `isfile` devuelve `False` para esa ruta: el resultado sigue siendo 404. |
| `../phantom_descargas_secreto/clave.txt` | **200** `clave-interna-no-publica` | 404 | Comparte prefijo con la raíz: un chequeo con `startswith` lo dejaría pasar. `commonpath` compara por componentes. |
| `enlace.txt` (symlink → `/etc/passwd`) | **200** `root:x:0:0…` | 404 | `realpath` resuelve el enlace antes de validar. |
| `../phantom_hardening.db` | **200** con `admin` + `sup3r-s3cr3t0` | 404 | Fuera de la raíz (ver P5: la cadena D2 → D5). |
| `../../../../etc/shadow` | **200** `root:*:20753…` | 404 | Fuera de la raíz. Que se haya podido leer revela otro problema: el proceso corre como root. |
| `manual.txt` (legítimo) | 200 | **200** | Está dentro de la raíz y es un archivo regular. |

La conclusión de la tabla: **ninguna variante necesitó un caso especial en el código**. El parche no conoce `%2e`, ni `....//`, ni los symlinks: solo pregunta si la ruta resuelta queda dentro de la carpeta. Esa es la diferencia entre un fix estructural y una lista de excepciones.

### P2 — D3: sacar la ruta del `robots.txt` vs. proteger la ruta

Son dos cosas de naturaleza distinta, y solo una es un control de seguridad.

**Sacarla del `robots.txt` reduce información, pero no controla el acceso.** `robots.txt` es un pedido de cortesía para crawlers que deciden respetarlo. No tiene ningún poder de *enforcement*: el servidor sigue respondiendo a quien pida la ruta. Si solo hubiéramos limpiado el robots, `curl /backup` seguiría devolviendo 200 con el dump. La ruta seguiría expuesta a cualquiera que la encuentre por otro camino: fuzzing de directorios con un diccionario (`backup` está en todos), un link viejo, el historial de Git, un buscador que la indexó antes, logs de un proxy, un ex empleado. El verificador lo sabe y por eso exige las **dos** condiciones.

Además, en el original el robots era peor que inútil: era un **mapa para el atacante**. Las rutas que alguien quiere esconder son, casi por definición, las interesantes, y es lo primero que lee cualquiera que hace recon (lo hicimos en el Lab 05). Sacar `/backup` de ahí está bien, pero como higiene: no es la defensa.

**Proteger la ruta es la defensa real**, porque cambia lo que el servidor *hace*, no lo que *dice*. Con el parche, que el atacante conozca la URL no le sirve de nada: sin credenciales, la respuesta es 404 (endpoint apagado) o 401 (endpoint habilitado sin autorización). La prueba es que el control **resiste aunque el atacante sepa exactamente dónde está**, y ese es el criterio: un control que se cae en cuanto se conoce un dato público no es un control.

Las dos medidas juntas son **defensa en profundidad**: el robots limpio deja de regalar el mapa (capa de información) y la autenticación decide quién entra (capa de control). En un despliegue real sumaríamos más capas: el dump fuera del árbol web, el endpoint escuchando solo en la red de administración, TLS obligatorio y logging de cada acceso al backup.

### P3 — D1: ¿ocultar el banner es una defensa "real"? Seguridad por oscuridad

**No, no por sí sola, pero tampoco es inútil.** Lo que la vuelve buena o mala práctica es *qué rol le asignamos*.

**Seguridad por oscuridad** es hacer depender la seguridad de que el atacante no conozca un detalle del sistema. El principio de Kerckhoffs dice lo contrario: un sistema tiene que seguir siendo seguro aunque el adversario conozca todo salvo la clave. Con D1 pasa justo eso: si hubiera una vulnerabilidad en "PhantomServer 2.4.1", cambiar el header a `webserver` **no la arregla**. El servidor sigue siendo explotable y el atacante puede probar el exploit igual, a ciegas. También puede identificar el software por fingerprinting de comportamiento: el orden de los headers, el formato de los 404 y del 501 (`Unsupported method ('HEAD')` delata a `http.server` de Python aunque el banner diga otra cosa), timing, etc. Nuestra propia evidencia lo muestra: `11-D1-despues.txt` tiene un 501 cuyo texto revela la stdlib aunque el header ya no la nombre.

**Cuándo ayuda.** Como capa *adicional* sobre un sistema que ya está parcheado:

- **Sube el costo del recon y saca al sistema del radar de la automatización.** Mucho escaneo masivo (bots, gusanos, `nuclei` con templates por versión) filtra por banner: si no ve `2.4.1`, no dispara el exploit específico. No frena a un atacante dirigido, pero sí al ruido oportunista, que es la mayoría del tráfico hostil.
- **Achica la ventana entre CVE y parche.** El día que sale un CVE para tu versión, un banner que la anuncia te pone primero en la lista.
- En este caso además filtraba **`-debug`**: no solo producto y versión, también que el build es de desarrollo. Eso es información operativa que invita a buscar justamente cosas como D2.

**Cuándo engaña.** Cuando se la cuenta como *la* defensa. Si un equipo cierra el hallazgo "banner con versión vulnerable" cambiando el banner en vez de actualizar el software, se dio una falsa sensación de seguridad y además perdió visibilidad: ahora ni su propio escáner interno lo marca. La regla que adoptamos: **ocultar la versión es higiene que se hace *además* de parchar, nunca *en vez de* parchar**. En el informe de riesgo, D1 se reporta como severidad baja/informativa justamente por eso.

### P4 — Por qué `replace("'", "")` no alcanza y la parametrización sí

Para no discutirlo en abstracto, probamos el "fix" del compañero con [`evidencia/scripts/p4_replace_demo.py`](evidencia/scripts/p4_replace_demo.py): SQLite en memoria, la misma tabla y los mismos ataques (salida en `43-P4-replace-vs-parametrizada.txt`).

**Primero, la honestidad:** en *esta* consulta, con SQLite, sacar las comillas **sí** impide cerrar el literal. `admin'--` se convierte en `'admin--'` y no entra (caso 1 de la demo). El problema es que eso funciona por casualidad, no por diseño. Hay cuatro razones:

1. **Rompe datos legítimos.** `O'Brien` con contraseña `pa'ss` (credenciales correctas) pasa a ser `OBrien` / `pass` y **no puede entrar**. La consulta parametrizada lo deja entrar sin problema (caso 2). Un fix de seguridad que rechaza usuarios válidos es una regresión.
2. **No sirve en contexto numérico.** `WHERE id = ` + `"0 OR 1=1"` no necesita ninguna comilla: el filtro no toca nada y la consulta devuelve **todas** las filas (caso 3). La misma idea aplicada a otro endpoint deja la puerta abierta.
3. **Depende del lexer del motor.** En MySQL (modo por defecto) la barra invertida escapa comillas. Con `user=\` y `pass= OR 1=1 -- ` (sin una sola comilla, así que el filtro no hace nada) la consulta queda `WHERE user = '\' AND password = ' OR 1=1 -- '`. MySQL lee `\'` como una comilla escapada, el literal de `user` pasa a ser `' AND password = `, y `OR 1=1 -- ` queda **afuera, como código** (caso 4: no se ejecuta porque SQLite no trata `\` como escape, y la demo lo aclara). Un filtro que es seguro o no según el motor de base de datos no es un control: es suerte.
4. **Es una lista negra sobre la representación, no una separación de canales.** Hay que acordarse de aplicarlo en cada consulta y en cada parámetro, y además adivinar todos los caracteres especiales de cada contexto (strings, números, `LIKE`, nombres de columna...).

**Por qué la parametrización sí es estructural.** La causa raíz de la inyección es **mezclar código y datos en un mismo string** que después parsea el motor. Con `?`, la sentencia se compila **antes** y con forma fija, y los valores llegan por un canal separado (*binding*). El motor nunca los interpreta como SQL, sin importar qué caracteres traigan. No hay nada que escapar porque no hay nada que parsear. El caso 5 de la demo lo muestra: las tres cargas maliciosas (incluida la de MySQL) devuelven `[]`, y el login legítimo devuelve `[('admin',)]`.

En una frase: `replace` intenta que el dato **no parezca** código; la parametrización hace que el dato **no pueda** ser código.

### P5 — Ranking de gravedad

Criterio: los cinco problemas son explotables **sin autenticación, de forma remota y con un solo pedido HTTP**. La facilidad de explotación empata, así que los diferencia el **impacto** (qué obtiene el atacante) y el **alcance** (cuánto más allá de la app llega).

| # | Defensa | Impacto demostrado | Severidad |
|---|---|---|---|
| 1 | **D5 — Path traversal** | Lectura de **cualquier archivo** que pueda leer el proceso (los primeros 8 KB de cada uno, por el `read(8192)`), y el proceso es root: `/etc/passwd`, **`/etc/shadow`**, código y configuración, y **la base completa con la contraseña del admin en claro** (`30-antes-D5.txt`). | Crítica |
| 2 | **D4 — SQLi en `/login`** | Entrar como **cualquier usuario** sin contraseña (`admin'--`). Por *blind* SQLi (200 vs. 401) se puede extraer la base carácter por carácter. | Crítica |
| 3 | **D3 — `/backup` sin auth** | Descarga del dump pre-migración. En el lab es un texto de prueba, pero en la vida real un backup es la base entera. | Alta |
| 4 | **D2 — `/api/status`** | Expone `debug:true`, el PID y **la ruta absoluta de la base**: no es grave por sí solo, pero **habilita la cadena** con D5. | Media |
| 5 | **D1 — Banner** | Producto, versión y build `-debug`. Facilita el recon (ver P3). | Baja / informativa |

**Justificación del #1, como para gerencia:**

> Cualquier persona en Internet, sin usuario ni contraseña y con un solo pedido desde el navegador, podía descargar **cualquier archivo del servidor**. Lo comprobamos: obtuvimos la contraseña del administrador del portal, el archivo de contraseñas del sistema operativo y la base de datos completa. No hace falta ninguna herramienta especial, y el ataque no deja rastro: el servidor no registra los pedidos que recibe (`log_message` está anulado), así que ni siquiera sabríamos si ya ocurrió. Esto expone a la vez los datos de la empresa, las credenciales de sus usuarios (que suelen reutilizarse en otros sistemas) y la información para tomar el control del servidor. Lo ubicamos por encima de la falla de login (#2) porque **la incluye**: leyendo la base con D5, el atacante obtiene la contraseña real del administrador y entra de forma "legítima", y además accede a todo lo que está fuera de la aplicación. Recomendación: parche inmediato (ya aplicado y verificado). Como medidas complementarias: que el servicio deje de correr como administrador del sistema, para limitar el daño de futuras fallas; que se registren los accesos, para poder detectar y investigar un abuso; y que se cambie la contraseña del administrador, porque hay que asumirla comprometida mientras no haya registros que prueben lo contrario.

Dos aclaraciones para no sobrevender el ranking:

- **D4 vs. D5 depende de la app.** Si el usuario admin tuviera funciones de escritura (altas, pagos, cambios de configuración), D4 sumaría impacto en **integridad** y podría subir al #1. En esta app el login solo saluda, así que el daño concreto de D4 es confidencialidad de la base, algo que D5 ya cubre.
- **El orden individual subestima las cadenas.** D2 parece "media", pero es lo que le dice al atacante **dónde** está la base (`/tmp/phantom_hardening.db`), y D5 es lo que le permite **leerla**. Juntas, más las contraseñas en texto plano (riesgo residual de D4), son robo de credenciales en dos pedidos. En un informe real, la cadena se reporta como un hallazgo propio.

## 5. Conclusión

Fue más difícil **arreglarla** que romperla. En los labs 05–07, a cada hallazgo le alcanzaba **una** variante que funcionara. Acá, para D4 y D5 el verificador prueba solo tres cargas, y en la oral se puede pedir cualquier otra, así que tuvimos que razonar sobre **todas** las formas de escribir el mismo ataque: 16 variantes, varias de ellas trampas para fixes mal hechos (`....//` contra un `replace`, el directorio hermano contra un `startswith`, la ruta absoluta contra un `os.path.join` ingenuo). El fix correcto resultó ser **más corto** que cualquier lista de filtros, pero llegar a él exigió entender la causa raíz (datos mezclados con código en D4, validar la forma en vez del destino en D5) en lugar del síntoma. Además, defender tiene restricciones que atacar no tiene: el parche no puede romper `O'Brien` ni la descarga legítima, y la evidencia tiene que ser honesta. Lo aprendimos cuando el verificador nos dio un 4/5 contra un server que ni siquiera había arrancado. El atacante demuestra con **una** captura; el defensor tiene que demostrar que **ninguna** variante funciona, que la app sigue andando, y explicar por qué. Y aun así quedan deudas que el verificador no mide: el proceso corre como root, las contraseñas están en texto plano y el server no registra los accesos.
