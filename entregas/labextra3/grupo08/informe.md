# Informe — Lab Extra 3 · Defendé PhantomCorp (hardening)

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 12/11/2026

> **Estado:** Parte 1 de 2 — **exposición de información y superficie** (D1, D2, D3, P2, P3).
> Parte 2 (pendiente): D4 (SQLi), D5 (path traversal), P1, P4, P5, verificador 5/5 y conclusión.

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en los parches D1–D3 del `server.py`, en la captura de evidencia y en la redacción de las secciones 1–4 (P2, P3). | `objetivo/server.py` (D1–D3), secciones 1–4. | **Todas las salidas pegadas son ejecuciones reales** guardadas en `evidencia/salidas/` (el server y el verificador corren en la imagen `cyberlab-attacker`). Las 3 flags se validaron con `./ctf submit extra3 D1/D2/D3` → progreso **3/5** (§3). El grupo revisó el diff línea por línea y puede explicar cada cambio. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## Cómo se corrió

La app y el verificador se ejecutan **dentro de la imagen Linux del curso** (`cyberlab-attacker`, Python 3.13.5), no en Windows nativo, por dos motivos que encontramos en el camino:

1. El ataque D5 busca `/etc/passwd`. En Windows ese archivo no existe, así que el verificador marcaría D5 como "bloqueado" **aunque el código siga vulnerable**.
2. El verificador espera solo 1,2 s a que levante el server. En la primera corrida, desde el volumen montado de Windows, el arranque tardó más y **todas** las peticiones dieron `Connection refused`. El verificador lo contó como 4/5 bloqueados: un verde falso. Descartamos esa corrida y ahora copiamos los archivos al filesystem del contenedor antes de ejecutar (`evidencia/scripts/run.sh`).

> Lección colateral, que retomamos en el *research*: un "ataque que no funcionó" no es lo mismo que una "defensa que funciona". El verificador no distingue *bloqueado* de *caído*.

Diff completo de la parte 1: [`evidencia/salidas/10-diff-D1-D3.patch`](evidencia/salidas/10-diff-D1-D3.patch).

---

## 1. Tabla de defensas (antes → después)

| Defensa | Ataque que funcionaba | Fix aplicado (resumen + diff) | Verificación (salida del ataque bloqueado) |
|---|---|---|---|
| **D1** | `curl -si /` → `Server: PhantomServer/2.4.1-debug ` en **todas** las respuestas, incluidos el 404 y el 501 de `HEAD` (`01-D1-antes.txt`). | `VERSION = "webserver"` y override de `version_string()` para que devuelva siempre ese valor fijo. Cubre también las páginas de error que arma `BaseHTTPRequestHandler`. | `Server: webserver` en 200, 404 y 501 (`11-D1-despues.txt`). Verificador: `✓ D1 (header Server: 'webserver')`. |
| **D2** | `GET /api/status` → 200 `{"debug": true, "env": "produccion", "db": "/tmp/phantom_hardening.db", "pid": 19}` (`02-D2-antes.txt`). | Se **eliminó** la rama `/api/status`. No se dejó una versión "con menos datos": la ruta cae en el 404 genérico. | `GET /api/status` → `404 - no existe`, **byte a byte igual** a una ruta que nunca existió (`12-D2-despues.txt`). Verificador: `✓ D2 (-> 404)`. |
| **D3** | `robots.txt` → `Disallow: /backup` + `Disallow: /api/status`; `GET /backup` → 200 `dump_pre_migracion...` sin auth (`03-D3-antes.txt`). | (a) `robots.txt` ya no lista rutas sensibles. (b) **La ruta se protege**: HTTP Basic contra credenciales de operador por entorno (`PHANTOM_BACKUP_USER/PASS`), con `hmac.compare_digest`. Sin credenciales configuradas, el endpoint queda **apagado** (fail-closed → 404). | Sin credenciales: `/backup` → 404, robots limpio (`13-…`). Con credenciales configuradas: sin header → 401, pass incorrecta → 401, header malformado → 401, credenciales correctas → 200 (`14-…`). Verificador: `✓ D3 (-> 404; robots menciona /backup: False)`. |
| D4 | *(parte 2)* | | |
| D5 | *(parte 2)* | | |

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

## 2. Regresión funcional (parte 1)

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

Las tres funciones que exige la consigna siguen operando. `/login` y `/descargar` todavía no se tocaron (D4/D5 son de la parte 2): la regresión se vuelve a correr al final.

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

Faltan para la parte 2: verificador **5/5** y status 5/5.

## 4. Preguntas

### P1 — Antes/después completo

*(parte 2: se desarrolla sobre D5, con traversal, parche de confinamiento y variantes `%2e%2e%2f` / `....//`)*

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

*(parte 2)*

### P5 — Ranking de gravedad

*(parte 2)*

## 5. Conclusión

*(parte 2)*
