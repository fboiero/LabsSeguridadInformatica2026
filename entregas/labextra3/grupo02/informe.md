# Informe — Lab Extra 3: Defendé PhantomCorp

**Grupo:** 02

**Integrantes:**

- Romero Jimena Soledad (legajo 15377) — @Jimena-Romero
- Milanesio Hebe Del Lourdes (legajo 15343) — @hebemilanesio1
- Toranzo Juan Cruz (legajo 15308) — @JuanToranzo
- Torres Damaris (legajo 14563) — @damaris412

## Declaración de uso de IA

- **Herramienta:** Claude (Anthropic), en la interfaz de chat.
- **Para qué la usamos:**
  - Generar la propuesta de parches para D1–D5 sobre `server.py`.
  - Resolver problemas de entorno (Python no instalado en Windows, error de codificación `cp1252`, WSL, saltos de línea CRLF en los scripts de `ctf`, configuración de identidad de Git).
  - Ayudar a redactar este informe.
- **Qué partes del entregable se originaron o modificaron con esa asistencia:**
  - El `server.py` parchado (`entregas/labextra3/grupo02/objetivo/server.py`).
  - Los comandos de evidencia (`comandos.txt`).
  - El borrador de este informe.
- **Cómo verificamos que era correcto:**
  - Corrimos `verificar-defensa.py` contra nuestra copia: 0/5 inicial y 5/5 final.
  - Hicimos una regresión funcional con `curl` (sección 2).
  - Enviamos las 5 flags con `./ctf submit` y `./ctf status extra3` marcó 5/5.
  - Releímos el diff contra el original (`evidencia/salidas/diff-server.txt`) para entender cada cambio.

> Nota de proceso: la primera corrida del verificador, en Windows nativo, dio un falso "4/5". El servidor no llegaba a levantar (`sqlite3.OperationalError: unable to open database file`, rutas `/tmp` de Linux) y el verificador contaba la falta de conexión como "ataque bloqueado". Descartamos esa salida, no usamos esas flags, y repetimos todo en WSL (Ubuntu), donde el estado inicial dio 0/5 real.

---

## 1. Tabla de defensas (antes → después)

Estado inicial: `evidencia/salidas/verificador-inicial-0de5.txt` (0/5). Estado final: `evidencia/salidas/verificador-final-5de5.txt` (5/5). Diff completo: `evidencia/salidas/diff-server.txt`.

| Defensa | Ataque que funcionaba | Fix aplicado | Verificación (ataque bloqueado) |
|---|---|---|---|
| **D1** | Header `Server: PhantomServer/2.4.1-debug` | Se eliminó la constante `VERSION`; `server_version = "web"` y se sobrescribió `version_string()` para devolver `"web"`. | `header Server: 'web'` |
| **D2** | `GET /api/status` → 200 con `debug:true`, ruta de la BD y PID | Se eliminó por completo el endpoint; la ruta cae en el 404 final. | `GET /api/status -> 404 '404 - no existe'` |
| **D3** | `robots.txt` listaba `/backup` y `GET /backup` → 200 sin autenticación | `/backup` exige `Authorization: Bearer <BACKUP_TOKEN>` (variable de entorno), comparado con `hmac.compare_digest`; si no hay token configurado queda cerrado. `robots.txt` ya no lista rutas. | `GET /backup -> 401; robots menciona /backup: False` |
| **D4** | `admin'--` y `OR 1=1` entraban sin contraseña | Consulta parametrizada: `WHERE user = ? AND password = ?` con la tupla `(user, pwd)`. | `bypass admin'--: bloqueado; OR 1=1: bloqueado` |
| **D5** | `/descargar?archivo=` leía `/etc/passwd` (path traversal) | `os.path.realpath` sobre la ruta pedida y verificación con `os.path.commonpath` de que queda dentro de `DESCARGAS`; además exige `os.path.isfile`. | `traversal /etc/passwd -> 404 (bloqueado)` |

Cambios adicionales no pedidos:

- Se agregó `html.escape(user)` al mensaje de bienvenida de `/login`, porque el original reflejaba el usuario en el HTML (XSS reflejado).
- Se quitaron imports sin uso (`base64`, `urlparse`).

Fragmento del diff de D4:

```diff
-            cur = db.execute(
-                "SELECT user FROM usuarios WHERE user = '" + user
-                + "' AND password = '" + pwd + "'")     # ¡NUNCA así!
+            cur = db.execute(
+                "SELECT user FROM usuarios WHERE user = ? AND password = ?",
+                (user, pwd))
```

## 2. Regresión funcional

Servidor parchado levantado con `PORT=8081 BACKUP_TOKEN=prueba123 python3 server.py`. Salida completa en `evidencia/salidas/regresion-funcional.txt`.

| Prueba | Resultado |
|---|---|
| `GET /` | `HTTP/1.0 200 OK`, `Server: web`, `<h1>PhantomCorp</h1><p>Portal de empleados.</p>` |
| Login legítimo `admin` / `sup3r-s3cr3t0` | `<h1>Bienvenido, admin</h1>` |
| `/descargar?archivo=manual.txt` | `Manual de la intranet PhantomCorp.` |
| `/backup` con `Authorization: Bearer prueba123` | `dump_pre_migracion: usuarios=1 OK` |
| `/descargar?archivo=%2e%2e%2f%2e%2e%2fetc/passwd` | `HTTP/1.0 404 Not Found`, `no encontrado` |

La app sigue funcionando. La única diferencia de comportamiento es intencional: `/backup` ahora requiere autorización.

## 3. Evidencia de progreso

- Verificador inicial: `evidencia/salidas/verificador-inicial-0de5.txt` → **0/5**, con `Server: 'PhantomServer/2.4.1-debug'` y respuestas HTTP 200 reales en D2, D3 y D5.
- Verificador final: `evidencia/salidas/verificador-final-5de5.txt` → **5/5**.
- `./ctf status extra3`: `evidencia/salidas/ctf-status.txt` → las cinco defensas con ✓ (5/5, 100%).
  - Los scripts de `ctf` venían con saltos de línea CRLF de Windows, así que lo corrimos desde una copia temporal convertida a LF, fuera del repo.
- Comandos ejecutados: `evidencia/comandos.txt`.

## 4. Preguntas P1–P5

### P1 — Antes/después de una defensa (D4, SQL injection)

**Antes** (verificador sobre la copia sin parchar):

```
✗ D4 — todavía vulnerable  (bypass admin'--: FUNCIONA (vulnerable); OR 1=1: FUNCIONA (vulnerable))
```

**Parche** (diff):

```diff
-            cur = db.execute(
-                "SELECT user FROM usuarios WHERE user = '" + user
-                + "' AND password = '" + pwd + "'")
+            cur = db.execute(
+                "SELECT user FROM usuarios WHERE user = ? AND password = ?",
+                (user, pwd))
```

**Después**:

```
✓ D4 — ataque BLOQUEADO  (bypass admin'--: bloqueado; OR 1=1: bloqueado)
```

**Por qué funcionaba el ataque:** con `user = admin'--` la consulta concatenada quedaba `... WHERE user = 'admin'--' AND password = ''`. El `--` comenta el resto, se elimina la condición de contraseña y la consulta devuelve la fila de `admin`.

**Por qué ya no funciona:** con `?` el motor recibe la consulta ya compilada y los valores aparte. `admin'--` se compara como un texto literal contra la columna `user`, no coincide con ningún usuario y el login falla. Mantuvimos además el login legítimo funcionando (sección 2).

### P2 — D3: sacar la ruta del robots.txt vs. proteger la ruta

- **Sacar la ruta del `robots.txt`** solo quita el "cartel": `robots.txt` es una convención para buscadores y no controla el acceso. Si `/backup` seguía respondiendo 200 sin autenticación, cualquiera que adivine, enumere o haya visto la ruta antes (diccionarios, fuzzing, logs) puede leerla. Quien enumera `/backup` con una wordlist la encuentra igual.
- **Proteger la ruta** (exigir autorización en el servidor) es la defensa real: aunque el atacante conozca la ruta, no puede usarla sin la credencial. Nuestro fix devuelve 401 sin token válido y deja el endpoint cerrado si no hay token configurado.
- Hicimos las dos cosas, pero solo la autorización es el control de seguridad. Quitar la ruta del robots es una reducción de información, no una barrera.
- Esto es un caso de **defense in depth**: la autorización es la capa que protege, y sacar la ruta del robots solo suma una capa menor de ocultamiento.

### P3 — D1: ¿ocultar información es una defensa "real"?

Por sí sola no: ocultar el banner no elimina ninguna vulnerabilidad, y eso es la esencia de la *seguridad por oscuridad*.

- **Cuándo ayuda:** como capa adicional, cuesta poco y quita información que facilita el reconocimiento. Un atacante que ve `PhantomServer/2.4.1-debug` sabe producto y versión, y puede buscar CVEs específicos o explotar que es una versión de debug. Sin ese dato tiene que averiguarlo con fingerprinting, que es más lento y más ruidoso para quien monitorea.
- **Cuándo engaña:** si se la toma como la defensa principal. Un servidor vulnerable con un banner genérico sigue siendo vulnerable, y se puede identificar por su comportamiento (formato de errores, orden de headers). Creer que "ya está protegido porque no dice la versión" es peor que no haberlo hecho.
- **Conclusión:** la seguridad no puede depender de que el atacante no sepa cómo funciona el sistema; D1 es útil como higiene, pero no reemplaza parchear (D2–D5).

### P4 — D4: por qué `user.replace("'", "")` no alcanza

- **Es un filtro de strings sobre un problema estructural.** El problema es mezclar datos con código SQL, y el filtro intenta adivinar qué caracteres son peligrosos.
- **Se puede esquivar.** Ejemplos:
  - Hay contextos donde no hace falta la comilla (valores numéricos, cláusulas `ORDER BY`, nombres de columna).
  - Se pueden usar otras codificaciones o caracteres equivalentes según el motor y el charset (por ejemplo el truco de la barra invertida o conversiones de caracteres).
  - Si el filtro se aplica en un solo punto y otro camino del código arma una consulta similar, queda sin cubrir.
- **Rompe datos legítimos.** Un usuario con apóstrofe en el nombre (`O'Brien`) no podría autenticarse.
- **La consulta parametrizada sí es la solución estructural**, porque separa en el protocolo el código (la consulta) de los datos (los valores). El motor nunca interpreta el valor como SQL, sin importar qué caracteres contenga, así que no depende de acordarse de todos los casos peligrosos.

### P5 — Ranking de gravedad

| # | Defensa | Justificación breve |
|---|---|---|
| 1 | **D4** — SQLi en `/login` | Permite saltear la autenticación sin conocer ninguna credencial. En una app real, además, abre la puerta a leer o modificar toda la base. |
| 2 | **D5** — Path traversal | Permite leer archivos arbitrarios del servidor (`/etc/passwd`, configuraciones, claves, código fuente). |
| 3 | **D3** — `/backup` sin autenticación | Expone un respaldo de datos de usuarios sin ningún control, y el `robots.txt` lo anunciaba. |
| 4 | **D2** — `/api/status` con debug | Filtra datos internos (ruta de la BD, PID, modo debug) que facilitan ataques posteriores, pero no da acceso directo. |
| 5 | **D1** — Banner con versión | Es solo información de reconocimiento. Ayuda al atacante a elegir exploits, pero no da acceso por sí misma. |

**Justificación del #1 como informe a gerencia:**
Cualquier persona en internet puede entrar al portal como administrador sin conocer una contraseña, escribiendo una línea en el formulario de login. A partir de ahí puede ver y operar como el administrador, y en un sistema con más datos la misma falla permitiría extraer o alterar toda la información de la base. Es de explotación trivial, no requiere herramientas especiales, y el impacto es sobre la confidencialidad, la integridad y la confianza de los clientes. Además, el arreglo es barato (cambiar una consulta), así que corregirla es la prioridad más rentable. Los problemas de los puestos 2 y 3 son también muy serios y deberían corregirse en el mismo ciclo.

## 5. Conclusión

Fue más difícil arreglar PhantomCorp que romperla. Para atacar bastaba con encontrar una puerta abierta, y en los labs 05–07 una vez que apareció una vulnerabilidad el trabajo estaba hecho. Para defender hubo que cerrar las cinco, elegir un arreglo estructural en lugar de uno cosmético (parametrizar en vez de filtrar comillas, confinar el path en vez de bloquear `..`), y además comprobar que la app siguiera funcionando (login legítimo, descarga legítima). También tuvimos que demostrar el resultado con evidencia reproducible y no con una captura. Un parche que no se entiende se puede romper al tocarlo, así que entender por qué funciona cada defensa fue parte del trabajo.