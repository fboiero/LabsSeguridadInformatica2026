# Entregable — Lab Extra 3: Defendé PhantomCorp

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0)

**Estado:** Lorenzo implementó D1/D2 y respondió P3; Fernando implementó D4/D5 y respondió P4; Guadalupe integró ambos bloques en una sola copia de `objetivo/server.py` y respondió P1. Lautaro cerró **D3** (robots sin rutas sensibles y `/backup` eliminado) sobre esa copia combinada y respondió P2/P5. El verificador oficial sobre el código integrado da ahora **5/5** (`evidencia/salidas/verificador-5-5-lautaro.txt`). Las flags se envían con `./ctf submit extra3 D1..D5` desde el host.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para organizar el parche y redactar mis filas/P3. Apliqué los cambios a la copia de `objetivo/server.py`, comparé el diff contra el original y ejecuté el verificador oficial con `--dir` sobre mi copia. Verifiqué las flags de D1/D2 con `./ctf status extra3`. No usé IA para inventar salidas ni para atribuirme los bloques pendientes. Fernando Cagliero (@Ferca19) usó OpenAI Codex para implementar D4/D5, preparar un harness local y redactar P4; la salida real de su verificación se conserva. No se afirman como integradas las verificaciones independientes.

**Declaración de uso de IA — Guadalupe (@guadagomezgg8):** bloque de integración (regresión integrada, P1, evidencia final, conclusión). Usé **Claude (Anthropic)** para (a) correr el verificador oficial `verificar-defensa.py --dir` sobre la copia combinada del grupo y la regresión funcional de los endpoints legítimos, más el antes/después del original vulnerable, con salida en `evidencia/salidas/verificador-integrado.txt`, y (b) redactar esta integración y declaración. No se leyó `solucion.md`; los resultados salen del verificador y de respuestas HTTP. D3 no se tocó (es de Lautaro). Reviso y puedo explicar cada paso.

**Declaración de uso de IA — Lautaro Mariño (@lautaromarino0):** bloque D3 y preguntas P2/P5. Usé **Claude (Anthropic)** para aplicar el fix de D3 sobre la copia combinada `objetivo/server.py`, correr el verificador oficial `--dir` (resultado 5/5) y redactar P2/P5, que revisé antes de commitear. No leí `solucion.md`; la flag de D3 la emite el verificador al bloquear el ataque. No toqué los bloques D1/D2/D4/D5 de los demás.

---

## 1. Tabla de defensas (antes → después)

| Defensa | Ataque que funcionaba | Fix aplicado | Verificación (salida del ataque bloqueado) |
|---|---|---|---|
| D1 | El verificador inicial observó `Server: 'PhantomServer/2.4.1-debug '`. | `VERSION` queda vacío y `sys_version` sigue vacío; el header ya no identifica el producto ni la versión. El diff está en `evidencia/salidas/d1-d2.diff`. | El verificador con `--dir` observó `header Server: ''` y marcó D1 bloqueado. Salida: `evidencia/salidas/verificador-parcial.txt`. D1 aceptado por el CTF. |
| D2 | El verificador inicial recibió HTTP 200 de `/api/status` con `debug`, la ruta de la base y el PID. | Se eliminó la rama que publicaba el endpoint; la ruta cae en el 404 genérico. | El verificador recibió `GET /api/status -> 404 '404 - no existe'` y marcó D2 bloqueado. Salida: `evidencia/salidas/verificador-parcial.txt`. D2 aceptado por el CTF. |
| D3 | `GET /backup` devolvía HTTP 200 con un dump de pre-migración sin autenticación, y `robots.txt` lo delataba con `Disallow: /backup`. | Se **elimina** el endpoint `/backup` (era un resto de migración, no una función del portal): cae en el 404 genérico. Y `robots.txt` deja de enumerar rutas internas (robots no es un control de acceso; listarlas solo las hace descubribles). | El verificador observó `GET /backup -> 404; robots menciona /backup: False` y marcó D3 bloqueado. Salida: `evidencia/salidas/verificador-5-5-lautaro.txt`. Flag `FLAG{def_rutas_blindadas}`. |
| D4 | Los payloads de SQLi podían alterar la consulta de login. | Consulta SQLite parametrizada con valores enlazados. | En el harness local, los bypasses devuelven 401 y el login legítimo 200; salida en `evidencia/salidas/verificacion-d4-d5.txt`. |
| D5 | `archivo=../../etc/passwd` podía salir del directorio de descargas. | `realpath` del destino y raíz, con `commonpath` para exigir que permanezca dentro del directorio permitido. | El harness bloqueó traversal directo, codificado y un nombre con prefijo similar; `manual.txt` sigue disponible. Salida en `evidencia/salidas/verificacion-d4-d5.txt`. |

### Nota sobre D5 y el entorno

El verificador inicial del original dio 1/5: D1–D4 vulnerables, D5 aparecía bloqueado. Después de mis cambios dio 3/5: D1 y D2 bloqueados por mi parche y D5 aparecía igual que antes. Como `server.py` original no se modificó y el target copiado no tiene parche D5 de mi parte, esa señal es un falso positivo del entorno Windows/ruta POSIX para esta comprobación, no un arreglo. Ese resultado precede al parche D5 de Fernando y no se atribuye a su código. El CTF confirma 2/5 y solo D1/D2 están aceptados. Se conservaron ambas salidas completas.

## 2. Regresión funcional

El harness local de Fernando, contra su copia con D4/D5 antes de integrar D1/D2, confirmó GET / 200, login legítimo 200, bypasses SQLi 401 y descarga de manual.txt 200, además de bloquear traversal.

**Regresión de la copia integrada (D1/D2 + D4/D5):** se verificó que los parches no rompen la funcionalidad válida sobre el `server.py` combinado del grupo:

| Petición legítima | Resultado |
|---|---|
| `GET /` | HTTP 200 |
| `GET /login?user=admin&pass=sup3r-s3cr3t0` | HTTP 200 (login válido) |
| `GET /descargar?archivo=manual.txt` | HTTP 200 |
| `GET /robots.txt` | HTTP 200 |

Salida: [verificador-integrado.txt](evidencia/salidas/verificador-integrado.txt).
## 3. Evidencia de progreso

- Verificador inicial: `evidencia/salidas/verificador-inicial.txt` (salida 1/5 observada en Windows).
- Verificador contra la copia tras el bloque de Lorenzo: `evidencia/salidas/verificador-parcial.txt` (3/5 observado; D1/D2 aceptados y el D5 no atribuido al parche).
- Estado completo del CTF: `evidencia/salidas/status-extra3.txt` (2/5; D1/D2 ✓).
- Diff D1/D2: `evidencia/salidas/d1-d2.diff`.
- Verificación local D4/D5 y regresiones: `evidencia/salidas/verificacion-d4-d5.txt`.

**Corrida integrada (Guadalupe):** el verificador oficial `verificar-defensa.py --dir` sobre la copia combinada dio **4/5**:

```
✓ D1 header Server: ''                         FLAG{def_banner_neutralizado}
✓ D2 GET /api/status -> 404                     FLAG{def_debug_apagado}
✗ D3 GET /backup -> 200 (robots lo menciona)    [vulnerable — bloque de Lautaro]
✓ D4 bypass admin'-- y OR 1=1: bloqueados       FLAG{def_sqli_parametrizado}
✓ D5 traversal /etc/passwd -> 404 (bloqueado)   FLAG{def_traversal_bloqueado}
4/5 defensas correctas.
```

D1/D2/D4/D5 quedaban integrados y verificados; **D3 era el único gap**. Salida de esa corrida: `evidencia/salidas/verificador-integrado.txt`.

**Corrida integrada con D3 (Lautaro):** tras aplicar el fix de D3 sobre la misma copia combinada, el verificador oficial da **5/5**:

```
✓ D1 header Server: ''                          FLAG{def_banner_neutralizado}
✓ D2 GET /api/status -> 404                      FLAG{def_debug_apagado}
✓ D3 GET /backup -> 404; robots: /backup False   FLAG{def_rutas_blindadas}
✓ D4 bypass admin'-- y OR 1=1: bloqueados        FLAG{def_sqli_parametrizado}
✓ D5 traversal /etc/passwd -> 404 (bloqueado)    FLAG{def_traversal_bloqueado}
5/5 defensas correctas.
```

Las cinco defensas quedan integradas y verificadas. Salida completa: `evidencia/salidas/verificador-5-5-lautaro.txt`.

## 4. Preguntas P1–P5

### P1 — Antes/después de una defensa

Tomo **D4 (SQLi en `/login`)**, la defensa de mayor impacto.

- **Antes (server original):** el login concatenaba el input en la consulta (`SELECT user FROM usuarios WHERE user='" + user + "'...`). El payload `user=admin'--` cerraba la cadena y comentaba el resto, salteando la verificación de contraseña: la respuesta fue `HTTP 200 «Bienvenido, admin'--»` — bypass de autenticación.
- **Después (parche):** la consulta pasa a ser parametrizada (`... WHERE user = ? AND password = ?`), con usuario y contraseña enlazados como **valores**, no como SQL. El mismo payload ya no altera la estructura: el verificador oficial lo marca bloqueado (`bypass admin'--: bloqueado; OR 1=1: bloqueado`), y el login legítimo sigue devolviendo 200.

La diferencia de fondo: el fix no "filtra" caracteres peligrosos (lista siempre incompleta) sino que separa dato de código, que es la defensa estructural contra SQLi. Evidencia del antes/después en `evidencia/salidas/verificador-integrado.txt`.

### P2 — `robots.txt` y autorización

`robots.txt` es una **directiva para crawlers**, no un control de acceso. Le pide a los buscadores que se abstengan de indexar ciertas rutas, pero no exige credenciales ni bloquea una petición: cualquiera puede leer el propio `robots.txt` y pedir igual las rutas listadas. La RFC 9309 lo dice explícitamente —el protocolo no es un mecanismo de autorización— y la documentación de Google aclara que `Disallow` no sirve para mantener una página fuera de su alcance si alguien la enlaza o la pide directo.

Por eso, listar `/backup` en `Disallow` tiene el efecto **opuesto** al buscado: en vez de proteger la ruta, se la **publica**. Un atacante lee `robots.txt` primero, justamente para descubrir los directorios que el administrador considera sensibles (es el patrón de WSTG-INFO-03 de OWASP). El `robots.txt` del original era un índice de recon servido en bandeja.

El fix correcto es doble y no pasa por `robots.txt`: (1) **sacar el recurso** de la superficie pública —se eliminó `/backup`, que era un dump de pre-migración— y, cuando una ruta interna deba existir, (2) protegerla con **autenticación/autorización** del lado del servidor (401/403 sin credenciales), no con una línea de `Disallow`. `robots.txt` puede seguir existiendo, pero sin enumerar rutas internas: no se gana nada ocultándolas y se pierde al nombrarlas.

### P3 — ¿D1 es una defensa real?

Neutralizar el banner es una medida de reducción de información: dificulta que un escaneo pasivo identifique inmediatamente producto y versión, y puede reducir ruido automatizado. No corrige una vulnerabilidad de autenticación, autorización ni ejecución. Un atacante todavía puede inferir tecnología por respuestas, rutas, formato de errores o comportamiento, y el producto vulnerable permanece vulnerable. Por eso ocultar versión puede ser una capa auxiliar, pero confiar en que el atacante no la descubra es seguridad por oscuridad y da una falsa sensación de protección. La defensa real está en corregir y actualizar el software y en controles que impidan el acceso no autorizado.

### P4 — Reemplazar comillas frente a consultas parametrizadas

Eliminar comillas con user.replace es un filtro de sintaxis SQL y depende de una lista incompleta de caracteres y formas de escritura. No separa de manera fiable el dato del código: comentarios, operadores, codificaciones y diferencias entre motores o contextos de consulta pueden dejar variantes sin cubrir, y el escape manual es fácil de aplicar de forma inconsistente. La consulta parametrizada mantiene fija la estructura SQL y enlaza usuario y contraseña como valores separados; el motor no los interpreta como operadores ni cláusulas. Esa es la defensa estructural. El parche D4 usa parámetros SQLite y la evidencia bloquea los dos payloads del verificador.

### P5 — Ranking de los cinco problemas

Ordenados por impacto si quedaran sin corregir (de más grave a menos):

1. **D4 — SQLi en `/login` (bypass de autenticación).** Es el más grave: `user=admin'--` entra como `admin` sin contraseña. Rompe directamente la confidencialidad y la integridad del sistema (acceso no autorizado con identidad ajena) y suele ser la cabecera de una cadena hacia datos o RCE. Defensa estructural: consulta parametrizada.
2. **D5 — Path traversal en `/descargar`.** `archivo=../../etc/passwd` lee archivos arbitrarios del servidor fuera del directorio de descargas: fuga de configuración, credenciales o código. Alto impacto en confidencialidad, sin necesidad de autenticarse. Defensa: canonizar con `realpath` y exigir `commonpath` dentro de la raíz.
3. **D3 — `/backup` sin auth + `robots` que lo delata.** Expone directamente un dump de datos (`usuarios=1`) a cualquiera, y encima lo señaliza. No requiere técnica: es un `GET`. Lo pongo por debajo de D4/D5 porque el recurso expuesto acá es acotado (un dump de pre-migración), mientras SQLi y traversal dan acceso general; pero sigue siendo una fuga de datos concreta.
4. **D2 — endpoint de debug `/api/status`.** Filtra información interna (PID, ruta de la base, flag de debug) que acelera y orienta el resto del ataque. No es una brecha por sí solo, pero es **uplift**: convierte otros ataques en más fáciles y certeros.
5. **D1 — banner con producto y versión.** El de menor impacto: solo adelanta qué software corre. Facilita buscar CVEs conocidos, pero no abre ninguna puerta por sí mismo y se evade con otras señales (seguridad por oscuridad). Es una capa auxiliar, no una defensa.

El criterio del ranking: arriba, lo que da **acceso o datos sin autenticación** (D4, D5, D3); abajo, lo que solo **da información al atacante** (D2, D1). Endurecer de verdad es cerrar las primeras; ocultar banner o rutas sin corregir el fondo es seguridad por oscuridad.

## 5. Conclusión

Sobre el código combinado del grupo, las cinco defensas quedan verificadas por el verificador oficial (**5/5**): banner neutralizado (D1), endpoint de debug apagado (D2), rutas blindadas —`/backup` eliminado y `robots` sin enumerar internos— (D3), login parametrizado contra SQLi (D4) y descarga sin path traversal (D5), sin romper la funcionalidad legítima (regresión 200 en home, login válido y descarga). El aprendizaje central del lab se sostiene: endurecer es corregir la vulnerabilidad (D4/D5), no solo ocultar información (D1), y cada fix se valida atacándolo de nuevo y comprobando que lo legítimo sigue funcionando.
