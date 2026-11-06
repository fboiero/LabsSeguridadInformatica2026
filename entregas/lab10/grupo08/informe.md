# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

> **Nota de armado.** La entrega se divide en 3 partes:
> - **Parte 1** (R1 Blue + R2 Red) — *completa.*
> - **Parte 2** (R3 Blue + R4 Red + fila `sqli-union` de la tabla) — *completa.*
> - **Parte 3** (R5 + preguntas P1–P5 + `research.md`) — *completa en este commit.*

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Asistencia en la Parte 1: levantar el entorno monitoreado, acceder a la vista del SOC (R1, Blue) y provocar una detección por User-Agent de scanner leyendo la alerta del IDS (R2, Red); borrador de la redacción de esas secciones, evidencias y fila `scanner-ua` de la tabla de firmas. | `informe.md`: sección 1 (flags R1–R2), sección 2.1 y 2.2, fila `scanner-ua` de la tabla de firmas y bloque de la Parte 1 de la bitácora. | Las salidas pegadas corresponden a la ejecución real del entorno (`make lab N=10`, `docker exec cyberlab-attacker curl ...`). Las flags `FLAG{soc_log_access}` y `FLAG{detection_triggered}` se validaron contra el evaluador con `./ctf submit 10 R1/R2` (progreso 2/5). El grupo revisó técnicamente el contenido y comprende las implicancias de detección y evasión. |
| Claude (Anthropic), vía Claude Code | Asistencia en la Parte 2: consulta del ruleset activo del IDS (R3, Blue), análisis de la firma regex `sqli-union` y diseño del payload de evasión con comentarios SQL `/**/` (R4, Red); redacción de secciones 2.3, 2.4, fila `sqli-union` y bitácora. | `informe.md`: sección 1 (flags R1–R4), secciones 2.3 y 2.4, fila `sqli-union` de la tabla de firmas y bloque de la Parte 2 de la bitácora. | Las flags `FLAG{signature_ruleset}` y `FLAG{signature_evaded}` se validaron con `./ctf submit 10 R3/R4`. Se comprobó que el payload `UNION/**/SELECT` esquiva la regex `union\s+select` del servidor manteniendo validez sintáctica. |
| Claude (Anthropic), vía Claude Code | Asistencia en la Parte 3 (Blue): análisis del log del SOC para hallar la intrusión real escondida en el ruido (R5) filtrando por alertas; borrador de la redacción del R5, de las respuestas P1–P5 y del `research.md`. | `informe.md`: sección 1 (flags R1–R5), fila R5 y sección 2.5, respuestas P1–P5 y bloque de la Parte 3 de la bitácora; archivo `research.md` completo. | La salida pegada en §2.5 es la ejecución real del servicio del lab (`curl .../soc | grep 'ALERT['`). La flag `FLAG{intrusion_in_the_noise}` se validó contra el evaluador con `./ctf submit 10 R5` (progreso 5/5). El grupo revisó técnicamente el contenido, verificó las fuentes citadas del research y comprende las implicancias de detección y evasión. |

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas (salida de `./ctf status 10`)

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 10                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     Acceso a la vista del SOC
   ✓  R2     Disparar una deteccion (te vieron)
   ✓  R3     Conocer el ruleset del IDS
   ✓  R4     Evadir una firma de deteccion
   ✓  R5     Encontrar la intrusion en el ruido

  ██████████████████████████████  5/5 (100%)
```

> Estado final: las 5 flags capturadas y validadas contra el evaluador.

---

## 2. Detección y evasión — evidencias

| Reto | Cara | Qué se hizo | Comando | Evidencia | Lectura defensiva |
|---|---|---|---|---|---|
| R1 | Blue | Acceder a la vista del SOC (consola de eventos). | `curl -s http://phantomcorp/soc` | `FLAG{soc_log_access}` | El SOC es el punto de partida del defensor: toda actividad queda registrada ahí. |
| R2 | Red | Provocar una detección con User-Agent de scanner y **leer la alerta** que la delató. | `curl -s -A sqlmap http://phantomcorp/` | 403 · `ALERTA IDS · firma 'scanner-ua'` → `FLAG{detection_triggered}` | La alerta nombra **qué firma** disparó: para el defensor es un evento; para el atacante, un mapa de qué esquivar. |
| R3 | Blue | Consultar el ruleset activo publicado por el SOC para conocer las firmas. | `curl -s http://phantomcorp/soc/reglas` | `FLAG{signature_ruleset}` | Conocer las reglas revela al atacante los límites exactos y supuestos ingenuos de la detección. |
| R4 | Red | Evadir la firma `sqli-union` sustituyendo el espacio por un comentario inline `/**/`. | `curl -s "http://phantomcorp/api?q=1+UNION/**/SELECT+1,2,3--"` | 200 OK · `FLAG{signature_evaded}` | La firma exigía un espacio literal (`\s+`); al cambiar la representación sintáctica, el backend procesa el SQL pero la regex no lo ve. |
| R5 | Blue | Encontrar en el log del SOC la única intrusión real (no provocada por el grupo) filtrando las líneas de alerta en medio del tráfico benigno. | `curl -s http://phantomcorp/soc \| grep 'ALERT['` | `185.220.101.42 ... /admin/../../etc/passwd 200 ALERT[path-traversal]` → `FLAG{intrusion_in_the_noise}` | Lo que una firma marca pero nadie mira es ruido inútil: la detección solo sirve si hay un analista (o correlación/alertado) que la lea y responda. |

### 2.1 R1 (Blue) — Acceso a la vista del SOC

PhantomCorp expone la consola del SOC en `/soc`. Esta ruta **no** se inspecciona como ataque: es la vista del defensor sobre el tráfico. Acceder a ella es el primer paso del análisis.

```console
$ docker exec cyberlab-attacker curl -s http://phantomcorp/soc | head -5
=== PhantomCorp SOC · vista de eventos ===
Acceso a la consola del SOC concedido. FLAG{soc_log_access}
Tip: filtrá por ALERT. Hay UNA intrusion real que no disparaste vos.
------------------------------------------------------------
10.0.1.21 - GET /catalogo?item=1 200 BENIGN
```

El encabezado confirma el acceso y entrega `FLAG{soc_log_access}`. El log mezcla ~120 líneas de tráfico benigno con alertas; el análisis fino (la intrusión del R5) se desarrolla en §2.5.

### 2.2 R2 (Red) — Disparar una detección y leer la alerta

Del lado rojo, lo más fácil de delatar es la **identidad declarada**: la User-Agent. El IDS tiene la firma `scanner-ua` que matchea `sqlmap|nikto|nmap|dirb`. Un simple request anunciándose como `sqlmap` ya dispara la alerta.

```console
$ docker exec cyberlab-attacker curl -s -A sqlmap http://phantomcorp/
🚨 ALERTA IDS · firma 'scanner-ua' disparada.
Tu request fue DETECTADA y logueada. FLAG{detection_triggered}
Para ver todas las reglas: GET /soc/reglas
```

Respuesta **403** + `FLAG{detection_triggered}`. La alerta dice explícitamente qué firma disparó (`scanner-ua`) y hacia dónde seguir (`/soc/reglas`, que es el R3 de la Parte 2). Clave: el IDS detectó **quién decís ser**, no **qué hacés** — esa es justamente la debilidad que la fila `scanner-ua` de la tabla analiza, y la base de la evasión.

### 2.3 R3 (Blue) — Conocer el ruleset del IDS

El endpoint `/soc/reglas` expone las reglas activas del motor de detección:

```console
$ docker exec cyberlab-attacker curl -s http://phantomcorp/soc/reglas
=== Ruleset del IDS (firmas activas) ===
Conocer las reglas es el primer paso para evadirlos. FLAG{signature_ruleset}
  scanner-ua      User-Agent contiene sqlmap|nikto|nmap|dirb
  path-traversal  la ruta contiene '../'
  git-probe       la ruta contiene '/.git'
  sqli-union      el query matchea /union\s+select/  (OJO: exige un ESPACIO)

Una firma que exige un espacio se esquiva quitando el espacio. Pensá.
```

El ruleset evidencia una regla frágil: `sqli-union` usa la expresión regular `union\s+select`, asumiendo que cualquier inyección SQL con `UNION` y `SELECT` tendrá forzosamente un carácter de espacio en blanco (`\s+`) intermedio. Conocer esto le da al atacante la pista exacta para la evasión.

### 2.4 R4 (Red) — Evadir una firma de detección

En SQL, los comentarios de bloque `/**/` son tratados por el parser léxico como espacios/separadores válidos de tokens. Sin embargo, para la expresión regular `union\s+select`, la secuencia de caracteres `/**/` no matchea `\s+`.

Se ejecutó una consulta inyectando `UNION/**/SELECT`:

```console
$ docker exec cyberlab-attacker curl -s "http://phantomcorp/api?q=1+UNION/**/SELECT+1,2,3--"
200 OK (procesado como benigno)
Tu request ERA maliciosa pero NINGUNA firma la detectó. FLAG{signature_evaded}
```

El IDS procesó la petición como benigna devolviendo HTTP 200 y entregando `FLAG{signature_evaded}`.

### 2.5 R5 (Blue) — Encontrar la intrusión en el ruido

Último reto, de vuelta del lado defensor. El log del SOC (`/soc`) tiene ~120 líneas de tráfico benigno (`GET /catalogo?item=N 200 BENIGN`) y, escondida entre ellas, **una** intrusión real que **no** provocó el grupo. Revisar 120 líneas a ojo es inviable y propenso a error: el analista filtra por lo que importa. Como el motor etiqueta cada evento marcado con `ALERT[<firma>]`, filtramos exactamente por esa marca:

```console
$ docker exec cyberlab-attacker curl -s http://phantomcorp/soc | grep 'ALERT['
185.220.101.42 - GET /admin/../../etc/passwd 200 ALERT[path-traversal] # intrusion no atribuida -> FLAG{intrusion_in_the_noise}
```

Una sola línea sobrevive al filtro, y es inequívocamente maliciosa. Al leerla, tres señales la delatan:

- **Payload:** `GET /admin/../../etc/passwd` — un *path traversal* clásico que intenta salir del webroot para leer `/etc/passwd`. Disparó la firma `path-traversal` (la misma del ruleset del R3).
- **Origen:** `185.220.101.42` — una IP del rango de **nodos de salida de Tor**, ajena a las IPs internas `10.0.x.x` del resto del tráfico. Un origen anonimizado para pedir `/etc/passwd` no es un usuario legítimo.
- **Resultado:** status `200` — lo más grave. No es un intento bloqueado: la firma **detectó y logueó** el ataque, pero el servidor igual **respondió 200** (lo sirvió). Detección sin prevención: quedó registrado, nadie lo frenó, y sin un analista leyendo el log nadie se entera.

La línea entrega `FLAG{intrusion_in_the_noise}`. La lección del reto —y el cierre del lab— es que **una alerta que nadie lee es equivalente a no tener alerta**: la firma hizo su trabajo (marcó el evento), pero la detección solo tiene valor si alguien o algo (un analista, una regla de correlación, un alertado automático) la convierte en respuesta.

---

## 3. Tabla de firmas

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| scanner-ua | La firma mira sólo el header `User-Agent` contra una lista fija (`sqlmap\|nikto\|nmap\|dirb`). Se evade **cambiando la UA** por la de un navegador legítimo (`curl -A "Mozilla/5.0 ..."`): el mismo scan pasa desapercibido porque la firma inspecciona *quién decís ser*, no *qué hacés*. | No confiar en la identidad autodeclarada. Correlacionar **comportamiento**: tasa de requests por IP, cantidad de 404/403 en ráfaga, recorrido de rutas no enlazadas, timing automático. Un escaneo se delata por su *patrón*, no por su etiqueta. |
| sqli-union | La firma exige un espacio en blanco (`\s+`) entre `UNION` y `SELECT`. Se evade sustituyendo el espacio por delimitadores válidos en SQL como comentarios inline (`UNION/**/SELECT`), tabuladores URL-encodeados (`UNION%09SELECT`), saltos de línea (`UNION%0ASELECT`) o paréntesis sintácticos. | Normalizar el input antes de inspeccionar (eliminar comentarios SQL, decodificar capas de URL encoding). Mejorar la regex a `union(?:\s|/\*.*?\*/)+select` o utilizar análisis semántico / parser AST de SQL en lugar de pattern matching por texto plano. |
| path-traversal | La firma busca el literal `../` en la ruta. Se evade con encodings que el servidor decodifica pero la firma no normaliza: `%2e%2e%2f`, doble encoding (`%252e%252e%252f`), `....//` (que tras colapsar queda `../`), o variantes Unicode/overlong. Es la firma que marcó la intrusión del R5 (sin evadir, por eso quedó logueada). | Canonicalizar la ruta **antes** de inspeccionar y de resolverla (decodificar todas las capas de URL, resolver `.`/`..` a una ruta absoluta) y recién ahí comparar contra el webroot. Mejor aún: no construir rutas de archivo con input del usuario (whitelists, IDs indirectos) y confinar el proceso (chroot/contenedor) para que, aunque se evada la firma, no haya `/etc/passwd` que leer. |
| git-probe | La firma busca `/.git` en la ruta para detectar sondas al repositorio expuesto. Se evade pidiendo los objetos por rutas que no contengan ese literal exacto (p. ej. variando mayúsculas si el FS no distingue, o encodings de los caracteres) o enumerando archivos sueltos sin pasar por `/.git`. | No desplegar el directorio `.git` en producción (es un problema de configuración, no de firma): excluirlo del build/deploy o bloquearlo en el servidor web. La firma es un parche; la causa raíz es servir artefactos de desarrollo. |

---

## 4. Preguntas P1–P5

**P1 — ¿Por qué la detección por firmas es evadible por diseño? ¿Qué la complementa?**

Una firma reconoce un **patrón conocido**: una cadena, una regex, un hash de algo que alguien ya vio y catalogó como malicioso. Esa es a la vez su fuerza (es rápida, barata, con pocos falsos positivos sobre lo conocido) y su límite estructural: solo detecta lo que **ya está en el catálogo**. Es evadible *por diseño* por dos razones. Primera, una misma acción maliciosa tiene **infinitas representaciones** sintácticas equivalentes, y la firma captura una sola: lo vivimos en el R4, donde `UNION SELECT` y `UNION/**/SELECT` hacen lo mismo para el motor SQL pero solo el primero matchea `union\s+select`. Segunda, las firmas describen el ataque *conocido*, así que un ataque nuevo (*zero-day*) o una variante no catalogada pasa invisible por definición: no hay firma de algo que nadie vio todavía.

Lo que la complementa es la **detección por anomalía/comportamiento** y la **correlación** (SIEM): en vez de preguntar "¿esto coincide con un patrón malo conocido?", pregunta "¿esto se desvía de la línea base de lo normal?" o "¿la *suma* de estos eventos cuenta una historia de ataque?". No reconoce la firma del payload sino el patrón de conducta: una IP que pide 500 rutas en 10 segundos, un origen que nunca apareció antes, una secuencia recon → explotación → exfiltración. Firmas y anomalía son defensa en profundidad: las firmas atajan barato lo conocido; la anomalía y el análisis humano atrapan lo que ninguna firma tenía.

**P2 — Reescribir `sqli-union` para que no se evada con `/**/`. ¿Existe una firma "perfecta"?**

El problema de `union\s+select` es que asume que el separador entre los dos tokens es un espacio en blanco. La corrección mínima es hacer que el separador **también acepte un comentario de bloque** (y, en general, cualquier separador válido para el parser SQL):

```
union(?:\s|/\*.*?\*/|%09|%0a|%0c|\+)+select
```

Pero esto es una **carrera de parches**: cubre `/**/`, tabs y saltos URL-encodeados, pero no el doble URL encoding (`UNION%252f%252a...`), ni los comentarios anidados, ni variantes con mayúsculas/mezcla ya contempladas por el `re.I`, ni representaciones que ni imaginamos. Por cada regex que endurecemos, aparece otra codificación equivalente. **No existe una firma regex "perfecta"**, y la razón es de fondo: el atacante y el motor SQL coinciden en qué es una inyección válida (el parser del motor), pero la regex trabaja sobre el **texto plano** sin entender esa gramática. La única defensa robusta cambia el nivel de abstracción: **normalizar/canonicalizar** el input (decodificar todas las capas, remover comentarios) *antes* de inspeccionar, y mejor aún analizar **semánticamente** la query (un parser/AST de SQL, o librerías tipo libinjection que deciden por estructura, no por coincidencia de texto). Y, sobre todo, la defensa real contra SQLi no es la firma sino las **consultas parametrizadas**: que el input nunca pueda cambiar la estructura de la query.

**P3 — Detección por User-Agent: ¿por qué es débil? ¿Qué mirarías en vez de "quién dice ser"?**

Es débil porque la User-Agent es un **header que el cliente controla por completo**: es una identidad *autodeclarada*, no verificada. La firma `scanner-ua` confía en que una herramienta ofensiva se va a anunciar honestamente como `sqlmap`/`nikto`/`nmap`/`dirb` — y ninguna lo hace si el operador no quiere: un solo `-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"` disfraza el mismo escaneo de navegador legítimo y la firma deja de verlo (lo analizamos en la fila `scanner-ua` de la §3). Es detección de *quién decís ser*, no de *qué hacés*.

Lo que miraríamos es el **comportamiento**, que el atacante no puede falsear tan fácil porque *es* el ataque: tasa de requests por IP y por unidad de tiempo (un humano no pide 300 rutas en 5 segundos), ráfagas de `404`/`403` (un scanner prueba rutas que no existen), recorrido de rutas **no enlazadas** desde la app (nadie navega a `/.git` o `/admin/../` por casualidad), regularidad temporal sospechosamente automática (intervalos de milisegundos constantes), y correlación de varias de estas señales sobre la misma IP/sesión. Un escaneo se delata por su *patrón de conducta*, no por la etiqueta que elige ponerse.

**P4 — El R5: ¿qué habría hecho que la intrusión se detecte automáticamente?**

En el R5 la intrusión **ya estaba detectada** en el sentido débil: la firma `path-traversal` la marcó y la línea quedó etiquetada `ALERT[path-traversal]` en el log. Lo que faltó fue todo lo que convierte una línea de log en una **respuesta**. En concreto:

1. **Alertado activo (no pasivo).** El evento quedó esperando que un humano abriera `/soc` y lo encontrara entre 120 líneas. Un *push* automático —disparar un ticket/mail/mensaje al SOC apenas se genera un `ALERT[...]`— lo habría elevado al instante en vez de dejarlo sepultado en el ruido.
2. **Prevención, no solo detección (IPS vs IDS).** Lo más grave es que el request devolvió `200`: se detectó **y aun así se sirvió**. Un modo *inline* que **bloquee** (403/drop) ante la firma habría frenado el ataque, no solo anotado que ocurrió.
3. **Correlación/enriquecimiento (SIEM + threat intel).** La IP `185.220.101.42` es un nodo de salida de Tor: cruzar el origen contra listas de reputación habría subido la severidad automáticamente. Sumado a reglas de correlación ("origen externo anónimo + path traversal + acceso a archivo sensible"), el evento se habría escalado solo.
4. **Umbrales y baselining.** Una regla tan simple como "cualquier `ALERT[...]` desde una IP fuera del rango interno `10.0.x.x` → severidad alta" habría separado esta línea del ruido sin intervención humana.

En resumen: la detección por firma hizo su parte; faltaron **alertado, bloqueo inline y correlación** para cerrar el lazo detección → respuesta.

**P5 — Cierre del curso: ¿por qué red y blue son el mismo conocimiento?**

Porque las dos caras operan sobre **el mismo modelo del ataque**, solo que lo usan en direcciones opuestas. Todo este lab lo demuestra en un mismo objeto: el **ruleset** del R3 es, para el blue, la lista de lo que defiende; y para el red, el mapa exacto de qué evadir (R4). No son dos conocimientos distintos, es uno solo leído de los dos lados. Para **evadir** una firma (red) primero hay que entender *cómo detecta* (blue): sin saber que `sqli-union` exige `\s+`, no se nos ocurre meter `/**/`. Y para **escribir o mejorar** una firma (blue) hay que pensar como el atacante que la va a sortear (red): la regex `union(?:\s|/\*.*?\*/)+select` de P2 solo se nos ocurre si anticipamos la evasión. El pentester que entiende detección evade mejor; el defensor que entiende evasión detecta mejor. Por eso el curso cierra acá: después de cinco labs de ofensiva, darse vuelta al lado defensor no es aprender otra cosa, es **ver el mismo conocimiento completo**. Un buen red team piensa como blue y un buen blue team piensa como red.

---

## 5. Bitácora

### Parte 1 — Blue inicial + primera detección (R1, R2)

1. Se levantó el entorno monitoreado con `make lab N=10` (contenedores `cyberlab-attacker` + `cyberlab-phantomcorp` sobre `labnet`).
2. **R1 (Blue):** `curl -s http://phantomcorp/soc` → acceso a la consola del SOC → `FLAG{soc_log_access}`. Validada con `./ctf submit 10 R1`.
3. **R2 (Red):** `curl -s -A sqlmap http://phantomcorp/` → 403, firma `scanner-ua` disparada → `FLAG{detection_triggered}`. Validada con `./ctf submit 10 R2`.
4. Se registró la fila `scanner-ua` en la tabla de firmas (evasión por cambio de UA + mejora por correlación de comportamiento).
5. Progreso al cierre: **2/5**. Siguiente: R3 (ruleset) y R4 (evasión `sqli-union`) en la Parte 2.

### Parte 2 — Ruleset + evasión (R3, R4)

1. **R3 (Blue):** Se consultó `curl -s http://phantomcorp/soc/reglas`, obteniendo las 4 firmas activas y `FLAG{signature_ruleset}`. Se validó con `./ctf submit 10 R3`.
2. **R4 (Red):** Se analizó la regla `sqli-union`, notando que exigía `\s+`. Se diseñó el payload `UNION/**/SELECT` y se envió mediante `curl -s "http://phantomcorp/api?q=1+UNION/**/SELECT+1,2,3--"`, obteniendo respuesta 200 OK y `FLAG{signature_evaded}`. Se validó con `./ctf submit 10 R4`.
3. Se documentaron las evidencias en §2.3 y §2.4, y se completó la fila `sqli-union` en la Tabla de firmas (§3).
4. Progreso al cierre: **4/5**. Siguiente: R5 (intrusión oculta), preguntas P1–P5 y `research.md` en la Parte 3.

### Parte 3 — Intrusión en el ruido + análisis (R5, P1–P5, research)

1. **R5 (Blue):** Se descargó el log completo del SOC y se filtró por la marca de alerta del motor para separar la intrusión del tráfico benigno: `curl -s http://phantomcorp/soc | grep 'ALERT['`. Sobrevive una sola línea (`185.220.101.42 - GET /admin/../../etc/passwd 200 ALERT[path-traversal]`) → `FLAG{intrusion_in_the_noise}`. Se validó con `./ctf submit 10 R5`.
2. Se analizó la línea (payload de path traversal a `/etc/passwd`, origen en nodo de salida de Tor, status `200` = detectada pero no bloqueada) y se documentó en §2.5.
3. Se completaron las filas `path-traversal` y `git-probe` de la Tabla de firmas (§3), cubriendo las 4 firmas del ruleset.
4. Se respondieron las preguntas P1–P5 (§4) y se redactó el `research.md` (tema C: SIEM y correlación de logs).
5. Progreso final: **5/5 (100%)**.

```bash
# Validación de las 5 flags desde la raíz del repositorio
./ctf submit 10 R1 'FLAG{soc_log_access}'
./ctf submit 10 R2 'FLAG{detection_triggered}'
./ctf submit 10 R3 'FLAG{signature_ruleset}'
./ctf submit 10 R4 'FLAG{signature_evaded}'
./ctf submit 10 R5 'FLAG{intrusion_in_the_noise}'
./ctf status 10   # Progreso: 5/5 (100%)
```
