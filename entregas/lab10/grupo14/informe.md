# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 14 · **Integrantes:** Fede Peron (@fedeeperon), Laureano Gomez Redondo (@Laureano-GR), Martín Cesano (@martincesano), Martín Gaido (@martingaidoo), Valentina Chiapero (@valechiapero)

> **Estado de la entrega:** entorno `phantomcorp` levantado en Docker y auditado de
> punta a punta. **5/5 flags capturadas** contra el target real. Las salidas de esta
> entrega son reproducibles (evidencia en `evidencia/`).

## 0. Declaración de uso de IA

- **Herramienta:** Claude (modelo Opus, de Anthropic) usado a través de Claude Code (CLI), con acceso al repositorio del grupo y a la consola atacante del lab.
- **Uso:** orquestación de los comandos del engagement contra el target autorizado `phantomcorp`, armado de la evidencia en `/loot`, y redacción de este informe y del research.
- **Qué NO hizo:** no se consultó ninguna solución del docente. Ninguna flag ni salida fue inventada: todo sale de corridas reales guardadas en `evidencia/`.
- **Verificación:** cada flag se registró con `./ctf submit`, que compara el SHA-256 contra `retos.manifest`; el contraste detección-vs-evasión de la sección 2 se ejecutó contra el IDS real. Todo es reproducible con los comandos de abajo.

## 1. Flags capturadas (salida de `./ctf status 10`)

Comandos del engagement (desde la consola atacante, contra `phantomcorp`):

```bash
curl -s http://phantomcorp/soc               # R1: vista del SOC
curl -s -A sqlmap http://phantomcorp/        # R2: dispara scanner-ua y devuelve la alerta
curl -s http://phantomcorp/soc/reglas        # R3: ruleset activo del IDS
curl -s "http://phantomcorp/api?q=UNION/**/SELECT"   # R4: evade sqli-union (comentario en vez de espacio)
curl -s http://phantomcorp/soc | grep -i ALERT       # R5: la intrusión que NO disparamos (185.220.101.42)
```

Salida real de `./ctf status 10` (evidencia: `evidencia/00-ctf-status.txt`):

```
   ✓  R1     Acceso a la vista del SOC
   ✓  R2     Disparar una deteccion (te vieron)
   ✓  R3     Conocer el ruleset del IDS
   ✓  R4     Evadir una firma de deteccion
   ✓  R5     Encontrar la intrusion en el ruido
  ██████████████████████████████  5/5 (100%)
```

| Reto | Flag | De dónde sale |
|---|---|---|
| R1 | `FLAG{soc_log_access}` | cabecera de `GET /soc` (vista del SOC) |
| R2 | `FLAG{detection_triggered}` | `GET /` con `User-Agent: sqlmap` → 403 ALERTA IDS firma `scanner-ua` |
| R3 | `FLAG{signature_ruleset}` | `GET /soc/reglas` (ruleset publicado) |
| R4 | `FLAG{signature_evaded}` | `GET /api?q=UNION/**/SELECT` → 200 "maliciosa pero ninguna firma la detectó" |
| R5 | `FLAG{intrusion_in_the_noise}` | línea de `185.220.101.42 - GET /admin/../../etc/passwd ALERT[path-traversal]` entre 120 líneas BENIGN |

## 2. Tabla de firmas

Ruleset real confirmado en `/soc/reglas` (evidencia `evidencia/03-ruleset.txt`):
`scanner-ua` (UA contiene `sqlmap|nikto|nmap|dirb`), `path-traversal` (`../` en la
ruta), `git-probe` (`/.git`) y `sqli-union` (el query matchea `union\s+select`).
Las dos firmas pedidas, confirmadas contra el IDS real:

| Firma | Cómo se evade (confirmado) | Cómo se mejora la detección |
|---|---|---|
| scanner-ua | La firma mira el header `User-Agent`, que el cliente controla. **Confirmado:** con `-A sqlmap` → 403 ALERTA (`evidencia/02b`); con `-A "Mozilla/5.0"` el mismo request pasa como benigno (`evidencia/02a`). La regla mira *quién dice ser* el cliente, no *qué hace*. Se evade con `sqlmap --random-agent` o cualquier UA de navegador. | Detectar por **comportamiento**: tasa de requests por IP, ráfagas de 404/403, barrido de rutas, payloads con sintaxis SQL/traversal en los parámetros sin importar la UA. Correlacionar por IP/sesión en ventanas de tiempo y complementar con fingerprinting del cliente (orden de headers, TLS/JA3). La UA pasa a ser un indicio más, no la condición. |
| sqli-union | La regla real es `re.search("union\s+select", query_crudo, re.I)`: exige **whitespace literal** entre `UNION` y `SELECT`, y matchea sobre el **query crudo (sin URL-decodificar)**. **Confirmado** (`evidencia/04b`): `UNION/**/SELECT`, `UNION%20SELECT` y `UNION+SELECT` **todas evaden** (200) porque ninguna contiene un `\s` literal en crudo. Y un espacio/tab literal en la URL da **400 Bad Request** (rompe la request line). **Hallazgo:** esta firma es inservible — no puede dispararse con tráfico HTTP válido, pero sí deja pasar el ataque real. | **Normalizar antes de comparar** (URL-decode repetido, quitar comentarios `/*...*/`, colapsar whitespace, minúsculas) y matchear con una regex tolerante (ver P2). Sumar reglas de **comportamiento** (ráfagas de errores SQL, `ORDER BY n` incremental, respuestas anómalamente largas) y, como defensa de fondo, consultas parametrizadas en la app: el WAF es una capa extra, no el arreglo. |

## 3. Preguntas P1–P5

**P1. ¿Por qué la detección por firmas es evadible por diseño? ¿Qué la complementa?**
Una firma describe una **representación concreta** de un ataque (una cadena, un patrón). Pero el
mismo efecto se puede expresar de infinitas formas (encodings, comentarios, mayúsculas, espacios
alternativos, fragmentación), y el atacante controla la representación. El IDS solo reconoce lo que
ya conoce y, además, un ruleset publicado o inferible le dice al atacante exactamente qué esquivar.
Es una consecuencia del diseño (lista de lo conocido-malo), no un bug. La complementan: detección por
**anomalía/comportamiento** (baselines, tasas, secuencias), **normalización** previa a las reglas,
**correlación de logs** en un SIEM, análisis humano (SOC, threat hunting), controles preventivos en la
app (parametrización, validación) y defensa en profundidad.

**P2. Reescribir `sqli-union` para que no se evada con `/**/`. ¿Se puede una firma "perfecta"?**
La regla original quedó confirmada en el código del IDS: `re.search("union\s+select", q, re.I)` sobre
el query **crudo** (ver sección 2 y `evidencia/04b`). Peor aún que evadible: como matchea en crudo, un
espacio literal rompe la request (400) y toda codificación del ataque (`%20`, `+`, `/**/`) la esquiva.
Regla propuesta: normalizar el input (URL-decode dos veces, reemplazar `/*...*/` por un espacio,
colapsar whitespace) y recién ahí aplicar, sin distinguir mayúsculas:

```
\bunion\b(?: all| distinct)? ?\(?\s*select\b
```

Prueba real offline en Python 3 ("orig" = la regla real del IDS `union\s+select` sobre el texto;
"nueva" = normalización + regex propuesta):

```
'1 UNION SELECT 1,2'        orig: True   nueva: True
'1 UNION/**/SELECT 1,2'     orig: False  nueva: True
'1%20UNION%0aSELECT 1'      orig: False  nueva: True
'1 UnIoN/*x*/AlL SELECT 1'  orig: False  nueva: True
'1+UNION+SELECT+1'          orig: False  nueva: True
'hola union de empleados'   orig: False  nueva: False
'1 UNION(SELECT 1)'         orig: False  nueva: True
```

**No existe una firma perfecta:** siempre quedan variantes que la regex no contempla (encodings
exóticos, comentarios específicos de un motor como `/*!50000UNION*/`, fragmentación de parámetros,
HTTP Parameter Pollution, inyecciones sin `UNION` como blind/time-based), y cuanto más amplia es la
regla más **falsos positivos** genera (la palabra "union" en texto legítimo). Es un equilibrio entre
falsos positivos y falsos negativos; por eso hace falta defensa en profundidad y arreglar la causa
(consultas parametrizadas).

**P3. Detectar por User-Agent: ¿por qué es débil? ¿Qué mirar en su lugar?**
Porque el header lo declara el cliente y es trivial de cambiar: detecta al atacante descuidado, no al
real. Además produce falsos positivos (herramientas legítimas de monitoreo). En su lugar se mira **qué
hace** el cliente: volumen y cadencia de requests por IP, proporción de errores 404/403, barrido de
rutas, payloads de ataque en parámetros, orden y conjunto de headers, huella TLS (JA3), reputación de
IP y secuencias anómalas dentro de una misma sesión.

**P4. R5: la intrusión estaba en el log. ¿Qué la habría detectado automáticamente?**
Reglas de **correlación/alerta en un SIEM** sobre los logs: alertar ante un evento que se aparta de la
línea base (IP, endpoint, método u horario nunca vistos; acceso a recursos sensibles o administrativos;
respuestas exitosas a requests con payloads sospechosos), ante secuencias (reconocimiento seguido de
explotación desde la misma IP) y por umbrales. También detección por anomalía/UEBA, listas de IOCs /
threat intel, y que las alertas lleguen a una persona con triage en lugar de quedar en un archivo.
En el log real (`evidencia/01-soc-log.txt`), la línea intrusiva se distingue por **tres campos** a la
vez: IP externa `185.220.101.42` (todas las benignas son `10.0.x.x` internas), ruta con
`/admin/../../etc/passwd` (acceso administrativo + path traversal) y el tag `ALERT[path-traversal]`
frente al `BENIGN` del resto. Una regla concreta: alertar ante cualquier evento con IP de origen fuera
del rango interno **o** cuya ruta contenga `../`, y escalarlo a revisión humana.

**P5. Cierre del curso: ¿por qué atacante y defensor tienen que entenderse?**
Son el mismo conocimiento visto desde dos lados. El atacante que entiende cómo se detecta sabe qué
huella deja y qué evadir (y en un pentest, qué reportar como falla de detección); el defensor que
entiende cómo se ataca sabe qué escribir en las reglas y qué buscar en los logs, y no confía en una
firma que se esquiva con un comentario. Los labs 05–08 (ataque), 09 (agentes) y 10 (defensa) mostraron
que cada técnica ofensiva tiene una contramedida y cada contramedida una evasión: ese ciclo mejora a
ambos lados (purple team). Todo bajo marco legal y ético (Ley 26.388).

## 4. Bitácora

| Fecha | Qué se hizo | Quién |
|---|---|---|
| 19/11/2026 | Lectura del enunciado; redacción de informe y research con asistencia de Claude Code; prueba offline de la regex de P2. | Grupo 14 |
| 20/11/2026 | Entorno `phantomcorp` levantado en Docker; captura real de R1–R5 (5/5); confirmación del ruleset y del contraste detección-vs-evasión de `sqli-union` (incl. el hallazgo del 400 con whitespace literal); completado de secciones 1 y 2 y evidencia. | Valentina Chiapero (@valechiapero) |
