# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 14 · **Integrantes:** Fede Peron (@fedeeperon), Laureano Gomez Redondo (@Laureano-GR), Martín Cesano (@martincesano), Martín Gaido (@martingaidoo), Valentina Chiapero (@valechiapero)

> **Estado de la entrega:** este equipo no tiene Docker, por lo que el entorno
> `phantomcorp` **no se pudo levantar**. No hay flags ni salidas reales en este informe.
> Todo lo que depende del entorno está marcado **PENDIENTE (requiere Docker)**. Las
> secciones teóricas (P1–P5 y el diseño de las mejoras) están completas.

## 0. Declaración de uso de IA

- **Herramienta:** Claude (modelo Claude Sonnet 5.5, de Anthropic) usado a través de Claude Code (CLI), con acceso al repositorio del grupo.
- **Uso:** redacción de este informe y del research a partir del enunciado y de la teoría; diseño de la regla mejorada de la P2 y una prueba puntual de esa regla en Python.
- **Qué NO hizo:** no se levantó el entorno, no se capturó ninguna flag ni se inventó salida alguna. No se consultó ninguna solución del docente.
- **Verificación:** la única ejecución real fue la prueba de la regex de la P2, cuya salida se reproduce tal cual. El resto debe ser revisado por los integrantes y contrastado contra el entorno real cuando se pueda correr.

## 1. Flags capturadas (salida de `./ctf status 10`)

**PENDIENTE (requiere Docker).** Comandos exactos a correr desde la raíz del repo:

```bash
make setup
./ctf lab 10
make shell                                   # dentro de la consola atacante:
curl -s http://phantomcorp/soc               # R1: vista del SOC
curl -s -A sqlmap http://phantomcorp/        # R2: disparar scanner-ua y leer la alerta
curl -s http://phantomcorp/soc/reglas        # R3: ruleset activo
# R4: sqli-union sin el espacio literal (comentario SQL /**/ en vez de espacio):
curl -s "http://phantomcorp/api?q=1%20UNION/**/SELECT%201"   # ajustar según lo que muestre /soc/reglas
# R5: buscar la línea de intrusión que NO generamos nosotros:
curl -s http://phantomcorp/soc | grep ALERT
curl -s http://phantomcorp/soc | less        # revisar las 120 líneas a mano / filtrar según el formato real
# entregar cada flag y adjuntar la salida real:
./ctf submit 10 R1 'FLAG{...}'    # ... R2..R5
./ctf status 10
```

| Reto | Flag | Estado |
|---|---|---|
| R1 | — | PENDIENTE (requiere Docker) |
| R2 | — | PENDIENTE (requiere Docker) |
| R3 | — | PENDIENTE (requiere Docker) |
| R4 | — | PENDIENTE (requiere Docker) |
| R5 | — | PENDIENTE (requiere Docker) |

*(Pegar acá la captura / salida real de `./ctf status 10`.)*

## 2. Tabla de firmas

Las firmas son las que nombra el enunciado (`scanner-ua`, `sqli-union`). Cómo se
evade cada una **en teoría** está completo; la confirmación contra el IDS real
(texto exacto de cada regla en `/soc/reglas`) queda **PENDIENTE (requiere Docker)**.

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| scanner-ua | La firma mira el header `User-Agent`, que el cliente controla. Basta `curl -A "Mozilla/5.0 ..."` (o `sqlmap --random-agent`) para que el mismo ataque pase: la regla mira *quién dice ser* el cliente, no *qué hace*. **Confirmación real: PENDIENTE (requiere Docker).** | Detectar por **comportamiento**: tasa de requests por IP, ráfagas de 404/403, barrido de rutas, payloads con sintaxis SQL/traversal en los parámetros sin importar la UA. Correlacionar por IP/sesión en ventanas de tiempo y complementar con fingerprinting del cliente (orden de headers, TLS/JA3). La UA pasa a ser un indicio más, no la condición. |
| sqli-union | La firma exige un **espacio literal** entre `UNION` y `SELECT`. Se evade con otra cadena de igual efecto en SQL: `UNION/**/SELECT` (comentario en lugar de espacio), `UNION%0aSELECT` (salto de línea), `UNION+SELECT`, mayúsculas/minúsculas mezcladas, `UNION ALL SELECT`, `UNION(SELECT ...)`, o doble URL-encoding si el IDS no decodifica. **Confirmación real: PENDIENTE (requiere Docker).** | **Normalizar antes de comparar** (URL-decode repetido, quitar comentarios `/*...*/`, colapsar whitespace, minúsculas) y matchear con una regex tolerante (ver P2). Sumar reglas de **comportamiento** (ráfagas de errores SQL, `ORDER BY n` incremental, respuestas anómalamente largas) y, como defensa de fondo, consultas parametrizadas en la app: el WAF es una capa extra, no el arreglo. |

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
Se parte de que la regla original equivale a buscar `union select` con un espacio literal (supuesto
a partir del enunciado; el texto real está en `/soc/reglas`, PENDIENTE requiere Docker). Regla propuesta:
normalizar el input (URL-decode dos veces, reemplazar `/*...*/` por un espacio, colapsar whitespace)
y luego aplicar, sin distinguir mayúsculas:

```
\bunion\b(?: all| distinct)? ?\(?\s*select\b
```

Prueba real offline en Python 3 (la columna "orig" es **nuestro supuesto** de la regla literal
`union select`; "nueva" es normalización + regex propuesta):

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
Cuando se pueda ver el log real (PENDIENTE requiere Docker), hay que identificar qué campo hacía
distinguible la línea intrusiva y escribir la regla concreta sobre ese campo.

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
| 19/11/2026 | Lectura del enunciado; redacción de informe y research con asistencia de Claude Code; prueba offline de la regex de P2. Entorno no levantado (sin Docker). | COMPLETAR |
| COMPLETAR | Levantar el entorno, capturar R1–R5, completar sección 1 y confirmar las evasiones de la sección 2. | COMPLETAR |
