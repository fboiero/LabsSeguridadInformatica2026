# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0) · **Fecha:** 2026-11-19 (America/Buenos_Aires)

> Esta edición cubre el bloque de Lorenzo: R2, firma `scanner-ua` y P3. Las demás firmas y preguntas siguen pendientes de sus responsables.

## 0. Declaración de uso de IA

Se usó OpenAI Codex como asistente con acceso a la terminal local para guardar una captura inicial del SOC antes de las pruebas, ejecutar requests HTTP de comparación en el contenedor local, capturar las respuestas, analizar el comportamiento observado y redactar este bloque. La IA ejecutó las requests registradas. No se leyó el código del objetivo. Lorenzo debe revisar y poder explicar los resultados antes de la entrega grupal.

Lautaro Mariño (@lautaromarino0) — bloque C (R4, fila `sqli-union`, P2): se utilizó **Claude (Anthropic)** como asistente, en dos aspectos. **Redacción:** ayudó a redactar la fila `sqli-union`, P2 y esta declaración a partir del análisis de Lautaro, que revisó y ajustó cada texto antes de commitearlo. **Contraste de pruebas:** sirvió de soporte para evadir la firma en el target del Lab 10 corrido en un sandbox Linux (`server.py` en `/app`, `phantomcorp -> 127.0.0.1`): se leyó el ruleset publicado en `GET /soc/reglas` y se mandó un `union/**/select` que pasó como benigno. **Verificación:** no se leyó el código del target ni `solucion.md`; la flag de R4 salió de la respuesta HTTP y se validó su `sha256` contra el hash del reto en `retos.manifest`. El envío al CTF se hace desde el host.

Guadalupe Gómez (@guadagomezgg8) — bloque A (R1/R3/R5 y P1/P4): se utilizó **Claude (Anthropic)** como asistente, en dos aspectos. **Operación:** se corrió el `server.py` del Lab 10 en un sandbox Linux (`phantomcorp -> 127.0.0.1`, caja negra) y la IA ejecutó los requests `GET /soc` y `GET /soc/reglas`, capturó las respuestas y filtró por `ALERT` para aislar la intrusión; la salida quedó en `evidencia/salidas/r1-r3-r5-soc.txt`. **Redacción:** ayudó a redactar las filas R1/R3/R5, P1, P4 y esta declaración a partir de ese análisis. **Verificación:** no se leyó el código del target ni `solucion.md`; las flags salieron de las respuestas HTTP y se validó su `sha256` contra `retos.manifest`. Guada revisa y puede explicar cada resultado; el envío al CTF se hace desde el host.

## 1. Flags capturadas

Estado observado con `./ctf status 10`:

```text
R1  Acceso a la vista del SOC                             resuelto
R2  Disparar una deteccion (te vieron)                    resuelto
R3  Conocer el ruleset del IDS                            resuelto
R4  Evadir una firma de deteccion                          pendiente
R5  Encontrar la intrusion en el ruido                    resuelto
Progreso: 1/5 (20%)
```

R2 se obtuvo por la respuesta directa del detector; no se enviaron flags de los otros retos. La salida completa está en `evidencia/salidas/status-10.txt`.

**Bloque A — acceso al SOC e intrusión (Blue).** Con acceso a la consola del SOC se resolvieron, corriendo el target local y capturando las respuestas en `evidencia/salidas/r1-r3-r5-soc.txt`:

- **R1 — vista del SOC** (`GET /soc`): la consola concede acceso y devuelve `FLAG{soc_log_access}`.
- **R3 — ruleset del IDS** (`GET /soc/reglas`): lista las firmas activas (`scanner-ua`, `path-traversal`, `git-probe`, `sqli-union`) y devuelve `FLAG{signature_ruleset}`.
- **R5 — la intrusión en el ruido**: filtrando por `ALERT` entre 120 accesos benignos a `/catalogo` aparece una sola línea no atribuida al tráfico propio — `185.220.101.42 - GET /admin/../../etc/passwd 200 ALERT[path-traversal]` → `FLAG{intrusion_in_the_noise}`. La captura se tomó antes del tráfico de prueba del grupo, así que esa intrusión es preexistente, no la generamos nosotros.

Las tres flags se verificaron por `sha256` contra `retos.manifest`. Se envían desde el host con `./ctf submit 10 R1`, `R3` y `R5` para actualizar el estado.

## 2. Tabla de firmas

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| scanner-ua | Observado: `GET /` con `User-Agent: sqlmap` respondió `403` y mostró la alerta `scanner-ua`; el mismo `GET /` con una cadena de UA de Chrome respondió `200` sin alerta. Esto demuestra que basta cambiar un encabezado autodeclarado para esquivar esta firma específica. No demuestra que una actividad real de escaneo haya pasado inadvertida, porque aquí se probó la misma ruta simple. | Tratar UA como señal de baja confianza, nunca como identidad ni criterio único de bloqueo. Combinar método, rutas, secuencia, frecuencia, errores, rasgos del payload normalizado y contexto de sesión/IP con logs de proxy, aplicación y endpoint; correlacionar varias señales y alertar ante patrones de reconocimiento aunque la UA parezca normal. La mitigación de detección no corrige la vulnerabilidad que un escáner pudiera encontrar. |
| sqli-union | La firma es `/union\s+select/`: exige **whitespace literal** entre las keywords y se aplica sobre la **ruta cruda**. Enviando `item=1 union/**/select 1,2` (un comentario `/**/` en lugar del espacio) el request se procesa como benigno —no hay `\s` que matchee `\s+`— y devuelve `FLAG{signature_evaded}` (R4; `sha256` verificado contra `retos.manifest`). También la esquiva codificar el espacio (`%20`), porque la firma mira la ruta sin decodificar. Contraste: la firma `scanner-ua` sí dispara con User-Agent `sqlmap`. Ver `evidencia/salidas/r4-evasion.txt`. | No basar la firma en una secuencia literal: **normalizar** la entrada antes de matchear (URL-decode, quitar comentarios `/* */`, colapsar whitespace, minúsculas) y recién ahí aplicar el patrón. Mejor aún, detectar por semántica sobre el query ya parseado. Un patrón literal siempre es evadible con encoding o comentarios: sirve como defensa en profundidad, no como barrera única. |

La captura inicial del SOC (`01:53:56Z`) se tomó antes del tráfico propio y conserva la intrusión preexistente. Tras la alerta, el detector respondió que el request se registró, pero el `/soc` consultado al final mostró el mismo conjunto estático de 120 eventos y no añadió una línea de nuestra prueba; se conservan ambas respuestas para no afirmar una persistencia que no observamos. Ver `evidencia/salidas/baseline-soc-y-reglas.txt` y `evidencia/salidas/prueba-scanner-ua-y-soc-final.txt`.

## 3. Preguntas P1–P5

- **P1 — firmas y límites:** una firma de IDS detecta un **patrón literal conocido** (una secuencia de bytes o una regex) en el tráfico. Su límite es que solo ve lo que ya está escrito como patrón: se esquiva cambiando la forma sin cambiar el efecto. En este lab se vio dos veces: `scanner-ua` mira el `User-Agent` —un dato que el cliente **autodeclara** y puede falsear (`sqlmap` dispara, una UA de Chrome no)— y `sqli-union` exige `union␣select` con **espacio literal** sobre la **ruta cruda**, así que `union/**/select` o `union%20select` pasan. Lo que las complementa: (1) **normalizar** la entrada antes de matchear (URL-decode, quitar comentarios, colapsar espacios, minúsculas) y, mejor, detectar por **semántica** sobre lo ya parseado; (2) **detección por anomalía/comportamiento**, que no busca un patrón fijo sino desvíos de lo normal (rutas, ritmo, errores, secuencia); (3) **correlación** de varias fuentes (proxy, app, endpoint) y de varias señales, porque una sola —como la UA— no acredita nada. Las firmas sirven como defensa en profundidad y para lo conocido, no como barrera única.
- **P2 — regla `sqli-union`:** la regla actual, `/union\s+select/`, falla por dos motivos: exige whitespace literal (se esquiva con `/**/`) y corre sobre la ruta cruda (se esquiva con `%20`). No se arregla **agregando más patrones literales** —es whack-a-mole—, se arregla **normalizando antes de matchear**. Propuesta: (1) URL-decodear el query; (2) eliminar comentarios SQL `/\*.*?\*/`; (3) colapsar todo el whitespace a un espacio y pasar a minúsculas; (4) recién entonces matchear `\bunion\s*select\b`. Así caen `union/**/select`, `UNION  SELECT`, `union%20select` y `uNiOn select`. El límite de palabra `\b` evita falsos positivos con texto benigno que contenga la subcadena pegada dentro de otra palabra. La clave es que la firma mire **lo que el motor SQL va a ejecutar**, no los bytes crudos del request.
- **P3 — confiar en identidad autodeclarada:** el `User-Agent` identifica el software que el cliente dice usar; el servidor no puede autenticarlo por ese campo. La prueba local lo muestra: `curl -A sqlmap` dispara la firma y un `curl` al mismo recurso con una UA de navegador no. Un atacante puede cambiar esa cadena, y una UA legítima también puede producir actividad automatizada. Conviene autenticar usuarios por mecanismos de sesión/credenciales verificables y usar UA solo como contexto. Para detección, correlacionar rutas, métodos, ritmo, errores y respuestas con sesión/cuenta, IP, proxy y telemetría del endpoint; tratar headers de otras zonas de confianza como datos no confiables y registrarlos con validación/escape. Ninguna señal aislada acredita quién está detrás del cliente. [RFC 9110 §10.1.5 — User-Agent](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.5) · [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- **P4 — detección automática de la intrusión:** la intrusión real no era un escaneo ruidoso sino un **único** request —`185.220.101.42 - GET /admin/../../etc/passwd 200 ALERT[path-traversal]`— mezclado entre 120 accesos benignos a `/catalogo`. ¿Qué lo detectaría sin leerlo a mano? (1) Una firma/anomalía de **path traversal** sobre la ruta **normalizada**: `../` repetido y la referencia a `/etc/passwd` son patrones que ningún cliente legítimo del catálogo produce (de hecho el ruleset ya trae la firma `path-traversal`). (2) **Correlación por recurso**: alertar ante accesos a rutas sensibles (`/admin`, archivos del sistema) fuera del conjunto esperado, y marcar un `200` ahí como acceso exitoso a algo que no debería existir. (3) **Correlación por origen**: una IP que hace un solo request anómalo hacia un recurso sensible, distinta del patrón de las demás, se prioriza aunque el volumen sea bajo. La clave: el evento no se caza por **volumen** (fue uno solo) sino por **desvío del patrón normal y por el recurso tocado** —justo lo que aportan la detección por comportamiento y la correlación sobre una firma literal.
- **P5 — relación atacante/defensor:** pendiente — bloque de Fernando.

## 4. Bitácora

Los comandos reproducibles están en `evidencia/comandos.txt`. La captura SOC/ruleset inicial está en `evidencia/salidas/baseline-soc-y-reglas.txt`; las respuestas benignas, la alerta y la captura SOC final están en `evidencia/salidas/prueba-scanner-ua-y-soc-final.txt`.
