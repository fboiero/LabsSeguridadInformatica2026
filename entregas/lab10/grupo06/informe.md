# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 06
**Fecha:** 30/10/2026

| Nombre y apellido    | Usuario de GitHub |
| -------------------- | ----------------- |
| Martín Beccereca     | martinbeccereca   |
| Belén Benito         | belubenito603     |
| Alejo José De Miguel | AlejoDM           |
| Tomás Giudici        | TomasGiudici      |
| Carolina Suppo       | carosuppo         |

## 0. Declaración de uso de IA

**Herramienta:** Claude Code.

- **Finalidad del uso:** apoyo para acceder a la vista `/soc` y capturar su línea base antes de cualquier prueba del grupo, y para redactar la estructura inicial del informe, la fila de R1 en la tabla de flags, el contexto de la vista del SOC y la respuesta a P1.
- **Partes asistidas:** estructura de `entregas/lab10/grupo06/`, fila "R1 — Vista inicial del SOC" en la tabla de flags, subsección "Contexto de la vista `/soc`" y respuesta a P1.
- **Verificación:** la consulta a `/soc` se ejecutó con `curl` de solo lectura contra `phantomcorp`, dentro del contenedor `cyberlab-attacker`, antes de generar cualquier tráfico de prueba; la salida se guardó cruda y sin editar en `evidencia/salidas/`. La respuesta a P1 describe limitaciones generales de la detección por firma, citando únicamente lo que el ruleset del lab ya hace explícito en el enunciado de R4 (el espacio exigido por `sqli-union`), sin adelantar trabajo de R2-R5 que corresponde a otros responsables. Se revisó el contenido antes de incorporarlo.

**Herramienta:** Codex (OpenAI).

- **Finalidad del uso:** apoyo para ejecutar y documentar R2 dentro del contenedor autorizado, y para redactar la fila `scanner-ua` y la respuesta P2.
- **Partes asistidas:** evidencia de la alerta R2, registro de la flag, tabla de firmas para `scanner-ua`, respuesta P2 y bitácora.
- **Verificación:** la solicitud usó únicamente `curl -A sqlmap http://phantomcorp/` desde `cyberlab-attacker`; se contrastó el texto del informe contra la respuesta HTTP cruda y el verificador oficial.

**Herramienta:** Codex (OpenAI).

**Finalidad y partes asistidas:** apoyo para la ejecución de R3 y revisión limitada del aporte P2.
**Verificación realizada:** contraste con el ruleset HTTP real, aceptación de la flag por el motor oficial y comprobaciones locales de la expresión propuesta.

**Herramienta:** ChatGPT (OpenAI), aporte P5.

- **Finalidad del uso:** asistencia para analizar los registros del SOC, identificar y correlacionar el evento de intrusión, validar la flag y redactar la documentación del Reto 5.
- **Partes asistidas:** evidencia y análisis de R5, respuestas P4 y P5, registro de comandos y revisión de integración.
- **Verificación:** se analizó la línea base del SOC conservada por el grupo, se identificó el evento `ALERT[path-traversal]` y se comprobó que no correspondía a las pruebas propias. La flag fue aceptada mediante una copia temporal del validador compatible con Linux.

**Herramienta:** Opencode.

- **Finalidad del uso:** apoyo para ejecutar y documentar la evasión controlada del reto R4 y componer la fila `sqli-union` de la tabla de firmas, junto con su registro en la bitácora.
- **Partes asistidas:** conservación de la evidencia cruda de R4 (respuesta del request, resultado en el log del SOC y aceptación de la flag), fila `sqli-union` en la tabla de firmas y aporte P4 en la bitácora.
- **Verificación:** el request único se ejecutó con `curl` contra `http://phantomcorp/api`, desde `cyberlab-attacker` dentro de Docker, usando únicamente la condición publicada por el ruleset de R3 (`union\s+select`, que exige un espacio). El informe contrasta la respuesta cruda, la ausencia de alertas en el log del SOC y la aceptación por el verificador oficial (5/5 consolidado).

## 1. Flags capturadas (salida de `./ctf status 10`)

_Las cinco flags tienen evidencias individuales de obtención o envío. Además, se revalidaron desde un progreso vacío con una copia temporal de los scripts y manifiesto normalizada a LF: R1–R5 fueron aceptadas y el estado resultante fue 5/5. La salida cruda es [status-10-revalidado-lf.txt](evidencia/salidas/status-10-revalidado-lf.txt). Los archivos originales CRLF no fueron modificados._

| Reto                                    | Estado                                                     | Evidencia                                                                                                                                                                                                                                                                   |
| --------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1 — Vista inicial del SOC              | Obtenida; envío en una sesión anterior                     | [Línea base del SOC](evidencia/salidas/r1-soc-inicial.txt) y [envío de R1](evidencia/salidas/r1-submit.txt)                                                                                                                                                                 |
| R3 — Ruleset publicado                  | Obtenida y aceptada en esta sesión                         | [Ruleset original](evidencia/salidas/r3-ruleset.txt), [envío R3](evidencia/salidas/r3-submit.txt) y [estado parcial](evidencia/salidas/status-10-p3.txt)                                                                                                                    |
| R2 — Detección por User-Agent           | Obtenida; respuesta asociada a `scanner-ua`                | [Respuesta y alerta `scanner-ua`](evidencia/salidas/r2-scanner-ua.txt) y [envío de R2](evidencia/salidas/r2-submit.txt)                                                                                                                                                     |
| R4 — Evasión controlada de `sqli-union` | Obtenida y validada en esta sesión                         | [Respuesta cruda del request](evidencia/salidas/r4-evasion-controlada.txt), [SOC tras la prueba](evidencia/salidas/r4-soc-despues.txt), [envío R4](evidencia/salidas/r4-submit.txt) y [estado consolidado](evidencia/salidas/status-10.txt). Flag `FLAG{signature_evaded}`. |
| R5 — Intrusión en el ruido              | Evento identificado; flag validada mediante flujo temporal | [Línea base completa](evidencia/salidas/r5-soc-completo.txt), [evento identificado](evidencia/salidas/r5-correlacion-log.txt) y [validación temporal](evidencia/salidas/r5-status-10.txt). Flag `FLAG{intrusion_in_the_noise}`.                                             |

### Contexto de la vista `/soc` (línea base, R1)

`GET /soc` devuelve, antes de cualquier prueba del grupo, 120 líneas de tráfico más el mensaje de acceso con la flag de R1. Cada línea tiene la estructura `<origen> - <método> <ruta> <código> <etiqueta>`: una IP de origen, el verbo y la ruta solicitados, el código HTTP de respuesta y una etiqueta `BENIGN` o `ALERT[<firma>]` con, en algunos casos, un comentario adicional. Esta línea base es la referencia contra la que se compara todo lo que el grupo genere después: cualquier evento nuevo que aparezca tras una prueba propia debe poder explicarse por esa prueba, y todo lo que no se explique así es candidato a intrusión real (R5).


## 2. Tabla de firmas

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| `scanner-ua` | La detección observada se activa cuando el cliente declara una User-Agent reconocida como herramienta de escaneo. Un atacante podría declarar una User-Agent de navegador para evitar esta firma aislada. Esta evasión no fue probada en el laboratorio. | No confiar únicamente en la User-Agent. El ruleset identifica nombres como `sqlmap`, `nikto`, `nmap` o `dirb`, pero eso no demuestra la intención del cliente. Correlacionar esta señal con rutas solicitadas, parámetros sospechosos, frecuencia, errores HTTP y secuencias de enumeración. Incorporar límites de tasa y detección de comportamiento. |
| `sqli-union` | Demostrado en R4: la firma publicada utiliza `union\s+select`, que reconoce espacios en blanco entre ambas palabras. Se envió `UNION/**/SELECT`, utilizando un comentario SQL como separador. La respuesta del laboratorio confirmó que ninguna firma detectó la solicitud y entregó la flag correspondiente. Esto demuestra la evasión de esa firma concreta, no de todas las posibles defensas. | Normalizar los parámetros antes de analizarlos, considerando la misma decodificación que realiza la aplicación. Como mejora conceptual, utilizar la expresión `(?i)\bunion(?:\s|/\*[\s\S]*?\*/)+select\b`, que reconoce espacios y comentarios de bloque. Validarla con pruebas de regresión y falsos positivos. Complementar con consultas parametrizadas, controles de acceso, correlación de eventos y revisión humana. Ninguna firma es perfecta. |

## 3. Preguntas P1–P5

**P1.** ¿Por qué la detección por firmas es evadible por diseño? ¿Qué la complementa?

Una firma detecta una **cadena o patrón concreto**, no la intención ni el efecto de una acción. Para que funcione, el defensor tiene que anticipar de antemano exactamente qué forma va a tener el ataque: un User-Agent, una secuencia literal como `UNION SELECT `, una ruta. El problema es que casi siempre existen muchas formas distintas de lograr el mismo efecto sin que ninguna de ellas calce con la cadena exacta que la regla busca. En R4, por ejemplo, el ruleset de este lab exige un espacio después de `UNION SELECT` para disparar la firma `sqli-union`; para el intérprete SQL, un espacio y un comentario `/**/` son equivalentes como separador, pero para una regla que busca el carácter espacio literal, no lo son. La firma es evadible porque codifica una **forma superficial** del ataque, no su significado.

Esto no es un defecto corregible de una vez: es una limitación estructural de cualquier sistema que decida "coincide / no coincide" contra un conjunto finito de patrones conocidos. Siempre va a quedar afuera alguna variante sintáctica, codificación o transformación que un atacante puede probar. Por eso la detección por firma nunca debería ser la única capa. Se complementa con: (a) **validación y parametrización en la aplicación**, que elimina la causa raíz en vez de solo detectar el síntoma; (b) **normalización/canonicalización** de la entrada antes de aplicar la firma, para que variantes de encoding o espaciado converjan a una forma comparable; (c) **detección por comportamiento y correlación**, que mira patrones de uso (frecuencia, secuencia de endpoints, volumen) en vez de una cadena puntual; y (d) **revisión humana**, porque ninguna de las capas anteriores sustituye el criterio de alguien que mire el log completo y note lo que no encaja. R5 ilustra otra limitación: la firma de traversal sí etiquetó el evento, pero la señal quedó mezclada en la línea base y no recibió priorización ni seguimiento.

**P2.** La firma `sqli-union` exigía un espacio. Reescribí la regla para que NO se evada con `/**/`. ¿Se puede hacer una firma "perfecta"?

La fuente observada es [el ruleset crudo de R3](evidencia/salidas/r3-ruleset.txt): `el query matchea /union\s+select/`. Aunque su nota dice «un ESPACIO», `\s+` normalmente expresa uno o más caracteres de espacio en blanco, no exclusivamente un espacio ASCII. No se inspeccionó la implementación: el modo de comparación, la decodificación y el motor no se deducen de esa descripción. La limitación relevante es que un comentario no coincide con `\s+`.

Una propuesta conceptual, en sintaxis de expresiones regulares de Python, es:

```text
(?i)\bunion(?:\s|/\*[\s\S]*?\*/)+select\b
```

El modificador `(?i)` ignora mayúsculas; los límites `\b` delimitan las palabras; el grupo repetido acepta espacios en blanco o comentarios de bloque completos, incluso combinados. `[\s\S]*?` incluye saltos de línea y termina en el primer cierre del comentario. Así reconoce `UNION/**/SELECT`, además de `UNION SELECT` y mezclas de ambos separadores. Es una propuesta para detección: no se instaló ni se probó una evasión HTTP de R4.

Antes de inspeccionar, extraer el parámetro con la misma decodificación que la aplicación, con límites de tamaño y costo de procesamiento. Una alternativa es canonicalizar comentarios ordinarios como espacios y aplicar `(?i)\bunion\s+select\b`. Esto requiere un analizador compatible con el dialecto y contexto: no eliminar comentarios dentro de cadenas ni tratar comentarios ejecutables de ciertos dialectos como si fueran espacios inocuos. Conservar tanto el original como la representación normalizada permite auditar la decisión. No decodificar repetidamente sin límite.

No hay una firma perfecta: esta propuesta cubre el separador solicitado, pero no todo SQLi, variantes de dialecto o diferencias entre parsers. Texto legítimo como documentación que incluya `UNION/**/SELECT` también podría coincidir. Se deben evaluar falsos positivos con tráfico representativo, acotar la inspección por contexto y probar regresiones. La aplicación debe usar consultas parametrizadas, validación de entradas y privilegios mínimos de BD; correlación y revisión humana complementan las alertas. Una coincidencia de regex no prueba explotación ni compromiso.

**P3.** Detectar por User-Agent: ¿por qué es una detección débil? ¿Qué mirarías en lugar de "quién dice ser"?

Porque el User-Agent es un campo de cabecera del cliente y no una prueba de autenticidad ni de intención. Cualquier cliente puede enviarlo arbitrariamente; un atacante puede declarar `Mozilla/5.0`, un navegador o incluso un valor genérico, y la regla deja de distinguir entre una herramienta de escaneo y un usuario normal. En el laboratorio, la firma `scanner-ua` observada depende de que el cliente diga literalmente `sqlmap`; eso la vuelve frágil, fácil de evadir y poco confiable como indicador de riesgo. Además, un User-Agent sospechoso no prueba que una petición sea maliciosa: existen herramientas legítimas, navegadores con extensiones, proxies, bots de validación y clientes internos que pueden reutilizar cabeceras de navegador o modificarlas por conveniencia.

En lugar de mirar "quién dice ser", conviene analizar el comportamiento. La señal más útil es la combinación de método HTTP, ruta, parámetros, frecuencia, secuencia de requests, volumen, tiempo de respuesta, errores, y la relación entre varios eventos desde la misma IP. Un atacante que está enumerando endpoints o probando payloads suele generar patrones muy distintos a los de un usuario normal, aunque su User-Agent sea indistinguible. Por eso una detección robusta correlaciona el valor del User-Agent con rutas sospechosas, parámetros anómalos, respuestas con errores, ráfagas de escaneo y cambios de comportamiento en ventanas cortas de tiempo. El User-Agent puede conservarse como una señal de baja confianza, pero no como criterio único ni como prueba de explotación.

**P4.** El R5: la intrusión estaba en el log. ¿Qué habría hecho que se detecte automáticamente y no dependiera de que alguien la mire?

La intrusión del Reto 5 podría haberse detectado automáticamente mediante una regla de correlación en el SOC o en un SIEM que analice los registros HTTP.

En nuestro caso, encontramos una solicitud desde la IP `185.220.101.42` hacia `/admin/../../etc/passwd`, con respuesta HTTP 200 y una alerta `path-traversal`. Este evento se diferenciaba del tráfico habitual, que consistía principalmente en consultas al catálogo, y ya estaba presente antes de que nuestro grupo realizara sus pruebas.

Propondríamos una regla que detecte solicitudes con secuencias de recorrido de directorios, como `../`, especialmente cuando intentan acceder a archivos sensibles. La alerta debería registrar el origen, la ruta, el método HTTP, la respuesta del servidor y el momento del evento.

Como mejora, también se podría correlacionar esa señal con varias solicitudes sospechosas provenientes del mismo origen dentro de una ventana de cinco minutos, aumentando la prioridad si se observan rutas sensibles o respuestas exitosas. Sin embargo, una única solicitud claramente sospechosa también debería generar una alerta, aunque no supere un umbral de frecuencia.

Esta detección permitiría que el equipo de seguridad reciba una notificación y revise el evento sin depender exclusivamente de una inspección manual de los logs.

De todas formas, la alerta no demuestra por sí sola que se haya comprometido el sistema. Un código HTTP 200 no garantiza que el archivo solicitado se haya leído. Sería necesario revisar la respuesta y otros registros disponibles para confirmar el impacto.

También podrían existir falsos positivos o variantes que no coincidan con la regla. Por eso, la correlación debe complementarse con validación de rutas en el servidor, controles de acceso y revisión humana.

**P5.** Cierre del curso: recorriste ataque (05–08), agentes (09) y defensa (10). ¿Qué cambió en cómo pensás la seguridad?

A lo largo de los laboratorios fuimos cambiando nuestra manera de entender la seguridad informática. Al principio nos enfocábamos principalmente en descubrir vulnerabilidades y comprobar si podían explotarse, pero después comprendimos que también es importante analizar qué consecuencias tienen y cómo podemos prevenirlas o detectarlas.

En los laboratorios 05 y 06 aprendimos a reconocer y enumerar servicios. En el 07 trabajamos con vulnerabilidades que permitían realizar acciones no autorizadas, y en el 08 analizamos las posibilidades y los riesgos que aparecen después de obtener acceso a un sistema.

En el Laboratorio 09 incorporamos la automatización mediante agentes, entendiendo que pueden facilitar determinadas tareas, pero que necesitan límites claros y supervisión humana.

Finalmente, el Laboratorio 10 nos permitió observar las mismas actividades desde el punto de vista del defensor. Aprendimos que no alcanza con detectar una cadena sospechosa: también necesitamos interpretar registros, relacionar eventos y distinguir entre tráfico normal, pruebas autorizadas e intentos de intrusión.

Como conclusión, entendimos que Red Team y Blue Team se complementan. Conocer cómo se realiza un ataque nos ayuda a diseñar mejores defensas, y comprender cómo funciona la detección nos permite evaluar con mayor criterio los riesgos de seguridad.

Nos llevamos una visión más completa: la seguridad no consiste solamente en encontrar fallas, sino también en prevenirlas, detectarlas y responder de manera fundamentada.

## 4. Bitácora

### P3 — Consulta del ruleset y validación de R3 (2026-10-23)

Los comandos HTTP se ejecutaron desde `cyberlab-attacker`, la misma consola usada por `make shell`, mediante `docker exec` en modo no interactivo. Los comandos de administración de Docker se ejecutaron desde la raíz del repositorio en el host. El registro ampliado se conserva en [evidencia/comandos.txt](evidencia/comandos.txt).

1. **Consulta inicial y diagnóstico.** Se consultó el ruleset:

   ```bash
   docker exec cyberlab-attacker bash -c 'curl -sS http://phantomcorp/soc/reglas'
   docker inspect cyberlab-phantomcorp --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}'
   docker exec cyberlab-attacker bash -c 'curl -sS -i http://phantomcorp/'
   ```

   La primera consulta devolvió `Not Found` ([salida conservada](evidencia/salidas/r3-intento-target-lab09.txt)). Las etiquetas del contenedor indicaron el compose de Lab 09 y el portal respondió con el banner `PhantomCapstone/1.0`.

2. **Activación del target correcto y captura de R3.**

   ```powershell
   docker compose -p cyberlab --project-directory . -f entorno/docker-compose.yml -f labs/lab10-deteccion-evasion/entorno/target.compose.yml up -d --build phantomcorp
   docker exec cyberlab-attacker bash -c 'curl -sS http://phantomcorp/soc/reglas' > entregas/lab10/grupo06/evidencia/salidas/r3-ruleset.txt
   ```

   El [ruleset obtenido](evidencia/salidas/r3-ruleset.txt) publicó cuatro firmas y la flag de R3. El reemplazo del target inició otra sesión: sus logs no deben considerarse una continuación de la línea base anterior de R1.

3. **Validación de la flag y consulta del progreso.** Por los finales de línea CRLF de Windows, el motor se ejecutó en una copia temporal normalizada a LF dentro del contenedor, sin alterar sus archivos originales. Desde la raíz de esa copia se ejecutó:

   ```bash
   bash ./ctf submit 10 R3 'FLAG{signature_ruleset}'
   bash ./ctf status 10
   ```

   El verificador [aceptó R3](evidencia/salidas/r3-submit.txt). El [estado parcial](evidencia/salidas/status-10-p3.txt) mostró únicamente R3, 1/5: no se encontró el archivo de progreso anterior al preparar la copia. Se conservan las evidencias históricas de R1/R2 sin atribuirles validación actual. Se copió el progreso generado al host mediante:

   ```powershell
   docker cp cyberlab-attacker:/tmp/lab10-p3/.progreso/10.done .progreso/10.done
   ```

4. **Comprobación de la regla propuesta para P2.** Se envió un script por entrada estándar a `docker exec -i cyberlab-attacker python3 -`. Los [ocho casos locales](evidencia/salidas/p3-regresion-regla.txt) verificaron espacios, comentarios, límites de palabras y un posible falso positivo. No generaron solicitudes HTTP ni constituyen una ejecución de R4.

### P4 — Evasión controlada de `sqli-union` (2026-10-28)

Al iniciar la sesión, los contenedores del laboratorio estaban detenidos desde la anterior; se levantó el target del Lab 10 con el mismo comando documentado por P3 en `evidencia/comandos.txt`, lo que reconstruyó los contenedores e inició una sesión de logs nueva. Antes de generar tráfico de prueba se verificó el objetivo: `curl -sS http://phantomcorp/soc/reglas` devolvió el ruleset del Lab 10 y confirmó la condición exacta de la firma — `sqli-union` matchea `/union\s+select/`, que exige un espacio. La prueba se basó únicamente en esa fuente publicada; no se leyó `server.py` ni `retos.manifest` para obtener rutas, reglas o flags.

El registro cronológico completo queda en [evidencia/comandos.txt](evidencia/comandos.txt).

1. **Supuestos anotados antes del request.** El endpoint `/api` con parámetro `q` es el indicado por el README del lab (`curl -s "http://phantomcorp/api?q=..."`); el separador `/**/` sustituye al espacio que la propia nota del ruleset menciona. Un solo request, sin automatización de variantes ni extracción de datos.

2. **Prueba mínima.** Se ejecutó `curl -sS -i "http://phantomcorp/api?q=1%20UNION/**/SELECT%20null,null--"` desde `cyberlab-attacker`. La [respuesta cruda](evidencia/salidas/r4-evasion-controlada.txt) es `200 OK (procesado como benigno)` y el texto `Tu request ERA maliciosa pero NINGUNA firma la detectó`, con `FLAG{signature_evaded}`. La primera captura llegó al host en UTF-16 por la redirección de PowerShell; el archivo se reescribió con el mismo contenido de texto y no se repitió ningún request HTTP para ello.

3. **Comprobación en el SOC.** Después de la prueba, `curl -sS http://phantomcorp/soc` ([snapshot en `r4-soc-despues.txt`](evidencia/salidas/r4-soc-despues.txt)) reproduce la vista íntegra: sin alertas de `sqli-union`, sin eventos nuevos y sin rastro del request propio; sus últimas 125 líneas coinciden línea a línea con la línea base de R1. La evasión no dejó traza en el log: la firma literal no disparó nada.

4. **Envío de la flag y estado.** El verificador oficial se ejecutó en copia temporal (`/tmp/lab10-p4`) con `ctf`, `bin/lib/*.sh` y `retos.manifest` normalizados a LF para eliminar el CRLF de Windows. En `.progreso/10.done` se sembraron los retos ya validados por el grupo en sesiones previas (R1, R2, R3 y R5, respaldados por sus respectivas evidencias) para reflejar el progreso consolidado; en esta sesión solo se envió R4, [aceptado](evidencia/salidas/r4-submit.txt), y `./ctf status 10` mostró los cinco retos completos ([conservado en `status-10.txt`](evidencia/salidas/status-10.txt)). El progreso consolidado se copió al host con `docker cp`.
