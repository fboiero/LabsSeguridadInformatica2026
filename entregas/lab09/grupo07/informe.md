# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 07 · **Fecha de corte:** 19/11/2026 (America/Argentina/Buenos_Aires).
**Autor de la auditoría:** Lorenzo Blanc — @LoloBlanc — legajo 15034.
**Proveedor usado:** mock, sin API key.

Este informe integra los aportes B de Fernando y C de Lorenzo. La corrida auditada por Lorenzo es complementaria a las capturas operativas de Fernando y no es el transcript de su aporte ni una ejecución del esqueleto de Lautaro. Al incorporar las corridas restantes habrá que revisar diferencias y auditar el esqueleto propio.

## 0. Declaración de uso de IA

Para el aporte de Lorenzo se utilizó Codex para inspeccionar los módulos autorizados, ejecutar la referencia en Docker, preparar pruebas aisladas y redactar la auditoría. Afecta esta sección, la sección 3 y los archivos de evidencia de C. El asistente contrastó el análisis con el código, el transcript, los resultados completos de las tools y las pruebas sin red. Lorenzo debe revisar y comprender el aporte para su defensa; no se afirma que ya haya realizado esa revisión personal.

El motor `mock` del laboratorio emitió las acciones de la corrida auditada por Lorenzo: sigue un plan determinista y no llama a una API de razonamiento.

Para el bloque B, Fernando usó OpenAI Codex para redactar P1 y P3 y preparar comprobaciones locales. Contrastó las respuestas con la consigna y el contrato de los adaptadores de `llm.py`. La prueba de P1 usa `ClienteOpenAI` con respuestas fijas e interceptadas en el transporte; no ejecutó el proveedor ni el agente de pentest. La declaración afecta sus respuestas y comprobaciones, cuya salida se adjunta para revisión. [Bitácora de Fernando](evidencia/comandos-fernando.txt).

**Lautaro Mariño — Parte A (agente propio, `agente_esqueleto.py`):** se utilizó **Claude (Anthropic)** como asistente, en dos aspectos. **Redacción:** ayudó a resolver los tres TODO del loop de tool-use y a redactar la sección 2 a partir del análisis de Lautaro, que revisó y ajustó el código y el texto antes de commitearlo. **Contraste de pruebas:** sirvió de soporte para probar el loop, mediante una suite de pruebas aisladas sin red (`evidencia/pruebas_esqueleto.py`) y una corrida del agente propio en modo mock contra el target oficial del Lab 09 levantado en un sandbox Linux sin Docker (`phantomcorp -> 127.0.0.1`). **Verificación:** las cinco flags del transcript provienen de las respuestas del servicio en ejecución, no de leer el código del target ni `solucion.md`; la realimentación (TODO 3) se verificó con una prueba que condiciona el `POST /api/vault` a haber recibido el token por `resultados`. No se ejecutaron proveedores reales ni se subieron API keys. El esqueleto no se copió de `agente_pentest.py`.

## 1. Flags capturadas

El checkout local de Fernando registró **0/5 flags** al 19/11/2026; esta captura no representa un estado consolidado del grupo. Siguen pendientes las corridas oficiales y sus transcripts. Las cinco flags de la corrida complementaria de C no prueban que se hayan enviado al CTF ni que R5 se haya obtenido con el agente propio. C no envió flags. [Estado local de Fernando](evidencia/salidas/status-09-fernando.txt).

## 2. Tu agente

Entrego `src/agente_esqueleto.py` completo y corriendo. Los tres TODO del loop de tool-use quedaron resueltos así:

- **Fin (`tipo == "final"`):** cuando el cliente ya no pide más tools, imprimo su texto de cierre y corto el loop.
- **Despacho de tool:** cada acción `tool` se ejecuta por el único punto de ejecución `ejecutar_tool(accion["nombre"], accion["argumentos"])`, que pasa sí o sí por los guardrails de `herramientas.py`. El agente no ejecuta nada por fuera de ahí.
- **Realimentación:** devuelvo al cliente una lista `[{"id": accion["id"], "output": salida}]`. El `id` ata cada observación a la acción que la pidió; es lo que permite encadenar (usar en el `POST` el token que apareció en el `GET` anterior).

Mantengo la condición de parada del esqueleto: `MAX_PASOS = 12`. Si el cliente nunca responde `final`, el `for` termina sin `break` y se informa el corte por límite de pasos (es un guardrail de parada, no una auditoría completa). En `src/` copié además `herramientas.py` y `llm.py` sin modificar, porque el esqueleto los importa; son copias de referencia y no se debilitan sus límites.

**Corrida (mock).** Corrí `LLM_PROVIDER=mock python3 agente_esqueleto.py` contra el target oficial del lab (`entorno/phantomcorp/server.py`) levantado tal cual (= CMD del Dockerfile) en un sandbox Linux sin Docker, con `phantomcorp -> 127.0.0.1`. El loop recorrió los 8 pasos del plan y reportó las 5 flags, incluida la capstone de R5 por el encadenamiento `GET /api/token` -> `POST /api/vault`:

- R1 `FLAG{agente_primer_recon}` — header `X-Recon-Flag` en `GET /`.
- R2 `FLAG{agente_ruta_oculta}` — ruta sacada de `robots.txt`.
- R3 `FLAG{agente_api_expuesta}` — `GET /api/debug`.
- R5 `FLAG{agente_esqueleto_completo}` — `POST /api/vault` con el token.
- R4 `FLAG{guardrail_fuera_de_alcance}` — el paso 8 intenta `nmap_scan(8.8.8.8)` y el guardrail lo bloquea localmente antes de ejecutar nada.

[Transcript de la corrida](evidencia/salidas/transcript-esqueleto-mock.txt) · [contexto: fecha, versiones, entorno](evidencia/salidas/contexto.txt) · [comandos y procedencia](evidencia/comandos-lautaro.txt).

**Qué prueba la corrida mock y qué no.** El paso 1 (`nmap_scan`) devolvió `error nmap: ... 'nmap'` porque el sandbox no tenía nmap instalado; el loop siguió sin romperse y R1 salió igual del header HTTP. La corrida demuestra que el loop ejecuta las tools, realimenta con el `id` correcto y llega a R5. **No** demuestra razonamiento ni extracción dinámica del token: `ClienteMock` sigue un plan fijo y lleva el token escrito en `PLAN`, no lo deduce del resultado del paso 6 (coincide con lo que señala la auditoría de la sección 3). Para probar que es la realimentación —y no el plan fijo— la que habilita el encadenamiento, agregué pruebas aisladas (abajo). El encadenamiento dinámico con un LLM real se vería con `LLM_PROVIDER=claude|openai`; no lo ejecuté (sin API key, y no se suben keys al repo).

**Pruebas del loop (sin red).** `evidencia/pruebas_esqueleto.py` inyecta clientes-doble y reemplaza `ejecutar_tool`, sin tocar phantomcorp ni lanzar procesos. Cubre las cuatro situaciones del reparto y pasan todas ([salida](evidencia/salidas/pruebas-esqueleto.txt)):

1. Acción `final`: corta el loop y no ejecuta ninguna tool.
2. Realimentación / encadenamiento: el doble **solo** propone el `POST /api/vault` si recibió el token por `resultados`, y verifica que el `id` realimentado sea el de la acción. Así el TODO 3 queda probado con independencia del plan del mock.
3. Tool desconocida / error: `ejecutar_tool` devuelve un string de error y el loop continúa y lo realimenta sin caerse.
4. Agotamiento del límite: un cliente que nunca termina corta exactamente en `MAX_PASOS` e informa el corte.

El envío de las flags al CTF (`./ctf submit 09 ...`) y el `status 09` en 5/5 se hacen desde el host con Docker; no se ejecutaron en este sandbox. Según el reparto, B adjunta además la corrida de este mismo esqueleto en el entorno oficial.

## 3. Auditoría crítica del agente — Lorenzo

### Evidencia y método

Se ejecutó `labs/lab09-agentes/src/agente_pentest.py` de `upstream/main@a1abb79`, con el target Docker del lab 09. Se leyeron únicamente los módulos autorizados del agente, sin leer código del target ni soluciones. El único objetivo operativo fue el contenedor `phantomcorp`.

- [Transcript sin anotaciones](evidencia/salidas/transcript-referencia.txt).
- [Resultados completos por tool, JSONL](evidencia/salidas/resultados-tools.jsonl).
- [Fecha UTC y versión de Python del contenedor](evidencia/salidas/contexto.txt).
- [Salida de las pruebas aisladas](evidencia/salidas/pruebas-auditoria.txt).
- [Comandos y procedencia](evidencia/comandos.txt).

La consola de referencia muestra solo las primeras 12 líneas de cada resultado. `capturar_referencia.py` registra además el retorno completo de las tools en JSONL sin cambiar argumentos, salidas ni validaciones. El análisis se mantiene separado del transcript crudo. La hora UTC de la captura corresponde al 19/11/2026 por la noche en Argentina.

### Decisión por decisión

Los números coinciden con `[paso n]` del transcript. La decisión humana es el juicio de esta auditoría, no una segunda operación ejecutada.

| Paso y acción | ¿La habría tomado el humano? | Evidencia y evaluación |
|---|---|---|
| 1. `nmap_scan(phantomcorp)` | Sí: reconocer servicios antes de elegir herramientas de aplicación. | El escaneo `-Pn -sV --top-ports 50` agotó el timeout de 60 s. No hay inventario de servicios confirmado. No reintentaría idénticamente sin analizar el timeout; ajustaría una prueba acotada dentro del alcance. La cobertura prevista tampoco incluía todos los puertos ni UDP. |
| 2. `GET /` | Sí: comprobar disponibilidad de la aplicación tras el fallo del escaneo. | HTTP 200 y flag R1 en `X-Recon-Flag`. Fue útil porque HTTP funcionó pese al timeout de nmap. Esto no explica por sí solo la causa del timeout ni confirma una vulnerabilidad explotable. |
| 3. `GET /robots.txt` | Sí: revisar pistas públicas de enumeración. | HTTP 200 con `Disallow: /vault-interno-x7`. `robots.txt` informa a crawlers; no implementa autorización ni vuelve privada una ruta. |
| 4. `GET /vault-interno-x7` | Sí, después de corroborar la pista anterior. | HTTP 200 y flag R2. La secuencia es coherente, pero el mock ya tiene la ruta escrita en `PLAN`: no demuestra descubrimiento dinámico. |
| 5. `GET /api/debug` | Sí, como consulta de enumeración de la aplicación autorizada. | HTTP 200 con `debug: true` y flag R3. Confirma exposición en esta respuesta. El endpoint está prefijado en el mock; no hubo deducción del modelo. |
| 6. `GET /api/token` | Sí: obtener el token antes de intentar el vault. | HTTP 200 con token ficticio y descripción de uso. Un operador validaría status y estructura antes de continuar. |
| 7. `POST /api/vault` con JSON | Sí, si usa el token recibido y la operación está autorizada. | HTTP 200, `ok: true` y flag capstone. El mock envía un token fijo de su plan; no lo extrae del paso 6. El éxito con la referencia no acredita R5 con el esqueleto propio. |
| 8. `nmap_scan(8.8.8.8)` | No lo propondría en una auditoría real; aquí es el caso negativo previsto por R4. | Se devuelve el bloqueo local antes de ejecutar nmap. La respuesta no contiene información obtenida de esa dirección. |
| Fin, siguiente llamada al cliente | Sí: detenerse al recibir `tipo=final`. | Se termina por agotamiento del plan, no por evaluación de cobertura. El resumen lista cinco flags, pero no severidades, impacto ni recomendaciones por hallazgo. |

### Aciertos, errores y eficiencia

La secuencia evita repetir rutas y obtiene respuestas útiles con pocas consultas HTTP. Tras el timeout de nmap, verificar HTTP fue una decisión razonable; sin embargo, el mock la habría tomado con cualquier resultado anterior. No hay evidencia de que haya diagnosticado el error.

El despacho centralizado restringe los nombres a `TOOLS`, cada tool comprueba alcance y el loop realimenta el resultado con el `id` de la acción. Las flags se deduplican. Son propiedades del programa, no pruebas de la calidad de razonamiento de un modelo real.

La limitación principal es que `ClienteMock.paso()` ignora `resultados`. Tanto la ruta como el token ya están escritos. Una prueba aislada entrega `HTTP 500 sin token` en todos los pasos y confirma que aun así se propone el POST. El mock sirve para demostrar el circuito, pero esta corrida no mide adaptación, alucinaciones ni calidad de Claude/OpenAI. No se ejecutaron esos proveedores.

No hay recuperación explícita ante errores ni comprobación de precondiciones entre pasos. El timeout observado consumió un minuto sin producir un inventario y la auditoría se declaró completa igualmente. El mensaje final debería distinguir una finalización del plan de una cobertura satisfactoria.

La allowlist tampoco valida los argumentos: las pruebas muestran `TypeError` al omitir `url` y `AttributeError` si no es textual. `ejecutar_tool()` no normaliza esas excepciones y la referencia no las captura alrededor del despacho; podrían interrumpir el loop.

La lectura HTTP se limita a 4096 bytes (2048 en errores) y la consola a 12 líneas por resultado. Puede perderse contexto; el JSONL conserva el retorno de la tool, pero no recupera bytes que esta nunca leyó. El límite de 12 pasos frena un loop infinito, aunque no establece presupuesto de API, bytes o duración total.

Por lectura de `llm.py`, los adaptadores reales devuelven solo la primera tool cuando una respuesta contiene varias, aunque guardan el mensaje completo. Haría falta gestionar todos los IDs o exigir una única llamada para mantener un historial consistente. Es una limitación estática; no se probó con una API.

### R4: bloqueo y límites de la validación

`ALCANCE` contiene únicamente `phantomcorp`. `_verificar_alcance()` compara el host extraído con ese conjunto. Para `8.8.8.8` devuelve un mensaje de bloqueo y `nmap_scan()` retorna antes de `subprocess.run()`. La flag R4 forma parte de esa respuesta local del guardrail, no proviene de la máquina externa.

La prueba negativa verifica nmap, GET y POST con el destino fuera de alcance. Durante todas las pruebas se sustituyen `subprocess.run` y `urllib.request.urlopen` y se exige que no hayan sido llamados. Así se comprueba el orden de rechazo sin lanzar procesos ni requests externos.

Ese caso confirma el rechazo de un destino directo concreto. No demuestra seguridad completa:

| Límite | Qué se verificó y qué no |
|---|---|
| Parser manual | `_host_de()` usa reemplazos y cortes de texto. La fixture `http://phantomcorp:80@externo.invalid/` pasa el guardrail, mientras el parser estándar identifica `externo.invalid` como host. Se prueba solo como texto, sin pasarla a una tool ni intentar acceso externo. |
| Redirecciones HTTP | Las tools validan la URL inicial y usan `urlopen` sin revalidación explícita por salto. La prueba usa `HTTPRedirectHandler.redirect_request()` para construir un Request externo con dominio `.invalid`, sin abrirlo. Demuestra que el handler estándar admite ese salto; no afirma que el target lo haya servido ni que se haya realizado una conexión. |
| Puertos y resolución | La fixture `http://phantomcorp:9999/` es aceptada. El control limita el nombre, no puertos ni direcciones resueltas. No se probó DNS rebinding ni se afirma que haya ocurrido. |
| Contenido no confiable | Las respuestas del target se realimentan al cliente. Un modelo real podría seguir instrucciones inyectadas; no se observó ese ataque en el mock. El prompt no sustituye las restricciones del ejecutor. |

### Controles adicionales propuestos

Se proponen sin quitar el alcance, la allowlist ni el límite actual. Este aporte no modifica las tools oficiales.

1. Parsear URLs con `urllib.parse.urlsplit`; permitir solo HTTP/HTTPS, rechazar credenciales embebidas y validar hostname y puertos autorizados. Validar tipos, campos requeridos, tamaños y campos extra antes del despacho; convertir errores en resultados estructurados.
2. Desactivar redirecciones o comprobar cada salto y destino resuelto antes de abrirlo. Controlar proxies y restringir la salida del contenedor al target y puertos aprobados. Con proveedor real, separar su acceso a la API del tráfico de las tools ofensivas.
3. Mantener 12 pasos y sumar límites de tiempo total, requests, reintentos, repeticiones, bytes y costo de API. Registrar el motivo de corte y distinguirlo de una auditoría completada.
4. Exigir status y estructura esperados antes de encadenar; obtener el token de la respuesta real. Tratar resultados HTTP como datos no confiables y pedir revisión humana para efectos no previstos en la autorización.
5. Registrar tool, argumentos sin secretos, decisión de alcance, duración, errores y evidencia por hallazgo. Separar confirmado, inferido y no probado; revisar manualmente las conclusiones sin respaldo.

### Verificación y estado para integrar

Pasaron seis pruebas aisladas: bloqueo de las tres tools antes de efectos, rechazo de tool desconocida, errores de argumentos, discrepancia del parser y ausencia de restricción de puerto, construcción de redirección sin I/O y mock independiente de resultados. Son pruebas de auditoría de los módulos oficiales; no son las pruebas del loop de Lautaro.

La corrida real respalda los HTTP 200, las cinco flags en la referencia, el timeout de nmap y el bloqueo R4. Falta contrastar los transcripts de B y el esqueleto de A, especialmente fin, manejo de errores, límite y extracción del token. No se certifica la entrega grupal ni el estado 5/5 del CTF.

El validador general falló sobre el checkout Windows por CRLF en los scripts;
se conserva esa salida en `evidencia/salidas/validar-repo.txt`. Se ejecutó sin
modificarlo sobre una exportación `git archive HEAD` de la base oficial en el
contenedor y pasó los seis chequeos (`validar-repo-exportado.txt`). Esto verifica
el material base del repositorio; las seis pruebas anteriores verifican el
bloque de auditoría. `git diff --cached --check` señala espacios presentes en
headers y líneas vacías del transcript crudo: se conservan para no alterar la
evidencia. El resto de archivos del aporte pasa el control de espacios.

## 4. Preguntas de análisis

**P1 — el loop de tool-use.** El programa anfitrión presenta al cliente un conjunto de herramientas. El cliente puede devolver una acción `tool` con nombre, argumentos e identificador; el anfitrión valida y, si está permitida, ejecuta la herramienta. Después devuelve la salida asociada a ese identificador. El cliente recibe la observación y puede proponer otra herramienta o responder `final`. Esa respuesta cierra el ciclo, mientras que el presupuesto de pasos limita su duración. [Consigna](../../../labs/lab09-agentes/README.md) · [Contrato del cliente](../../../labs/lab09-agentes/src/llm.py).

En la prueba local, el adaptador devolvió `normalizar_nombre` con el texto `"  Ana  "` y el identificador `local-01`; la operación de ejemplo devolvió `ana`. El adaptador asoció el resultado a un mensaje de rol `tool` con el mismo `tool_call_id`, y luego normalizó la respuesta simulada a `final`. [Salida de la prueba local](evidencia/salidas/pruebas-locales-fernando.txt).

**P2 — LLM vs. script fijo:** pendiente de Guadalupe.

**P3 — ventaja del diseño agnóstico.** El programa usa el contrato común `crear_cliente(system, tools)` y `cliente.paso(resultados)`: envía resultados con `id` y `output`, y recibe acciones `tool` o `final`. Cada adaptador traduce ese contrato al formato de su proveedor. Por ejemplo, Claude vincula el resultado mediante `tool_use_id` en un bloque `tool_result`, mientras que OpenAI usa `tool_call_id` en un mensaje de rol `tool`.

Así, cambiar `LLM_PROVIDER` permite usar los adaptadores disponibles sin reescribir la gestión de acciones ni los controles de las herramientas. El modo `mock` permite probar el intercambio con un plan fijo y sin credenciales. Los proveedores reales pueden elegir acciones distintas según los resultados, por lo que sus decisiones todavía requieren evaluación. [Implementación de adaptadores](../../../labs/lab09-agentes/src/llm.py) · [Configuración y modo mock](../../../labs/lab09-agentes/README.md).

**P4 — dos riesgos y su guardrail:** pendiente de Guadalupe.

**P5 — por qué los labs 05–08 eran requisito:** pendiente de Guadalupe.

El mini-research y el armado final corresponden a Guadalupe según el reparto.
