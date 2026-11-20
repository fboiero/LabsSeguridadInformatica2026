# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 06
**Fecha:** 30/10/2026
**Proveedor usado:** mock

| Nombre y apellido    | Usuario de GitHub |
| -------------------- | ----------------- |
| Martín Beccereca     | martinbeccereca   |
| Belén Benito         | belubenito603     |
| Alejo José De Miguel | AlejoDM           |
| Tomás Giudici        | TomasGiudici      |
| Carolina Suppo       | carosuppo         |

## 0. Declaración de uso de IA

**Herramienta:** Claude Code.

- **Finalidad del uso:** apoyo para correr el agente de referencia en modo `mock` contra `phantomcorp`, armar la estructura inicial de la entrega y redactar la fila de R1 en la tabla de flags, la auditoría de los pasos 1-2 del transcript y la respuesta a P1.
- **Partes asistidas:** estructura de `entregas/lab09/grupo06/`, fila "R1 — Recon inicial" en la tabla de flags, filas de los pasos 1-2 en la tabla de auditoría, y respuesta P1.
- **Verificación:** el agente de referencia (`agente_pentest.py`) se ejecutó sin modificar, con `LLM_PROVIDER=mock` y sin ninguna API key, dentro del contenedor `cyberlab-attacker`; el transcript completo se guardó sin editar en `evidencia/salidas/referencia-mock.txt`. No se tocó `herramientas.py` ni el guardrail de alcance. Se revisó el contenido antes de incorporarlo.

**Herramienta:** Codex (OpenAI).

- **Finalidad del uso:** apoyo para revisar la evidencia de R2, redactar la respuesta P2 y elaborar el mini-research sobre prompt injection indirecta.
- **Partes asistidas:** fila R2 de flags, pasos 3–4 de la auditoría, respuesta P2, `research.md` y la bitácora de comandos.
- **Verificación:** se contrastó cada afirmación de R2 con el transcript crudo. Las fuentes del research se abrieron y leyeron antes de citarlas.

**Herramienta:** Codex (OpenAI)

- **Finalidad y partes asistidas:** documentación de R3 y del paso 5, síntesis de aciertos y errores P1–P3, ayuda en redacción de respuesta P3 y revisión cruzada de P1.
- **Verificación:** contraste con el transcript crudo existente y con `llm.py`, `herramientas.py` y el esqueleto públicos, sin leer el target ni soluciones. Se intentó presentar exclusivamente R3 al verificador oficial local y se guardó su rechazo sin alterarlo. No se probaron APIs externas ni se realizaron commits o acciones en GitHub.

**Herramienta:** ChatGPT (OpenAI)

- **Finalidad del uso:** asistencia para comprender e implementar el ciclo de herramientas del agente, ejecutar las pruebas en modo `mock`, resolver problemas de compatibilidad entre Windows y Linux y redactar la documentación correspondiente.
- **Partes asistidas:** implementación de `src/agente_esqueleto.py`, sección 2 del informe, respuesta P5 y comandos de ejecución de R5.
- **Verificación:** el agente fue ejecutado dentro del contenedor `cyberlab-attacker` contra el objetivo autorizado `phantomcorp`. Se comprobó el encadenamiento de `/api/token` y `/api/vault`, la detección de la flag R5, el bloqueo por guardrail y la finalización del ciclo. La flag fue aceptada mediante una copia temporal del validador compatible con Linux.

**Herramienta:** Opencode.

- **Finalidad del uso:** apoyo para levantar el entorno del Lab 09, correr el agente de referencia en modo `mock` para capturar el bloqueo de R4, verificar con una captura de paquetes que el intento fuera de alcance no genera tráfico hacia el destino, y redactar la parte documental correspondiente.
- **Partes asistidas:** fila R4 de la tabla de flags, fila del paso 8 en la tabla de auditoría, subsección "El guardrail (R4)" con la matriz riesgo → guardrail → límite residual, respuesta P4, comandos de R4 en `evidencia/comandos.txt` y registro final de las flags restantes (R1, R2, R3 y R5) con su estado en `evidencia/salidas/status-09.txt`.
- **Verificación:** el agente se ejecutó sin modificar, con `LLM_PROVIDER=mock` y sin ninguna API key, dentro del contenedor `cyberlab-attacker`; las salidas se guardaron sin editar en `evidencia/salidas/` (`r4-guardrail.txt`, `r4-no-trafico.txt`, `r4-submit.txt`, `r4-status-09.txt`). No se tocó `herramientas.py`, el guardrail de alcance ni el target, y no se leyó `server.py` ni `retos.manifest`. Se revisó el contenido antes de incorporarlo.

**Herramienta:** Claude Code y ChatGPT, revisión final.

- **Finalidad del uso:** revisión de coherencia del informe, del research y del código antes de la entrega.
- **Partes asistidas:** limpieza de comentarios de plantilla en `src/agente_esqueleto.py` (sin cambiar la lógica del loop; se agregó solo un mensaje al cortar por `MAX_PASOS`), unificación de la tabla de auditoría (pasos 1–8), corrección de afirmaciones que atribuían decisiones adaptativas al cliente `mock`, remoción de notas internas de revisión cruzada y ajustes de redacción en `research.md`.
- **Verificación:** cada corrección se contrastó con `ClienteMock.PLAN` en `llm.py` y con los transcripts crudos de `evidencia/salidas/`. No se volvió a ejecutar el entorno ni se modificaron las evidencias.

## 1. Flags capturadas

**Estado final:** los cinco retos quedaron registrados en el verificador oficial (5/5). Salida completa y sin editar de `./ctf status 09`: [status-09.txt](evidencia/salidas/status-09.txt); presentación de las flags que faltaban registrar al cierre: [submit-final.txt](evidencia/salidas/submit-final.txt).

| Reto                            | Estado   | Evidencia                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1 — Recon inicial              | Obtenida | [Transcript de referencia](evidencia/salidas/referencia-mock.txt) (pasos 1-2) y [envío de R1](evidencia/salidas/r1-submit.txt)                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| R2 — Pista en `robots.txt`      | Obtenida | [Transcript de referencia](evidencia/salidas/referencia-mock.txt) (pasos 3-4) y [rechazo inicial conservado](evidencia/salidas/r2-submit-rechazado.txt). El target devolvió `FLAG{agente_ruta_oculta}` y una validación inicial en una copia temporal la rechazó. El estado final registra R2 como resuelto (ver [submit-final.txt](evidencia/salidas/submit-final.txt) y [status-09.txt](evidencia/salidas/status-09.txt)); las salidas disponibles no permiten atribuir con certeza la causa del rechazo inicial.                                             |
| R3 — API de debug expuesta      | Obtenida | [Transcript del agente](evidencia/salidas/referencia-mock.txt), paso 5: `HTTP 200` y `FLAG{agente_api_expuesta}`. La flag fue aceptada mediante `./ctf submit 09 R3`. Ver [estado confirmado](evidencia/salidas/r3-status-confirmado.txt).                                                                                                                                                                                                                                                                                                                      |
| R4 — Bloqueo por guardrail      | Obtenida | [Transcript de referencia](evidencia/salidas/r4-guardrail.txt), paso 8: `nmap_scan({'host': '8.8.8.8'})` bloqueado antes de ejecutar nmap; captura de red sin paquetes hacia el destino en [r4-no-trafico.txt](evidencia/salidas/r4-no-trafico.txt) y [envío de R4](evidencia/salidas/r4-submit.txt). `./ctf status 09` muestra R4 registrado ([estado](evidencia/salidas/r4-status-09.txt)); el registro local quedó en 1/5 porque los retos presentados anteriormente ya no figuraban en `.progreso` al momento de esta corrida y no se volvieron a reenviar. |
| R5 — Encadenamiento token→vault | Obtenida | [Transcript del agente propio](evidencia/salidas/r5-esqueleto-mock.txt): `GET /api/token` (paso 6) y `POST /api/vault` (paso 7) devuelven `HTTP 200` y `FLAG{agente_esqueleto_completo}`. La flag fue aceptada mediante una copia temporal del validador compatible con Linux; ver [estado de validación temporal](evidencia/salidas/r5-status-09.txt).                                                                                                                                                                                                         |

## 2. Tu agente

Para el Reto 5 completamos el archivo `agente_esqueleto.py` proporcionado por la cátedra, implementando el ciclo de ejecución de herramientas (_tool-use_) del agente.

El programa utiliza `cliente.paso(resultados)` para recibir la siguiente acción, ejecuta las herramientas mediante `ejecutar_tool()` y devuelve sus resultados al cliente en el formato esperado. También identifica las flags presentes en las respuestas y finaliza cuando recibe una acción de tipo `final` o alcanza el límite de 12 pasos establecido por `MAX_PASOS`.

Se ejecutó utilizando **`LLM_PROVIDER=mock`**, sin claves de API. En esta modalidad, el cliente sigue una secuencia de acciones predefinida, por lo que la prueba demuestra el funcionamiento del ciclo, pero no razonamiento autónomo de un modelo de lenguaje.

Durante la ejecución, el agente realizó ocho llamadas a herramientas. En el paso 6, `GET /api/token` devolvió `{"token": "T-9f3k-vault", ...}` y, en el paso 7, el agente envió `POST /api/vault` con `{'token': 'T-9f3k-vault'}`. El servidor devolvió `HTTP 200` y la flag `FLAG{agente_esqueleto_completo}`, que el validador del repositorio registra como resuelta en el [estado final](evidencia/salidas/status-09.txt).

Hay que precisar qué demuestra ese encadenamiento: el token del POST coincide con el devuelto en el paso 6, pero en `ClienteMock.PLAN` ese valor ya está escrito en los argumentos del paso 7. El loop entrega la respuesta del token al cliente; es el cliente `mock` el que no la lee. Con un proveedor real, el modelo tendría que extraer el token de la observación anterior, y eso no se ensayó.

También comprobamos que la solicitud a `8.8.8.8` fue bloqueada por el guardrail, sin ejecutar un escaneo fuera del alcance permitido. La primera ejecución de `nmap_scan` sobre `phantomcorp` terminó por timeout a los 60 segundos; el loop registró el error como resultado y continuó con la siguiente acción del plan.

**Evidencias:** [Código del agente](src/agente_esqueleto.py), [transcript de ejecución](evidencia/salidas/r5-esqueleto-mock.txt), [validación temporal de R5](evidencia/salidas/r5-status-09.txt) y [estado final 5/5](evidencia/salidas/status-09.txt).

**Límites:** No se modificaron las herramientas, los controles de alcance ni el servidor objetivo. Tampoco se utilizaron proveedores externos de LLM. La corrida terminó por la acción `final` tras ocho tools; no llegó a `MAX_PASOS`, así que el corte por agotamiento de pasos está implementado (con su mensaje `[CORTE]`) pero no quedó ejercitado en el transcript. La prueba demuestra que el agente propio ejecuta el ciclo, realimenta resultados, detecta flags y termina dentro del entorno autorizado.

## 3. Auditoría crítica del agente

**Transcript:** la corrida completa y sin editar del agente de referencia está en [referencia-mock.txt](evidencia/salidas/referencia-mock.txt); la del agente propio, con los mismos ocho pasos, en [r5-esqueleto-mock.txt](evidencia/salidas/r5-esqueleto-mock.txt). El bloqueo del paso 8 y su captura de red están en [r4-guardrail.txt](evidencia/salidas/r4-guardrail.txt) y [r4-no-trafico.txt](evidencia/salidas/r4-no-trafico.txt).

<details>
<summary>Transcript completo del agente propio (<code>LLM_PROVIDER=mock python3 agente_esqueleto.py</code>), copiado sin editar de <code>r5-esqueleto-mock.txt</code></summary>

```text

[Paso 1] Tool: nmap_scan
Argumentos: {'host': 'phantomcorp'}
Resultado:
error nmap: Command '['nmap', '-Pn', '-sV', '--top-ports', '50', 'phantomcorp']' timed out after 60 seconds

[Paso 2] Tool: http_get
Argumentos: {'url': 'http://phantomcorp/'}
Resultado:
HTTP 200
Server: PhantomCapstone/1.0 
Date: Mon, 26 Oct 2026 22:55:47 GMT
Content-Type: text/plain; charset=utf-8
X-Recon-Flag: FLAG{agente_primer_recon}

PhantomCorp Capstone. Auditame.

[Paso 3] Tool: http_get
Argumentos: {'url': 'http://phantomcorp/robots.txt'}
Resultado:
HTTP 200
Server: PhantomCapstone/1.0 
Date: Mon, 26 Oct 2026 22:55:47 GMT
Content-Type: text/plain; charset=utf-8

User-agent: *
Disallow: /vault-interno-x7


[Paso 4] Tool: http_get
Argumentos: {'url': 'http://phantomcorp/vault-interno-x7'}
Resultado:
HTTP 200
Server: PhantomCapstone/1.0 
Date: Mon, 26 Oct 2026 22:55:47 GMT
Content-Type: text/plain; charset=utf-8

Ruta interna. FLAG{agente_ruta_oculta}


[Paso 5] Tool: http_get
Argumentos: {'url': 'http://phantomcorp/api/debug'}
Resultado:
HTTP 200
Server: PhantomCapstone/1.0 
Date: Mon, 26 Oct 2026 22:55:47 GMT
Content-Type: application/json

{"debug": true, "flag": "FLAG{agente_api_expuesta}"}

[Paso 6] Tool: http_get
Argumentos: {'url': 'http://phantomcorp/api/token'}
Resultado:
HTTP 200
Server: PhantomCapstone/1.0 
Date: Mon, 26 Oct 2026 22:55:47 GMT
Content-Type: application/json

{"token": "T-9f3k-vault", "uso": "POST /api/vault con {\"token\": ...}"}

[Paso 7] Tool: http_post
Argumentos: {'url': 'http://phantomcorp/api/vault', 'data': {'token': 'T-9f3k-vault'}}
Resultado:
HTTP 200
{"ok": true, "flag": "FLAG{agente_esqueleto_completo}"}

[Paso 8] Tool: nmap_scan
Argumentos: {'host': '8.8.8.8'}
Resultado:
BLOQUEADO POR GUARDRAIL: '8.8.8.8' esta FUERA DE ALCANCE. El agente NO ejecuta acciones fuera del scope autorizado. FLAG{guardrail_fuera_de_alcance}
[FINAL] Auditoría simulada completa. Revisá las flags en el transcript.

=== Flags encontradas (5) ===
  FLAG{agente_api_expuesta}
  FLAG{agente_esqueleto_completo}
  FLAG{agente_primer_recon}
  FLAG{agente_ruta_oculta}
  FLAG{guardrail_fuera_de_alcance}
```

</details>

**Aciertos y errores:** la tabla evalúa cada una de las ocho decisiones del transcript. Como criterio general, distinguimos dos planos: el **loop** (ejecuta la tool, realimenta el resultado y respeta el alcance), que es lo que la corrida sí demuestra, y el **cliente** que propone las acciones. En esta corrida el cliente es `ClienteMock`, cuyo método `paso` ignora `resultados` y recorre `PLAN` en orden fijo; por eso ninguna fila atribuye una decisión a lo observado en el paso anterior, y cada una se evalúa como lo haría un operador humano revisando la secuencia.

| Paso | Acción solicitada                                                                       | Resultado observado                                                                                                     | Evaluación                                                                                                                                                                                                                                                                                                                                                    |
| ---- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | `nmap_scan({'host': 'phantomcorp'})`                                                    | `error nmap: Command [...] timed out after 60 seconds`                                                                  | **Acierto de elección, error de resultado.** `nmap -sV` es un primer paso de recon estándar (Lab 05), pero consumió 60 s sin identificar servicios. La causa del timeout no está diagnosticada. Un operador habría reintentado con un escaneo más acotado; la tool actual no permite elegir puertos ni opciones, y el plan pasa a otra acción sin reintentar. |
| 2    | `http_get({'url': 'http://phantomcorp/'})`                                              | `HTTP 200` con header `X-Recon-Flag: FLAG{agente_primer_recon}` y cuerpo "PhantomCorp Capstone. Auditame."              | **Acierto.** Consulta a la raíz, acotada al objetivo, que encuentra la flag R1 en un header en un solo pedido. Que ocurra después del timeout no demuestra que el cliente haya reaccionado al error: es el segundo elemento fijo de `PLAN`.                                                                                                                   |
| 3    | `http_get({'url': 'http://phantomcorp/robots.txt'})`                                    | `HTTP 200` con `Disallow: /vault-interno-x7`                                                                            | **Acierto.** `robots.txt` es enumeración de bajo impacto y entregó una pista concreta. El archivo no impone control de acceso; solo comunica una preferencia a rastreadores, por lo que la ruta debía confirmarse.                                                                                                                                            |
| 4    | `http_get({'url': 'http://phantomcorp/vault-interno-x7'})`                              | `HTTP 200` y `Ruta interna. FLAG{agente_ruta_oculta}`                                                                   | **Acierto con salvedad.** Una única consulta confirma el recurso, sin adivinar rutas adicionales. Pero la URL ya está en `PLAN`: no demuestra que el cliente haya extraído la ruta del paso 3. Tampoco implica que toda ruta de un `robots.txt` sea sensible o accesible en otros sistemas.                                                                   |
| 5    | `http_get({'url': 'http://phantomcorp/api/debug'})`                                     | `HTTP 200`, `Content-Type: application/json` y `{"debug": true, "flag": "FLAG{agente_api_expuesta}"}`                   | **Acierto con salvedad.** Confirma una API de diagnóstico expuesta con una sola consulta. **Error de método:** ningún resultado previo apunta a `/api/debug`; la ruta proviene del plan, no de una enumeración. Un agente real necesitaría descubrirla (wordlist, enlaces, documentación) y eso no se evaluó.                                                 |
| 6    | `http_get({'url': 'http://phantomcorp/api/token'})`                                     | `HTTP 200` y `{"token": "T-9f3k-vault", "uso": "POST /api/vault con {\"token\": ...}"}`                                 | **Acierto.** Obtiene la credencial necesaria para el reto R5. Igual que en el paso 5, la ruta no surge de una observación previa. La respuesta incluye instrucciones de uso: es justamente el tipo de contenido del target que un LLM real leería como guía y que debe tratarse como dato no confiable.                                                       |
| 7    | `http_post({'url': 'http://phantomcorp/api/vault', 'data': {'token': 'T-9f3k-vault'}})` | `HTTP 200` y `{"ok": true, "flag": "FLAG{agente_esqueleto_completo}"}`                                                  | **Acierto de resultado, encadenamiento no demostrado.** El servidor acepta el token y devuelve la flag R5. El token del POST coincide con el del paso 6, pero está escrito en `PLAN`: la corrida prueba la secuencia, no la extracción dinámica. Además es la única acción con efecto potencial (POST con credencial) y se ejecutó sin aprobación previa.     |
| 8    | `nmap_scan({'host': '8.8.8.8'})`                                                        | `BLOQUEADO POR GUARDRAIL ... FLAG{guardrail_fuera_de_alcance}`, sin ejecutar nmap; captura sin tráfico hacia el destino | **Error del cliente, acierto del control.** Proponer un host fuera de alcance es un error grave para un agente de pentest. El intento está prefijado en el plan para probar el guardrail, así que demuestra el control y no un desvío real de un modelo. El bloqueo en la capa de ejecución no depende de que un humano esté mirando la corrida.              |

**Síntesis.** Aciertos: las ocho acciones son pertinentes, no hay pedidos repetidos, cada recurso se confirma con una sola consulta y el único intento fuera de alcance fue bloqueado. Errores y límites: el timeout del paso 1 consumió 60 s sin aporte ni reintento; los pasos 4, 5, 6 y 7 usan rutas y argumentos que el cliente no derivó de las observaciones; el POST del paso 7 no pasó por ninguna aprobación; y la corrida no permite saber qué haría el agente si el target respondiera distinto. El loop realimenta resultados correctamente, pero esta ejecución `mock` no demuestra decisiones adaptativas.

**El guardrail (R4):**

En el paso 8 del transcript de referencia (`evidencia/salidas/r4-guardrail.txt`) el motor propuso `nmap_scan({'host': '8.8.8.8'})`. `ejecutar_tool` despachó esa tool y, antes de lanzar nmap, `nmap_scan` invocó `_verificar_alcance('8.8.8.8')`: el host no está en `ALCANCE` (que contiene únicamente `phantomcorp`), por lo que la función devolvió un mensaje de bloqueo generado localmente — que incluye la flag de R4 — y el escaneo nunca se ejecutó. La corrida del agente propio muestra el mismo bloqueo en su paso 8.

Para verificar que el bloqueo ocurre antes de que salga cualquier paquete hacia el destino, se corrió dentro de `cyberlab-attacker` un script de captura (`evidencia/salidas/r4-captura-no-trafico.py`) que escucha en vivo la interfaz de red mediante un socket `AF_PACKET` mientras invoca las tools directamente, sin modificar `herramientas.py` ni el guardrail. Salida cruda: `evidencia/salidas/r4-no-trafico.txt`.

| Llamada                                       | Duración | Paquetes IP capturados                | Paquetes hacia 8.8.8.8 |
| --------------------------------------------- | -------- | ------------------------------------- | ---------------------- |
| `http_get http://phantomcorp/` (en alcance)   | 0.05 s   | 12 (destinos 172.21.0.2 y 172.21.0.3) | 0                      |
| `nmap_scan host=8.8.8.8` (fuera de alcance)   | 0.00 s   | 0                                     | 0                      |
| `http_get http://8.8.8.8/` (fuera de alcance) | 0.00 s   | 0                                     | 0                      |

La llamada en alcance funciona como control positivo: la captura ve tráfico legítimo hacia la red interna, así que el cero de las otras dos no se debe a que la captura no funcionara. Los dos intentos fuera de alcance devolvieron el bloqueo de forma inmediata (0.00 s es un valor redondeado; un `nmap` real consumió 60 s en el paso 1) y sin un solo paquete hacia `8.8.8.8`. La captura respalda el bloqueo en esa ventana e interfaz; no se documentó una prueba equivalente para `http_post` fuera de alcance.

Por qué importa: el límite no está en el prompt sino en la capa de ejecución. El intento de salir de alcance ya está prefijado en el plan del motor (`ClienteMock.PLAN` lo incluye a propósito); con un proveedor real, ese mismo intento podría surgir de una alucinación o de una instrucción inyectada en la respuesta del target. Un prompt puede ser ignorado o inducido; la validación en la función de la tool no se puede "persuadir", se aplica a toda URL/host antes de ejecutar la operación.

**Límite residual detectado en el código (no ensayado):** `http_get` valida la URL original, pero `urllib.request.urlopen` sigue redirecciones HTTP automáticamente: si `phantomcorp` respondiera con una redirección hacia un host externo, la petición final escaparía del guardrail a nivel de red. Un control complementario sería revalidar cada redirección o desactivar los redirects automáticos. No se probó porque exigiría modificar el target o las tools, lo cual está prohibido.

### Matriz riesgo → guardrail → límite residual

| Riesgo                                                                                                                    | Guardrail que lo mitiga                                                                                                                                                  | Límite residual                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| El agente ataca un host fuera del alcance (decisión errónea, alucinación o pista maliciosa del target).                   | Validación de alcance exacta por host/URL en cada tool (`_verificar_alcance`), aplicada antes de toda acción.                                                            | Vive en el mismo proceso que las tools: editar el código o agregar una tool sin validación lo anula. Las redirecciones HTTP se siguen después de validar la URL original. No se comprobó un aislamiento general de la red del laboratorio; una política de salida a nivel de red sería una segunda barrera. |
| Ejecución de acciones no autorizadas o arbitrarias (una tool inventada, parámetros absurdos).                             | Allowlist cerrada: `ejecutar_tool` solo despacha nombres registrados en `TOOLS` y devuelve "tool desconocida" en cualquier otro caso.                                    | El esquema de argumentos es descriptivo, no tipado: la allowlist limita qué se puede ejecutar, no con qué parámetros ni con qué intención dentro del alcance.                                                                                                                                               |
| El agente no termina nunca (loop infinito, costo y tráfico desmedidos).                                                   | `MAX_PASOS` (12) corta el ciclo; las tools tienen timeout (nmap 60 s, HTTP 10 s).                                                                                        | No limita el costo por paso ni el volumen total de peticiones al target dentro del alcance autorizado.                                                                                                                                                                                                      |
| Acción de alto impacto dentro del alcance (por ejemplo, el `POST /api/vault` con credencial del paso 7).                  | Ninguno específico: el host permitido basta para que se ejecute.                                                                                                         | Restringir métodos, rutas y parámetros por tarea y exigir aprobación humana previa para POST u operaciones con credenciales.                                                                                                                                                                                |
| Instrucciones maliciosas en la respuesta del target (prompt injection indirecta) que "piden" acciones fuera de la misión. | El contenido se realimenta como dato (mensaje de resultado de tool, no instrucción del sistema) y toda acción resultante vuelve a pasar por la allowlist y el guardrail. | El texto inyectado entra al contexto sin marcado ni sanitización: puede sesgar decisiones legítimas dentro del alcance aunque no consiga ejecutar nada fuera de él.                                                                                                                                         |

## 4. Preguntas de análisis

**P1 — el loop de tool-use.**

El loop de tool-use tiene cuatro piezas que se repiten hasta una condición de corte: (1) un cliente de LLM —o, en modo `mock`, un motor determinista— propone una acción; (2) el programa ejecuta únicamente una herramienta de la allowlist, nunca una acción arbitraria elegida libremente por el modelo; (3) el resultado de esa herramienta se devuelve al cliente como nueva observación; y (4) el ciclo vuelve al paso 1 hasta que el cliente emite una acción final o se alcanza `MAX_PASOS`.

En la corrida de referencia (`evidencia/salidas/referencia-mock.txt`), el paso 1 ejecuta `nmap_scan({'host': 'phantomcorp'})`; el timeout resultante se entrega al cliente antes del paso 2. El paso 2 es `http_get` a la raíz y devuelve la flag de R1. Esto demuestra que el loop ejecuta y realimenta resultados en el formato previsto. Sin embargo, `ClienteMock.paso` ignora `resultados` y avanza por `PLAN`: la secuencia observada es fija y no demuestra que el motor haya elegido el segundo paso por el timeout ni que se adaptaría ante una respuesta distinta. Con un proveedor real, esa observación sí podría influir en la acción siguiente, pero eso no se ensayó aquí.

La condición de fin es la otra mitad del diseño: el loop tiene que poder terminar tanto porque el agente decide una acción "final" (como ocurre al cierre del transcript, con el mensaje "Fin: Auditoría simulada completa") como porque se agota `MAX_PASOS`, para que un modelo que nunca decide finalizar no deje el proceso corriendo indefinidamente. El motor `mock` usado en esta corrida no tiene razonamiento real —sus decisiones están prefijadas—, pero respeta exactamente esta misma estructura de loop, que es la pieza que sí se evalúa en R5 con el esqueleto propio del grupo.

**P2 — LLM vs. script fijo.**

Un LLM puede interpretar una observación nueva y elegir la siguiente acción sin que todas las bifurcaciones estén programadas de antemano. En el recorrido esperado, tras recibir de `robots.txt` la ruta `/vault-interno-x7`, puede decidir que esa ruta es una pista pertinente y consultar solo ese recurso. Esa adaptación es útil cuando el target devuelve rutas, parámetros, tecnologías o errores que no se conocían al escribir el programa. Con un proveedor real, además, la decisión puede variar según el contexto recibido; el modo `mock` del laboratorio imita la interfaz y el ciclo, pero usa un plan fijo y por ello no demuestra razonamiento generativo.

Un script fijo como `recolector.py` del Lab 08 hace mejor una tarea estrecha, conocida y repetitiva: recorre un rango definido, aplica la misma regla a cada respuesta, ofrece resultados predecibles y es más fácil de probar, auditar y acotar en costo. No interpreta una pista nueva por sí mismo; habría que programar explícitamente que lea `robots.txt`, extraiga una directiva y consulte la ruta. Por eso la elección no es entre “LLM bueno” y “script obsoleto”: el LLM aporta adaptación bajo controles, mientras que el script aporta determinismo cuando el flujo ya está definido.

En ambos casos, la salida del modelo o el contenido recibido del target no debe convertirse directamente en una acción. En este lab, `ejecutar_tool` y la validación de alcance son la barrera que evita que una decisión —razonable, errónea o manipulada— alcance otro host.

**P3 — ventaja del diseño agnóstico.**

La ventaja concreta es poder usar el mismo loop con un mock local sin credenciales o con Claude/OpenAI cambiando `LLM_PROVIDER`, sin reescribir el despacho de herramientas ni el control de alcance. Esto permite desarrollar y verificar el flujo sin costo de API y luego sustituir el motor. No implica que los proveedores produzcan decisiones idénticas ni que el mock valide su razonamiento.

El agente se acopla al contrato común de `llm.py`: crea el cliente con `crear_cliente(SYSTEM, TOOLS)` y llama a `cliente.paso(resultados)`. Recibe una acción normalizada de tool (`tipo`, `nombre`, `argumentos`, `id`) o de fin (`tipo`, `texto`); devuelve los resultados como una lista de diccionarios con `id` y `output`. No necesita conocer los formatos particulares de mensajes HTTP de cada proveedor.

Los adaptadores `ClienteClaude` y `ClienteOpenAI` traducen el registro `TOOLS` al esquema de su API y las respuestas al contrato común; `crear_cliente` selecciona la implementación. Por ejemplo, el resultado interno con `id` y `output` se representa como `tool_result` con `tool_use_id` en Claude y como mensaje `tool` con `tool_call_id` en OpenAI. Esa traducción queda fuera del loop. Un proveedor nuevo requeriría implementar el contrato y agregarlo a la fábrica, conservando `ejecutar_tool` y la validación de alcance.

**Límite comprobado en el código:** los adaptadores actuales exponen una sola acción por llamada y no resuelven de forma general respuestas con múltiples llamadas simultáneas. El desacoplamiento es el que ofrece esta interfaz concreta, no compatibilidad universal con cualquier comportamiento de API. Solo se verificó localmente el código y la evidencia mock existente; no se probaron servicios externos.

**P4 — dos riesgos y su guardrail.**

**Riesgo 1: salida de alcance.** Un agente ofensivo que decide por sí mismo puede apuntar a un objetivo equivocado: por alucinación, por seguir una pista que vio en la respuesta del target (un dominio o una IP de un tercero) o por una prompt injection indirecta. En R4 ocurrió literalmente: el motor propuso `nmap_scan({'host': '8.8.8.8'})`. El guardrail que lo mitiga es la validación de alcance en la capa de ejecución: cada tool verifica el host/URL contra `ALCANCE` antes de actuar, y lo hace en código, no en el prompt, por eso no se puede persuadir. Lo comprobamos además a nivel de red: durante los intentos bloqueados no salió ningún paquete hacia `8.8.8.8` (`evidencia/salidas/r4-no-trafico.txt`). Límite residual: el control vive en el mismo código que las tools, y una redirección HTTP del target se seguiría después de validar la URL original.

**Riesgo 2: ejecución de acciones no autorizadas o sin control de fin.** Aun dentro del alcance, el agente puede invocar tools que no existen (desperdiciando pasos del presupuesto), repetir acciones sin información nueva o no terminar nunca, con el costo y el tráfico que eso implica. Los guardrails son la allowlist cerrada de tools — `ejecutar_tool` solo despacha lo registrado en `TOOLS` y rechaza todo lo demás — y el límite de pasos `MAX_PASOS` junto con los timeouts por tool (60 s para nmap, 10 s para HTTP), que cortan el ciclo aunque el modelo nunca emita una acción final. Límite residual: la allowlist restringe qué se ejecuta, no con qué parámetros ni con qué frecuencia dentro del alcance; para acciones de alto impacto haría falta además una aprobación humana previa, que el diseño actual no implementa.

La lección de R4 es que el control debe estar en la función de validación de las tools, aplicada a toda URL/host antes de la ejecución, y no como una instrucción opcional del prompt: el prompt puede ser ignorado o inducido; la capa de ejecución no, mientras no se edite su código.

**P5 — por qué los labs 05–08 eran requisito.**

Los laboratorios 05 al 08 fueron necesarios porque nos permitieron comprender las distintas etapas de una prueba de penetración antes de intentar automatizarlas mediante un agente.

En el **Laboratorio 05** aprendimos a realizar reconocimiento, identificando hosts, servicios y superficie de exposición. En el **Laboratorio 06** profundizamos en la enumeración, buscando rutas, recursos y funcionalidades disponibles en los servicios encontrados.

En el **Laboratorio 07** trabajamos sobre la explotación de vulnerabilidades, comprendiendo cómo una debilidad puede permitir acciones o accesos no autorizados. Finalmente, en el **Laboratorio 08** analizamos qué puede hacerse después de obtener acceso inicial y aprendimos a automatizar tareas repetitivas mediante un script Python.

Estos conocimientos se relacionan directamente con el Laboratorio 09 porque el agente utiliza herramientas que representan varias de esas etapas. Por ejemplo, ejecuta reconocimiento con `nmap_scan`, enumera recursos mediante `http_get` y realiza una secuencia de consultas que termina accediendo al vault mediante `http_post`.

La principal diferencia es que ahora esas acciones están organizadas dentro de un ciclo que puede recibir resultados y utilizarlos para solicitar nuevas herramientas. Sin embargo, en nuestra ejecución con `mock`, las acciones estaban predefinidas y no se eligieron dinámicamente según las respuestas.

Por eso, consideramos que los laboratorios anteriores fueron fundamentales: para diseñar y supervisar un agente no alcanza con saber programar el ciclo, también necesitamos entender qué hace cada herramienta, interpretar sus resultados y reconocer cuándo una acción puede exceder el alcance autorizado.
