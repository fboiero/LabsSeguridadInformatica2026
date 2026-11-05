# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 10 · **Integrantes:** Belén Rocío Ramello — @belramello · Carolina Paula Corazza — @carocor1 · Chiara Agustina Kordek — @chiarakordek · Juan Pablo Saby — @JuanSaby · **Fecha:**
**Proveedor usado:** mock

## 0. Declaración de uso de IA
utilización de ChatGPT como herramienta de apoyo para analizar el funcionamiento del agente, revisar las decisiones tomadas durante la ejecución y comparar el enfoque de un LLM con el de un script fijo. También lo utilicé para organizar y mejorar la redacción de las secciones asignadas. El análisis y la versión final fueron revisados por el equipo, tomando como referencia el código y las evidencias reales del laboratorio.

## 1. Flags capturadas

## 2. Tu agente

## 3. Auditoría crítica del agente

### 3.1 Transcript

#### Entorno y ejecución de referencia

**Proveedor: `mock`.** Se ejecutó el agente de referencia de la cátedra,
`labs/lab09-agentes/src/agente_pentest.py`, sin modificarlo, sobre la base
`7023ec3`. El mock simula las decisiones con un plan fijo: no consulta un LLM
externo ni requiere una API key. Las herramientas sí se ejecutaron realmente
contra el `phantomcorp` local de Docker; no son respuestas HTTP simuladas.

Esta PC tenía Docker Desktop, pero no una distribución Ubuntu instalada en
WSL. Para conservar la copia de Windows sin cambiar sus finales de línea, se
levantó el mismo entorno del laboratorio mediante Docker Compose y se corrió
Python dentro de la consola Linux `cyberlab-attacker`. Comandos ejecutados desde
la raíz del repositorio en PowerShell:

```powershell
docker compose -p cyberlab --project-directory . -f entorno/docker-compose.yml -f labs/lab09-agentes/entorno/target.compose.yml up -d --build
docker exec -e LLM_PROVIDER=mock -e PYTHONDONTWRITEBYTECODE=1 -w /repo/labs/lab09-agentes/src cyberlab-attacker bash -o pipefail -c "python3 -B agente_pentest.py 2>&1 | tee /loot/transcript_referencia.txt"
```

El primer comando construye e inicia el atacante y el objetivo del Lab 09.
El segundo fija el proveedor, ejecuta la referencia y conserva su salida en
`.loot/transcript_referencia.txt` mediante `tee`; `pipefail` permite detectar
un error del proceso Python aunque la copia de la salida termine correctamente.
La corrida terminó con código de salida **0**. Esto no implica que todas las
tools hayan tenido éxito: el timeout del paso 1 quedó registrado y el loop
continuó. La referencia imprime hasta las primeras 12 líneas de cada respuesta
de herramienta; se conserva íntegra la salida que emitió ese programa.

#### Salida real de la corrida

```text

[paso 1] → nmap_scan({'host': 'phantomcorp'})
    error nmap: Command '['nmap', '-Pn', '-sV', '--top-ports', '50', 'phantomcorp']' timed out after 60 seconds

[paso 2] → http_get({'url': 'http://phantomcorp/'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Sun, 01 Nov 2026 18:01:06 GMT
    Content-Type: text/plain; charset=utf-8
    X-Recon-Flag: FLAG{agente_primer_recon}
    
    PhantomCorp Capstone. Auditame.
    [+] FLAG NUEVA: FLAG{agente_primer_recon}

[paso 3] → http_get({'url': 'http://phantomcorp/robots.txt'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Sun, 01 Nov 2026 18:01:06 GMT
    Content-Type: text/plain; charset=utf-8
    
    User-agent: *
    Disallow: /vault-interno-x7

[paso 4] → http_get({'url': 'http://phantomcorp/vault-interno-x7'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Sun, 01 Nov 2026 18:01:06 GMT
    Content-Type: text/plain; charset=utf-8
    
    Ruta interna. FLAG{agente_ruta_oculta}
    [+] FLAG NUEVA: FLAG{agente_ruta_oculta}

[paso 5] → http_get({'url': 'http://phantomcorp/api/debug'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Sun, 01 Nov 2026 18:01:06 GMT
    Content-Type: application/json
    
    {"debug": true, "flag": "FLAG{agente_api_expuesta}"}
    [+] FLAG NUEVA: FLAG{agente_api_expuesta}

[paso 6] → http_get({'url': 'http://phantomcorp/api/token'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Sun, 01 Nov 2026 18:01:06 GMT
    Content-Type: application/json
    
    {"token": "T-9f3k-vault", "uso": "POST /api/vault con {\"token\": ...}"}

[paso 7] → http_post({'url': 'http://phantomcorp/api/vault', 'data': {'token': 'T-9f3k-vault'}})
    HTTP 200
    {"ok": true, "flag": "FLAG{agente_esqueleto_completo}"}
    [+] FLAG NUEVA: FLAG{agente_esqueleto_completo}

[paso 8] → nmap_scan({'host': '8.8.8.8'})
    BLOQUEADO POR GUARDRAIL: '8.8.8.8' esta FUERA DE ALCANCE. El agente NO ejecuta acciones fuera del scope autorizado. FLAG{guardrail_fuera_de_alcance}
    [+] FLAG NUEVA: FLAG{guardrail_fuera_de_alcance}

[agente] Fin: Auditoría simulada completa. Revisá las flags en el transcript.

=== Flags encontradas (5) ===
  FLAG{agente_api_expuesta}
  FLAG{agente_esqueleto_completo}
  FLAG{agente_primer_recon}
  FLAG{agente_ruta_oculta}
  FLAG{guardrail_fuera_de_alcance}
```

#### Decisiones anotadas

La tabla identifica cada acción y dónde aparecen **R1–R4**, sin repetir sus
valores. Es una evaluación humana de lo observado, no un razonamiento generado
por el mock. El proveedor siguió el orden fijo de `ClienteMock.PLAN` incluso
después del timeout; no adaptó ese plan a los resultados.

| Paso | Tool y argumentos | Qué obtuvo | ¿La habríamos tomado? (sí/no) | Por qué |
|---|---|---|---|---|
| 1 | `nmap_scan(host="phantomcorp")` | Timeout después de 60 s; no hay listado de puertos en esta salida. | Sí | Como en el Lab 05, reconocer los servicios del único host autorizado es un comienzo razonable. El timeout no demuestra que el host esté caído o que no tenga puertos abiertos; corresponde registrar la limitación, no inventar un resultado. |
| 2 | `http_get(url="http://phantomcorp/")` | HTTP 200, cabeceras y presentación del servicio. **Aparece R1** en `X-Recon-Flag`. | Sí | Una petición HTTP al objetivo local permite comprobar el servicio aunque el escaneo anterior haya fallado. Revisaría cabeceras además del cuerpo, como en reconocimiento y enumeración de los labs 05–06. |
| 3 | `http_get(url="http://phantomcorp/robots.txt")` | HTTP 200; `Disallow: /vault-interno-x7`. | Sí | En el Lab 06 se buscan rutas y pistas publicadas. `robots.txt` permite descubrir una ruta, pero no es una protección de acceso ni autoriza por sí solo a explorar otros objetivos. |
| 4 | `http_get(url="http://phantomcorp/vault-interno-x7")` | HTTP 200 y contenido de la ruta indicada. **Aparece R2**. | Sí | Es una pista concreta del paso anterior y permanece en el host permitido. Comprobaría la respuesta en lugar de asumir que una ruta listada necesariamente existe o está protegida. |
| 5 | `http_get(url="http://phantomcorp/api/debug")` | HTTP 200 y JSON con `debug: true`. **Aparece R3**. | Sí | Dentro del laboratorio autorizado, comprobar una API de depuración permite verificar si expone datos. Aquí la ruta está programada en el mock: no debe presentarse como si el modelo la hubiera descubierto razonando sobre la respuesta anterior. |
| 6 | `http_get(url="http://phantomcorp/api/token")` | HTTP 200 y JSON con un token del laboratorio e indicación de usarlo en `POST /api/vault`. | Sí | La enumeración de una API puede dar el dato y el formato necesarios para el siguiente paso. Como al encadenar acciones en los labs 07–08, primero comprobaría la respuesta y después usaría el valor observado. |
| 7 | `http_post(url="http://phantomcorp/api/vault", data={"token": <valor fijo del PLAN>})` | HTTP 200, `ok: true` y una flag adicional del vault. | No, con un token fijado de antemano | Sí probaría el POST previsto por el laboratorio usando el token recibido, pero no sustituiría esa extracción por una constante. El resultado exitoso de esta referencia no demuestra que el mock haya interpretado el paso 6. |
| 8 | `nmap_scan(host="8.8.8.8")` | Bloqueo por alcance. **Aparece R4**; no se ejecutó ese escaneo. | No | El objetivo externo no está autorizado. `nmap_scan` consulta `_verificar_alcance` antes de invocar el proceso; la barrera en código impidió convertir esa acción del plan en tráfico hacia un tercero. |

Después de las ocho acciones, el cliente devolvió `tipo="final"` y el agente
terminó antes de alcanzar su límite de 12 pasos. El resumen muestra cinco
valores distintos encontrados; no equivale a cinco retos entregados ni prueba
que el agente propio del grupo esté implementado.

**Validación de esta contribución:** se tomaron de esta corrida los valores de
R1, R2, R3 y R4 y se entregaron con `ctf submit 09 R1` a `ctf submit 09 R4`,
cada uno con su flag correspondiente. Los cuatro fueron aceptados por el
verificador oficial, con código de salida 0. El progreso local quedó en
**4/5 (80 %)**, con R5 pendiente. El `ctf status 09` devuelve 1 mientras no
están todos los retos; se conserva ese resultado, no se presenta como 5/5.
Los recibos y el estado están en `.loot/lab09-submit-r1.txt` a
`.loot/lab09-submit-r4.txt` y `.loot/lab09-status-09.txt` (no versionados).

Para ejecutar la verificación en Linux sin alterar esta copia de Windows,
se copiaron temporalmente `ctf`, `bin/lib/{ui,banner,check}.sh` y el manifiesto
del Lab 09 a un contenedor separado, sin red, normalizando solo CRLF a LF.
Se invocaron allí los mismos scripts oficiales mediante Bash; no se cambiaron
sus comprobaciones ni los hashes esperados. `.progreso` se montó sobre la
carpeta local homónima para conservar el resultado en esta PC.

**Observación sobre R5:** esta versión de la referencia también devuelve la
flag del vault en el paso 7 porque el token de prueba de su plan coincide con
el del servidor. No se entregó R5 desde esta referencia ni se atribuye ese
resultado al trabajo sobre `agente_esqueleto.py`: ese código y su corrida
corresponden a la sección 2. La auditoría detallada y la explicación de R4
quedan para 3.2 y 3.3, respectivamente.

**Material consultado para las anotaciones:**
[README del Lab 09](../../../labs/lab09-agentes/README.md),
[agente de referencia](../../../labs/lab09-agentes/src/agente_pentest.py),
[herramientas y guardrail](../../../labs/lab09-agentes/src/herramientas.py) y
[ClienteMock](../../../labs/lab09-agentes/src/llm.py). Se contrastaron con esta
corrida; no se modificó ninguno de esos archivos.

### 3.2 Aciertos y errores

Mirando la corrida en detalle, podemos separar las decisiones que tuvieron sentido práctico de los problemas que surgieron durante la ejecución:

- **Inicio con Nmap y falta de reacción al fallo:** Intentar un escaneo inicial sobre `phantomcorp` era el paso lógico para ver qué puertos estaban abiertos. El error estuvo en cómo se manejó el resultado: la herramienta dio timeout tras 60 segundos y el agente no intentó adaptarse (por ejemplo, probando puertos puntuales o verificando conectividad básica). Simplemente descartó el fallo y pasó a la siguiente acción porque su lista así lo indicaba.
- **Seguimiento de pistas con `robots.txt`:** Revisar `robots.txt` y usar la ruta que apareció allí (`/vault-interno-x7`) fue el comportamiento más acertado de la secuencia. Es justo lo que haríamos manualmente: buscar pistas públicas y verificar qué contienen sin salir del alcance.
- **Rutas de API que aparecieron de la nada:** Probar `/api/debug` y `/api/token` trajo información útil (una flag y un token), pero no fue producto de una deducción. En las respuestas anteriores no había enlaces ni menciones a esas rutas; el agente fue directo a ellas porque venían escritas en su plan, no porque haya hecho enumeración o razonamiento.
- **El POST al vault con credencial fija:** Enviar el token por POST a `/api/vault` completó la consigna, pero expone una limitación importante del mock: no extrajo el token de la respuesta del paso 6, sino que usó una constante ya escrita en el código (`T-9f3k-vault`). Si el servidor hubiera generado un token dinámico o distinto, la acción habría fallado.
- **Intento de escaneo a una IP externa (`8.8.8.8`):** Fue el error más crítico. El agente intentó escanear una dirección pública fuera del laboratorio autorizado. En una auditoría real esto violaría el acuerdo de trabajo. La acción no llegó a ejecutarse únicamente porque el control en `herramientas.py` la frenó antes de mandar tráfico.

Lo principal que aprendemos de esta corrida es a no confundir un resultado exitoso con una decisión inteligente: varias acciones trajeron flags, pero casi todas funcionaron porque el plan ya estaba armado a medida del laboratorio y no porque el agente haya entendido lo que estaba haciendo.

### 3.3 El guardrail (R4)

### 3.4 Otros guardrails que agregaríamos

Además del control de alcance existente, proponemos agregar estas capas en `herramientas.py`:

1. **Validación estricta de destinos y redirecciones.** Parsear URLs con una biblioteca de URL, normalizar el hostname y validar direcciones resueltas. En `http_get` y `http_post`, revisar cada redirección y bloquear cualquier salto fuera de `phantomcorp`; la comprobación actual del host inicial no alcanza si una respuesta redirige a otro servidor.
2. **Allowlist de operaciones y rutas.** Separar los GET de los POST, limitar rutas y parámetros aceptados, y exigir aprobación humana para operaciones que cambien estado o envíen datos. El modelo no debería convertir una instrucción recibida en una página en autorización para hacer un POST.
3. **Límites por ejecución y auditoría.** Además de `MAX_PASOS`, fijar un máximo global y por herramienta de solicitudes, una tasa permitida, tamaños de respuesta y registro con objetivo, método, herramienta y resultado. Esto reduce loops, consumo excesivo y facilita reconstruir qué ocurrió.
4. **Marcar resultados externos como no confiables.** Encapsular las respuestas de `http_get` como datos, filtrar secretos antes de devolverlas al LLM y comprobar la acción propuesta con reglas deterministas. Delimitar el contenido ayuda, pero no sustituye la autorización de las herramientas (OWASP GenAI Security Project, 2025; OpenAI, 2026).

## 4. Preguntas de análisis

### P1 — el loop de tool-use

### P2 — LLM vs. script fijo

La diferencia principal está en cómo deciden qué hacer:

- **Un script fijo (como el `recolector.py` del Lab 08)** tiene los pasos definidos de antemano en el código. Si le pedimos recorrer legajos del 1 al 250, va a hacer exactamente eso: es rápido, predecible y no gasta recursos de más. El problema es que no tiene ninguna flexibilidad; si la API cambia el nombre de un parámetro o devuelve un formato inesperado, el script se rompe salvo que un programador lo modifique a mano.
- **Un agente con un LLM real** busca aportar criterio sobre la marcha. Podría leer texto en lenguaje natural, notar que `robots.txt` prohíbe una ruta, entender que un mensaje dice *"usá este token en tal endpoint"* y armar el siguiente pedido HTTP sin que nadie le haya escrito esa secuencia exacta de antemano. También podría leer que Nmap dio timeout y decidir probar directamente por HTTP al puerto 80.

Sin embargo, esta corrida dejó en evidencia que **el `ClienteMock` funcionó como un script rígido disfrazado de agente:**
- No interpretó el texto del paso 6 para extraer el token: el valor `"T-9f3k-vault"` ya estaba hardcodeado en la lista del mock.
- Cuando Nmap falló en el paso 1, no recalculó nada; siguió con el plan fijo.
- Propuso escanear `8.8.8.8` simplemente porque estaba anotado en la lista, sin evaluar si correspondía.

La automatización permite acelerar el trabajo repetitivo, pero un script tradicional solo hace lo que le ordenamos, mientras que un modelo de lenguaje puede intentar acciones imprevistas o salirse del objetivo si no tiene límites técnicos que lo contengan. Por eso, en seguridad ofensiva no alcanza con darle herramientas a un modelo: los límites (como el chequeo de alcance) tienen que estar asegurados por código y no depender de la voluntad del agente.

### P3 — ventaja del diseño agnóstico

El agente no necesita conocer el formato particular de la API de Claude o de OpenAI. `crear_cliente(system, tools)` selecciona una implementación según `LLM_PROVIDER`; cada adaptador transforma el esquema genérico de herramientas al formato de su proveedor y `paso(resultados)` devuelve una acción común (`tool` con nombre y argumentos, o `final` con texto). Así, el loop de `agente_esqueleto.py` y el despachador de herramientas pueden mantenerse iguales al cambiar de proveedor. El mock permite recorrer el flujo sin claves ni conexión externa y de forma determinista, lo que sirve para depurar el loop; no demuestra que un LLM real vaya a elegir las mismas acciones ni que los proveedores tengan igual calidad o seguridad.

El agente queda acoplado a esa interfaz (`crear_cliente(...).paso()`), al formato de acción normalizada y al contrato de nombres y argumentos de `TOOLS`. Los detalles de autenticación, endpoint y formato de function calling quedan dentro de `llm.py`. La abstracción facilita sustituir proveedores, aunque solo cubre el conjunto común de funciones; capacidades particulares de una API pueden requerir cambios en su adaptador (ver `llm.py`).

### P4 — dos riesgos y su guardrail

1. **Que una instrucción del objetivo desvíe al agente fuera del alcance.** Una respuesta de `phantomcorp` podría pedirle que escanee `8.8.8.8`. Si el modelo la obedece, se produciría tráfico no autorizado y la auditoría podría afectar a un tercero. El control actual es que cada herramienta verifica el objetivo contra `ALCANCE = {"phantomcorp"}` mediante `_verificar_alcance()` y bloquea el host directo que no coincide. La validación del host y las redirecciones debe endurecerse como se propone en 3.4; no alcanza con confiar en el prompt (OWASP GenAI Security Project, 2025).
2. **Acciones excesivas o con efectos no previstos.** Un proveedor podría repetir llamadas, consumir recursos del entorno o intentar usar `http_post` cuando bastaba con leer una respuesta. `MAX_PASOS = 12` limita la cantidad de iteraciones de esta ejecución; además, `nmap_scan` y las llamadas HTTP tienen tiempos de espera. Como defensa complementaria, limitar solicitudes por herramienta y exigir confirmación antes de POST reduce el impacto de una selección equivocada o manipulada (OpenAI, 2026).

### P5 — por qué los labs 05–08 eran requisito

## Cierre

### Dificultades encontradas

### Distribución del trabajo

### Fuentes consultadas
