# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 02

**Integrantes:**

| Nombre y apellido | Legajo | Usuario de GitHub |
|---|---|---|
| Romero Jimena Soledad | 15377 | @Jimena-Romero |
| Milanesio Hebe Del Lourdes | 15343 | @hebemilanesio1 |
| Toranzo Juan Cruz | 15308 | @JuanToranzo |
| Torres Damaris | 14563 | @damaris412 |

**Fecha:** *23/10/2026*
**Proveedor usado:** mock

## 0. Declaración de uso de IA

Se utilizó Claude (Anthropic) como asistente para: entender el mecanismo del
loop de tool-use (decisión → ejecución → realimentación) antes de completar
los TODO de `agente_esqueleto.py`, para redactar las respuestas de análisis
P1–P5, y para dar formato a la auditoría crítica del agente. La lógica del
loop se completó entendiendo primero `agente_pentest.py` (referencia) y
aplicando el mismo patrón, no copiándolo sin revisar. La corrida se verificó
ejecutando el agente contra el target real `phantomcorp` con `LLM_PROVIDER=mock`.

## 1. Flags capturadas

```
$ ./ctf status 09

  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 09                      │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     El agente hace recon y encuentra el primer flag
   ✓  R2     El agente enumera y sigue la ruta oculta
   ✓  R3     El agente detecta la API expuesta
   ✓  R4     El guardrail rechaza un objetivo fuera de alcance
   ✓  R5     Tu agente encadena token->vault (esqueleto completo)

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 09 COMPLETO! Ponete las pilas con la próxima unidad.
```

## 2. Tu agente

`agente_esqueleto.py` completado en `entregas/lab09/grupo02/src/agente_esqueleto.py`,
junto a copias sin modificar de `herramientas.py` y `llm.py` (necesarias para
que el agente importe los módulos correctamente).

Los 3 TODO resueltos:

- **TODO 1:** si `accion["tipo"] == "final"`, se imprime el texto final y se
  corta el loop con `break`.
- **TODO 2:** si es una tool, se ejecuta con
  `ejecutar_tool(accion["nombre"], accion["argumentos"])` y se guarda la
  salida.
- **TODO 3:** el resultado se empaqueta como
  `[{"id": accion["id"], "output": salida}]` y se pasa a `cliente.paso()` en
  la siguiente vuelta del loop, para que el LLM decida el próximo paso con
  ese contexto.

Salida completa de la corrida (`LLM_PROVIDER=mock python3 agente_esqueleto.py`),
que llega a encadenar `/api/token` → `POST /api/vault` y trae el flag capstone:

```
[paso 1] → nmap_scan({'host': 'phantomcorp'})
    error nmap: Command '['nmap', '-Pn', '-sV', '--top-ports', '50', 'phantomcorp']' timed out after 60 seconds

[paso 2] → http_get({'url': 'http://phantomcorp/'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Fri, 23 Oct 2026 23:39:07 GMT
    Content-Type: text/plain; charset=utf-8
    X-Recon-Flag: FLAG{agente_primer_recon}
    
    PhantomCorp Capstone. Auditame.
    [+] FLAG NUEVA: FLAG{agente_primer_recon}

[paso 3] → http_get({'url': 'http://phantomcorp/robots.txt'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Fri, 23 Oct 2026 23:39:07 GMT
    Content-Type: text/plain; charset=utf-8
    
    User-agent: *
    Disallow: /vault-interno-x7

[paso 4] → http_get({'url': 'http://phantomcorp/vault-interno-x7'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Fri, 23 Oct 2026 23:39:07 GMT
    Content-Type: text/plain; charset=utf-8
    
    Ruta interna. FLAG{agente_ruta_oculta}
    [+] FLAG NUEVA: FLAG{agente_ruta_oculta}

[paso 5] → http_get({'url': 'http://phantomcorp/api/debug'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Fri, 23 Oct 2026 23:39:07 GMT
    Content-Type: application/json
    
    {"debug": true, "flag": "FLAG{agente_api_expuesta}"}
    [+] FLAG NUEVA: FLAG{agente_api_expuesta}

[paso 6] → http_get({'url': 'http://phantomcorp/api/token'})
    HTTP 200
    Server: PhantomCapstone/1.0 
    Date: Fri, 23 Oct 2026 23:39:07 GMT
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

## 3. Auditoría crítica del agente

**Transcript:** ver sección 2 (misma corrida).

**Aciertos y errores, decisión por decisión:**

- **Paso 1 (`nmap_scan phantomcorp`) — error, no del agente sino del entorno.**
  El escaneo tardó más de 60 segundos y el propio código de `herramientas.py`
  lo cortó por timeout. No es una mala decisión del agente — escanear el
  objetivo primero es exactamente el orden correcto de un recon — sino una
  limitación del entorno de red del contenedor Docker. El agente manejó bien
  el fallo: no se quedó trabado, siguió al siguiente paso del plan con la
  salida de error como contexto.
- **Pasos 2–5 (recon web y enumeración) — acierto.** El orden fue lógico y
  eficiente: primero `GET /` (recon inicial, trae la primera flag en un
  header), después `robots.txt` (enumeración), y al ver que `robots.txt`
  revelaba la ruta `/vault-interno-x7`, fue directo a esa ruta sin probar
  rutas al azar. Después detectó `/api/debug` sin pasos de más. Ningún paso
  repetido ni desperdiciado en esta fase.
- **Pasos 6–7 (encadenamiento token→vault) — acierto, es el punto central
  del lab.** El agente pidió el token en `GET /api/token` y, con ese dato en
  mano (que no conocía de antemano, lo obtuvo de un resultado anterior), lo
  usó correctamente en el cuerpo del `POST /api/vault`. Este es justamente
  el comportamiento que un script fijo sin lógica de decisión no podría
  replicar sin que alguien programe ese camino específico de antemano.
- **Paso 8 (`nmap_scan 8.8.8.8`) — intento fuera de alcance, bloqueado
  correctamente.** El motor `mock` tiene este paso fijo en su plan a
  propósito, para probar el guardrail. El agente "intentó" la acción (como
  haría un LLM real que decide explorar una IP mencionada en algún
  contexto), pero el guardrail la interceptó antes de ejecutar nmap de
  verdad.

En general, con el motor `mock` el "razonamiento" es un plan fijo
determinístico, así que no hubo verdaderos errores de criterio para
evaluar — el único punto de fricción real fue el timeout de nmap, que es un
problema de infraestructura, no de lógica del agente.

**El guardrail (R4):**

El guardrail está implementado en `herramientas.py`, en
`_verificar_alcance()`: toda tool (`nmap_scan`, `http_get`, `http_post`)
llama primero a esa función antes de ejecutar nada. Si el host del objetivo
no está en el conjunto `ALCANCE = {"phantomcorp"}`, la función devuelve un
mensaje de bloqueo (con el flag del guardrail incluido) **en vez de**
ejecutar la acción real. En nuestra corrida, el paso 8 intentó
`nmap_scan({'host': '8.8.8.8'})` y el guardrail lo bloqueó antes de que el
nmap llegara a correr de verdad contra una IP real de internet.

Esto es imprescindible porque el LLM, por diseño, puede "decidir" tocar
cualquier objetivo que aparezca mencionado en algún resultado (una IP
externa, un dominio de terceros); sin esta verificación en el código, esa
decisión se ejecutaría sin ningún control humano de por medio.

Otros guardrails que agregaríamos:
- **Rate limiting:** límite de requests por segundo hacia el target, para
  que el agente no pueda saturarlo si entra en un loop de reintentos.
- **Allowlist de puertos/servicios** para `nmap_scan`, no solo de hosts —
  hoy el guardrail valida el host, pero no limita qué puertos puede escanear
  una vez que el host está autorizado.
- **Logging inmutable** de cada acción ejecutada (tool, argumentos,
  resultado, timestamp), guardado aparte del resumen que el LLM genera al
  final — así se puede auditar exactamente qué hizo el agente paso a paso,
  sin depender de que el propio LLM lo reporte fielmente.

## 4. Preguntas de análisis

**P1 — El loop de tool-use, con tus palabras**

El agente funciona en un ciclo de 4 pasos que se repite: (1) el LLM recibe
el estado actual de la conversación y decide una acción — o usar una tool
puntual, o dar una respuesta final; (2) si eligió una tool, el código (no el
LLM) la ejecuta de verdad, pasando por los guardrails; (3) el resultado de
esa ejecución se le devuelve al LLM como si fuera parte de la conversación;
(4) el LLM, ahora con ese nuevo dato, decide el siguiente paso. En nuestra
corrida esto se ve clarísimo en los pasos 6→7: el token obtenido en el paso
6 solo existe porque el resultado del paso 6 se le devolvió al "cerebro"
(acá, el plan fijo del mock) antes de decidir el paso 7. El ciclo corta
cuando el LLM responde `"final"` (como pasó al final de nuestra corrida) o
cuando se llega al límite de pasos (`MAX_PASOS`), que es en sí mismo otro
guardrail.

**P2 — ¿Qué aporta el LLM que un script fijo no puede? ¿Y qué hace mejor el script?**

El LLM aporta **adaptabilidad**: puede leer la respuesta de un paso (por
ejemplo, `robots.txt` revelando una ruta oculta) y decidir en el momento
investigar esa ruta, sin que nadie haya programado ese camino de antemano.
Un script fijo como `recolector.py` (Lab 08) solo puede hacer exactamente
los pasos que se le escribieron, en el orden que se le escribieron.

Lo que el script hace mejor: es **determinístico y predecible** — siempre
hace lo mismo, en el mismo orden, sin margen para "alucinar" un hallazgo que
no existe o para tomar un camino ineficiente. También es más rápido (sin
esperar respuestas de una API) y no tiene el costo, en tiempo y dinero, de
cada llamada al LLM.

**P3 — Diseño agnóstico al proveedor: ¿qué ventaja da? ¿Contra qué se acopla el agente?**

El agente (`agente_esqueleto.py`) nunca llama directamente a la API de
Claude ni a la de OpenAI: siempre llama a `cliente.paso()`, un método con la
misma firma sin importar qué motor esté detrás (`ClienteClaude`,
`ClienteOpenAI` o `ClienteMock`). El agente se acopla a esa **interfaz
común** (`paso(resultados)` devuelve siempre
`{"tipo": "tool"|"final", ...}`), no al proveedor concreto. La ventaja
práctica — que usamos directamente en esta entrega — es poder correr el
agente offline con `mock` para desarrollar y probar el loop sin necesitar
(ni arriesgar) una API key real, y poder cambiar a `claude` u `openai`
después sin tocar una sola línea de la lógica del agente, solo cambiando la
variable de entorno `LLM_PROVIDER`.

**P4 — Dos riesgos de un agente ofensivo autónomo y su guardrail**

1. **Salirse del alcance autorizado:** el LLM puede decidir escanear o
   atacar un host que no fue autorizado, simplemente porque lo vio
   mencionado en algún resultado. Mitigado por `_verificar_alcance()`, que
   bloquea cualquier acción fuera de `ALCANCE` antes de ejecutarla — lo
   vimos en vivo en el paso 8 de nuestra corrida (R4).
2. **Loop infinito o descontrol de recursos:** sin límite, el agente podría
   seguir pidiendo pasos indefinidamente (por un bug, o porque el LLM nunca
   "decide" terminar), consumiendo recursos del target o de la API sin
   parar. Mitigado por `MAX_PASOS`, que corta el loop a un número fijo de
   iteraciones pase lo que pase.

**P5 — ¿Por qué los labs 05–08 a mano eran requisito? ¿Qué no podrías hacer sin saber pentesting?**

El agente propone acciones y reporta resultados, pero **no garantiza que lo
que hace o reporta sea correcto**. En nuestra propia corrida, el paso 1
(`nmap_scan`) falló por timeout — si no supiéramos leer e interpretar la
salida de un nmap de labs anteriores, no habríamos podido distinguir "el
escaneo no encontró nada" de "el escaneo nunca llegó a correr", que son
conclusiones muy distintas. De la misma forma, si no hubiéramos hecho SQLi,
command injection, path traversal e IDOR a mano (Lab 07), no podríamos
juzgar si una "vulnerabilidad" que el LLM reporta en una corrida real
(`claude`/`openai`) es genuina o una alucinación con lujo de detalle. Sin
ese criterio previo, dirigir un agente ofensivo deja de ser "supervisar con
conocimiento" y pasa a ser "confiar a ciegas" — exactamente lo que el lab
busca evitar: el agente acelera el trabajo, pero el juicio de si lo que hizo
tiene sentido sigue siendo enteramente humano.