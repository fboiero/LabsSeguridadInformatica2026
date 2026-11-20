# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 14 · **Integrantes:** ver `INTEGRANTES.md` (COMPLETAR) · **Fecha:** 19/11/2026
**Proveedor usado:** mock (offline, sin API key)

> **Estado de la entrega.** El equipo que preparó esta entrega no tiene Docker, por lo
> que el entorno PhantomCorp no se pudo levantar. El código del agente está completo y
> se ejecutó con el motor mock, pero **no hay evidencia del target real ni flags
> capturadas**. Lo que depende del entorno está marcado **PENDIENTE (requiere Docker)**.

## 0. Declaración de uso de IA

- **Herramienta:** Claude (Anthropic) a través de Claude Code (CLI), con acceso al
  repositorio del grupo.
- **Uso:** completar los TODO de `agente_esqueleto.py`, correr el agente con el mock y
  redactar este informe y el research.
- **Restricciones aplicadas:** no se usó ninguna API key ni llamadas externas (motor
  `mock`); no se consultó `solucion.md`; no se inventaron flags ni salidas.
- **Verificación:** el transcript es la salida real de la corrida local (con las flags
  reemplazadas por `FLAG{REDACTADA}`). PENDIENTE: revisión humana del código y de las
  respuestas; el grupo debe poder defenderlos oralmente.

## 1. Flags capturadas

**PENDIENTE (requiere Docker).** Comandos que debe correr el humano:

```bash
./ctf lab 09
export LLM_PROVIDER=mock        # o claude/openai con la key en variable de entorno
make shell
cd /repo/labs/lab09-agentes/src
python3 agente_pentest.py       # R1-R4 (agente de referencia)
./ctf submit 09 R1 'FLAG{...}'  # idem R2, R3, R4
./ctf status 09                 # pegar acá la salida real
```

Para R5: ejecutar `entregas/lab09/grupo14/src/agente_esqueleto.py` con
`labs/lab09-agentes/src` en el `PYTHONPATH` (importa `herramientas` y `llm`), contra el
target levantado, y enviar con `./ctf submit 09 R5 'FLAG{...}'`.

Lo único observable offline: el guardrail bloquea `8.8.8.8` y devuelve su mensaje de
bloqueo (que contiene el flag de R4, no reproducido acá); ver transcript.

## 2. Tu agente

Archivo: `src/agente_esqueleto.py`. Se completaron los tres TODO:

1. **TODO 1:** si `accion["tipo"] == "final"`, imprime el texto y sale del loop (`break`).
2. **TODO 2:** si es una tool, imprime paso y argumentos y ejecuta
   `ejecutar_tool(accion["nombre"], accion["argumentos"])`; muestra los primeros 300
   caracteres de la salida.
3. **TODO 3:** `resultados = [{"id": accion["id"], "output": salida}]`, para que el
   próximo `cliente.paso(resultados)` realimente al LLM (el `id` asocia cada resultado
   a su llamada a tool).

El detector de flags (`re.findall`) ya venía dado y se mantuvo.

Salida de la corrida local con mock (**sin target**, ver limitación):

```
[paso 1] tool=nmap_scan args={'host': 'phantomcorp'}
[resultado] error nmap: [WinError 2] The system cannot find the file specified
[paso 2] tool=http_get args={'url': 'http://phantomcorp/'}
[resultado] error http_get: <urlopen error [Errno 11001] getaddrinfo failed>
... (pasos 3 a 6: http_get a /robots.txt, /vault-interno-x7, /api/debug, /api/token; mismo error)
[paso 7] tool=http_post args={'url': 'http://phantomcorp/api/vault', 'data': {'token': 'T-9f3k-vault'}}
[resultado] error http_post: <urlopen error [Errno 11001] getaddrinfo failed>
[paso 8] tool=nmap_scan args={'host': '8.8.8.8'}
[resultado] BLOQUEADO POR GUARDRAIL: '8.8.8.8' esta FUERA DE ALCANCE. El agente NO ejecuta acciones fuera del scope autorizado. FLAG{REDACTADA}
[final] Auditoría simulada completa. Revisá las flags en el transcript.
=== Flags encontradas (1) ===
```

El loop funciona: ejecuta las 8 acciones, realimenta y corta en `final`. **Flag R5:
PENDIENTE (requiere Docker)**: sin el target no hay respuesta de `/api/token` ni de
`/api/vault`, por lo que no se pudo verificar el encadenamiento token a vault. Nota: el
mock envía un token fijo (`T-9f3k-vault`) en vez de leerlo de la respuesta; es una
limitación del mock, un LLM real tomaría el token de la salida del paso 6.

## 3. Auditoría crítica del agente

**Transcript:** ver sección 2 (corrida mock sin target). El transcript con el target
real es **PENDIENTE (requiere Docker)** y debe pegarse completo y reanalizarse.

**Aciertos y errores** (sobre la corrida mock; no sobre un LLM real):

- *Paso 1, `nmap_scan phantomcorp`:* primer paso lógico (recon). Falló solo por no
  tener nmap ni target en este equipo. Un humano habría hecho lo mismo.
- *Pasos 2–3, `/` y `/robots.txt`:* decisión correcta (enumeración web básica;
  robots.txt suele delatar rutas ocultas).
- *Paso 4, `/vault-interno-x7`:* sigue una pista de ruta oculta; el mock la conoce de
  antemano, un LLM real debería leerla de robots.txt (a verificar con el target).
- *Pasos 5–6, `/api/debug` y `/api/token`:* buena progresión hacia la API expuesta.
- *Paso 7, `POST /api/vault`:* encadenamiento correcto en lo conceptual, pero el token
  está hardcodeado: no se adapta si el token cambia.
- *Paso 8, `nmap 8.8.8.8`:* acción fuera de alcance, deliberada para probar el
  guardrail; un humano nunca la ejecutaría.
- *Errores generales:* el agente no distingue "error de red" de "sin hallazgos" (siguió
  igual tras seis fallos seguidos, sin reintentar ni abortar); no resume ni deduplica;
  el mock no razona. Con un LLM real se sumaría el riesgo de alucinar hallazgos.

**El guardrail (R4):** el mock pide escanear `8.8.8.8`. `nmap_scan` llama a
`_verificar_alcance()`, que extrae el host y, como no está en `ALCANCE = {"phantomcorp"}`,
devuelve un mensaje de bloqueo sin ejecutar nada (incluye el flag del reto, no
reproducido acá). Es imprescindible porque la validación está en el **código** y no
depende de que el modelo obedezca el prompt: un LLM puede ser engañado (prompt injection
en una respuesta del target) o equivocarse, y sin guardrail escanearía a un tercero
(Ley 26.388). Todas las tools pasan por el mismo chequeo.

Guardrails que agregaría: (1) resolver el host a IP y validarla contra el rango del
target (hoy `_host_de` compara texto, y una redirección HTTP 3xx o un alias DNS podría
esquivarlo); (2) confirmación humana antes de `http_post` o acciones que modifiquen
estado; (3) tope total de tiempo y requests, con rate limit; (4) log de cada acción;
(5) tratar el contenido de las respuestas como datos no confiables (anti prompt
injection); (6) allowlist de métodos y rutas.

## 4. Preguntas de análisis

**P1 — el loop de tool-use.** El LLM decide una acción (qué tool y con qué argumentos);
nuestro código la ejecuta con guardrails; el resultado se devuelve al LLM con el `id` de
la llamada; se repite hasta que el LLM responde `final` o se agota `MAX_PASOS`. En la
corrida: `cliente.paso(None)` devolvió `nmap_scan`, se ejecutó con `ejecutar_tool`, la
salida se empaquetó en `[{"id", "output"}]` y se pasó a `paso(resultados)`, y así 8 veces
hasta el `final`.

**P2 — LLM vs. script fijo.** El LLM aporta decisión contextual: lee un resultado
(robots.txt, un header) y elige el próximo paso, encadena y se adapta a lo inesperado. El
script fijo (como `recolector.py` del Lab 08) es determinístico, reproducible, barato,
auditable y no alucina ni se desvía; es mejor cuando el procedimiento es conocido.

**P3 — ventaja del diseño agnóstico.** Permite cambiar de proveedor (Claude, OpenAI,
mock) con una variable de entorno sin tocar el agente: evita lock-in, permite tests
offline sin key ni costo (como hicimos) y comparar modelos. El agente se acopla a una
**interfaz** normalizada (`paso()` devuelve `{"tipo":"tool",...}` o `{"tipo":"final",...}`),
no al proveedor.

**P4 — dos riesgos y su guardrail.** (1) *Salida de alcance* (atacar a un tercero por
error o por prompt injection): guardrail de alcance en código (`_verificar_alcance`).
(2) *Exceso de autonomía* (loop sin fin, costo, daño): límite `MAX_PASOS`, allowlist de
tools y confirmación humana para acciones destructivas. También la alucinación de
hallazgos, mitigada con validación humana.

**P5 — por qué los labs 05–08 eran requisito.** El agente solo automatiza lo que uno ya
sabe hacer: para dirigirlo hay que definir el scope, elegir qué tools darle y, sobre
todo, **evaluar** sus decisiones (¿ese `nmap -sV` tiene sentido? ¿ese hallazgo es real o
alucinado?). Sin saber pentesting no se podría validar la salida, detectar que se desvió
o que inventó una vulnerabilidad, ni escribir un guardrail correcto. El agente exige
saber más, no menos.
