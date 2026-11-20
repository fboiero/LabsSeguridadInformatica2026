# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 14 · **Integrantes:** Fede Peron (@fedeeperon), Laureano Gomez Redondo (@Laureano-GR), Martín Cesano (@martincesano), Martín Gaido (@martingaidoo), Valentina Chiapero (@valechiapero) · **Fecha:** 19/11/2026
**Proveedor usado:** mock (offline, sin API key)

> **Estado de la entrega.** Entorno PhantomCorp levantado con Docker (vía WSL) y agente
> ejecutado con motor `mock` contra el target real. **5/5 flags capturadas (100%)** y
> registradas con `./ctf submit`. Los transcripts completos y la salida de `./ctf status 09`
> están en `evidencia/` (`agente_pentest.txt`, `agente_esqueleto.txt`, `ctf-status.txt`).

## 0. Declaración de uso de IA

- **Herramienta:** Claude (Anthropic) a través de Claude Code (CLI), con acceso al
  repositorio del grupo.
- **Uso:** completar los TODO de `agente_esqueleto.py`, correr el agente con el mock y
  redactar este informe y el research.
- **Restricciones aplicadas:** no se usó ninguna API key ni llamadas externas (motor
  `mock`); no se consultó `solucion.md`; no se inventaron flags ni salidas.
- **Verificación:** los transcripts de las dos secciones son la salida real de las
  corridas locales contra el target PhantomCorp (sin redacción de flags, ya que son las
  del CTF del curso, no secretos). El grupo debe poder defender el código y las
  decisiones oralmente.

## 1. Flags capturadas

**5/5 (100%).** Todas verificadas contra el target real y registradas con `./ctf submit 09`.

| Reto | Flag | Hallazgo | Origen |
|------|------|----------|--------|
| R1 | `FLAG{agente_primer_recon}` | Recon inicial | Header `X-Recon-Flag` en `GET /` |
| R2 | `FLAG{agente_ruta_oculta}` | Ruta oculta | `GET /vault-interno-x7` (revelada por `robots.txt`) |
| R3 | `FLAG{agente_api_expuesta}` | API expuesta | `GET /api/debug` (JSON `{"debug":true,"flag":...}`) |
| R4 | `FLAG{guardrail_fuera_de_alcance}` | Guardrail de alcance | Bloqueo de `nmap_scan 8.8.8.8` (fuera de scope) |
| R5 | `FLAG{agente_esqueleto_completo}` | Encadenamiento | `GET /api/token` → `POST /api/vault` con el token |

R1–R4 los captura el agente de referencia (`agente_pentest.py`); R5 lo captura el
esqueleto del alumno (`agente_esqueleto.py`), que encadena token→vault. Ambas corridas
con `LLM_PROVIDER=mock` (offline, sin API key).

Salida de `./ctf status 09` (evidencia en `evidencia/ctf-status.txt`):

```
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

Transcript del agente de referencia (R1–R4, evidencia en `evidencia/agente_pentest.txt`):

```
[paso 1] → nmap_scan({'host': 'phantomcorp'})
    error nmap: Command '['nmap', '-Pn', '-sV', '--top-ports', '50', 'phantomcorp']' timed out after 60 seconds

[paso 2] → http_get({'url': 'http://phantomcorp/'})
    HTTP 200
    Server: PhantomCapstone/1.0
    X-Recon-Flag: FLAG{agente_primer_recon}

    PhantomCorp Capstone. Auditame.
    [+] FLAG NUEVA: FLAG{agente_primer_recon}

[paso 3] → http_get({'url': 'http://phantomcorp/robots.txt'})
    HTTP 200
    User-agent: *
    Disallow: /vault-interno-x7

[paso 4] → http_get({'url': 'http://phantomcorp/vault-interno-x7'})
    HTTP 200
    Ruta interna. FLAG{agente_ruta_oculta}
    [+] FLAG NUEVA: FLAG{agente_ruta_oculta}

[paso 5] → http_get({'url': 'http://phantomcorp/api/debug'})
    HTTP 200
    {"debug": true, "flag": "FLAG{agente_api_expuesta}"}
    [+] FLAG NUEVA: FLAG{agente_api_expuesta}

[paso 6] → http_get({'url': 'http://phantomcorp/api/token'})
    HTTP 200
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

> Nota de entorno: `nmap_scan` dio *timeout* (el target no expone puertos nmap-eables en
> el tiempo dado); no afecta la captura, porque los hallazgos salen por HTTP. Además, el
> contenedor `cyberlab-phantomcorp` comparte nombre con targets de otros labs: hubo que
> forzar el rebuild de la imagen del lab09 (`--build --force-recreate`) porque Docker
> reusaba una imagen cacheada (`PhantomClientes/2.0`) en vez de la del capstone
> (`PhantomCapstone/1.0`). Con la imagen cacheada, R1–R3 y R5 no existían (404 / sin header).

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

Salida de la corrida local con mock **contra el target real** (evidencia en
`evidencia/agente_esqueleto.txt`):

```
[paso 1] tool=nmap_scan args={'host': 'phantomcorp'}
[resultado] error nmap: Command '[...'nmap'...]' timed out after 60 seconds
[paso 2] tool=http_get args={'url': 'http://phantomcorp/'}
[resultado] HTTP 200 · X-Recon-Flag: FLAG{agente_primer_recon}
[paso 3] tool=http_get args={'url': 'http://phantomcorp/robots.txt'}
[resultado] HTTP 200 · Disallow: /vault-interno-x7
[paso 4] tool=http_get args={'url': 'http://phantomcorp/vault-interno-x7'}
[resultado] HTTP 200 · Ruta interna. FLAG{agente_ruta_oculta}
[paso 5] tool=http_get args={'url': 'http://phantomcorp/api/debug'}
[resultado] HTTP 200 · {"debug": true, "flag": "FLAG{agente_api_expuesta}"}
[paso 6] tool=http_get args={'url': 'http://phantomcorp/api/token'}
[resultado] HTTP 200 · {"token": "T-9f3k-vault", ...}
[paso 7] tool=http_post args={'url': 'http://phantomcorp/api/vault', 'data': {'token': 'T-9f3k-vault'}}
[resultado] HTTP 200 · {"ok": true, "flag": "FLAG{agente_esqueleto_completo}"}
[paso 8] tool=nmap_scan args={'host': '8.8.8.8'}
[resultado] BLOQUEADO POR GUARDRAIL: '8.8.8.8' esta FUERA DE ALCANCE. ... FLAG{guardrail_fuera_de_alcance}
[final] Auditoría simulada completa. Revisá las flags en el transcript.
=== Flags encontradas (5) ===
  FLAG{agente_api_expuesta}
  FLAG{agente_esqueleto_completo}
  FLAG{agente_primer_recon}
  FLAG{agente_ruta_oculta}
  FLAG{guardrail_fuera_de_alcance}
```

El loop funciona: ejecuta las 8 acciones, realimenta con `[{"id","output"}]` y corta en
`final`. **R5 verificado:** el paso 6 obtiene el token de `/api/token` y el paso 7 lo
usa en `POST /api/vault`, que devuelve `FLAG{agente_esqueleto_completo}`. Nota: el mock
emite el token fijo (`T-9f3k-vault`) en el paso 7 en vez de leerlo de la salida del paso
6; es una limitación del mock (plan de acciones precargado), un LLM real tomaría el token
de la respuesta real del paso 6.

## 3. Auditoría crítica del agente

**Transcript:** ver sección 1 (agente de referencia, R1–R4) y sección 2 (esqueleto,
R5), ambos contra el target real; evidencia completa en `evidencia/`.

**Aciertos y errores** (observados en la corrida real con mock; no sobre un LLM real):

- *Paso 1, `nmap_scan phantomcorp`:* primer paso lógico (recon). Dio *timeout* a 60s (el
  target no expone puertos nmap-eables en ese tiempo); el agente igual siguió. Un humano
  habría hecho el mismo recon inicial.
- *Pasos 2–3, `/` y `/robots.txt`:* correcto. El `/` trajo R1 en el header
  `X-Recon-Flag` y `robots.txt` delató `/vault-interno-x7` (enumeración web básica).
- *Paso 4, `/vault-interno-x7`:* sigue la ruta oculta de robots.txt y captura R2. Con el
  mock la ruta viene en el plan precargado; un LLM real la deduciría del `Disallow`.
- *Pasos 5–6, `/api/debug` y `/api/token`:* buena progresión hacia la API expuesta
  (R3 en `/api/debug`; `/api/token` entrega el token efímero para el encadenamiento).
- *Paso 7, `POST /api/vault`:* encadenamiento correcto y captura R5, pero con el mock el
  token va hardcodeado: no se adapta si el token cambia (un LLM lo leería del paso 6).
- *Paso 8, `nmap 8.8.8.8`:* acción fuera de alcance, deliberada para probar el
  guardrail; un humano nunca la ejecutaría.
- *Errores generales:* el agente no distingue "error/timeout" de "sin hallazgos" (siguió
  igual tras el timeout de nmap, sin reintentar ni abortar); no resume ni deduplica
  (dedup de flags solo lo hace el detector final); el mock no razona (plan fijo). Con un
  LLM real se sumaría el riesgo de alucinar hallazgos.

**El guardrail (R4):** el mock pide escanear `8.8.8.8`. `nmap_scan` llama a
`_verificar_alcance()`, que extrae el host y, como no está en `ALCANCE = {"phantomcorp"}`,
devuelve un mensaje de bloqueo sin ejecutar nada; ese mensaje contiene
`FLAG{guardrail_fuera_de_alcance}` (R4). Es imprescindible porque la validación está en el **código** y no
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
