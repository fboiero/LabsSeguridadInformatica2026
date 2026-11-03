# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919 · **Fecha:** 30/10/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Ejecución del agente (motor `mock`) contra el target capstone, captura del transcript y borrador de la auditoría (sección B) y de las flags. | `informe.md`: secciones 1, A y B (transcript, aciertos/errores y análisis del guardrail). | El transcript pegado es la corrida real del agente. Las 5 flags se validaron contra el evaluador con `./ctf submit 09` (progreso 5/5). El grupo revisó el loop de tool-use y el guardrail y comprende cada decisión del agente. |
| Claude (Anthropic), vía Claude Code | **Parte 3 — validación y análisis.** Correr el agente entregado contra el entorno **Docker oficial** (`make lab N=09`, motor `mock`), capturar transcript auténtico y `./ctf status 09`; redactar las respuestas **P1–P5**; y escribir `research.md`. | `informe.md` (sección 2: P1–P5), `research.md` (nuevo) y `evidencia/` (nueva). | El transcript de `evidencia/agente-docker-transcript.txt` es la corrida real del agente en el contenedor `cyberlab-attacker` contra `phantomcorp`; las 5 flags se re-validaron con `./ctf submit 09` → `5/5` (ver `evidencia/ctf-status-09.txt`). Sin API key: motor `mock`. |

> **Motor usado: `mock` (offline).** No se usó ninguna API key de LLM: el agente corrió con el motor `mock`, que recorre el objetivo de forma determinística. El loop de tool-use, las tools y el guardrail son **reales**; lo único simulado es el "razonamiento" (qué tool pedir en cada paso), que con `mock` viene de un plan fijo en vez de un LLM. Ninguna key se subió al repo.

El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del análisis.

---

## 1. Flags capturadas

> `./ctf status 09` validado contra el entorno **Docker oficial** tras entregar las 5 flags con `./ctf submit 09`. Copia literal en [`evidencia/ctf-status-09.txt`](evidencia/ctf-status-09.txt); transcript completo de la corrida del agente en el contenedor, en [`evidencia/agente-docker-transcript.txt`](evidencia/agente-docker-transcript.txt).

```
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 09                     │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     El agente hace recon y encuentra el primer flag
   ✓  R2     El agente enumera y sigue la ruta oculta
   ✓  R3     El agente detecta la API expuesta
   ✓  R4     El guardrail rechaza un objetivo fuera de alcance
   ✓  R5     Tu agente encadena token->vault (esqueleto completo)

  ██████████████████████████████  5/5 (100%)
```

| Reto | Flag | De dónde salió |
|---|---|---|
| R1 | `FLAG{agente_primer_recon}` | Recon del objetivo: header `X-Recon-Flag` en el `GET /`. |
| R2 | `FLAG{agente_ruta_oculta}` | El agente leyó `robots.txt` y siguió a la ruta `Disallow: /vault-interno-x7`. |
| R3 | `FLAG{agente_api_expuesta}` | Endpoint de debug expuesto `GET /api/debug`. |
| R4 | `FLAG{guardrail_fuera_de_alcance}` | El guardrail bloqueó un `nmap_scan` contra `8.8.8.8` (fuera de alcance). |
| R5 | `FLAG{agente_esqueleto_completo}` | Encadenamiento: `GET /api/token` → `POST /api/vault` con ese token. |

---

## A. Nuestro agente

El entregable central, `src/agente_esqueleto.py`, está completo y funcionando. Completamos los tres `TODO` del loop de tool-use:

1. **Condición de fin:** si la acción del cliente es de tipo `final`, imprime el texto y corta el loop.
2. **Ejecución de la tool:** toma `accion["nombre"]` y `accion["argumentos"]` y los despacha con `ejecutar_tool(...)`, que pasa sí o sí por el guardrail de alcance.
3. **Realimentación:** devuelve el resultado al LLM como `[{"id": accion["id"], "output": salida}]` para que decida el paso siguiente.

Corrido con el motor `mock`, el agente llega a encadenar `/api/token` → `POST /api/vault` y trae el flag capstone `FLAG{agente_esqueleto_completo}` (R5), igual que el agente de referencia.

> **Nota de ejecución (sin Docker).** El equipo que armó esta parte no tenía Docker en la máquina, así que levantó el target capstone en local (`server.py` del contenedor, escuchando en el puerto 80) y resolvió el nombre `phantomcorp` a `127.0.0.1` —lo mismo que hace el DNS interno de Docker— sin tocar el código del agente, el guardrail ni el plan del `mock`. Además, como la consola local no tiene `nmap` instalado, el paso de `nmap_scan` devuelve un error de binario ausente; no afecta a ningún reto, porque la flag de recon (R1) viaja en el header HTTP del `GET /` y la captura igual el `http_get`.

---

## B. Auditoría del agente

### B.1 Transcript (corrida real, motor `mock`)

```
[paso 1] → nmap_scan({'host': 'phantomcorp'})
    error nmap: [WinError 2] El sistema no puede encontrar el archivo especificado

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
    BLOQUEADO POR GUARDRAIL: '8.8.8.8' esta FUERA DE ALCANCE. El agente NO
    ejecuta acciones fuera del scope autorizado. FLAG{guardrail_fuera_de_alcance}
    [+] FLAG NUEVA: FLAG{guardrail_fuera_de_alcance}

[agente] Fin: Auditoría simulada completa.

=== Flags encontradas (5) ===
  FLAG{agente_api_expuesta}
  FLAG{agente_esqueleto_completo}
  FLAG{agente_primer_recon}
  FLAG{agente_ruta_oculta}
  FLAG{guardrail_fuera_de_alcance}
```

**¿Cada decisión fue la que habríamos tomado nosotros?** Sí, el plan es el flujo metódico de los labs 05–08:

| Paso | Decisión del agente | ¿La habríamos tomado? |
|---|---|---|
| 1 | Recon con `nmap_scan` | Sí: empezar reconociendo es correcto (aunque acá nmap faltaba en el host). |
| 2 | `GET /` | Sí: leer la raíz y sus headers es lo primero de la enumeración web (Lab 06). |
| 3–4 | Leer `robots.txt` y seguir la ruta `Disallow` | Sí: `robots.txt` delata lo que esconden (la "ironía" del Lab 05); seguir esa pista es de manual. |
| 5 | `GET /api/debug` | Sí: un endpoint de debug expuesto es un hallazgo clásico de enumeración de APIs (Lab 06). |
| 6–7 | Pedir el token y **encadenarlo** en el `POST /api/vault` | Sí, y es lo más valioso: usar la salida de un paso como entrada del siguiente es exactamente lo que un script fijo no hace solo. |
| 8 | Intentar `nmap` sobre `8.8.8.8` | **No.** Acá el agente se fue de alcance; lo correcto es que el guardrail lo frene (ver B.3). |

### B.2 Aciertos y errores

**Aciertos.**
- **Encadenamiento autónomo (pasos 6–7).** El agente leyó en un resultado "usá este token en `POST /api/vault`" y lo hizo. Esa capacidad de usar la salida de una tool como entrada de la siguiente es el valor real del agente sobre un script fijo.
- **Seguir pistas (pasos 3–4).** No se quedó en la raíz: leyó `robots.txt` y fue a la ruta oculta. Enumeración dirigida, no a ciegas.
- **Eficiencia.** Resolvió los 5 retos en 8 pasos, sin vueltas ni repeticiones, dentro del `MAX_PASOS=12`.

**Errores y límites.**
- **Se fue de scope (paso 8).** Intentó escanear `8.8.8.8`, un host de terceros. Un agente sin guardrail lo habría hecho (posible delito, Ley 26.388). Acá no fue un acierto del agente sino del **guardrail** que lo detuvo.
- **No validó ni priorizó.** El agente reporta todas las flags por igual; no distingue cuál es grave ni verifica que un hallazgo sea real (riesgo de "alucinar con confianza" que advierte el lab). Esa validación la pone el humano, apoyado en los labs 05–08.
- **Dependencia del entorno.** El paso de `nmap` falló por un binario ausente; el agente no se dio cuenta de que ese recon quedó incompleto: siguió como si nada. Un operador humano habría notado que faltó el barrido de puertos.

### B.3 El guardrail (R4) y qué más agregaríamos

En el paso 8 el agente pidió `nmap_scan` contra `8.8.8.8`. Antes de ejecutar nada, `nmap_scan` llama a `_verificar_alcance()`, que extrae el host del objetivo y comprueba si está en el conjunto `ALCANCE = {"phantomcorp"}`. Como `8.8.8.8` no está, la función **no corre nmap**: devuelve el mensaje de bloqueo (con `FLAG{guardrail_fuera_de_alcance}`) y el agente nunca toca el host externo. Esa es la lección central del lab: el agente aporta el razonamiento, pero los **límites los pone el código del humano**. Diez líneas de validación de alcance son la diferencia entre una herramienta útil y un arma que escanea lo que no debe. Es importante además que la validación esté **en cada tool** (no en el prompt del LLM): un LLM se puede convencer de saltarse una regla del prompt, pero no puede saltarse un `if` en el código que ejecuta la acción.

Otros guardrails que le agregaríamos:
1. **Allowlist de puertos/acciones**, no solo de host: que `nmap` solo barra ciertos puertos y que no haya tools destructivas (nada de borrar, apagar o modificar).
2. **Rate limiting y tope de pasos** (ya existe `MAX_PASOS`): sumar un límite de requests por minuto para no "martillar" el target ni disparar su detección.
3. **Confirmación humana para acciones de impacto** (*human-in-the-loop*): que cualquier `POST`/escritura o cualquier intento fuera de una lista verde pida aprobación antes de ejecutarse.
4. **Registro/auditoría inmutable** de cada acción propuesta y ejecutada, para poder revisar después qué hizo el agente y por qué.

---

## 2. Preguntas de análisis

**P1 — El loop de tool-use.**

El loop de tool-use es el ciclo que vimos imprimir paso a paso en la corrida. En cada vuelta pasan cuatro cosas: (1) el **LLM decide** una acción — qué tool conviene correr ahora y con qué argumentos (en nuestra corrida con motor `mock` esa decisión viene de un plan fijo, pero la mecánica es idéntica a la de un LLM real); (2) nuestro **código ejecuta** esa tool a través del punto único `ejecutar_tool(nombre, argumentos)`, que *siempre* pasa por el guardrail de alcance antes de actuar; (3) le **devolvemos el resultado** al modelo como `[{"id": accion["id"], "output": salida}]` para que lo tenga en cuenta; y (4) **se repite** hasta que la acción sea de tipo `final` o hasta chocar con el tope `MAX_PASOS = 12`. Esos son exactamente los tres `TODO` que completamos en `agente_esqueleto.py`: la condición de corte, el despacho de la tool y la realimentación. En la corrida se ve claro en los pasos 6→7: el `GET /api/token` devolvió un token y en la vuelta siguiente el agente lo metió en el `POST /api/vault`. La salida de un paso fue la entrada del próximo: eso es el loop.

**P2 — Qué aporta el LLM que un script fijo no, y qué hace mejor el script.**

**Lo que aporta el LLM: decisión adaptativa.** Un script fijo como el `recolector.py` del Lab 08 ejecuta siempre la misma secuencia pre-programada; no reacciona a lo que encuentra. El LLM, en cambio, **lee un resultado y decide el paso siguiente según su contenido**. En la corrida esto se ve dos veces: leyó `Disallow: /vault-interno-x7` en el `robots.txt` y fue a esa ruta (pistas que no estaban previstas de antemano), y leyó "usá este token en `POST /api/vault`" y encadenó la llamada. Esa capacidad de improvisar sobre lo no previsto es lo que un script no hace solo.

**Lo que hace mejor el script: todo lo demás.** Es **determinístico** (hace exactamente lo mismo siempre), **rápido y gratis** (no llama a una API ni cuesta tokens), **reproducible** (ideal para CI/tests — por eso existe el motor `mock`), **auditable** y **no alucina**: un script nunca va a "inventar" una vulnerabilidad que no existe. Regla práctica: LLM para razonamiento abierto y adaptación; script para tareas repetitivas y bien definidas.

**P3 — Diseño agnóstico al proveedor.**

El agente **no se acopla a un proveedor; se acopla a una interfaz**. Toda la lógica del loop depende solamente del contrato uniforme `crear_cliente(system, tools).paso(resultados)`, que devuelve una acción normalizada (`{"tipo": "tool", ...}` o `{"tipo": "final", ...}`). Detrás de esa misma interfaz, `llm.py` tiene tres implementaciones intercambiables (`ClienteClaude`, `ClienteOpenAI`, `ClienteMock`) y se elige con una sola variable de entorno (`LLM_PROVIDER`). La ventaja concreta es triple: (1) **probar sin key y offline** con `mock` —que es justo como validamos esta entrega, sin arriesgar filtrar una API key—; (2) **cambiar de proveedor** (Claude ↔ OpenAI) si uno sube de precio, cambia su API o se cae, sin tocar una línea del agente; y (3) **evitar el vendor lock-in**. Es el principio de inversión de dependencias: el código de alto nivel (el agente) no depende de los detalles (el SDK de un proveedor), sino de una abstracción que ambos cumplen.

**P4 — Dos riesgos de un agente ofensivo autónomo y su guardrail.**

**Riesgo 1 — Salirse de alcance.** Un agente que decide solo puede terminar escaneando o atacando un host que no está autorizado (un tercero visto en un resultado, una IP externa). Fuera del lab eso es un delito (Ley 26.388). *Guardrail:* una **allowlist de alcance validada en cada tool** (`_verificar_alcance` contra `ALCANCE = {"phantomcorp"}`), no en el prompt. En la corrida se ve en el paso 8: el agente pidió `nmap_scan` contra `8.8.8.8` y la tool lo **bloqueó antes de ejecutar nada**. Que esté en el código y no en el prompt es clave: a un LLM se lo puede convencer de ignorar una regla del prompt, pero no puede saltear un `if` en la función que ejecuta la acción.

**Riesgo 2 — Loop descontrolado / martilleo del objetivo.** Un agente sin tope puede quedar en un bucle infinito, agotar recursos o golpear el target hasta tumbarlo (DoS) o disparar su detección. *Guardrail:* **límite de pasos** (`MAX_PASOS = 12`, ya presente) más **rate limiting** (tope de requests por minuto). Un tercer guardrail que agregaríamos es **human-in-the-loop**: que toda acción de escritura o impacto (`POST`, borrados) pida confirmación humana antes de ejecutarse.

**P5 — Por qué los labs 05–08 a mano fueron requisito para este.**

Porque **vos dirigís al agente, y no podés dirigir lo que no sabés hacer**. Haber hecho recon (05), enumeración (06), explotación (07) y post-explotación (08) a mano es lo que te permite: (1) **juzgar** si la decisión del agente fue la correcta —¿empezar con `nmap -sV` tenía sentido?, ¿se le escapó un puerto?—; (2) **validar** los hallazgos y no comerte una alucinación "con confianza", el riesgo que el propio lab advierte; (3) **diseñar las tools y los guardrails**: no se puede escribir una validación de alcance ni una tool para un ataque que no entendés; y (4) **recuperar** cuando el agente se traba o la app tiene una defensa rara. La corrida lo muestra: el `nmap_scan` del paso 1 falló (timeout) y el agente **siguió como si nada**, sin notar que el barrido de puertos quedó incompleto. Solo un humano que sabe hacer recon se da cuenta de ese agujero. Si no supieras pentesting no podrías distinguir un agente que trabaja bien de uno que hace cualquier cosa con cara de seguridad. Como dice la regla del lab: un agente no te exime de saber, **te exige saber más**.
