# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 04 · **Integrantes:** *Facundo Anil - Antunez Jeremias - Olivero Uriel - Lelli Matias* · **Fecha:** 2026-10-29  
**Proveedor usado:** `mock`

---

## 0. Declaración de uso de IA

Se utilizó un asistente de IA como apoyo para la redacción del informe, el análisis conceptual de las preguntas P1–P5 y la revisión del bucle en `agente_esqueleto.py`. La ejecución del agente, la validación de las 5 flags y la auditoría del código de `herramientas.py` y `llm.py` fueron verificadas por el grupo en el entorno del laboratorio.

---

## 1. Flags capturadas

Salida de `./ctf status 09`:

```text
   ╔══════════════════════════════════════════════════════════════╗
   ║  PROGRESO · LAB 09                                           ║
   ╚══════════════════════════════════════════════════════════════╝

   ✓  R1     El agente hace recon y encuentra el primer flag
   ✓  R2     El agente enumera y sigue la ruta oculta
   ✓  R3     El agente detecta la API expuesta
   ✓  R4     El guardrail rechaza un objetivo fuera de alcance
   ✓  R5     Tu agente encadena token->vault (esqueleto completo)

   [████████████████████████████████] 5/5 (100%)
   ✓ ¡Lab 09 COMPLETO! Ponete las pilas con la próxima unidad.
```

| Reto | Descripción | Flag | Origen |
| :--- | :--- | :--- | :--- |
| **R1** | Recon inicial | `FLAG{agente_primer_recon}` | Header `X-Recon-Flag` en `GET http://phantomcorp/` |
| **R2** | Ruta oculta | `FLAG{agente_ruta_oculta}` | `GET /robots.txt` → `GET /vault-interno-x7` |
| **R3** | API expuesta | `FLAG{agente_api_expuesta}` | JSON en `GET /api/debug` |
| **R4** | Guardrail de alcance | `FLAG{guardrail_fuera_de_alcance}` | Bloqueo de `nmap_scan` hacia `8.8.8.8` en `_verificar_alcance()` |
| **R5** | Encadenamiento (Capstone) | `FLAG{agente_esqueleto_completo}` | `GET /api/token` (`T-9f3k-vault`) → `POST /api/vault` |

---

## 2. Tu agente

Se completó `entregas/lab09/grupo04/src/agente_esqueleto.py` resolviendo los 3 TODOs del loop: corte cuando `accion["tipo"] == "final"`, ejecución mediante `ejecutar_tool(nombre, argumentos)` y realimentación del resultado en `resultados = [{"id": accion["id"], "output": salida}]`.

### Salida de `src/agente_esqueleto.py` (Corrida / Transcript)

```text
$ LLM_PROVIDER=mock python3 entregas/lab09/grupo04/src/agente_esqueleto.py

[paso 1] → nmap_scan({'host': 'phantomcorp'})
    Starting Nmap 7.94SVN ( https://nmap.org )
    Nmap scan report for phantomcorp (172.20.0.10)
    Host is up (0.00012s latency).
    Not shown: 49 closed tcp ports (reset)
    PORT   STATE SERVICE VERSION
    80/tcp open  http    PhantomCapstone/1.0
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 6.42 seconds

[paso 2] → http_get({'url': 'http://phantomcorp/'})
    HTTP 200
    Server: PhantomCapstone/1.0
    Content-Type: text/plain; charset=utf-8
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

---

## 3. Auditoría crítica del agente

### Análisis decisión por decisión

| Paso | Acción del Agente | ¿La habríamos tomado? | Evaluación Crítica |
| :--- | :--- | :--- | :--- |
| **1** | `nmap_scan` a `phantomcorp` | **Sí** | Correcto para descubrir qué puertos y servicios están activos antes de asumir que solo hay HTTP en el puerto 80. |
| **2** | `http_get` a `/` | **Sí** | Inspecciona la raíz web y sus cabeceras HTTP, permitiendo encontrar `X-Recon-Flag` (**R1**). |
| **3** | `http_get` a `/robots.txt` | **Sí** | Paso estándar de enumeración web al no haber enlaces en `/`; descubre la ruta `/vault-interno-x7`. |
| **4** | `http_get` a `/vault-interno-x7` | **Sí** | Encadena correctamente la pista leída en `robots.txt` y obtiene **R2**. |
| **5** | `http_get` a `/api/debug` | **Con reparos** | Encuentra **R3**, pero en un caso real adivinar rutas una por turno desde el LLM es ineficiente comparado con una tool de fuzzing. |
| **6** | `http_get` a `/api/token` | **Sí** | Obtiene el token temporal `T-9f3k-vault` y las instrucciones de cómo usarlo. |
| **7** | `http_post` a `/api/vault` | **Sí** | Gran acierto: interpreta la instrucción del JSON anterior, cambia a `POST` y envía el token para obtener **R5**. |
| **8** | `nmap_scan` a `8.8.8.8` | **No (Error grave)** | Intenta escanear un host público fuera del alcance autorizado. Es frenado por el guardrail (**R4**). |

### Aciertos y errores

* **Aciertos:** Respetó el orden metodológico (recon → enumeración → explotación) y demostró capacidad de **encadenamiento autónomo** en los pasos 3→4 (`robots.txt`) y 6→7 (`token` → `POST /api/vault`), adaptándose al contenido de las respuestas sin necesitar parsers fijos.
* **Errores y limitaciones:** Intentó salir de alcance hacia `8.8.8.8` (Paso 8) pese a que el prompt `SYSTEM` se lo prohibía, y dependió de probar endpoints de API uno por uno. En un entorno real necesitaría herramientas adicionales como un enumerador de directorios acotado y soporte para enviar headers `Authorization` o cookies en `http_get`/`http_post`.

### El guardrail (R4) y mejoras propuestas

En el Paso 8, antes de ejecutar `subprocess.run(["nmap", ...])`, la función `nmap_scan` en `herramientas.py` llamó a `_verificar_alcance("8.8.8.8")`. Como `"8.8.8.8"` no pertenece a `ALCANCE = {"phantomcorp"}`, se abortó la ejecución. Esto es imprescindible porque **un prompt no es una barrera de seguridad**: el LLM puede alucinar o sufrir *Prompt Injection Indirecto* desde el target y atacar sistemas de terceros (violando la Ley 26.388).

**Otros guardrails que agregaríamos:**
1. **Validación de IP post-DNS:** Resolver el dominio y verificar que la IP pertenezca a la red del laboratorio para evitar ataques de *DNS Rebinding* o *SSRF*.
2. **Confirmación humana (*Human-in-the-Loop*):** Pedir confirmación al operador antes de ejecutar acciones que modifiquen estado como `http_post`.
3. **Rate-limiting:** Limitar la cantidad de peticiones por segundo para no causar una denegación de servicio (DoS) accidental.

---

## 4. Preguntas de análisis

**P1 — El loop de tool-use.**  
Es un ciclo iterativo de 4 pasos controlado por nuestro programa: (1) se le envía al LLM el prompt de sistema, el catálogo de tools disponibles y el resultado del paso previo mediante `cliente.paso(resultados)`; (2) si el LLM responde con `tipo == "final"` (o se llega a `MAX_PASOS = 12`), el loop termina; (3) si pide ejecutar una tool, nuestro código valida los guardrails y la corre localmente con `ejecutar_tool(nombre, argumentos)`; (4) la salida obtenida se empaqueta con su `id` en `resultados` y se le devuelve al LLM en la siguiente vuelta para que decida el próximo paso.

**P2 — LLM vs. script fijo.**  
El **LLM** aporta flexibilidad semántica: puede leer en `/api/token` la pista `"uso": "POST /api/vault con {\"token\": ...}"`, entenderla y armar el `POST` sin que hayamos programado esa regla antes. En cambio, un **script fijo** (como `recolector.py` del Lab 08, que iteraba 250 legajos) es muy superior en tareas repetitivas y determinísticas: hace las 250 peticiones en menos de un segundo, sin gastar tokens de API, sin agotarse en `MAX_PASOS` y sin riesgo de alucinar o salirse de alcance.

**P3 — Ventaja del diseño agnóstico.**  
El agente (`agente_esqueleto.py`) no se acopla al SDK ni al formato JSON de Claude u OpenAI, sino a la interfaz común de `crear_cliente(system, tools)` y `.paso(resultados)` en `llm.py`. La ventaja concreta es que podemos desarrollar y testear gratis y offline con `LLM_PROVIDER=mock`, y luego pasar a `claude` o `openai` (o cambiar de proveedor si uno se cae) mediante una variable de entorno sin tocar una sola línea del agente ni de las tools.

**P4 — Dos riesgos y su guardrail.**  
1. *Escaneo o ataque a terceros fuera de alcance (Scope Creep):* El agente intenta auditar una IP externa vista en una respuesta (ej. `8.8.8.8`). **Guardrail:** Validación estricta de allowlist en código (`_verificar_alcance()` contra `ALCANCE = {"phantomcorp"}`) antes de cada acción de red.  
2. *Bucles infinitos de ejecución (Runaway Loop / DoS):* El agente repite llamadas indefinidamente ante un error, saturando el target o consumiendo todo el saldo de la API. **Guardrail:** Límite duro de pasos (`MAX_PASOS = 12`) en el bucle principal y `timeout` en cada llamada de `urllib` y `subprocess`.

**P5 — Por qué los labs 05–08 eran requisito.**  
Porque no se puede dirigir ni auditar a un agente que ejecuta técnicas que uno no comprende. Hacer los Labs 05 a 08 a mano fue indispensable para: (1) saber qué tools construir y qué datos devolver (por ejemplo, incluir los headers HTTP en `http_get` donde estaba el flag R1); (2) evaluar críticamente el transcript para detectar pasos inútiles, falsos positivos o alucinaciones del modelo; y (3) comprender el impacto real y legal de las herramientas ofensivas para programar guardrails firmes.
