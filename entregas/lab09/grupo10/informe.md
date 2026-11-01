# Informe — Laboratorio 09 · Agentes de pentest

**Grupo:** 10 · **Integrantes:** Belén Rocío Ramello — @belramello · Carolina Paula Corazza — @carocor1 · Chiara Agustina Kordek — @chiarakordek · Juan Pablo Saby — @JuanSaby · **Fecha:**
**Proveedor usado:** mock

## 0. Declaración de uso de IA

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

### 3.3 El guardrail (R4)

### 3.4 Otros guardrails que agregaríamos

## 4. Preguntas de análisis

### P1 — el loop de tool-use

### P2 — LLM vs. script fijo

### P3 — ventaja del diseño agnóstico

### P4 — dos riesgos y su guardrail

### P5 — por qué los labs 05–08 eran requisito

## Cierre

### Dificultades encontradas

### Distribución del trabajo

### Fuentes consultadas
