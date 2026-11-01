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
