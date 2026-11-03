# Evidencia — Lab 09 (validación contra el entorno Docker oficial)

Validación del agente entregado (`src/agente_esqueleto.py`) **contra el target
capstone del entorno Docker de la cátedra** (no en local), con el motor `mock`
(sin API key).

| Archivo | Qué es |
|---|---|
| `agente-docker-transcript.txt` | Corrida real de `agente_esqueleto.py` (motor `mock`) desde la consola atacante (`cyberlab-attacker`) contra `phantomcorp`. Las 5 flags, el encadenamiento `/api/token` → `POST /api/vault` (R5) y el bloqueo del guardrail (R4). |
| `ctf-status-09.txt` | Salida de `./ctf status 09` tras entregar las 5 flags: `5/5 (100%)`, validadas contra los hashes de `labs/lab09-agentes/retos.manifest`. |

## Cómo se reprodujo

```bash
make lab N=09                 # levanta phantomcorp + consola atacante (red cyberlab_labnet)
make shell                    # entra a cyberlab-attacker (sin key: usa el motor mock por defecto)
cd /repo/entregas/lab09/grupo08/src
LLM_PROVIDER=mock python3 agente_esqueleto.py
```

Luego, desde la raíz del repo:

```bash
./ctf submit 09 R1 'FLAG{agente_primer_recon}'
./ctf submit 09 R2 'FLAG{agente_ruta_oculta}'
./ctf submit 09 R3 'FLAG{agente_api_expuesta}'
./ctf submit 09 R4 'FLAG{guardrail_fuera_de_alcance}'
./ctf submit 09 R5 'FLAG{agente_esqueleto_completo}'
./ctf status 09
```

## Nota: diferencia con la corrida en local de los compañeros

El equipo que armó el agente corrió en Windows sin Docker, donde `nmap` no existía
(error `WinError 2`). En el contenedor oficial `nmap` **sí** está instalado: el
`nmap_scan` del paso 1 se ejecuta de verdad, aunque hace **timeout** con `-sV` y no
aporta ninguna flag (la de recon, R1, viaja en el header `X-Recon-Flag` y la captura
el `http_get`). Ningún reto depende de `nmap`. **No se usó ninguna API key** (motor
`mock`): nada que rotar ni filtrar.
