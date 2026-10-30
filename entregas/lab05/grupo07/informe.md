# Informe — Laboratorio 05 · Reconocimiento

**Grupo:** 07
**Integrantes:**
Lorenzo Blanc — @LoloBlanc
Fernando Cagliero — @Ferca19
Guadalupe Gómez — @guadagomezgg8
Lautaro Mariño — @lautaromarino0
**Fecha:** 30/10/2026

---

## 0. Declaración de uso de IA

Se utilizó el asistente de IA **Claude (Anthropic)**. Según lo que pide el `CONTRIBUTING.md`:

- **Qué herramienta:** Claude (Anthropic).
- **Qué partes / para qué:** ayudó en el reconocimiento sobre la investigación y elección de técnicas para aplicar en los retos y ayudó a redactar el informe.
- **Cómo se verificó:** cada flag se validó con `./ctf submit`; las versiones de los servicios se confirmaron contra la salida real de los comandos, guardada en `/loot`.
- _(Completar cada integrante: usos de IA en el mapa, las demás preguntas o el mini-research, si los hubo, y cómo lo verificó.)_

---

## 1. Parte práctica — flags capturadas

Las 5 flags se capturaron **operando las herramientas** contra `phantomcorp`, no leyéndolas de ningún archivo. Salida de `./ctf status 05`:

```
  PROGRESO · LAB 05
   ✓  R1     Puerto oculto en rango alto (barrido completo)
   ✓  R2     Banner grabbing del servicio FTP
   ✓  R3     Fuga de informacion en headers HTTP
   ✓  R4     Enumeracion de rutas via robots.txt
   ✓  R5     Servicio dev expuesto en produccion
  ██████████████████████████████  5/5 (100%)
```

| Reto | Puerto | Técnica | Flag |
|---|---|---|---|
| R1 | 31337 | Barrido completo de puertos (`nmap -p-`) + banner con `ncat` | `FLAG{high_port_secret_service}` |
| R2 | 21 | Banner grabbing FTP (`ncat`) | `FLAG{banner_grab_proftpd_135}` |
| R3 | 80 | Análisis de headers HTTP (`curl -I`) | `FLAG{http_headers_leak_info}` |
| R4 | 80 | Enumeración de rutas vía `robots.txt` | `FLAG{recon_hidden_path}` |
| R5 | 8080 | Servicio de desarrollo expuesto (endpoint `/status`) | `FLAG{dev_service_exposed}` |

---

## 2. Mapa de superficie de ataque

> ⚠️ **PENDIENTE — Partes B y C del reparto.** (B: puertos **21** y **80** · C: puertos **8080** y **31337**.)
> Completar la clasificación —CVE relevante, CVSS, criticidad **justificada contra este caso**— usando la evidencia del recon de la Parte A. Recordá: inventar un CVE o afirmar una versión sin evidencia es causal de rechazo; "no pude determinar la versión" es válido.

**Datos crudos del recon (Parte A), para construir el mapa:**

| Puerto | Servicio | Versión / evidencia hallada (Parte A) |
|---|---|---|
| 21 | FTP | `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)` — banner obtenido con `ncat phantomcorp 21`. |
| 80 | HTTP | `Server: PhantomServer/2.4.1`, `X-Powered-By: PhantomCMS 2.4.1` — headers con `curl -I`. Son productos ficticios del lab → evaluar "sin CVE conocido" (respuesta honesta y válida). |
| 8080 | HTTP (dev) | `Server: Werkzeug/2.0.1 Python/3.9.2`, `version: 0.9.3-DEV`, `debug: true` — server de desarrollo de Flask, no apto para producción. |
| 31337 | "maintenance shell" | `PhantomCorp maintenance shell v0.1` — banner con `ncat`. Puerto **oculto**, hallado solo con `nmap -Pn -p-`. |

*Evidencia completa en `.loot/`: `01-nmap-allports.txt`, `02-r1-port31337.txt`, `03-r2-ftp-banner.txt`, `04-r3-http-headers.txt`, `05-r4-robots.txt`, `06-r4-oculta.txt`, `07/08/09-r5-8080-*.txt`.*

**Tabla de clasificación (a completar por B y C):**

| Puerto | Servicio | Versión (evidencia) | ¿Cómo lo identificaste? | CVE relevante | CVSS | Criticidad | Justificación (contra ESTE caso) |
|---|---|---|---|---|---|---|---|
| 21 | | | | | | | |
| 80 | | | | | | | |
| 8080 | | | | | | | |
| 31337 | | | | | | | |

---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**
> ⚠️ PENDIENTE (Parte C). Pista de la evidencia: el `31337` solo apareció con `nmap -Pn -p-`; el escaneo default (1000 puertos) no lo veía.

**P2 — El servicio dev en producción.**
> ⚠️ PENDIENTE (Parte D). Evidencia de la Parte A: `Server: Werkzeug/2.0.1` (server de desarrollo de Flask), `version: 0.9.3-DEV`, `debug: true` en el `/status` del 8080.

**P3 — La ironía de `robots.txt`.**
> ⚠️ PENDIENTE (Parte B). Evidencia: el `robots.txt` del 80 listaba `Disallow: /panel-interno-9x2f`, con un comentario de infra admitiendo que "sigue accesible desde afuera".

**P4 — Pasivo vs. activo.**

El reconocimiento **pasivo** recolecta información **sin tocar** el objetivo (por ejemplo `whois`, `dig`/DNS público, certificados, OSINT): no genera tráfico contra el target, así que es casi indetectable y de bajo riesgo legal. El **activo** **interactúa** con el objetivo —le manda paquetes o peticiones— y por eso queda registrado en sus logs y requiere autorización.

En este laboratorio **todo lo que hice fue reconocimiento activo**: el barrido de puertos (`nmap -Pn -p- phantomcorp`), el banner grabbing con `ncat` contra el FTP (21) y el servicio oculto (31337), y las peticiones HTTP con `curl` contra el 80 y el 8080 (headers, `robots.txt`, `/panel-interno-9x2f`, `/status`). No hice recon pasivo porque `phantomcorp` es un host **interno**, sin dominio ni DNS público, así que `whois`/`dig` no aplicaban; en un engagement real el pasivo iría **primero**, justamente para no alertar al objetivo antes de tener autorización.

**¿Cuáles de mis acciones habrían quedado en los logs de PhantomCorp?** Todas, porque todas fueron activas: cada conexión TCP y cada petición dejó rastro. La más ruidosa es el `nmap -p-`: sondear los 65535 puertos genera un patrón de conexiones inconfundible para cualquier IDS o revisión de logs. Y cada `curl` dejó su línea en el access-log del servidor web (IP de origen, método, ruta, user-agent y timestamp), incluido el acceso a la ruta "oculta" `/panel-interno-9x2f`.

**P5 — Ahora sos el defensor.**
> ⚠️ PENDIENTE (Parte D). Dos candidatos fuertes a partir de los hallazgos: cerrar/filtrar el `31337` (o sacar ese "maintenance shell"), y quitar el server dev del `8080` de producción (o al menos desactivar `debug`).

---

## 4. Bitácora de comandos

Reconocimiento ejecutado desde la consola del atacante (`docker exec -it cyberlab-attacker bash`), contra `phantomcorp`. Las salidas completas están en `.loot/`.

```bash
# Alcance del target
ping -c1 phantomcorp

# R1 — barrido completo: aparece el puerto oculto 31337
nmap -Pn -p- phantomcorp -oN /loot/01-nmap-allports.txt
ncat -w3 phantomcorp 31337 </dev/null | tee /loot/02-r1-port31337.txt

# R2 — banner grabbing del FTP (ProFTPD 1.3.5)
ncat -w3 phantomcorp 21 </dev/null | tee /loot/03-r2-ftp-banner.txt

# R3 — headers HTTP del puerto 80 (fuga en X-Backend-Flag)
curl -sI phantomcorp | tee /loot/04-r3-http-headers.txt

# R4 — enumeración de rutas por robots.txt → ruta oculta
curl -s phantomcorp/robots.txt | tee /loot/05-r4-robots.txt
curl -s phantomcorp/panel-interno-9x2f | tee /loot/06-r4-oculta.txt

# R5 — servicio dev en el 8080 (Werkzeug, debug:true) → /status
curl -sI phantomcorp:8080/ | tee /loot/07-r5-8080-headers.txt
curl -s  phantomcorp:8080/ | tee /loot/08-r5-8080-root.txt
curl -s  phantomcorp:8080/status | tee /loot/09-r5-8080-status.txt
```
