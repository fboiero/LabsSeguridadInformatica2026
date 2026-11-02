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

**Guadalupe Gómez — Parte A:**

Se utilizó el asistente de IA **Claude (Anthropic)**. Según lo que pide el `CONTRIBUTING.md`:

- **Qué herramienta:** Claude (Anthropic).
- **Qué partes / para qué:** ayudó en el reconocimiento sobre la investigación y elección de técnicas para aplicar en los retos y ayudó a redactar el informe.
- **Cómo se verificó:** cada flag se validó con `./ctf submit`; las versiones de los servicios se confirmaron contra la salida real de los comandos, guardada en `/loot`.
- **Pendiente — Lautaro Mariño (Parte B):** incorporar su declaración de uso
  de IA al completar las filas 21 y 80 y P3.

**Lorenzo Blanc — Parte C:** se utilizó **Codex (OpenAI)** para analizar la evidencia de la Parte A, redactar la clasificación de los puertos 8080 y 31337 y responder P1. La verificación consistió en contrastar los banners y datos transcritos en este informe con las afirmaciones de las filas, y consultar la documentación oficial de Werkzeug y Nmap enlazada en las secciones correspondientes. Se distinguieron riesgos potenciales de capacidades comprobadas, sin asignar CVEs ni puntajes sin respaldo. No se repitió el reconocimiento: se reutilizó la evidencia capturada por Guadalupe; los archivos originales de `.loot/` no estaban disponibles en esta copia local.

**Fernando Cagliero — Parte D:** se utilizó **OpenAI Codex** para investigar
el modo debug de Werkzeug, redactar `research.md`, P2 y P5, y revisar el armado
de la entrega. Las afirmaciones se contrastaron con las transcripciones de la
Parte A y las fuentes primarias de Pallets y MITRE, incluida la documentación
de Werkzeug 2.0.1. Se verificaron estructura del informe, referencias y
consistencia de versiones, puertos y medidas propuestas. Se reutiliza el
reconocimiento de Guadalupe: no se levantó Docker ni se realizaron nuevas
capturas, explotación o cambios sobre el objetivo. La revisión y los pendientes
del armado se detallan en la sección 5.

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

> ⚠️ **PENDIENTE — Parte B del reparto:** clasificación de los puertos **21** y **80**. Parte C: puertos **8080** y **31337** completos a partir de la evidencia de la Parte A.

**Datos crudos del recon (Parte A), para construir el mapa:**

| Puerto | Servicio | Versión / evidencia hallada (Parte A) |
|---|---|---|
| 21 | FTP | `220 ProFTPD 1.3.5 Server (PhantomCorp FTP)` — banner obtenido con `ncat phantomcorp 21`. |
| 80 | HTTP | `Server: PhantomServer/2.4.1`, `X-Powered-By: PhantomCMS 2.4.1` — headers con `curl -I`. Son productos ficticios del lab → evaluar "sin CVE conocido" (respuesta honesta y válida). |
| 8080 | HTTP (dev) | `Server: Werkzeug/2.0.1 Python/3.9.2`, `version: 0.9.3-DEV`, `debug: true` — server de desarrollo de Flask, no apto para producción. |
| 31337 | "maintenance shell" | `PhantomCorp maintenance shell v0.1` — banner con `ncat`. Puerto **oculto**, hallado solo con `nmap -Pn -p-`. |

*Evidencia completa en `.loot/`: `01-nmap-allports.txt`, `02-r1-port31337.txt`, `03-r2-ftp-banner.txt`, `04-r3-http-headers.txt`, `05-r4-robots.txt`, `06-r4-oculta.txt`, `07/08/09-r5-8080-*.txt`.*

**Tabla de clasificación (pendientes las filas de la Parte B):**

| Puerto | Servicio | Versión (evidencia) | ¿Cómo lo identificaste? | CVE relevante | CVSS | Criticidad | Justificación (contra ESTE caso) |
|---|---|---|---|---|---|---|---|
| 21 | | | | | | | |
| 80 | | | | | | | |
| 8080 | HTTP de desarrollo | Header `Server: Werkzeug/2.0.1 Python/3.9.2`; aplicación `version: 0.9.3-DEV`, `debug: true`. Son versiones distintas: servidor y aplicación. | Evidencia de Guadalupe: `curl -sI phantomcorp:8080/` y `curl -s phantomcorp:8080/status`. | No se atribuye un CVE: el hallazgo es la exposición del servicio dev y su configuración declarada. El banner no prueba una vulnerabilidad explotable. | No asignado: no se calculó un vector CVSS para este hallazgo. | Alta (evaluación cualitativa). | El `/status` accesible revela versión interna y debug activo en una aplicación DEV. Werkzeug advierte que el depurador interactivo permite ejecutar código y no debe exponerse en producción [1]. Esto implica un riesgo potencial grave si esa consola está habilitada y accesible; `debug: true` por sí solo no demuestra acceso a ella ni ejecución de código en este lab. |
| 31337 | Servicio TCP identificado como "maintenance shell" | Banner `PhantomCorp maintenance shell v0.1`; no identifica un producto comercial ni la versión del sistema operativo. | Evidencia de Guadalupe: hallazgo con `nmap -Pn -p- phantomcorp` y banner con `ncat -w3 phantomcorp 31337 </dev/null`. | Sin CVE identificado para este servicio específico del lab; no se extrapola desde el nombre "shell". | No asignado: no se calculó un vector CVSS para este hallazgo. | Alta (evaluación cualitativa, por su aparente función de mantenimiento). | Servicio no documentado expuesto en un puerto alto: entrega su banner sin autenticación. Eso confirma acceso al servicio y fuga de información, pero no prueba una shell operativa ni ejecución de comandos sin credenciales. Si ofrece funciones administrativas sin autenticación, el impacto podría ser crítico. El número alto del puerto no constituye un control de acceso. |

**Alcance de la Parte C:** clasificación basada en las transcripciones del recon de Guadalupe incluidas arriba; no se realizaron pruebas de explotación. La criticidad expresa una prioridad contextual, no un puntaje CVSS ni una explotación confirmada.

[1] [Werkzeug — Debugging Applications](https://werkzeug.palletsprojects.com/en/stable/debug/): riesgos del depurador y advertencia de no utilizarlo en producción.

---

## 3. Preguntas de análisis

**P1 — El puerto que el escaneo default se perdió.**

Nmap escanea por defecto los **1000 puertos más frecuentes**, no los puertos del 1 al 1000. `-p-` amplía el rango a **1–65535**; en el comando utilizado en este lab corresponde a TCP, sin incluir UDP ni el puerto 0. `-Pn` omite el descubrimiento previo del host, pero no amplía los puertos examinados. Véase la [documentación oficial de Nmap](https://nmap.org/book/man-port-specification.html).

Según el registro de la Parte A, `nmap -Pn -p- phantomcorp` descubrió el **31337/tcp**, omitido por el barrido común; luego `ncat` devolvió `PhantomCorp maintenance shell v0.1`. La diferencia es la cobertura del escaneo: un puerto no examinado no puede considerarse cerrado. Un puerto alto tampoco garantiza quedar fuera de los 1000 más frecuentes en todas las instalaciones.

Como regla operativa, haría un barrido TCP completo dentro del alcance autorizado antes de cerrar el mapa, y después identificaría los servicios abiertos mediante versiones y banners. Registraría comandos, cobertura y evidencia; evaluaría UDP por separado, porque este barrido no lo cubre.

**P2 — El servicio dev en producción.**

La evidencia de Guadalupe reúne tres indicios en **8080/tcp**: el header
`Server: Werkzeug/2.0.1 Python/3.9.2`, la versión de aplicación
`0.9.3-DEV` y `debug: true` en `/status`. La combinación presenta un servicio
de desarrollo expuesto a otras máquinas del lab. Las versiones del servidor,
Python y la aplicación corresponden a componentes distintos; no deben
confundirse ni usarse para atribuirles automáticamente un CVE.

El problema no depende de encontrar un CVE: la funcionalidad de depuración
está pensada para el desarrollador. En Werkzeug 2.0.1, una traza puede incluir
una consola que, si está habilitada la evaluación interactiva (`evalex`) y
es accesible, permite ejecutar Python en el contexto de la aplicación.
El PIN no constituye una garantía suficiente para exponerla en producción
([documentación de Werkzeug 2.0.1](https://github.com/pallets/werkzeug/blob/2.0.1/docs/debug.rst)).
Además, Flask advierte que el servidor de desarrollo no está diseñado para
ser particularmente seguro, estable o eficiente en un despliegue de producción
([guía de despliegue](https://flask.palletsprojects.com/en/stable/deploying/)).

En **este** recon se comprobó la exposición de metadatos y del estado declarado
de debug. No se demostró una consola accesible ni ejecución remota. Eso limita
la conclusión técnica, pero no justifica mantener la instancia DEV publicada:
la información interna facilita el reconocimiento y una depuración interactiva
expuesta podría ampliar mucho el impacto.

**P3 — La ironía de `robots.txt`.**
> ⚠️ PENDIENTE (Parte B). Evidencia: el `robots.txt` del 80 listaba `Disallow: /panel-interno-9x2f`, con un comentario de infra admitiendo que "sigue accesible desde afuera".

**P4 — Pasivo vs. activo.**

El reconocimiento **pasivo** recolecta información **sin tocar** el objetivo (por ejemplo `whois`, `dig`/DNS público, certificados, OSINT): no genera tráfico contra el target, así que es casi indetectable y de bajo riesgo legal. El **activo** **interactúa** con el objetivo —le manda paquetes o peticiones— y por eso queda registrado en sus logs y requiere autorización.

En este laboratorio **todo lo que hice fue reconocimiento activo**: el barrido de puertos (`nmap -Pn -p- phantomcorp`), el banner grabbing con `ncat` contra el FTP (21) y el servicio oculto (31337), y las peticiones HTTP con `curl` contra el 80 y el 8080 (headers, `robots.txt`, `/panel-interno-9x2f`, `/status`). No hice recon pasivo porque `phantomcorp` es un host **interno**, sin dominio ni DNS público, así que `whois`/`dig` no aplicaban; en un engagement real el pasivo iría **primero**, justamente para no alertar al objetivo antes de tener autorización.

**¿Cuáles de mis acciones habrían quedado en los logs de PhantomCorp?** Todas, porque todas fueron activas: cada conexión TCP y cada petición dejó rastro. La más ruidosa es el `nmap -p-`: sondear los 65535 puertos genera un patrón de conexiones inconfundible para cualquier IDS o revisión de logs. Y cada `curl` dejó su línea en el access-log del servidor web (IP de origen, método, ruta, user-agent y timestamp), incluido el acceso a la ruta "oculta" `/panel-interno-9x2f`.

**P5 — Ahora sos el defensor.**

1. **Retirar el servicio de mantenimiento de 31337/tcp.** El barrido completo
   encontró un servicio no documentado que entrega su banner sin autenticar.
   Proponemos detenerlo y eliminar su arranque automático y su publicación de
   red. Mientras se retira, denegar expresamente las conexiones a ese puerto
   desde redes no autorizadas. Si el mantenimiento es necesario, debe pasar
   por un acceso administrativo documentado, autenticado y restringido a los
   responsables. **Comprobación posterior propuesta:** desde la misma red del
   recon, 31337 ya no debe aparecer abierto ni entregar el banner. Esto elimina
   una entrada innecesaria sin asumir que el banner demostró una shell operativa.

2. **Retirar la instancia DEV expuesta en 8080/tcp.** Proponemos quitar ese
   servicio del despliegue de producción. Si su aplicación es necesaria,
   desplegarla con un servidor WSGI de producción, debug y depurador interactivo
   deshabilitados, sin recargador automático, y acceso de red solo por el
   frontal previsto. Restringir también `/status` y evitar que publique versión
   interna o configuración de depuración, conforme a las recomendaciones de
   [Flask](https://flask.palletsprojects.com/en/stable/deploying/) y al tratamiento
   de código debug de [CWE-489](https://cwe.mitre.org/data/definitions/489.html).
   **Comprobación posterior propuesta:** la instancia DEV del 8080 no acepta
   conexiones desde la red del atacante, el frontal legítimo sigue disponible
   y el estado detallado no es público. Cambiar solamente el banner no corrige
   la exposición de la funcionalidad.

Son medidas y criterios de aceptación propuestos para el rol defensor; no se
aplicaron al entorno vulnerable de la cátedra durante esta revisión.

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

## 5. Revisión del aporte D y estado del armado — Fernando

Revisión documental realizada el **02/11/2026** con Python 3.12.2 y Git Bash
en Windows. El reconocimiento de la sección 4 fue realizado previamente por
Guadalupe; sus comandos y las cinco flags se conservaron. Los archivos
originales de `.loot/` no están presentes en este checkout: para P2, P5 y el
mini-research se utilizaron las transcripciones de las secciones 1 y 2.

La revisión contrastó las tres versiones del 8080 con la evidencia, verificó
que P5 contenga dos medidas y sus criterios de aceptación, y distinguió las
capacidades documentadas del depurador de las observadas en el lab. Las
tres fuentes del mini-research se consultaron directamente, incluida la
documentación de Werkzeug 2.0.1. Las comprobaciones propuestas en P5 quedan
para después de aplicar las medidas; no se presentan como pruebas realizadas.

Desde la raíz del repositorio se ejecutaron:

```bash
git diff --check
bash bin/validar-repo.sh
```

Ambos pasaron. La validación del repositorio comprobó compilación de Python,
sintaxis shell, manifiestos, documentación y enlaces internos. En Git Bash
se utilizó una función `python3` que delega en el Python 3.12.2 instalado y
`PYTHONPYCACHEPREFIX` apuntó a una carpeta temporal externa al repositorio.
La revisión de sintaxis no sustituye una nueva ejecución del reconocimiento.

**Estado para la entrega final:**

- [x] Parte D: `research.md`, P2, P5 y declaración de IA incorporados.
- [x] `INTEGRANTES.md` completo, con los datos de la entrega del Lab 04.
- [ ] Parte B de Lautaro: filas 21 y 80, P3 y su declaración de IA.
- [ ] Commit propio de Lautaro en esta rama; requisito de las cuatro cuentas.

El PR debe permanecer **en borrador** hasta incorporar esos pendientes y
revisar nuevamente el mapa y las cinco respuestas de análisis.
