# PTaaS – Grupo 02

## Descripción

Implementación de un núcleo de **Pentest as a Service (PTaaS)** gobernado por un
**swarm de agentes**, con un plano de control determinista (el *harness*) que hace
cumplir autorización, alcance, ejecución segura, auditoría y aprobación humana.

Idea central del diseño: **el agente propone, el harness dispone.** Un modelo
puede equivocarse o ser engañado; el sistema que lo rodea no puede permitírselo.

## Arquitectura

El sistema tiene dos mitades con trabajos opuestos:

- **Swarm (propone, nunca ejecuta):** agentes con mandato acotado, definidos en
  `prompts/`. Cada uno recibe información, produce una salida con *schema* y la
  entrega; no toca herramientas por su cuenta.
- **Harness (decide y registra, en código determinista):** toda acción cruza
  `Harness.invoke`, que chequea en orden **kill switch → guard + scope token →
  gate humano → adaptador → bitácora**.

## Estructura

- `harness/contracts.py`: contratos, Guard, Harness, ScopeToken, adaptadores, bitácora y Kill Switch.
- `harness/engagement.py`: máquina de estados del engagement.
- `harness/loops.py`: loops de reconocimiento, detección y validación.
- `harness/adapters/`: adaptadores Nmap y Nuclei.
- `harness/poc/`: catálogo de pruebas de concepto parametrizadas (inertes).
- `harness/policy.yaml`: políticas de seguridad.
- `harness/tools.yaml`: capacidades y herramientas permitidas.
- `harness/schemas.py`: modelos y validación de datos de intercambio entre agentes.
- `harness/reporting.py`: generación y control de entrega de informes.
- `prompts/`: **system prompts de los agentes del swarm** (ver abajo).
- `demo_swarm.py`: **recorrido de los agentes de punta a punta en modo golden.**
- `tests/`: pruebas automatizadas.

## Swarm de agentes

Cada agente se define por un *system prompt* (`prompts/`) con seis partes: rol y
mandato, prohibiciones explícitas, entrada → salida con *schema*, permiso para no
saber (`null`/`unknown`), condición de parada a cargo del harness, y contexto mínimo.

| Prompt | Agente | Entrada → Salida (schema) |
|---|---|---|
| `00-orchestrator.md` | Orchestrator | RoE y objetivos → plan de fases |
| `02-discovery.md` | Discovery | token de recon → `Asset[]` |
| `03-analysis.md` | Analysis | grafo de activos → `CandidateFinding[]` y `PrioritizedVuln[]` |
| `05-validation.md` | Validation | vuln aprobada → elección de PoC + parámetros (con gate humano) |
| `06-reporting.md` | Reporting | evidencia → informe |

No son agentes: el **Scope Guard** es código determinista (la autorización no
puede ser probabilística) y el **Reviewer** de los gates es una persona.

**Por qué el *schema* es una barrera de seguridad:** si un candidato no puede
existir sin evidencia, un hallazgo inventado no tiene dónde apoyarse. El propio
modelo de datos rechaza la invención.

## Demo del swarm

`demo_swarm.py` ejecuta el recorrido Discovery → Analysis → Validation →
Reporting en **modo golden** (sin llamar a un modelo real), usando un caso real
del engagement del grupo (phantomcorp). Cada salida se valida contra su *schema*,
y el cierre demuestra el control en acción: si un agente intentara devolver un
candidato **sin evidencia**, el *schema* lo rechaza (`SchemaError`).

Ejecutar:

    cd entregas/labfinal/grupo02
    python3 demo_swarm.py

## Requisitos

- Python 3.11 o superior.
- Dependencias declaradas en `requirements.txt`.

Instalación:

    python -m pip install -r entregas/labfinal/grupo02/requirements.txt

## Ejecutar pruebas

Desde la raíz del repositorio:

    DEST="entregas/labfinal/grupo02"
    PYTHONPATH="$DEST" python -m pytest -v "$DEST/tests"

## Controles de seguridad

- Restricción de activos por CIDR y dominios autorizados.
- Validación de ventana temporal y fase del engagement.
- Allowlist de acciones por fase.
- Bloqueo de acciones y adaptadores destructivos.
- Aprobación humana para operaciones que la requieren.
- Kill Switch para abortar ejecuciones.
- Registro de decisiones y encadenamiento de hashes de auditoría.
- Adaptadores con argumentos acotados y ejecución sin shell.

## Validación

La batería de pruebas automatizadas del harness está aprobada. Las pruebas de
adaptadores utilizan runners controlados; el resultado de las pruebas no implica
que se haya ejecutado un escaneo real.

## Alcance y próximos pasos (honesto)

- **Hecho:** el harness (controles + invariantes), los 5 agentes definidos, y el
  recorrido del swarm corriendo en modo golden con validación de schema.
- **Siguiente paso:** ejecución en vivo (modo *live*), donde un modelo real genera
  las salidas de cada agente a partir de las entradas. Requiere una API key y es
  la continuación natural del trabajo. El modo golden demuestra que los contratos
  entre agentes cierran de punta a punta antes de incorporar el modelo.

## Uso responsable

Este sistema debe utilizarse exclusivamente sobre activos con autorización
expresa y dentro de las condiciones definidas en el Rules of Engagement (RoE).
La aprobación humana y los controles del Harness no sustituyen la autorización
legal ni la revisión del operador.