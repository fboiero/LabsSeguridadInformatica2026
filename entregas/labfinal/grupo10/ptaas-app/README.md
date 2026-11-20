# PTaaS — Grupo 10

**Primera demo funcional: cuatro agentes con IA real y herramientas simuladas.**
No es todavía un pentest, una plataforma completa ni una entrega final aprobada.
La extensión opcional agrega un quinto rol de análisis de código propio. Se probó
offline con un informe real de Bandit, sin enviar dicho informe a un proveedor.

## Qué funciona

1. **Planificador:** organiza el trabajo de los especialistas.
2. **Reconocimiento:** propone la consulta permitida y decide cuándo detenerse.
3. **Correlación:** analiza el inventario sin inventar CVE cuando no hay fuentes.
4. **Informe:** redacta un borrador, sin aprobar su propia entrega.

Son contextos y mandatos separados sobre el modelo configurado en OpenCode;
no requieren cuatro modelos diferentes. No son subagentes programadores.
Los agentes devuelven JSON validado con Pydantic y no tienen terminal, archivos
ni MCPs. Solo el harness puede llamar al adaptador, que en esta demo devuelve
datos sintéticos para `dvwa.lab.test`: **no hace escaneos ni tráfico al objetivo**.

El historial se guarda en SQLite con hashes encadenados, protección contra
edición/borrado ordinarios, registro previo a ejecutar y suspensión ante fallos.
Sin anclaje externo **no se detecta confiablemente el truncamiento final ni
la reescritura completa**. El verificador declara ese límite.

## Ejecutar en Windows

Desde esta carpeta, usando Python 3.12:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider
.\.venv\Scripts\python.exe -B -m evals.run_evals
.\.venv\Scripts\python.exe -B tools/progress.py
```

Prueba offline (sin modelo, explícitamente identificada como fixture):

```powershell
.\.venv\Scripts\python.exe -B -m runtime.demo --provider fixture --approve-fixture --output runs/mi-prueba-offline
```

Prueba con **IA real**, usando la cuenta ya conectada en OpenCode V2:

```powershell
.\.venv\Scripts\python.exe -B -m runtime.demo --provider opencode --approve-fixture --output runs/mi-prueba-real
```

Cada ejecución necesita un directorio nuevo y puede consumir hasta seis llamadas
al modelo predeterminado. No equivale a un presupuesto monetario. No se leen ni
copian credenciales de OpenCode. Si su launcher de Windows no se puede resolver,
`PTAAS_OPENCODE_EXE` puede apuntar al ejecutable nativo `opencode.exe`.

`--approve-fixture` es una decisión de la persona que opera, limitada a esta demo
sintética. Sin ella no hay llamadas al modelo ni al adaptador. No autoriza un
escaneo real. El resultado exitoso termina en `PENDING_HITL / before_deliver`:
es el gate humano funcionando, no un error. No hay aprobación automática de entrega.

## Ver lo que hizo cada agente

### Analizar nuestro código con Bandit

Bandit revisa archivos Python sin ejecutarlos. Genera alertas preliminares, no
pruebas de explotabilidad. La persona ejecuta Bandit; el agente no lo puede llamar.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-security.txt
New-Item -ItemType Directory -Force runs | Out-Null
.\.venv\Scripts\bandit.exe -r harness runtime -f json -o runs/bandit-local.json
.\.venv\Scripts\python.exe -B -m runtime.demo --provider fixture --approve-fixture --bandit-report runs/bandit-local.json --output runs/mi-analisis-offline
```

Bandit puede salir con código 1 si encuentra alertas. El importador rechaza informes
incompletos; toma hasta 20 alertas ordenadas por severidad y confianza. `bandit-N`
corresponde a la posición original (desde 1) en `results` del JSON local.
Al analista solo le llegan esos IDs, la regla, severidad y confianza. Su análisis
queda separado en `bandit_analysis` de `result.json`; no se mezcla con los hallazgos
de la demo sintética. `fixture` no usa IA; `opencode` usa el modelo asignado al rol.

El ruteo queda fijado en `runtime/providers.py`: GPT‑6.2 Astra para Bandit y
MITRE; GPT‑6.2 Sol para coordinar y redactar; GPT‑6.1 Terra para inventario
simulado y correlación básica. La corrida histórica usó Astra para cuatro roles;
no incluyó Bandit ni MITRE. El ruteo no implica una comparación de rendimiento.

### Piloto defensivo MITRE ATT&CK

CLI separada, sin acciones sobre el laboratorio. Usa tres fixtures y un extracto
local de una técnica de ATT&CK Enterprise 17.1, no el catálogo completo. Queda
pendiente de revisión humana y guarda las referencias en `result.json`.

```powershell
.\.venv\Scripts\python.exe -B -m runtime.attack_pilot --provider fixture --output runs/mitre-offline
.\tools\attack-pilot-sandbox.ps1
```

El primer comando no usa IA real. Para una generación real, usar `--provider opencode`
y un directorio nuevo. El segundo construye una imagen con dependencias y corre
los tests en un contenedor desechable sin red. No es el sandbox del change 006.

Ver [pendientes de cátedra](docs/checkpoints-catedra.md).
Ver también [cómo reproducir el checkpoint 1](docs/evidencia-checkpoint-1.md).
Para PhantomCorp: [recolección local de evidencia autorizada](docs/phantomcorp-evidencia.md).
Para el análisis y los resultados: [paquete de revisión de evidencia](docs/calidad-de-evidencia.md).
Para el cierre: [demo documental en sandbox y exportación](docs/entrega-defensiva.md),
[informe técnico](docs/informe-tecnico-ptaas.md) y [selección de herramientas](docs/tool-selection.md).
[Loop de revisión y sandbox por caso](docs/loop-y-sandbox-defensivo.md) ·
[cobertura y pendientes frente a la cátedra](docs/cierre-catedra.md).
Para la ejecución sobre el laboratorio: [recorrido activo de PhantomCorp](docs/recorrido-activo-phantomcorp.md).
Para las verificaciones permitidas en DVWA/Juice Shop: [catálogo curado](docs/catalogo-poc.md).

Las ejecuciones que fallan por el proveedor guardan `result.json` con estado
`FAILED`, pasos ya aceptados y causa saneada. Las respuestas inválidas se
registran desde el primer intento sin guardar su contenido.

En el directorio de ejecución:

- `result.json`: roles, decisiones, cantidad de llamadas y estado final.
- `draft.json`: borrador marcado como simulado, si reporting terminó.
- `audit.db`: historial verificable. Estos artefactos se ignoran en Git.

La primera prueba real quedó en `runs/opencode-compatible/`: cinco generaciones,
cuatro roles, una consulta simulada y cero hallazgos confirmados.

```powershell
.\.venv\Scripts\python.exe -B -m harness.audit verify runs/opencode-compatible/audit.db
```

El comando no modifica la base. Código 0 significa estructura válida del archivo
disponible, no prueba de autenticidad o completitud histórica.

## Alcance y próximos pasos

Faltan la autorización desde RoE real (003), herramientas y loops completos
(004–005), análisis/validación en sandbox (006), informe profesional/exportación
(007), más evals y revisión independiente. No se conectaron herramientas de
pentest ni se habilitaron objetivos de terceros o PhantomCorp.

## Documentación y trazabilidad

- [Propuesta aprobada y alcance](openspec/changes/002-audit-persistence/proposal.md).
- [Diseño](openspec/changes/002-audit-persistence/design.md).
- [Tareas](openspec/changes/002-audit-persistence/tasks.md).
- [Resultados y correspondencia de escenarios con tests](docs/resultados.md).
- [Revisión preliminar y próximos pasos](docs/revision-y-proximos-pasos.md).

Rama local: `change/002-audit-persistence`. Base del profesor:
`a1abb79449a68f3cae29d1e9d43a4ac4a4f53960`.
El [kit original](../../../../labs/labfinal-practico-integrador/ptaas-kit/README.md)
permanece sin modificaciones. Esta es una adaptación parcial ejecutable, no una
copia completa: `harness/types.py` y los contratos/guard derivan del código docente.
El desarrollo se guarda en `entregas/` porque la guía general prohíbe editar `labs/`.

## Uso de IA y aprobaciones

OpenCode con GPT-6.1 Sol asistió en diagnóstico, especificaciones, tests, código
y documentación. El usuario informó el acuerdo de los integrantes con la propuesta
y aprobó explícitamente la demo real mediante la cuenta configurada en OpenCode.
No se delegó desarrollo a subagentes ni se inventaron firmas de revisores.

Los agentes de runtime sí hicieron llamadas reales al modelo configurado.
Se verificaron tests, evals, tipos, restricciones y una ejecución real con datos
sintéticos. Esto no reemplaza la revisión independiente del código ni una demo
contra el laboratorio. No se hicieron commits, push ni publicaciones.
