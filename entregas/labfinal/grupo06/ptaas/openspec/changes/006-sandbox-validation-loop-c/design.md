# Design — Change 006: sandbox efímero y loop C

## Contexto

El catálogo de verificaciones inertes (`harness/poc/`) ya resuelve qué se puede
verificar y cómo se evalúa la respuesta: `run_parametrized()` rechaza una
verificación fuera del catálogo, la falta de aprobación y los parámetros
inválidos. Lo que falta es el componente que **envía la solicitud** (`Sender`),
el orquestador del loop C y la CLI con la que una persona aprueba o rechaza cada
hallazgo.

Este change no amplía el catálogo ni cambia el contrato de `Harness.invoke`,
`run_parametrized()` o `decide_validation()`.

Invariantes que gobiernan el diseño (skill `harness-invariants`):

- **I1:** el `Sender` es un `ToolAdapter`; nada lanza contenedores fuera de `Harness.invoke`.
- **I5:** aprobación humana por hallazgo antes de validar.
- **I7:** sin red hacia afuera, sin persistencia, sin datos de cliente.
- **I8:** solo se parametrizan entradas del catálogo versionado.

Criterio general: ante cualquier duda o fallo, **se falla cerrado**. La
verificación no se ejecuta o el hallazgo queda "no validado"; nunca al revés.

## Decisiones

### 1. Ciclo de vida: un contenedor por verificación

| Opción | Ventaja | Problema |
|---|---|---|
| Un sandbox compartido por todo el loop C | Arranca una sola vez | Arrastra estado entre verificaciones; "no deja estado" es difícil de demostrar |
| **Un contenedor por verificación** | El estado no sobrevive a la verificación por construcción | ~1 s de arranque por verificación |

**Elegida:** un contenedor por verificación. Con 6 entradas en el catálogo y 2
intentos como máximo, el costo de arranque no importa.

Cada contenedor:

- se crea con `docker run --rm` en la red interna del lab (nombre configurable;
  hoy `ptaas-p3_lab`);
- `--read-only`, `--tmpfs /tmp:size=8m`, sin volúmenes montados, sin variables
  de entorno del host;
- `--cap-drop ALL`, `--security-opt no-new-privileges`;
- `--memory 128m`, `--cpus 0.5`, `--pids-limit 64`;
- lleva la etiqueta `ptaas.engagement=<engagement_id>` y un nombre único
  (`ptaas-sbx-<engagement>-<uuid>`);
- ejecuta un script fijo que hace **una sola** solicitud GET y escribe el
  `ResponseRecord` como JSON por stdout.

La destrucción va en un `finally` con `docker rm -f <nombre>`, también cuando la
verificación falla o se agota el tiempo. Si la destrucción falla, el resultado se
registra como `ABORTED` en la bitácora y el engagement no avanza hasta que una
persona lo revise.

### 2. El `Sender` es un `ToolAdapter`

**Elegida:** `SandboxSender` implementa la firma
`Sender = Callable[[str, dict], ResponseRecord]` y se registra como herramienta
del harness. Cada envío pasa por `Harness.invoke` con un token de fase
`VALIDATE`; por lo tanto, el kill switch, el token y el gate se chequean antes de
crear el contenedor, y todo queda en bitácora.

Argv fijo y sin shell, como los adaptadores de P3. El agente solo aporta los
valores de los parámetros que declara la entrada del catálogo.

**Segunda barrera:** antes de crear el contenedor, el adaptador rechaza un
`base_url` cuyo host no esté en `targets.lab_only_domains` de `profiles.yaml`, o
cuyo esquema no sea `http`/`https`. Así, aunque la red quedara mal configurada,
la solicitud no sale del lab.

### 3. Límites

| Límite | Valor | Justificación |
|---|---|---|
| Timeout de la solicitud | 10 s | Igual a `httpx.timeout_s` en `profiles.yaml` |
| Timeout del contenedor completo | 30 s | Margen para arranque y destrucción |
| Tamaño de la respuesta | 1 MB; se trunca y se marca `truncated=true` | Los evaluadores de listado de directorio y de errores verbosos necesitan el cuerpo, pero acotado |
| Solicitudes por verificación | 1, sin seguir redirecciones | Verificación inerte; P3 tampoco sigue `Location` |
| Intentos por hallazgo | 2 | `max_loop_iterations.validation` de `policy.yaml` |

Los valores van en `profiles.yaml` bajo una entrada `sandbox`. Cambiarlos exige
delta de spec y revisión del `security-reviewer`, como el resto de los perfiles.

### 4. Evidencia: referencia, no contenido

**Se registra:**

- el id y la versión de la verificación;
- los parámetros enviados;
- el resultado (`validated` / `not_validated`) y el detalle del evaluador;
- el código HTTP;
- el **SHA-256 y el largo del cuerpo**, y si fue truncado.

**No se registra** el cuerpo de la respuesta ni sus encabezados completos. Lo
exige I7 (sin datos del cliente), y la bitácora de P1 ya rechaza la clave
`contenido`. El hash permite demostrar qué respuesta se observó sin guardarla.

### 5. Resultados distintos entre corridas

**Elegida:** un hallazgo queda `validated` solo si **todos** los intentos dan
`validated`. Si los intentos se contradicen, queda `not_validated` con motivo
"inconsistente".

Un falso positivo en el informe es peor que un hallazgo sin confirmar.

### 6. Si el Reviewer no responde

| Opción | Problema |
|---|---|
| Aprobar automáticamente tras un timeout | Es saltear el gate: causal de descalificación |
| Rechazar automáticamente tras un timeout | Pierde la decisión humana sin que nadie la tome |
| **Quedar en `PENDING_HITL`** | Ninguno |

**Elegida:** el hallazgo queda en `PENDING_HITL` y **nunca se aprueba solo**.
Cuando vence el token de la fase `VALIDATE`, el hallazgo pasa al informe como
"no validado (sin aprobación)". El informe se puede entregar con ese estado
visible.

### 7. Alcance de una aprobación

Una aprobación cubre la tupla **(hallazgo, verificación, hash de los
parámetros)**, no solo el hallazgo.

Si el agente cambia un parámetro después de la aprobación, el hash deja de
coincidir, la aprobación no vale y el hallazgo vuelve a `PENDING_HITL`. Sin esto,
el agente podría obtener aprobación para `path=/` y después ejecutar otra cosa.

La CLI de aprobación (`python -m harness.validation_cli`):

- `list`: muestra los hallazgos pendientes con la verificación propuesta y sus
  parámetros;
- `approve <hallazgo> --reviewer <nombre> --reason <texto>`;
- `reject <hallazgo> --reviewer <nombre> --reason <texto>`.

Cada aprobación o rechazo queda en bitácora con quién, cuándo, motivo y el hash
de parámetros. La CLI no se invoca desde código del agente ni desde los tests
como forma de aprobar: los tests construyen el registro de aprobación a mano
para probar el control, no la CLI.

### 8. Proponer una verificación nueva

No hay código. Una entrada nueva en `catalog.yaml` requiere:

1. un change OpenSpec con la justificación y la prueba de que es inerte;
2. revisión del subagente `security-reviewer`;
3. aprobación de una persona registrada en `approved_by` y `approved_at`.

`validate_entries()` ya rechaza entradas sin esos campos.

## Interfaz

```python
# harness/sandbox.py
class SandboxSender:                      # ToolAdapter
    def __init__(self, network: str, limits: SandboxLimits, runner=docker_runner): ...
    def __call__(self, poc_id: str, params: dict) -> ResponseRecord: ...

# harness/validation.py
def run_validation_loop(harness, token, findings, approvals, catalog) -> list[Evidence]: ...
```

`runner` se inyecta para que los tests unitarios no necesiten Docker; las
pruebas de aislamiento (3.3 y 3.4) sí corren contra Docker real.

## Verificación propuesta

| Task | Test |
|---|---|
| 3.1 | Sin aprobación, `run_validation_loop` devuelve `PENDING_HITL` y el `runner` no se llama |
| 3.1 | Aprobación con otro hash de parámetros: `PENDING_HITL` y el `runner` no se llama |
| 3.2 | Verificación fuera del catálogo: `not_validated` y el `runner` no se llama |
| 3.3 | Desde el sandbox, conectar a `1.1.1.1:80` falla; `base_url` fuera de `lab_only_domains` se rechaza antes de crear el contenedor |
| 3.4 | Con un evaluador que lanza una excepción, al terminar no queda ningún contenedor con la etiqueta del engagement |
| 2.3 | Respuesta de más de 1 MB: se trunca y se marca; timeout: `not_validated` |
| 2.6 | La bitácora contiene hash y largo del cuerpo y no contiene el cuerpo |

Mutaciones previstas: quitar el chequeo de aprobación, quitar el `finally`,
quitar la validación del host y aprobar sin comparar el hash de parámetros. Cada
una tiene que romper al menos un test.

## Qué no cubre este change

- Verificaciones nuevas en el catálogo.
- Validación con más de una solicitud (flujos autenticados, formularios).
- Ejecución fuera del lab del kit.

## Riesgos

- **Docker no disponible en el runner:** el sandbox se crea desde el host; si no
  hay Docker, el adaptador falla cerrado y el hallazgo queda `not_validated`.
- **Contenedor huérfano por un corte abrupto del proceso:** al iniciar el loop C
  se buscan contenedores con la etiqueta del engagement y se eliminan antes de
  empezar; el hallazgo se registra.
- **Dependencia de 005:** hasta que P4 entregue hallazgos reales, el loop C se
  prueba con hallazgos de fixture que respetan el schema `Finding`.
