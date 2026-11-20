# Design — Change 003 · RoE y emisión de scope tokens

## Contexto
Hasta el change 001, los `ScopeToken` se construían a mano en los tests. Este change agrega el camino real: un **RoE firmado** (YAML) se valida y, solo si es válido, un **emisor** entrega tokens de corta vida, uno por fase. No se modifica la interfaz pública de `harness/contracts.py`.

## Archivos
| Archivo | Responsabilidad |
|---|---|
| `harness/roe.py` | Modelo `RoE` (inmutable) y `parse_roe()` con validaciones y errores explicativos (`RoEError`) |
| `harness/tokens.py` | `TokenIssuer` (único constructor de `ScopeToken`), `TokenRejected` y `EngagementGuard` |
| `roe/roe-lab.example.yaml` | RoE de ejemplo para el laboratorio aislado |
| `tests/test_roe_tokens.py` | Scenarios del delta + adversariales A6, A7 y A8 |

## Formato del RoE
Campos obligatorios: `engagement_id`, `scope` (`cidrs` y/o `domains`), `window` (`start`, `end`), `phases`, `emergency_contacts` (cada uno con `name` y `channel`) y `approver` (`name`, `role`, `approved_at`). Campo opcional: `exclusions` (`cidrs`, `domains`). Ver el ejemplo en `roe/roe-lab.example.yaml`.

## Validaciones (en este orden)
1. Es un mapa YAML y están todos los campos obligatorios.
2. El alcance no está vacío.
3. **Alcance máximo:** cada CIDR debe ser subred de `targets.lab_only_cidrs` y cada dominio debe estar en `targets.lab_only_domains` (`profiles.yaml`). Por eso un `/8`, un `/16` o `0.0.0.0/0` se rechazan (A8).
4. **Exclusiones:** si dejan el alcance vacío, el RoE se rechaza. Una exclusión que sea subdominio de un dominio autorizado también se rechaza (ver decisión 3).
5. **Ventana:** fechas ISO-8601 **con zona horaria obligatoria**; se convierten a epoch UTC. Una fecha sin zona se rechaza (A7). `end` debe ser posterior a `start`.
6. **Fases:** solo valores de `Phase`.
7. **Aprobación:** `approver.role` debe ser `reviewer` (el mismo rol de los gates HITL de `policy.yaml`) y `approved_at` no puede ser posterior al fin de la ventana.

## Decisiones
1. **Representación de la aprobación (pregunta abierta 1).** Aprobador + rol + fecha dentro del RoE, más una **huella SHA-256** del contenido canónico (`RoE.fingerprint`). La huella identifica qué versión exacta del RoE se aprobó. Una firma criptográfica real queda como mejora (desafío C3).
2. **Las exclusiones se descuentan al emitir.** El emisor calcula `alcance − exclusiones` con `ipaddress.address_exclude` y el token solo contiene lo que queda. Así el `Guard` existente aplica las exclusiones sin conocerlas y sin cambiar su contrato.
3. **Exclusión de subdominio = RoE rechazado.** El `Guard` autoriza un dominio y todos sus subdominios por sufijo; con el `ScopeToken` actual no se puede expresar "este dominio menos este subdominio". En vez de aceptar un RoE que no se puede hacer cumplir, se rechaza y se pide listar los hosts exactos.
4. **Vida del token.** `min(TTL de la fase en policy.yaml, fin de la ventana del RoE)`. Nunca supera la ventana.
5. **Sin renovación automática.** No existe `renew()`. Al vencer, hay que pedir un token nuevo, que se vuelve a validar contra el RoE y queda registrado.
6. **Revocación (pregunta abierta 2).** `TokenIssuer.revoke()` impide nuevas emisiones y **activa el kill switch**: los tokens ya emitidos dejan de servir porque `Harness.invoke` aborta todo. Se registra como `ABORTED`.
7. **Tokens en paralelo (pregunta abierta 3).** Se permiten tokens de varias fases a la vez, pero cada uno habilita **solo su fase** (lo garantiza el `Guard`). El orden de fases lo impone la máquina de estados del engagement, no el emisor.
8. **Token de otro engagement (A6).** `EngagementGuard` extiende `Guard` y rechaza tokens cuyo `engagement_id` no coincide. Se usa en lugar de `Guard` al armar el `Harness` del engagement.
9. **Registro de rechazos.** `AuditLog.record` exige un token. Para registrar un rechazo, el emisor usa un token nulo (sin alcance y con ventana 0–0, nunca vigente) que solo identifica el engagement y la fase.
10. **Único constructor.** Un test recorre el código y falla si algún archivo de producción fuera de `harness/tokens.py` construye `ScopeToken`. Los tests sí pueden hacerlo (fixtures).

## Riesgos y límites conocidos
- La huella no es una firma: alguien con acceso al archivo puede cambiar el RoE y recalcularla. Mitigación prevista: firma (C3) y bitácora persistente (change 002).
- La validación de alcance usa `profiles.yaml`; si ese archivo se amplía sin revisión, se amplía el alcance posible. Por eso `profiles.yaml` exige delta de spec y revisión.
- `Harness.invoke` valida vigencia con el reloj real; los tests del emisor usan un reloj inyectado y los que pasan por el `Harness` usan un RoE con ventana alrededor de la hora actual.

## Mutation check (registro)
Se rompió el código a propósito para comprobar que los tests lo detectan. Las 5 mutaciones fueron detectadas:

| Mutación | Tests que fallaron |
|---|---|
| El emisor ignora las exclusiones | 1 |
| `EngagementGuard` no compara el engagement | 1 |
| El parser acepta fechas sin zona horaria | 1 |
| El parser acepta CIDR fuera del laboratorio | 4 |
| El emisor ignora las fases del RoE | 1 |
