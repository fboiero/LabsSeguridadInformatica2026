# Design — Change 003: RoE y emisión de scope tokens

## Contexto

Hoy `ScopeToken` se construye a mano en los tests. El harness ya bloquea por
fase, ventana y alcance, pero no existe una ruta que convierta un **RoE firmado**
en tokens de corta vida. Este change agrega el parser del RoE y el emisor; el
Guard y `Harness.invoke` no cambian de contrato salvo extensiones compatibles.

## Formato del RoE (YAML)

```yaml
engagement_id: eng-lab-001
approver: "Nombre y apellido (rol)"
approval_ref: "correo o ticket de aprobación"
signed_at: "2026-11-11T09:00:00-03:00"
window:
  start: "2026-11-11T09:00:00-03:00"
  end: "2026-11-11T18:00:00-03:00"
scope:
  cidrs: ["10.99.0.0/24"]
  domains: ["dvwa.lab.test", "juiceshop.lab.test"]
exclusions:
  cidrs: ["10.99.0.10/32"]
  domains: ["admin.dvwa.lab.test"]
emergency_contacts:
  - "responsable-lab@example.test"
authorized_phases: ["recon", "correlate", "analyze"]
```

`authorized_phases` es opcional: si falta, el RoE autoriza las fases de
`policy.yaml`. No se admiten comodines (`*`) ni rangos.
Si se declara explícitamente como una lista vacía, el RoE se rechaza para evitar
que una configuración vacía se interprete como autorización general.

## Validaciones (todas deterministas, sin LLM)

| Campo | Regla | Error |
|---|---|---|
| `engagement_id` | no vacío | `RoEValidationError` |
| `approver`, `approval_ref` | no vacíos | falta aprobación humana registrada |
| `signed_at`, `window.*` | ISO 8601 con zona horaria; se convierten a UTC | ventana inválida |
| `window.start < window.end` | estricto | ventana invertida o vacía |
| `scope.cidrs` / `scope.domains` | al menos uno no vacío | RoE sin alcance |
| CIDR | subred de `targets.lab_only_cidrs` de `profiles.yaml` y prefijo mínimo /24 (v4) o /64 (v6) | CIDR público, demasiado amplio o fuera del laboratorio |
| dominio | FQDN válido, igual o subdominio de `targets.lab_only_domains` | dominio fuera del laboratorio |
| `emergency_contacts` | al menos uno | falta contacto de emergencia |
| exclusiones | se restan del alcance; si dejan el alcance vacío, el RoE se rechaza | la exclusión anula todo el alcance |

La aprobación se representa con **aprobador + referencia + hash del contenido
canónico** (`approval_hash`). El hash incluye alcance, exclusiones, fases,
contactos, ventana y revocación; un cambio de cualquiera de esos datos cambia
el hash. Es trazabilidad, no una firma criptográfica: el diseño no pretende
reemplazar la firma legal del contrato.

## Emisión de tokens

`tokens.issue(roe, phase, *, audit, now=None, agent="scope-guard")`:

1. Rechaza si la fase no está en `authorized_phases`.
2. Rechaza si `now` está fuera de `window` o si el RoE está revocado.
3. Calcula `ttl` desde `policy.yaml` (`phases.<fase>.token_ttl_minutes`).
4. `window_start = now`, `window_end = min(now + ttl, roe.window.end)`.
5. Resta las exclusiones de CIDR con `address_exclude` y filtra los dominios
   excluidos (el dominio excluido cubre a sus subdominios); si las exclusiones
   combinadas dejan vacíos todos los CIDR y dominios, rechaza el RoE.
6. Construye el `ScopeToken` con el `engagement_id` del RoE y registra la
   emisión antes de devolverlo. `audit` es obligatorio; sin un sink no se emite
   ningún token.

El token **no se renueva solo**: su intervalo de vigencia es `[window_start,
window_end)`, por lo que en el instante exacto `window_end` ya venció;
`is_live()` da falso y el Guard bloquea. Emitir otro token exige una llamada
explícita al emisor, que vuelve a validar la ventana del RoE y deja un registro.

## Vinculación a engagement y fase

- `Guard` acepta un `engagement_id` opcional. Si está configurado, un token de
  otro engagement se rechaza aunque el alcance coincida (A6).
- La fase ya se comparaba en `is_allowed`; se mantiene y se prueba con un token
  de otra fase (A6).
- `ScopeToken` sigue siendo un `dataclass` público por compatibilidad, pero el
  test de trazabilidad verifica que **ningún módulo de `harness/` lo construya
  fuera de `tokens.py`**. La restricción es de código y se revisa en cada PR.

## Zonas horarias (A7)

Todas las fechas se parsean con `datetime.fromisoformat` y se convierten a
`time.time()` (UTC). Un `start` con `-03:00` y el mismo instante en `Z`
producen el mismo epoch; la comparación nunca usa la hora de pared local.

## Resolución DNS (A4)

`Guard` acepta un `resolver` inyectable (por defecto `None`, para no depender de
DNS en tests). Cuando está configurado, antes de permitir una acción sobre un
hostname resuelve todas sus direcciones y exige que **cada una** caiga dentro de
los CIDR del token. Si alguna queda fuera, bloquea. En producción se configura
con `socket.getaddrinfo`; en tests se inyecta un fake.

## Redirecciones HTTP (A5)

El adaptador HTTP futuro no sigue redirecciones a ciegas. `RedirectPolicy`
(valida esquema, credenciales embebidas y host) decide si una redirección es
seguible; una redirección a otro host fuera del token se rechaza antes de la
segunda petición. El adaptador concreto es parte del change 004; acá queda la
política compartida y su test.

## Parámetros de herramientas (A9)

`validate_parameters` rechaza claves que parezcan flags, saltos de línea,
metacaracteres de shell y valores con espacios o control. Se aplica antes de
construir argv; junto con `validate_target` y `reject_forbidden` cierra la
inyección por target o por parámetros.

## Preguntas abiertas del proposal

| Pregunta | Decisión |
|---|---|
| ¿Cómo se representa la aprobación? | `approver` + `approval_ref` + `approval_hash`; sin criptografía en este change. |
| ¿Qué pasa si el RoE se revoca? | `revoked_at` (opcional) hace que `issue` rechace y registre; los tokens ya emitidos vencen por TTL y el Guard los bloquea al vencer. |
| ¿Tokens de varias fases en paralelo? | Sí, uno por fase; cada uno con su TTL y su registro. Un token no habilita otra fase. |

## Fuera de alcance

- Firma digital real del RoE y gestión de claves.
- Revocación instantánea de tokens ya emitidos (solo TTL y ventana).
- Persistencia del RoE (la bitácora persistente es del change 002).
- Adaptador HTTP real (change 004).
