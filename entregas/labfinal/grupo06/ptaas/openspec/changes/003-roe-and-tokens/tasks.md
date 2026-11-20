# Tasks — Change 003

## Spec y diseño
- [x] 1.1 `design.md`: formato del RoE, validaciones, representación de aprobación
- [x] 1.2 Delta de `authorization` con ≥ 5 Requirements nuevos (≥ 3 negativos)
- [x] 1.3 Revisión cruzada del delta — Martin Beccereca (P5), 2026-11-19: aprobado con observaciones (ver abajo)

## Implementación
- [x] 2.1 Tests que fallan para RoE inválidos (sin alcance, ventana invertida, CIDR amplio, exclusión que anula todo)
- [x] 2.2 `harness/roe.py`: modelo y parser (YAML) con errores explicativos
- [x] 2.3 `harness/tokens.py`: emisor por fase con TTL de `policy.yaml`
- [x] 2.4 Restringir la creación de `ScopeToken` al emisor y probarlo
- [x] 2.5 Registrar emisiones y rechazos en la bitácora

## Verificación
- [x] 3.1 Test: RoE válido → token solo de la fase pedida
- [x] 3.2 Test: pedir una fase no autorizada → rechazo registrado
- [x] 3.3 Test: exclusiones del RoE prevalecen sobre el alcance
- [x] 3.4 Test: token vencido no se renueva solo
- [x] 3.5 Tests adversariales A6, A7 y A8 de `docs/desafios-extension.md`
- [x] 3.6 Archivar el delta en `openspec/specs/authorization/spec.md`

**Evidencia:** `tests/test_roe_tokens.py` (31 tests), `tests/test_redteam_guard.py`
(A1–A10), `entrega/red-team.md`, `entrega/mutaciones.md`, salidas en
`entrega/evidencia/salidas/`. `1.3` sigue pendiente de revisión cruzada por otra
persona integrante del grupo.

**Revisión cruzada (1.3) — Martin Beccereca (P5), 2026-11-19: APROBADO CON OBSERVACIONES.**
Delta (8 Requirements, 19 Scenarios con negativos), 84 tests de RoE/tokens/red team/autorización
en verde, red team A1–A10 con historia de commits y mutaciones M1–M9: aprobados.
- Los pendientes A4 (resolver DNS en runtime) y A5 (redirecciones en el adaptador HTTP) quedaron
  resueltos después: el recorrido configura `Guard(resolver=...)` en recon, análisis y sandbox, y el
  adaptador httpx usa `RedirectPolicy`.
- Observación: la task 2.4 figura hecha, pero `ScopeToken` sigue siendo una clase pública que
  cualquier código puede construir sin pasar por el emisor; la prueba es estática. No es un bypass
  para los agentes (no escriben código del harness), pero el informe no debe presentarlo como un
  control de runtime.
