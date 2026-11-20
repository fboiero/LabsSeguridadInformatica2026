# Tasks — Change 003

## Spec y diseño
- [x] 1.1 `design.md`: formato del RoE, validaciones, representación de aprobación
- [x] 1.2 Delta de `authorization` con ≥ 5 Requirements nuevos (≥ 3 negativos)
- [ ] 1.3 Revisión cruzada del delta  <!-- pendiente: la hace otro integrante del grupo -->

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
