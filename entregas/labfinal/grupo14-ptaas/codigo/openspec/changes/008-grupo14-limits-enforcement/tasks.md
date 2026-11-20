# Tasks — Change 008 (grupo 14)

## Hallazgo y spec
- [x] 1.1 Documentar el hallazgo (spec exige tope; harness MVP no lo aplica)
- [x] 1.2 Confirmar el requisito en el delta `asset-discovery` ("tope alcanzado")

## Implementación
- [x] 2.1 Test que documenta el hallazgo (50 invocaciones sin tope en el MVP)
- [x] 2.2 `harness/limits.py`: `GuardedHarness` con tope por `(acción, objetivo)`
- [x] 2.3 Registrar el bloqueo por tope en la bitácora (`Result.BLOCKED`)
- [x] 2.4 Mantener el contrato público de `Harness` (composición, no herencia)

## Verificación
- [x] 3.1 Test de corrección: la invocación k+1 se bloquea con `LimitExceeded`
- [x] 3.2 Test de aislamiento: el contador es por objetivo
- [x] 3.3 Suite completa en verde (`python -m pytest -q`)

## Pendiente (change futuro)
- [ ] 4.1 Rate limit por segundo (`rps_per_target`) con ventana temporal
- [ ] 4.2 Integrar el tope en los loops A/B/C vía `LoopDecision`
