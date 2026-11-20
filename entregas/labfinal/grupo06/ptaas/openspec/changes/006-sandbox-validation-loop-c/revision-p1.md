# Revisión cruzada del change 006 — P1

**Revisor:** P1 (no es autor del sandbox ni del loop C).
**Fecha:** 2026-11-20.
**Veredicto:** aprobado con observaciones.

## Qué comprobé

- `pytest -q tests/test_sandbox_loop_c.py` → 62 passed, 1 skipped (el omitido es
  `test_real_sandbox_no_alcanza_internet`, que exige `PTAAS_SANDBOX_DOCKER=1`).
- `pytest -q` (suite completa) → 477 passed, 1 skipped.
- `mypy --strict harness/sandbox.py` → sin errores en ese módulo.
- `ruff check harness/sandbox.py` → limpio.
- `docker_argv` (harness/sandbox.py): argv fijo, `--rm`, `--read-only`,
  `--tmpfs /tmp`, `--cap-drop ALL`, `--security-opt no-new-privileges`,
  `--memory`, `--cpus`, `--pids-limit`, un contenedor por verificación con nombre
  único y etiqueta de engagement. Sin volúmenes ni variables del host.
- Destrucción: `SandboxAdapter.run` llama a `_destroy` en `finally`; si el borrado
  falla, registra `ABORTED` en la bitácora y lanza `SandboxAborted`.
- Tareas 3.1 a 3.4 y sus tests: 3.1 aprobación (`test_sin_aprobacion_queda_pendiente_y_no_envia`),
  3.2 verificación fuera del catálogo (`test_verificacion_fuera_del_catalogo`),
  3.3 red (ver observación 1), 3.4 destrucción (ver observación 2).

## Observaciones

1. **Aislamiento de red (3.3) solo con Docker.** La prueba automática está omitida
   por defecto. La evidencia de la corrida real existe en
   `entrega/evidencia/salidas/P5-006-sandbox-sin-salida.txt` (2026-11-18), con
   control positivo: `dvwa.lab.test` conecta (True) y `1.1.1.1` no (False). No la
   pude repetir hoy porque Docker Desktop no arrancaba en esta máquina.
2. **Destrucción tras un fallo (3.4) probada con un runtime falso.**
   `test_fallo_del_runtime_destruye_igual_y_no_valida` comprueba que `remove` se
   llama para cada contenedor creado, pero con `FakeRuntime`. El camino real
   (`docker run --rm` y `docker rm -f` en el `finally`) no tiene prueba automática;
   solo se apoya en el diseño y en la corrida manual de P5.

## Lo que no revisé

- No ejecuté el sandbox contra el lab: Docker no estaba disponible.
- No revisé las evals de validación ni el catálogo; no son parte de 006 · 1.3.

## Respuesta de P5 (2026-11-20)

- **Observación 2 (destrucción tras un fallo real):** se agregó
  `test_real_sandbox_se_destruye_aunque_docker_falle`, que hace fallar un `docker run`
  real (imagen inexistente con `--pull never`) y comprueba con Docker que no queda
  ningún contenedor del engagement (commit `f04a386`). Como el de aislamiento, corre con
  `PTAAS_SANDBOX_DOCKER=1`.
- **Observación 1 (aislamiento solo con Docker):** se mantiene la evidencia manual con
  control positivo; los dos tests con Docker real se corren con la variable de arriba.

