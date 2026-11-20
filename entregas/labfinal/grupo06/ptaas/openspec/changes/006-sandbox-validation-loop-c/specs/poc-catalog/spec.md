# Delta — poc-catalog (change 006)

Tests: `tests/test_sandbox_loop_c.py`

Decisiones de origen: `openspec/changes/006-sandbox-validation-loop-c/design.md`
(decisión 8). Los Requirements existentes de `openspec/specs/poc-catalog/spec.md`
se mantienen.

## Requirement: Ningún agente aprueba una entrada del catálogo

`approved_by` DEBE identificar a una persona. El catálogo NO DEBE aceptar una
entrada aprobada por un agente o subagente del proyecto.

### Scenario: entrada aprobada por un subagente

- GIVEN una entrada con `approved_by: security-reviewer`
- WHEN se carga el catálogo
- THEN se rechaza indicando que la aprobación debe ser humana

### Scenario: entrada aprobada por una persona

- GIVEN una entrada con `approved_by` igual al nombre de un integrante y `approved_at` válido
- WHEN se carga el catálogo
- THEN se acepta

## Requirement: El catálogo no cambia durante el loop C

El loop C DEBE cargar el catálogo una vez al iniciar y usar esa versión hasta
terminar. La bitácora DEBE registrar `catalog_version` y la versión de cada
entrada usada.

### Scenario: entrada agregada durante la ejecución

- GIVEN un loop C en curso y una entrada nueva agregada a `catalog.yaml` después de iniciarlo
- WHEN el agente propone esa entrada
- THEN se trata como fuera del catálogo y el hallazgo queda `not_validated`

### Scenario: versión registrada en la evidencia

- GIVEN una verificación ejecutada
- WHEN se lee la bitácora
- THEN contiene `catalog_version` y la versión de la entrada usada

## Requirement: Los parámetros no cambian el objetivo

Los parámetros DEBEN apuntar solo al activo aprobado. `path` DEBE ser una ruta
relativa que empiece con `/`, sin esquema ni host. `param_name` DEBE ser un
identificador simple.

### Scenario: path que cambia de host

- GIVEN una verificación con `path` = `//example.com/` o `http://example.com/`
- WHEN se ejecuta la verificación
- THEN se rechaza con `ParameterError` y el `Sender` no es invocado

### Scenario: path con secuencias de recorrido

- GIVEN una verificación con `path` = `/../../etc/passwd`
- WHEN se ejecuta la verificación
- THEN se rechaza con `ParameterError` y el `Sender` no es invocado

### Scenario: param_name con caracteres especiales

- GIVEN una verificación de reflexión con `param_name` = `q&admin=1`
- WHEN se ejecuta la verificación
- THEN se rechaza con `ParameterError` y el `Sender` no es invocado

### Scenario: parámetros válidos

- GIVEN una verificación con `path` = `/login.php` y `base_url` del laboratorio
- WHEN se ejecuta la verificación aprobada
- THEN el `Sender` recibe exactamente esos parámetros
