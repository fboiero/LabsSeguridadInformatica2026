# Spec — poc-catalog

Tests: `tests/test_poc_catalog.py`, `tests/test_sandbox_loop_c.py`
Datos: `harness/poc/catalog.yaml` · Código: `harness/poc/catalog.py`

## Requirement: Verificaciones inertes
Toda entrada del catálogo DEBE ser de tipo `inert_check`: confirma una debilidad observando la respuesta, sin ejecutar código en el objetivo ni extraer datos.

### Scenario: entrada de otro tipo
- GIVEN una entrada con `kind` distinto de `inert_check`
- WHEN se carga el catálogo
- THEN se rechaza

## Requirement: Solo laboratorio
Toda entrada DEBE ser `lab_only`.

### Scenario: entrada no marcada como laboratorio
- GIVEN una entrada con `lab_only: false`
- WHEN se carga el catálogo
- THEN se rechaza

## Requirement: Aprobación registrada
Toda entrada DEBE tener `approved_by` y `approved_at`.

### Scenario: entrada sin aprobación
- GIVEN una entrada sin `approved_at`
- WHEN se carga el catálogo
- THEN se rechaza

## Requirement: Parámetros declarados
La ejecución DEBE aceptar exactamente los parámetros declarados por la entrada, con valores de texto acotados y sin saltos de línea.

### Scenario: parámetro extra
- GIVEN un parámetro no declarado (por ejemplo `payload`)
- WHEN se ejecuta la verificación
- THEN se rechaza y no se envía nada

## Requirement: Aprobación humana previa
La ejecución NO DEBE enviar tráfico sin la aprobación del Reviewer para ese hallazgo.

### Scenario: sin aprobación
- GIVEN una verificación sin aprobación
- WHEN se intenta ejecutar
- THEN se rechaza y el sender no es invocado

## Requirement: Canario inerte
La verificación de reflexión DEBE usar un canario único sin marcado ejecutable y concluir solo observando la respuesta.

### Scenario: canario reflejado sin codificar
- GIVEN una respuesta que refleja el canario sin codificar
- WHEN se evalúa
- THEN el resultado es `validated`

### Scenario: canario codificado
- GIVEN una respuesta que codifica el canario
- WHEN se evalúa
- THEN el resultado es `not_validated`

<!-- Archivado desde change 006 (2026-11-18) -->

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
