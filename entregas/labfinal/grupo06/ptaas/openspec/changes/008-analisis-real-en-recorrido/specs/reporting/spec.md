# Delta — reporting (change 008)

Tests: `tests/test_analisis_real.py`

## Requirement: Análisis real con gate humano propio

El recorrido DEBE ejecutar el análisis con el loop B de P4 (ZAP baseline) a través
de `Harness.invoke`, con token de fase `analyze`, solo sobre activos que el recon
relevó. NO DEBE ejecutar ZAP sin la aprobación registrada del gate
`active_analysis`.

### Scenario: sin aprobación del análisis activo

- GIVEN el gate `first_active_action` aprobado y el gate `active_analysis` sin aprobar
- WHEN se ejecuta el recorrido con análisis real y vence la espera
- THEN ZAP no se ejecuta, se registra `PENDING_HITL` y el recorrido termina con error

### Scenario: RoE sin la fase de análisis

- GIVEN un RoE cuyo `authorized_phases` no incluye `analyze`
- WHEN se ejecuta el recorrido con análisis real
- THEN no se emite token de análisis, ZAP no se ejecuta y el recorrido termina con error

### Scenario: análisis real aprobado

- GIVEN todos los gates aprobados
- WHEN se ejecuta el recorrido con análisis real
- THEN ZAP se ejecuta una vez por activo relevado y la etapa de análisis figura `real` en el informe

## Requirement: Tabla de mapeo de alertas aprobada por una persona

Cada alerta de ZAP con riesgo ≥ 1 DEBE convertirse en hallazgo solo si su plugin
figura en `harness/zap_mapping.yaml`, que DEBE tener `approved_by` (una persona,
no un agente) y `approved_at`, y vectores CVSS v4.0 válidos.

### Scenario: tabla sin aprobación

- GIVEN una tabla de mapeo sin `approved_by`
- WHEN se carga
- THEN se rechaza y el recorrido no genera hallazgos

### Scenario: tabla aprobada por un agente

- GIVEN una tabla con `approved_by: security-reviewer`
- WHEN se carga
- THEN se rechaza indicando que la aprobación debe ser humana

### Scenario: vector inválido en la tabla

- GIVEN una entrada con un vector CVSS v4.0 inválido
- WHEN se carga la tabla
- THEN se rechaza indicando el plugin

### Scenario: alerta sin mapeo aprobado

- GIVEN una alerta de riesgo bajo cuyo plugin no figura en la tabla
- WHEN se generan los hallazgos
- THEN la alerta no entra al informe y su descarte queda en la bitácora con el plugin

### Scenario: alerta informativa

- GIVEN una alerta de riesgo 0
- WHEN se generan los hallazgos
- THEN no se genera hallazgo

### Scenario: alerta mapeada

- GIVEN una alerta "Missing Anti-clickjacking Header" (CWE-1021) mapeada a `POC-HDR-001`
- WHEN se generan los hallazgos
- THEN el hallazgo tiene CWE-1021, la remediación de ZAP sin HTML, el vector de la tabla y la verificación `POC-HDR-001`

## Requirement: Reporte de ZAP acotado al objetivo

El recorrido NO DEBE aceptar un reporte de ZAP con instancias sobre un host
distinto del objetivo analizado.

### Scenario: instancia fuera del objetivo

- GIVEN un reporte de ZAP para `dvwa.lab.test` con una instancia en `http://example.com/`
- WHEN se procesa
- THEN se rechaza, no se generan hallazgos y el recorrido termina con error

## Requirement: Informe entregable con análisis real

Con todas las etapas reales y las aprobaciones registradas, el informe NO DEBE
marcarse DEMO, DEBE poder entregarse y exportarse, y DEBE indicar que los vectores
CVSS fueron asignados por el analista.

### Scenario: recorrido completo con análisis real

- GIVEN recon, análisis y validación reales y todos los gates aprobados, incluida la entrega
- WHEN se ejecuta el recorrido
- THEN el informe no es DEMO, se entrega, se escribe la exportación a DefectDojo y el informe indica el origen de los vectores CVSS
