## Requirements

Las lecturas de la respuesta normal en la raíz del laboratorio se ofrecen de a
una. Cada decisión consume solo su propuesta. Finalizar conserva los resultados
anteriores y deriva el acumulado a Correlación y Redacción.

### Scenario: Cobertura documental después de la decisión
- GIVEN una consulta aprobada o rechazada y el catálogo del laboratorio
- WHEN termina la decisión
- THEN Correlación y Redacción reciben la cobertura de esa sesión sin repetir consultas y su resumen persiste

### Scenario: Inicio limpio y aprobación de una sola consulta
- GIVEN una sesión nueva sin recibos ni observaciones
- WHEN Validación propone una lectura de cabeceras para la raíz del laboratorio
- THEN solo la aprobación explícita de esa sesión permite un intento; el rechazo no ejecuta nada

Tests: `tests/test_relevo.py`.

### Scenario: Revisión pendiente sobrevive al reinicio
- GIVEN un caso iniciado sin respuesta
- WHEN se abre nuevamente la aplicación
- THEN se conserva pendiente hasta una decisión explícita

### Scenario: Evidencia modificada
- GIVEN un caso pendiente vinculado a un hash
- WHEN cambian los bytes de la evidencia
- THEN no se registra la decisión y se requiere otra revisión

### Scenario: Caso desconocido
- GIVEN un identificador no incluido en el selector
- WHEN se intenta iniciar una revisión
- THEN se rechaza sin crear una sesión
