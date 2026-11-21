# Propuesta P3 — Change 007, tareas 2.3 y 2.4

Tests: tests/test_reporting_p3.py. Documento separado de los deltas de P1. No modifica `harness/reporting.py`, propiedad de P5.

## Diseño

Se propone un módulo propio `harness/reporting_p3.py` con validación estricta de vector CVSS v4.0 y generación de secciones PTES a partir de datos suministrados. Consume Finding sin cambiar su contrato. El módulo conserva el contrato del renderizador existente sin modificar `harness/reporting.py`.

El vector se parsea por métricas: versión exacta, métricas base obligatorias, nombres y valores válidos, ausencia de duplicados y segmentos vacíos. Las métricas opcionales se validan mediante tabla de la especificación oficial, a comprobar antes de implementar. No se acepta el sufijo libre que actualmente permite la expresión regular. No se calcula ni inventa puntaje CVSS. EPSS es null o número finito entre cero y uno; se muestra junto al vector con su procedencia si fue aportada. Cero no se representa como dato ausente.

El resumen se deriva de hallazgos y estados suministrados, sin afirmar compromiso, validación humana o cobertura no demostrada. La estructura incluye resumen ejecutivo, alcance y RoE, metodología, hallazgos priorizados y anexos con referencias a bitácora e inventario. Los datos ausentes se muestran como unknown; no se infieren ventana, exclusiones ni evidencia. El gate de entrega permanece en el componente existente.

Tests previstos en archivo propio `tests/test_reporting_p3.py`, con secuencia delta revisado → test fallido → código y mutaciones sobre validación de vector y EPSS.

## Requirement: CVSS v4.0 estricto junto a EPSS
El componente DEBE validar todas las métricas del vector y presentar EPSS sin inventar datos.

### Scenario: vector válido y EPSS conocido
- GIVEN vector válido y probabilidad 0 o 0.25
- WHEN se construye la sección de hallazgo
- THEN muestra ambos valores distinguiendo probabilidad de severidad

### Scenario: vector o EPSS inválidos
- GIVEN métrica repetida, desconocida, base ausente, valor ilegal, otra versión, EPSS NaN o fuera de rango
- WHEN se valida el hallazgo
- THEN se rechaza indicando el campo y no se genera una presentación válida

### Scenario: probabilidad ausente
- GIVEN EPSS null
- WHEN se presenta el hallazgo
- THEN indica unknown y no lo sustituye por cero

## Requirement: Resumen y estructura PTES
El componente DEBE producir las cinco secciones previstas, con afirmaciones derivadas de los datos de entrada.

### Scenario: reporte con evidencia
- GIVEN hallazgos, alcance y referencias explícitos
- WHEN se arma el documento
- THEN incluye resumen ejecutivo, alcance y RoE, metodología, hallazgos y anexos preservando referencias y estado de validación

### Scenario: información ausente
- GIVEN cero hallazgos o metadatos de alcance ausentes
- WHEN se genera el resumen
- THEN no declara que el sistema sea seguro, no inventa pruebas y señala datos ausentes como unknown

### Scenario: sin aprobación de entrega
- GIVEN un documento generado sin aprobación del Reviewer
- WHEN se solicita entregar mediante el mecanismo existente
- THEN se conserva el rechazo del gate sin introducir aprobación automática

Implementación verificada: `harness/reporting_p3.py`. Su `render_report` conserva el contenedor del renderizador existente y usa el mismo `deliver`; no modifica `harness/reporting.py`.
