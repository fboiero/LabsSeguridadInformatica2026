# Delta — reporting (change 007)

Tests: `tests/test_reporting_e2e.py`

Decisiones de origen: `openspec/changes/007-reporting-defectdojo/design.md`.
Los Requirements vigentes de `openspec/specs/reporting/spec.md` (hallazgo
completo, entrega con aprobación) y los de `p3/proposal.md` (CVSS v4.0 estricto
junto a EPSS, estructura PTES) se mantienen.

## Requirement: Estado de validación respaldado por la bitácora

El estado de cada hallazgo en el informe DEBE derivarse del registro
`validation.result` del loop C en la bitácora. El informe NO DEBE mostrar como
validado un hallazgo que la bitácora no respalda.

### Scenario: hallazgo validado en la bitácora

- GIVEN un hallazgo con un registro `validation.result` con estado `validated`
- WHEN se genera el informe
- THEN el hallazgo figura como "validado en sandbox" con la verificación, su versión y sus referencias

### Scenario: validado declarado sin respaldo

- GIVEN un `Finding` con `validation_status="validated"` y ningún registro `validation.result` para ese hallazgo
- WHEN se genera el informe
- THEN la generación falla indicando el hallazgo y no se produce informe parcial

### Scenario: hallazgo pendiente de aprobación

- GIVEN un hallazgo cuyo último registro es `PENDING_HITL`
- WHEN se genera el informe
- THEN el hallazgo figura como "no validado (sin aprobación)"

### Scenario: hallazgo no validado de severidad alta

- GIVEN un hallazgo no validado con vector CVSS de impacto alto
- WHEN se genera el informe
- THEN el hallazgo se lista igual y el resumen ejecutivo lo menciona como "requiere validación"

## Requirement: Referencias a la evidencia verificables

Cada referencia de evidencia DEBE ser el hash de una entrada existente de la
bitácora. El informe DEBE incluir el hash de la cabeza de la bitácora usada. El
sistema NO DEBE generar un informe sobre una bitácora alterada.

### Scenario: referencia inexistente

- GIVEN un hallazgo con una referencia que no corresponde a ninguna entrada de la bitácora
- WHEN se genera el informe
- THEN la generación falla indicando la referencia

### Scenario: bitácora alterada

- GIVEN una bitácora en la que se modificó una entrada después de escrita
- WHEN se genera el informe
- THEN la generación falla porque la verificación de la cadena no pasa

### Scenario: referencias válidas

- GIVEN hallazgos cuyas referencias existen en una bitácora íntegra
- WHEN se genera el informe
- THEN cada hallazgo lista sus referencias y el informe incluye el hash de la cabeza de la bitácora

## Requirement: Informe versionado e identificado por su hash

El informe DEBE tener número de versión y un `report_hash` calculado sobre su
contenido canónico. Un cambio en un hallazgo DEBE producir una versión nueva
con otro hash.

### Scenario: mismas entradas

- GIVEN los mismos hallazgos y la misma bitácora
- WHEN se genera el informe dos veces
- THEN ambos tienen el mismo `report_hash`

### Scenario: hallazgo modificado

- GIVEN un informe generado en la versión 1
- WHEN cambia la remediación de un hallazgo y se vuelve a generar
- THEN el informe nuevo es versión 2 con otro `report_hash`

## Requirement: Entrega con aprobación registrada y ligada al hash

La entrega DEBE requerir una aprobación registrada por una persona en la CLI,
con Reviewer y motivo, para ese `report_hash`. El sistema NO DEBE entregar un
informe sin esa aprobación ni con la aprobación de otra versión.

### Scenario: entrega sin aprobación registrada

- GIVEN un informe generado y sin aprobación registrada
- WHEN se intenta entregar
- THEN el informe queda en `REPORT`, no se marca entregado y se registra `PENDING_HITL`

### Scenario: aprobación de otra versión

- GIVEN una aprobación registrada para el `report_hash` de la versión 1
- WHEN se intenta entregar la versión 2
- THEN la entrega se rechaza

### Scenario: aprobación sin motivo

- GIVEN un informe generado
- WHEN se ejecuta `approve-delivery` sin `--reason`
- THEN la CLI falla y no se registra ninguna aprobación

### Scenario: entrega aprobada

- GIVEN una aprobación registrada para el `report_hash` del informe
- WHEN se entrega
- THEN el informe se marca entregado y la entrega queda en la bitácora con Reviewer, motivo y hash

## Requirement: Sin datos sensibles en el informe

El informe NO DEBE contener datos sensibles. Si el contenido coincide con algún
patrón de la lista (cookies de sesión, `Authorization`, tokens JWT, contraseñas,
claves privadas, canario de reflexión), la generación DEBE fallar indicando el
patrón y el hallazgo.

### Scenario: cookie de sesión en la evidencia

- GIVEN un hallazgo cuyo detalle contiene `PHPSESSID=abc123`
- WHEN se genera el informe
- THEN la generación falla indicando el patrón "cookie de sesión" y el hallazgo

### Scenario: token JWT en la remediación

- GIVEN un hallazgo cuya remediación contiene un token `eyJ…`
- WHEN se genera el informe
- THEN la generación falla indicando el patrón "token JWT"

### Scenario: informe sin datos sensibles

- GIVEN hallazgos sin coincidencias con la lista de patrones
- WHEN se genera el informe
- THEN el informe se genera

## Requirement: Exportación al formato de importación de DefectDojo

El sistema DEBE exportar solo informes entregados, en el formato de importación
genérico de DefectDojo, sin cuerpos de respuesta, encabezados, cookies, canario
ni nombres de personas. NO DEBE inventar una severidad.

### Scenario: exportar un informe no entregado

- GIVEN un informe generado y no entregado
- WHEN se intenta exportar
- THEN la exportación se rechaza y no se escribe ningún archivo

### Scenario: contenido exportado

- GIVEN un informe entregado con un hallazgo validado
- WHEN se exporta
- THEN el JSON contiene título, activo, CWE, vector CVSS, EPSS, estado, remediación, referencias e identificador estable, y no contiene cuerpo, cookies, canario ni el nombre del Reviewer

### Scenario: severidad desconocida

- GIVEN un hallazgo sin severidad con fuente
- WHEN se exporta
- THEN el hallazgo lleva la etiqueta `severity-unknown` y la descripción indica que la severidad no fue calculada

### Scenario: hallazgo duplicado

- GIVEN dos hallazgos con el mismo activo, CWE y verificación
- WHEN se genera el informe y se exporta
- THEN aparece un solo hallazgo con las referencias de ambos y un único identificador estable

## Requirement: Procedencia declarada de cada etapa

El informe DEBE declarar si cada etapa del recorrido es `real` o `fixture`. Un
informe con alguna etapa `fixture` DEBE marcarse DEMO y NO DEBE poder
entregarse ni exportarse.

### Scenario: etapa simulada

- GIVEN un recorrido con la etapa de análisis en `fixture`
- WHEN se genera el informe
- THEN el informe se marca DEMO y su encabezado lista la etapa simulada

### Scenario: entregar un informe DEMO

- GIVEN un informe DEMO con una aprobación registrada para su hash
- WHEN se intenta entregar o exportar
- THEN se rechaza indicando que contiene etapas simuladas

## Requirement: Sección de divulgación

El informe DEBE incluir una sección de divulgación (ISO/IEC 29147) con receptor,
canal, fecha de entrega y plazo de remediación. Lo que no esté en el RoE DEBE
figurar como `unknown`.

### Scenario: datos de divulgación ausentes

- GIVEN un RoE sin plazo de remediación
- WHEN se genera el informe
- THEN la sección de divulgación muestra el plazo como `unknown` y no inventa una fecha

## Requirement: Recorrido de un comando con gates humanos

Un solo comando DEBE recorrer RoE → recon → análisis → validación → informe →
entrega contra el laboratorio. En cada gate humano (primera acción activa,
validación por hallazgo, entrega) el comando DEBE esperar una decisión
registrada por una persona en la CLI y NO DEBE aprobar nada por su cuenta. Las
bitácoras exportadas DEBEN pasar la verificación.

### Scenario: RoE inválido

- GIVEN un RoE sin aprobador
- WHEN se ejecuta el comando
- THEN termina con error, no se emite ningún token y no se ejecuta ninguna herramienta

### Scenario: sin aprobación de la primera acción activa

- GIVEN un RoE válido y ninguna aprobación del gate `first_active_action`
- WHEN se ejecuta el comando y vence la espera
- THEN ninguna herramienta se ejecuta, se registra `PENDING_HITL` y el comando termina con error

### Scenario: directorio de salida existente

- GIVEN un directorio de salida que ya existe
- WHEN se ejecuta el comando
- THEN termina con error sin sobrescribir nada

### Scenario: candidato fuera de lo relevado

- GIVEN un candidato del análisis sobre un activo que el recon no relevó
- WHEN se ejecuta la validación
- THEN el candidato se descarta, no llega al sandbox y el descarte queda en la bitácora

### Scenario: hallazgo sin decisión al vencer la espera

- GIVEN un hallazgo propuesto que ninguna persona aprobó ni rechazó
- WHEN vence la espera de la validación
- THEN el sandbox no se invoca para ese hallazgo y el informe lo muestra "no validado (sin aprobación)"

### Scenario: análisis simulado

- GIVEN el análisis en modo `fixture` y las aprobaciones de validación registradas
- WHEN se ejecuta el comando
- THEN la validación corre en el sandbox, el informe sale DEMO, no se entrega ni se exporta, y las dos bitácoras exportadas pasan la verificación

### Scenario: recorrido completo con etapas reales

- GIVEN todas las etapas reales y todas las aprobaciones registradas, incluida la de entrega para el hash del informe
- WHEN se ejecuta el comando
- THEN el informe se entrega, se escribe la exportación a DefectDojo y las bitácoras exportadas pasan la verificación
