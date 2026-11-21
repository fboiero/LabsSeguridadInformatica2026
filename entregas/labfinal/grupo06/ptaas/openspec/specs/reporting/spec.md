# Delta — reporting

Tests: tests/test_reporting.py, tests/test_reporting_gates.py, tests/test_reporting_p3.py, tests/test_reporting_e2e.py, tests/test_analisis_real.py

## Requirement: Hallazgo completo
Cada hallazgo del informe DEBE incluir CWE, CVSS v4.0 y recomendación de remediación.

### Scenario: hallazgo sin CWE
- GIVEN un hallazgo sin CWE asignado
- WHEN se genera el informe
- THEN la generación falla con error indicando el campo faltante

## Requirement: Entrega con aprobación
El informe NO DEBE entregarse sin aprobación del Reviewer.

### Scenario: entrega sin aprobación
- GIVEN un informe generado y sin aprobación
- WHEN se intenta entregar
- THEN el estado permanece en REPORT y se registra PENDING_HITL

<!-- Archivado desde change 007, propuesta de P3 (tasks 2.3 y 2.4) -->

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

<!-- Archivado desde change 007, delta de P5 (2026-11-18) -->

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

<!-- Archivado desde change 008 (P5, 2026-11-19) -->

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
