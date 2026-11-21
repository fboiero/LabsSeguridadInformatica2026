# Delta — vuln-analysis (Change 005, propuesta P4)

Tests: tests/test_schemas.py, tests/test_engagement_and_loops.py, tests/test_authorization.py, tests/test_correlation_loop_b.py

## ADDED Requirements

### Requirement: Adaptadores de análisis seguros y auditados
Las capacidades `zap.baseline_scan` y `nuclei.safe_templates` DEBEN ejecutarse exclusivamente mediante `Harness.invoke`, con token válido de fase `ANALYZE`, alcance permitido, argumentos fijos y sin shell. El análisis NO DEBE iniciar PoCs, fuzzing, pruebas destructivas ni tráfico a terceros.

#### Scenario: ZAP baseline permitido en laboratorio
- GIVEN un objetivo DVWA o Juice Shop dentro del alcance y un token `ANALYZE` válido
- WHEN se invoca `zap.baseline_scan`
- THEN el adaptador usa únicamente el perfil baseline no destructivo y el harness registra la acción

#### Scenario: objetivo fuera del laboratorio
- GIVEN un objetivo fuera del alcance autorizado
- WHEN se intenta ejecutar ZAP o Nuclei
- THEN el harness bloquea y audita el intento sin llamar al runner

#### Scenario: intento de PoC en fase de análisis
- GIVEN un token para `ANALYZE`
- WHEN se solicita `poc_catalog.run_parametrized`
- THEN el harness rechaza y audita la acción sin ejecutar validaciones

### Requirement: Allow-list verificable de templates Nuclei
El sistema DEBE permitir únicamente templates revisados y aprobados por P4 y otra persona, con ruta y hash íntegros y entrada aprobada en un manifiesto verificable. La coincidencia de tags permitidos NO ES suficiente para autorizar un template.

#### Scenario: template aprobado e íntegro
- GIVEN un template local registrado con hash coincidente y aprobaciones humanas comprobables
- WHEN se solicita análisis Nuclei dentro del laboratorio
- THEN solo ese template puede formar parte del conjunto ejecutable

#### Scenario: template sin autorización
- GIVEN un template presente en el directorio pero ausente del manifiesto aprobado
- WHEN se solicita ejecutar Nuclei
- THEN el adaptador no invoca el runner y el rechazo se registra

#### Scenario: template modificado tras la aprobación
- GIVEN un template registrado cuyo hash ya no coincide
- WHEN se prepara la ejecución
- THEN se bloquea antes de ejecutar la herramienta y se requiere nueva revisión humana

### Requirement: Contradicciones y falsos positivos con evidencia
Los resultados de ZAP y Nuclei DEBEN conservarse individualmente. Un desacuerdo NO DEBE resolverse automáticamente como `confirmed` o `discarded`; cada resultado final DEBE tener justificación y referencias verificables.

#### Scenario: resultados contradictorios
- GIVEN un reporte positivo de un analizador y uno negativo de otro sobre el mismo candidato
- WHEN se consolida el análisis sin evidencia suficiente para resolver el conflicto
- THEN el estado es `inconclusive`, con ambas fuentes y la contradicción documentadas

#### Scenario: falso positivo conocido del laboratorio
- GIVEN una coincidencia considerada falso positivo con evidencia documentada y verificable
- WHEN se descarta el candidato
- THEN el estado es `discarded` con justificación y evidencia específica; no se aplica una excepción global silenciosa

#### Scenario: resultado sin justificación
- GIVEN un resultado que carece de `rationale`
- WHEN se construye `PrioritizedVuln`
- THEN se rechaza por schema inválido

### Requirement: Priorización reproducible y datos faltantes explícitos
La priorización DEBE usar las reglas deterministas vigentes de CVSS v4.0, EPSS y criticidad del activo cuando existan insumos válidos. La ausencia de EPSS DEBE mantenerse como `None` en el dato original. Sin CVSS v4.0 verificable NO DEBE inventarse un puntaje numérico.

#### Scenario: mismos insumos
- GIVEN dos análisis con idéntico CVSS v4.0, EPSS y criticidad
- WHEN se calcula la prioridad
- THEN se obtiene el mismo puntaje

#### Scenario: EPSS faltante
- GIVEN un hallazgo con CVSS v4.0 verificable pero sin EPSS
- WHEN se calcula la prioridad con la función existente
- THEN el dato EPSS continúa siendo `None` y se identifica la limitación de la puntuación

#### Scenario: CVSS v4.0 inexistente
- GIVEN un candidato sin puntaje CVSS v4.0 respaldado por la fuente
- WHEN se intenta priorizar
- THEN no se asigna un CVSS v4.0 inventado ni se presenta una puntuación como si fuera completa

### Requirement: Loop B acotado y escalado humano
La ejecución del Loop B DEBE utilizar `decide_detection`, detenerse cuando el hallazgo queda resuelto, tras dos iteraciones consecutivas sin evidencia nueva o por tope. En los casos no resueltos DEBE producir `inconclusive`. Dos salidas de schema inválido consecutivas DEBEN escalar a `PENDING_HITL` sin aprobación automática.

#### Scenario: hallazgo resuelto
- GIVEN un candidato con evidencia suficiente y resolución justificada
- WHEN el Loop B evalúa continuar
- THEN se detiene con el estado resuelto y referencias de evidencia

#### Scenario: dos iteraciones sin novedades
- GIVEN dos iteraciones consecutivas que agregan cero referencias de evidencia nuevas
- WHEN el Loop B evalúa continuar sin haber resuelto el candidato
- THEN se detiene y entrega `inconclusive` con la razón de parada

#### Scenario: tope de iteraciones
- GIVEN un candidato todavía no resuelto que alcanzó el límite configurado
- WHEN el Loop B evalúa continuar
- THEN se detiene con `inconclusive` sin invocar otra herramienta

#### Scenario: dos schemas inválidos consecutivos
- GIVEN dos respuestas consecutivas que no validan el schema
- WHEN el orquestador decide el próximo paso
- THEN entra en `PENDING_HITL` y no reintenta ni emite una aprobación automática

> Nota para revisión con P3: definir la precedencia entre el tope y las dos iteraciones sin novedades cuando ambas condiciones ocurren en la misma vuelta. No alterar `harness/loops.py` sin revisión del dueño.
