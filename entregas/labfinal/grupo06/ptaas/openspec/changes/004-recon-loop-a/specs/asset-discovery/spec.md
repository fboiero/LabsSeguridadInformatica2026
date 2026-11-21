# Delta propuesto — asset-discovery — P3 / 004

Tests: tests/test_recon_loop_a.py

## Requirement: Orden pasivo antes de activo
El loop DEBE completar la enumeración pasiva del lote antes del primer sondeo activo.

### Scenario: orden verificable
- GIVEN dos semillas autorizadas y resultados pasivos válidos
- WHEN se ejecuta una vuelta
- THEN ambas enumeraciones preceden a todos los sondeos activos

### Scenario: fase pasiva inválida
- GIVEN salida pasiva con schema inválido
- WHEN se evalúa iniciar sondeos
- THEN no se ejecuta la fase activa ni se declara grafo estabilizado

## Requirement: Alcance, autorización y bitácora
Toda acción DEBE pasar por Harness.invoke; un descubrimiento excluido DEBE registrarse sin sondeo ni resolución DNS externa.

### Scenario: descubrimiento excluido
- GIVEN un token restringido a DVWA y una referencia fuera de su alcance
- WHEN el loop procesa la referencia
- THEN la registra BLOCKED y ningún adaptador ni resolver recibe esa referencia

### Scenario: autorización revocada entre acciones
- GIVEN un token vencido o kill switch activado después de la enumeración
- WHEN comienza la acción siguiente
- THEN Harness bloquea o aborta, registra la decisión y no ejecuta la herramienta

### Scenario: gate activo sin aprobación
- GIVEN un target autorizado sin aprobación humana de acción activa
- WHEN el loop intenta sondearlo
- THEN devuelve PENDING_HITL sin aprobarse ni ejecutar el adaptador activo

## Requirement: Grafo persistido y validado
El grafo DEBE validar activos, normalizar identidad, fusionar tecnologías y preservar estado por engagement.

### Scenario: deduplicación y recarga
- GIVEN observaciones equivalentes con mayúsculas y punto final
- WHEN se incorporan, persisten y recargan
- THEN hay un activo con tecnologías fusionadas y el mismo estado de iteración

### Scenario: datos persistidos inválidos
- GIVEN falta source_tool, versión desconocida o engagement distinto
- WHEN se carga el grafo
- THEN se rechaza sin sobrescribir el último archivo válido

## Requirement: Parada acotada y reanudación
El loop DEBE usar decide_recon y el presupuesto acumulado configurado, sin contar activos excluidos como progreso.

### Scenario: punto fijo
- GIVEN una vuelta sin activos nuevos en alcance
- WHEN se evalúa continuar
- THEN termina con motivo grafo estabilizado

### Scenario: tope y reanudación
- GIVEN cinco vueltas acumuladas con activos nuevos y límite de cinco
- WHEN se intenta continuar, incluso tras recargar
- THEN no existe una sexta invocación de vuelta y el motivo es tope de iteraciones

### Scenario: errores no son progreso
- GIVEN dos respuestas consecutivas con schema inválido
- WHEN el loop procesa la segunda
- THEN escala a PENDING_HITL sin inventar activos ni declarar convergencia

## Requirement: Límite por target
Los adaptadores DEBEN aplicar el menor límite de perfil y policy compartiendo el presupuesto entre llamadas al mismo target.

### Scenario: ráfaga limitada
- GIVEN un límite de cinco solicitudes por segundo y reloj controlado
- WHEN varias invocaciones intentan emitir una ráfaga al mismo target
- THEN las emisiones respetan el intervalo y presupuesto, aunque cambie la instancia del adaptador

### Scenario: configuración inválida
- GIVEN tasa cero, negativa, no finita o timeout inválido
- WHEN se prepara una ejecución
- THEN se rechaza antes de emitir tráfico
