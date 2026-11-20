
## Verificación real P3 — ejecución aislada

Se conserva el alcance DVWA/Juice Shop y no se habilitan proveedores públicos de enumeración.

### Scenario: enumeración nativa sin proveedores externos
- GIVEN subfinder instalado en runner aislado y todos sus proveedores excluidos explícitamente
- WHEN Harness invoca subfinder.enum
- THEN se captura su salida real (que puede ser vacía), sin fabricar subdominios; las semillas autorizadas continúan al sondeo HTTP

### Scenario: catálogo de proveedores no interpretable
- GIVEN una salida de catálogo desconocida o vacía
- WHEN se prepara el runner nativo
- THEN falla cerrado antes de enumerar

### Scenario: evidencia verificable de corrida
- GIVEN acciones reales registradas por AuditLog
- WHEN se exporta la evidencia y se ejecuta el verificador de P3 que delega en verificar_cadena de P1
- THEN se valida el hash encadenado; alterar una fila o borrar una intermedia produce fallo

### Scenario: acción real sin autorización registrada
- GIVEN ausencia de una referencia de autorización humana o ventana vencida
- WHEN se solicita la corrida real
- THEN no se inicia reconocimiento

### Scenario: captura HTTP no altera la autorización
- GIVEN un observador de salida cruda configurado
- WHEN se ejecuta httpx
- THEN conserva la resolución a IP autorizada y argv acotado; el observador recibe la salida después de ejecutar, sin sustituir el runner

La versión instalada devuelve 'No sources selected for this search' con código 1 al excluir todas las fuentes. Solo ese resultado exacto se clasifica UNAVAILABLE y queda registrado; se sondean las semillas autorizadas sin afirmar descubrimiento pasivo. Otros errores abortan. Los puertos fijos son DVWA:80 y JuiceShop:3000, también al resolver Location relativa.
