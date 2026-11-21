## ADDED Requirements

### Comprobaciones activas autorizadas por sesión

El sistema PUEDE ejecutar comprobaciones activas definidas en un catálogo
versionado con carga fija, únicamente contra el laboratorio efímero y solo si la
persona que opera habilita el modo activo en esa sesión. La autorización de
operador NO equivale a aprobación docente: el estado de revisión DEBE conservarse
como `pending_teacher_review`. Toda ejecución activa exige una aprobación por
intento, incluso con catálogo automático. Una propuesta sin adaptador DEBE quedar
visible y no ejecutable.

#### Scenario: Sesión sin autorización
- GIVEN una sesión sin autorización de comprobaciones activas
- WHEN se intenta aprobar una comprobación activa
- THEN se rechaza sin enviar tráfico al laboratorio

#### Scenario: Autorización con gate por intento
- GIVEN una sesión con comprobaciones activas habilitadas y catálogo automático
- WHEN Validación propone `PROPOSAL-AUTH-SQLI-001`
- THEN la sesión espera decisión humana y solo ejecuta una carga fija tras la aprobación

#### Scenario: Propuesta sin adaptador
- GIVEN una propuesta activa que requiere navegador o multipart
- WHEN el flujo la evalúa
- THEN queda declarada como no ejecutable y no se envía ninguna petición

#### Scenario: Profundizar sin depender del modelo
- GIVEN una sesión con comprobaciones activas habilitadas y ninguna activa ejecutada
- WHEN la persona elige profundizar
- THEN se encola la próxima comprobación activa y la sesión espera aprobación por intento

### Índice de directorio descriptivo
Cuando una comprobación de listado observa entradas, el sistema DEBE describir
los nombres ya presentes en esa respuesta, sin descargar ni abrir los archivos.

#### Scenario: Índice de /ftp visible
- GIVEN una respuesta con un índice de `/ftp`
- WHEN se evalúa la comprobación
- THEN el recibo enumera las entradas observadas y aclara que no se descargó ningún archivo

Tests: `tests/test_active_checks.py`, `tests/test_relevo.py`, `tests/test_poc_catalog.py`.
