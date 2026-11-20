## ADDED Requirements

Tests: `tests/test_roe.py`.

### Requirement: RoE limitado a datos de laboratorio
### Scenario: Alcance inválido
- GIVEN un YAML vacío de alcance, con CIDR público, wildcard, claves duplicadas o alias
- WHEN el operador intenta cargarlo
- THEN no se crea un RoE válido

### Scenario: Ventana inválida o fase no permitida
- GIVEN una ventana invertida o una fase ausente del acuerdo
- WHEN se valida o se solicita una credencial de esa fase
- THEN se rechaza

### Requirement: Emisión local y vigencia acotada
### Scenario: Aprobación fuera del documento
- GIVEN un RoE válido sin aprobación del operador
- WHEN se solicita un token
- THEN no se emite

### Scenario: TTL y fin exclusivo
- GIVEN una ventana activa y la aprobación de la demo inerte
- WHEN se emite un token
- THEN autoriza solo esa fase hasta el menor fin entre TTL y RoE, exclusivo

### Scenario: Objeto copiado o reemplazado
- GIVEN un token fabricado, copiado o sustituido por una renovación
- WHEN se invoca el adaptador inerte en el perfil 003
- THEN el Guard lo bloquea y no se ejecuta el adaptador

### Scenario: Recorrido permitido y bloqueado
- GIVEN un token emitido y un adaptador inerte
- WHEN se invoca un host exacto autorizado y después un host fuera del RoE
- THEN solo la primera invocación llega al adaptador y ambas decisiones son auditables
