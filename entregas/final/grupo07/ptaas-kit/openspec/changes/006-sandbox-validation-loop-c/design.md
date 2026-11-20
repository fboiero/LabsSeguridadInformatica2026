# Diseño — 006-sandbox-validation-loop-c
Autor: Fernando Cagliero. Revisión cruzada: pendiente de Lautaro; no se marca 1.3.

La interfaz de contracts.py permanece intacta. Todo adaptador se invoca por Harness.invoke.
Se usa TokenIssuer del 003 y EngagementGuard. No se construyen tokens directamente.

006: aprobaciones explícitas por CLI, id/activo/PoC/parámetros canónicos con SHA-256,
TTL de 15 minutos, motivos obligatorios, rechazo y vencimiento deniegan por defecto.
Loop C máximo dos intentos, cierre en finally. Sender HTTP restringido: DNS validado
contra CIDR del token y lab; conexión fijada a IP comprobada, sin proxies ni redirects;
2 solicitudes, 3 segundos por conexión y 64 KiB. Es un recorte sin contenedor y no
se afirma aislamiento de red del sistema operativo. Fixtures sintéticas son el modo
por defecto; no existe fallback silencioso de red a fixture. Fallas quedan registradas.

007: referencias a hashes existentes del audit y del mismo activo/engagement;
reporte determinista versionado por SHA-256 y gate de entrega independiente. Formato
Generic Findings Import, sin API real de DefectDojo. Vector base CVSS v4 validado
estrictamente; no se inventa score. Severidad Info de exportación es conservadora
hasta valoración humana, se explica en descripción. EPSS desconocido se muestra unknown.
Secretos se rechazan en todos los campos exportables. No se exporta respuesta cruda.

Integración: demo fixture explícita mientras 002/004/005 no estén disponibles;
la bitácora en memoria se exporta y verifica con hash (no sustituye SQLite 002).
La ventana RoE del ejemplo se conserva; tests usan ventanas vigentes.
