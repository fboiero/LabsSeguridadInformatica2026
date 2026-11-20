# Diseño — 007-reporting-defectdojo
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

## Actualización tras habilitar Docker Desktop
Se agregó DockerSender: verifica red internal y subred de laboratorio, ejecuta
un worker Python stdlib read-only, sin capacidades, sin privilegios nuevos, usuario
65534, límite de memoria/CPU/pids. Se elimina con --rm y cleanup en finally.
La red del compose se fijó en 10.99.0.0/28 con DVWA .2, Juice Shop .3 y runner .4,
coherente con el RoE del 003. La exclusión .5 no se usa como objetivo.
Validación real de POC-CSP-001 en DVWA /login.php: validated; worker eliminado.
Las aprobaciones de esa corrida se identifican como prueba automatizada, no como
revisión humana académica. Reporte y exportación JSON se probaron localmente.
Dos mutation checks detectaron la eliminación de los gates; evidencia/fernando/.
Error real de la IA corregido: el chequeo inicial de la red Docker exigía que toda
la subred estuviera en un único fragmento CIDR del token tras descontar .5, y rechazaba
el lab válido. Se separó red interna dentro del máximo del lab de IP de destino dentro
del token efectivo. Otro error: GET / redirigía; se eligió /login.php sin habilitar redirects.
Revisión cruzada por Lautaro y archivado definitivos permanecen pendientes.
