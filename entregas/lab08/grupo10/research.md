# Mini-research — Laboratorio 08

**Grupo:** 10  
**Tema elegido:** C — Gestión de secretos: riesgos de `.env` y alternativas.

## Desarrollo

Un archivo `.env` es cómodo para configurar una aplicación, pero no constituye por sí mismo un mecanismo seguro para guardar credenciales. Si contiene contraseñas, tokens o claves y queda dentro de un directorio web, una imagen de contenedor, una copia de seguridad o un repositorio accesible, quien obtenga lectura puede reutilizar esos secretos. El riesgo se agrava cuando varias aplicaciones comparten una misma credencial: no queda claro qué sistema la filtró y su revocación puede interrumpir más servicios de los necesarios. OWASP describe el problema más amplio como la presencia de secretos en texto claro en archivos de configuración y recomienda centralizar su almacenamiento, aprovisionamiento, auditoría, rotación y revocación (OWASP, s. f.).

La alternativa no es simplemente cambiar el archivo por una variable de entorno permanente. La aplicación necesita obtener el secreto en tiempo de ejecución desde un gestor de secretos o un servicio equivalente, autenticándose con una identidad de workload. El acceso debe limitarse a los secretos que necesita esa aplicación y quedar registrado. Cuando el backend lo permite, las credenciales dinámicas y de corta duración reducen el período durante el cual una credencial robada podría reutilizarse. OWASP advierte que detener el proceso consumidor no revoca por sí solo un secreto dinámico: el proveedor debe vencerlo o recibir una revocación explícita. Para credenciales estáticas, se puede automatizar la rotación coordinando el cambio tanto en el gestor como en la base de datos o servicio que valida la credencial.

La rotación reduce la ventana de exposición, pero no reemplaza los controles de acceso. NIST explica que el período de uso de una clave (cryptoperiod) influye en cuánto dura la exposición si se compromete; si una clave se considera comprometida, su período autorizado deja de ser válido (NIST, 2020). Aplicado a credenciales de aplicación, esto respalda disponer de procedimientos de revocación y sustitución, aunque las contraseñas de bases de datos y las claves criptográficas no son objetos idénticos y no deben gestionarse con la misma política sin análisis.

La documentación de AWS Secrets Manager ilustra una implementación concreta de rotación: al rotar, se actualiza la credencial tanto en Secrets Manager como en la base de datos o servicio que la consume. La documentación describe rotación administrada para ciertos secretos y rotación mediante funciones Lambda para otros tipos (Amazon Web Services, s. f.). Esto muestra que la rotación necesita coordinación y pruebas, no solo generar un valor nuevo en una bóveda.

Persisten límites. Un gestor central se convierte en un activo crítico: una identidad de workload excesivamente privilegiada, una política incorrecta o una filtración en logs puede exponer muchos secretos. La rotación también puede causar fallas si consumidores conservan valores antiguos o si no se valida la nueva credencial antes de retirar la anterior. Por eso hacen falta mínimo privilegio, identidad fuerte de workloads, auditoría, alertas, ocultamiento de secretos en salidas y un plan de respuesta para revocar credenciales comprometidas. Si un secreto apareció en `.env` o en el historial del shell, borrarlo del archivo no invalida copias: hay que revocarlo o rotarlo y revisar dónde se reutilizó.

## Fuentes

1. [PRIMARIA] Amazon Web Services. (s. f.). *Rotate AWS Secrets Manager secrets*. https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html
2. [PRIMARIA] National Institute of Standards and Technology. (2020). *Recommendation for key management: Part 1 — General (NIST SP 800-57 Part 1 Rev. 5).* https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-57pt1r5.pdf
3. [PRIMARIA] OWASP Foundation. (s. f.). *Secrets management cheat sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Reflexión

El gestor de secretos mejora el control y la trazabilidad, pero no vuelve inocua una credencial filtrada. La defensa útil combina acceso mínimo, corta duración cuando sea posible, rotación probada y revocación rápida. En el escenario del laboratorio, encontrar un secreto en un archivo debe llevar a evaluar su alcance y reemplazarlo, no solo a borrar la evidencia.

A lo largo de los laboratorios anteriores se fue avanzando desde el reconocimiento y la enumeración hasta la explotación y la post-explotación. Muchas de estas tareas repetitivas pueden automatizarse mediante scripts, lo que permite procesar información de forma más rápida y ordenada. De cara a la orquestación que se aborda en el Laboratorio 09, automatizar no significa dejar todo en manos de una herramienta: definir la autorización, respetar los límites del alcance y evaluar el impacto de cada acción sigue siendo responsabilidad del criterio humano.
