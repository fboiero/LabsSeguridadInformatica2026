# Mini-research — Laboratorio 08

**Grupo:** 06
**Tema elegido:** C. Gestión de secretos: por qué un `.env` en el servidor es un problema y qué lo reemplaza.

## Desarrollo

Los secretos de una aplicación (contraseñas de base de datos, claves de API, certificados, tokens) tienen un ciclo de vida: se crean, se entregan a quien los usa, se rotan, se revocan y deberían expirar. OWASP plantea la gestión de secretos en esos términos y recomienda centralizar su almacenamiento, aprovisionamiento, auditoría y rotación, con acceso regido por el principio de mínimo privilegio [1]. Un archivo `.env` resuelve una parte menor del problema: saca la configuración del código, pero no protege los valores que contiene ni gestiona su ciclo de vida.

En R2 el problema concreto fue de permisos. `/var/www/.env` era de `root` con permisos `0644`, así que `operador`, una cuenta sin privilegios, pudo leer la contraseña de la base y el secreto de la aplicación. A eso se suma que la credencial era estática: una vez copiada, sirve hasta que alguien note la filtración y la cambie. OWASP recomienda usar secretos dinámicos cuando sea posible y crearlos con vencimiento, justamente para acortar ese período [1].

El enfoque Twelve-Factor propone separar estrictamente configuración y código y guardar la configuración, credenciales incluidas, en variables de entorno, porque cambian entre despliegues sin tocar el código y es difícil versionarlas por accidente [2]. Ese criterio evita contraseñas escritas en el código o subidas al repositorio, pero no alcanza como medida de seguridad. La misma guía de OWASP, en su apartado sobre contenedores, desaconseja las variables de entorno para secretos salvo que no haya otra opción, y prefiere que la aplicación los obtenga en tiempo de ejecución desde un gestor, o los monte como archivos con permisos acotados [1]. Las dos fuentes no se contradicen del todo: Twelve-Factor responde a dónde no tiene que estar la configuración, y OWASP a cómo proteger un secreto una vez que sale del código.

Cuando el secreto es una clave criptográfica, NIST trata su protección como parte de la gestión de claves: cada clave tiene un período de uso definido, requisitos de protección según su tipo y funciones de gestión como la generación, la distribución, el reemplazo y la destrucción [3]. Es una norma para claves criptográficas, no para contraseñas de aplicación, pero respalda la misma idea: un secreto que no expira ni se rota no está gestionado.

Para PhantomCorp, la respuesta inmediata sería rotar la contraseña de `phantom_app` y el `APP_SECRET`, quitar la lectura del `.env` a otros usuarios y revisar si alguien usó la credencial. Como corrección de fondo, la aplicación debería pedir la credencial a un gestor de secretos con una identidad propia, recibir un valor de corta duración y dejar registro de cada acceso.

## Bonus: un pipeline recon → enum → explotación

Si encadenáramos en un solo script lo que hicimos a mano en los labs anteriores, cada etapa tomaría la salida estructurada de la anterior:

| Etapa | Lab | Entrada → salida | Herramienta base |
| --- | --- | --- | --- |
| Recon | 05 | objetivo autorizado → `host:puerto:servicio` | `nmap -sV` con salida XML |
| Enumeración | 06 | servicios HTTP → rutas, métodos y archivos expuestos | wordlist de directorios, `robots.txt`, `OPTIONS` |
| Explotación | 07 | endpoints candidatos → confirmación de inyección de comandos | payload inocuo (`id`) y comparación de la respuesta |
| Post-explotación | 08 | shell como usuario limitado → loot, SUID, hosts internos | comandos de recon del host y `recolector.py` |

Dos controles irían fuera de las etapas: una lista de alcance que se verifica antes de cada solicitud, y una pausa para que una persona apruebe antes de pasar de la enumeración a la explotación. Lo que el pipeline no resuelve es la interpretación: decidir qué ruta vale la pena o qué respuesta indica una inyección sigue dependiendo de reglas que escribimos nosotros. Esa es la parte que en el Lab 09 se delega en un agente.

## Fuentes

1. OWASP Cheat Sheet Series. «[Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)», secciones 1 (Introduction), 2.2 (Centralize and Standardize), 2.3 (Access Control), 2.4 (Automate Secrets Management), 2.7 (Secret Lifecycle) y 5.1 (Containers & Orchestrators). Consultado el 30/10/2026.
2. Wiggins, A. «[The Twelve-Factor App — III. Config](https://12factor.net/config)». Consultado el 30/10/2026.
3. Barker, E. *Recommendation for Key Management: Part 1 – General*. NIST SP 800-57 Part 1 Rev. 5, mayo de 2020. DOI: [10.6028/NIST.SP.800-57pt1r5](https://doi.org/10.6028/NIST.SP.800-57pt1r5).

## Reflexión

R2 mostró que separar los secretos del código no alcanza si el archivo que los guarda lo puede leer cualquier cuenta local. También nos hizo pensar en el tiempo: una contraseña estática filtrada sigue siendo un problema hasta que se rota. Mover el mismo valor a una variable de entorno no cambia eso; lo que cambia el riesgo es limitar quién puede pedir el secreto, que dure poco y que cada acceso quede registrado.
