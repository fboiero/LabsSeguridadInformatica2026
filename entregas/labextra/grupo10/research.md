# Research — Lab Extra SSRF: El Metadata Service en Entornos Cloud e IMDS de AWS

**Grupo:** 10  
**Integrantes:** Carolina Paula Corazza — @carocor1; Belén Rocío Ramello — @belramello; Chiara Agustina Kordek — @chiarakordek; Juan Pablo Saby — @JuanSaby.  
**Redacción y desarrollo de esta sección:** Juan Pablo Saby — @JuanSaby.  
**Fecha:** Noviembre 2026.  
**Entorno de referencia:** Laboratorio SSRF de cátedra (recursos internos simulados en contenedores Docker locales).

---

## Declaración de uso de IA

Para la elaboración de este documento de investigación se utilizó asistencia de modelos de lenguaje (Antigravity / Gemini) como herramienta de apoyo para refinar la redacción de las explicaciones arquitectónicas. Todos los comandos ya análisis transversal con documentación oficial de proveedores y estandares IETF son de elaboracion propia.

---

## 1. El Metadata Service en entornos Cloud (Opción B)

### 1.1. ¿Qué información expone y a quién?

El *Instance Metadata Service* (IMDS) es un servicio de infraestructura provisto por las plataformas de computación en la nube pública (como Amazon Web Services, Google Cloud Platform y Microsoft Azure) que permite a las instancias virtuales acceder a información sobre su propia configuración, aprovisionamiento y entorno operativo en tiempo de ejecución.

Arquitectónicamente, el servicio se expone en una dirección IPv4 especial de enlace local (*link-local*): **`169.254.169.254`** (definida en el estándar RFC 3927), complementada en AWS con su dirección IPv6 correspondiente (`fd00:ec2::254`) y en GCP con el nombre de resolución interna `metadata.google.internal`. Por diseño de la pila de protocolos TCP/IP, las direcciones de enlace local no son enrutables fuera del segmento de red local: los routers de internet descartan de forma predeterminada cualquier paquete dirigido a `169.254.0.0/16`. En consecuencia, el servicio está concebido para ser consumido **única y exclusivamente por los procesos que se ejecutan dentro del sistema operativo de la propia instancia virtual**, comunicándose de manera directa con el hipervisor a través de la interfaz de red virtualizada.

Entre las principales categorías de información expuestas por el IMDS se destacan:

1. **Datos de configuración e inventario de la instancia:** Identificadores únicos (`instance-id`, `ami-id`), tipo de instancia, región geográfica, zona de disponibilidad, nombre de host, interfaces de red, direcciones IP públicas y privadas, tablas de enrutamiento y grupos de seguridad asignados.
2. **Datos de usuario (*User-Data*):** Scripts de inicialización o directivas de configuración (ej. scripts de *cloud-init*) suministrados durante el lanzamiento de la instancia. En despliegues deficientes, el endpoint `user-data` suele almacenar por mala práctica variables de entorno con credenciales maestras, cadenas de conexión a bases de datos, tokens de API o certificados TLS embebidos.
3. **Credenciales de seguridad temporales para roles IAM:** En arquitecturas de nube modernas, se desaconseja almacenar claves de acceso estáticas en el disco de los servidores. En su lugar, se asocia un rol de Identity and Access Management (IAM) a la instancia (mediante un *Instance Profile* en AWS). El hipervisor consulta periódicamente a AWS Security Token Service (STS) y deposita credenciales temporales rotativas en el endpoint de metadatos:
   ```text
   http://169.254.169.254/latest/meta-data/iam/security-credentials/<nombre-del-rol>
   ```
   Cualquier proceso local puede consultar este endpoint mediante una solicitud HTTP y recibir un objeto JSON que contiene un `AccessKeyId`, un `SecretAccessKey`, un `Token` criptográfico de sesión y la fecha de expiración correspondiente.

*Matiz de diseño entre proveedores:* Mientras que AWS en su versión inicial (IMDSv1) no exigía cabeceras HTTP específicas para responder, Google Cloud Platform (GCP) y Microsoft Azure implementaron desde sus orígenes requisitos defensivos en la capa de aplicación: GCP exige obligatoriamente la cabecera HTTP `Metadata-Flavor: Google`, y Azure requiere `Metadata: true`, lo cual bloquea de forma predeterminada intentos de consulta a través de clientes web primitivos que no permiten inyectar encabezados arbitrarios.

---

### 1.2. ¿Por qué un SSRF lo convierte en robo de credenciales?

En una arquitectura tradicional bajo IMDSv1, el servicio de metadatos confía ciegamente en la **posición topológica de red** del emisor: asume que cualquier solicitud que arribe a `169.254.169.254` proviene legítimamente del código autorizado de la instancia. No implementa autenticación previa mediante contraseña, certificados de cliente o tokens estáticos.

Cuando una aplicación web desplegada en dicha instancia presenta una vulnerabilidad de *Server-Side Request Forgery* (SSRF, CWE-918) —similar a la observada en el parámetro `/preview?url=` de este laboratorio—, se produce una ruptura total del modelo de confianza:

1. **Abuso del origen confiable:** El atacante externo, ubicado en internet, no puede enrutar tráfico directamente hacia la dirección no enrutable `169.254.169.254`. Sin embargo, al suministrar dicha URL en la entrada de la aplicación vulnerable, **fuerza al servidor web a realizar la petición en su nombre**.
2. **Extracción en dos etapas:**
   - En una primera solicitud, el atacante instruye al servidor a consultar `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. El servidor ejecuta la petición HTTP interna y devuelve la lista de nombres de roles asociados al perfil de la instancia (por ejemplo: `AppProductionRole`).
   - En una segunda solicitud, el atacante solicita `http://169.254.169.254/latest/meta-data/iam/security-credentials/AppProductionRole`. El servidor web fetchea la URL y refleja el cuerpo de la respuesta, entregando al atacante el JSON con las credenciales temporales generadas por STS.
3. **Trascendencia del host y compromiso de la cuenta:** A diferencia de una vulnerabilidad que solo expone datos locales del disco, estas credenciales de STS son **tokens criptográficos válidos contra las APIs públicas globales de AWS**. El atacante no necesita mantener persistencia en el servidor ni obtener una shell: simplemente exporta `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` y `AWS_SESSION_TOKEN` en su propia consola externa y ejecuta llamadas con la herramienta oficial `aws cli` o cualquier SDK de AWS contra los servicios en la nube de la víctima.

*Dependencia del impacto según permisos y controles:* El daño real derivado del robo de credenciales no es uniforme: está estrictamente condicionado por las políticas de permisos asociadas al rol IAM comprometido. Si la organización aplicó con rigor el principio de menor privilegio (otorgando al rol permisos de solo lectura sobre una ruta específica de un bucket S3), el impacto queda confinado a esos datos. Por el contrario, si el rol fue configurado con políticas excesivas o comodines (como `AdministratorAccess` o `s3:*` sobre todos los recursos), el atacante obtiene control absoluto sobre el almacenamiento perimetral, bases de datos gestionadas (RDS), instancias adicionales y la infraestructura global de la cuenta.

---

### 1.3. ¿Qué es IMDSv2 (AWS) y qué ataque bloquea?

En respuesta a la proliferación de incidentes críticos de explotación de SSRF contra instancias cloud en la industria, AWS lanzó en noviembre de 2019 el **Instance Metadata Service Version 2 (IMDSv2)**. IMDSv2 introduce un modelo de **defensa en profundidad orientado a sesiones** (*session-oriented requests*), diseñado específicamente para neutralizar la explotación de SSRF y el abuso de intermediarios de red desconfigurados.

#### Mecanismo operativo de IMDSv2

IMDSv2 reemplaza la consulta directa en un solo paso por un flujo obligatorio de dos fases:

1. **Paso 1 — Negociación del token de sesión:** La aplicación debe iniciar la sesión emitiendo una petición HTTP con el método **`PUT`** dirigida al endpoint `/latest/api/token`, incorporando obligatoriamente una cabecera personalizada que define la vida útil del token en segundos (entre 1 y 21600 segundos / 6 horas):
   ```http
   PUT /latest/api/token HTTP/1.1
   Host: 169.254.169.254
   X-aws-ec2-metadata-token-ttl-seconds: 21600
   ```
   El hipervisor valida la solicitud y devuelve en el cuerpo de la respuesta un token secreto de sesión firmado criptográficamente.
2. **Paso 2 — Acceso autenticado a los metadatos:** Para realizar cualquier consulta posterior a los metadatos (utilizando métodos `GET` o `HEAD`), la aplicación debe adjuntar el token obtenido en la cabecera HTTP **`X-aws-ec2-metadata-token`**:
   ```http
   GET /latest/meta-data/iam/security-credentials/AppProductionRole HTTP/1.1
   Host: 169.254.169.254
   X-aws-ec2-metadata-token: <TOKEN_OBTENIDO_EN_PASO_1>
   ```

#### Ataques y vectores que bloquea de forma efectiva

1. **SSRF basados en peticiones GET simples:** La inmensa mayoría de las vulnerabilidades SSRF en aplicaciones web (como previews de enlaces, importadores de imágenes o webhooks básicos) solo permiten al atacante controlar la URL solicitada mediante una petición HTTP de tipo `GET`. No ofrecen capacidades para alternar el verbo HTTP a `PUT` ni para inyectar cabeceras HTTP arbitrarias (`X-aws-ec2-metadata-token-ttl-seconds`). Sin la capacidad de emitir ese `PUT` inicial con su cabecera requerida, el atacante no puede obtener el token de sesión y el servicio rechaza cualquier intento de lectura directa devolviendo un error HTTP 401 Unauthorized.
2. **Abuso de proxies inversos abiertos y WAFs mal configurados:** IMDSv2 inspecciona las cabeceras de transporte y **rechaza automáticamente cualquier petición que contenga la cabecera `X-Forwarded-For`**. Esto impide que atacantes externos utilicen balanceadores de carga, proxies reversos o firewalls de aplicaciones web que reenvían tráfico HTTP como intermediarios involuntarios para consultar el metadata service.
3. **Contención en entornos contenerizados (Límite de saltos de IP / TTL=1):** En las instancias configuradas con IMDSv2, el número máximo de saltos de red (*IP Hop Limit*) para las respuestas de metadatos se establece de forma predeterminada en **1**. En arquitecturas de contenedores (como Docker o Kubernetes en EC2), el tráfico que sale desde un contenedor hacia la red del host anfitrión atraviesa una interfaz virtual (*bridge*) que decrementa el TTL del paquete IP en 1. Al llegar el TTL a 0, el kernel descarta el paquete, impidiendo que un contenedor comprometido con SSRF pueda consultar el metadata service del host subyacente a menos que se incremente intencionalmente dicho límite.

*Estado actual de adopción:* Desde mediados de 2024, AWS establece IMDSv2 como la configuración predeterminada para todas las nuevas instancias lanzadas en la plataforma. Para alcanzar la protección completa, las organizaciones deben forzar el parámetro `HttpTokens=required` y deshabilitar explícitamente IMDSv1, eliminando la compatibilidad retroactiva vulnerable.

---

### 1.4. Relación con lo observado en el laboratorio (Reto R1)

El análisis del reto **R1** en el laboratorio extra presenta una correlación teórica y arquitectónica directa con la problemática del Metadata Service en la nube:

| Aspecto analizado | Reto R1 del laboratorio | Metadata Service en Cloud (IMDS) |
|---|---|---|
| **Dirección de destino** | `http://127.0.0.1:9000/` (interfaz Loopback) | `http://169.254.169.254/` (interfaz Link-Local) |
| **Premisa de diseño del servicio** | "Solo escucha en localhost, nadie desde afuera puede alcanzarlo" | "Solo responde dentro de la instancia, no es enrutable en internet" |
| **Mecanismo de explotación** | Petición HTTP a través de `/preview?url=...` | Petición HTTP a través de la función vulnerable de la app |
| **Rol del servidor vulnerable** | Intermediario involuntario (fetchea desde el contexto local) | Intermediario involuntario (fetchea desde la interfaz de la instancia) |
| **Información expuesta** | Panel administrativo y clave de despliegue local (`FLAG_PANEL`) | Datos de configuración y credenciales temporales IAM (STS) |
| **Mecanismo de autenticación base** | Ausente en la capa HTTP interna | Ausente en IMDSv1 (mitigado mediante tokens en IMDSv2) |

Tanto el panel en `localhost` como el endpoint `169.254.169.254` basaron su seguridad exclusivamente en la **suposición de aislamiento de red**. El vector SSRF demostró en ambos casos que cualquier servicio interno que carezca de autenticación propia en la capa de aplicación y confíe únicamente en la procedencia del socket queda desprotegido en cuanto un proceso local puede ser inducido a emitir peticiones arbitrarias.

*Aclaración de alcance del laboratorio:* Es fundamental resaltar que en este trabajo práctico se interactuó de manera exclusiva con contenedores Docker locales provistos por la cátedra (`phantomcorp` y `phantomcorp-intra`). Los servicios auditados corresponden a implementaciones simuladas en Python con fines de aprendizaje; **en ningún momento se interactuó con endpoints de metadatos de un proveedor de nube real ni se comprometió infraestructura productiva.**

---

## 2. Pregunta de cierre (obligatoria)

> *¿Qué similitud y qué diferencia hay entre "el server fetchea por vos" (SSRF) y "el server ejecuta por vos" (inyección de comandos, Lab 07)? ¿Cuál te parece más peligrosa y por qué?*

### 2.1. Similitudes conceptuales

1. **Falla de validación en la frontera de entrada:** Ambas vulnerabilidades se originan en el mismo error de diseño fundamental: la **confianza ciega en entradas suministradas por el usuario**. La aplicación toma un valor externo arbitrario y lo inserta sin desinfección ni listas blancas en una operación de alto privilegio.
2. **Delegación involuntaria de privilegios y personificación:** En ambos escenarios, la aplicación actúa como un mandatario no intencional del atacante. El atacante no ataca directamente el recurso final (el sistema operativo en RCE o el servicio interno en SSRF), sino que convence al servidor de que realice la acción prestando su propia identidad, su posición de red privilegiada y sus permisos de ejecución.
3. **Evasión de barreras perimetrales tradicionales:** Ni la inyección de comandos ni el SSRF son detenidos por firewalls de red perimetrales estándar que protegen la entrada (`ingress`), dado que el tráfico malicioso inicial arriba a través de puertos legítimos y abiertos al público (puerto HTTP 80/443). Una vez que la petición ingresa, la acción posterior se ejecuta desde adentro hacia adentro.

### 2.2. Diferencias operativas y primitivas técnicas

| Criterio técnico | Inyección de comandos — RCE (Lab 07) | Server-Side Request Forgery — SSRF (Lab Extra) |
|---|---|---|
| **Primitiva fundamental** | **Ejecución en el sistema operativo** (plano de cómputo local). | **Emisión de tráfico de red** (plano de transporte / socket HTTP). |
| **Mecanismo subyacente** | Paso de parámetros no saneados a un intérprete de comandos (`/bin/sh`, `cmd.exe`, `subprocess(shell=True)`). | Paso de una URL no validada a un cliente o biblioteca HTTP (`urllib`, `requests`, `cURL`). |
| **Control del atacante** | Control del flujo de instrucciones de la CPU y llamadas al sistema (*syscalls*). | Control del destino de red (IP/puerto) y protocolo de la petición. |
| **Alcance inmediato** | Modificación del sistema de archivos, ejecución de procesos, lectura de variables locales, spawn de shells interactivas. | Interacción con sockets de red: lectura de respuestas HTTP internas, escaneo de puertos, pivot a intranets. |
| **Dependencia del entorno** | Autosuficiente: el compromiso del host ocurre de forma directa e inmediata. | Condicionada: el impacto depende de los servicios accesibles en la red interna alcanzada. |

### 2.3. ¿Cuál es más peligrosa y por qué?

Desde un análisis de riesgo técnico riguroso, la respuesta requiere evaluar el **contexto arquitectónico**:

#### La perspectiva tradicional (Host-Centric): Inyección de comandos como máxima amenaza
En servidores dedicados o máquinas virtuales tradicionales ("monolitos" en infraestructura física o VPS clásicos), la **inyección de comandos (RCE) es intrínsecamente más peligrosa y letal de manera inmediata**. Un RCE otorga control directo del plano de cómputo: el atacante compromete la integridad, confidencialidad y disponibilidad del sistema operativo bajo los privilegios del servicio web (`www-data`). Desde allí puede desplegar *web shells*, alterar código fuente, leer archivos del sistema (`/etc/shadow`, claves privadas SSH), establecer persistencia mediante tareas programadas (*cron jobs*) e instalar herramientas de red avanzadas para escanear y pivotar lateralmente con sockets completos (no limitados al protocolo HTTP). Frente a esto, un SSRF en un servidor aislado sin servicios locales ni redes internas adyacentes tiene una utilidad muy limitada para el atacante.

#### La perspectiva moderna (Cloud-Native y Microservicios): La letalidad sistémica del SSRF
En arquitecturas modernas basadas en microservicios contenerizados y nubes públicas, **el SSRF puede resultar significativamente más devastador a nivel sistémico que un RCE local**:

1. **La contención del contenedor ante RCE:** Una aplicación moderna empaquetada en un contenedor Docker con sistema de archivos de solo lectura (*read-only root filesystem*), sin binarios de shell instalados (imágenes *distroless* o mínimas), usuario no root y límites de recursos estrictos, reduce drásticamente el radio de explosión de una inyección de comandos. El atacante queda confinado a un entorno efímero y degradado donde ejecutar comandos es inviable o no permite escalar privilegios fácilmente.
2. **La amplificación del SSRF hacia el plano de control:** En ese mismo contenedor severamente restringido, un SSRF permite emitir peticiones que abandonan el contenedor a través de la red. Si el entorno corre sobre una infraestructura cloud con IMDSv1 activo, el SSRF permite consultar `169.254.169.254` y exfiltrar las credenciales temporales de IAM de la instancia anfitriona. De forma análoga, en un clúster de Kubernetes, un SSRF puede apuntar a la API del Kubelet (`https://10.254.0.1:10250`), al servidor de etcd o a motores de secretos internos (HashiCorp Vault). Con estas credenciales, el atacante trasciende completamente el contenedor y la máquina virtual, tomando control del plano de gestión en la nube (buckets de almacenamiento globales, bases de datos gestionadas y despliegues de infraestructura).

**Conclusión fundamentada:**  
La **inyección de comandos** representa el compromiso más grave e inmediato a nivel de **sistema operativo local** (máxima severidad en el activo puntual). Por su parte, el **SSRF** se ha consolidado en la actualidad como una de las amenazas más críticas a nivel de **arquitectura distribuida y de nube**, ya que tiene la capacidad de sortear la segmentación física y lógica de redes y convertir la identidad del servidor en una llave de acceso para comprometer el plano de control y los datos masivos de toda la organización.

---

## 3. Fuentes y referencias bibliográficas

1. **Amazon Web Services (AWS) Documentation:**
   - *Instance metadata and user data for Amazon EC2:*  
     [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
   - *Configure the instance metadata service options (IMDSv2):*  
     [https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
2. **AWS Security Blog:**
   - *Add defense in depth against open firewalls, reverse proxies, and SSRF vulnerabilities with enhancements to the EC2 Instance Metadata Service (Colm MacCárthaigh, 2019):*  
     [https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)
   - *Get the full benefits of IMDSv2 and disable IMDSv1 across your AWS infrastructure (Saju Sivaji & Josh Levinson, 2023):*  
     [https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/](https://aws.amazon.com/blogs/security/get-the-full-benefits-of-imdsv2-and-disable-imdsv1-across-your-aws-infrastructure/)
3. **OWASP (Open Web Application Security Project):**
   - *Server-Side Request Forgery Prevention Cheat Sheet:*  
     [https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
   - *OWASP Top 10:2021 — A10: Server-Side Request Forgery (SSRF):*  
     [https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
4. **Internet Engineering Task Force (IETF):**
   - *RFC 3927 — Dynamic Configuration of IPv4 Link-Local Addresses (Section 2.1: Link-Local Address Selection):*  
     [https://datatracker.ietf.org/doc/html/rfc3927](https://datatracker.ietf.org/doc/html/rfc3927)

