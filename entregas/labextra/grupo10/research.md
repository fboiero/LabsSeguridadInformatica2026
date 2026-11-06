# Research — Lab Extra SSRF: El Metadata Service en Entornos Cloud e IMDS de AWS

**Grupo:** 10  
**Integrantes:** Carolina Paula Corazza — @carocor1; Belén Rocío Ramello — @belramello; Chiara Agustina Kordek — @chiarakordek; Juan Pablo Saby — @JuanSaby.  
**Redacción y desarrollo de esta sección:** Juan Pablo Saby — @JuanSaby.
**Fecha:** Noviembre 2026.  
**Entorno de referencia:** Laboratorio SSRF de cátedra (recursos internos simulados en contenedores Docker locales).

---

## Declaración de uso de IA

Para la elaboración de este documento se utilizó asistencia de modelos de lenguaje (Antigravity / Gemini) como apoyo para refinar la redacción de explicaciones arquitectónicas. El autor revisó las afirmaciones técnicas contra la documentación oficial de AWS citada en las referencias y el RFC 3927. No se ejecutaron consultas contra servicios de metadata cloud; el análisis es documental y está separado de las pruebas en los contenedores del laboratorio.

---

## 1. El Metadata Service en entornos Cloud (Opción B)

### 1.1. ¿Qué información expone y a quién?

El *Instance Metadata Service* (IMDS) es un servicio de infraestructura que permite a una instancia de nube acceder a información sobre su configuración y entorno de ejecución. AWS, GCP y Azure ofrecen servicios de metadata, aunque sus endpoints y mecanismos de protección varían.

En AWS EC2, el servicio está disponible en la dirección IPv4 de enlace local `169.254.169.254` y, bajo condiciones de instancia y red compatibles, en `fd00:ec2::254`. GCP también documenta `metadata.google.internal`. Estas direcciones y nombres identifican servicios locales al entorno de la instancia; no se debe generalizar que todos los proveedores usan la misma implementación. RFC 3927 define el bloque IPv4 link-local, pero no describe por sí mismo el servicio IMDS.

Entre las principales categorías de información expuestas por el IMDS se destacan:

1. **Datos de configuración e inventario de la instancia:** Identificadores únicos (`instance-id`, `ami-id`), tipo de instancia, región geográfica, zona de disponibilidad, nombre de host, interfaces de red, direcciones IP públicas y privadas, tablas de enrutamiento y grupos de seguridad asignados.
2. **Datos de usuario (*User-Data*):** Datos o scripts de configuración suministrados durante el lanzamiento. No son credenciales por definición; incluir secretos allí es una práctica insegura que debe evitarse.
3. **Credenciales de seguridad temporales para roles IAM:** Se puede asociar un rol de Identity and Access Management (IAM) a la instancia (mediante un *Instance Profile* en AWS). Si el rol está presente, el endpoint de metadata expone credenciales temporales:
   ```text
   http://169.254.169.254/latest/meta-data/iam/security-credentials/<nombre-del-rol>
   ```
Los procesos con acceso al endpoint pueden recibir un objeto JSON con `AccessKeyId`, `SecretAccessKey`, `Token` de sesión y fecha de expiración. La disponibilidad de credenciales depende de que haya un rol asociado y de la configuración del servicio.

*Matiz de diseño entre proveedores:* AWS IMDSv1 no exige el token de sesión de IMDSv2. GCP documenta la cabecera `Metadata-Flavor: Google` y Azure la cabecera `Metadata: true`. Estos requisitos pueden dificultar SSRF simples sin control de cabeceras, pero el efecto depende de las capacidades de la aplicación vulnerable y de la configuración concreta.

---

### 1.2. ¿Por qué un SSRF lo convierte en robo de credenciales?

En AWS IMDSv1, una solicitud de metadata no requiere el token de sesión que exige IMDSv2. La restricción principal es de acceso desde el entorno de la instancia, no una autenticación de usuario convencional para cada consulta.

Cuando una aplicación web desplegada en dicha instancia presenta una vulnerabilidad de *Server-Side Request Forgery* (SSRF, CWE-918) —similar a la observada en el parámetro `/preview?url=` de este laboratorio—, puede romperse el límite de confianza de red, sujeto a los controles de la instancia y de la aplicación:

1. **Abuso del origen confiable:** Un atacante externo puede no tener acceso directo al endpoint local `169.254.169.254`. Si la aplicación vulnerable puede alcanzarlo, aceptar la URL y exponer su respuesta, el atacante podría inducir una solicitud desde el servidor.
2. **Extracción según capacidades del SSRF:** Si la aplicación permite solicitar esas rutas y devolver respuestas, un atacante podría intentar consultar el endpoint de credenciales del rol asociado. Un SSRF restringido a `GET` y sin cabeceras personalizadas no suele poder completar por sí mismo el flujo de IMDSv2; no se debe asumir que siempre se pueden obtener credenciales. El éxito depende de la versión/configuración de IMDS, del control sobre método/cabeceras/redirecciones y del contenido reflejado por la aplicación.
3. **Alcance condicionado por permisos:** Si se obtienen credenciales temporales, estas pueden autenticarse contra APIs de AWS según sus permisos y vencimiento. Su uso desde otro entorno puede depender de condiciones adicionales de la política IAM y del contexto de la solicitud. El impacto no equivale automáticamente al compromiso de toda la cuenta.

*Dependencia del impacto según permisos y controles:* El daño depende de las políticas asociadas al rol, su vencimiento y las restricciones adicionales aplicables. Un rol de menor privilegio limita el alcance; permisos amplios pueden habilitar acciones sensibles sobre recursos cloud. El acceso a una credencial no implica automáticamente control de toda la cuenta.

---

### 1.3. ¿Qué es IMDSv2 (AWS) y qué ataque bloquea?

AWS presentó IMDSv2 en 2019. IMDSv2 introduce solicitudes orientadas a sesión (*session-oriented requests*) y añade una defensa que dificulta algunos vectores SSRF y solicitudes reenviadas por intermediarios de red.

#### Mecanismo operativo de IMDSv2

IMDSv2 reemplaza la consulta directa en un solo paso por un flujo obligatorio de dos fases:

1. **Paso 1 — Negociación del token de sesión:** La aplicación inicia una sesión con una petición HTTP **`PUT`** al endpoint `/latest/api/token`, con una cabecera que define la vida útil del token en segundos (entre 1 y 21600 segundos / 6 horas):
   ```http
   PUT /latest/api/token HTTP/1.1
   Host: 169.254.169.254
   X-aws-ec2-metadata-token-ttl-seconds: 21600
   ```
    El servicio valida la solicitud y devuelve un token de sesión en el cuerpo de la respuesta.
2. **Paso 2 — Acceso autenticado a los metadatos:** Para realizar consultas posteriores, la aplicación adjunta el token obtenido en la cabecera HTTP **`X-aws-ec2-metadata-token`**:
   ```http
   GET /latest/meta-data/iam/security-credentials/AppProductionRole HTTP/1.1
   Host: 169.254.169.254
   X-aws-ec2-metadata-token: <TOKEN_OBTENIDO_EN_PASO_1>
   ```

#### Ataques y vectores que dificulta

1. **SSRF limitados a GET y sin cabeceras:** IMDSv2 requiere primero una petición `PUT` a `/latest/api/token` con la cabecera `X-aws-ec2-metadata-token-ttl-seconds`, y luego el token en `X-aws-ec2-metadata-token`. Una función SSRF que solo permite `GET` y no deja controlar cabeceras no puede completar directamente ese flujo. Esto reduce ese vector, pero no es una solución universal frente a SSRF con control de método/cabeceras, cadenas de proxy, vulnerabilidades adicionales o configuraciones alternativas.
2. **Algunas solicitudes reenviadas:** En IMDSv2, AWS rechaza la petición `PUT` de obtención de token si incluye `X-Forwarded-For`, mitigando ciertos patrones de reenvío por proxies. Esta propiedad no sustituye la configuración segura del IMDS ni los controles de salida de la aplicación.
3. **Límite de saltos configurado:** AWS documenta que el *HTTP PUT response hop limit* es 1 por defecto. Un valor bajo puede dificultar que contenedores alcancen el servicio a través de ciertos saltos de red; debe verificarse y ajustarse según la topología real, y no reemplaza la exigencia de tokens.

*Configuración:* AWS documenta que, de forma predeterminada, una instancia puede aceptar IMDSv1, IMDSv2 o ambos. Para exigir IMDSv2 se configura `HttpTokens=required` en las opciones de metadata de la instancia o mediante políticas organizacionales; hay que verificar el valor efectivo.

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

El panel del laboratorio y algunos endpoints de metadata comparten el riesgo de que la ubicación de red del servidor influya en el acceso. Sin embargo, la analogía no implica que todos los servicios internos carezcan de autenticación, ni que un SSRF pueda superar cualquier control: los tokens, cabeceras requeridas, permisos y reglas de red son relevantes.

*Aclaración de alcance del laboratorio:* Es fundamental resaltar que en este trabajo práctico se interactuó de manera exclusiva con contenedores Docker locales provistos por la cátedra (`phantomcorp` y `phantomcorp-intra`). Los servicios auditados corresponden a implementaciones simuladas en Python con fines de aprendizaje; **en ningún momento se interactuó con endpoints de metadatos de un proveedor de nube real ni se comprometió infraestructura productiva.**

---

## 2. Pregunta de cierre (obligatoria)

> *¿Qué similitud y qué diferencia hay entre "el server fetchea por vos" (SSRF) y "el server ejecuta por vos" (inyección de comandos, Lab 07)? ¿Cuál te parece más peligrosa y por qué?*

### 2.1. Similitudes conceptuales

1. **Falla de validación en la frontera de entrada:** Ambas pueden originarse cuando la aplicación usa una entrada no confiable para seleccionar o construir una operación privilegiada sin validación ni controles adecuados.
2. **Delegación involuntaria de privilegios y personificación:** En ambos escenarios, la aplicación actúa como un mandatario no intencional del atacante. El atacante no ataca directamente el recurso final (el sistema operativo en RCE o el servicio interno en SSRF), sino que convence al servidor de que realice la acción prestando su propia identidad, su posición de red privilegiada y sus permisos de ejecución.
3. **Uso de una interfaz expuesta:** Ambos ataques pueden iniciarse mediante una petición a una aplicación accesible, pero los firewalls de red no bastan por sí solos para evitarlos; hacen falta validación de entradas, controles de privilegios y segmentación adecuados.

### 2.2. Diferencias operativas y primitivas técnicas

| Criterio técnico | Inyección de comandos — RCE (Lab 07) | Server-Side Request Forgery — SSRF (Lab Extra) |
|---|---|---|
| **Primitiva fundamental** | **Ejecución en el sistema operativo** (plano de cómputo local). | **Emisión de tráfico de red** (plano de transporte / socket HTTP). |
| **Mecanismo subyacente** | Paso de parámetros no saneados a un intérprete de comandos (`/bin/sh`, `cmd.exe`, `subprocess(shell=True)`). | Paso de una URL no validada a un cliente o biblioteca HTTP (`urllib`, `requests`, `cURL`). |
| **Control del atacante** | Puede influir en los argumentos o instrucciones que procesa el intérprete, según la vulnerabilidad. | Puede influir en el destino y, según la implementación, método y cabeceras de la petición de red. |
| **Alcance inmediato** | Puede causar ejecución de procesos o acciones sobre el sistema operativo con los permisos del proceso vulnerable. | Puede generar conexiones y leer respuestas de servicios alcanzables; no implica por sí solo ejecución de comandos. |
| **Dependencia del entorno** | El impacto depende de los permisos del proceso, las mitigaciones y el aislamiento del host. | El impacto depende además de los destinos alcanzables y de las respuestas que la aplicación revele. |

### 2.3. ¿Cuál es más peligrosa y por qué?

Desde un análisis de riesgo técnico riguroso, la respuesta requiere evaluar el **contexto arquitectónico**:

#### La perspectiva tradicional (Host-Centric): Inyección de comandos como máxima amenaza
En un servidor con pocos servicios internos y egreso restringido, una inyección de comandos puede ser más grave de forma inmediata porque permite ejecutar acciones en el sistema con los permisos del proceso vulnerable. El alcance no es absoluto: depende de los privilegios, el aislamiento y las mitigaciones. Un SSRF aislado, sin destinos internos sensibles, puede tener un impacto más limitado.

#### La perspectiva moderna (Cloud-Native y Microservicios): el alcance depende de la arquitectura
En arquitecturas de microservicios y nubes públicas, el SSRF puede ampliar el riesgo al alcanzar destinos internos, si la red y la aplicación lo permiten:

1. **Efecto de la contención:** Un contenedor con privilegios mínimos, sistema de archivos de solo lectura y capacidades reducidas puede limitar el impacto de una inyección de comandos, aunque no elimina la vulnerabilidad.
2. **Posible alcance de SSRF:** Un SSRF puede alcanzar servicios internos o metadata si la red, las opciones de metadata y la aplicación lo permiten. La explotación y el impacto dependen de controles como IMDSv2, autenticación, permisos IAM y reglas de egreso; no se presume acceso automático a credenciales ni al plano de control.

**Conclusión fundamentada:**  
La inyección de comandos suele tener un impacto más directo sobre el sistema operativo en el contexto afectado, mientras que un SSRF puede resultar más grave si la aplicación alcanza servicios internos sensibles. No hay una respuesta universal: la severidad depende de los permisos, la arquitectura, la segmentación y las mitigaciones efectivas.

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

