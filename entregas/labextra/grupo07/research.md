# Research — Lab Extra SSRF · aporte de Lorenzo (opción B)

**Alcance:** mitad de investigación asignada a Lorenzo; la integración final de 1–2 carillas, el cierre comparativo y la selección/armonización de fuentes quedan pendientes de Lautaro. No se hicieron solicitudes a servicios metadata reales.

## Metadata de instancia: de datos operativos a credenciales

Un servicio de metadata de nube hace accesible información asociada a la instancia desde el entorno que corre en ella. En EC2 se accede al Instance Metadata Service (IMDS) a través de direcciones link-local como `169.254.169.254`; según la configuración y los endpoints consultados, puede exponer atributos de instancia y datos de identidad/credenciales temporales del rol asociado. AWS documenta tanto IMDSv1 como IMDSv2 y recomienda configurar IMDSv2 como requisito cuando la compatibilidad lo permite ([AWS, “Use the Instance Metadata Service to access instance metadata”](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)). La capacidad de leer esos datos depende de los permisos de red, la política de metadata y el rol asignado; alcanzar el endpoint no equivale automáticamente a tener permisos ilimitados.

El riesgo de SSRF aparece cuando un backend permite que una entrada controlada por el usuario determine la URL de una petición saliente. Si ese backend puede alcanzar IMDS y además devuelve la respuesta al usuario, un atacante podría intentar obtener credenciales temporales disponibles para la instancia. El paso posterior dependería de los permisos concretos del rol y de la validez de las credenciales: el impacto podría incluir acceso no autorizado a recursos cloud permitidos por ese rol. Por eso conviene conceder al workload el mínimo privilegio y bloquear el camino de red a destinos internos que la función de fetch no necesita.

OWASP recomienda validación estricta de destinos cuando la aplicación solo debería comunicarse con servicios identificados; también recomienda controles de red como defensa complementaria. Una lista de cadenas bloqueadas, por sí sola, es frágil ante cambios de representación, resolución DNS o redirecciones, así que la política debe verificarse sobre la URL analizada y la dirección efectivamente conectada, y reforzarse con salida de red restringida ([OWASP, “Server Side Request Forgery Prevention”](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)).

## Qué cambia IMDSv2

IMDSv2 usa una sesión: el cliente primero hace una solicitud `PUT` para recibir un token y debe presentar ese token en las solicitudes posteriores de metadata. Si la instancia está configurada para exigir IMDSv2, peticiones sin token válido reciben 401. Esto eleva el costo de SSRF simples que solo permiten emitir una solicitud `GET` sin encabezados arbitrarios, y dificulta ciertas clases de proxy abierto. No es una solución universal: una vulnerabilidad que permita controlar método, encabezados o secuencia de solicitudes podría sortear esa limitación; además, controles de red y roles de mínimo privilegio siguen siendo necesarios. AWS documenta que el token es obligatorio cuando el uso de tokens está configurado como `required` y que el límite TTL de respuesta predeterminado de `1` ayuda a limitar ciertos saltos de red.

La relación con la práctica es directa: en R3, `/preview` convirtió al servidor en cliente HTTP hacia un host que el operador no contactó directamente. En R1 se busca el mismo patrón en localhost; en cloud, el destino sería el endpoint link-local de metadata. El principio de riesgo es el mismo —la URL se solicita desde la posición de red del servidor—, pero el activo y la consecuencia cambian: un panel interno en el laboratorio frente a metadatos y posibles credenciales temporales en una instancia real.

## Pregunta de cierre — pendiente de integración

Propuesta para que Lautaro la integre al research común: SSRF e inyección de comandos comparten que una entrada manipulada hace que el servidor actúe en nombre del atacante; SSRF induce solicitudes de red, mientras que la inyección induce ejecución en el sistema operativo. La peligrosidad depende del contexto: ejecución de comandos puede dar control directo del host, mientras que SSRF puede alcanzar servicios internos o credenciales cloud con permisos amplios. El cierre final debería relacionar esa comparación con los privilegios y límites observados en los labs 07 y SSRF.

## Fuentes

- Amazon Web Services, [Use the Instance Metadata Service to access instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- OWASP Cheat Sheet Series, [Server Side Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
