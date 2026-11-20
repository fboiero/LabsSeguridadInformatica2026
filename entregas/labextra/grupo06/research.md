# Research — Laboratorio Extra SSRF

**Grupo:** 06
**Fecha del trabajo:** 2026-10-29
**Opción elegida:** A — Caso real: Capital One, 2019

## 1. El incidente y la cadena SSRF

En 2019, Capital One informó una intrusión que afectó a unos 100 millones de personas en Estados Unidos y seis millones en Canadá. La empresa sitúa el acceso a los datos el 22 y 23 de marzo; un aviso externo llegó el 17 de julio y la investigación confirmó el incidente el 19 de julio [1].

La página del caso del Departamento de Justicia describe una entrada mediante un firewall de aplicaciones web mal configurado. También indica que una persona que vio evidencia en GitHub alertó a Capital One el 17 de julio y que la empresa contactó al FBI después de confirmar la intrusión el día 19 [2]. Esto no equivale a afirmar que quien dio el aviso publicara una denuncia en GitHub.

Los datos afectados incluían información de solicitudes de tarjetas y, para parte de las personas, números de identificación o cuentas bancarias. Capital One indicó que no se comprometieron contraseñas de acceso ni números de cuentas de tarjetas de crédito [1].

La reconstrucción técnica publicada por KrebsOnSecurity atribuye el acceso inicial a una mala configuración de un WAF basado en ModSecurity. Según esa reconstrucción, se indujo al componente a consultar el servicio de metadatos de EC2 y se obtuvieron credenciales temporales del rol asociado a la instancia, utilizadas después para acceder a datos de S3 [3].

Conviene separar esa explicación de los hechos que confirma directamente la página judicial: esta última menciona el firewall mal configurado y el robo de datos, pero no documenta por sí sola cada detalle de implementación de ModSecurity ni el payload exacto. El caso no debe presentarse como una vulnerabilidad demostrada de cualquier instalación de ModSecurity.

El mecanismo descrito es consistente con SSRF: una entrada externa influye en solicitudes que realiza el servidor desde su posición de red. En EC2, el servicio de metadatos puede proporcionar credenciales temporales del rol de la instancia. La dirección IPv4 habitual es 169.254.169.254, un destino link-local, no un servicio público accesible de la misma forma desde Internet [4]. Una credencial temporal no da acceso ilimitado a AWS: sus posibilidades dependen de las políticas y restricciones aplicables al rol.

El paralelo con PhantomCorp es el uso de un intermediario. En el laboratorio, /preview permitió recuperar el panel local y contenido de intranet según las evidencias del grupo. En la reconstrucción de Capital One, el intermediario permitió alcanzar metadatos y después usar permisos cloud. El laboratorio no demuestra robo de credenciales IAM ni reproduce toda la cadena del incidente real.

## 2. Controles que reducen el riesgo

La defensa comienza por limitar qué destinos necesita consultar el componente. OWASP recomienda controles tanto en la aplicación como en la red, además de considerar la resolución DNS y las redirecciones [5].

Separar la función de consulta de los componentes con acceso interno reduce las rutas que puede aprovechar una SSRF. En cloud también conviene limitar o deshabilitar el acceso a metadatos cuando no sea necesario y asignar al rol únicamente los permisos requeridos. Reducir permisos de S3 habría limitado el acceso a esos datos; no habría corregido la SSRF ni vuelto inocua cualquier credencial filtrada.

Los controles deben aplicarse en una capa que realmente vea el tráfico. No debe asumirse que un firewall perimetral o una regla de red cloud bloquea automáticamente el loopback o el servicio de metadatos de la propia instancia.

### IMDSv2: protección posterior al incidente

IMDSv2 fue anunciado en noviembre de 2019, después de la intrusión de marzo y de su divulgación en julio. Por eso corresponde presentarlo como una medida posterior de defensa, no como una opción que Capital One omitió configurar antes de ese ataque [6].

El mecanismo utiliza sesiones con token: primero se realiza un PUT para obtenerlo y luego se incorpora en un encabezado de las consultas de metadatos. Para impedir que continúen funcionando consultas de IMDSv1 sin token hay que configurar la instancia para exigir IMDSv2 [4].

Esto dificulta una SSRF que solo permita reenviar un GET sin controlar encabezados. No elimina todas las SSRF: el resultado depende de si la vulnerabilidad permite completar el intercambio necesario. El límite de saltos para la respuesta al PUT que entrega el token no es un contador general de redirecciones HTTP [4].

## 3. SSRF e inyección de comandos

En ambos casos, una entrada no confiable influye en una acción ejecutada por el servidor. La diferencia está en la capacidad que se controla.

| Aspecto | SSRF | Inyección de comandos del sistema operativo |
|---|---|---|
| Acción controlada | Solicitudes hacia destinos elegidos o manipulados | Ejecución de comandos o argumentos interpretados de forma insegura |
| Límites relevantes | Protocolos, métodos, encabezados, redirecciones y destinos disponibles | Contexto de ejecución, comandos alcanzables, permisos y aislamiento |
| Impacto posible | Lectura de datos, acciones en servicios internos, obtención de credenciales o cadenas posteriores | Lectura o modificación de archivos, ejecución de procesos y otras acciones permitidas al proceso |

Una SSRF no se limita a leer páginas: una solicitud puede cambiar estado o alcanzar un servicio vulnerable. A su vez, detectar una inyección de comandos no demuestra automáticamente control total del host. Los permisos y el aislamiento siguen limitando el alcance.

Con ejecución arbitraria suficientemente amplia normalmente se dispone de más capacidades que con una SSRF restringida. Pero no existe una clasificación universal de riesgo por el nombre de la vulnerabilidad: una SSRF que expone credenciales de gran alcance puede causar más daño que una inyección de comandos dentro de un entorno fuertemente aislado.

En PhantomCorp, el resultado observado fue lectura de recursos internos. No se documentó ejecución de código, escritura ni control del host. El caso Capital One muestra por qué esa misma clase de acceso puede tener otras consecuencias cuando permite obtener credenciales cloud.

## Fuentes

1. Capital One. [Información oficial sobre el incidente de 2019](https://www.capitalone.com/digital/facts2019/).
2. U.S. Attorney’s Office, Western District of Washington. [United States v. Paige Thompson](https://www.justice.gov/usao-wdwa/united-states-v-paige-thompson).
3. Brian Krebs. [What We Can Learn from the Capital One Hack](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/). Fuente secundaria para la reconstrucción técnica, no un informe forense oficial completo.
4. AWS. [How Instance Metadata Service Version 2 works](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html).
5. OWASP. [Server-Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
6. AWS. [Add defense in depth against open firewalls, reverse proxies, and SSRF vulnerabilities with enhancements to the EC2 Instance Metadata Service](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/).

## Declaración de uso de IA y verificación

Codex asistió en la ejecución y documentación de R1 y R3; ChatGPT, en el análisis cloud y P5; Claude Code, en P4 y la redacción inicial del research; y OpenCode, en R2 y P2. El grupo contrastó el código del laboratorio, las salidas crudas y las fuentes antes de incorporar afirmaciones al informe.

En esta revisión se mejoró la redacción y se separaron los hechos documentados, la reconstrucción técnica del incidente y los resultados observados en PhantomCorp. Se verificaron las páginas de Capital One, el Departamento de Justicia, Krebs y AWS citadas. No se realizaron pruebas contra Capital One, AWS ni servicios de metadatos reales.
