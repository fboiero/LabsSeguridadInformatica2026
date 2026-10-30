# Mini-research — Laboratorio 06

**Tema elegido:** **C.** El método HTTP `PUT` y el WebDAV: cómo se pasa de
"método habilitado" a subir un webshell.

**Justificación de la elección:** elegimos este tema porque es el hallazgo de
mayor riesgo del lab —el `OPTIONS` reveló `PUT`/`DELETE` habilitados— y es el
puente directo con la fase de explotación del Lab 07.

## Desarrollo

**Qué es `PUT` y de dónde viene.** El método `PUT` está definido en el estándar
HTTP (RFC 9110, §9.3.4) y su semántica es *crear o reemplazar* el recurso ubicado
en la URI indicada con el cuerpo de la petición. En un servidor de contenido
estático sin control de acceso, un `PUT /archivo` escribe literalmente ese archivo
en el document root. `WebDAV` (RFC 4918) extiende HTTP con métodos de edición
remota (`PUT`, `DELETE`, `MKCOL`, `COPY`, `MOVE`, `PROPFIND`) para que clientes
puedan administrar archivos sobre HTTP; muchos servidores lo traen como módulo
(p. ej. `mod_dav` en Apache, el rol WebDAV en IIS) y, mal configurado, deja
escritura anónima.

**La cadena de ataque (método habilitado → webshell → RCE).**
1. **Detección.** Un `OPTIONS` al servidor devuelve la cabecera `Allow:` con los
   métodos aceptados. Si aparece `PUT` (y a veces `DELETE`), hay escritura. Es
   exactamente lo que observamos en el lab: `Allow: GET, POST, PUT, DELETE,
   OPTIONS`.
2. **Subida.** El atacante envía el payload como cuerpo de un `PUT`:
   `curl -X PUT http://victima/shell.php --data-binary @shell.php`. Si el server
   responde `201 Created` (o `200/204`), el archivo quedó escrito.
3. **Ejecución.** Si el document root ejecuta ese tipo de archivo (PHP, JSP,
   ASPX…), el atacante invoca el webshell con una petición normal
   (`GET /shell.php?cmd=id`) y obtiene **ejecución remota de comandos**. Con eso
   pasa de "puedo escribir un archivo" a "ejecuto comandos en el servidor".

**Matices y defensas.** El ataque requiere dos condiciones: que `PUT` esté
permitido *y* que el directorio donde se escribe ejecute código del lado del
servidor. Por eso una mitigación clásica es permitir escritura solo en carpetas
donde los scripts no se ejecutan, pero lo robusto es **deshabilitar los métodos de
escritura** salvo que WebDAV sea un requisito real, exigir autenticación y
restringir por carpeta. En MITRE ATT&CK esto se relaciona con
*Server Software Component: Web Shell* (T1505.003). Herramientas como `nmap
--script http-methods`, `davtest` y `cadaver` automatizan tanto la detección como
la prueba de subida.

## Fuentes (mín. 3, verificables)

1. IETF — RFC 9110, *HTTP Semantics*, §9.3.4 "PUT".
   https://www.rfc-editor.org/rfc/rfc9110#name-put
2. IETF — RFC 4918, *HTTP Extensions for Web Distributed Authoring and Versioning
   (WebDAV)*. https://www.rfc-editor.org/rfc/rfc4918
3. OWASP — *Test HTTP Methods* (WSTG-CONF-06), Web Security Testing Guide.
   https://owasp.org/www-project-web-security-testing-guide/
4. MITRE ATT&CK — T1505.003 *Server Software Component: Web Shell*.
   https://attack.mitre.org/techniques/T1505/003/

## Reflexión (3–5 líneas)

Lo que nos quedó claro es que un header aparentemente inocuo —la respuesta de un
`OPTIONS`— puede ser el inicio de un compromiso total del servidor. `PUT` no es
"peligroso" por sí solo: lo es en combinación con un directorio que ejecuta
código. Entender esa condición doble es lo que separa marcar un hallazgo de
explicar su impacto real, y también lo que orienta la defensa: no basta con
"apagar PUT", hay que pensar dónde se escribe y qué se ejecuta. Es el enlace
natural con el Lab 07.
