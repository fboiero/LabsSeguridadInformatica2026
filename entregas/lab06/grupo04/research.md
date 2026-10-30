# Mini-research — Laboratorio 06

**Grupo:** 04
**Tema elegido:**

- [ ] **A.** Cómo un `.git` expuesto permite reconstruir el código (git-dumper) y casos reales de credenciales filtradas por esta vía.
- [ ] **B.** Wordlists de enumeración: qué son SecLists, cómo se eligen, por qué una wordlist mala hace fallar la enumeración.
- [x] **C.** El método HTTP `PUT` y el WebDAV: cómo se pasa de "método habilitado" a subir un webshell.
- [ ] **D.** Fingerprinting pasivo vs. activo: cómo `whatweb` deduce el stack.

---

## Desarrollo

### 1. Qué es `PUT` y qué es WebDAV

`PUT` es un método HTTP que le pide al servidor crear o reemplazar un recurso en la URL indicada, con el contenido que viaja en el cuerpo de la solicitud. Las aplicaciones web comunes solo necesitan `GET` y `POST`; `PUT` y `DELETE` se usan de forma legítima en servicios REST para crear y borrar objetos, y por eso la guía de pruebas de OWASP pide verificar que su uso esté limitado a usuarios de confianza y a condiciones seguras.

WebDAV (*Web Distributed Authoring and Versioning*) es una extensión de HTTP/1.1 estandarizada en el RFC 4918 (2007, reemplaza al RFC 2518 de 1999). Agrega métodos, headers y tipos de contenido para administrar propiedades de recursos, crear y gestionar colecciones (directorios), manipular el espacio de URLs y bloquear recursos para evitar colisiones. Entre sus métodos están `PROPFIND`, `MKCOL`, `COPY`, `MOVE`, `LOCK` y `UNLOCK`, y el RFC también define cómo se comportan `PUT` y `DELETE` sobre colecciones. En otras palabras, WebDAV convierte al servidor web en algo parecido a un sistema de archivos remoto, y un WebDAV mal protegido le da a un atacante esa capacidad de escritura.

### 2. De "método habilitado" a "webshell"

El camino típico tiene cuatro pasos, y cada uno puede fallar:

1. **Descubrir el método.** Un `OPTIONS` devuelve el header `Allow` con los métodos aceptados. Es lo que hicimos en el R3. OWASP aclara una limitación importante: no todos los servidores responden a `OPTIONS` y algunos devuelven información inexacta, por lo que el resultado hay que confirmarlo.
2. **Confirmar que se puede escribir.** La prueba que describe OWASP es subir un archivo inofensivo con `PUT` (por ejemplo `test.html`) y pedirlo después con `GET`. Si el servidor responde con un código 2xx o 3xx y el archivo aparece, el método está efectivamente habilitado. OWASP recomienda además borrar o avisar al equipo del objetivo cuando se deja un archivo de prueba.
3. **Lograr que el servidor ejecute lo subido.** Subir un archivo no alcanza: el servidor tiene que interpretar ese tipo de archivo. Un `.html` solo muestra contenido; un script que el servidor ejecuta (por ejemplo, una página con código del lado del servidor) permite correr comandos. Esta condición depende de la configuración del servidor y del directorio de destino.
4. **Usar la webshell.** Con el archivo ejecutable subido, el atacante lo pide por `GET` y obtiene ejecución remota de código con los privilegios del servicio web. OWASP resume el riesgo diciendo que, con `PUT`, un atacante puede colocar contenido arbitrario y potencialmente malicioso en el sistema, lo que puede llevar a ejecución remota de código, defacement o denegación de servicio.

Por eso "`PUT` habilitado" es una **condición necesaria pero no suficiente** para el RCE: el impacto depende de dónde se puede escribir y de si el servidor ejecuta lo que se sube. Esa distinción es la misma que hicimos en el Lab 05 con el CVE-2015-3306 del FTP: vulnerable por configuración, no explotado.

### 3. Un caso real: CVE-2017-12615 (Apache Tomcat)

El aviso de seguridad del proyecto Apache (19/09/2017) describe el caso: en Tomcat 7.0.0 a 7.0.79 ejecutándose en Windows con `PUT` habilitado (por ejemplo, poniendo en `false` el parámetro `readonly` del servlet por defecto), era posible subir un archivo JSP con una solicitud especialmente construida. Al pedir ese archivo, el servidor ejecutaba el código que contenía. La corrección fue actualizar a Tomcat 7.0.81 o posterior (la 7.0.80 no se publicó), y el hallazgo se atribuye a un investigador del laboratorio 360 Sg Lab.

Dos detalles muestran por qué el caso es instructivo. Primero, el `PUT` estaba deshabilitado por defecto y se habilitó por una decisión de configuración. Segundo, Tomcat ya impedía por diseño subir archivos JSP, pero una verificación insuficiente permitía eludirlo, y por eso se publicó un parche adicional bajo el identificador CVE-2017-12617, que describe la misma vulnerabilidad según el análisis de F5. La vulnerabilidad forma parte del catálogo de vulnerabilidades explotadas conocidas (KEV) de CISA, es decir que se explotó en ataques reales.

### 4. Qué vimos en PhantomCorp

La respuesta a `OPTIONS /` del Lab 06 fue:

```
HTTP/1.0 200 OK
Server: PhantomServer/3.7
Allow: GET, POST, PUT, DELETE, OPTIONS
X-Dangerous-Methods: <flag omitida>
```

Lo que esta evidencia **sostiene**: el servidor declara aceptar `PUT` y `DELETE` en la raíz. Lo que **no sostiene**: que se pueda subir un archivo ni que el servidor lo ejecute, porque no probamos ninguna escritura (el lab pide enumerar y no explotar). Además, la respuesta no incluye el header `DAV`, que el RFC 4918 define para anunciar soporte WebDAV, ni métodos como `PROPFIND` o `MKCOL` en `Allow`. Esto indica que el servidor ofrece `PUT` y `DELETE` sueltos y no un WebDAV completo, aunque la ausencia de un header no es una prueba definitiva. Con ese alcance, clasificamos el hallazgo como crítico por el riesgo que habilita, pero dejamos explícito que quedó sin verificar.

### 5. Detección y mitigación

- **Detectar:** OPTIONS manual con `curl -X OPTIONS -i`, o el script `http-methods` de nmap, que además marca los "métodos potencialmente riesgosos". OWASP advierte que estas herramientas pueden no probar los métodos peligrosos o provocar cambios en el servidor si están habilitados, por lo que hay que usarlas con cuidado.
- **Mitigar:** dejar habilitados solo los métodos que la aplicación necesita (normalmente `GET` y `POST`) y responder `405 Method Not Allowed` al resto; quitar permisos de escritura del usuario del servicio sobre el webroot; si se necesita WebDAV o una API con `PUT`, exigir autenticación y autorización. En los entornos con balanceadores o WAF, bloquear `PUT` en el perímetro es una capa adicional: F5 documenta que su WAF restringe `PUT` por defecto.
- **Cuidado con los bypass:** OWASP documenta que algunos entornos aceptan headers de sobreescritura de método (`X-HTTP-Method`, `X-HTTP-Method-Override`, `X-Method-Override`), por lo que un `405` sobre `PUT` no alcanza si el servidor acepta esos headers.

---

## Fuentes

1. IETF — **RFC 4918**, *HTTP Extensions for Web Distributed Authoring and Versioning (WebDAV)*, junio de 2007 (métodos, headers y propósito de WebDAV): https://rfc-editor.org/rfc/rfc4918.html
2. OWASP — Web Security Testing Guide, **WSTG-CONF-06: Test HTTP Methods** (descubrimiento con `OPTIONS`, prueba de `PUT`, riesgos y method overriding): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods
3. Apache Software Foundation — aviso **[SECURITY] CVE-2017-12615**, *Apache Tomcat Remote Code Execution via JSP upload* (Mark Thomas, 19/09/2017), en la lista oss-security: https://openwall.com/lists/oss-security/2017/09/19/1
4. F5 DevCentral — *Apache Tomcat Remote Code Execution via JSP upload (CVE-2017-12615 / CVE-2017-12617)* (mecánica de la subida por `PUT` y relación entre ambos CVE): https://community.f5.com/tag/cve-2017-12615
5. stack.watch — *Apache Tomcat on Windows Remote Code Execution Vulnerability* (inclusión de CVE-2017-12615 en el catálogo KEV de CISA): https://stack.watch/vuln/CVE-2017-12615/

---

## Reflexión

Este tema resume lo que nos dejó el R3: un header `Allow` con `PUT` no es todavía un ataque, pero es la condición de partida de uno. Con una sola línea de `OPTIONS` pudimos clasificar el servidor como crítico sin escribir nada, y a la vez descubrimos qué no podíamos afirmar: si se puede subir un archivo y si el servidor lo ejecuta. El caso de Tomcat nos mostró que un método peligroso habilitado por configuración y una verificación insuficiente son suficientes para llegar a ejecución remota. También aprendimos a leer lo que falta en la respuesta, como el header `DAV`, para no suponer que hay un WebDAV cuando solo vimos `PUT` y `DELETE` sueltos. La lección para la defensa es limitar los métodos a los necesarios y no dar permisos de escritura sobre lo que se publica.