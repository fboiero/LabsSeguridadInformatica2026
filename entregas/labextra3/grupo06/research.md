# Research — Lab Extra 3: Defendé PhantomCorp

**Grupo:** 06
**Fecha:** 30/10/2026
**Opción elegida:** A — Guías reales de hardening web

**Declaración de uso de IA:** Codex (OpenAI), ChatGPT (OpenAI), OpenCode y Claude Code (Anthropic) se usaron como apoyo para estructurar y revisar el texto, relacionar los parches con fuentes públicas y mejorar la claridad. El grupo contrastó las fuentes, el código y las salidas de evidencia antes de incluir afirmaciones de ejecución.

## 1. Qué defensas del laboratorio aparecen en guías públicas, y con qué nombre

Las cinco defensas corregidas en `objetivo/server.py` tienen un equivalente directo en guías públicas de OWASP:

- **D4 (SQLi en `/login`):** la _SQL Injection Prevention Cheat Sheet_ de OWASP recomienda consultas parametrizadas con variables enlazadas como defensa primaria [1]. El cambio aplicado pasa de concatenar `user`/`pass` a `db.execute("... WHERE user = ? AND password = ?", (user, pwd))`, de modo que SQLite recibe valores separados de la estructura SQL.
- **D1 (banner `Server`):** reemplazar un banner que revela producto y versión reduce el _fingerprinting_. Es una medida complementaria: ocultar ese dato no corrige una vulnerabilidad explotable por sí misma [2].
- **D2 (`/api/status` con `debug:true`, rutas y PID):** publicar diagnóstico, rutas internas o información innecesaria en producción es consistente con **A05:2021 — Security Misconfiguration** [3]. El campo `debug:true` no demuestra, por sí solo, que exista un depurador interactivo accesible.
- **D3 (backup sin autorización):** entregar un recurso sensible sin un control efectivo corresponde principalmente a **A01:2021 — Broken Access Control** [4]. Que `robots.txt` publique la ruta facilita descubrirla, pero no causa ni soluciona la falta de autorización.
- **D5 (path traversal en `/descargar`):** OWASP describe esta clase de ataque como la manipulación de rutas para acceder a archivos fuera del directorio previsto [5]. La corrección debe comprobar el destino resuelto, no limitarse a filtrar la cadena literal `..`. En una aplicación con otros actores que puedan alterar enlaces simbólicos o directorios, una comprobación previa a abrir el archivo tampoco elimina por sí sola las posibles carreras; el alcance debe evaluarse según el sistema de archivos y sus permisos [10].

## 2. Un control que las guías recomiendan y el laboratorio no cubre

Un control adicional es el manejo de errores y registros. OWASP recomienda evitar que las respuestas entreguen detalles de implementación y conservar la información útil para diagnóstico en registros protegidos [6].

Es importante distinguir cliente y servidor: `socketserver`, usado por `http.server`, puede imprimir el traceback de una excepción del manejador en la salida de error del servidor; eso no implica que el traceback se envíe como cuerpo HTTP al cliente [7][8]. Tampoco existe un modo debug implícito de `http.server` que permita afirmarlo sin revisar el código.

Con la biblioteca estándar, una mejora razonable sería capturar las excepciones antes de enviar una respuesta, devolver un `500` genérico cuando todavía sea posible y registrar el detalle de manera controlada, sin contraseñas ni tokens. Si los encabezados o parte del cuerpo ya fueron enviados, no corresponde intentar una segunda respuesta. Sobrescribir `log_message()` con un método vacío solo suprime esos mensajes; no reemplaza el manejo de excepciones y puede quitar registros útiles. Python además advierte que `http.server` no está recomendado para producción [7].

## 3. Defense in depth aplicado a D3

"Defensa en profundidad" significa no depender de un único control para proteger un recurso, sino superponer varias capas independientes, de modo que si una falla las demás sigan conteniendo el riesgo. D3 lo ilustra porque `robots.txt` es una preferencia pública para rastreadores, no una frontera de seguridad ni un control de autorización [9].

El parche de D3 aplica dos capas, no una: deja de anunciar la ruta en `robots.txt` (reduce descubrimiento casual) **y** hace que `/backup` responda `404` sin importar si alguien la conoce o no (el control real). Una defensa en profundidad más completa agregaría una tercera capa independiente de la aplicación —por ejemplo, que el recurso de backup ni siquiera resida bajo el directorio que el servidor HTTP puede leer o servir— para que, aunque un futuro cambio de código reintroduzca el endpoint por error, el archivo ya no esté alcanzable desde ese proceso. Ninguna capa aislada (ocultar la ruta, bloquear la respuesta, o mover el archivo) sustituye a las otras: la combinación es lo que reduce el riesgo de que un solo error de configuración vuelva a exponer el recurso.

## 4. Pregunta de cierre — el verificador del lab frente a un escáner real (Nessus, OpenVAS, nuclei)

El `verificar-defensa.py` del laboratorio ejecuta un conjunto predefinido de solicitudes y evalúa sus respuestas. Comparte con Nuclei el uso de condiciones y plantillas, pero no debe equipararse sin matices con todos los escáneres: según la herramienta y su configuración, Nessus u OpenVAS también pueden realizar comprobaciones de versión, revisiones autenticadas u otros métodos que no explotan la vulnerabilidad [11].

Lo que un escaneo automático de este tipo **puede** demostrar es exactamente lo que este laboratorio demostró para D5: que un payload concreto, conocido de antemano, ya no produce el resultado vulnerable esperado bajo las condiciones exactas de la prueba (puerto, timing, entorno de red).

Lo que **no** puede demostrar, y que este mismo laboratorio evidenció en carne propia:

1. **Un "verde" puede ser un resultado favorable espurio.** Antes de considerar bloqueado un ataque hay que comprobar que el servidor estuvo disponible, que el archivo de control externo existía y era legible y que el rechazo provino del control de ruta. Un error de conexión o un 404 porque `/etc/passwd` no existe no prueban confinamiento. En detección de vulnerabilidades, ese error puede ocultar una vulnerabilidad existente: es un falso negativo.
2. **Un escaneo solo cubre los patrones que conoce.** El verificador prueba cinco ataques puntuales y predefinidos; no agota variantes de encoding, de payload, ni la superficie completa de la aplicación. Un escáner real tiene el mismo límite estructural: detecta lo que sus firmas/plantillas contemplan, no cualquier debilidad posible del código.
3. **No reemplaza entender ni demostrar el mecanismo de la corrección.** Una salida "5/5" certifica que cinco pruebas puntuales pasaron, no que el código sea estructuralmente correcto; es la misma razón por la que este informe exige, además del resultado del verificador, el diff del parche y una prueba de regresión funcional explicada —igual que una auditoría de seguridad real no se conforma con "el escáner no encontró nada" como única evidencia de que una aplicación es segura.

## 5. Fuentes

1. OWASP Cheat Sheet Series. _SQL Injection Prevention Cheat Sheet_. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
2. OWASP Cheat Sheet Series. _HTTP Headers Cheat Sheet_, apartado _Server_. https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server
3. OWASP. _A05:2021 – Security Misconfiguration_ (OWASP Top 10 2021). https://owasp.org/Top10/2021/A05_2021-Security_Misconfiguration/
4. OWASP. _A01:2021 – Broken Access Control_. https://owasp.org/Top10/2021/A01_2021-Broken_Access_Control/
5. OWASP. _Path Traversal_. https://owasp.org/www-community/attacks/Path_Traversal
6. OWASP. _Error Handling Cheat Sheet_. https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
7. Python Software Foundation. _http.server_. https://docs.python.org/3/library/http.server.html
8. Python Software Foundation. _socketserver_, método `handle_error`. https://docs.python.org/3/library/socketserver.html
9. IETF. _RFC 9309 — Robots Exclusion Protocol_. https://www.rfc-editor.org/rfc/rfc9309.html
10. Python Software Foundation. _os.path: realpath y commonpath_. https://docs.python.org/3/library/os.path.html
11. ProjectDiscovery. _Introduction to Nuclei Templates_. https://docs.projectdiscovery.io/templates/introduction
