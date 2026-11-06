# Mini-investigación — Lab Extra 3: Defendé PhantomCorp

## Opción A — Guías de hardening web de OWASP

Para relacionar las defensas del laboratorio con prácticas de desarrollo seguro, se consultaron fichas de OWASP sobre encabezados HTTP, autorización y prevención de SQL injection, junto con el OWASP Web Security Testing Guide (WSTG). Estas guías ayudan a separar controles que reducen exposición de los que realmente impiden una operación no autorizada.

### 1. ¿Qué defensas del laboratorio aparecen en las guías?

**D1, banner del servidor.** La ficha de [encabezados HTTP de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) recomienda quitar el encabezado `Server` o asignarle un valor no informativo. Aclara que esto no impide toda identificación: otras respuestas pueden revelar la tecnología. Por eso, neutralizar el banner reduce una pista, pero no reemplaza el hardening de los componentes.

**D2, endpoint de debug.** La [ficha de autorización transaccional de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html) incluye como práctica evitar funciones de depuración en código de producción; la [ficha de autorización](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) recomienda denegar por defecto. En el laboratorio, deshabilitar `/api/status` evita exponer rutas, PID y estado interno a cualquier visitante.

**D3, `/robots.txt` y `/backup`.** La [ficha de autorización de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) recomienda “deny by default” y validar los permisos en cada solicitud. `robots.txt` solo comunica instrucciones a rastreadores que deciden respetarlas; no controla quién puede pedir una URL. La defensa efectiva tiene que estar en el servidor que atiende `/backup`: denegar por defecto o permitir solo a usuarios autorizados.

**D4, SQL injection.** La ficha de [prevención de SQL injection de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet) recomienda sentencias preparadas con consultas parametrizadas: la estructura SQL se define por separado y los valores se enlazan como datos. La ficha desaconseja el escape manual como sustituto de la parametrización. En este laboratorio, `user` y `pass` se pasan a SQLite con `?` y una tupla; no se concatenan a la consulta.

**D5, traversal.** El [WSTG de OWASP](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include/) explica que una ruta construida con parámetros no confiables puede permitir leer archivos fuera del directorio previsto, y recomienda probar variantes codificadas. El parche resuelve la ruta canónica y verifica que quede bajo la raíz de descargas antes de leerla; revisar únicamente si el texto contiene `..` no cubriría todas las representaciones posibles.

### 2. Control adicional no cubierto y aplicación

Un control complementario es Content Security Policy (CSP), que limita los orígenes de scripts y otros recursos que el navegador puede cargar. La ficha de [encabezados HTTP de OWASP](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) la presenta como una capa adicional para mitigar ciertos ataques de contenido, y señala que debe adaptarse a los recursos reales del sitio.

En esta aplicación de Python estándar se podría centralizar el encabezado en `_send`:

```python
self.send_header(
    "Content-Security-Policy",
    "default-src 'self'; object-src 'none'; base-uri 'self'",
)
```

La política debe comprobarse con las páginas reales antes de desplegarla: una política demasiado estricta puede bloquear recursos legítimos. CSP actúa en el navegador; no corrige el SQL, no autoriza `/backup` y no confina las rutas del sistema de archivos, por lo que no sustituye D1–D5.

### 3. Defense in depth aplicada a D3

Defense in depth consiste en usar controles complementarios, para que una sola omisión no deje el recurso expuesto. En D3, quitar `/backup` de `robots.txt` reduce su descubrimiento casual, pero no protege el contenido. El servidor debe denegar el acceso por defecto y comprobar autorización en cada solicitud. Si se retira el recurso, `/backup` puede devolver 404; si la aplicación lo necesita, debe exigir permisos antes de servirlo. La evidencia del laboratorio confirma ambas cosas separadas: `robots.txt` no nombra la ruta y una solicitud directa recibe 404.

### Pregunta de cierre — ¿Qué demuestra un verificador automático?

El verificador del laboratorio se parece a una prueba dinámica acotada: envía un conjunto fijo de solicitudes y comprueba si las respuestas cumplen condiciones conocidas. Es útil para repetir pruebas, encontrar regresiones y confirmar casos concretos —por ejemplo, los bypass SQLi del enunciado—. No demuestra que no haya otras rutas, codificaciones, flujos de negocio o combinaciones que no probó. Tampoco reemplaza revisar el código y confirmar el contexto de los hallazgos. La [introducción al WSTG](https://wstg.owasp.org/latest/2-Introduction/) recomienda combinar herramientas automáticas con análisis manual dirigido y revisión de código. La diferencia entre la ruta `/etc/passwd` de Unix y la ubicación de archivos en Windows también muestra que el resultado de un escaneo depende del sistema y de los casos de prueba disponibles.

## Fuentes

- OWASP, [HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
- OWASP, [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) y [Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html).
- OWASP, [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet).
- OWASP, [Web Security Testing Guide: Directory Traversal / File Include](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/01-Testing_Directory_Traversal_File_Include/) e [Introduction](https://wstg.owasp.org/latest/2-Introduction/).
