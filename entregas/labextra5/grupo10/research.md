# Research — Lab Extra 5: JWT inseguro

**Responsable:** Belén · **Opción elegida:** B — JWT bien hecho

## Opción B — JWT bien hecho

### 1. Claims de validación (`exp`, `iss`, `aud`, `nbf`)

`exp` y `nbf` vienen del RFC 7519 base: `exp` "identifica el momento de expiración en o después del cual el JWT NO DEBE ser aceptado", y el receptor debe verificar que la hora actual sea anterior; `nbf` exige que sea posterior o igual al instante indicado [1]. Los dos son opcionales en el formato general, pero el perfil de la aplicación puede exigirlos. Si no se exige `exp` ni hay otro mecanismo de caducidad o revocación, un token robado podría reutilizarse indefinidamente. **No es el comportamiento de este portal:** `verificar()` usa `payload.get("exp", 0)` y rechaza un token sin ese claim. Nuestras forjas incluyen una hora de vigencia. Sin validar `nbf`, una aplicación podría aceptar un token antes de su inicio de validez; este portal no verifica ese claim.

`iss` y `aud` están endurecidos en el RFC 8725: cuando el JWT contiene `iss`, la aplicación "DEBE validar que las claves usadas pertenecen al emisor" y rechazarlo si no es así [2]. Si el emisor genera JWT para más de una aplicación, el RFC exige `aud` y que el receptor rechace el token si falta su audiencia o no lo incluye [2]. El perfil debe exigir los claims que necesite, no tratarlos como obligatorios universales del formato. Sin esos controles, un token emitido para un servicio puede reutilizarse en otro que confíe en el mismo emisor: es un ataque de sustitución [2]. OWASP advierte, en su ejemplo específico de PyJWT, que comprobar los valores esperados requiere pasar `issuer` y `audience` [3]; cada biblioteca tiene su propia configuración. El portal de este lab no emite ni valida `iss`/`aud`, por lo que no se demostró aquí un ataque entre emisores o servicios.

### 2. RS256/EdDSA vs HS256 en microservicios

Con HS256 (simétrico), la misma clave firma y verifica. El RFC 8725 es tajante: "las claves memorizables por humanos NO DEBEN usarse como clave de un MAC como HS256" [2] — justo lo que permitió crackear `mate123` y forjar tokens con el secreto del servidor. En microservicios eso implica que **cualquier servicio que solo necesite verificar también podría firmar**, porque comparte el mismo secreto. OWASP lo plantea como gestión de credenciales: con clave pública "el verificador solo necesita información pública"; con MAC, "cada par (emisor, audiencia) necesita su propio secreto, y los secretos deben distribuirse y rotarse" [3]. Con un esquema asimétrico (OWASP recomienda hoy ES256/384/512 o PS256/384/512 por sobre RS256 clásico [3]), un microservicio de solo lectura nunca puede firmar: solo tiene la clave pública. La diferencia de velocidad entre ambos esquemas "suele ser despreciable en la práctica" [3], así que la ventaja de aislar quién puede firmar pesa más.

### 3. Por qué "guardá el JWT en localStorage" es discutido

OWASP lo dice sin matices: "No almacenar identificadores de sesión en local storage, ya que esos datos son siempre accesibles por JavaScript"; un solo XSS "puede usarse para robar todos los datos" ahí guardados [4]. Una cookie `HttpOnly` impide su lectura directa desde JavaScript, pero no evita que un XSS realice solicitudes autenticadas [4]. Como las cookies se envían automáticamente en las solicitudes que cumplen sus restricciones, requieren defensas CSRF apropiadas: `SameSite`, validación de origen y tokens anti-CSRF según el flujo [5]. La guía advierte que "XSS puede derrotar todas las técnicas de mitigación de CSRF" [5]: el atacante puede ejecutar la acción sensible desde el mismo origen sin robar el token. Hay que prevenir XSS en ambos diseños; `HttpOnly` limita la extracción del token y las defensas CSRF protegen frente a solicitudes inducidas desde otros sitios, no frente a código malicioso que ya corre en el origen.

## Pregunta de cierre (obligatoria)

**No, el problema no queda resuelto.** Rotar a un secreto de 32 bytes aleatorios corrige el fallo de R2 — un secreto de alta entropía deja de ser crackeable por diccionario — pero no toca R1 en absoluto, porque son fallos de capas distintas. R1 (`FLAG{jwt_solo_base64}`) demuestra que el payload de un JWT **no está cifrado**: es JSON en Base64url, legible sin ninguna clave, _por diseño_ del formato JWS que usa este lab — la firma protege integridad (que nadie lo altere sin ser detectado), no confidencialidad (que nadie lo lea). Cambiar el secreto de firma no cambia esa codificación: cualquiera con el token en la mano sigue pudiendo decodificar `nota_interna: "deploy-tag FLAG{jwt_solo_base64}"`, igual que en la sección 1 del informe, tenga o no la clave de firma.

R2 es un problema de verificación (¿puedo forjar un token que el servidor acepte?); R1 es de exposición de contenido (¿puedo leer lo que ya hay adentro, sin forjar nada?). Mientras PhantomCorp siga metiendo datos sensibles en el payload, esos datos van a seguir viajando legibles. La solución para R1 no es un secreto más fuerte: es no poner información sensible sin cifrar en el payload, o usar JWE si el caso de uso realmente necesita confidencialidad.

## Fuentes consultadas

1. **[PRIMARIA]** Jones, M., Bradley, J., & Sakimura, N. (2015, mayo). _JSON Web Token (JWT)_ (RFC 7519, §§4.1.4–4.1.5). RFC Editor. https://www.rfc-editor.org/rfc/rfc7519 — Definición y validación de `exp` y `nbf`.
2. **[PRIMARIA]** Sheffer, Y., Hardt, D., & Jones, M. (2020, febrero). _JSON Web Token Best Current Practices_ (RFC 8725, §§2.1, 2.7–2.8, 3.1, 3.5, 3.8–3.9). RFC Editor. https://www.rfc-editor.org/rfc/rfc8725 — Validación de `iss`/`aud`, ataques de sustitución, prohibición de usar contraseñas memorizables como clave HMAC.
3. **[PRIMARIA]** OWASP Foundation. (s. f.). _JSON Web Token Cheat Sheet_. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html — Gestión de claves simétricas vs. asimétricas, algoritmos recomendados.
4. **[PRIMARIA]** OWASP Foundation. (s. f.). _HTML5 Security Cheat Sheet_. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html — No guardar identificadores de sesión en `localStorage`; mitigación con cookies `httpOnly`.
5. **[PRIMARIA]** OWASP Foundation. (s. f.). _Cross-Site Request Forgery Prevention Cheat Sheet_. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — Token anti-CSRF esencial en autenticación por cookies; XSS derrota cualquier mitigación de CSRF.

## Declaración de uso de IA

Se utilizó OpenCode (GPT-6 Luna) para revisar la consistencia técnica de esta investigación con las fuentes citadas. La herramienta también asistió en la edición de la redacción.
