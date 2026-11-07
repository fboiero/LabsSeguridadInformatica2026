# Research — Lab Extra 5: JWT inseguro

**Responsable:** Belén · **Opción elegida:** B — JWT bien hecho

## Opción B — JWT bien hecho

### 1. Claims de validación (`exp`, `iss`, `aud`, `nbf`)

`exp` y `nbf` vienen del RFC 7519 base: `exp` "identifica el momento de expiración en o después del cual el JWT NO DEBE ser aceptado", y el receptor debe verificar que la hora actual sea anterior; `nbf` es su espejo, exige que sea posterior [1]. Los dos son opcionales en la especificación — un emisor puede omitirlos sin romper el formato. Sin `exp`, un token robado o forjado (como el nuestro, con `iat`/`exp` copiados para no caducar durante la corrida) queda utilizable indefinidamente.

`iss` y `aud` están endurecidos en el RFC 8725: la aplicación "DEBE validar que las claves usadas pertenecen al emisor" y "DEBE rechazar" si no es así [2]; sobre `aud`, el receptor "DEBE rechazar el JWT" si su identificador no está en esa lista [2]. Sin esos controles, un token emitido para un servicio puede reutilizarse en otro que confíe en el mismo emisor: el RFC lo llama ataque de sustitución, que "puede resultar en que el atacante obtenga acceso a recursos a los que no tiene derecho" [2]. OWASP agrega una advertencia operativa, válida para cualquier biblioteca: "un token solo se verifica contra un emisor y una audiencia esperados cuando esos argumentos se pasan" [3] — tener la librería no alcanza si no se configura.

### 2. RS256/EdDSA vs HS256 en microservicios

Con HS256 (simétrico), la misma clave firma y verifica. El RFC 8725 es tajante: "las claves memorizables por humanos NO DEBEN usarse como clave de un MAC como HS256" [2] — justo lo que permitió crackear `mate123` y forjar tokens con el secreto del servidor. En microservicios eso implica que **cualquier servicio que solo necesite verificar también podría firmar**, porque comparte el mismo secreto. OWASP lo plantea como gestión de credenciales: con clave pública "el verificador solo necesita información pública"; con MAC, "cada par (emisor, audiencia) necesita su propio secreto, y los secretos deben distribuirse y rotarse" [3]. Con un esquema asimétrico (OWASP recomienda hoy ES256/384/512 o PS256/384/512 por sobre RS256 clásico [3]), un microservicio de solo lectura nunca puede firmar: solo tiene la clave pública. La diferencia de velocidad entre ambos esquemas "suele ser despreciable en la práctica" [3], así que la ventaja de aislar quién puede firmar pesa más.

### 3. Por qué "guardá el JWT en localStorage" es discutido

OWASP lo dice sin matices: "No almacenar identificadores de sesión en local storage, ya que esos datos son siempre accesibles por JavaScript"; un solo XSS "puede usarse para robar todos los datos" ahí guardados [4]. Una cookie `httpOnly` cierra esa puerta puntual, porque JavaScript no puede leerla [4]. Pero eso traslada el riesgo a CSRF (la cookie se envía sola en cada solicitud), por lo que OWASP trata el token anti-CSRF como "esencial" junto a cookies [5]. La discusión no tiene ganador absoluto porque, como dice la propia guía de CSRF, "XSS puede derrotar todas las técnicas de mitigación de CSRF" [5]: si ya hay XSS, el atacante ejecuta la solicitud sensible él mismo, sin necesidad de robar el token. La elección de almacenamiento decide contra qué ataque queda expuesto el token si XSS falla, no si el sistema es seguro en general.

## Pregunta de cierre (obligatoria)

**No, el problema no queda resuelto.** Rotar a un secreto de 32 bytes aleatorios corrige el fallo de R2 — un secreto de alta entropía deja de ser crackeable por diccionario — pero no toca R1 en absoluto, porque son fallos de capas distintas. R1 (`FLAG{jwt_solo_base64}`) demuestra que el payload de un JWT **no está cifrado**: es JSON en Base64url, legible sin ninguna clave, *por diseño* del formato JWS que usa este lab — la firma protege integridad (que nadie lo altere sin ser detectado), no confidencialidad (que nadie lo lea). Cambiar el secreto de firma no cambia esa codificación: cualquiera con el token en la mano sigue pudiendo decodificar `nota_interna: "deploy-tag FLAG{jwt_solo_base64}"`, igual que en la sección 1 del informe, tenga o no la clave de firma.

R2 es un problema de verificación (¿puedo forjar un token que el servidor acepte?); R1 es de exposición de contenido (¿puedo leer lo que ya hay adentro, sin forjar nada?). Mientras PhantomCorp siga metiendo datos sensibles en el payload, esos datos van a seguir viajando legibles. La solución para R1 no es un secreto más fuerte: es no poner información sensible sin cifrar en el payload, o usar JWE si el caso de uso realmente necesita confidencialidad.

## Fuentes consultadas

1. **[PRIMARIA]** Jones, M., Bradley, J., & Sakimura, N. (2015, mayo). *JSON Web Token (JWT)* (RFC 7519, §§4.1.4–4.1.5). RFC Editor. https://www.rfc-editor.org/rfc/rfc7519 — Definición y validación de `exp` y `nbf`.
2. **[PRIMARIA]** Sheffer, Y., Hardt, D., & Jones, M. (2020, febrero). *JSON Web Token Best Current Practices* (RFC 8725, §§2.1, 2.7–2.8, 3.1, 3.5, 3.8–3.9). RFC Editor. https://www.rfc-editor.org/rfc/rfc8725 — Validación de `iss`/`aud`, ataques de sustitución, prohibición de usar contraseñas memorizables como clave HMAC.
3. **[PRIMARIA]** OWASP Foundation. (s. f.). *JSON Web Token Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html — Gestión de claves simétricas vs. asimétricas, algoritmos recomendados.
4. **[PRIMARIA]** OWASP Foundation. (s. f.). *HTML5 Security Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html — No guardar identificadores de sesión en `localStorage`; mitigación con cookies `httpOnly`.
5. **[PRIMARIA]** OWASP Foundation. (s. f.). *Cross-Site Request Forgery Prevention Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html — Token anti-CSRF esencial en autenticación por cookies; XSS derrota cualquier mitigación de CSRF.

## Declaración de uso de IA
