# Research — Lab Extra 5: JWT inseguro (Opción — vulnerabilidades reales de JWT)

**Grupo:** 14 · **Declaración de uso de IA:** usamos IA para redactar y resumir;
contrastado con la RFC 7519/7518 y guías de OWASP.

## 1. `alg: none` y confusión de algoritmos
El ataque histórico más conocido: la librería confía en el campo `alg` del
header. Con `alg:none` y firma vacía, algunos verificadores aceptan el token sin
validar nada. La variante RS256→HS256 abusa de que la **clave pública** (conocida)
se use como secreto HMAC. Defensa: el servidor **fija** el algoritmo esperado y
jamás deja que el header lo elija.

## 2. Secreto débil / crackeable offline
Como en este lab: si el secreto HS256 es una palabra de diccionario, se crackea
sin tocar el servidor (herramientas como `jwt_tool`, hashcat modo 16500, jwt_tool
de ticarpi). Defensa: secreto aleatorio de ≥256 bits gestionado en un vault.

## 3. Falta de validación de claims
No validar `exp`/`nbf`/`aud`/`iss`, o confiar en `sub`/`role` para autorizar
acceso a datos de otros (IDOR). Defensa: validar todos los claims temporales y
de audiencia, y hacer control de acceso real del lado servidor.

## Cierre
JWT no es malo per se: los incidentes vienen de implementación (confiar en `alg`,
secretos débiles, claims sin validar) y de usarlo como si cifrara. Para datos
sensibles, o se usa JWE (cifrado) o directamente no viajan en el token.
