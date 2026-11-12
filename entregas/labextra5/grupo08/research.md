# Research — Lab Extra 5: JWT inseguro

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919

**Declaración de uso de IA:** Sí. Claude (Anthropic), vía Claude Code, asistió en la redacción y en organizar las fuentes. El grupo leyó las referencias citadas, verificó cada afirmación contra ellas y puede explicar y defender el contenido. Las fuentes están al pie.

> Opción elegida: **A — El catálogo de ataques a JWT.** La elegimos porque
> extiende directamente la P4 de nuestro informe (`alg:none`), donde ya vimos
> que el objetivo es inmune por accidente y no por diseño.

---

## 1. `alg:none` y confusión de algoritmo

**`alg:none`.** El header de un JWT declara el algoritmo de firma. El valor
especial `none` significa "token sin firmar": su definición normativa está en
el **RFC 7518 §3.6** (JWA), que exige firma vacía y que las implementaciones
**no** acepten JWS sin asegurar por defecto; el RFC 7519 §6 lo enmarca como
"Unsecured JWT" para casos donde la integridad ya está garantizada por otro
canal. Fue un error de diseño de usabilidad: una librería que lee el `alg` del token y, al ver `none`,
**salta la verificación**, acepta cualquier payload con la firma borrada. El
atacante arma `{"alg":"none"}`, pone `role:admin`, deja la tercera parte vacía y
entra.

- **Condición que lo habilita:** que la librería decida si verificar según el
  `alg` que viene en el token, y que `none` esté en la lista aceptada.
- **Defensa:** pinnear el algoritmo del lado del servidor
  (`algorithms=["HS256"]` / `["RS256"]`) y nunca aceptar `none` en producción.
  En nuestro lab el objetivo es inmune porque su `verificar()` cablea
  HMAC-SHA256 e **ignora** el header `alg` (informe, P4): una firma vacía nunca
  iguala al HMAC recalculado.

**Confusión de algoritmo (RS256 → HS256).** Es el ataque más interesante y
aplica cuando el servidor usa un algoritmo **asimétrico** (RS256: clave privada
firma, clave pública verifica). El atacante toma un token, cambia el header a
`{"alg":"HS256"}` y lo firma con **HMAC usando la clave pública RSA como si
fuera el secreto**. Si la librería, al ver `HS256`, verifica el HMAC con la
clave que tiene cargada (la pública), la verificación pasa: la clave pública es
conocida, así que el atacante firmó un token válido sin tener la privada.

- **Condición que lo habilita:** que el server acepte el `alg` del token y que
  use la misma variable de "clave" para ambos algoritmos (la pública como clave
  de verificación HMAC).
- **Defensa:** igual que arriba — pinnear el algoritmo. Si el server solo acepta
  RS256, un token HS256 se rechaza antes de verificar nada.

## 2. Inyección por `kid`, y `jku` / `x5u`

Estos headers le dicen al server **qué clave** usar para verificar. Son punteros
a la clave, controlados por el atacante.

- **`kid` (key id).** Identifica la clave dentro de un conjunto. Si el server lo
  usa sin sanitizar, se convierte en una inyección clásica:
  - **Path traversal:** `kid: "../../dev/null"` hace que el server lea un archivo
    de contenido predecible (o vacío) como clave; el atacante firma con ese
    contenido. Es el traversal del Lab Extra 3, ahora apuntando a la clave.
  - **SQLi:** si la clave se busca en una base con `kid` concatenado, un
    `kid` con `UNION SELECT` devuelve una clave controlada por el atacante.
- **`jku` / `x5u` (JWK/X.509 Set URL).** Apuntan a una **URL** desde donde el
  server baja la clave pública. Si el server confía en cualquier URL, el
  atacante aloja su propia clave y pone `jku: https://atacante/claves.json`: el
  server verifica con la clave del atacante. Es un SSRF + confianza mal puesta
  (SSRF lo vimos en el Lab Extra 1).
- **Condición que los habilita:** usar el valor del header como fuente de la
  clave sin validación.
- **Defensa:** no resolver claves por datos del token; usar un conjunto de claves
  fijo del lado del server, y si se usa `jku`, una allowlist estricta de dominios.

## Pregunta de cierre (obligatoria)

**El secreto pasa a 32 bytes aleatorios, pero siguen metiendo datos sensibles en
el payload. ¿El problema quedó resuelto?**

No. Quedó resuelto **la mitad**, y es exactamente la distancia entre R2 y R1 de
nuestro lab.

- **R2/R3 (forja) sí se resuelven.** Dependen de crackear el secreto para
  **escribir** un token válido. Con 32 bytes aleatorios el crack por diccionario
  y por fuerza bruta es inviable (2^256), así que nadie puede forjar `role:admin`
  ni `sub:maria`. El atacante pierde la capacidad de **firmar**.
- **R1 (lectura) NO se resuelve.** R1 no necesita firmar nada: el payload es
  base64url, texto plano reversible, y la firma solo da **integridad**, nunca
  **confidencialidad** (informe, P1). Un secreto fortísimo protege contra
  modificar el token, pero cualquiera con el token sigue **leyendo**
  `nota_interna` con `base64 -d`.

Son dos propiedades distintas atacadas por dos retos distintos. Rotar el secreto
sube el muro contra la forja y deja la ventana de la lectura abierta de par en
par. La defensa de R1 es otra —**no poner secretos en el payload** (claims
mínimos)— y, si el dato tiene que viajar protegido de lectura, cifrarlo: un JWE
(JWT cifrado), no un JWS (JWT firmado). "Firmado" nunca fue "secreto".

---

## Fuentes

- IETF **RFC 8725** — *JSON Web Token Best Current Practices* (2020):
  https://www.rfc-editor.org/rfc/rfc8725 — recomienda pinnear algoritmos,
  prohibir `none` en verificación, y validar `alg` contra una lista fija.
- IETF **RFC 7518 §3.6** — *JSON Web Algorithms (JWA)*, "Using the Algorithm
  `none`": https://www.rfc-editor.org/rfc/rfc7518#section-3.6 — define la firma
  vacía y el "MUST NOT accept by default".
- IETF **RFC 7519 §6** — *JSON Web Token (JWT)*, "Unsecured JWTs":
  https://www.rfc-editor.org/rfc/rfc7519#section-6
- **OWASP** — *JSON Web Token for Java / JWT Cheat Sheet*:
  https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- **PortSwigger Web Security Academy** — *JWT attacks* (`alg:none`, algorithm
  confusion, `kid`, `jku`/`x5u`):
  https://portswigger.net/web-security/jwt
- **Auth0** — *Critical vulnerabilities in JSON Web Token libraries* (el caso
  original de confusión de algoritmo RS256→HS256, 2015):
  https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
