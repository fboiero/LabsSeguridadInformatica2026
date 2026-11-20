# Entregable — Lab Extra 5: JWT inseguro

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero
(@Ferca19), Guadalupe Gómez (@guadagomezgg8) y Lautaro Mariño
(@lautaromarino0) · **Fecha:** 19/11/2026 (America/Buenos_Aires)

## Declaración de uso de IA

Fernando Cagliero (@Ferca19) usó OpenAI Codex para inspeccionar el flujo local
de `/perfil`, contrastar P3/P5 con el caso del laboratorio y redactar estas
respuestas. Las conclusiones se apoyan en el código adjunto como referencia y
en RFC 7519, RFC 8725 y OWASP API Security. No se presenta evidencia de login,
cracking, forja, respuestas HTTP ni flags que no se hayan ejecutado/capturado
en este bloque.

## 1. Anatomía del token real

Pendiente del bloque que ejecutó el login. No se incluye token ni payload sin
una salida observada.

## 2. Crack offline del secreto

Pendiente del bloque que ejecutó el crack. No se declara secreto, cantidad de
candidatos ni duración sin evidencia local.

## 3. Las dos forjas

Las forjas y respuestas operativas R2/R3 quedan pendientes de integración con
el bloque que ejecutó el cliente del laboratorio.

### R2 — Escalada vertical (role=admin)

Pendiente de evidencia del token y respuesta HTTP.

### R3 — Suplantación horizontal (sub=maria)

Pendiente de evidencia del token y respuesta HTTP.

## 4. Control de sanidad

Pendiente de las respuestas capturadas para el token original y la firma
alterada.

## 5. Preguntas P1–P5

**P1:** pendiente del bloque asignado.

**P2:** pendiente del bloque asignado.

**P3 — por qué R3 es IDOR/BOLA aunque no haya `?id=`.** El parámetro que elige
el objeto no tiene que estar en la URL: en este servidor `/perfil` toma
`payload["sub"]` del JWT y lo usa directamente para buscar el registro y
devolver sus datos. Por eso la identidad/objeto solicitado viaja en el claim.
Como el secreto débil permite a un cliente fabricar una firma aceptada para
`sub=maria`, el servidor no vuelve a comprobar que esa identidad corresponde
al principal autenticado ni que ese principal esté autorizado para ese objeto.
Cambiar el identificador de objeto en el token produce el acceso horizontal,
la misma falla de autorización a nivel de objeto que un `?id=` manipulable.
La defensa es validar firma, emisor, audiencia y sujeto, derivar el principal
de una identidad confiable y comprobar autorización por objeto en el servidor
en cada solicitud. OWASP describe este tipo de fallo como BOLA/API1; RFC 8725
recomienda validar los claims de sujeto y audiencia.

**P4:** pendiente del bloque asignado. En este aporte no se probó `alg:none`.

**P5 — defensas priorizadas.**

1. **Secreto de alta entropía.** Para HS256 usar una clave aleatoria de al
   menos 256 bits, generada por CSPRNG y guardada en un gestor de secretos; no
   una palabra o contraseña humana. Esto hace inviable el diccionario offline
   de R2. RFC 8725 §3.5 exige entropía suficiente para claves simétricas.
2. **Algoritmo permitido fijado por configuración.** La biblioteca debe aceptar
   solo el algoritmo previsto por el servidor y rechazar `none` y confusión
   entre algoritmos/tipos de clave. No se debe elegir la verificación según el
   valor no confiable del header `alg`. Esto bloquea la clase de bypass de P4.
   (RFC 8725 §3.1.)
3. **Rotar ante sospecha de exposición y revocar los tokens emitidos con la
   clave anterior.** La rotación por sí sola no invalida JWT ya firmados si el
   servidor todavía confía en la clave vieja: retirar esa versión, versionar
   claves (`kid`) y revocar sesiones/tokens cierra el uso de las forjas R2/R3.
4. **Claims mínimos y sin datos sensibles.** Eliminar `nota_interna` y guardar
   datos privados solo en el servidor; el payload de un JWT firmado se puede
   leer porque Base64URL no cifra. Esto evita la filtración R1, aunque no impide
   por sí solo la falsificación.
5. **Autorización por objeto y rol en cada endpoint.** Resolver el sujeto desde
   identidad confiable y verificar que tenga acceso al registro; no conceder
   `/admin` por un rol que el código no haya validado y autorizado. Esto limita
   R2 y R3 incluso si aparece otro fallo de token.
6. **Expiración breve y mecanismo de revocación.** Reducen la ventana de uso
   de un token robado/forjado; la expiración no ofrece revocación inmediata,
   así que mantener una versión de sesión, lista de revocados u otro control
   server-side permite cortar el acceso antes de `exp`.

Las recomendaciones de claves, algoritmo y validación se contrastaron con
[RFC 8725, JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html);
la visibilidad del payload con [RFC 7519 §12](https://www.rfc-editor.org/rfc/rfc7519.html#section-12),
y el control de acceso por objeto con [OWASP API1:2023 — Broken Object Level
Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).

## 6. Evidencia de progreso

No se adjunta `ctf status extra5` ni se declaran flags: quedan pendientes de
la corrida de integración grupal.
