# Entregable — Lab Extra 5: JWT inseguro

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0), Fernando Cagliero (@Ferca19)

**Estado integrado:** Lorenzo implementó y verificó `jwt_tool.py` con pruebas sintéticas. Guadalupe completó R1–R3, el control de sanidad y el estado del portal (CTF 3/3), con flags verificadas por `sha256` contra `retos.manifest`. Lautaro respondió P1/P2/P4 y probó `alg:none`; Fernando integró el análisis P3/P5 y su evidencia estática.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para revisar el diseño del código y preparar pruebas sintéticas. Verifiqué el resultado con assertions locales para firma, alteración, diccionario sintético, errores de formato y CLI. No utilicé IA para afirmar aceptación del servidor ni para inventar hallazgos del caso.

**Declaración de uso de IA — Guadalupe (@guadagomezgg8):** bloque R1–R3, control de sanidad y status. Usé **Claude (Anthropic)** para (a) levantar el portal local (`objetivo/server.py`), pedir un token con las credenciales demo, y operar con `jwt_tool.py` la decodificación (R1), el crack offline + forja de `role=admin` (R2) y la forja de `sub=maria` (R3), más las pruebas de sanidad, con salidas en `evidencia/salidas/r1-r3-jwt.txt` y `status-extra5.txt`, y (b) redactar estos bloques y esta declaración. No se leyó el generador ni `solucion.md`: las flags salieron del payload del token y de las respuestas HTTP, y se validaron por `sha256` contra `retos.manifest`. Reviso y puedo explicar cada paso.

**Declaración de uso de IA — Lautaro Mariño (@lautaromarino0):** preguntas P1, P2 y P4. Usé **Claude (Anthropic)** para redactar P1/P2 a partir del análisis del caso y para escribir y correr `evidencia/prueba_alg_none.py`, que levanta el portal y prueba la forja con `alg:none`; revisé el código y la salida antes de commitear. La medición de P4 sale de las respuestas HTTP del propio server (`evidencia/salidas/alg-none-lautaro.txt`), no de leer `objetivo/server.py` para deducir la respuesta ni de `solucion.md`.

**Declaración de uso de IA — Fernando Cagliero (@Ferca19):** usé OpenAI Codex para revisar estáticamente el flujo local de `/perfil`, contrastar P3/P5 con RFC 7519, RFC 8725 y OWASP API Security, y redactar el análisis. No ejecuté el portal ni afirmo haber capturado flags; mis conclusiones se basan en el código del caso y las fuentes listadas.

---

## 1. Anatomía del token real

Con el portal levantado, `GET /login?user=diego&pass=diego123` devolvió un JWT HS256. Decodificando sus dos primeros tramos con `jwt_tool.py decodificar` (base64url, sin secreto):

```
HEADER:  {"alg":"HS256","typ":"JWT"}
PAYLOAD: {"sub":"diego","role":"user","iat":...,"exp":...,
          "nota_interna":"deploy-tag FLAG{jwt_solo_base64}"}
```

El claim `nota_interna` no debería viajar en el token: **base64url no es cifrado**, cualquiera lo lee sin la clave. Flag R1: `FLAG{jwt_solo_base64}` (`sha256` verificado contra `retos.manifest`). Salida: [r1-r3-jwt.txt](evidencia/salidas/r1-r3-jwt.txt).

## 2. Crack offline del secreto

La implementación de `firma_es_valida()` calcula HMAC-SHA256 sobre los segmentos codificados exactos `header.payload` y compara la firma decodificada usando `hmac.compare_digest`. Con un token y un candidato, la validación ocurre localmente; no hace una solicitud al servidor. La prueba sintética confirmó un secreto correcto, un secreto incorrecto y una firma alterada. No se probó el secreto del caso en ese aporte; eso corresponde a Guadalupe.

**Resultado real (Guadalupe):** `jwt_tool.py crackear <token> caso/diccionario.txt` recuperó el secreto **`mate123`** probando los 31 candidatos del diccionario contra la firma del token, todo local (el server no interviene ni lo registra). Con ese secreto se firman tokens arbitrarios (R2/R3).

## 3. Las dos forjas

### R2 — Escalada vertical (role=admin)

Con el secreto `mate123`, `jwt_tool.py forjar mate123 --sub diego --role admin` produjo un token con `role=admin`. El portal lo aceptó:

```bash
curl -s -H 'Authorization: Bearer <token-admin>' http://localhost:8080/admin
{"panel":"admin","auditoria":"FLAG{jwt_forjado_admin}"}
```

Flag R2: `FLAG{jwt_forjado_admin}` (`sha256` verificado). El server confía en el claim `role` porque la firma valida: quien tiene el secreto, gobierna.

### R3 — Suplantación horizontal (sub=maria)

Con el mismo secreto, `jwt_tool.py forjar mate123 --sub maria --role user` y una consulta a `/perfil`:

```bash
curl -s -H 'Authorization: Bearer <token-maria>' http://localhost:8080/perfil
{"usuario":"maria","role":"user","datos":"Legajo 1007 — Finanzas. Nota confidencial: FLAG{jwt_suplantacion_idor}"}
```

Flag R3: `FLAG{jwt_suplantacion_idor}` (`sha256` verificado). Es un IDOR (Lab 07) pero sin `?id=`: la identidad vive en el claim `sub`, y al controlarlo paso a ser otro usuario.

## 4. Control de sanidad

Se verificó contra el portal que lo único roto es el secreto débil; el resto de los controles responde bien:

| Prueba | Esperado | Resultado |
|---|---|---|
| Token **real** de diego (`role=user`) en `/admin` | denegar | HTTP 403 «solo administradores» |
| Token **forjado** `role=admin` en `/admin` | aceptar | HTTP 200 (panel admin) |
| Token con **firma alterada** (1 char) en `/admin` | rechazar | HTTP 401 (firma inválida) |
| `/perfil` **sin token** | rechazar | HTTP 401 |

Es decir: el server valida firma y autoriza por `role` correctamente. El problema no es el código de verificación sino el **secreto de diccionario** (`mate123`), que permite forjar firmas válidas. Salida: [r1-r3-jwt.txt](evidencia/salidas/r1-r3-jwt.txt).

## 5. Preguntas P1–P5

### P1 — Integridad vs. confidencialidad

Un JWT firmado da **integridad y autenticidad**, no **confidencialidad**. La firma HMAC garantiza que el payload no se modificó y que lo emitió quien tiene el secreto: si cambiás un claim sin el secreto, la firma deja de validar. Lo que la firma **no** hace es ocultar el contenido: el payload es `base64url`, una codificación reversible sin clave, no un cifrado. Cualquiera que tenga el token lo lee entero.

El equipo de PhantomCorp confundió las dos propiedades: tenían **integridad** (el token está firmado) y creían tener además **confidencialidad** ("está firmado, no se puede tocar" → asumieron "ni leer"). Por eso metieron `nota_interna` con una flag en el payload: viaja en claro en cada request (R1). La integridad tampoco les sirvió de mucho, porque el secreto era de diccionario (`mate123`) y, una vez crackeado, el atacante firma tokens válidos a gusto (R2/R3): con un secreto débil, la propiedad de integridad se evapora. Regla: nunca pongas en un JWT algo que no quieras que el portador lea; si tiene que ser secreto, va cifrado o directamente no va en el token.

### P2 — Crack offline vs. login online

El crack del secreto es **offline**: con un solo token capturado, el atacante prueba candidatos del diccionario calculando `HMAC-SHA256(candidato, header.payload)` y comparándolo con la firma del token, **en su propia máquina**. El portal no participa: no recibe ninguna petición, no ve los intentos, no los registra.

Eso cambia todo respecto de atacar el `/login` online:

| | Crack offline del secreto | Fuerza bruta contra `/login` |
|---|---|---|
| ¿Quién procesa los intentos? | La CPU/GPU del atacante | El servidor |
| Velocidad | Millones por segundo, sin límite | Limitada por la red y el servidor |
| Rate limit / lockout | No aplica (el server no interviene) | Lo frena (bloqueo tras N intentos) |
| Logs / alertas | Ninguno; es invisible | Quedan registrados; disparan alertas |
| Límite real | Solo el tamaño del diccionario y la fuerza del secreto | Defensas del portal |

Implicancia: un secreto débil no se "protege" con rate limiting ni con logs, porque el ataque ni toca el servidor. La única defensa contra el crack offline es que el secreto sea **largo y aleatorio** (alta entropía), de modo que el diccionario y la fuerza bruta sean inviables. Por eso, aunque el `/login` tuviera lockout perfecto, `mate123` cae igual.

- **P3 — IDOR/BOLA en el claim y autorización.** El identificador del objeto no necesita estar en la URL: este servidor toma `payload["sub"]` del JWT en `/perfil` y lo usa directamente para buscar el registro y devolver sus datos. La identidad/objeto solicitado viaja en el claim. Como el secreto débil permite fabricar una firma aceptada con `sub=maria`, el servidor no vuelve a comprobar que esa identidad corresponde al principal autenticado ni que tenga autorización para ese objeto. Cambiar el identificador dentro del token produce la misma falla de autorización a nivel de objeto que manipular un `?id=`. La defensa es validar la firma, el emisor, la audiencia y el sujeto; derivar el principal de una identidad confiable y comprobar autorización por objeto en cada solicitud. OWASP clasifica esta falla como BOLA/API1; RFC 8725 recomienda validar claims de sujeto y audiencia.

Fuentes: [OWASP API1:2023 — Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/) y [RFC 8725 §§3.8–3.9](https://www.rfc-editor.org/rfc/rfc8725.html).

### P4 — `alg:none`

**Lo probé: este servidor NO acepta `alg:none`.** Forjé un token con header `{"alg":"none","typ":"JWT"}`, `role=admin`, `sub=diego` y **firma vacía**, y lo mandé a `/admin` y a `/perfil`: ambos respondieron **401**. Con firma basura, igual. En contraste, un token HS256 firmado con el secreto crackeado (`mate123`) sí entra a `/admin` (200). Script y salida: `evidencia/prueba_alg_none.py` y `evidencia/salidas/alg-none-lautaro.txt`.

El motivo está en cómo verifica: `verificar()` **ignora el header `alg`** del token y siempre recalcula `HMAC-SHA256(secreto, header.payload)`, comparando con `hmac.compare_digest`. Una firma vacía nunca coincide con un HMAC real → rechazo. O sea, el server **fija el algoritmo del lado del servidor**, que es exactamente lo que hay que hacer.

Qué debería hacer un servidor correcto con el claim `alg` del header: **no confiar en él**. El `alg` lo elige el atacante, así que un verificador seguro define de antemano el algoritmo esperado (y rechaza cualquier otro), nunca despacha la verificación según lo que dice el token. Confiar en el `alg` del header es lo que habilita dos ataques clásicos: `alg:none` (firma vacía aceptada) y la confusión RS256→HS256 (verificar con la clave pública usada como secreto HMAC). Este portal está bien en ese punto; su falla real no es el algoritmo sino el **secreto de diccionario**.

- **P5 — Defensas priorizadas.**

1. **Contener la exposición ahora:** rotar la clave comprometida y retirar de confianza la versión anterior; revocar los JWT/sesiones que dependan de ella para impedir las forjas R2/R3.
2. **Usar una clave impredecible:** para HS256, generar una clave aleatoria de al menos 256 bits con CSPRNG, guardarla en un gestor de secretos y no derivarla de una contraseña humana. Esto bloquea el diccionario offline R2. RFC 8725 §3.5 exige entropía suficiente.
3. **Fijar el algoritmo en el servidor:** permitir solo el algoritmo configurado, rechazar `none` y evitar confusión entre algoritmos o tipos de clave. No confiar en el valor `alg` del header para decidir cómo verificar; esto bloquea la clase de ataque P4. (RFC 8725 §3.1.)
4. **Minimizar los claims:** quitar `nota_interna` y cualquier dato sensible. Un JWT firmado no cifra su payload; Base64URL se puede decodificar. Esto evita la filtración R1, aunque no impide por sí solo falsificaciones.
5. **Autorizar cada objeto y función:** resolver el principal desde identidad validada y comprobar acceso al registro; verificar el rol administrativo en el servidor. Esto limita suplantación horizontal R3 y escalada R2.
6. **Reducir la ventana y habilitar revocación:** `exp` breve limita cuánto dura un token robado/forjado, pero no lo invalida de inmediato. Mantener revocación por sesión/versión o lista de tokens invalidados permite cortar acceso antes de `exp`.

Fuentes: [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html), [RFC 7519 §12 — privacidad del JWT](https://www.rfc-editor.org/rfc/rfc7519.html#section-12), y [OWASP API1:2023 — BOLA](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).

## 6. Evidencia de progreso

`evidencia/salidas/` contiene la ayuda CLI y las pruebas sintéticas de Lorenzo, la operación de la cadena (`r1-r3-jwt.txt`) y la captura del CTF (`status-extra5.txt`). Tras enviar R1–R3, el estado es **3/3 (100%)**:

```
✓ R1  El payload viaja en claro (base64 no es cifrado)
✓ R2  Secreto debil crackeado -> token forjado con role=admin
✓ R3  Suplantacion por claim: sub=maria (IDOR via JWT)
██████████████████████████████  3/3 (100%)
```

La revisión estática de Fernando sobre el flujo de `/perfil` está en `evidencia/salidas/revision-r3-p5.txt`; las fuentes conceptuales están en `evidencia/referencias.md`. Fernando no ejecutó el portal ni presentó flags.
