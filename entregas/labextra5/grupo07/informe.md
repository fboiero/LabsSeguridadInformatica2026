# Entregable — Lab Extra 5: JWT inseguro

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0), Fernando Cagliero (@Ferca19)

**Estado parcial:** Lorenzo implementó y verificó las cuatro funciones de jwt_tool.py con datos sintéticos. Fernando agregó P3/P5 y la revisión estática del flujo de /perfil. R1–R3, control de sanidad y estado del portal siguen asignados a Guadalupe; P1/P2/P4, a Lautaro. No se levantó el portal, no se presentaron flags y el CTF capturado sigue en 0/3.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para revisar el diseño del código y preparar pruebas sintéticas. Verifiqué el resultado con assertions locales para firma, alteración, diccionario sintético, errores de formato y CLI. No utilicé IA para afirmar aceptación del servidor ni para inventar hallazgos del caso. Fernando Cagliero (@Ferca19) usó OpenAI Codex para revisar el flujo local de /perfil, contrastar P3/P5 con RFC 7519, RFC 8725 y OWASP API Security, y redactar su análisis. No se afirmaron pruebas del portal ni flags; las conclusiones se basan en el código del caso y las fuentes listadas.

---

## 1. Anatomía del token real

Pendiente: asignada a Guadalupe. No se solicitó un token del portal en este aporte.

## 2. Crack offline del secreto

La implementación de `firma_es_valida()` calcula HMAC-SHA256 sobre los segmentos codificados exactos `header.payload` y compara la firma decodificada usando `hmac.compare_digest`. Con un token y un candidato, la validación ocurre localmente; no hace una solicitud al servidor. La prueba sintética confirmó un secreto correcto, un secreto incorrecto y una firma alterada. No se probó el secreto del caso ni se reporta cantidad/tiempo de candidatos reales; eso corresponde a Guadalupe.

## 3. Las dos forjas

### R2 — Escalada vertical (role=admin)

Pendiente: ejecución y evidencia asignadas a Guadalupe. `forjar()` está implementada, pero aún no se afirma que el portal acepte un token de esta copia.

### R3 — Suplantación horizontal (sub=maria)

Pendiente: ejecución y evidencia asignadas a Guadalupe.

## 4. Control de sanidad

Pendiente: asignado a Guadalupe. Las pruebas sintéticas comprueban firma incorrecta en la función local, pero no sustituyen los requisitos del servidor: token regular de Diego rechazado en `/admin` y token forjado modificado rechazado con 401.

## 5. Preguntas P1–P5

- **P1 — Integridad vs. confidencialidad:** pendiente, asignada a Lautaro.
- **P2 — Crack offline vs. login online:** pendiente, asignada a Lautaro.
- **P3 — IDOR/BOLA en el claim y autorización.** El identificador del objeto no necesita estar en la URL: este servidor toma `payload["sub"]` del JWT en `/perfil` y lo usa directamente para buscar el registro y devolver sus datos. La identidad/objeto solicitado viaja en el claim. Como el secreto débil permite fabricar una firma aceptada con `sub=maria`, el servidor no vuelve a comprobar que esa identidad corresponde al principal autenticado ni que tenga autorización para ese objeto. Cambiar el identificador dentro del token produce la misma falla de autorización a nivel de objeto que manipular un `?id=`. La defensa es validar la firma, el emisor, la audiencia y el sujeto; derivar el principal de una identidad confiable y comprobar autorización por objeto en cada solicitud. OWASP clasifica esta falla como BOLA/API1; RFC 8725 recomienda validar claims de sujeto y audiencia.

Fuentes: [OWASP API1:2023 — Broken Object Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/) y [RFC 8725 §§3.8–3.9](https://www.rfc-editor.org/rfc/rfc8725.html).
- **P4 — `alg:none`:** pendiente; Lautaro debe medir el comportamiento de este servidor.
- **P5 — Defensas priorizadas.**

1. **Contener la exposición ahora:** rotar la clave comprometida y retirar de confianza la versión anterior; revocar los JWT/sesiones que dependan de ella para impedir las forjas R2/R3.
2. **Usar una clave impredecible:** para HS256, generar una clave aleatoria de al menos 256 bits con CSPRNG, guardarla en un gestor de secretos y no derivarla de una contraseña humana. Esto bloquea el diccionario offline R2. RFC 8725 §3.5 exige entropía suficiente.
3. **Fijar el algoritmo en el servidor:** permitir solo el algoritmo configurado, rechazar `none` y evitar confusión entre algoritmos o tipos de clave. No confiar en el valor `alg` del header para decidir cómo verificar; esto bloquea la clase de ataque P4. (RFC 8725 §3.1.)
4. **Minimizar los claims:** quitar `nota_interna` y cualquier dato sensible. Un JWT firmado no cifra su payload; Base64URL se puede decodificar. Esto evita la filtración R1, aunque no impide por sí solo falsificaciones.
5. **Autorizar cada objeto y función:** resolver el principal desde identidad validada y comprobar acceso al registro; verificar el rol administrativo en el servidor. Esto limita suplantación horizontal R3 y escalada R2.
6. **Reducir la ventana y habilitar revocación:** `exp` breve limita cuánto dura un token robado/forjado, pero no lo invalida de inmediato. Mantener revocación por sesión/versión o lista de tokens invalidados permite cortar acceso antes de `exp`.

Fuentes: [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725.html), [RFC 7519 §12 — privacidad del JWT](https://www.rfc-editor.org/rfc/rfc7519.html#section-12), y [OWASP API1:2023 — BOLA](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/).

## 6. Evidencia de progreso

`evidencia/salidas/` conserva ayuda CLI, pruebas sintéticas de Lorenzo y estado CTF 0/3. La revisión estática de Fernando sobre `server.py` está en `evidencia/salidas/revision-r3-p5.txt`; las referencias están en `evidencia/referencias.md`. No se ejecutó el portal ni se capturaron R1–R3 en este bloque.
