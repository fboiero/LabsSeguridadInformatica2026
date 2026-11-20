# Entregable — Lab Extra 5: JWT inseguro

**Grupo:** 14 · **Integrantes:** Peron, Fede (@fedeeperon) · Gomez Redondo, Laureano (@Laureano-GR) · Cesano, Martín (@martincesano) · Gaido, Martín (@martingaidoo) · Chiapero, Valentina (@valechiapero)

**Declaración de uso de IA:** Usamos IA para redactar el informe y las respuestas
P1–P5. La implementación de `jwt_tool.py` (decodificar, firma_es_valida,
crackear_secreto, forjar), los ataques contra el portal y la validación con
`./ctf submit` los hicimos nosotros.

---

## 1. Hallazgos

### R1 — El payload viaja en claro → `FLAG{jwt_solo_base64}`
`jwt_tool.py decodificar <token>` muestra el payload sin verificar nada: un JWT
es `base64url(header).base64url(payload).firma`. El claim `nota_interna` trae
`deploy-tag FLAG{jwt_solo_base64}`. **Base64 no es cifrado**: cualquiera que
intercepte el token lee todo el payload.

### R2 — Secreto débil → token forjado admin → `FLAG{jwt_forjado_admin}`
`jwt_tool.py crackear <token> diccionario.txt` recupera el secreto **offline**:
`mate123`. Con él forjamos `{"sub":"diego","role":"admin",...}`,
lo firmamos y `GET /admin` con `Authorization: Bearer <token>` devuelve
`{"panel":"admin","auditoria":"FLAG{jwt_forjado_admin}"}`.

### R3 — Suplantación por claim (IDOR vía JWT) → `FLAG{jwt_suplantacion_idor}`
La identidad es solo el claim `sub`. Con el secreto, forjamos un token con
`sub=maria` y `GET /perfil` devuelve los datos de maria:
`... Nota confidencial: FLAG{jwt_suplantacion_idor}`. No hace falta `?id=`: el
control de acceso se delegó en un dato que el atacante controla.

## 2. Las flags

`./ctf status extra5` → R1, R2, R3 en ✓ (3/3, 100%). Ver `evidencia/salidas/ctf-status.txt`.

## 3. Preguntas P1–P5

- **P1. Integridad vs. confidencialidad.** La firma HMAC da **integridad**
  (detecta modificaciones *si no conocés el secreto*) y autenticidad del emisor.
  **No** da **confidencialidad**: el payload viaja legible. PhantomCorp tenía
  integridad (frágil, por el secreto débil) pero creía tener confidencialidad
  ("está firmado, no se puede tocar/leer") — que nunca tuvo.
- **P2. Crack offline.** El token **es** el oráculo: con header+payload+firma, el
  atacante prueba candidatos recalculando el HMAC en su máquina, sin tocar el
  servidor. No hay rate limit, ni logs, ni lockout, ni latencia de red; va a
  millones de intentos/segundo. Contra `/login` el brute force es **online**:
  lento, logueado y frenable con rate limit/lockout. Por eso un secreto débil en
  JWT es mucho peor que una password débil detrás de un login.
- **P3. IDOR que migra al token.** En el Lab 07 el IDOR estaba en `?id=`; acá la
  identidad vive en el claim `sub`. Cuando el servidor confía en un dato del
  token para decidir "quién sos" / "qué podés ver" y ese token es forjable
  (secreto débil), el control de acceso roto se mueve del parámetro al claim: el
  atacante se declara maria/admin. La raíz es la misma: confiar en input del
  cliente para autorización.
- **P4. alg:none.** Lo probamos (ver `evidencia/salidas/P4-alg-none.txt`): este
  server lo **rechaza**, porque `verificar()` recalcula siempre HMAC-SHA256 con
  su secreto e ignora el `alg` del header; una firma vacía no coincide → 401. Un
  server correcto debe hacer exactamente eso: **fijar el algoritmo esperado del
  lado servidor** y nunca dejar que el header `alg` elija el modo de
  verificación (la confusión `none` / RS256↔HS256 es un bug clásico de librerías).
- **P5. Defensas en orden de prioridad.**
  1. **Secreto fuerte y aleatorio** (≥256 bits) fuera del código → mata R2 (el
     crack offline deja de ser viable).
  2. **Algoritmo fijado en el servidor** (no confiar en `alg`) → mata alg:none y
     confusión de algoritmos (P4).
  3. **Claims mínimos / no meter secretos en el payload** → mata R1 (el token no
     cifra; nada sensible debe viajar ahí).
  4. **Autorización server-side real** (no confiar solo en `sub`/`role` del
     token para datos de otro usuario) → mitiga R3 aunque se filtre el secreto.
  5. **Expiración corta + rotación de secreto + revocación** (lista negra /
     `jti`) → reduce la ventana de un token forjado o filtrado.

## 4. Conclusión

El JWT firmado garantiza integridad, no secreto, y su seguridad entera depende
de un secreto fuerte, un algoritmo fijado del lado servidor y de no delegar la
autorización en claims controlables por el cliente.
