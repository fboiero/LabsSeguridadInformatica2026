# Entregable — Lab Extra 5: JWT inseguro

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0), Fernando Cagliero (@Ferca19)

**Estado parcial:** Lorenzo implementó y verificó las cuatro funciones de `jwt_tool.py` con datos sintéticos. Guadalupe completó R1–R3, el control de sanidad y el status (CTF 3/3). P1/P2/P4 son de Lautaro; P3/P5 e integración, de Fernando. Las flags se recuperaron operando el portal local y se validaron por `sha256` contra `retos.manifest`.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para revisar el diseño del código y preparar pruebas sintéticas. Verifiqué el resultado con assertions locales para firma, alteración, diccionario sintético, errores de formato y CLI. No utilicé IA para afirmar aceptación del servidor ni para inventar hallazgos del caso. Declaraciones de Lautaro y Fernando: pendientes.

**Declaración de uso de IA — Guadalupe (@guadagomezgg8):** bloque R1–R3, control de sanidad y status. Usé **Claude (Anthropic)** para (a) levantar el portal local (`objetivo/server.py`), pedir un token con las credenciales demo, y operar con `jwt_tool.py` la decodificación (R1), el crack offline + forja de `role=admin` (R2) y la forja de `sub=maria` (R3), más las pruebas de sanidad, con salidas en `evidencia/salidas/r1-r3-jwt.txt` y `status-extra5.txt`, y (b) redactar estos bloques y esta declaración. No se leyó el generador ni `solucion.md`: las flags salieron del payload del token y de las respuestas HTTP, y se validaron por `sha256` contra `retos.manifest`. Reviso y puedo explicar cada paso.

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

- **P1 — Integridad vs. confidencialidad:** pendiente, asignada a Lautaro.
- **P2 — Crack offline vs. login online:** pendiente, asignada a Lautaro.
- **P3 — IDOR en el claim y autorización:** pendiente, asignada a Fernando.
- **P4 — `alg:none`:** pendiente; Lautaro debe medir el comportamiento de este servidor.
- **P5 — Defensas priorizadas:** pendiente, asignada a Fernando.

## 6. Evidencia de progreso

`evidencia/salidas/` contiene la ayuda CLI y las pruebas sintéticas de Lorenzo, la operación de la cadena (`r1-r3-jwt.txt`) y la captura del CTF (`status-extra5.txt`). Tras enviar R1–R3, el estado es **3/3 (100%)**:

```
✓ R1  El payload viaja en claro (base64 no es cifrado)
✓ R2  Secreto debil crackeado -> token forjado con role=admin
✓ R3  Suplantacion por claim: sub=maria (IDOR via JWT)
██████████████████████████████  3/3 (100%)
```
