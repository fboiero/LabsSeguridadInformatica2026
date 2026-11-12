# Informe — Lab Extra 5: JWT inseguro

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919

**Declaración de uso de IA:** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Mitad B: análisis P3, P4 y P5, reproducción de la cadena y la evidencia de la Parte 2 (`10`–`13`), script dedicado de `alg:none` y medición reproducible del crack, y `research.md`. | Secciones 2 (reconciliación del tiempo), 4 y P3–P5 del informe; `evidencia/scripts/parte2-*`; `research.md`. | **Todas las salidas pegadas son ejecuciones reales** (`evidencia/salidas/10`–`13`), corridas contra el objetivo levantado en WSL (Python 3.12.3). Las 3 flags ya estaban validadas en la Mitad A (`./ctf status extra5` → 3/3). El grupo revisó el `jwt_tool.py` y puede explicar por qué HMAC permite crack offline y RS256 no. |

> **División del trabajo (grupo08).** Esta entrega se hizo a dos mitades:
> - **Mitad A — práctica (HECHA):** `jwt_tool.py` funcional (4 funciones),
>   cadena R1–R3, control de sanidad (§4) y evidencia. Secciones **1, 2, 3, 4**
>   y preguntas **P1** y **P2**.
> - **Mitad B — análisis (HECHA):** preguntas **P3, P4, P5**, evidencia propia de
>   la Parte 2 (`evidencia/salidas/10`–`13`, `evidencia/scripts/parte2-*`),
>   `research.md` y la declaración de IA.

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
- **Tiempo (medición reproducible, `evidencia/salidas/13-parte2-medicion-crack.txt`,
  promedio de 1000 corridas, Python 3.12.3):**
  - solo las verificaciones HMAC hasta el acierto, sin I/O: **0.071 ms**;
  - operación completa, incluyendo abrir y leer el diccionario cada vez: **8.8 ms**.

  Las dos son instantáneas: la diferencia es casi toda **lectura de archivo**, no
  criptografía (HMAC-SHA256 es un hash rápido y el diccionario tiene 31 palabras).
  La cifra de ≈ 0.17 ms que anotamos en la Mitad A (`03-medicion-crack.txt`) la
  tomamos a mano en otra máquina y no dejamos script, así que no podemos
  reconstruir qué incluía; por el orden de magnitud, era el camino cripto-puro
  (los 0.071 ms de acá), no la operación completa. La medición reproducible es
  esta. Ninguna de las dos toca el servidor.
- **Con un secreto de 32 bytes aleatorios** el crack por diccionario se vuelve
  inviable: el secreto deja de estar en ninguna lista y habría que recorrer
  2^256 candidatos. El ataque de este lab muere ahí (ver P5).

Comando: `python3 src/jwt_tool.py crackear <token> caso/diccionario.txt` →
`SECRETO: mate123`. Evidencia: `evidencia/salidas/13-parte2-medicion-crack.txt`
(reproducible) y `03-medicion-crack.txt` (Mitad A).

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
las forjas no probarían nada). Evidencia de la Mitad A:
`evidencia/salidas/02-control-sanidad.txt`; reproducida en la Parte 2 en
`11-parte2-sanidad.txt` y `12-parte2-alg-none.txt`.

| Caso | Request | Respuesta |
|---|---|---|
| (a) token **real** de diego (`role=user`) en `/admin` | firma válida, rol insuficiente | **HTTP 403** `{"error":"solo administradores"}` |
| (b) token forjado admin con **1 char cambiado** en la firma | firma inválida | **HTTP 401** `{"error":"token invalido o expirado"}` |
| (P4) `alg:none` con firma vacía, firma basura, y HS256 con secreto equivocado | ninguna matchea el HMAC recalculado | **HTTP 401** los tres (`12-parte2-alg-none.txt`) |

Esto confirma que las flags de R2/R3 se obtuvieron con **firmas válidas** (no
porque el server acepte cualquier cosa): el control de acceso funciona, lo que
falla es la **fuerza del secreto**. La cadena completa R1–R3 se volvió a correr
en la Parte 2 y sigue dando las 3 flags (`10-parte2-cadena.txt`).

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

### P3 — IDOR en el claim

R3 es el mismo bug que el IDOR del Lab 07, cambiado de lugar. En el Lab 07 el
identificador viajaba en la URL (`/perfil?id=maria`) y el servidor servía los
datos de ese `id` **sin preguntar si el que pide tiene permiso**. Acá no hay
`?id=`: el identificador es el claim `sub` del token. El endpoint hace, textual:

```python
u = USUARIOS.get(payload["sub"])          # objetivo/server.py, /perfil
... "datos": u["datos"] ...
```

El servidor sirve los datos **de quien diga `sub`**. Nunca compara "quién está
autenticado" contra "a quién pertenece el recurso", porque para él son la misma
cosa: la identidad **es** el claim. Esa es la definición de IDOR —
*Insecure Direct Object Reference*—: referencia directa a un objeto (el usuario
`maria`) sin control de autorización.

¿Por qué el control de acceso "migra" al token? Porque lo único que impedía
cambiar `sub` era la **firma**. En un JWT bien hecho, la firma es la frontera de
autorización: no podés cambiar `sub` porque no sabés refirmar. Pero esa frontera
se apoya **entera** en el secreto. Cuando el secreto cae (R2), el `sub` vuelve a
ser un parámetro bajo control del atacante, exactamente como el `?id=` del Lab
07. El IDOR no desapareció al pasar a JWT: se escondió detrás de la firma, y la
firma valía `mate123`. Lo demostramos forjando `sub=maria` y leyendo su nota
confidencial (`10-parte2-cadena.txt`). La lección: **autenticar la identidad no
es autorizar el acceso.** El server tendría que validar permisos sobre el recurso
aunque el `sub` fuera 100% confiable.

### P4 — `alg:none`

**Lo probamos: este servidor lo rechaza** (`12-parte2-alg-none.txt`). Un token
con `"alg":"none"` y firma vacía, uno con firma basura y hasta uno HS256 bien
formado firmado con el secreto equivocado (`secret`): los tres dan **401**.

El motivo está en `verificar()` (`objetivo/server.py`):

```python
esperada = b64url(hmac.new(SECRETO, f"{cab}.{pay}".encode(), hashlib.sha256).digest())
if not hmac.compare_digest(fir, esperada):
    return None
```

El server **nunca lee el `alg` del header**: siempre recalcula HMAC-SHA256 con su
secreto y lo compara. Una firma vacía o cualquier otra que no sea el HMAC exacto
no matchea. Es decir, es inmune a `alg:none` **por una razón de implementación,
no de diseño**: soporta un solo algoritmo cableado y jamás despacha según lo que
pide el token.

El peligro real aparece en librerías que **sí** soportan varios algoritmos y
eligen cuál usar leyendo el `alg` del token. Ahí caen dos ataques clásicos
(detallados en `research.md`):

- **`alg:none`:** si la librería interpreta "none" como "no verifiques", la firma
  sobra y el atacante escribe lo que quiera.
- **Confusión de algoritmo (RS256→HS256):** si el server espera RS256 (asimétrico)
  pero acepta un token que dice `HS256`, algunas librerías verifican el HMAC
  usando la **clave pública RSA** como secreto. Y la clave pública es… pública:
  el atacante firma con ella.

Qué debe hacer un server correcto: **pinnear el algoritmo** del lado del servidor
y rechazar cualquier token cuyo `alg` no coincida. Nunca confiar en el `alg` que
viaja en el token. En PyJWT esto es, literalmente, el parámetro obligatorio
`jwt.decode(token, key, algorithms=["RS256"])`: la lista la decide el servidor,
no el atacante.

### P5 — Defensas priorizadas

Ordenadas por lo que atacan: primero lo que corta la **causa raíz** (la forja),
después lo que reduce el impacto.

| # | Defensa | Qué ataque de este lab bloquea |
|---|---|---|
| 1 | **Secreto fuerte (≥32 bytes aleatorios) y, mejor, algoritmo asimétrico (RS256 / EdDSA).** | **R2 y R3.** Toda la cadena de forja depende de recuperar el secreto; sin crack, no hay token admin ni suplantación. Es el #1 porque mata las dos forjas de una. |
| 2 | **Claims mínimos: nada sensible en el payload.** | **R1.** El payload es legible siempre. Un secreto fuerte **no** arregla R1 (ver la pregunta de cierre del research): aunque nadie pueda forjar, cualquiera sigue leyendo `nota_interna`. Son dos bugs independientes. |
| 3 | **Pinnear el algoritmo del lado del server.** | **`alg:none` y confusión de algoritmo (P4).** El server decide el algoritmo, no el token. Este objetivo ya es inmune de hecho, pero por accidente; una app con librería real lo necesita explícito. |
| 4 | **Expiración corta (`exp`) y validarla.** | Acota la ventana de un token robado o forjado. El server **ya** valida `exp` (lo vimos: un token vencido da 401); bajar su duración reduce el replay. |
| 5 | **Rotación del secreto / clave.** | Limita el daño si el secreto se filtra: obliga a recrackear y caduca los tokens forjados viejos. |
| 6 | **Revocación (denylist o tokens cortos + refresh).** | JWT es *stateless*: un token válido vale hasta `exp` aunque sepas que está comprometido. Una lista de revocación es el interruptor de apagado que al diseño le falta. |

**La diferencia estructural #1 (la que se pregunta en la oral).** Con **HS256** la
*misma* clave firma y verifica: todo servicio que valida tokens puede también
forjarlos, y si esa clave es débil se crackea offline (este lab). Con **RS256 /
EdDSA** hay dos claves: la **privada firma**, la **pública verifica**. Los
verificadores solo tienen la pública, con la que **no se puede forjar**, y no hay
secreto compartido que crackear. En microservicios es decisivo: repartís la clave
pública a diez servicios sin riesgo, mientras que repartir un secreto HMAC es
repartir la capacidad de firmar a los diez (y a quien comprometa a cualquiera de
ellos).

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
