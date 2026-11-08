# Informe — Laboratorio Extra 5: JWT inseguro

**Grupo:** 10 · **Fecha de la corrida técnica:** 03/11/2026.

**Integrantes:** Carolina Paula Corazza (`@carocor1`), Juan Pablo Saby (`@JuanSaby`), Belén Rocío Ramello (`@belramello`) y Chiara Agustina Kordek (`@chiarakordek`).

**Estado de preparación:** implementación y secciones de Carolina preparadas con asistencia de IA; falta completar las secciones asignadas a Juan, Belén y Chiara, la revisión humana grupal y adjuntar la captura solicitada del status. Este archivo todavía no es una entrega grupal cerrada.

**Declaración de uso de IA:** se utilizó OpenCode (GPT-6 Luna) para revisar requisitos, analisis final de la implementación de las cuatro funciones de `jwt_tool.py`, pruebas de verificación técnica y scripts de reproducción y asistir en la redacción de este informe. Las partes asistidas incluyen analisis de código y evidencia automatizada. La verificación técnica consistió en 10 pruebas unitarias y peticiones HTTP contra el `Handler` original de la cátedra; las salidas están adjuntas. Se contrastaron conceptos con RFC 7518, RFC 7519 y RFC 8725.

**Alcance y entorno:** caso ficticio autorizado de la cátedra, **sin Docker** como indica la consigna; no se instalaron dependencias externas. Python 3.12.10, Windows 11. El reproductor importa el `Handler` original sin modificar y lo sirve en `127.0.0.1` en puerto libre, en lugar de exponerlo en `0.0.0.0:8080`. En la corrida usada fue `127.0.0.1:54232`. No se probaron sistemas de terceros. El hash del archivo original y los detalles del entorno están en `evidencia/salidas/base-validada/00-entorno.json`.

## 1. Anatomía del token real

Se obtuvo un token mediante `GET /login?user=diego&pass=diego123`, usando las credenciales públicas del caso. La respuesta HTTP 200 está en `evidencia/salidas/base-validada/01-login.http.txt`. Token real de esa respuesta:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWVnbyIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkzNzM5MzQ0LCJleHAiOjE3OTM3NDI5NDQsIm5vdGFfaW50ZXJuYSI6ImRlcGxveS10YWcgRkxBR3tqd3Rfc29sb19iYXNlNjR9In0.P90v5C9BokTjjd7Fwj3CmkdTSKOiSG36kOZb0QtQico
```

La CLI del grupo se ejecutó con `decodificar <token-real>`. Header y payload obtenidos, sin necesitar el secreto:

```json
{ "alg": "HS256", "typ": "JWT" }
```

```json
{
  "sub": "diego",
  "role": "user",
  "iat": 1793739344,
  "exp": 1793742944,
  "nota_interna": "deploy-tag FLAG{jwt_solo_base64}"
}
```

**Claim problemático (R1): `nota_interna`.** Expone información interna a cualquier portador del token: base64url codifica, no cifra. Los dos primeros segmentos representan objetos JSON; el tercero representa el MAC binario HMAC-SHA256, no otro JSON. `iat` indica emisión y `exp` vencimiento, con una hora de diferencia. El valor de la flag visible aquí documenta el hallazgo; su envío al motor oficial se acredita con la salida exitosa del submit, no solo por aparecer en el payload.

`decodificar()` solo permite leer; no confirma autenticidad. El token histórico puede estar vencido cuando se revise el informe y sigue siendo evidencia de esta ejecución; para repetir el experimento hay que pedir un login nuevo. Salida original: `03-decodificado.txt`; token: `02-token-original.txt`, en la misma carpeta de evidencia.

## 2. Crack offline del secreto

**Oráculo en una oración:** un candidato es correcto si `HMAC-SHA256(candidato, header_codificado + "." + payload_codificado)` coincide con la firma del token observado, sin consultar al servidor.

Implementación de `firma_es_valida()` en la herramienta entregada:

```python
def firma_es_valida(token: str, secreto: bytes) -> bool:
    try:
        cab, pay, fir = token.split(".")
        header = json.loads(b64url_dec(cab))
        if not isinstance(header, dict) or header.get("alg") != "HS256":
            return False
        mensaje = f"{cab}.{pay}".encode("ascii")
        esperada = b64url(hmac.new(secreto, mensaje, hashlib.sha256).digest())
        return hmac.compare_digest(fir.encode("ascii"), esperada.encode("ascii"))
    except (ValueError, UnicodeError, binascii.Error):
        return False
```

Se usa exactamente la representación recibida de `header.payload`, sin decodificar y reserializar esos JSON para calcular el HMAC: cambiar espacios o el orden de propiedades cambiaría el mensaje firmado. La comparación es en tiempo constante. La función está fijada a HS256 y **solo valida la firma**, no vigencia, emisor, audiencia ni permisos de una sesión.

La CLI probó en orden las líneas no vacías de `labs/labextra5-jwt/caso/diccionario.txt`. Su stdout real fue:

```text
SECRETO: mate123
```

Y sus estadísticas en stderr:

```text
CANDIDATOS: 11
SEGUNDOS: 0.000440600
```

El tiempo medido por `perf_counter()` incluye abrir y recorrer el diccionario hasta la coincidencia; no incluye arranque de Python ni login. Es una muestra muy pequeña de una sola corrida de CPU, **no un benchmark general ni una medición de GPU**. Evidencia: `04-crack.txt` y `04-crack.stderr.txt`. No se usaron jwt.io ni PyJWT; el proceso del cracker no realiza peticiones de red. La clave se tomó de esa salida para las forjas posteriores.

Con **32 bytes uniformemente aleatorios** habría 256 bits de entropía: este diccionario dejaría de ser una estrategia viable; una búsqueda exhaustiva ideal tendría `2^256` posibilidades y aproximadamente `2^255` intentos en promedio. No se asigna una duración práctica extrapolando esta muestra. HS256 no está roto: el problema del caso es la clave predecible. Una clave fuerte **no oculta `nota_interna`**, por lo que R1 persistiría (RFC 7518 §3.2 y RFC 8725 §3.5).

**Verificación de implementación:** 10 pruebas unitarias aprobadas, incluyendo firma independiente, clave incorrecta, alteración de payload/firma, formato inválido, `none`, diccionario vacío/sin coincidencia y claves con espacios y Unicode. Registro en `evidencia/pruebas-unitarias.txt`. La corrida HTTP demostró que las forjas se aceptan y que los tokens inválidos se rechazan; la explicación de R2, R3 y los controles corresponde a los responsables indicados en esas secciones.

## 3. Las dos forjas

### R2 — Escalada vertical (role=admin)

Una vez obtenido el secreto simétrico (`mate123`) mediante el ataque offline documentado en la sección anterior, se procedió a forjar un token JWT con privilegios elevados (`role=admin`) manteniendo la identidad del usuario (`sub=diego`).

#### 1. Generación y estructura del token forjado

Se ejecutó la CLI del grupo invocando el subcomando `forjar`:

```bash
python jwt_tool.py forjar mate123 --sub diego --role admin
```

La herramienta construyó el header y el payload correspondientes, calculó el HMAC-SHA256 con la clave recuperada y generó el token (registrado en `evidencia/salidas/base-validada/05-token-admin.txt`):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWVnbyIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc5MzczOTM0NCwiZXhwIjoxNzkzNzQyOTQ0fQ.FyXSeI5vkb_ad0dzfvVza72dYo1InXpNRhqwYhncuyY
```

Al decodificarlo sin verificar clave, se observan sus dos partes JSON legibles:

```json
{ "alg": "HS256", "typ": "JWT" }
```

```json
{
  "sub": "diego",
  "role": "admin",
  "iat": 1793739344,
  "exp": 1793742944
}
```

#### 2. Acceso al panel de administración y respuesta observada

Se envió una solicitud HTTP `GET /admin` al servidor local incluyendo el token forjado en la cabecera `Authorization: Bearer <token_forjado>`. A diferencia del token legítimo de Diego —que es rechazado con código 403 Forbidden como se detalla en el control de sanidad—, el servidor aceptó la firma recalculada y autorizó el acceso con `HTTP 200 OK`.

Respuesta recibida (preservada en `evidencia/salidas/base-validada/06-admin.http.txt`):

```http
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.12.10
Date: Tue, 03 Nov 2026 20:55:44 GMT
Content-Type: application/json; charset=utf-8

{"panel": "admin", "auditoria": "FLAG{jwt_forjado_admin}"}
```

**Flag obtenida (R2):** `FLAG{jwt_forjado_admin}`.
El registro oficial de envío y aceptación por el motor CTF se documenta en `evidencia/salidas/base-validada/ctf-submit-R2.txt` (`[ OK ] Correcta (ya la tenías). Reto R2 ✓`) y en `ctf-status-extra5.txt`.

#### 3. Diff conceptual respecto del token original

El contraste entre el token emitido por el endpoint `/login` (`02-token-original.txt`) y el token forjado para la escalada (`05-token-admin.txt`) evidencia las siguientes diferencias estructurales y semánticas:

| Elemento | Token original (`diego` legítimo) | Token forjado (R2) | Impacto / Rol en la autorización |
|---|---|---|---|
| **Header** | `{"alg": "HS256", "typ": "JWT"}` | `{"alg": "HS256", "typ": "JWT"}` | Idéntico. Mantiene el algoritmo simétrico HMAC-SHA256. |
| **Claim `sub`** | `"diego"` | `"diego"` | Sin cambio. Se conserva la identidad para aislar la escalada de rol de la suplantación de usuario. |
| **Claim `role`** | `"user"` | `"admin"` | **Cambio crítico**. Altera el nivel de privilegios declarado para satisfacer la validación del endpoint `/admin`. |
| **Claim `nota_interna`** | `"deploy-tag FLAG{...}"` | *(Omitido)* | Demuestra que el servidor no exige este claim adicional para autorizar; evalúa únicamente `role`. |
| **Timestamps (`iat`/`exp`)** | `1793739344` / `1793742944` | `1793739344` / `1793742944` | En la corrida controlada se mantuvieron vigentes para evitar el rechazo por expiración en `verificar()`. |
| **Firma HMAC** | `P90v5C9BokTjjd...` | `FyXSeI5vkb_ad0...` | **Recalculada íntegramente**. Dado que el payload cambió, la firma anterior es inválida; se calculó un nuevo MAC válido con `mate123`. |

#### 4. Problema de seguridad: validación de firma y confianza en claims

La vulnerabilidad demostrada en R2 ilustra un desacople crítico entre la validación criptográfica y la política de autorización:

1. **Simetría y pérdida del control de emisión:** En esquemas basados en HMAC (`HS256`), el secreto es compartido. Quien puede verificar un token también tiene la capacidad matemática de crearlo y firmarlo. Al haberse utilizado una clave de diccionario (`mate123`), el atacante rompe la garantía de autenticidad del emisor: el servidor ya no puede distinguir si un token fue generado por su propio proceso de autenticación o por un tercero.
2. **Confianza ciega en claims autodeclarados:** La arquitectura stateless del portal delega el rol del usuario exclusivamente en el payload del JWT. En `server.py`, el método `_payload_o_401()` se limita a validar que `verificar(token)` sea no nulo (es decir, firma HMAC coincidente y fecha no expirada). Una vez superado ese filtro, la función de ruta confía plenamente en `payload.get("role") == "admin"` sin contrastar contra una base de datos ni verificar si el usuario `diego` posee efectivamente privilegios de administrador.
3. **Escalada de privilegios inadvertida:** Dado que el token forjado porta una firma matemáticamente válida ante la clave del servidor, la verificación criptográfica tiene éxito y el control de acceso concede el recurso restringido de forma transparente.

#### 5. Alcance de la demostración y limitaciones

- **Lo demostrado en el laboratorio:** Se confirmó experimentalmente en un entorno local y controlado (`127.0.0.1`, sin dependencias externas ni conexión a red) que una clave débil permite forjar claims de autorización y alcanzar la condición HTTP 200 en un endpoint protegido (`/admin`), sorteando la restricción por rol que normalmente bloquea a usuarios estándar (HTTP 403 verificado en `09-original-en-admin.http.txt`).
- **Consecuencias potenciales en un sistema real:** Si este patrón se replica en producción, un atacante que capture o reciba un token legítimo podría vulnerar la separación de privilegios de toda la plataforma, accediendo a consolas de administración, manipulando configuraciones operativas o exfiltrando información confidencial sin generar alertas por firma inválida.
- **Limitaciones de la evidencia:** Este experimento no evalúa ni compromete sistemas de terceros ni usuarios reales. En una arquitectura de producción robusta intervienen factores ausentes en este prototipo educativo, tales como secretos de alta entropía (256 bits pseudoaleatorios), criptografía asimétrica (donde los servicios consumidores solo tienen clave pública para verificar), listas de revocación o re-validación de roles contra un almacén persistente.

### R3 — Suplantación horizontal (sub=maria)

Con el mismo secreto recuperado en la sección 2 (`mate123`), se forjó un token para `maria` **sin tocar el claim `role`**: a diferencia de R2, acá no se escala a administrador, sino que se cambia la identidad declarada. El objetivo es acceder a los datos personales de otro usuario legítimo usando el endpoint `/perfil`.

#### 1. Generación del token forjado

```bash
python jwt_tool.py forjar mate123 --sub maria --role user
```

Token resultante (registrado en `evidencia/salidas/base-validada/07-token-maria.txt`):

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtYXJpYSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzkzNzM5MzQ0LCJleHAiOjE3OTM3NDI5NDR9.aAxRXMXJ7JLoa0ejjK_4OyzsC-Gjf3BJiCQpOV-n0NY
```

Decodificado:

```json
{ "alg": "HS256", "typ": "JWT" }
```

```json
{
  "sub": "maria",
  "role": "user",
  "iat": 1793739344,
  "exp": 1793742944
}
```

#### 2. Acceso al perfil ajeno y respuesta observada

Se envió `GET /perfil` con `Authorization: Bearer <token_forjado>`. El servidor validó la firma con el secreto recuperado, la encontró correcta y devolvió los datos del usuario indicado en `sub`, sin que nada en la solicitud identificara a quien la envió más allá de ese claim.

Respuesta recibida (preservada en `evidencia/salidas/base-validada/08-perfil-maria.http.txt`):

```http
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.12.10
Date: Tue, 03 Nov 2026 20:55:44 GMT
Content-Type: application/json; charset=utf-8

{"usuario": "maria", "role": "user", "datos": "Legajo 1007 — Finanzas. Nota confidencial: FLAG{jwt_suplantacion_idor}"}
```

**Flag obtenida (R3):** `FLAG{jwt_suplantacion_idor}`.
El registro oficial de envío y aceptación por el motor CTF se documenta en `evidencia/salidas/base-validada/ctf-submit-R3.txt` y en `ctf-status-extra5.txt`. Belén reprodujo además esta sección en una corrida propia (`evidencia/salidas/belen-01/`), que repite el mismo resultado —`08-perfil-maria.http.txt`: `HTTP 200` con `FLAG{jwt_suplantacion_idor}`— sobre un puerto, timestamp y entorno distintos a la corrida común.

#### 3. Diff conceptual respecto del token original

| Elemento | Token original (`diego`) | Token forjado (R3) | Impacto |
|---|---|---|---|
| **Header** | `{"alg": "HS256", "typ": "JWT"}` | `{"alg": "HS256", "typ": "JWT"}` | Idéntico. |
| **Claim `sub`** | `"diego"` | `"maria"` | **Cambio central de R3**. No se altera ningún privilegio; se cambia de quién dice ser el portador del token. |
| **Claim `role`** | `"user"` | `"user"` | Sin cambio, a propósito: R3 no depende de escalar rol, sino de la identidad. |
| **Firma HMAC** | `P90v5C9BokTjjd...` | `aAxRXMXJ7JLoa0...` | Recalculada con `mate123` para el nuevo payload, igual que en R2. |

#### 4. Por qué es un IDOR aunque no haya `?id=`

En el `/perfil` del Lab 07 la vulnerabilidad IDOR se veía con claridad porque el identificador del recurso ajeno viajaba explícito en la URL (`?id=`); acá no hay ningún parámetro así. El endpoint de este laboratorio determina de quién son los datos a devolver leyendo directamente `payload["sub"]` del token ya verificado, y busca ese usuario en `USUARIOS` sin ningún chequeo adicional de que la identidad declarada corresponda a quien realmente controla la sesión.

Eso es, en esencia, lo mismo que un IDOR: el servidor confía en un identificador controlado por el cliente para decidir qué registro devolver, sin comprobar la pertenencia del recurso al solicitante. La diferencia es solo **dónde** viaja ese identificador: en el Lab 07 era un parámetro de la URL; acá es un claim dentro de un token que, con el secreto comprometido, el propio atacante puede escribir. El control de acceso roto "migra" del parámetro al token porque, en un esquema stateless como este, el token *es* la sesión: no hay una base de datos de sesiones del lado del servidor contra la cual contrastar que `sub=maria` haya sido efectivamente emitido tras un login real de María.

#### 5. Alcance de la demostración y limitaciones

- **Lo demostrado:** con el secreto recuperado, cualquier identidad (`sub`) puede escribirse en un token válido y usarse contra `/perfil` para leer datos de otro usuario, sin que el endpoint distinga entre una sesión legítima y una forjada.
- **Lo que no se demostró:** no se accedió a ningún otro usuario fuera de `diego` y `maria`, que son los dos contemplados en el caso del laboratorio; no se afirma que el mismo patrón aplique a cualquier cantidad de usuarios, aunque el código de `/perfil` no distingue entre dos usuarios o mil.
- **Consecuencia en un sistema real:** si `/perfil` expusiera datos sensibles de muchos usuarios (como en este caso, "Legajo... Nota confidencial"), comprometer una sola clave de firma equivaldría a comprometer la confidencialidad de todos los perfiles del sistema, no solo del usuario que forjó el token.

## 4. Control de sanidad

En una corrida local separada contra el `Handler` original de la cátedra, el token legítimo de Diego recibió **403 Forbidden** al solicitar `/admin`: el token es válido, pero su rol `user` no autoriza el acceso. Después se tomó el token de administrador generado para R2, se cambió exactamente un carácter de su firma y se envió de nuevo; el servidor respondió **401 Unauthorized** porque el HMAC dejó de coincidir. Las respuestas crudas están en `evidencia/salidas/verificacion-controles-01/09-original-en-admin.http.txt` y `11-firma-alterada.http.txt`; el token alterado y el orden de los comandos también se conservaron en esa carpeta.

## 5. Preguntas P1–P5

### P1. Integridad y confidencialidad

**Carolina — completada.** Integridad significa detectar modificaciones del mensaje sin autorización; confidencialidad significa que terceros no puedan leerlo. En este JWT con HMAC, la firma proporciona integridad y autenticación del mensaje frente a quien **no conoce ni puede adivinar la clave**, pero no cifra el header ni el payload. No es una firma asimétrica con no repudio: la misma clave sirve para generar y verificar el MAC.

PhantomCorp tenía un mecanismo de integridad, pero lo debilitó usando un secreto de diccionario. Creía que «firmado» implicaba contenido secreto e imposible de alterar en cualquier circunstancia. R1 refuta la confidencialidad incluso sin conocer la clave. R2/R3 muestran que, recuperada la clave, se pueden cambiar claims y producir un MAC nuevo válido. Modificar un token sin recalcular correctamente el MAC no es lo mismo: ese token se rechaza con 401, como registra la prueba de firma alterada.

### P2. Por qué el crack es offline

**Carolina — completada.** El token contiene tanto el mensaje firmado como el MAC de referencia, de modo que cada candidato se comprueba localmente. No se envía un intento de login por clave: el servidor no puede aplicar rate limit, lockout ni registrar esos intentos mediante sus logs de acceso. Solo se necesita obtener inicialmente un token válido, que en este caso se consiguió con las credenciales de demo. La obtención y el uso posterior de tokens sí pueden producir tráfico observable; «offline» describe la búsqueda de la clave, no toda la cadena.

En cambio, adivinar contraseñas contra `/login` requiere peticiones por intento y podría ser detectado o limitado si se implementan esos controles. No se verificó que este servidor de práctica tenga rate limit o lockout: son posibilidades defensivas del ataque online, no resultados observados aquí. El secreto HMAC tampoco es la contraseña de Diego. Los once intentos y su medición se registran en §2; un límite sobre `/login` no impediría esa búsqueda local una vez obtenido el token.

### P3. IDOR sin parámetro `id`

Un IDOR (*Insecure Direct Object Reference*) ocurre cuando un sistema usa un identificador que el cliente controla para decidir qué recurso devolver, sin verificar que ese cliente tenga derecho sobre ese recurso en particular. En el Lab 07, ese identificador era visible y manipulable a simple vista: `GET /perfil?id=1`, `?id=2`, etc. Bastaba con cambiar el número en la URL.

Acá el mecanismo de fondo es idéntico, pero el identificador no está en la URL: está en el claim `sub` del JWT. El servidor no mantiene sesiones del lado propio; delega por completo en el token la pregunta "¿quién sos?". `_payload_o_401()` solo verifica que la firma sea válida y el token no haya expirado — eso confirma que el token fue firmado con el secreto correcto, pero no confirma que la persona que lo presenta sea realmente `maria`. Una vez pasado ese único control, `/perfil` hace `USUARIOS.get(payload["sub"])` y devuelve esos datos sin ningún otro chequeo. Con el secreto en mano (sección 2), cualquiera puede escribir el `sub` que quiera y el servidor se lo cree.

Lo que falta, entonces, es la misma autorización a nivel de objeto que faltaba en el Lab 07: comprobar que el solicitante tiene derecho sobre *ese* recurso específico, no solo que presentó *algún* credencial válido en general. La diferencia entre los dos labs no es conceptual, es de **dónde vive el identificador manipulable**: un parámetro de query en un lab, un claim de un token stateless en el otro. Eso es justo la migración que menciona la consigna: cuando la identidad del usuario pasa a ser "lo que diga el token" en vez de "lo que dice una sesión del servidor", cualquier punto donde el cliente pueda influir ese claim —incluida la posibilidad de forjarlo con un secreto débil— reabre el mismo problema de control de acceso roto, aunque la URL ya no tenga ningún `?id=` que lo delate.

### P4. Prueba con `alg:none`

Se envió a `/admin` un token con header `{"alg":"none","typ":"JWT"}`, rol `admin` y firma vacía. El servidor respondió **401 Unauthorized** (`evidencia/salidas/verificacion-controles-01/13-none.http.txt`): rechaza la ausencia de una firma válida.

Como control adicional, se conservó el mismo header `alg:none` y se calculó un HMAC-SHA256 válido para el token. Esa solicitud respondió **200 OK** (`15-none-con-hmac.http.txt`). Esto muestra que el servidor siempre comprueba HMAC, pero no verifica que el algoritmo declarado coincida con una política permitida. Un validador debe fijar los algoritmos aceptados en la aplicación, asociar cada clave al algoritmo esperado y rechazar un `alg` no permitido o inconsistente; no debe decidirlo confiando en el header del token, como recomienda RFC 8725 §3.1. La evidencia incluye ambos tokens y las respuestas crudas en `evidencia/salidas/verificacion-controles-01/`.

### P5. Defensas priorizadas

1. **Fijar y validar el algoritmo.** El servidor debe aceptar solo el algoritmo previsto para ese servicio y rechazar `none` o cualquier otro valor no permitido. Esto evita la aceptación de tokens sin firma y confusiones entre algoritmos, como el control adicional de P4. La selección no debe depender del header no confiable (RFC 8725 §3.1).
2. **Usar una clave aleatoria y fuerte.** Para HS256, generar al menos 32 bytes aleatorios criptográficamente y no una contraseña de diccionario. Esto dificulta el crack offline y evita las forjas de rol e identidad de R2 y R3. Una clave fuerte no cifra el payload ni corrige la exposición de R1 (RFC 7518 §3.2; RFC 8725 §3.5).
3. **Proteger y rotar las claves.** Guardarlas en un gestor de secretos con acceso restringido y un procedimiento de rotación. Si una clave se filtra, retirar su confianza e invalidar los tokens firmados con ella reduce el tiempo de abuso; cambiarla sin dejar de aceptar la anterior no resuelve el compromiso.
4. **Limitar los claims.** Quitar del payload `nota_interna` y cualquier dato sensible o innecesario. Un JWT firmado no es un JWT cifrado; los claims siguen siendo legibles como demuestra R1. Si un dato debe ser confidencial, no incluirlo en un JWS legible.
5. **Exigir y validar vencimiento.** Usar expiraciones cortas y comprobar `exp` (y `nbf` cuando corresponda) limita el período de uso de tokens robados o reproducidos. No impide el crack offline ni oculta el payload.
6. **Implementar revocación cuando se necesite corte inmediato.** Una lista de revocación o un estado de sesión consultado por el servidor permite invalidar un token antes de su expiración; un JWT autocontenido no se revoca automáticamente. Complementa, pero no reemplaza, la verificación criptográfica y los vencimientos.

Con HS256, quien obtiene el secreto puede firmar tokens. Con RS256 o EdDSA, los servicios consumidores pueden verificar con una clave pública mientras solo el emisor conserva la clave privada de firma, lo que reduce la cantidad de componentes capaces de crear tokens. Ninguna de esas opciones cifra el payload ni reemplaza la validación de algoritmo, claims, vencimiento y autorización.

## 6. Evidencia de progreso

Los tres retos fueron aceptados por el motor oficial; el registro de texto y la captura muestran **3/3 (100%)**. La captura real de la terminal está guardada como `evidencia/status-extra5.png`. Las verificaciones adicionales están en `evidencia/salidas/verificacion-controles-01/`, y su `comandos.txt` conserva la secuencia reproducible.

![Captura del estado del Lab Extra 5](evidencia/status-extra5.png)

## Fuentes y trazabilidad

- Consigna, entregable y rúbrica en `labs/labextra5-jwt/`; protocolo en `docs/PROTOCOLO-EVIDENCIA.md`.
- [RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2): HMAC, clave HS256 y comparación en tiempo constante.
- [RFC 7519 §3 y §4.1](https://www.rfc-editor.org/rfc/rfc7519.html): estructura y claims.
- [RFC 8725 §2.2, §3.1 y §3.5](https://www.rfc-editor.org/rfc/rfc8725.html): claves débiles y validación de algoritmos.
- Fuentes consultadas mediante el asistente el 03/11/2026; falta que Belén consulte y revise las fuentes para su sección de research.
- `evidencia/comandos.txt` enumera en orden la secuencia ejecutada y enlaza los logs detallados. Las respuestas HTTP preservan estado, cabeceras y cuerpos recibidos.
- `evidencia/salidas/base-tecnica/` conserva la primera ejecución incompleta por codificación de stdout; no respalda resultados de cracking. La base completa es `base-validada/`.
