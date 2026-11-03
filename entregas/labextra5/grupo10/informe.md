# Informe — Laboratorio Extra 5: JWT inseguro

**Grupo:** 10 · **Fecha de la corrida técnica:** 03/11/2026.

**Integrantes:** Carolina Paula Corazza (`@carocor1`), Juan Pablo Saby (`@JuanSaby`), Belén Rocío Ramello (`@belramello`) y Chiara Agustina Kordek (`@chiarakordek`).

**Estado de preparación:** implementación y secciones de Carolina preparadas con asistencia de IA; falta completar las secciones asignadas a Juan, Belén y Chiara, la revisión humana grupal y adjuntar la captura solicitada del status. Este archivo todavía no es una entrega grupal cerrada.

**Declaración de uso de IA:** se utilizó OpenCode (GPT-6 Luna) para revisar requisitos, implementar las cuatro funciones de `jwt_tool.py`, generar pruebas y scripts de reproducción, ejecutar la verificación técnica local y asistir en la redacción de este informe. Las partes asistidas incluyen código, evidencia automatizada y análisis. La verificación técnica consistió en 10 pruebas unitarias y peticiones HTTP contra el `Handler` original de la cátedra; las salidas están adjuntas. Se contrastaron conceptos con RFC 7518, RFC 7519 y RFC 8725. Esto no sustituye la revisión humana de cada integrante, que deberá actualizar esta declaración si usa otras herramientas.

**Alcance y entorno:** caso ficticio autorizado de la cátedra, **sin Docker** como indica la consigna; no se instalaron dependencias externas. Python 3.12.10, Windows 11. El reproductor importa el `Handler` original sin modificar y lo sirve en `127.0.0.1` en puerto libre, en lugar de exponerlo en `0.0.0.0:8080`. En la corrida usada fue `127.0.0.1:54232`. No se probaron sistemas de terceros. El hash del archivo original y los detalles del entorno están en `evidencia/salidas/base-validada/00-entorno.json`.

## 1. Anatomía del token real

**Responsable: Carolina (con asistencia de IA; pendiente de revisión y defensa personal).**

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

**Responsable: Carolina (con asistencia de IA; pendiente de revisión y defensa personal).**

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

**Pendiente de completar por Juan Pablo:** documentar el token forjado para R2, el comando utilizado, la respuesta observada en `/admin` con la flag y el cambio conceptual respecto del token original. La evidencia técnica común está en `evidencia/salidas/base-validada/`; todavía no se atribuye una reproducción personal a Juan.

### R3 — Suplantación horizontal (sub=maria)

**Pendiente de completar por Belén:** documentar el token forjado para R3, la respuesta observada en `/perfil` con los datos de María y explicar por qué el acceso inseguro es un IDOR aunque no haya un parámetro `?id=`. La evidencia técnica común está en `evidencia/salidas/base-validada/`; todavía no se atribuye una reproducción personal a Belén.

## 4. Control de sanidad

**Pendiente de completar por Chiara:** mostrar que el token original de Diego recibe 403 en `/admin` y que un token forjado con un carácter alterado en la firma recibe 401. La evidencia técnica común está en `evidencia/salidas/base-validada/09-original-en-admin.http.txt` y `11-firma-alterada.http.txt`. Estos dos controles son obligatorios según la rúbrica.

## 5. Preguntas P1–P5

### P1. Integridad y confidencialidad

**Carolina — completada.** Integridad significa detectar modificaciones del mensaje sin autorización; confidencialidad significa que terceros no puedan leerlo. En este JWT con HMAC, la firma proporciona integridad y autenticación del mensaje frente a quien **no conoce ni puede adivinar la clave**, pero no cifra el header ni el payload. No es una firma asimétrica con no repudio: la misma clave sirve para generar y verificar el MAC.

PhantomCorp tenía un mecanismo de integridad, pero lo debilitó usando un secreto de diccionario. Creía que «firmado» implicaba contenido secreto e imposible de alterar en cualquier circunstancia. R1 refuta la confidencialidad incluso sin conocer la clave. R2/R3 muestran que, recuperada la clave, se pueden cambiar claims y producir un MAC nuevo válido. Modificar un token sin recalcular correctamente el MAC no es lo mismo: ese token se rechaza con 401, como registra la prueba de firma alterada.

### P2. Por qué el crack es offline

**Carolina — completada.** El token contiene tanto el mensaje firmado como el MAC de referencia, de modo que cada candidato se comprueba localmente. No se envía un intento de login por clave: el servidor no puede aplicar rate limit, lockout ni registrar esos intentos mediante sus logs de acceso. Solo se necesita obtener inicialmente un token válido, que en este caso se consiguió con las credenciales de demo. La obtención y el uso posterior de tokens sí pueden producir tráfico observable; «offline» describe la búsqueda de la clave, no toda la cadena.

En cambio, adivinar contraseñas contra `/login` requiere peticiones por intento y podría ser detectado o limitado si se implementan esos controles. No se verificó que este servidor de práctica tenga rate limit o lockout: son posibilidades defensivas del ataque online, no resultados observados aquí. El secreto HMAC tampoco es la contraseña de Diego. Los once intentos y su medición se registran en §2; un límite sobre `/login` no impediría esa búsqueda local una vez obtenido el token.

### P3. IDOR sin parámetro `id`

**Pendiente de completar por Belén:** responder P3 conectando la suplantación del claim `sub` con IDOR del Lab 07 y explicar qué autorización a nivel de objeto falta en el endpoint `/perfil`.

### P4. Prueba con `alg:none`

**Pendiente de completar por Chiara:** reportar el resultado observado al enviar un token `alg:none` con firma vacía y explicar por qué un validador correcto debe fijar una lista permitida de algoritmos en la aplicación, verificar la firma según esa política y rechazar los no admitidos, sin confiar en el `alg` provisto por el token.

### P5. Defensas priorizadas

**Pendiente de completar por Chiara:** ordenar por prioridad las defensas indicadas en P5 (secreto, algoritmo, rotación, claims mínimos, expiración y revocación) y asociar cada una con el reto o riesgo que mitiga. Distinguir qué impide el crack/forja, qué reduce exposición y qué limita abuso de tokens ya emitidos.

## 6. Evidencia de progreso

Los tres retos fueron aceptados por el motor oficial en la corrida técnica común. El estado textual devuelto por el motor está conservado en `evidencia/salidas/base-validada/ctf-status-extra5.txt`. **Pendiente de completar por Chiara:** adjuntar una captura real y legible de `./ctf status extra5` que muestre los tres ✓, guardarla como `evidencia/status-extra5.png` y enlazarla aquí. No sustituir la captura pedida por el log de texto.

## Fuentes y trazabilidad

- Consigna, entregable y rúbrica en `labs/labextra5-jwt/`; protocolo en `docs/PROTOCOLO-EVIDENCIA.md`.
- [RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2): HMAC, clave HS256 y comparación en tiempo constante.
- [RFC 7519 §3 y §4.1](https://www.rfc-editor.org/rfc/rfc7519.html): estructura y claims.
- [RFC 8725 §2.2, §3.1 y §3.5](https://www.rfc-editor.org/rfc/rfc8725.html): claves débiles y validación de algoritmos.
- Fuentes consultadas mediante el asistente el 03/11/2026; falta que Belén consulte y revise las fuentes para su sección de research.
- `evidencia/comandos.txt` enumera en orden la secuencia ejecutada y enlaza los logs detallados. Las respuestas HTTP preservan estado, cabeceras y cuerpos recibidos.
- `evidencia/salidas/base-tecnica/` conserva la primera ejecución incompleta por codificación de stdout; no respalda resultados de cracking. La base completa es `base-validada/`.
