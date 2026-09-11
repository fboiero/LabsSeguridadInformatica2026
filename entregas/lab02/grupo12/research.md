# Mini-research — Laboratorio 02

**Tema elegido:** **B.** HMAC y el ataque de length-extension: cómo funciona el ataque y por qué HMAC lo previene.

- [x] **B.** HMAC y el ataque de length-extension: cómo funciona el ataque y por qué HMAC lo previene.

## Desarrollo

La forma ingenua `MAC = SHA-256(clave || mensaje)` es insegura porque SHA-256 usa la construcción Merkle-Damgård: procesa la entrada en bloques de 512 bits con una función de compresión iterativa y el digest final **es** el estado interno tras el último bloque acolchado, sin transformación secreta posterior. Quien intercepta un par mensaje/tag recibe entonces el estado completo de la compresión tras `clave || mensaje || pad_1`. Conociendo o estimando solo la longitud de la clave, el atacante reconstruye `pad_1`, carga ese estado como IV propio y continúa el hash con bytes arbitrarios `M_extra` más su `pad_2`. El resultado es idéntico a `SHA-256(clave || M || pad_1 || M_extra)`: una firma válida para un mensaje extendido sin haber conocido jamás la clave. En el laboratorio esto se demuestra conceptualmente con `mac_ingenuo()` (`hashlib.sha256(clave + msg)`): ante `accion=transferir&monto=100&para=juan` el atacante puede forjar `...juan<pad1>&para=atacante&monto=100000` y, como la mayoría de los parsers toma el último valor de claves duplicadas, el servidor valida y ejecuta a favor del atacante.

HMAC (Krawczyk, Bellare y Canetti, 1997; RFC 2104, instanciado para SHA-256 en RFC 4231) corta ese camino estructuralmente con un doble hash: `HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))`, con `K'` normalizada al bloque e `ipad/opad` en `0x36/0x5c`. La clave nunca va como prefijo directo del flujo comprimido y el digest expuesto es el del hash externo, cuyo estado no sirve para continuar el interno donde vive el mensaje. Para extender, el atacante necesitaría el intermedio `H((K' XOR ipad) || M)` —nunca expuesto— o la clave misma. Por eso en `cripto.py` `mac --modo hmac` (`hmac.new(clave, msg, hashlib.sha256)`) da para `secreta`/`pago 100` el tag `5ec4a52...b902e`, distinto del ingenuo `a8cc54c0...`, y solo el primero resiste la reanudación. El complemento obligatorio es verificar con `hmac.compare_digest`: `==` hace retorno temprano y filtra por tiempo cuántos bytes iniciales se acertaron (oráculo temporal byte a byte), mientras `compare_digest` recorre todo con igual costo y cierra ese canal lateral.

## Fuentes (mín. 3, verificables)

1. Krawczyk, H., Bellare, M. y Canetti, R. (1997). *RFC 2104: HMAC: Keyed-Hashing for Message Authentication*. IETF. https://www.rfc-editor.org/rfc/rfc2104
2. Nystrom, M. (2005). *RFC 4231: Identifiers and Test-Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512*. IETF. https://www.rfc-editor.org/rfc/rfc4231
3. National Institute of Standards and Technology. (2012). *FIPS PUB 180-4: Secure Hash Standard (SHS)*. U.S. Department of Commerce. https://doi.org/10.6028/NIST.FIPS.180-4
4. Dang, Q. H. (2008). *NIST SP 800-107 Rev. 1: Recommendation for Applications Using Approved Hash Algorithms*. NIST. https://doi.org/10.6028/NIST.SP.800-107r1

## Reflexión (3–5 líneas)

La lección es la del curso entero: el algoritmo (SHA-256) estaba sano, el *uso* (`hash(clave||msg)`) no. HMAC muestra que la seguridad sale de la construcción —doble hash con pads que aíslan la clave del estado reutilizable— y de los detalles operativos como comparar en tiempo constante. Un MAC bien diseñado no es el que "se ve complicado", sino el que le quita al atacante tanto el estado interno como el oráculo temporal.
