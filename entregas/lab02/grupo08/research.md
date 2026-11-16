# Mini-research — Laboratorio 02

**Tema elegido:**

- [ ] **A.** Modos de operación de cifrado por bloques (ECB vs CBC vs GCM) y por qué ECB filtra estructura (el "pingüino" de Adobe).
- [x] **B.** HMAC y el ataque de length-extension: cómo funciona el ataque y por qué HMAC lo previene.
- [ ] **C.** Derivación de claves desde contraseñas (PBKDF2, bcrypt, scrypt, Argon2): por qué un `sha256(password)` no alcanza.
- [ ] **D.** Cifrado asimétrico y firmas digitales: qué problema resuelven que el simétrico no.

---

## Planteo y postura del grupo

Una de las trampas más persistentes en la ingeniería de software es la intuición de que combinar un secreto compartido con una función de hash criptográfica sólida (`Hash(secreto || mensaje)`) produce automáticamente un código de autenticación de mensajes seguro. La premisa intuitiva suele ser: *"si el adversario no conoce la clave, no puede calcular el hash del mensaje adulterado"*.

Nuestra postura es que esta intuición confunde las propiedades de **resistencia a la preimagen** y **resistencia a colisiones** con la propiedad de **autenticación de mensajes (función pseudoaleatoria o PRF)**. Debido a la arquitectura interna iterativa con la que se diseñaron las principales funciones de hash de los últimos treinta años (MD5, SHA-1, SHA-256), la salida pública de la función revela la totalidad de su estado interno. El ataque de extensión de longitud (*length-extension attack*) explota esa transparencia para vulnerar la autenticidad del canal sin romper el algoritmo de compresión. Comprender por qué HMAC previene este ataque y cómo las construcciones modernas de esponja (SHA-3) lo eliminan desde su raíz es indispensable para cualquier desarrollador que diseñe arquitecturas de comunicación segura.

---

## Desarrollo

### 1. La construcción Merkle-Damgård y la arquitectura de estado expuesto

La inmensa mayoría de las funciones de hash utilizadas en la actualidad descienden del principio de diseño formulado de manera independiente por Ralph Merkle y Ivan Damgård en CRYPTO '89 (Merkle, 1989; Damgård, 1989). El principio establece que si se dispone de una función de compresión $f: \{0,1\}^b \times \{0,1\}^c \to \{0,1\}^c$ resistente a colisiones sobre bloques de longitud fija, se puede extender inductivamente a una función de hash para mensajes de longitud arbitraria:

1. **Fragmentación y relleno (*padding*):** El mensaje de entrada se extiende mediante una regla de relleno reversible (*Merkle-Damgård strengthening*): se concatena un bit `1`, una secuencia suficiente de ceros `0`, y un entero de 64 o 128 bits que codifica la longitud exacta del mensaje original antes del relleno. Esto garantiza que la longitud total sea un múltiplo exacto del tamaño de bloque $b$ (512 bits / 64 bytes en SHA-256).
2. **Encadenamiento iterativo:** Partiendo de un Vector de Inicialización público prefijado ($IV = H_0$), se evalúa la función de compresión $f$ en cascada:
   $$H_i = f(H_{i-1}, M_i) \quad \text{para } i = 1, \dots, n$$
3. **Digest de salida:** El valor final del hash es simplemente el último estado: $H(M) = H_n$.

El talón de Aquiles de esta construcción respecto a la autenticación ingenua es que **el digest resultante es idéntico al estado interno de la función de compresión tras procesar el último bloque**. No interviene ninguna transformación final que dependa de un secreto, ni se ocultan registros internos. Para la función de compresión, haber terminado un mensaje o estar a mitad de camino procesando bloques adicionales de un mensaje más largo es exactamente la misma operación.

---

### 2. Anatomía del ataque de Length-Extension en escenarios reales

Supongamos el esquema ingenuo de autenticación prefijada de clave (*secret-prefix MAC*):
$$\text{MAC}(M) = H(K \parallel M)$$

Un atacante en la red intercepta el mensaje en claro $M$ y su firma legítima $T = H(K \parallel M)$. Aunque el atacante desconoce $K$, la estructura Merkle-Damgård le permite extender el mensaje del siguiente modo:

1. **Reconstrucción del relleno original:** Aunque el atacante no conoce los bytes específicos de $K$, solo necesita conocer (o deducir probando valores comunes de 8 a 64 bytes) la **longitud** de la clave $|K|$. Con $|K|$ y $|M|$, el atacante reconstruye el padding exacto que la función aplicó internamente a $(K \parallel M)$:
   $$\text{pad} = \text{padding}(|K| + |M|)$$
2. **Inyección de estado:** El atacante divide el digest interceptado $T$ en los registros de trabajo de la función de hash (por ejemplo, los ocho enteros de 32 bits $A, B, C, D, E, F, G, H$ en SHA-256). Inicializa una nueva instancia de la función de hash configurando esos valores como el estado inicial $H_0'$, en lugar del $IV$ estándar.
3. **Absorción de la carga maliciosa:** El atacante procesa un bloque de datos arbitrario $M_{\text{extra}}$ que favorezca sus intereses (por ejemplo, `&role=admin` o `&transfer=1000000`), calculando:
   $$T' = f(T, M_{\text{extra}} \parallel \text{pad}')$$
4. **Falsificación exitosa:** El mensaje compuesto transmitido es:
   $$M' = M \parallel \text{pad} \parallel M_{\text{extra}}$$
   Cuando el receptor legítimo recalcula el MAC sobre $M'$ con la clave secreta $K$, computa:
   $$H(K \parallel M \parallel \text{pad} \parallel M_{\text{extra}})$$
   Dado que el estado interno tras procesar $K \parallel M \parallel \text{pad}$ es precisamente $T$, la función continuará comprimiendo $M_{\text{extra}}$ y llegará exactamente al mismo digest $T'$ obtenido por el atacante. El servidor acepta la petición como genuina, quedando comprometida la **autenticidad**.

#### Impacto en la práctica: El caso de la API de Flickr (2009)
Este vector no es una debilidad teórica de laboratorio. En 2009, los investigadores Thai Duong y Juliano Rizzo descubrieron que la API REST de Flickr utilizaba para firmar sus solicitudes el esquema `MD5(secret || arg1=val1&arg2=val2...)` (Duong & Rizzo, 2009). Utilizando la técnica de extensión de longitud, demostraron que cualquier usuario con una petición firmada con permisos de sólo lectura (`perms=read`) podía inyectar `&perms=delete` o `&perms=write` junto con el relleno MD5, falsificando una firma válida y adquiriendo control total sobre cuentas ajenas sin conocer jamás el secreto del servidor.

---

### 3. La solución demostrada: HMAC y el modelo PRF

Para resolver de manera definitiva las fallas de las composiciones ad-hoc, Mihir Bellare, Ran Canetti y Hugo Krawczyk publicaron en CRYPTO '96 el diseño de HMAC (Bellare et al., 1996), estandarizado posteriormente en la RFC 2104 (Krawczyk et al., 1997) y en NIST FIPS PUB 198-1 (NIST, 2008).

HMAC aplica una arquitectura anidada de doble hash (*nested MAC*):
$$\text{HMAC}(K, M) = H\Big((K' \oplus opad) \;\parallel\; H\big((K' \oplus ipad) \;\parallel\; M\big)\Big)$$

Donde $K'$ es la clave normalizada a un bloque de tamaño $B$ (64 bytes en SHA-256), e $ipad$ (`0x36`) y $opad$ (`0x5c`) son constantes fijas que derivan dos claves internas con alta distancia de Hamming:
$$K_{\text{in}} = K' \oplus ipad, \quad K_{\text{out}} = K' \oplus opad$$

#### Por qué previene el ataque estructuralmente
1. **Aislamiento del mensaje mediante anidamiento:** El mensaje $M$ es procesado exclusivamente dentro del hash interno:
   $$H_{\text{in}} = H(K_{\text{in}} \parallel M)$$
   El atacante nunca ve $H_{\text{in}}$. Lo que se expone al canal de comunicación es el hash externo:
   $$T = H(K_{\text{out}} \parallel H_{\text{in}})$$
2. **Ruptura de la cadena de extensión:** Si el adversario intenta extender el hash externo visible $T$, solo podría añadir datos a continuación de $H_{\text{in}}$, es decir:
   $$H(K_{\text{out}} \parallel H_{\text{in}} \parallel \text{pad} \parallel M_{\text{extra}})$$
   Esto alteraría los parámetros del hash exterior, pero es incapaz de inyectar bytes dentro de $M$, pues $M$ ya fue transformado en el digest irrevocable $H_{\text{in}}$.
3. **Resistencia a la preimagen en el hash externo:** Para extender $M$ en la fase interna, el atacante requeriría conocer $H_{\text{in}}$ para utilizarlo como estado inicial. Pero recuperar $H_{\text{in}}$ a partir de $T$ requeriría invertir la función de hash externa ($H$), lo cual está protegido por la resistencia a la preimagen ($2^{256}$ operaciones para SHA-256).
4. **Seguridad formal:** Bellare et al. (1996) demostraron mediante reducción formal que HMAC es un generador de funciones pseudoaleatorias (PRF) seguro siempre que la función de compresión $f$ subyacente se comporte como un PRF, incluso si la función de hash como un todo carece de resistencia a ataques de extensión de longitud.

---

### 4. Más allá de Merkle-Damgård: La construcción Esponja (SHA-3 / KMAC)

La necesidad de añadir una capa externa como HMAC para autenticar mensajes es en realidad un síntoma de las limitaciones de Merkle-Damgård. Al estandarizar **SHA-3** en 2015 (FIPS PUB 202), el NIST seleccionó el algoritmo Keccak, basado en la **construcción de esponja** (*sponge construction*) diseñada por Guido Bertoni, Joan Daemen, Michaël Peeters y Gilles Van Assche.

En una esponja criptográfica, el estado interno es significativamente mayor que el bloque de salida (por ejemplo, 1600 bits en Keccak). El estado se divide en dos componentes:
- La **tasa** (*rate*, $r$): la porción del estado que absorbe los bloques del mensaje mediante operaciones XOR.
- La **capacidad** (*capacity*, $c$): una porción interna del estado que **nunca se expone ni interactúa directamente con los datos de entrada**.

Durante la fase de absorción (*absorbing*), los bloques del mensaje se combinan con $r$ y se permutan mediante transformaciones no lineales de difusión y confusión. Durante la fase de exprimido (*squeezing*), se extraen bloques de longitud $r$ como salida del digest.

Dado que la capacidad interna $c$ permanece secreta y oculta, un adversario que observe la salida del hash **no puede reconstruir el estado completo de 1600 bits** de la esponja. Por lo tanto, SHA-3 es **inmune por definición al ataque de length-extension**. Esto permite que en estándares basados en SHA-3 (como KMAC en NIST SP 800-185), la autenticación de mensajes pueda implementarse simplemente concatenando la clave con el mensaje (`KMAC(K, M) = Keccak(K || M)`), alcanzando la máxima eficiencia sin la complejidad del doble hash de HMAC.

---

## Tensión y límites

A pesar de su solidez matemática, HMAC y los códigos de autenticación presentan límites de seguridad y diseño que no deben pasarse por alto en la arquitectura de sistemas:

1. **Autenticidad no implica confidencialidad:** HMAC garantiza que el mensaje no fue modificado y que proviene de alguien que posee la clave, pero el mensaje viaja en texto claro. Para proteger confidencialidad e integridad simultáneamente se debe recurrir a esquemas de cifrado autenticado (AEAD como AES-GCM o ChaCha20-Poly1305), evitando composiciones manuales propensas a errores.
2. **Dependencia del secreto simétrico y no repudio:** Al ser una primitiva simétrica, tanto el emisor como el receptor comparten la misma clave $K$. En caso de litigio, HMAC no proporciona **no repudio**: el receptor puede generar mensajes falsos idénticos a los del emisor, ya que ambos conocen la clave. Para garantizar no repudio frente a terceros es obligatorio recurrir a firmas digitales asimétricas (RSA, ECDSA, Ed25519).
3. **Vulnerabilidades de implementación (canales laterales):** Un diseño HMAC perfecto resulta completamente vulnerable si la verificación en el servidor se implementa con comparadores que no operen en tiempo constante (como se analizó en la Parte B.2.3 del informe). La seguridad de un sistema criptográfico es siempre igual a la seguridad del eslabón más débil en su pila de implementación.

---

## Reflexión

El estudio del ataque de extensión de longitud y la génesis de HMAC deja una lección indeleble: en seguridad informática, las propiedades criptográficas no se transfieren mágicamente al combinar primitivas. Una función de hash no es un sustituto de un MAC, del mismo modo que un cifrado por bloques no es un sustituto de una firma digital. La ingeniería de software segura exige abandonar el desarrollo criptográfico artesanal (*"roll your own crypto"*), adoptar estándares rigurosamente evaluados como HMAC o AEAD, y comprender en profundidad los supuestos y limitaciones sobre los que reposa cada algoritmo.

---

## Fuentes

1. Bellare, M., Canetti, R., & Krawczyk, H. (1996). Keying hash functions for message authentication. En N. Koblitz (Ed.), *Advances in Cryptology — CRYPTO '96* (LNCS 1109, pp. 1–15). Springer. https://doi.org/10.1007/3-540-68697-5_1 — **Arbitrada** (paper fundacional de HMAC en conferencia con revisión por pares).
2. Krawczyk, H., Bellare, M., & Canetti, R. (1997). *HMAC: Keyed-hashing for message authentication* (RFC 2104). Internet Engineering Task Force (IETF). https://www.rfc-editor.org/rfc/rfc2104 — **Primaria** (estándar oficial de Internet).
3. National Institute of Standards and Technology. (2008). *The Keyed-Hash Message Authentication Code (HMAC)* (FIPS PUB 198-1). U.S. Department of Commerce. https://doi.org/10.6028/NIST.FIPS.198-1 — **Primaria** (estándar federal estadounidense).
4. National Institute of Standards and Technology. (2015). *SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions* (FIPS PUB 202). U.S. Department of Commerce. https://doi.org/10.6028/NIST.FIPS.202 — **Primaria** (estándar oficial de funciones de hash por esponja).
5. Duong, T., & Rizzo, J. (2009). *Flickr's API signature forgery vulnerability* [Informe técnico]. Netifera. http://netifera.com/research/flickr_api_signature_forgery.pdf (sitio fuera de línea; copia archivada: https://web.archive.org/web/2010/http://netifera.com/research/flickr_api_signature_forgery.pdf) — **Primaria** (informe técnico de los propios investigadores que descubrieron la vulnerabilidad; sin revisión por pares).
6. Merkle, R. C. (1989). A certified digital signature. En G. Brassard (Ed.), *Advances in Cryptology — CRYPTO '89* (LNCS 435, pp. 218–238). Springer. https://doi.org/10.1007/0-387-34805-0_21 — **Arbitrada** (paper fundacional de la construcción Merkle-Damgård).
7. Damgård, I. B. (1989). A design principle for hash functions. En G. Brassard (Ed.), *Advances in Cryptology — CRYPTO '89* (LNCS 435, pp. 416–427). Springer. https://doi.org/10.1007/0-387-34805-0_39 — **Arbitrada** (paper fundacional de la construcción Merkle-Damgård).

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Antigravity (Google) y Claude (Anthropic) | Asistencia en la estructuración de conceptos formales (Merkle-Damgård vs. Sponge), redacción técnica y sugerencia de fuentes bibliográficas primarias y arbitradas. | Redacción general del mini-research. | El grupo revisó exhaustivamente cada párrafo, verificó las fórmulas matemáticas contra los estándares RFC 2104 y FIPS 198-1, y constató individualmente cada una de las referencias citadas ingresando a sus respectivos enlaces y DOIs. |

**Verificación de fuentes:** El grupo declara haber accedido, consultado y validado individualmente cada una de las fuentes primarias y arbitradas referenciadas en este documento.
