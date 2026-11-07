# Mini-research — Laboratorio 02

**Tema elegido:** *(uno)*

- [x] **A.** Modos de operación de cifrado por bloques (ECB vs CBC vs GCM) y por
  qué ECB filtra estructura (el "pingüino" de Adobe).
- [ ] **B.** HMAC y el ataque de length-extension: cómo funciona el ataque y por
  qué HMAC lo previene.
- [ ] **C.** Derivación de claves desde contraseñas (PBKDF2, bcrypt, scrypt,
  Argon2): por qué un `sha256(password)` no alcanza.
- [ ] **D.** Cifrado asimétrico y firmas digitales: qué problema resuelven que el
  simétrico no.

## Desarrollo

### 1. ¿Qué son los modos de operación de cifrado por bloques?

Los algoritmos de cifrado simétrico por bloques, como AES, procesan la información en bloques de tamaño fijo. AES utiliza bloques de 128 bits, independientemente de que se utilicen claves de 128, 192 o 256 bits.

Sin embargo, cifrar un mensaje completo requiere definir cómo se procesan sus bloques y cómo se relacionan entre sí. Para eso existen los **modos de operación**.

Un modo de operación determina cómo se transforma un conjunto de bloques de texto plano en bloques cifrados. Por lo tanto, aunque AES sea un algoritmo criptográfico robusto, utilizarlo con un modo inadecuado puede provocar filtraciones de información o permitir modificaciones no detectadas [1].

### 2. Modo ECB (Electronic Codebook)

ECB es el modo de operación más sencillo. Divide el mensaje en bloques independientes y cifra cada uno utilizando la misma clave.

Su principal problema es que **dos bloques de texto plano idénticos producen exactamente el mismo bloque cifrado**.

Esto permite que un atacante que observa el texto cifrado pueda identificar patrones y repeticiones de la información original, aunque no conozca la clave.

Por ejemplo, si una imagen contiene grandes regiones del mismo color, los bloques correspondientes pueden repetirse. Al cifrarla utilizando ECB, esos patrones permanecen visibles en el resultado.

**El caso del pingüino:**

El ejemplo más conocido de esta debilidad consiste en cifrar una imagen del pingüino de Linux utilizando AES en modo ECB. Aunque los píxeles se cifran, las estructuras y los contornos generales de la imagen continúan siendo reconocibles.

<https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)>

Esta debilidad también tuvo consecuencias reales en el incidente de seguridad de Adobe de 2013. La compañía almacenaba contraseñas cifradas mediante Triple DES en modo ECB, utilizando una misma clave para todos los registros.

Debido a este diseño, contraseñas idénticas producían textos cifrados idénticos. Los investigadores pudieron agrupar contraseñas repetidas y relacionarlas con pistas almacenadas en texto plano, lo que permitió identificar numerosas contraseñas sin necesidad de recuperar la clave criptográfica [2].

La lección es que un algoritmo de cifrado puede ser seguro y, aun así, utilizarse de una manera que filtre información sensible.

### 3. Modo CBC (Cipher Block Chaining)

CBC fue diseñado para evitar que los bloques idénticos del mensaje produzcan siempre el mismo resultado cifrado.

Para conseguirlo, cada bloque de texto plano se combina mediante XOR con el bloque cifrado anterior antes de aplicar el algoritmo de cifrado.

El primer bloque utiliza un **vector de inicialización (IV)**, que introduce variabilidad desde el comienzo del proceso.

Su funcionamiento puede representarse mediante:

```text
C1 = AES(K, P1 XOR IV)
C2 = AES(K, P2 XOR C1)
C3 = AES(K, P3 XOR C2)
```

Donde:

- K: clave secreta.
- P: bloque de texto plano.
- C: bloque cifrado.
- IV: vector de inicialización.

De esta manera, dos mensajes iguales pueden producir resultados diferentes si utilizan distintos IV.

Sin embargo, CBC tiene algunas limitaciones importantes:

- Necesita un IV impredecible y único para cada cifrado bajo la misma clave.
- Requiere padding cuando el mensaje no tiene una longitud múltiplo del tamaño del bloque.
- No proporciona autenticación ni garantiza por sí mismo la integridad del mensaje.
- Una modificación del texto cifrado puede provocar alteraciones en el texto descifrado.

Por estas razones, CBC debe combinarse con un mecanismo de autenticación independiente, implementando correctamente el esquema de cifrado y autenticación [1].

### 4. Modo GCM (Galois/Counter Mode)

GCM es un modo de operación que proporciona **cifrado autenticado con datos asociados (AEAD)**.

A diferencia de ECB y CBC, GCM no solamente protege la confidencialidad, sino que también permite verificar la integridad y autenticidad de los datos cifrados.

Combina el funcionamiento del modo Counter (CTR), utilizado para cifrar los datos, con un mecanismo de autenticación basado en operaciones matemáticas sobre el campo de Galois.

Sus principales características son:

- Proporciona confidencialidad mediante cifrado.
- Genera una etiqueta de autenticación (*authentication tag*).
- Permite detectar modificaciones del texto cifrado.
- Permite autenticar datos adicionales que no necesitan cifrarse, conocidos como AAD.
- No requiere padding como CBC.

Un aspecto fundamental de GCM es el uso de un **nonce único** para cada operación de cifrado con una misma clave. Reutilizarlo puede comprometer gravemente tanto la confidencialidad como la autenticidad de los mensajes [3].

Por estas características, GCM es una alternativa ampliamente utilizada en protocolos y aplicaciones modernas que necesitan proteger tanto los datos como su integridad.

### 5. Comparación entre ECB, CBC y GCM

| Característica | ECB | CBC | GCM |
|---|---|---|---|
| Confidencialidad | Sí, pero filtra patrones | Sí | Sí |
| Integridad | No | No | Sí |
| Autenticación | No | No | Sí |
| IV / Nonce | No utiliza | IV impredecible | Nonce único |
| Padding | Sí | Sí | No |
| Detecta modificaciones | No | No | Sí |

La principal diferencia es que ECB cifra cada bloque de manera independiente, CBC introduce una dependencia entre bloques y GCM incorpora además un mecanismo de autenticación.

En aplicaciones actuales, GCM suele ser una opción preferible cuando se necesita cifrado autenticado, siempre que se respeten sus requisitos de implementación, especialmente la unicidad del nonce.

---

## Fuentes

[1] National Institute of Standards and Technology (NIST), Morris Dworkin, *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*, Special Publication 800-38A, 2001.

https://csrc.nist.gov/pubs/sp/800/38/a/final

[2] Dan Goodin, *How Adobe's messy password breach can spill to sites like Diapers.com*, Ars Technica, noviembre de 2013.

https://arstechnica.com/information-technology/2013/11/how-adobes-messy-password-breach-can-spill-to-sites-like-diapers-com/

[3] National Institute of Standards and Technology (NIST), Morris Dworkin, *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, Special Publication 800-38D, 2007.

https://csrc.nist.gov/pubs/sp/800/38/d/final

[4] Adobe, Brad Arkin, *Important Customer Security Announcement*, 3 de octubre de 2013.

https://blog.adobe.com/en/publish/2013/10/03/important-customer-security-announcement

---

## Reflexión

Esta investigación me permitió comprender que la seguridad de un sistema criptográfico no depende únicamente de utilizar un algoritmo robusto como AES, sino también de seleccionar correctamente su modo de operación. El caso de Adobe demuestra cómo una implementación inadecuada puede permitir que los atacantes obtengan información útil sin necesidad de romper el algoritmo de cifrado. Me resultó especialmente interesante observar cómo ECB conserva patrones visibles incluso cuando los datos están cifrados. Como conclusión, considero que GCM representa una alternativa más completa para aplicaciones modernas, porque combina confidencialidad, integridad y autenticación en un mismo mecanismo.