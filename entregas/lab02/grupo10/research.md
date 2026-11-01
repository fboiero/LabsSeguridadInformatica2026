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

Un cifrador por bloques transforma, mediante una clave secreta, bloques de tamaño fijo en bloques cifrados del mismo tamaño. [1]
Por ejemplo, AES trabaja con bloques de 128 bits; ese tamaño no debe confundirse con la longitud de su clave. [3]
Para proteger mensajes más largos hace falta establecer cómo se aplica el cifrador a los distintos bloques.
Esa organización se llama **modo de operación**: no cambia el algoritmo base, sino cómo se lo utiliza. [1]
La elección importa porque ocultar el contenido no equivale a detectar modificaciones: ECB y CBC no autentican por sí solos, mientras que GCM integra esa protección. [1][2]

### ECB: cifra los bloques, pero deja ver patrones

En **ECB** (Electronic Codebook), cada bloque se cifra independientemente con la misma clave. Esto permite paralelizar el cifrado y el descifrado, pero dos bloques de texto iguales producen bloques cifrados iguales: se reconocen repeticiones sin conocer la clave. [1, §6.1]

El ejemplo clásico es una imagen sin comprimir del pingüino **Tux**: al cifrar sus píxeles con ECB y conservar la cabecera para visualizarla, todavía se reconoce la silueta. Las zonas repetidas siguen produciendo patrones repetidos. Es una demostración del problema, no una imagen extraída de Adobe. [4]

En el caso **Adobe de 2013**, la base filtrada contenía contraseñas cifradas con **Triple DES (3DES) en ECB**, en lugar de hashes con salt. Contraseñas iguales daban resultados iguales; al agruparlas y comparar sus pistas, almacenadas en claro, se podían inferir contraseñas sin recuperar la clave de cifrado. [5][6] Además, ECB no aporta integridad: no permite comprobar que los datos no fueron alterados. [1]

### CBC: encadena los bloques, pero no los autentica

En **CBC** (Cipher Block Chaining), antes de cifrar cada bloque se lo combina mediante XOR con el bloque cifrado anterior. Para el primero se utiliza un **vector de inicialización (IV)**. Por mensaje debe generarse un IV impredecible, por ejemplo con un generador aleatorio criptográficamente seguro; no necesita ser secreto. Este encadenamiento evita la filtración directa de repeticiones característica de ECB. [1, §6.2 y apéndice C]

El cifrado es secuencial porque necesita el resultado anterior; el descifrado sí puede paralelizarse. CBC convencional necesita bloques completos, por lo que para longitudes arbitrarias se agrega **padding**. Una opción es **PKCS#7**, que rellena con bytes cuyo valor indica cuántos se agregaron; no es el único esquema posible. [1, §5.2 y §6.2][9, §6.3]

CBC solo no autentica: cambiar bits de un bloque cifrado altera predeciblemente los mismos bits del siguiente bloque al descifrar y corrompe el actual. [1, apéndice D] Si el receptor revela si el padding es válido, funciona como un **padding oracle** que puede permitir recuperar información mediante consultas. **Serge Vaudenay estudió este problema en 2002**. [7] **POODLE** explota el manejo del padding de CBC en **SSL 3.0**; no toda implementación de CBC es automáticamente vulnerable. [8]

### GCM: confidencialidad e integridad juntas

**GCM** (Galois/Counter Mode) es un modo de **cifrado autenticado con datos asociados (AEAD)**. Combina cifrado basado en contadores, como CTR, con **GHASH**, que interviene en el cálculo de una etiqueta de autenticación. Así integra confidencialidad e integridad en una misma operación y permite paralelizar el procesamiento. [2, §3 y §6–7]

También admite **AAD**: datos que se autentican, pero no se cifran, como una cabecera. El receptor debe verificar la etiqueta y rechazar el mensaje si la comprobación falla. [2, §5.2 y §7.2]

Su requisito crítico es un **nonce único para cada cifrado con la misma clave**, típicamente de **96 bits**. No necesita ser impredecible como el IV de CBC: puede construirse con un contador administrado para no repetirse. Reutilizarlo puede romper la confidencialidad y permitir falsificar etiquetas; usar GCM no compensa una mala gestión del nonce. [2, §5.2.1.1, §8 y apéndice A]

### Comparación

Las propiedades técnicas resumen [1][2][7][8]; las recomendaciones se fundamentan en esas limitaciones y en encrypt-then-MAC. [10]

| Propiedad | ECB | CBC | GCM |
|---|---|---|---|
| Paralelizable | Sí, cifrado y descifrado | Cifrado no; descifrado sí | Sí, cifrado y descifrado |
| Necesita IV/nonce | No | IV impredecible por mensaje | Nonce único por clave; típicamente 96 bits |
| Oculta patrones | No: revela bloques iguales | Sí, con IV adecuado | Sí, con nonce adecuado |
| Autentica | No | No por sí solo | Sí, al verificar la etiqueta; incluye AAD |
| Riesgos típicos | Filtración de estructura y repeticiones | IV inadecuado, modificación de bits y padding oracle si hay respuestas reveladoras | Reutilizar nonce o no verificar la etiqueta |
| Uso recomendado | No usar para mensajes | Solo si es necesario por compatibilidad y con autenticación adicional | Preferible si se garantiza el uso correcto del nonce y la etiqueta |

### Recomendación práctica

Para un diseño nuevo elegiría un **AEAD**, como **AES-GCM** o **ChaCha20-Poly1305**, garantizando un nonce único por clave y la verificación de su etiqueta. ChaCha20-Poly1305 es otra construcción AEAD, no un modo de AES. [2][11] Si fuera necesario usar CBC, lo combinaría con **HMAC** y claves separadas para cifrado y autenticación, siguiendo **encrypt-then-MAC**: primero cifrar, después autenticar el IV y el texto cifrado, y comprobar el MAC antes de descifrar. [10, §3] No usaría ECB para proteger mensajes, porque deja visibles las repeticiones. [1, §6.1]

## Fuentes (mín. 3, verificables)

1. Morris Dworkin (NIST). *Recommendation for Block Cipher Modes of Operation: Methods and Techniques*, SP 800-38A. 2001. https://csrc.nist.gov/pubs/sp/800/38/a/final — Texto completo: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
2. Morris Dworkin (NIST). *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC*, SP 800-38D. 2007. https://csrc.nist.gov/pubs/sp/800/38/d/final — Texto completo: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
3. National Institute of Standards and Technology (NIST). *Advanced Encryption Standard (AES)*, FIPS 197. 2001, actualización editorial de 2023. https://csrc.nist.gov/pubs/fips/197/final
4. Filippo Valsorda. *The ECB Penguin*. 2013. https://words.filippo.io/the-ecb-penguin/
5. Blair Hanley Frank (GeekWire). *Adobe breach hit more than 150 million usernames and passwords*. 2013. https://www.geekwire.com/2013/report-adobe-breach-hit-150-million-usernames-passwords/
6. Alex Hern (The Guardian). *Did your Adobe password leak? Now you and 150m others can check*. 2013. https://www.theguardian.com/technology/2013/nov/07/adobe-password-leak-can-check
7. Serge Vaudenay. *Security flaws induced by CBC padding — Applications to SSL, IPSEC, WTLS...*, EUROCRYPT 2002. 2002. Registro y resumen en EPFL: https://infoscience.epfl.ch/entities/publication/60268d2e-9c20-4d4f-9c85-6fff38c5454f
8. US-CERT (publicado en CISA). *SSL 3.0 Protocol Vulnerability and POODLE Attack*, TA14-290A. 2014, revisado en 2016. https://www.cisa.gov/news-events/alerts/2014/10/17/ssl-30-protocol-vulnerability-and-poodle-attack
9. Russ Housley. *Cryptographic Message Syntax (CMS)*, RFC 5652, §6.3. 2009. https://www.rfc-editor.org/rfc/rfc5652.html#section-6.3
10. Peter Gutmann. *Encrypt-then-MAC for Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)*, RFC 7366. 2014. https://www.rfc-editor.org/rfc/rfc7366.txt
11. Yoav Nir y Adam Langley. *ChaCha20 and Poly1305 for IETF Protocols*, RFC 8439, §2.8 y §4. 2018. https://www.rfc-editor.org/rfc/rfc8439.html#section-2.8

## Reflexión (3–5 líneas)

Entendí que elegir un algoritmo conocido no alcanza: también tengo que revisar cómo se usa.
Lo conecto con WEP y `sha256(clave || mensaje)`, los ejemplos de mal uso que propone el laboratorio.
En ECB, cifrar cada bloque sin relacionarlo con los demás deja visibles las repeticiones; en GCM, repetir el nonce puede arruinar la protección.
Me quedo con la idea de revisar el esquema completo y distinguir siempre confidencialidad de integridad.
