# Mini-research — Lab 01

**Grupo:** 08
**Tema elegido:** 4 — Criptografía post-cuántica
**Cantidad de palabras:** ~940 (sin bibliografía ni declaración de IA)

---

## Planteo

En agosto de 2024 el NIST publicó FIPS 203, 204 y 205, sus primeros
estándares de criptografía post-cuántica (PQC). Los titulares lo presentaron
como "la defensa contra las computadoras cuánticas". La pregunta de este
trabajo es más acotada: ¿qué parte de la criptografía rompe una computadora
cuántica, qué parte reparan exactamente estos estándares y por qué una
organización que hoy no tiene ningún adversario cuántico ya debería estar
migrando? Nuestra posición es que el riesgo real no está en el día en que
exista la máquina, sino en los datos confidenciales que se cifran **hoy** con
intercambio de claves clásico, y que la migración es sobre todo un problema
de inventario, no de algoritmos.

## Desarrollo

**Qué se rompe y qué no.** La amenaza tiene dos algoritmos detrás. El de
Shor (1997) resuelve en tiempo polinomial la factorización de enteros y el
logaritmo discreto, que son los problemas en los que se apoyan RSA,
Diffie-Hellman y la criptografía de curvas elípticas (ECDH, ECDSA, EdDSA).
Contra ellos no hay ajuste de parámetros que alcance: aumentar el tamaño de
clave no cambia la complejidad polinomial. El de Grover (1996), en cambio,
solo da una aceleración cuadrática a la búsqueda exhaustiva. Para AES o
SHA-256 eso equivale, en el peor caso teórico, a reducir a la mitad los bits
de seguridad, y se compensa usando claves y digests más largos (AES-256,
SHA-384). El propio NIST lo refleja: FIPS 203, 204 y 205 reemplazan
**únicamente** los mecanismos de clave pública; la criptografía simétrica y
las funciones de hash siguen vigentes (NIST, 2024d). Esto conecta con la
Parte B del laboratorio: el SHA-256 y el HMAC que implementamos no son el
problema cuántico.

**Qué resuelve cada estándar.** FIPS 203 especifica ML-KEM, un mecanismo de
encapsulamiento de claves basado en el problema *Module Learning With
Errors* sobre retículos, derivado de CRYSTALS-Kyber (NIST, 2024a). Es el
reemplazo del intercambio de claves: lo que hoy hacen ECDH o RSA al
establecer una sesión TLS. FIPS 204 especifica ML-DSA, firma digital también
sobre retículos, derivada de CRYSTALS-Dilithium (NIST, 2024b). FIPS 205
especifica SLH-DSA, firma basada solamente en funciones de hash, derivada de
SPHINCS+ (NIST, 2024c). La existencia de dos estándares de firma no es
redundancia: SLH-DSA tiene firmas mucho más grandes y es más lenta, pero su
seguridad depende solo de propiedades de las funciones de hash, que se
conocen mucho mejor que los retículos. Es un respaldo deliberado por si
aparece un ataque contra la familia de retículos.

**Por qué el apuro: *harvest now, decrypt later*.** Un adversario puede
capturar hoy tráfico cifrado con TLS y guardarlo. Si el intercambio de
claves fue ECDH, el día que disponga de una computadora cuántica capaz de
correr Shor recupera la clave de sesión y descifra todo lo almacenado. La
confidencialidad de un dato, entonces, no depende de cuándo llegue la
máquina, sino de cuánto tiempo tiene que seguir siendo secreto ese dato.
Una historia clínica, un expediente judicial o un secreto industrial con
vida útil de veinte años ya está expuesto si hoy viaja con criptografía
clásica. Por eso el primer estándar priorizado fue ML-KEM y no las firmas:
una firma falsificada en el futuro no compromete retroactivamente lo firmado
hoy (salvo en documentos de validez prolongada), pero un intercambio de
claves capturado sí compromete lo cifrado hoy.

**Qué implica la migración.** El borrador NIST IR 8547 propone un
calendario: los algoritmos clásicos de clave pública con 112 bits de
seguridad pasarían a estar desaconsejados después de 2030 y prohibidos
después de 2035 (Moody et al., 2024). En la práctica, el primer paso no es
cambiar algoritmos sino saber dónde están: certificados, VPN, firmas de
código, tarjetas inteligentes, bibliotecas embebidas en dispositivos que no
se actualizan. Sin ese inventario, la migración no se puede planificar. El
segundo paso, que ya se ve en navegadores y servidores, es el modo
**híbrido**: combinar ECDH (X25519) con ML-KEM en el mismo intercambio, de
modo que el atacante tenga que romper ambos. Si ML-KEM resultara débil, la
seguridad cae a la clásica, no por debajo de ella.

## Tensión / límites

Los estándares resuelven el problema matemático, pero dejan abiertos tres
frentes. Primero, la **madurez**: los retículos estructurados se estudian
hace mucho menos que la factorización. El caso SIKE, un candidato que llegó
a la cuarta ronda del mismo proceso del NIST y fue roto en 2022 con una
computadora personal en horas (Castryck y Decru, 2023), muestra que "llegar
lejos en el concurso" no equivale a "ser seguro". Por eso el modo híbrido y
SLH-DSA no son optativos de hecho. Segundo, el **costo operativo**: claves y
firmas de ML-DSA ocupan kilobytes en lugar de decenas de bytes, lo que
afecta cadenas de certificados, dispositivos IoT y protocolos con paquetes
chicos. Tercero, la **incertidumbre temporal**: nadie sabe cuándo habrá una
máquina capaz de romper RSA-2048, y esa ambigüedad se usa tanto para
vender productos "quantum-safe" innecesarios como para postergar
indefinidamente. El estándar no resuelve qué dato migrar primero; esa
decisión depende del análisis de riesgo de cada organización.

## Cierre

Para la práctica profesional, PQC no es un tema de físicos sino de gestión
de activos. La pregunta útil no es "¿cuándo llega la computadora cuántica?"
sino "¿qué datos nuestros tienen que seguir siendo confidenciales más allá
de 2035 y por dónde viajan hoy?". Si la respuesta incluye información
sensible transmitida con ECDH o RSA, esa información ya está en riesgo por
*harvest now, decrypt later*. Lo concreto: inventariar dónde se usa
criptografía de clave pública, priorizar el intercambio de claves sobre las
firmas, adoptar modos híbridos donde el software lo permita y diseñar los
sistemas nuevos con agilidad criptográfica, para que el próximo cambio de
algoritmo sea una configuración y no un rediseño.

---

## Bibliografía

Formato APA.

1. [PRIMARIA] National Institute of Standards and Technology. (2024a).
   *Module-lattice-based key-encapsulation mechanism standard* (FIPS PUB 203).
   U.S. Department of Commerce. https://doi.org/10.6028/NIST.FIPS.203
2. [PRIMARIA] National Institute of Standards and Technology. (2024b).
   *Module-lattice-based digital signature standard* (FIPS PUB 204).
   U.S. Department of Commerce. https://doi.org/10.6028/NIST.FIPS.204
3. [PRIMARIA] National Institute of Standards and Technology. (2024c).
   *Stateless hash-based digital signature standard* (FIPS PUB 205).
   U.S. Department of Commerce. https://doi.org/10.6028/NIST.FIPS.205
4. [PRIMARIA] National Institute of Standards and Technology. (2024d, 13 de
   agosto). *NIST releases first 3 finalized post-quantum encryption
   standards* [Comunicado de prensa].
   https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards
5. [PRIMARIA] Moody, D., Perlner, R., Regenscheid, A., Robinson, A., &
   Cooper, D. (2024). *Transition to post-quantum cryptography standards*
   (NIST IR 8547, initial public draft). National Institute of Standards and
   Technology. https://doi.org/10.6028/NIST.IR.8547.ipd
6. [ARBITRADA] Shor, P. W. (1997). Polynomial-time algorithms for prime
   factorization and discrete logarithms on a quantum computer. *SIAM Journal
   on Computing, 26*(5), 1484–1509. https://doi.org/10.1137/S0097539795293172
7. [ARBITRADA] Grover, L. K. (1996). A fast quantum mechanical algorithm for
   database search. En *Proceedings of the 28th Annual ACM Symposium on
   Theory of Computing* (pp. 212–219). ACM. https://doi.org/10.1145/237814.237866
8. [ARBITRADA] Castryck, W., & Decru, T. (2023). An efficient key recovery
   attack on SIDH. En *Advances in Cryptology – EUROCRYPT 2023* (pp.
   423–447). Springer. https://eprint.iacr.org/2022/975

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí

| Herramienta | Para qué | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Borrador del texto y propuesta de bibliografía. | Todo el documento. | El grupo revisó el contenido técnico y entró a cada referencia (DOI / URL) para confirmar que existe y que dice lo que se le atribuye. |

**Verificación de fuentes:** el grupo declara haber accedido y verificado
individualmente cada una de las referencias citadas.
