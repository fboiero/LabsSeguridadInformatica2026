# Mini-research — Lab 01

**Grupo:** 14
**Tema elegido:** 4 — Criptografía post-cuántica
**Cantidad de palabras:** 947 (sin bibliografía ni declaración)

---

## Planteo

En agosto de 2024 el NIST publicó sus tres primeros estándares de criptografía post-cuántica (PQC): FIPS 203, 204 y 205. La divulgación suele presentarlos como la respuesta a «la computadora cuántica que va a romper toda la criptografía». La pregunta de este trabajo es más acotada: **qué problema resuelven exactamente estos estándares y cuál no**. Nuestra posición es que la PQC reemplaza una pieza precisa (la criptografía de clave pública), que la urgencia real no viene de la computadora cuántica sino de los datos que hoy se están capturando, y que el desafío principal de la migración no es criptográfico sino de inventario e ingeniería.

## Desarrollo

**Qué rompe una computadora cuántica.** La amenaza concreta es el algoritmo de Shor (1997). Shor demostró que una computadora cuántica puede factorizar enteros y calcular logaritmos discretos en tiempo polinomial. Sobre la dificultad de esos dos problemas se apoya casi toda la criptografía de clave pública en uso: RSA en el primer caso, y Diffie-Hellman, ECDH, ECDSA y EdDSA en el segundo. Una computadora cuántica «criptográficamente relevante» (CRQC) que ejecute Shor a escala no debilita estos esquemas: los vuelve inútiles, sin importar el tamaño de clave.

**Qué no rompe.** La criptografía simétrica y las funciones de hash quedan en otra situación. El NIST afirma (Moody et al., 2024) que sus estándares simétricos, incluidos AES, SHA-2 y SHA-3, «son significativamente menos vulnerables a los ataques cuánticos conocidos» que los de clave pública, y que no espera tener que abandonarlos como parte de la migración. Todo primitivo simétrico con al menos 128 bits de seguridad clásica cumple la categoría 1 de seguridad post-cuántica. Este matiz casi no aparece en los titulares. Implica, por ejemplo, que el verificador de integridad con SHA-256 y HMAC que implementamos en la Parte B de este laboratorio **no necesita migrar**. Lo que sí debe migrar es el canal TLS por el que se descargaría ese manifiesto, porque su intercambio de claves y sus certificados usan criptografía asimétrica.

**Qué estandarizó el NIST.** FIPS 203 define ML-KEM, un mecanismo de encapsulamiento de claves basado en retículos modulares, que permite a dos partes establecer un secreto compartido (NIST, 2024). Reemplaza el rol de Diffie-Hellman/ECDH en protocolos como TLS. FIPS 204 (ML-DSA) y FIPS 205 (SLH-DSA, basado solo en funciones de hash) cubren las firmas digitales, el rol de RSA y ECDSA. La elección de dos familias de firma no es redundante: si se descubriera una debilidad en los retículos, SLH-DSA depende únicamente de la seguridad de las funciones de hash, que es la hipótesis mejor entendida.

**Por qué es urgente si la CRQC no existe.** Moody et al. (2024), del NIST, lo dicen explícitamente: los datos cifrados ya están en riesgo por la amenaza *harvest now, decrypt later*, en la que un adversario captura hoy tráfico cifrado para descifrarlo cuando tenga capacidad cuántica. El mismo documento formaliza el razonamiento con el «teorema de Mosca»: si X es la cantidad de años que un dato debe seguir siendo secreto e Y es el tiempo que lleva migrar, hay que empezar antes de que X + Y supere el tiempo Z hasta que exista una CRQC. Una historia clínica o un expediente judicial cifrado en 2026 con ECDH tiene un X de décadas. Si alguien graba hoy esa sesión TLS, la confidencialidad del dato ya está comprometida *a futuro*, aunque nadie la haya roto todavía. En cambio, la autenticación no sufre esta amenaza: una firma solo tiene que ser segura en el momento en que se verifica (Moody et al., 2024). Por eso la prioridad es migrar primero el **intercambio de claves** (ML-KEM) y después las firmas.

**El calendario.** El borrador NIST IR 8547 propone que los algoritmos de clave pública con 112 bits de seguridad (por ejemplo, RSA-2048) queden *deprecados* después de 2030, y que todo RSA y criptografía de curva elíptica quede *prohibido* después de 2035, en línea con la meta de 2035 fijada por el memorando de seguridad nacional NSM-10 de EE. UU. (Moody et al., 2024).

## Tensión / límites

La PQC no resuelve tres problemas, y en ellos está la dificultad real.

Primero, **la confianza en los nuevos supuestos es menor**. RSA tiene más de cuarenta años de criptoanálisis encima, mientras que los esquemas sobre retículos tienen bastante menos exposición en producción. Por eso muchas implementaciones adoptan modos **híbridos** (ECDH + ML-KEM): si uno cae, el otro sostiene la seguridad. Es una cobertura sensata, pero suma complejidad, que es la fuente más habitual de vulnerabilidades.

Segundo, **la PQC no retroactúa**. Migrar en 2030 no protege lo que se capturó en 2024. Para los datos ya interceptados, el daño de *harvest now* es irreversible, y ningún estándar lo arregla.

Tercero, y más importante para una organización común: **el cuello de botella es saber dónde hay criptografía**. El NIST recuerda (Moody et al., 2024) que la integración de un algoritmo nuevo históricamente lleva de 10 a 20 años. La criptografía está escondida en bibliotecas, firmware, dispositivos embebidos que no se pueden actualizar, protocolos de terceros y certificados con vencimientos largos. Una PyME no va a «implementar ML-KEM»: va a depender de que su sistema operativo, su navegador, su VPN y su proveedor de nube lo hagan, y su trabajo es inventariar y exigir. El estándar existe; el inventario, en general, no.

## Cierre

Para la práctica profesional, la conclusión es concreta: hay que tratar la PQC como una migración de **confidencialidad a largo plazo** y no como una amenaza difusa. Eso implica clasificar qué datos tienen un X grande, priorizar los canales que los transportan, armar un inventario criptográfico y preferir componentes con agilidad criptográfica (que permitan cambiar de algoritmo sin rediseñar). Y no gastar esfuerzo en reemplazar SHA-256 o AES-256, que no son el problema.

---

## Bibliografía

1. **[PRIMARIA]** National Institute of Standards and Technology. (2024). *Module-lattice-based key-encapsulation mechanism standard* (FIPS 203). U.S. Department of Commerce. https://doi.org/10.6028/NIST.FIPS.203
2. **[PRIMARIA]** Moody, D., Perlner, R., Regenscheid, A., Robinson, A. y Cooper, D. (2024). *Transition to post-quantum cryptography standards* (NIST IR 8547, borrador inicial público). National Institute of Standards and Technology. https://csrc.nist.gov/pubs/ir/8547/ipd
3. **[ARBITRADA]** Shor, P. W. (1997). Polynomial-time algorithms for prime factorization and discrete logarithms on a quantum computer. *SIAM Journal on Computing, 26*(5), 1484–1509. https://doi.org/10.1137/S0097539795293172

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí

| Herramienta | Para qué | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic), vía Claude Code | Búsqueda y lectura de las fuentes, propuesta de estructura y redacción del borrador | Todo el documento | Se abrió cada fuente citada y se contrastaron con el texto original las afirmaciones atribuidas (fechas de deprecación 2030/2035, cita sobre *harvest now, decrypt later*, cita sobre criptografía simétrica, datos de FIPS 203). El grupo revisó y validó el borrador. |

**Verificación de fuentes:** el grupo declara haber accedido y verificado individualmente cada una de las referencias citadas.
