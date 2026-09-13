# Mini-research — Laboratorio 02

**Grupo:** 07
**Autor:** Lautaro Mariño — @lautaromarino0
**Tema elegido:** *(uno)*

- [ ] **A.** Modos de operación de cifrado por bloques (ECB vs CBC vs GCM) y por
  qué ECB filtra estructura (el "pingüino" de Adobe).
- [ ] **B.** HMAC y el ataque de length-extension: cómo funciona el ataque y por
  qué HMAC lo previene.
- [x] **C.** Derivación de claves desde contraseñas (PBKDF2, bcrypt, scrypt,
  Argon2): por qué un `sha256(password)` no alcanza.
- [ ] **D.** Cifrado asimétrico y firmas digitales: qué problema resuelven que el
  simétrico no.

---

## Desarrollo

### El problema no es SHA-256, es para qué se lo usa

Guardar `sha256(password)` parece razonable: la función es de un solo sentido,
está estandarizada y nadie la "rompió". Pero SHA-256 fue diseñada para ser
**rápida** —resumir archivos grandes, firmar, construir HMAC— y esa virtud es
exactamente el defecto cuando la entrada es una contraseña. Una contraseña no
es una clave aleatoria de 256 bits: es un valor de baja entropía elegido por
una persona, que casi siempre cae dentro de un diccionario. El atacante que
roba la base de datos no necesita invertir la función; le alcanza con
**adivinar y comparar**, y cada intento le cuesta lo mismo que a la función
correr una vez. El benchmark de hashcat sobre una única GPU de consumo (RTX
4090) da 21.975 MH/s para SHA2-256, es decir, unos 22.000 millones de intentos
por segundo (Chick3nman, 2022). A esa velocidad, todo el espacio de contraseñas
de 8 caracteres alfanuméricos (62⁸ ≈ 2,2 × 10¹⁴) se recorre en menos de tres
horas, y un diccionario de cientos de millones de contraseñas filtradas se
prueba en menos de un segundo.

Es el mismo razonamiento del punto B.1 del informe, mirado desde el otro lado:
allá rompimos XOR porque el espacio de claves era de 256 valores; acá el
espacio "de claves" es lo que la gente elige como contraseña, y es igual de
chico en la práctica. Lo que cambia es que ya no podemos agrandar el espacio
(no controlamos qué elige el usuario), así que la única palanca que queda es
**encarecer cada intento**.

### Salt: necesaria, no suficiente

La primera mitad de la solución es la *salt*: un valor aleatorio, distinto por
usuario, que se guarda en claro junto al hash. RFC 8018 explica su función:
produce "un conjunto grande de claves posibles" para una misma contraseña, de
modo que el atacante no puede precalcular tablas ni atacar a todos los usuarios
de una vez (Moriarty, Kaliski & Rusch, 2017, §4.1). NIST lo convierte en
requisito: los verificadores *deberán* almacenar contraseñas "saladas y
hasheadas con un esquema de hashing de contraseñas adecuado", con una salt de
al menos 32 bits (NIST, 2025, §3.1.1.2).

LinkedIn en 2012 muestra el costo de omitirla. Se filtraron 6,5 millones de
hashes SHA-1 **sin salt**; Kamp (2012) señaló que una computadora común calcula
entre 10 y 100 millones de SHA-1 por segundo con la GPU, y que sin salt todos
los usuarios que comparten una contraseña tienen el mismo hash, así que
crackear uno es crackear a todos. En 2016 se supo que el volcado real era de
117 millones de cuentas (Krebs, 2016). Adobe, un año después, hizo algo
todavía peor: no hasheó, **cifró** las contraseñas con 3DES en modo ECB y una
única clave, con lo cual dos usuarios con la misma contraseña producían el
mismo criptograma y las pistas en claro permitían adivinar el resto (Ducklin,
2013). Ese caso es el de la Parte A de este mismo lab, y es la razón por la
que el enunciado insiste en distinguir *cifrar* de *hashear*: cifrar es
reversible y depende de una clave que alguien tiene; una contraseña almacenada
nunca debería ser recuperable, ni siquiera por el servidor.

Pero la salt sola no frena la fuerza bruta contra **un** usuario: el atacante
simplemente concatena la salt conocida a cada candidato. Hace falta la segunda
mitad.

### Funciones de derivación de clave: hacer lento a propósito

Una KDF de contraseñas (*password-based key derivation function*) toma la
contraseña y la salt y devuelve una clave, pero está diseñada para que cada
evaluación cueste **mucho** y ese costo sea **ajustable**.

**PBKDF2** (RFC 8018, §5.2) itera una PRF —normalmente HMAC-SHA256— *c* veces.
El propio RFC cuantifica el efecto: "un contador de iteraciones *c* aumenta la
fortaleza de una contraseña en log₂(*c*) bits contra ataques por prueba", y
recomienda un mínimo de 1.000 iteraciones (Moriarty et al., 2017). Ese mínimo
es de 2017; OWASP hoy recomienda 600.000 iteraciones para PBKDF2-HMAC-SHA256
(OWASP, 2024). Su limitación: es *compute-hard* pero no *memory-hard*; una GPU
o un ASIC lo paralelizan tan bien como a SHA-256, solo *c* veces más lento.

**bcrypt** (Provos & Mazières, 1999) parte de la observación que da título al
paper: "la longitud y aleatoriedad de las contraseñas elegidas por usuarios
permanecen fijas en el tiempo; en contraste, las mejoras de hardware dan a los
atacantes cada vez más poder de cómputo". La respuesta es un esquema
*future-adaptable*: un factor de costo exponencial que el administrador sube a
medida que el hardware mejora, sin cambiar de algoritmo. Se apoya en la
programación de clave de Blowfish, que usa 4 KiB de tablas y por eso es
incómoda para GPUs: el mismo benchmark que hacía 22 GH/s de SHA-256 hace
184 kH/s de bcrypt con costo 5, unas 120.000 veces menos (Chick3nman, 2022).

**scrypt** (Percival & Josefsson, 2016) introduce la *memory-hardness* de
forma explícita: "busca reducir la ventaja que los atacantes pueden obtener
usando circuitos paralelos diseñados a medida". Sus parámetros *N*, *r* y *p*
fijan cuánta RAM debe ocupar cada evaluación; la memoria no se abarata al
ritmo del cómputo, así que un ASIC que quiera probar un millón de contraseñas
en paralelo necesita un millón de bloques de 128 MiB.

**Argon2** ganó la Password Hashing Competition y está estandarizado en RFC
9106 (Biryukov, Dinu, Khovratovich & Josefsson, 2021). Tiene tres variantes:
Argon2d (acceso a memoria dependiente de los datos, máxima resistencia a
GPUs pero vulnerable a canales laterales), Argon2i (acceso independiente,
resistente a canales laterales) y **Argon2id**, híbrida y obligatoria de
implementar, que el RFC recomienda como opción por defecto. Los parámetros de
referencia son *t*=1, *p*=4, *m*=2 GiB, o *t*=3 y 64 MiB en entornos
restringidos; OWASP lo pone como primera opción con *m*=19 MiB, *t*=2, *p*=1
como mínimo (OWASP, 2024).

### Verificación empírica con la biblioteca estándar

Para no quedarme en la teoría, medí el costo de una verificación con cada
esquema usando solo `hashlib`, en el mismo espíritu del lab (script en
`src/kdf_demo.py`, corrido con Python 3.11 en un contenedor Linux sin GPU):

```
sha256(password)                       0.002 ms/intento  ~     407,997 intentos/s
sha256(salt || password)               0.001 ms/intento  ~   1,032,844 intentos/s
pbkdf2_hmac sha256, c=600000         347.601 ms/intento  ~           3 intentos/s
scrypt N=2^17 r=8 p=1 (128 MiB)      446.612 ms/intento  ~           2 intentos/s
```

Las dos primeras líneas están limitadas por el intérprete de Python, no por
SHA-256; en C sobre GPU son cinco órdenes de magnitud más rápidas. Lo
relevante es la relación: agregar salt no cambia el costo por intento, y la
KDF lo multiplica por más de 10⁵. Para un usuario legítimo, 350 ms en el
login es imperceptible; para un atacante con 117 millones de hashes, es la
diferencia entre terminar en la tarde y no terminar nunca. `hashlib.scrypt`
y `hashlib.pbkdf2_hmac` vienen en la stdlib desde Python 3.6 (Python Software
Foundation, s. f.); Argon2 requiere un paquete externo, que por eso no se
usó acá.

### Qué elegir y cómo mantenerlo

La recomendación práctica de OWASP (2024) ordena las opciones: Argon2id
primero; scrypt si Argon2 no está disponible; bcrypt con factor de trabajo
≥ 10 solo en sistemas heredados (y recordando que trunca a 72 bytes); PBKDF2
únicamente cuando se exige FIPS-140. NIST (2025) agrega la parte que suele
olvidarse: el factor de costo "*debería* ser tan alto como sea práctico" y
"*debería* aumentarse con el tiempo". Un hash de contraseñas no es una
decisión que se toma una vez; es un parámetro que se revisa como cualquier
otra dependencia.

---

## Fuentes (mín. 3, verificables)

Todas las URL fueron abiertas y contrastadas el 13/09/2026. Se marca
[PRIMARIA] la fuente original (estándar, paper, autor del análisis) y
[SECUNDARIA] la cobertura periodística.

1. [PRIMARIA] Biryukov, A., Dinu, D., Khovratovich, D., & Josefsson, S. (2021).
   *Argon2 memory-hard function for password hashing and proof-of-work
   applications* (RFC 9106). IETF. https://www.rfc-editor.org/rfc/rfc9106.html
2. [PRIMARIA] Chick3nman. (2022). *Hashcat v6.2.6 benchmark on the Nvidia RTX
   4090*. GitHub Gist. https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd
3. [PRIMARIA] Ducklin, P. (2013, 4 de noviembre). *Anatomy of a password
   disaster – Adobe's giant-sized cryptographic blunder*. Naked Security,
   Sophos. https://nakedsecurity.sophos.com/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/
4. [PRIMARIA] Kamp, P.-H. (2012). LinkedIn password leak: Salt their hide.
   *ACM Queue, 10*(6). https://queue.acm.org/detail.cfm?id=2254400
5. [SECUNDARIA] Krebs, B. (2016, 18 de mayo). *As scope of 2012 breach expands,
   LinkedIn to again reset passwords for some users*. Krebs on Security.
   https://krebsonsecurity.com/2016/05/as-scope-of-2012-breach-expands-linkedin-to-again-reset-passwords-for-some-users/
6. [PRIMARIA] Moriarty, K., Kaliski, B., & Rusch, A. (2017). *PKCS #5:
   Password-based cryptography specification version 2.1* (RFC 8018). IETF.
   https://www.rfc-editor.org/rfc/rfc8018.html
7. [PRIMARIA] National Institute of Standards and Technology. (2025). *Digital
   identity guidelines: Authentication and authenticator management* (NIST SP
   800-63B-4). https://pages.nist.gov/800-63-4/sp800-63b.html
8. [PRIMARIA] OWASP Foundation. (2024). *Password storage cheat sheet*. OWASP
   Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
9. [PRIMARIA] Percival, C., & Josefsson, S. (2016). *The scrypt password-based
   key derivation function* (RFC 7914). IETF. https://www.rfc-editor.org/rfc/rfc7914.html
10. [PRIMARIA] Provos, N., & Mazières, D. (1999). A future-adaptable password
    scheme. En *Proceedings of the FREENIX Track: 1999 USENIX Annual Technical
    Conference*. USENIX. https://www.usenix.org/legacy/events/usenix99/provos/provos.pdf
11. [PRIMARIA] Python Software Foundation. (s. f.). *hashlib — Secure hashes and
    message digests: Key derivation*. Recuperado el 13 de septiembre de 2026, de
    https://docs.python.org/3/library/hashlib.html#key-derivation

---

## Reflexión (3–5 líneas)

Lo que más me quedó es que en este tema el algoritmo "bueno" es el que hace lo
contrario de lo que uno espera de la criptografía: ser lento y gastar memoria.
Todo el lab gira alrededor de la misma idea —XOR de un byte, `sha256(clave||msg)`,
`sha256(password)`— y es que una primitiva sólida usada para lo que no fue
diseñada no protege nada. La otra lección es que el hash de contraseñas no se
"configura y se olvida": el costo que era alto en 2017 hoy es el piso, y la
tabla de OWASP se actualiza cada año por eso.
