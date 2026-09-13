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

## Fuentes (mín. 3, verificables)
## Reflexión (3–5 líneas)
