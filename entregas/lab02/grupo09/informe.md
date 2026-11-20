# Informe — Laboratorio 02 · Criptografía

**Grupo:** 09 · **Integrantes:** *Cocchi Santiago, Ferraro Franco, Mossello Francisco, Spat Tomas, Torres Santiago* · **Fecha:** 04/09/2026

---

## 0. Declaración de uso de IA

Se utilizó un asistente de IA (Claude) para redactar y estructurar este informe y el
mini-research, buscar y verificar las fuentes citadas, y correr las pruebas de la Parte B.
El código de `src/cripto.py` lo completó el grupo; la IA lo revisó y lo validó con
`verificar.py` (4/4 OK) y con el reto de `data/generar_datos.py`. Las salidas de la
bitácora son las obtenidas al correr los comandos. El contenido fue revisado por el grupo.

---

## 1. Parte A — Análisis de la falla

**Caso:** 2 — Sony PS3 (ECDSA): reutilización del nonce *k* al firmar.

### A.1 — Qué prometía el sistema

La PlayStation 3 solo ejecuta software firmado digitalmente por Sony. Cada ejecutable,
actualización y juego lleva una firma **ECDSA** hecha con la clave privada de Sony, y la
consola la verifica con la clave pública antes de correrlo. La propiedad prometida es
**autenticidad e integridad del código**: nadie que no tenga la clave privada puede producir
un programa que la consola acepte como oficial. Sobre eso se apoya todo el control de
piratería y de software no autorizado.

### A.2 — El mal uso concreto

ECDSA no estaba roto. El error estuvo en **cómo Sony lo usó**: cada firma ECDSA necesita un
número secreto *k* (nonce) **aleatorio y distinto para cada firma**. Sony usó **el mismo *k*
en todas las firmas**, o sea un valor fijo en lugar de uno aleatorio. El grupo fail0verflow
lo presentó en el congreso 27C3 (diciembre de 2010) en la charla *"Console Hacking 2010 —
PS3 Epic Fail"* [1][2][3].

### A.3 — Propiedad rota y cómo se explotó

Se rompió la **autenticidad** (y con ella la integridad): con la clave privada filtrada,
cualquiera puede firmar código y la consola lo acepta como si fuera de Sony.

La explotación es pura aritmética. Una firma ECDSA es el par *(r, s)*, donde:

- *r* = coordenada x del punto *k·G* (mod *n*)
- *s* = *k*⁻¹ · (*z* + *r·d*) mod *n*, con *z* = hash del mensaje y *d* = clave privada

Si dos firmas de mensajes distintos (*z₁*, *z₂*) usan el mismo *k*, comparten el mismo *r*
(se nota a simple vista) y quedan dos ecuaciones con dos incógnitas:

- *s₁ − s₂* = *k*⁻¹ · (*z₁ − z₂*) → **k = (z₁ − z₂) / (s₁ − s₂) mod n**
- y despejando de la primera: **d = (s₁·k − z₁) / r mod n**

Con dos firmas públicas (las de cualquier par de actualizaciones oficiales) se calcula la
clave privada de Sony. La propia descripción del estándar lo advierte: es crucial elegir un
*k* distinto para cada firma; si no, la ecuación se puede resolver para la clave privada [4].
Pocos días después de la charla, George Hotz (geohot) publicó la clave raíz de la consola y
cualquiera pudo firmar software como si fuera Sony [3][5]. Como esa clave está grabada en el
hardware de millones de consolas, Sony no podía cambiarla sin dejar de reconocer su propio
software.

### A.4 — La forma correcta

Generar *k* con un generador criptográficamente seguro y **nuevo en cada firma**, o mejor,
usar **nonces deterministas** (RFC 6979 [6], o Ed25519 [7]), que derivan *k* del mensaje y
la clave privada: no depende de la calidad del azar y nunca se repite para mensajes distintos.

---

## 2. Parte B.1 — Romper el XOR

**Clave hallada:** `0x37`

**Mensaje en claro:**

> Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No
> compartir fuera de la empresa.

**Cómo se rompió.** `romper_xor_1byte()` prueba las 256 claves posibles de un byte, descifra
con cada una y le asigna un puntaje según cuántos bytes caen en letras y espacios (los
caracteres más frecuentes de un texto natural). La clave con mejor puntaje es la correcta.
Son solo 256 intentos: se resuelve al instante.

**Por qué el cifrado clásico falla:**

1. **Espacio de claves ridículo.** Una clave de 1 byte tiene 256 posibilidades; la fuerza
   bruta es trivial. Lo que protege a un cifrado moderno es que la clave tenga 128 o 256 bits
   aleatorios (2¹²⁸ posibilidades).
2. **No esconde la estadística del idioma.** XOR con una clave fija es una sustitución: cada
   letra del texto se convierte siempre en el mismo byte cifrado, así que la distribución de
   frecuencias del español pasa intacta al cifrado y delata la clave. Con claves más largas
   pero repetidas pasa lo mismo, separando el texto en columnas (una por byte de clave).
3. **Texto conocido = clave.** Como `cifrado ⊕ claro = clave`, alcanza con adivinar un
   fragmento (por ejemplo, "PhantomCorp") para recuperar la clave entera.
4. **Viola Kerckhoffs.** Todo su "secreto" depende de que no se sepa que es XOR de un byte.
   El único XOR seguro es el one-time pad: clave aleatoria, tan larga como el mensaje y
   **nunca reutilizada**, algo poco práctico.

---

## 3. Parte B.2 — Autenticación

Implementado en `src/cripto.py`: `mac_ingenuo()` = `sha256(clave || msg)`, `mac_hmac()` =
HMAC-SHA256 y `verificar_mac()` con `hmac.compare_digest`.

### B.2.1 — Por qué `sha256(clave || mensaje)` permite length-extension

SHA-256 usa la construcción **Merkle–Damgård**: procesa el mensaje en bloques de 64 bytes,
actualizando un estado interno de 256 bits, y **el hash final es ese estado interno tal
cual**. O sea, el MAC publicado es justamente el punto en el que quedó la función después de
procesar `clave || mensaje || relleno`.

Un atacante que ve un mensaje y su MAC, y conoce (o adivina probando) el largo de la clave,
puede:

1. Calcular el relleno que SHA-256 le agregó a `clave || mensaje`.
2. Cargar el MAC como estado inicial de SHA-256 y **seguir hasheando** desde ahí los bytes
   que quiera agregar.
3. El resultado es un MAC válido para `mensaje || relleno || agregado`, **sin conocer la
   clave**.

**Ejemplo:** el servidor autentica `monto=100&destino=juan` con `sha256(clave || msg)`. El
atacante produce, sin la clave, un MAC válido para
`monto=100&destino=juan<relleno>&destino=atacante`. Si el servidor se queda con el último
valor del parámetro repetido, el pago va al atacante, y el MAC verifica. Esto se explotó en
la API de Flickr en 2009 (Duong y Rizzo), donde las firmas eran `MD5(secreto || parámetros)`
[8][9]. MITRE lo cataloga como CAPEC-461 [10].

### B.2.2 — Cómo lo resuelve HMAC estructuralmente

HMAC (RFC 2104 [11]) hashea dos veces, con la clave en las dos pasadas:

```
HMAC(K, m) = H( (K ⊕ opad) || H( (K ⊕ ipad) || m ) )
```

El atacante puede extender el hash **interno**, pero el valor que se publica es el hash
**externo**, que vuelve a mezclar la clave con el resultado interno. Para producir un MAC
válido de un mensaje extendido tendría que calcular ese hash externo, y para eso necesita
la clave. Extender el MAC publicado tampoco sirve: daría el hash de
`(K ⊕ opad) || hash_interno || relleno || agregado`, que no corresponde a ningún mensaje que
el servidor vaya a verificar. Además, HMAC tiene prueba de seguridad: es un PRF/MAC seguro
siempre que la función de compresión del hash lo sea.

### B.2.3 — Qué ataque evita comparar en tiempo constante

Evita un **ataque de temporización (timing attack)**. Una comparación común (`==` o
`memcmp`) corta en el **primer byte distinto**: tarda un poco más cuanto más bytes iniciales
coinciden. Midiendo el tiempo de respuesta, el atacante descubre el MAC **de a un byte**.

**Ejemplo concreto:** una API recibe un webhook con un MAC en una cabecera y lo compara con
`==`. El atacante manda el mismo mensaje con MAC falsos, variando solo el primer byte (256
opciones) y repitiendo cada intento muchas veces para promediar el ruido. El valor que tarda
apenas más es el correcto; fija ese byte y sigue con el segundo. Para los 32 bytes de un
HMAC-SHA256 necesita del orden de 32 × 256 = 8.192 variantes (más las repeticiones), en vez
de 2²⁵⁶. Así se forjaron firmas en la verificación de la Xbox 360, que comparaba con
`memcmp` [12].

`hmac.compare_digest` recorre siempre todos los bytes y tarda lo mismo sin importar dónde
esté la diferencia, así que el tiempo no filtra nada [13].

---

## 4. Bitácora

```bash
$ python3 data/generar_datos.py
Creado data/muestra/reto_xor.hex — rompelo con: python3 src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)

$ python3 src/cripto.py xor --texto hola --clave K
2324272a

$ python3 src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
clave=0x37
Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

$ python3 src/cripto.py mac --clave secreta --msg "pago 100" --modo hmac
5ec4a52407221836a66e8d654d914aaa4b18bd31cf31907348bcd292677b902e

$ python3 src/cripto.py mac --clave secreta --msg "pago 100" --modo ingenuo
a8cc54c07b3acb7470c25ab9eea5234bfa2562e37298eee275e39a457004b725

$ python3 src/verificar.py
== Lab 02 · Criptografía ==
  ✓ romper_xor_1byte recupera clave y texto
  ✓ mac_ingenuo = sha256(clave||msg)
  ✓ mac_hmac = HMAC-SHA256
  ✓ verificar_mac compara bien

4 OK · 0 a revisar · 0 sin implementar
```

---

## Fuentes

1. fail0verflow, *Console Hacking 2010 — PS3 Epic Fail*, 27C3 (Chaos Communication
   Congress), diciembre de 2010. Discusión técnica en sci.crypt:
   <https://groups.google.com/g/sci.crypt/c/3isJl28Slrw>
2. Engadget, *Hackers obtain PS3 private cryptography key due to epic programming fail?*,
   29/12/2010.
   <https://www.engadget.com/2010/12/29/hackers-obtain-ps3-private-cryptography-key-due-to-epic-programm>
3. Exophase, *Hackers Describe PS3 Security As Epic Fail, Gain Unrestricted Access*.
   <https://www.exophase.com/20540/hackers-describe-ps3-security-as-epic-fail-gain-unrestricted-access/>
4. Wikipedia, *Elliptic Curve Digital Signature Algorithm* (sección sobre la elección de *k*
   y el caso Sony). <https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm>
5. SiliconANGLE, cobertura de la publicación de la clave raíz por geohot, 03/01/2011.
   <https://siliconangle.com/?p=35925>
6. T. Pornin, *RFC 6979 — Deterministic Usage of DSA and ECDSA*, IETF, 2013.
   <https://www.rfc-editor.org/rfc/rfc6979>
7. S. Josefsson, I. Liusvaara, *RFC 8032 — Edwards-Curve Digital Signature Algorithm
   (EdDSA)*, IETF, 2017. <https://www.rfc-editor.org/rfc/rfc8032>
8. T. Duong, J. Rizzo, *Flickr's API Signature Forgery Vulnerability*, 28/09/2009.
   <https://vnhacker.substack.com/p/flickrs-api-signature-forgery>
9. Bugtraq, *MD5 hash extension attack breaks API authentication of Flickr and others*,
   septiembre de 2009. <https://seclists.org/bugtraq/2009/Sep/239>
10. MITRE, *CAPEC-461: Web Services API Signature Forgery Leveraging Hash Function Extension
    Weakness*. <https://capec.mitre.org/data/definitions/461>
11. H. Krawczyk, M. Bellare, R. Canetti, *RFC 2104 — HMAC: Keyed-Hashing for Message
    Authentication*, IETF, 1997. <https://www.rfc-editor.org/rfc/rfc2104>
12. C. Hale, *A Lesson In Timing Attacks (or, Don't use MessageDigest.isEquals)*, 2009.
    <https://codahale.com/a-lesson-in-timing-attacks/>
13. Python Software Foundation, documentación de `hmac.compare_digest`.
    <https://docs.python.org/3/library/hmac.html#hmac.compare_digest>
