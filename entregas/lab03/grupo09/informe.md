# Informe — Laboratorio 03 · Autenticación

**Grupo:** 09 · **Integrantes:** *Cocchi Santiago, Ferraro Franco, Mossello Francisco, Spat Tomas, Torres Santiago*

---

## 0. Declaración de uso de IA

Se utilizó un asistente de IA (Claude) para: apoyar el análisis de la brecha de la
Parte A, revisar la implementación de `auth.py` y redactar/estructurar este informe.
El código fue verificado manualmente contra los vectores oficiales (RFC 6238) y la
autoevaluación `verificar.py` (3/3 OK). Las decisiones técnicas y las fuentes fueron
revisadas por el grupo.

---

## 1. Parte A — Análisis de la brecha

> **Nota:** el caso asignado surge de `número de grupo mod 4`. Abajo se desarrolla el
> **Caso 0 — LinkedIn 2012**. Si tu grupo cae en otro caso (1 RockYou, 2 Credential
> stuffing, 3 Timing), reemplazá esta sección; el resto del informe no cambia.

### Caso 0 — LinkedIn 2012

**Qué se guardó/comparó mal.**
En junio de 2012 se filtró un volcado con ~6,5 millones de hashes de contraseñas de
LinkedIn. Las contraseñas estaban hasheadas con **SHA-1 sin salt**. Dos problemas
combinados:

1. **Sin salt:** dos usuarios con la misma contraseña producen el mismo hash. Esto
   permite atacar todos los hashes en paralelo y usar **rainbow tables** precomputadas.
2. **SHA-1 es un hash rápido:** está diseñado para velocidad (integridad de archivos),
   no para frenar a un atacante. Una GPU calcula miles de millones de SHA-1 por segundo.

**Cómo se explotó.**
Con el volcado en mano, los atacantes corrieron ataques de diccionario y fuerza bruta
offline. Al no haber salt, cada palabra candidata se hasheaba **una sola vez** y se
comparaba contra los 6,5M de hashes de golpe. En días se recuperó un porcentaje muy
alto de las contraseñas. En 2016 apareció un segundo volcado que elevó la cifra a
**~117 millones** de credenciales de esa misma brecha, que alimentaron oleadas de
*credential stuffing* en otros sitios.

**La forma correcta.**

- **Salt único y aleatorio por usuario** → invalida rainbow tables y obliga a atacar
  cada hash por separado.
- **Función de derivación lenta y con costo configurable** (PBKDF2, bcrypt, scrypt,
  Argon2) con muchas iteraciones → cada intento cuesta caro, la fuerza bruta se vuelve
  económicamente inviable.
- **Verificación en tiempo constante** al comparar.
- Idealmente, **2FA** para que el robo del hash no baste para entrar.

Exactamente lo que implementa la Parte B de este lab (PBKDF2-HMAC-SHA256, salt de 16
bytes, 200.000 iteraciones, `hmac.compare_digest`).

**Fuentes.**
- Wikipedia — *2012 LinkedIn hack*: https://en.wikipedia.org/wiki/2012_LinkedIn_hack
- OWASP — *Password Storage Cheat Sheet*:
  https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- NIST SP 800-63B — *Digital Identity Guidelines (Authentication)*:
  https://pages.nist.gov/800-63-3/sp800-63b.html

---

## 2. Parte B.1 — Contraseñas

Implementación en `src/auth.py` (`hash_password` / `verify_password`). Formato del
registro: `pbkdf2_sha256$iters$salt_hex$dk_hex`.

**¿Por qué salt por usuario?**
Si dos usuarios eligen la misma contraseña y no hay salt, sus hashes son idénticos: el
atacante lo nota de inmediato y, con una sola tabla precomputada (rainbow table), crackea
a los dos —y a todos los demás con esa contraseña— de una vez. Un **salt aleatorio y
distinto por usuario** hace que el mismo password produzca hashes diferentes, anula las
tablas precomputadas y obliga a atacar cada cuenta por separado. En el código esto se ve
en `verificar.py`: dos `hash_password("misma")` dan resultados distintos.

**¿Por qué muchas iteraciones (200.000 y no una)?**
PBKDF2 repite el HMAC-SHA256 N veces a propósito para que derivar la clave sea **lento**.
Para el servidor, verificar un login son unos milisegundos —imperceptible—. Para un
atacante con GPUs que prueba **miles de millones de candidatas**, multiplicar el costo por
200.000 convierte horas de crackeo en años. Es el mismo principio que "hash lento": se
sacrifica un poco de rendimiento legítimo a cambio de encarecer masivamente el ataque
offline. El parámetro `iters` es configurable justamente para subirlo con el tiempo a
medida que el hardware mejora.

---

## 3. Parte B.2 — TOTP

Implementación de `totp()` sobre `hotp()`: el contador es `t // paso` (RFC 6238).
Validado con el vector oficial: secreto ASCII `12345678901234567890`, `t=59` →
**287082** (los 8 dígitos del RFC son `94287082`). Autoevaluación: 3/3 OK.

**Si el atacante te robó la contraseña, ¿por qué el TOTP lo frena?**
La contraseña es "algo que sabés"; el TOTP es "algo que tenés" (el secreto vive en tu
teléfono/app). Aunque el atacante consiga la contraseña —por la brecha de la Parte A, por
phishing o por reuso— **no tiene el secreto TOTP**, así que no puede generar el código de
6 dígitos válido en esa ventana de 30 segundos. Sube el listón de un factor a dos.

**¿Qué NO protege el TOTP?**
- **Phishing en tiempo real / adversary-in-the-middle:** si te engañan para que tipees el
  código en un sitio falso, el atacante lo reenvía al sitio real dentro de la ventana.
- **Malware / robo de sesión:** si te roban la cookie de sesión ya autenticada, el 2FA
  ya pasó y no aporta.
- **Robo del secreto TOTP** (si el servidor lo guarda mal, o por ingeniería social del
  código de recuperación).
- **SIM swapping** en el caso de códigos por SMS (no aplica a TOTP en app, pero es el
  motivo por el que TOTP > SMS).
- Contra esto, **FIDO2/WebAuthn (passkeys)** es superior: liga la credencial al dominio,
  así que resiste phishing.

---

## 4. Bitácora de comandos

```bash
# Autoevaluación
$ python3 src/verificar.py
  ✓ hash_password / verify_password
  ✓ salt por usuario (hashes distintos)
  ✓ totp coincide con el vector del RFC 6238
  3 OK · 0 a revisar · 0 sin implementar

# Contraseñas
$ python3 src/auth.py hash --password 'Phantom-2026!'
pbkdf2_sha256$200000$1a42437a...$1bf69fbce3...

$ python3 src/auth.py verify --password 'Phantom-2026!' --registro 'pbkdf2_sha256$200000$1a42437a...$1bf69fbce3...'
OK

# TOTP — vector oficial RFC 6238
$ python3 src/auth.py totp --secret 12345678901234567890 --t 59
287082
```
