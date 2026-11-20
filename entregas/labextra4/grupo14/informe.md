# Entregable — Lab Extra 4: Cracking de contraseñas

**Grupo:** 14 · **Integrantes:** Peron, Fede (@fedeeperon) · Gomez Redondo, Laureano (@Laureano-GR) · Cesano, Martín (@martincesano) · Gaido, Martín (@martingaidoo) · Chiapero, Valentina (@valechiapero)

**Declaración de uso de IA:** Usamos IA para redactar el informe y pulir las
respuestas P1–P5. La implementación de `cracker.py` (hash_de, cargar_sombra,
aplicar_reglas, crackear), el crackeo real de `sombra.txt` y el descifrado del
loot los hicimos y verificamos nosotros con `./ctf submit`.

---

## 1. Tabla de resultados

| Usuario | Algoritmo | ¿Cayó? | Técnica | Contraseña | Tiempo aprox. |
|---|---|---|---|---|---|
| operador | md5 | Sí | diccionario (match directo) | `riverplate` | instantáneo (<1 ms) |
| analista | sha256 | Sí | diccionario (match directo) | `matecocido` | instantáneo (<1 ms) |
| admin | sha256 | Sí | regla de mangling (`capitalize`→no; base+año `phantom`+`2026`) | `phantom2026` | instantáneo (49 lemmas × reglas) |
| root | pbkdf2 | No | — (200k iteraciones por intento) | — | — |

## 2. Medición de velocidad (P1)

Medido con `cracker.py velocidad` (subcomando propio, 50 hashes por algoritmo):

| Algoritmo | Intentos/segundo (nuestra máquina) | Diccionario (49) tardaría… |
|---|---|---|
| md5 | ~608.000 | < 1 ms |
| sha256 | ~1.000.000 | < 1 ms |
| pbkdf2-200k | ~30 | ~1,6 s |

La brecha es de **~4–5 órdenes de magnitud**: pbkdf2-200k es ~30.000× más lento
por intento que sha256. Es exactamente el objetivo del algoritmo.

## 3. El loot

- **operador** (`riverplate`): nota confidencial →
  `Evidencia: FLAG{crack_diccionario_md5}`.
- **analista** (`matecocido`): nota confidencial →
  `Evidencia: FLAG{crack_sha256_diccionario}`.
- **admin** (`phantom2026`): nota confidencial →
  `Evidencia: FLAG{crack_reglas_mangling}`.

Impacto: cada `.enc` recuperado filtra notas internas de PhantomCorp; con la
cuenta de admin, además, el atacante tiene credenciales administrativas reales.

## 4. Las flags

`./ctf status extra4` → R1, R2, R3 en ✓ (3/3, 100%). Ver `evidencia/ctf-status.txt`.

## 5. Preguntas P1–P5

- **P1.** md5 ~608k/s, sha256 ~1M/s, pbkdf2-200k ~30/s en una CPU. Diferencia
  ~10⁴–10⁵×. Una GPU hace ~10⁹ md5/s: el diccionario (49) o incluso listas de
  miles de millones caen en segundos. Contra pbkdf2-200k, esa misma GPU baja a
  ~10⁹/200k ≈ 5.000 intentos/s: el costo por intento domina todo.
- **P2.** El salt **no** frena un ataque de diccionario dirigido a una cuenta
  (igual hashés cada candidato). Lo que bloquea es: (a) **rainbow tables**
  (tablas precalculadas: con salt por usuario, la tabla no sirve), y (b)
  **atacar todas las cuentas a la vez** — sin salt, un hash crackeado revela a
  todos los que usan esa contraseña; con salt distinto por usuario, hay que
  re-atacar cada cuenta por separado.
- **P3.** La contraseña del admin era "compleja" pero **predecible**
  (`phantom` = nombre de la empresa + año). A la política de complejidad le
  falta chequear contra **palabras del contexto/diccionarios** y **longitud**.
  NIST SP 800-63B recomienda: largo mínimo alto, **passphrases**, comparar
  contra listas de contraseñas filtradas/comunes, y **eliminar** las reglas de
  complejidad y la rotación periódica obligatoria.
- **P4.** `root` no cayó por el **trabajo por intento**: pbkdf2 hace 200.000
  HMAC-SHA256 por candidato. Con 1.000 GPUs a ~5.000 intentos/s c/u = 5×10⁶
  intentos/s. El diccionario de 49 palabras caería al instante **si la clave
  estuviera ahí** — pero no está; contra un espacio real (p.ej. 10¹⁰
  candidatos) tardarían 10¹⁰ / 5×10⁶ ≈ 2.000 s. El punto: pbkdf2 convierte un
  crackeo de segundos (sha256) en uno de horas/días para el mismo espacio.
- **P5.** Respuesta a incidente, en orden: (1) **gestión** — declarar el
  incidente, contener, notificar a los responsables. (2) Forzar **reset** de
  todas las contraseñas y revocar sesiones/tokens. (3) Investigar alcance
  (qué se looteó, desde cuándo). (4) Notificar a afectados si corresponde.
  Política futura: **pbkdf2/argon2/bcrypt** con parámetros altos, salt único
  por usuario, pepper en un secreto aparte, y validación contra listas de
  contraseñas comunes en el alta.

## 6. Conclusión

Política para PhantomCorp (5 líneas): usar **Argon2id** (o bcrypt/pbkdf2-SHA256
≥ 600k) con salt aleatorio por usuario y un pepper fuera de la base. Rechazar
en el alta contraseñas de listas filtradas y las que contengan el nombre de la
empresa. Preferir passphrases largas sobre reglas de complejidad. Para las
cuentas existentes: forzar reset (los hashes md5/sha256 actuales son
indefendibles) y re-hashear con el algoritmo nuevo en el próximo login.
