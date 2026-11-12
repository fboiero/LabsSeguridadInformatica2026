# Informe — Lab Extra 4: Cracking de contraseñas

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919

**Declaración de uso de IA:** (obligatoria)

> | Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
> |---|---|---|---|
> | Claude (Anthropic) vía Claude Code | Apoyo en la implementación de `cracker.py` y en correr/medir el crackeo. | `src/cracker.py`, secciones 1–4 y P1. | **Todas las salidas pegadas son ejecución real** del cracker contra `caso/sombra.txt` (ver `evidencia/`). Las 3 flags validan contra los hashes de `labs/labextra4-cracking/retos.manifest`. El código es stdlib puro y el grupo lo comprende y puede defenderlo. |
> | Claude (Anthropic) vía Claude Code | Apoyo en la redacción del análisis (Mitad B). | Secciones P2–P5 y conclusión (6). | Números anclados a la evidencia real: salts de `caso/sombra.txt` (`s4l7-01..04`) y velocidad medida (pbkdf2 ≈ 13/s). Las cuentas de P4 usan el mismo factor GPU (~1.000×) declarado en P1. El grupo revisó y comprende el análisis. |

> **División del trabajo (grupo08).** Esta entrega se hizo a dos mitades, **ambas
> completas**:
> - **Mitad A — práctica (HECHA):** `cracker.py` funcional, crackeo R1–R3, apertura del
>   loot, medición de velocidad (P1) y evidencia. Secciones **1, 2, 3, 4** y **P1**.
> - **Mitad B — análisis (HECHA):** **P2, P3, P4, P5** y la **conclusión** (sección 6).

---

## 1. Tabla de resultados

| Usuario | Algoritmo | ¿Cayó? | Técnica | Contraseña | Intentos / tiempo |
|---|---|---|---|---|---|
| operador | md5 | ✅ sí | diccionario puro | `riverplate` | 8 intentos — instantáneo |
| analista | sha256 | ✅ sí | diccionario puro | `matecocido` | 11 intentos — instantáneo |
| admin | sha256 | ✅ sí | regla de mangling `palabra+año` (`phantom`→`phantom2026`) | `phantom2026` | 210 intentos (con `--reglas`) — instantáneo |
| root | pbkdf2 (200k) | ❌ no | — (se omite: inviable, ver P4) | — | — |

Evidencia cruda: [`evidencia/salidas/crackeo-sin-reglas.txt`](evidencia/salidas/crackeo-sin-reglas.txt)
y [`evidencia/salidas/crackeo-con-reglas.txt`](evidencia/salidas/crackeo-con-reglas.txt).

El `admin` cumplía la política típica (mayúscula/minúscula + números) pero su base
(`phantom`) **sí estaba en el diccionario**: `aplicar_reglas()` le probó el sufijo
`2026` y cayó. `root` es el único que no cae, y es la lección del lab (P4).

## 2. Medición de velocidad (P1)

Medido con `hash_de()` del propio cracker (md5 y sha256 con 200.000 intentos; pbkdf2
con 200, por ser ~10⁵× más lento). Máquina: CPython 3.13, 1 hilo, Windows.
Evidencia: [`evidencia/salidas/benchmark-velocidad.txt`](evidencia/salidas/benchmark-velocidad.txt).

| Algoritmo | Intentos/segundo (nuestra máquina, 1 hilo CPU) | Diccionario del caso (50 palabras) tardaría… |
|---|---|---|
| md5 | ≈ 1.05 × 10⁶ | ≈ 0.05 ms (instantáneo) |
| sha256 | ≈ 9.2 × 10⁵ | ≈ 0.05 ms (instantáneo) |
| pbkdf2-200k | ≈ 13 | ≈ 3.9 s (y ≈ 170 s con las ~45 variantes/palabra de `--reglas`) |

**Lectura (P1).** md5 y sha256 están en el **mismo orden de magnitud** (~10⁶/s en una
CPU de un hilo): sha256 no es "más seguro" por ser más nuevo, los dos son hashes
*rápidos* y por eso **malos para contraseñas**. pbkdf2-200k corre a ~13 intentos/s:
**~80.000× más lento** que md5 (casi 5 órdenes de magnitud), que es exactamente lo que
cuestan sus 200.000 iteraciones por intento.

Extrapolación a GPU: una GPU hace ~**10⁹** md5/s, unas **1.000×** (3 órdenes) más que
nuestra CPU. Contra md5/sha256 eso vuelve instantáneo no solo este mini-diccionario
sino una rockyou entera (~14M palabras → ~0.01 s). El salt no cambia esa velocidad
(ver P2); lo único que sube el costo por intento de forma útil es el **algoritmo
lento** (ver P4).

## 3. El loot

Salida real de `descifrar`: [`evidencia/salidas/descifrado-loot.txt`](evidencia/salidas/descifrado-loot.txt).

- **operador** (`riverplate`):
  ```
  Notas de operador — CONFIDENCIAL
  Recuperaste esto porque la contraseña era débil.
  Evidencia: FLAG{crack_diccionario_md5}
  ```
- **analista** (`matecocido`): `Evidencia: FLAG{crack_sha256_diccionario}`
- **admin** (`phantom2026`): `Evidencia: FLAG{crack_reglas_mangling}`

Impacto: con una contraseña débil se abren las notas confidenciales de cada cuenta.
En una empresa real esto es acceso directo a lo que cada usuario protegía — y si la
contraseña se reutiliza (lo habitual), el mismo valor abre otros sistemas.

## 4. Las flags

```
  ╭────────────────────────────────────────────────────────────╮
  │                   PROGRESO · LAB extra4                   │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     MD5 + diccionario (caida instantanea)
   ✓  R2     SHA-256 + diccionario
   ✓  R3     SHA-256 + regla de mangling (no esta literal en el diccionario)

  ██████████████████████████████  3/3 (100%)

[ OK ] ¡Lab extra4 COMPLETO!
```

Flags validadas contra los hashes de `labs/labextra4-cracking/retos.manifest`
(ver [`evidencia/README.md`](evidencia/README.md)).

## 5. Preguntas de análisis (P1–P5)

### P1 — Medición de intentos/segundo y extrapolación a GPU ✅ (hecho)

Resuelta en la **sección 2**: md5 ≈ 1.05×10⁶/s, sha256 ≈ 9.2×10⁵/s (mismo orden),
pbkdf2-200k ≈ 13/s (~80.000× más lento). Una GPU (~10⁹ md5/s) es ~1.000× nuestra CPU:
contra hashes rápidos, cualquier diccionario cae de forma instantánea.

### P2 — Si el salt no impidió que operador y analista cayeran, ¿para qué sirve?

El salt **no frena un ataque de diccionario**: si la contraseña está en la lista, cae
igual —el atacante rehashea `salt + palabra` y compara—. Eso es justo lo que pasó con
`operador` y `analista`. El salt ataca otra cosa: **el trabajo reutilizable**.

1. **Mata las tablas precalculadas (rainbow tables).** Sin salt, un atacante usa una
   tabla hash→contraseña calculada **una sola vez** y la reutiliza contra cualquier
   volcado. Con salt por usuario esa tabla no sirve: habría que recalcularla por cada
   salt distinto.
2. **Impide romper todas las cuentas de un cómputo.** Sin salt, dos usuarios con la
   misma contraseña tienen el **mismo hash**: un intento rompe a los dos. Con salt por
   usuario cada intento prueba **una sola cuenta**; hay que atacar cuenta por cuenta.

En `caso/sombra.txt` cada usuario tiene un salt **distinto**:
`73346c372d3031 … 34`, que en ASCII son `s4l7-01`, `s4l7-02`, `s4l7-03`, `s4l7-04`.
Por eso `operador` y `analista`, aun siendo contraseñas débiles, tuvieron que crackearse
por separado. Conclusión: el salt sube el costo del atacante **a escala** (muchas
cuentas / tablas precalculadas), no el de romper **una** contraseña débil puntual. Para
eso último hace falta un **hash lento** (P4).

### P3 — La contraseña del admin cumplía la política típica y cayó igual. ¿Qué le falta a esa política? ¿Qué recomienda NIST SP 800-63B?

`phantom2026` cumple la política "fuerte" de manual: mayúscula/minúscula (bueno, al menos
minúscula), número, largo ≥ 8. Y cayó en **210 intentos** con una regla trivial
(`palabra + año`). El problema es que la política mide **composición**, no
**resistencia**: una contraseña que es *lema de diccionario + sufijo obvio* pasa todas
las reglas y sigue estando en el espacio que un cracker prueba primero. La "complejidad"
da **falsa sensación de seguridad**: empuja a la gente a patrones predecibles
(`Palabra1!`, `Empresa2026`) que el mangling cubre.

Lo que **falta** es medir lo que importa: que la contraseña **no esté en listas de
comunes/comprometidas** ni sea un patrón derivable.

**NIST SP 800-63B** (guía actual) recomienda:
- **No** exigir reglas de composición (obligar símbolos/mayúsculas/números).
- **No** forzar rotación/caducidad periódica sin motivo (empeora: la gente incrementa un
  contador).
- **Sí** longitud mínima generosa (≥ 8, idealmente más) y **permitir passphrases largas**
  (hasta 64+ caracteres, espacios incluidos).
- **Verificar la contraseña nueva contra listas de comprometidas/comunes** (p. ej. Have I
  Been Pwned / diccionarios conocidos) y rechazarla si aparece.
- Permitir pegar y usar **gestores de contraseñas**; nada de "pistas" ni preguntas de
  seguridad.

Con esa política, `phantom2026` se rechaza en el momento del alta (aparece en cualquier
lista de patrones) y `admin` nunca habría tenido una contraseña crackeable por diccionario.

### P4 — ¿Por qué root no cayó, en términos de trabajo por intento? Con 1.000 GPUs, ¿cuánto tarda el diccionario entero contra PBKDF2-200k?

**Trabajo por intento.** PBKDF2-200k ejecuta **200.000 iteraciones de HMAC-SHA256 por
cada contraseña probada**. Un `sha256` pelado es **1** operación por intento; PBKDF2-200k
son 200.000. El espacio de contraseñas es el mismo: lo que cambia es que **cada prueba
cuesta ~10⁵ veces más**. Esa es toda la defensa de un hash lento: no achica el problema,
**encarece cada disparo**. Lo medimos: md5 ≈ 1.05×10⁶/s vs pbkdf2 ≈ **13/s** en 1 hilo
CPU (sección 2) → ~80.000× más lento, consistente con las 200k iteraciones.

**Cuenta con 1.000 GPUs.** Usamos el mismo factor que en P1 (una GPU ≈ **1.000×** nuestra
CPU para este tipo de hash):

- Velocidad PBKDF2-200k: `13/s × 1.000 (GPU) × 1.000 (GPUs)` ≈ **1,3×10⁷ intentos/s**.

| Objetivo | Contra PBKDF2-200k (1.000 GPUs ≈ 1,3×10⁷/s) | Contra md5 (1.000 GPUs ≈ 10¹²/s) |
|---|---|---|
| Diccionario del caso (50 palabras) | **instantáneo** (<1 µs) | instantáneo |
| `rockyou` entera (~14×10⁶) | ~**1,1 s** | ~14 µs |
| Fuerza bruta 8 chars alfanum (62⁸ ≈ 2,2×10¹⁴) | ~1,7×10⁷ s ≈ **194 días** | ~218 s ≈ **3,6 min** |

**Por qué root no cayó.** El diccionario del caso son 50 palabras y **la de `root` no está
en él** (igual que `admin`, pero `admin` sí tenía base en el diccionario + regla). Agotado
el diccionario, el único camino es **salir a fuerza bruta**, y ahí PBKDF2-200k lo vuelve
inviable: la misma fuerza bruta que contra md5 tarda **3,6 minutos**, contra PBKDF2-200k
tarda **~194 días** —y con una passphrase un poco más larga salta a siglos—. Nota honesta:
el *mini-diccionario* de 50 palabras cae al instante incluso contra PBKDF2 (es demasiado
chico); PBKDF2 **no** salva una contraseña que está en la lista —eso lo arregla P3—, pero
**sí** hace impagable todo lo que está **fuera** de la lista.

**Conexión con el Lab 03.** Por esto el almacenamiento correcto es **hash lento
(PBKDF2/Argon2/bcrypt) + salt por usuario**: el salt frena las tablas y el ataque en masa
(P2), y el hash lento encarece cada intento hasta volver la fuerza bruta inviable (P4).
`root` es la única cuenta que sobrevive al volcado, y es exactamente la que estaba guardada
"a la Lab 03".

### P5 — Como defensor de PhantomCorp, acciones de respuesta en orden + política de almacenamiento futura

**Acciones de respuesta (en orden).** La primera **no es técnica**:

1. **Activar gestión de incidentes.** Declarar el incidente, delimitar **alcance** (qué
   volcado se fugó, qué cuentas), **preservar evidencia** y comunicar según corresponda
   (legal/compliance; notificación si aplica). El volcado `sombra.txt` ya está en manos
   del atacante → **asumir todas las contraseñas comprometidas**.
2. **Invalidar credenciales y sesiones.** Forzar **reset de contraseña de todas las
   cuentas** y **cerrar las sesiones/tokens activos** (el reset no sirve si la sesión
   vieja sigue viva).
3. **Contener reutilización.** `operador`/`analista`/`admin` usaban contraseñas débiles;
   revisar **reúso** de esas contraseñas en otros sistemas (SSO, VPN, correo) y rotarlas.
   Priorizar `admin` por privilegio.
4. **Endurecer y monitorear.** MFA donde falte, alertas de login anómalo, revisar accesos
   recientes de las cuentas caídas.

**Política de almacenamiento futura.**
- **Algoritmo:** hash lento moderno — **Argon2id** (preferido) o bcrypt/scrypt; si hay que
  quedarse en PBKDF2, con iteraciones altas (≥ las del lab). Nunca md5/sha256 pelado.
- **Salt único por usuario** (ya lo hacían) + **pepper** (secreto global fuera de la BD,
  en KMS/HSM) para que un volcado de BD solo no alcance.
- **Migración de las cuentas existentes:** no se puede "re-hashear" lo viejo sin la
  contraseña → **rehashear en el próximo login válido** (o directamente forzar reset, que
  acá además toca por el incidente).
- **En el alta/cambio:** verificar contra **listas de comprometidas/comunes** (HIBP) y
  rechazar; política estilo NIST (P3), no reglas de composición.

Así, aunque vuelva a fugarse la base, el atacante enfrenta lo que enfrentó con `root`:
cada intento es caro y el diccionario/fuerza bruta deja de ser rentable.

## 6. Conclusión

Como defensores de PhantomCorp, la lección del volcado es clara: **tres de cuatro cuentas
cayeron y solo sobrevivió la que estaba guardada con hash lento**. La política concreta:

1. **Algoritmo:** migrar a **Argon2id** (o bcrypt/scrypt; en su defecto PBKDF2 con
   iteraciones altas). md5/sha256 pelados quedan prohibidos para contraseñas.
2. **Salt único por usuario + pepper** en KMS: frena tablas precalculadas y el ataque en
   masa (P2); el hash lento encarece cada intento hasta volver la fuerza bruta inviable
   (P4).
3. **Cuentas existentes:** reset forzado por el incidente + **rehash en el próximo login**.
4. **Cambio de mentalidad:** dejar de medir "**complejidad**" (mayús/número/símbolo, que
   `phantom2026` cumplía) y pasar a **resistencia a diccionario**: longitud/passphrases y
   **verificación contra listas de comprometidas** (NIST SP 800-63B).

El salt no salva una contraseña débil y la "complejidad" tampoco; lo que salva es
**contraseña fuera de toda lista + hash lento**. Eso es, literalmente, por qué `root` no
cayó.
