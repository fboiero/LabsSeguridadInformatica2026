# Informe — Lab Extra 4: Cracking de contraseñas

**Grupo:** 08 · **Integrantes:** Marco Cordoba — @MarcoCordoba · Thomas Koncurat — @Koncu1 · Lucas Leone — @LucasLeone · Geronimo Marquez — @Geromarquezz · Joaquin Moyano — @Joaco919

**Declaración de uso de IA:** (obligatoria — **la completa el grupo al cerrar la entrega**)

> Estado parcial: esta declaración cubre por ahora la **mitad práctica** (secciones
> 1–4 y P1). La mitad de análisis (P2–P5 y conclusión) la redacta otro integrante y
> debe sumar aquí su propia línea de declaración antes de entregar.
>
> | Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
> |---|---|---|---|
> | Claude (Anthropic) vía Claude Code | Apoyo en la implementación de `cracker.py` y en correr/medir el crackeo. | `src/cracker.py`, secciones 1–4 y P1. | **Todas las salidas pegadas son ejecución real** del cracker contra `caso/sombra.txt` (ver `evidencia/`). Las 3 flags validan contra los hashes de `labs/labextra4-cracking/retos.manifest`. El código es stdlib puro y el grupo lo comprende y puede defenderlo. |

> **⚠️ División del trabajo (grupo08).** Esta entrega está hecha a dos mitades:
> - **Mitad A — práctica (HECHA):** `cracker.py` funcional, crackeo R1–R3, apertura del
>   loot, medición de velocidad (P1) y evidencia. Secciones **1, 2, 3, 4** y **P1**.
> - **Mitad B — análisis (PENDIENTE, otro integrante):** **P2, P3, P4, P5** y la
>   **conclusión** (sección 6). Están marcadas con `TODO` más abajo.

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

<!-- TODO (otro integrante): el salt NO frena el diccionario (si la contraseña es débil,
cae igual). Lo que SÍ bloquea: (1) las tablas precalculadas / rainbow tables —cada
cuenta tiene salt distinto, así que no sirve una tabla hecha una sola vez—, y (2)
atacar todas las cuentas a la vez: sin salt, dos usuarios con la misma contraseña
tienen el mismo hash y un solo cómputo rompe a los dos; con salt por usuario hay que
atacar cuenta por cuenta. Mencionar que en sombra.txt cada salt es distinto
(73346c372d3031..34). -->
**TODO — Mitad B.**

### P3 — La contraseña del admin cumplía la política típica y cayó igual. ¿Qué le falta a esa política? ¿Qué recomienda NIST SP 800-63B?

<!-- TODO (otro integrante): la "complejidad" (mayús/minús/números/largo≥8) no mide lo
que importa: `phantom2026` cumple todo y es trivial (lemma de diccionario + año). Lo
que falta es resistencia a diccionario/patrones. NIST SP 800-63B: NO exigir reglas de
composición ni rotación periódica; SÍ longitud mínima generosa, permitir passphrases
largas, y chequear la contraseña contra listas de comprometidas/comunes (p. ej. HIBP).
Usar un gestor de contraseñas. -->
**TODO — Mitad B.**

### P4 — ¿Por qué root no cayó, en términos de trabajo por intento? Con 1.000 GPUs, ¿cuánto tarda el diccionario entero contra PBKDF2-200k?

<!-- TODO (otro integrante): PBKDF2-200k hace 200.000 iteraciones de HMAC-SHA256 por
CADA intento → el costo por intento sube ~10⁵ veces frente a un sha256 pelado. Esa es
la defensa: no achica el espacio de contraseñas, encarece cada prueba. Hacer la cuenta
con los números del lab: partir de la velocidad medida de pbkdf2 (~13/s en 1 CPU),
estimar una GPU/equipo y multiplicar por 1.000, y mostrar cuánto tarda el diccionario
(y comparar con md5). Conectar con el Lab 03 (por esto se usa hash lento + salt). -->
**TODO — Mitad B.**

### P5 — Como defensor de PhantomCorp, acciones de respuesta en orden + política de almacenamiento futura

<!-- TODO (otro integrante): la PRIMERA acción no es técnica: activar gestión de
incidentes (declarar el incidente, alcance, preservar evidencia, comunicar según
corresponda). Luego: forzar reset de todas las contraseñas (el volcado está
comprometido), invalidar sesiones, revisar reutilización, y migrar el almacenamiento a
un hash lento (Argon2id o bcrypt/scrypt, o PBKDF2 con iteraciones altas) + salt por
usuario + pepper, rehasheando en el próximo login. Chequeo contra listas de
comprometidas. -->
**TODO — Mitad B.**

## 6. Conclusión

<!-- TODO (otro integrante): 5 líneas como defensor — política concreta para PhantomCorp:
algoritmo (Argon2id/bcrypt con parámetros), salt por usuario, qué hacer con las cuentas
existentes (reset + rehash), y el cambio de mentalidad de "complejidad" a "resistencia
a diccionario + verificación contra listas comprometidas". -->
**TODO — Mitad B.**
