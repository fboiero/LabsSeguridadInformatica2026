# Informe — Lab Extra 4: Cracking de contraseñas

**Grupo:** 02

**Integrantes:**

- Romero Jimena Soledad (legajo 15377) — @Jimena-Romero
- Milanesio Hebe Del Lourdes (legajo 15343) — @hebemilanesio1
- Toranzo Juan Cruz (legajo 15308) — @JuanToranzo
- Torres Damaris (legajo 14563) — @damaris412

**Declaración de uso de IA:** usamos Claude (Anthropic), en la interfaz de chat, para: (1) generar la implementación de los TODO de `cracker.py` (`hash_de`, `cargar_sombra`, `aplicar_reglas`, `crackear`) a partir del esqueleto y del formato exacto de `generar_caso.py`; (2) resolver problemas de entorno heredados de labs anteriores (saltos de línea CRLF al correr `./ctf` en WSL); (3) ayudar a redactar este informe a partir de las salidas reales que corrimos nosotros. Verificamos lo generado corriendo `crackear` con y sin `--reglas` contra `caso/sombra.txt`, comprobando que las contraseñas recuperadas coincidieran con el contenido descifrado de cada `.enc`, y confirmando las 3 flags con `./ctf status extra4` (3/3).

---

## 1. Tabla de resultados

| Usuario | Algoritmo | ¿Cayó? | Técnica (diccionario / regla: cuál) | Contraseña | Tiempo aprox. |
|---|---|---|---|---|---|
| operador | md5 | Sí | Diccionario puro | `riverplate` | Instantáneo (8 intentos, <0.001 s) |
| analista | sha256 | Sí | Diccionario puro | `matecocido` | Instantáneo (11 intentos, <0.001 s) |
| admin | sha256 | Sí | Regla: palabra + año (`phantom` + `2026`) | `phantom2026` | Instantáneo (95 intentos con reglas, <0.001 s) |
| root | pbkdf2 | No | — (diccionario + reglas agotado, 970 candidatos) | — | 131,48 s sin encontrarla (7 intentos/s) |

## 2. Medición de velocidad (P1)

Medimos intentos/segundo con nuestro propio cracker, cronometrando cada ataque completo contra `caso/sombra.txt` (con `caso/diccionario.txt`, 49 palabras). Para `operador` y `analista` el ataque corta apenas encuentra la contraseña, así que el número de intentos es bajo y el tiempo registrado es casi cero; para tener una muestra más estable usamos también la corrida con `--reglas`, que genera más candidatos por palabra (970 candidatos totales recorridos contra `root`, que nunca cae, dándonos una medición limpia y sostenida).

| Algoritmo | Intentos/segundo (tu máquina) | Diccionario completo (49 palabras, ~970 candidatos con reglas) tardaría… |
|---|---|---|
| md5 | ~1,7 × 10⁵ intentos/s (139 intentos en 0,001 s, corrida con reglas) | Instantáneo (menos de 10 ms) |
| sha256 | ~2,7–3,1 × 10⁵ intentos/s (196 y 95 intentos en 0,000–0,001 s) | Instantáneo (menos de 10 ms) |
| pbkdf2-200k | ~7,4 intentos/s (970 intentos en 131,48 s, medición sostenida contra `root`) | ~131 s (lo medimos directamente: recorrió el diccionario completo con reglas sin encontrarla) |

**Diferencia en órdenes de magnitud:** pbkdf2 es entre 20.000 y 40.000 veces más lento que md5/sha256 en nuestra máquina (≈170.000/7,4 ≈ 23.000×, y ≈310.000/7,4 ≈ 42.000×). Esa diferencia no es casualidad: md5 y sha256 calculan un único hash por intento, mientras que pbkdf2 repite internamente el HMAC-SHA256 **200.000 veces** por cada candidato. El algoritmo hace, a propósito, 200.000 veces más trabajo por intento.

**Qué significa para un atacante con GPU (10⁹ intentos/s en MD5, dato del enunciado):** si la proporción que medimos en CPU se mantiene en GPU, un atacante con hardware dedicado haciendo ~10⁹ intentos/s contra MD5 lograría contra PBKDF2-200k algo del orden de 10⁹ / 20.000 ≈ 5 × 10⁴ intentos/s. Es decir: el mismo hardware que prueba mil millones de contraseñas MD5 por segundo apenas prueba unas 50.000 contraseñas PBKDF2-200k por segundo. Un diccionario chico (como el de este lab) sigue cayendo casi al instante incluso contra PBKDF2 con ese poder de cómputo — por eso el tamaño del diccionario no es la defensa real (ver P4).

## 3. El loot

**`operador.enc`** (contraseña `riverplate`):

```
Notas de operador — CONFIDENCIAL
==========================
Recuperaste esto porque la contraseña era débil.
Evidencia: FLAG{crack_diccionario_md5}
```

**`analista.enc`** (contraseña `matecocido`):

```
Notas de analista — CONFIDENCIAL
==========================
Recuperaste esto porque la contraseña era débil.
Evidencia: FLAG{crack_sha256_diccionario}
```

**`admin.enc`** (contraseña `phantom2026`):

```
Notas de admin — CONFIDENCIAL
==========================
Recuperaste esto porque la contraseña era débil.
Evidencia: FLAG{crack_reglas_mangling}
```

**Impacto en la empresa ficticia:** las tres cuentas comprometidas (`operador`, `analista`, `admin`) exponen notas marcadas como confidenciales. En un incidente real esto significa que un atacante que solo lootea hashes (no contraseñas en claro) puede, en minutos, recuperar el acceso de tres de las cuatro cuentas del volcado, incluida una cuenta de administrador. Dado que es común que las personas reutilicen contraseñas entre sistemas, esas tres contraseñas en claro también habilitan *credential stuffing* contra el correo corporativo, otras aplicaciones internas o servicios externos de cada usuario.

## 4. Las flags

```
  ╭────────────────────────────────────────────────────────────╮
  │                   PROGRESO · LAB extra4                    │
  ╰────────────────────────────────────────────────────────────╯

   ✓  R1     MD5 + diccionario (caida instantanea)
   ✓  R2     SHA-256 + diccionario
   ✓  R3     SHA-256 + regla de mangling (no esta literal en el diccionario)

  ██████████████████████████████  3/3 (100%)
```

(captura completa en `evidencia/salidas/ctf-status.txt`)

## 5. Preguntas P1–P5

Ver desarrollo completo de P1 en la sección 2.

### P2 — ¿Para qué sirve el salt si no impidió que cayeran `operador` y `analista`?

El salt no hace que una contraseña de diccionario sea más difícil de adivinar por fuerza bruta de diccionario: si la contraseña es `riverplate`, el atacante la va a encontrar probando `riverplate` con el salt correspondiente, salt o no salt. Lo que el salt bloquea es otro tipo de ataque, estructuralmente distinto:

- **Tablas precalculadas (rainbow tables).** Sin salt, un atacante puede calcular de antemano el hash de millones de contraseñas comunes **una sola vez**, y después comparar ese catálogo contra cualquier volcado de hashes, de cualquier sitio, para siempre. Con salt por usuario, el hash de `riverplate` con el salt de `operador` es distinto del hash de `riverplate` con cualquier otro salt, así que esa tabla precalculada deja de servir: hay que recalcular desde cero para cada salt.
- **Atacar todas las cuentas a la vez.** Sin salt, si diez usuarios eligieron la misma contraseña, el atacante calcula un hash y rompe las diez cuentas de un solo golpe (comparando ese hash contra las diez filas del volcado). Con salt por usuario, aunque dos personas usen la misma contraseña, sus hashes son distintos, y el atacante tiene que atacar **cuenta por cuenta**, sin poder reutilizar trabajo entre usuarios.

En resumen: el salt no defiende contra el diccionario dirigido a una cuenta puntual (eso lo bloquea la velocidad del hash, no el salt), pero sí evita la reutilización de cómputo entre cuentas y entre sitios distintos, que es lo que hace viable crackear volcados completos de millones de usuarios en poco tiempo.

### P3 — La política de complejidad no alcanzó para `admin`. ¿Qué le falta? ¿Qué recomienda NIST SP 800-63B?

`phantom2026` cumple todas las reglas típicas de complejidad: tiene 11 caracteres, mezcla minúsculas y números, y "complejidad" en el sentido clásico. Sin embargo, cayó en 95 intentos con una sola regla de mangling (palabra de diccionario + año). El problema es que la política de complejidad mide **forma**, no **imprevisibilidad**: una palabra común con un año pegado al final sigue siendo un patrón extremadamente frecuente y predecible, el primero que cualquier herramienta de cracking (john, hashcat) prueba por diseño.

NIST SP 800-63B recomienda abandonar las reglas de composición obligatoria (mayúscula + número + símbolo) y en su lugar:

- Priorizar la **longitud** por sobre la complejidad forzada (permitir y fomentar passphrases largas).
- **Verificar la contraseña elegida contra listas de contraseñas filtradas/comunes conocidas** (brechas previas, diccionarios, patrones triviales) y rechazarla si aparece, en vez de exigir símbolos que el usuario termina usando de forma predecible (`Contraseña1!`).
- No forzar cambios periódicos arbitrarios de contraseña sin motivo (lo cual empuja a los usuarios a variaciones mínimas y predecibles, como pasar de `phantom2025` a `phantom2026`).

Es decir: lo que faltó en PhantomCorp no fue más complejidad, sino un chequeo contra contraseñas/palabras conocidas y previsibles, que es exactamente lo que un atacante con un diccionario y reglas de mangling explota primero.

### P4 — ¿Por qué `root` no cayó, en términos de trabajo por intento? ¿Cuánto tardaría el diccionario completo con 1.000 GPUs?

**Por qué no cayó (trabajo por intento):** la contraseña de `root` es `Tq9#vL2!xZ8-wK7&nB4`, una cadena aleatoria de 19 caracteres que mezcla mayúsculas, minúsculas, números y símbolos. Esa contraseña **no es una palabra ni una variante de una palabra**: no está en `caso/diccionario.txt` ni se genera aplicando ninguna de nuestras reglas de mangling (año, número, mayúscula inicial). No importa cuánto tiempo o cómputo tengamos: si el candidato correcto nunca se genera, el ataque de diccionario nunca lo encuentra, sin importar la velocidad del hash. Además, aunque se generara, cada intento contra `root` cuesta 200.000 iteraciones de HMAC-SHA256 (pbkdf2), así que cada candidato probado es ~20.000 a 40.000 veces más caro que un candidato contra md5/sha256 (medido en la sección 2).

**Cuenta con 1.000 GPUs contra el diccionario completo de este lab:** usando la estimación de la sección 2 (~5 × 10⁴ intentos/s por GPU contra PBKDF2-200k, derivada de escalar los 10⁹ intentos/s de MD5 por el factor de 20.000× que medimos), 1.000 GPUs en paralelo alcanzarían:

```
1.000 GPUs × 5 × 10⁴ intentos/s = 5 × 10⁷ intentos/s
```

Nuestro diccionario completo con reglas tiene 970 candidatos (medido directamente al correr `crackear --reglas` contra `root`, que los agotó sin éxito en 131,48 s con 1 núcleo). Con 1.000 GPUs:

```
970 candidatos / 5 × 10⁷ intentos/s ≈ 0,0000194 s
```

Es decir, con 1.000 GPUs el diccionario completo (chico, como el de este lab) se agotaría en **menos de 20 microsegundos**, prácticamente instantáneo. Esto muestra que el costo por iteración de pbkdf2 ralentiza mucho el ataque en una sola máquina, pero **no hace inviable un diccionario pequeño** si el atacante tiene suficiente hardware en paralelo.

**Por qué igual no cae `root` (el punto real del lab):** la verdadera defensa de `root` no es la velocidad del hash contra un diccionario chico — esa, como mostramos, se vence con suficiente paralelismo. La defensa real es que su contraseña **no pertenece al espacio de búsqueda** que cualquier diccionario razonable cubre. Si en vez de un diccionario el atacante tuviera que probar **todas las combinaciones posibles** de una cadena de 19 caracteres sobre un alfabeto de ~94 símbolos imprimibles (el tipo de ataque de fuerza bruta puro que haría falta para dar con `Tq9#vL2!xZ8-wK7&nB4` sin conocerla de antemano), el espacio de búsqueda sería del orden de:

```
94^19 ≈ 3 × 10^37 combinaciones
```

Incluso con 1.000 GPUs a 5 × 10⁴ intentos/s cada una (5 × 10⁷ intentos/s totales):

```
3 × 10^37 / 5 × 10^7 ≈ 6 × 10^29 segundos
```

Eso es muchísimos órdenes de magnitud más que la edad del universo (~4,3 × 10^17 segundos). Esa es la verdadera razón estructural de por qué `root` no cae: la combinación de (a) una contraseña de alta entropía, impredecible, que ningún diccionario razonable contiene, con (b) un algoritmo de hash deliberadamente lento (pbkdf2-200k), hace que el ataque sea inviable sin importar cuánto hardware se le arroje. Esto es exactamente lo que implementamos en el Lab 03.

### P5 — Como defensor de PhantomCorp: ¿qué hacer, en orden?

1. **Contener y notificar (gestión de incidentes, no técnico):** confirmar el alcance del volcado, aislar el sistema comprometido (phantomcorp-web) de la red, y activar el protocolo de respuesta a incidentes de la empresa. Notificar a los responsables de seguridad y, según la normativa aplicable (en Argentina, la Ley 26.388 y la normativa de protección de datos personales), evaluar la obligación de informar a los usuarios afectados y, si corresponde, a la autoridad de control.
2. **Forzar el cambio de contraseña de TODAS las cuentas del volcado**, no solo las que cayeron: si el atacante tuvo acceso al volcado completo, tiene tiempo ilimitado para seguir atacando offline las que no cayeron hoy (incluida `root`, si en el futuro mejora su diccionario o su hardware).
3. **Revocar sesiones activas y tokens** asociados a las cuentas comprometidas (`operador`, `analista`, `admin`), para que la contraseña filtrada no sirva aunque ya se haya cambiado la actual.
4. **Investigar el alcance real:** revisar logs de acceso para ver si esas credenciales ya se usaron desde IPs o ubicaciones inusuales entre el momento del robo y la detección.
5. **Migrar el almacenamiento de contraseñas:** las cuentas `operador` y `analista` estaban en MD5/SHA-256, algoritmos inadecuados para contraseñas. Hay que migrar **todo** el sistema a un algoritmo de derivación de claves lento y con salt por usuario (PBKDF2 con alta cantidad de iteraciones como ya usa `root`, o preferentemente bcrypt/Argon2, pensado específicamente para este uso), siguiendo lo implementado en el Lab 03.
6. **Verificar contraseñas nuevas contra listas de contraseñas filtradas conocidas** (siguiendo NIST SP 800-63B, ver P3), para evitar que una nueva contraseña elegida por el usuario vuelva a ser una palabra de diccionario con un patrón trivial.
7. **Capacitar a los usuarios** sobre por qué "la del club" o "palabra+año" no son contraseñas seguras, y recomendar gestores de contraseñas o passphrases largas y aleatorias.

## 6. Conclusión

Como defensores, le propondríamos a PhantomCorp lo siguiente: (1) usar un algoritmo de derivación de claves lento y memory-hard, con preferencia por Argon2id o, si no está disponible, bcrypt o PBKDF2-HMAC-SHA256 con al menos 200.000–600.000 iteraciones (ajustado anualmente según el hardware disponible); (2) salt aleatorio único por usuario, generado con un generador criptográficamente seguro, nunca reutilizado entre cuentas; (3) rechazar contraseñas nuevas que coincidan con listas de contraseñas filtradas conocidas, en vez de exigir reglas de composición rígidas; (4) para las cuentas existentes con hashes rápidos (MD5/SHA-256), forzar un cambio de contraseña inmediato y re-hashear con el algoritmo nuevo en el próximo login exitoso; (5) monitorear y alertar sobre patrones de acceso anómalos en las cuentas migradas, durante al menos las semanas siguientes al incidente, por si la ventana de exposición ya fue explotada.
