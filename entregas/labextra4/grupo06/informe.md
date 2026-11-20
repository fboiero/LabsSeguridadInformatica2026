# Informe — Laboratorio Extra 4: cracking de contraseñas

**Grupo:** 06
**Fecha de las pruebas consignadas:** 2026-10-29

| Nombre y apellido | Usuario de GitHub |
|---|---|
| Martín Beccereca | martinbeccereca |
| Belén Benito | belubenito603 |
| Alejo José De Miguel | AlejoDM |
| Tomás Giudici | TomasGiudici |
| Carolina Suppo | carosuppo |

## Declaración de uso de IA

Se utilizó Codex para implementar y probar `hash_de()` y `aplicar_reglas()`, medir tasas locales y revisar la redacción. ChatGPT asistió en `cargar_sombra()`, `crackear()`, pruebas aisladas y análisis del salt. Opencode ayudó a estructurar la medición de PBKDF2, y Claude Code realizó una comprobación independiente de integración y flags.

Las implementaciones se revisaron contra el código entregado, las pruebas se reprodujeron sobre el caso ficticio y las afirmaciones de resultados se respaldan con las salidas conservadas en `evidencia/salidas/`. No se emplearon hashes ni credenciales ajenas al laboratorio.

---

## 1. Tabla de resultados

| Usuario | Algoritmo | ¿Cayó? | Técnica | Contraseña | Tiempo aprox. |
|---|---|---|---|---|---|
| operador | MD5 con salt | Sí | Diccionario | `riverplate` | No medido por cuenta; la estimación de 49 candidatos es 0,000108 s |
| analista | SHA-256 con salt | Sí | Diccionario | `matecocido` | No medido por cuenta; la estimación de 49 candidatos es 0,000099 s |
| admin | SHA-256 con salt | Sí | Reglas: palabra + año | `phantom2026` | 95 intentos y 0,000337 s en la prueba aislada |
| root | PBKDF2-HMAC-SHA256, 200.000 iteraciones | No aplicable | — | — | 13,73 candidatos/s en la medición controlada |

La regresión integrada sin reglas recuperó `operador` y `analista`; con reglas recuperó además `admin`. Las evidencias son `p5-regresion-diccionario.txt` y `p5-regresion-reglas.txt`.

`root` fue excluido deliberadamente por `crackear()` para evitar una búsqueda PBKDF2 masiva. Además, la rúbrica establece que su contraseña no existe en el caso: no puede recuperarse por diseño. Por ello, no se presenta como una búsqueda fallida ni como una contraseña resistente demostrada experimentalmente.

## 2. Medición de velocidad (P1)

Se ejecutó `evidencia/medir-p1.py` con Python 3.12.13 en Windows 11. El script importa el `cracker.py` entregado, usa candidatos sintéticos y los salts del caso, y mide con `time.perf_counter()`. Toma la mediana de 25 series de 100 intentos para MD5 y SHA-256, y de tres series de 20 para PBKDF2.

| Algoritmo | Intentos/segundo (máquina local) | Diccionario completo de 49 candidatos tardaría… |
|---|---:|---:|
| MD5 con salt | 454.545,45 | 0,000108 s |
| SHA-256 con salt | 493.096,65 | 0,000099 s |
| PBKDF2-HMAC-SHA256, 200.000 iteraciones | 13,73 | 3,569 s |

La salida cruda está en `evidencia/salidas/p1-benchmark.txt`. Esos tiempos son estimaciones de cálculo de hashes; una corrida completa agrega lectura, generación y comparación de candidatos.

Como control adicional, `evidencia/medir-pbkdf2.py` calculó 20 candidatos sintéticos con el salt de `root`, sin compararlos con su hash: 1,431237 s en total, 13,97 candidatos/s y 71,562 ms por candidato. Esta ejecución es independiente de la tasa de 13,73 y no se mezclan ambas muestras.

MD5 y SHA-256 quedaron en el mismo orden de magnitud en este equipo. PBKDF2-200k resultó aproximadamente 33.106 veces más lento que MD5 y 35.914 veces más lento que SHA-256. La diferencia relevante es que MD5 y SHA-256 realizan un hash rápido por candidato, mientras PBKDF2 repite HMAC-SHA256 200.000 veces.

## 3. El loot

Los tres descifrados se realizaron con el subcomando `descifrar` y las contraseñas recuperadas. Las salidas crudas están en `p5-loot-operador.txt`, `p5-loot-analista.txt` y `p5-loot-admin.txt`.

### operador

```text
Notas de operador — CONFIDENCIAL
==========================
Recuperaste esto porque la contraseña era débil.
Evidencia: FLAG{crack_diccionario_md5}
```

### analista

```text
Notas de analista — CONFIDENCIAL
==========================
Recuperaste esto porque la contraseña era débil.
Evidencia: FLAG{crack_sha256_diccionario}
```

### admin

```text
Notas de admin — CONFIDENCIAL
==========================
Recuperaste esto porque la contraseña era débil.
Evidencia: FLAG{crack_reglas_mangling}
```

El impacto en la empresa ficticia es que una filtración de hashes puede extenderse a datos cifrados si la misma contraseña se usa como clave. Estos resultados solo acreditan el descifrado de artefactos educativos: no demuestran acceso a cuentas o servicios reales. El XOR repetido del caso tampoco es un esquema apropiado de cifrado para producción.

## 4. Las flags

Se enviaron las tres flags recuperadas y el estado final fue 3/3. La salida completa de `./ctf status extra4`, también guardada en `evidencia/salidas/p5-status-final.txt`, fue:

```text
╭────────────────────────────────────────────────────────────╮
│                   PROGRESO · LAB extra4                   │
╰────────────────────────────────────────────────────────────╯

 ✓  R1     MD5 + diccionario (caida instantanea)
 ✓  R2     SHA-256 + diccionario
 ✓  R3     SHA-256 + regla de mangling (no esta literal en el diccionario)

██████████████████████████████  3/3 (100%)

[ OK ] ¡Lab extra4 COMPLETO! Ponete las pilas con la próxima unidad.
```

Las aceptaciones individuales se conservan en `p5-r1-submit.txt`, `p5-r2-submit.txt` y `p5-r3-submit.txt`.

## 5. Preguntas P1–P5

### P1. Trabajo por intento y significado para un atacante

La medición de la sección 2 muestra que un KDF cambia la cantidad de candidatos que puede probar un atacante. La consigna propone como escenario pedagógico una GPU capaz de realizar `10^9` intentos/s contra MD5. Para 49 candidatos, el cociente idealizado es `49 / 10^9 = 4,9 × 10⁻⁸ s`. No representa una latencia de extremo a extremo, porque omite generación de candidatos, transferencia y arranque, y no debe trasladarse a SHA-256 o PBKDF2.

PBKDF2-200k elevó el trabajo por candidato más de cuatro órdenes de magnitud en la máquina medida. Una GPU puede acelerar una implementación concreta, pero su tasa depende del algoritmo, sus parámetros y su implementación.

### P2. Salt y ataques de diccionario

Un salt es un valor no secreto incorporado al cálculo y almacenado junto al hash. Con salts distintos, una misma contraseña produce resultados distintos; por eso limita la reutilización de tablas precalculadas y de cálculos entre registros.

No impide un ataque de diccionario: quien obtiene un hash y su salt puede calcular cada candidato con ese salt y compararlo. El salt obliga a trabajar por registro, pero no protege una contraseña común como `riverplate` ni una predecible como `matecocido`. Para almacenamiento de contraseñas hace falta además un esquema lento y ajustable; MD5 y SHA-256 rápidos no son adecuados aunque usen salt.

### P3. Complejidad predecible y recomendación de NIST

`phantom2026` tiene 11 caracteres, minúsculas y dígitos. No cumple la condición de mayúsculas mencionada en la pregunta; se informa el resultado observado sin alterarlo. La debilidad sigue siendo conceptual: una palabra de diccionario más un año es una transformación barata de enumerar. Una variante con inicial mayúscula también estaba cubierta por las reglas, aunque no fue la contraseña hallada.

NIST SP 800-63B-4 exige un mínimo de 15 caracteres cuando la contraseña es el único factor y permite un mínimo de ocho cuando solo integra MFA. Recomienda permitir al menos 64 caracteres, no imponer reglas obligatorias de composición ni cambios periódicos sin evidencia de compromiso, y contrastar la contraseña completa con una lista de valores comunes, esperables o comprometidos. Una política basada solo en “mayúscula + número + símbolo” fomenta sustituciones previsibles.

### P4. Por qué root no cayó y escenario con 1.000 GPU

En este laboratorio, `root` no puede caer porque la contraseña no existe en el caso, según la rúbrica. Además, el programa excluye PBKDF2 de la corrida general y la medición de 20 candidatos no compara ningún resultado con el hash de `root`. Esto evita afirmar incorrectamente que se ejecutó una búsqueda exhaustiva que PBKDF2 resistió.

PBKDF2-HMAC-SHA256 realiza 200.000 iteraciones por candidato. Al ritmo local de 13,73 candidatos/s, 49 derivaciones costarían aproximadamente 3,569 s. No hay benchmark local de GPU; por eso cualquier cálculo requiere declarar un supuesto. Si cada GPU procesara un candidato por vez a `v = 100` candidatos/s, 49 candidatos solo ocuparían como máximo 49 de las 1.000 GPU: el límite ideal sería un intento por GPU, `1/v = 0,01 s`, más distribución y arranque. Es un modelo pedagógico, no un benchmark ni una extrapolación de la CPU.

### P5. Respuesta a una filtración real de hashes

1. Activar la gestión del incidente, designar responsables, preservar registros y contener la vía de exposición.
2. Determinar qué datos salieron, durante qué período y qué cuentas pueden estar afectadas.
3. Invalidar sesiones, tokens o credenciales relacionados según el alcance, y forzar un restablecimiento seguro de contraseñas para las cuentas expuestas.
4. Comunicar a los afectados y gestionar las notificaciones aplicables con apoyo legal o de cumplimiento.
5. Corregir la causa de la filtración y revisar el almacenamiento de contraseñas, sus parámetros y el proceso de migración.
6. Monitorear accesos anómalos e intentos de toma de cuentas, sin registrar ni reutilizar contraseñas recuperadas.

La secuencia es una propuesta para un incidente real, no una actividad efectuada en el laboratorio.

**Fuentes:** [Python `hashlib`](https://docs.python.org/3/library/hashlib.html#key-derivation); [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html); [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver); [NIST SP 800-61 Rev. 3](https://doi.org/10.6028/NIST.SP.800-61r3).

## 6. Conclusión

PhantomCorp debe almacenar contraseñas con Argon2id y parámetros revisables; si necesita PBKDF2-HMAC-SHA256 por compatibilidad o FIPS, OWASP recomienda 600.000 iteraciones. Cada registro debe tener un salt único y las contraseñas nuevas deben contrastarse contra listas de valores comprometidos. Las cuentas expuestas deben restablecer sus contraseñas, invalidar sus sesiones activas y revisarse por actividad anómala. Un KDF lento reduce la velocidad de adivinación, pero no reemplaza la respuesta a una filtración ya ocurrida.
