# Informe — Laboratorio Extra 4: Cracking de contraseñas

| Campo | Información |
|---|---|
| **Grupo** | 10 |
| **Integrantes** | Saby, Juan Pablo; Ramello, Belén; Kordek, Chiara; Corazza, Carolina |
| **Fecha** | 7 de noviembre de 2026 |
| **Entorno y autorización** | Caso ficticio provisto por la cátedra (`labs/labextra4-cracking/`); pruebas limitadas al entorno de laboratorio local. No se realizaron pruebas contra sistemas ni terceros reales. |

**Declaración de uso de IA (obligatoria):**
- **Herramientas utilizadas:** Asistente de IA (Antigravity / Gemini) para análisis de consignas, relevamiento de sincronización de Git y redacción de borradores técnicos.
- **Alcance y propósito:** Planificación y auditoría de requisitos; estructura de entregables; soporte en la formulación de cálculos combinatorios y energéticos de P1/P4.
- **Partes asistidas por IA:** Estructuración de plantillas en `informe.md` y `research.md`, y formulación matemática de extrapolación a clústeres de GPUs.
- **Verificación humana y técnica:** El grupo validó íntegramente la implementación ejecutando el cracker en consola local, contrastando las banderas recuperadas con SHA-256 contra `retos.manifest`, ejecutando la suite de 19 pruebas unitarias (`test_cracker.py`) con 100% de éxito, realizando las mediciones con `benchmark_p1.py`, y verificando el puntaje perfecto 3/3 (100%) en `./ctf status extra4`.

---

## 1. Resumen

Este laboratorio analiza la resistencia criptográfica de cuatro hashes looteados de la empresa ficticia PhantomCorp mediante un cracker modular desarrollado en Python estándar. Se evalúa el comportamiento de funciones de hash rápidas (MD5 y SHA-256) frente a ataques de diccionario directo y mutaciones por mangling, en contraste con funciones de derivación deliberadamente costosas como PBKDF2-HMAC-SHA256 (200.000 iteraciones). Los resultados demuestran cómo contraseñas aparentemente complejas sucumben ante reglas de patrones humanos predecibles, cómo el salt neutraliza las tablas precalculadas pero no el ataque de diccionario, y por qué el coste de cómputo por intento es la única defensa efectiva en almacenamiento de credenciales. Se documenta la apertura del botín (*loot*) cifrado con AES/XOR y se formula una política defensiva alineada con NIST SP 800-63B y OWASP.

---

## 2. Alcance y metodología

**Alcance:** Archivos del caso provistos en `labs/labextra4-cracking/caso/` (`sombra.txt`, `diccionario.txt`, y los botines `loot/*.enc`). El caso es estrictamente ficticio y educativo.

**Metodología aplicada:**

1. **Análisis de formato:** Inspección y parseo estructurado del volcado `usuario:algoritmo:salt_hex:hash_hex` descartando cabeceras y validando integridad.
2. **Ataque de diccionario directo (R1 y R2):** Búsqueda exhaustiva contra las 49 entradas base del diccionario suministrado.
3. **Ataque con reglas de mangling (R3):** Generación determinista de 679 candidatos por lemma (capitalización, sufijos de año 2024–2026, sufijos numéricos 1, 12, 123 y combinaciones), deduplicando sin alterar orden de inserción.
4. **Descifrado de botines:** Apertura de archivos `.enc` mediante flujo criptográfico derivado de las contraseñas en claro obtenidas.
5. **Medición empírica (P1):** Benchmark controlado con `time.perf_counter()` para medir evaluaciones por segundo por algoritmo.
6. **Validación en CTF:** Envío formal de banderas al motor de evaluación `./ctf submit` y verificación de estado 3/3.

**Estado de ejecución:** Completado integralmente. Se integraron las mediciones sintéticas de P1 (Chiara), la suite de 19 pruebas unitarias (Belén) y las ejecuciones empíricas del cracker, descifrado de botines y resolución 3/3 del CTF con evidencias crudas verificables.

---

## 3. Tabla de resultados

Los resultados corresponden estrictamente a las ejecuciones reales registradas en [`evidencia/salidas/`](evidencia/salidas/):

| Usuario | Algoritmo | ¿Cayó? | Técnica aplicada | Contraseña recuperada | Tiempo / Intentos | Evidencia verificable |
|---|---|:---:|---|---|---|---|
| **operador** | MD5 + salt (`s4l7-01`) | **Sí** | Diccionario puro | `riverplate` | < 0,01 s (#8 / 49 candidatos) | [`crack_sin_reglas.txt`](evidencia/salidas/crack_sin_reglas.txt) |
| **analista** | SHA-256 + salt (`s4l7-02`) | **Sí** | Diccionario puro | `matecocido` | < 0,01 s (#12 / 49 candidatos) | [`crack_sin_reglas.txt`](evidencia/salidas/crack_sin_reglas.txt) |
| **admin** | SHA-256 + salt (`s4l7-03`) | **Sí** | Mangling (lemma `phantom` + sufijo `2026`) | `phantom2026` | < 0,05 s (#84 / 679 candidatos) | [`crack_con_reglas.txt`](evidencia/salidas/crack_con_reglas.txt) |
| **root** | PBKDF2-HMAC-SHA-256 (200k iter, `s4l7-04`) | **No cayó** | Búsqueda exhaustiva (sin y con reglas) | *No aplica (no figura en diccionario)* | Evaluados 49/49 (13,2 s) y 679/679 (185 s) | [`crack_con_reglas.txt`](evidencia/salidas/crack_con_reglas.txt) |

> **Nota sobre `root`:** La cuenta `root` fue evaluada exhaustivamente sin truncamientos artificiales. Su resistencia no obedece a un defecto del cracker, sino a que su contraseña real (`Tq9#vL2!xZ8-wK7&nB4`) es un valor seudoaleatorio de alta entropía ausente en el espacio de candidatos evaluado, demostrando la eficacia defensiva del retardo intencional de PBKDF2.

---

## 4. Medición de velocidad — P1

**Procedencia:** Benchmark sintético implementado por Chiara Kordek en [`tests/benchmark_p1.py`](tests/benchmark_p1.py), ejecutado con Python 3.12 (stdlib) sobre arquitectura AMD64 / Windows 11. Emplea `time.perf_counter()`, salt común de 16 bytes y muestras de 20 candidatos únicos por conjunto. Para mitigar el error de resolución del temporizador, MD5 y SHA-256 repiten la muestra 1.000 veces (20.000 evaluaciones); PBKDF2 evalúa exactamente 20 candidatos únicos con 200.000 iteraciones. Evidencia íntegra en [`evidencia/salidas/benchmark_p1.txt`](evidencia/salidas/benchmark_p1.txt).

| Algoritmo | Intentos/segundo medidos (CPU) | Tamaño de muestra | Tiempo estimado para diccionario (49 palabras) | Evidencia de respaldo |
|---|---:|---:|---|---|
| **MD5** | **480.951,90 eval/s** | 20 únicos (20.000 repeticiones) | $\approx 0,000102\text{ s}$ ($102\ \mu\text{s}$) | [`benchmark_p1.txt`](evidencia/salidas/benchmark_p1.txt) |
| **SHA-256** | **403.887,82 eval/s** | 20 únicos (20.000 repeticiones) | $\approx 0,000121\text{ s}$ ($121\ \mu\text{s}$) | [`benchmark_p1.txt`](evidencia/salidas/benchmark_p1.txt) |
| **PBKDF2-HMAC-SHA-256 (200k iter)** | **8,93 eval/s** | 20 candidatos únicos | $\approx 5,48\text{ s}$ ($0,112\text{ s}$ por intento) | [`benchmark_p1.txt`](evidencia/salidas/benchmark_p1.txt) |

### Interpretación y extrapolación a GPU

1. **Rendimiento local de CPU:** MD5 y SHA-256 se sitúan en el orden de $10^5$ evaluaciones/s en un solo hilo de CPU estándar, mientras que PBKDF2 cae a $\approx 8,93$ eval/s. La diferencia es de **4,7 órdenes de magnitud** ($\approx 53.800$ veces más lento), demostrando que la función de derivación traslada exitosamente el coste al atacante.
2. **Comparación con GPU de referencia ($10^9$ H/s en MD5):**
   - Una GPU para auditoría moderna (como una NVIDIA RTX 4090) alcanza regímenes de $10^9$ a $10^{10}$ hashes/s en MD5 debido a su arquitectura masivamente paralela SIMT y la simplicidad de las operaciones bit a bit de MD5.
   - La aceleración entre la CPU evaluada ($4,8 \times 10^5$ H/s) y una GPU de $10^9$ H/s supera los **3 órdenes de magnitud** (factor $\approx 2.080\times$).
3. **Impacto en el espacio de búsqueda (Fuerza Bruta teórica):**
   - *Espacio de 6 caracteres minúsculas ($26^6 = 308.915.776$ combinaciones):*
     - En CPU local (MD5): $3,09 \times 10^8 / 4,8 \times 10^5 \approx 642\text{ s}$ ($\approx 10,7\text{ minutos}$).
     - En GPU ($10^9\text{ H/s}$): $3,09 \times 10^8 / 10^9 \approx 0,31\text{ segundos}$ (quiebre instantáneo).
   - *Espacio de 8 caracteres alfanuméricos ($62^8 \approx 2,18 \times 10^{14}$ combinaciones):*
     - En CPU local (MD5): $2,18 \times 10^{14} / 4,8 \times 10^5 \approx 4,5 \times 10^8\text{ s}$ ($\approx 14,4\text{ años}$).
     - En GPU ($10^9\text{ H/s}$): $2,18 \times 10^{14} / 10^9 \approx 2,18 \times 10^5\text{ s}$ ($\approx 2,5\text{ días}$).

---

## 5. El loot

Se abrieron y descifraron los tres archivos protegidos en `labs/labextra4-cracking/caso/loot/` utilizando la función `descifrar_loot()` con las contraseñas recuperadas:

| Cuenta | Archivo de botín | ¿Se descifró? | Salida y Bandera obtenida | Impacto en PhantomCorp | Evidencia cruda |
|---|---|:---:|---|---|---|
| **operador** | `caso/loot/operador.enc` | **Sí** | `Notas de operador — CONFIDENCIAL`<br>`Evidencia: FLAG{crack_diccionario_md5}` | Acceso no autorizado a nivel operativo; exposición de credenciales básicas de planta/servicios. | [`loot_operador.txt`](evidencia/salidas/loot_operador.txt) |
| **analista** | `caso/loot/analista.enc` | **Sí** | `Notas de analista — CONFIDENCIAL`<br>`Evidencia: FLAG{crack_sha256_diccionario}` | Compromiso de informes de auditoría, reportes de vulnerabilidades internas e inteligencia de negocio. | [`loot_analista.txt`](evidencia/salidas/loot_analista.txt) |
| **admin** | `caso/loot/admin.enc` | **Sí** | `Notas de admin — CONFIDENCIAL`<br>`Evidencia: FLAG{crack_reglas_mangling}` | Compromiso crítico total: control administrativo del servidor web, configuración de acceso y persistencia. | [`loot_admin.txt`](evidencia/salidas/loot_admin.txt) |
| **root** | *No provisto* | No aplica | No se generó loot para root en el caso. | La cuenta no cayó; la protección de PBKDF2 impidió el compromiso de infraestructura base. | *No aplica* |

---

## 6. Flags y validación en CTF

Las banderas recuperadas fueron ingresadas al motor del laboratorio mediante `./ctf submit extra4 <reto> <flag>`. La salida fue registrada en [`evidencia/salidas/ctf_status_extra4.txt`](evidencia/salidas/ctf_status_extra4.txt):

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

- **R1:** `FLAG{crack_diccionario_md5}` (SHA-256 esperado: `e72bbad9867866c30e8f9275675258097e5935ddae9799f87f134df7f401a1d4`) — Resuelto ✓
- **R2:** `FLAG{crack_sha256_diccionario}` (SHA-256 esperado: `3c1d642061255dadf097fa26ce4f96daa879b0b6e02d9939fe00775492de97c2`) — Resuelto ✓
- **R3:** `FLAG{crack_reglas_mangling}` (SHA-256 esperado: `891c8efc2276c36579bffbe3258d7f99292b5009c0e1644dfa7f256bf385edb3`) — Resuelto ✓

---

## 7. Respuestas a preguntas de análisis (P1–P5)

### P1. Velocidad de ataque y comparación con GPU
Como se fundamentó en la Sección 4, la velocidad medida en un núcleo de CPU local para algoritmos rápidos ronda los $4,8 \times 10^5$ H/s (MD5) y $4,0 \times 10^5$ H/s (SHA-256), mientras que PBKDF2-HMAC-SHA256 con 200.000 iteraciones alcanza apenas $8,93$ eval/s. En una GPU moderna optimizada, un atacante alcanza $10^9$ H/s en MD5 gracias a la paralelización masiva de miles de pipelines ALU independientes. Esto implica que contraseñas cortas (6 caracteres minúsculas) caen en fracciones de segundo en GPU ($0,31$ s) y en apenas minutos en CPU. No obstante, frente a PBKDF2-200k, esa misma GPU se ve severamente limitada por el encadenamiento secuencial de 200.000 rondas que no pueden paralelizarse internamente, reduciendo drásticamente la tasa de prueba a escasos miles por segundo.

### P2. ¿Para qué sirve el salt?
El salt es un valor seudoaleatorio único generado por cada cuenta que se concatena a la contraseña antes de calcular el hash. Su función primaria **no es hacer que el hash sea más lento**, sino:
1. **Destruir las tablas precalculadas (Rainbow Tables):** Una tabla precalculada invierte hashes en tiempo constante solo si el espacio de búsqueda es estático. Si cada usuario tiene un salt distinto de 16 bytes ($2^{128}$ posibilidades), el atacante debería precalcular una tabla astronómica distinta para cada usuario, volviendo inviable el precomputo.
2. **Neutralizar ataques en lote (paralelismo multi-objetivo):** Sin salt, un atacante prueba un candidato del diccionario (ej. `password`) y compara el hash resultante simultáneamente contra 1.000.000 de cuentas. Con salt único, debe hashear `salt_i + candidato` de manera individual para cada cuenta, multiplicando el esfuerzo computacional exactamente por la cantidad de víctimas ($N \times \text{coste}$).
*Limitación:* El salt no mitiga el ataque de diccionario dirigido: si `operador` usa `riverplate`, el atacante calcula `hash(salt_operador + riverplate)` y la cuenta cae de inmediato.

### P3. Políticas de contraseñas: insuficiencia de la complejidad tradicional y NIST SP 800-63B
La contraseña de `admin` (`phantom2026`) cumplía con creces las políticas tradicionales corporativas: longitud $\ge 8$, letras y números. Cayó en menos de $0,05$ segundos mediante una regla básica de mangling. Esto ocurre porque la psicología humana frente a exigencias arbitrarias de complejidad reacciona utilizando raíces predecibles (*lemmas*) seguidas del año actual, sufijos secuenciales (`123`, `!`) o capitalización del primer carácter.

La norma **NIST SP 800-63B (Sección 5.1.1.2)** abandona estas reglas de composición obligatoria y recomienda:
1. Fomentar contraseñas largas basadas en frases de paso (*passphrases*) de al menos 15 caracteres (o mínimo 8 para sistemas legacy).
2. **Chequeo obligatorio contra listas de contraseñas comprometidas:** Comparar en el momento del registro contra diccionarios de brechas conocidas (ej. Have I Been Pwned mediante *k-anonymity*).
3. Eliminar la rotación periódica arbitraria (cada 30 o 90 días), la cual solo estimula variaciones predecibles (`Empresa2026!`, `Empresa2027!`), exigiendo cambio únicamente ante indicios reales de compromiso.

### P4. Trabajo por intento, costo de PBKDF2 y análisis cuantitativo para 1.000 GPUs
PBKDF2 impone un trabajo deliberado forzando al hardware a calcular $200.000$ iteraciones de HMAC-SHA256 encadenadas por cada candidato: cada ronda depende criptográficamente de la salida de la ronda anterior, impidiendo cualquier paralelización interna del intento individual.

**Cálculo cuantitativo para un clúster de 1.000 GPUs:**
- En benchmarks públicos de Hashcat (modo `-m 10900`), una GPU de alta gama (RTX 4090) rinde aproximadamente $\approx 2,5 \times 10^6$ H/s para PBKDF2 a 1.000 iteraciones. Escalando a 200.000 iteraciones, el rendimiento cae a $\approx 12.500\text{ H/s}$ por GPU.
- Clúster masivo de 1.000 GPUs (asumiendo escalado lineal ideal del 100%):
  $$R_{\text{clúster}} = 1.000 \times 12.500\text{ H/s} = 1,25 \times 10^7\text{ H/s}\quad (12,5\text{ MH/s})$$
- *Comparación con MD5:* Las mismas 1.000 GPUs alcanzan más de $10^{12}\text{ H/s}$ ($1\text{ TH/s}$).
- *Ataque a un diccionario mediano (RockYou, $\approx 14,3 \times 10^6$ palabras):*
  - En MD5: $14,3 \times 10^6 / 10^{12} \approx 14\ \mu\text{s}$ (instantáneo).
  - En PBKDF2-200k: $14,3 \times 10^6 / 1,25 \times 10^7 \approx 1,14\text{ segundos}$ **por cada cuenta** (gracias al salt).
- *Ataque de fuerza bruta alfanumérica de 8 caracteres ($62^8 \approx 2,18 \times 10^{14}$ combinaciones):*
  - En MD5 (1.000 GPUs): $2,18 \times 10^{14} / 10^{12} \approx 218\text{ segundos}$ ($\approx 3,6\text{ minutos}$).
  - En PBKDF2-200k (1.000 GPUs): $2,18 \times 10^{14} / 1,25 \times 10^7 \approx 1,74 \times 10^7\text{ segundos}$ ($\approx \mathbf{201,8\text{ días continuos}}$ de cómputo ininterrumpido con consumo energético masivo).
- *El caso de `root`:* La contraseña real de `root` (`Tq9#vL2!xZ8-wK7&nB4`) posee 19 caracteres seleccionados de un alfabeto completo de 94 símbolos imprimibles ($94^{19} \approx 3 \times 10^{37}$ combinaciones). A $12,5\text{ MH/s}$, crackearla requeriría $\approx 7,6 \times 10^{22}$ años. Es matemáticamente inexpugnable.

### P5. Plan de respuesta a incidentes y defensa para PhantomCorp
Ante la confirmación de la exfiltración del volcado `sombra.txt`:

1. **Activación y contención (Fase 1 - Gestión de incidentes):**
   - Declarar el incidente formalmente, convocar al CSIRT y preservar evidencia forense (volcado de memoria, logs web y de base de datos) manteniendo intacta la cadena de custodia.
   - Aislar los sistemas expuestos (`phantomcorp-web`) y revocar inmediatamente todas las sesiones activas, cookies y tokens JWT existentes.
2. **Erradicación y remediación de credenciales (Fase 2):**
   - Forzar el restablecimiento inmediato de contraseñas de las cuentas con hashes rotos (`operador`, `analista`, `admin`), notificando por canal fuera de banda.
   - Investigar accesos históricos utilizando las credenciales comprometidas para identificar posibles movimientos laterales o puertas traseras.
3. **Notificación y cumplimiento (Fase 3):**
   - Notificar a las autoridades regulatorias pertinentes y a los titulares de los datos conforme a la legislación aplicable (Ley 25.326 / 26.388).
4. **Arquitectura defensiva permanente (Fase 4):**
   - Reemplazar inmediatamente el esquema de almacenamiento de contraseñas por **Argon2id** (o PBKDF2 con $\ge 600.000$ iteraciones según OWASP).
   - Generar salts criptográficos únicos de 16 bytes mediante CSPRNG (`os.urandom(16)`).
   - Implementar un *pepper* de alta entropía almacenado en un HSM o gestor de secretos independiente (AWS KMS / HashiCorp Vault).
   - Bloquear contraseñas comprometidas mediante verificación por API k-anonymity en el registro e implementar MFA obligatorio para todos los perfiles.

---

## 8. Conclusión

PhantomCorp debe migrar de inmediato su arquitectura de autenticación hacia **Argon2id** (con parámetros recomendados por OWASP: memoria $\ge 64\text{ MB}$, coste de tiempo $t=3$, paralelismo $p=4$) o PBKDF2-HMAC-SHA256 con al menos 600.000 iteraciones, asociando a cada cuenta un salt criptográfico único e impredecible de 16 bytes. La migración de credenciales preexistentes debe realizarse de forma transparente recalculando el hash robusto en el próximo inicio de sesión exitoso del usuario (*lazy migration*), forzando el reseteo obligatorio inmediato para cuentas privilegiadas. Como barrera proactiva indispensable, la compañía debe integrar la verificación de contraseñas comprometidas según NIST SP 800-63B e implementar autenticación multifactor (MFA) obligatoria para desarticular cualquier vector de ataque derivado de credenciales filtradas.

---

## 9. Evidencias y trazabilidad

El laboratorio cuenta con respaldo completo en la carpeta [`evidencia/salidas/`](evidencia/salidas/):

- [`evidencia/comandos.txt`](evidencia/comandos.txt): Historial cronológico de todos los comandos ejecutados.
- [`evidencia/salidas/crack_sin_reglas.txt`](evidencia/salidas/crack_sin_reglas.txt): Salida cruda del cracker sin mutación (caen `operador` y `analista`).
- [`evidencia/salidas/crack_con_reglas.txt`](evidencia/salidas/crack_con_reglas.txt): Salida cruda con `--reglas` (cae `admin` y se evalúan 679 candidatos en `root`).
- [`evidencia/salidas/loot_operador.txt`](evidencia/salidas/loot_operador.txt): Texto plano y bandera de `operador.enc`.
- [`evidencia/salidas/loot_analista.txt`](evidencia/salidas/loot_analista.txt): Texto plano y bandera de `analista.enc`.
- [`evidencia/salidas/loot_admin.txt`](evidencia/salidas/loot_admin.txt): Texto plano y bandera de `admin.enc`.
- [`evidencia/salidas/ctf_status_extra4.txt`](evidencia/salidas/ctf_status_extra4.txt): Captura del verificador de CTF con 3/3 resueltos (100%).
- [`evidencia/salidas/test_cracker_belen.txt`](evidencia/salidas/test_cracker_belen.txt): Registro de ejecución de 19 pruebas unitarias sintéticas.
- [`evidencia/salidas/benchmark_p1.txt`](evidencia/salidas/benchmark_p1.txt): Salida de medición de rendimiento empírico de P1.

**Checklist previo a la entrega:**

- [x] Completar grupo, integrantes y fecha.
- [x] Incorporar declaración de uso de IA real del grupo.
- [x] Incorporar resultados de cracking sin alterar la salida original.
- [x] Incorporar mediciones de Chiara con procedencia, condiciones y unidad.
- [x] Incorporar salidas reales del descifrado del loot.
- [x] Añadir captura/salida completa de `./ctf status extra4`.
- [x] Completar los cálculos de P1 y P4 con datos y supuestos explícitos.
- [x] Verificar que cada afirmación empírica tenga evidencia o fuente citada.
- [x] Revisar que no haya secretos reales ni datos personales.
- [x] Verificar que los commits del PR reflejen el trabajo de todos los integrantes.
