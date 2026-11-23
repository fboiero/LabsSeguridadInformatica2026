# Entregable — Lab Extra 4: Cracking de contraseñas

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0), Fernando Cagliero (@Ferca19)

**Estado:** Lorenzo completó P2/P3/P5 y la conclusión. Fernando completó P1/P4 con mediciones y cálculos. Guadalupe implementó el cracker y sus pruebas. Lautaro operó el cracker sobre el volcado: recuperó 3/4 contraseñas (operador, analista y admin; root/PBKDF2 resiste), abrió los tres loot y envió R1–R3. Estado consolidado: **3/3** (`evidencia/salidas/status-extra4.txt`).

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para estructurar las respuestas asignadas y consultar las publicaciones oficiales de NIST citadas abajo. Revisé las recomendaciones contra NIST SP 800-63B-4 y SP 800-61 Rev. 3. No usé IA para estimar benchmarks ni inventar resultados de cracking. Fernando Cagliero (@Ferca19) usó OpenAI Codex para preparar/revisar los scripts de medición y proyección, analizar sus resultados y redactar P1/P4. Las salidas adjuntas muestran mediciones CPU y una extrapolación GPU; no son una corrida de cracking ni de 1.000 GPU. No se afirman resultados de cuentas sin evidencia. **Declaración de uso de IA — Guadalupe:** usé Claude (Anthropic), vía Claude Code, para implementar las cuatro funciones del esqueleto `cracker.py` (`hash_de`, `cargar_sombra`, `aplicar_reglas`, `crackear`), sin cambiar firmas ni CLI y solo con biblioteca estándar. Lo verifiqué corriendo el cracker contra el caso del repositorio: recupera 3/4 (operador, analista y, con reglas, admin) y root/pbkdf2 no cae, como espera el lab; además contrasté `hash_de` contra cálculos de referencia de md5, sha256 y pbkdf2. La operación (tabla, loot y status) es la Parte B de Lautaro; no presento flags acá.

**Declaración de uso de IA — Lautaro Mariño (@lautaromarino0):** operé el cracker ya implementado sobre el volcado del caso y documenté la tabla de resultados, el loot y las flags (secciones 1, 3 y 4). Usé **Claude (Anthropic)** como asistente para correr el ataque en un sandbox Linux sin Docker y redactar estas secciones a partir de lo observado, que revisé antes de commitear. Las contraseñas salieron del ataque de diccionario y de reglas sobre cada hash, no de leer `caso/generar_caso.py` ni `solucion.md`; las flags salieron del loot descifrado y su `sha256` se verificó contra `retos.manifest`. No se tocaron los archivos del caso ni el cracker.

---

## 1. Tabla de resultados

Operación del cracker sobre el volcado `caso/sombra.txt` (4 usuarios, 3 algoritmos). Corrida en un sandbox Linux sin Docker (el lab es stdlib puro); el comando y la salida cruda están en `evidencia/salidas/crackeo-lautaro.txt`. No se leyó `caso/generar_caso.py` para obtener contraseñas: cada una salió del ataque sobre su hash.

| Usuario | Algoritmo (salt) | Técnica que lo tumbó | Contraseña | Reto |
|---|---|---|---|---|
| `operador` | MD5 + salt | Diccionario directo | `riverplate` | R1 |
| `analista` | SHA-256 + salt | Diccionario directo | `matecocido` | R2 |
| `admin` | SHA-256 + salt | Diccionario + **regla de mangling** (`phantom` → `phantom2026`) | `phantom2026` | R3 |
| `root` | PBKDF2, 200.000 iteraciones | — | **no cayó** | — |

Tres de cuatro cuentas cayeron, todas de forma casi instantánea: con las tasas medidas en P1 (del orden de 10⁶ hashes/s en MD5 y SHA-256 sobre esta CPU), 49 candidatos por cuenta —98 con reglas— se agotan en milisegundos. El salt **no** evitó ninguna de esas tres caídas (ver P2): obliga a atacar cuenta por cuenta, pero no encarece probar una palabra de diccionario contra un usuario concreto.

`admin` cumplía la política clásica (largo ≥ 8, mayúsculas/minúsculas/números en la variante del caso) y cayó igual, porque su contraseña es un **patrón predecible** `palabra+año` que la regla de mangling reproduce (ver P3). `root` es el único que resiste, y no por tener una contraseña más rara dentro del diccionario, sino porque su verificador es **PBKDF2-200k**: el diccionario entregado no la contiene y, aunque la contuviera, el costo por intento la volvería inviable a esta escala (ver P4).

## 2. Medición de velocidad (P1)

Medición de las primitivas de hash con hashlib en AMD Ryzen 7 3700X, Python 3.12.2 y Windows 11. Tres repeticiones; tasa mediana. No incluye E/S, comparación ni overhead del cracker completo. Diccionario: 49 entradas no vacías.

| Algoritmo | Intentos/s (CPU local) | Proyección para 49 candidatos |
|---|---:|---:|
| MD5(salt‖password) | 1.157.273 | 0,000042 s |
| SHA-256(salt‖password) | 873.897 | 0,000056 s |
| PBKDF2-HMAC-SHA256, 200.000 iteraciones | 8,89 | 5,510604 s |

PBKDF2 reduce la tasa local unas 5,11 órdenes frente a MD5 y 4,99 frente a SHA-256. Detalle reproducible: evidencia/medir_p1.py y evidencia/salidas/medicion-p1-local.txt.

## 3. El loot

Cada archivo `caso/loot/<usuario>.enc` se abre con la contraseña crackeada de ese usuario (la función `descifrar_loot()` deriva la clave AES de la password). Con las tres contraseñas recuperadas se abrieron los tres loot; la salida cruda está en `evidencia/salidas/loot-lautaro.txt`. `root` no se crackeó, así que su loot —si existiera— queda cerrado: sin la contraseña no hay clave.

Esto cierra la cadena del lab: **de hash crackeado a datos abiertos**. El loot no agrega una vulnerabilidad nueva; demuestra el **impacto** de que el verificador sea débil. Cada `.enc` contiene una nota marcada `CONFIDENCIAL` con la flag del reto como evidencia:

| Usuario | Contraseña | Contenido del loot | Flag |
|---|---|---|---|
| `operador` | `riverplate` | Nota CONFIDENCIAL | `FLAG{crack_diccionario_md5}` |
| `analista` | `matecocido` | Nota CONFIDENCIAL | `FLAG{crack_sha256_diccionario}` |
| `admin` | `phantom2026` | Nota CONFIDENCIAL | `FLAG{crack_reglas_mangling}` |

El dato que importa como defensor: el cifrado del loot era correcto (AES), pero su seguridad colgaba enteramente de la contraseña del usuario. Un buen algoritmo de cifrado no compensa una contraseña de diccionario; la única palanca que habría salvado estos datos es que el verificador de la contraseña fuera lento y la contraseña, no adivinable (ver P5).

## 4. Las flags

Las tres flags provienen del loot descifrado, no de leer el código del target ni `caso/generar_caso.py`. El `sha256` de cada una coincide con el hash del reto en `labs/labextra4-cracking/retos.manifest` (verificación en `evidencia/salidas/verificacion-flags.txt`):

- **R1** — MD5 + diccionario → `FLAG{crack_diccionario_md5}`
- **R2** — SHA-256 + diccionario → `FLAG{crack_sha256_diccionario}`
- **R3** — SHA-256 + regla de mangling → `FLAG{crack_reglas_mangling}`

Enviadas con `./ctf submit extra4 R1|R2|R3 'FLAG{...}'`; el estado consolidado es **3/3**, capturado en `evidencia/salidas/status-extra4.txt`. No hay R4/R5: `root` (PBKDF2) queda sin crackear a propósito, y es la conclusión del lab (ver P4 y P5).

## 5. Preguntas P1–P5

### P1 — Medición

La medición local muestra cerca de cinco órdenes de magnitud entre los hashes rápidos y PBKDF2-200k. Los 10⁹ MD5/s del enunciado son un ejemplo de tasa GPU, no una medición de esta CPU. La proyección separada de P4 estima una RTX 4090 a 44.284 intentos/s para 200.000 iteraciones; comparar esas referencias distintas es solo ilustrativo y ronda 4,35 órdenes, no sustituye un benchmark en la misma GPU.

### P2 — ¿Para qué sirve el salt?

Un salt es un valor aleatorio distinto para cada contraseña, almacenado junto con el verificador. No necesita ser secreto. Al incorporarlo antes del hash, dos usuarios con la misma contraseña producen hashes diferentes; una tabla precalculada para contraseñas sin salt ya no sirve directamente. El atacante tiene que calcular candidatos para cada salt/cuenta por separado, por lo que también pierde la ventaja de reutilizar un único cómputo para todas las cuentas.

El salt no añade entropía a una contraseña débil ni impide probar palabras de diccionario contra un usuario concreto: solo cambia el cálculo necesario. La resistencia offline depende además de una función de derivación para contraseñas con costo configurado alto. NIST requiere almacenar verificadores como hashes salados con un esquema adecuado y costo tan alto como sea práctico ([NIST SP 800-63B-4, §3.1.1](https://pages.nist.gov/800-63-4/sp800-63b.html)).

### P3 — Política de contraseñas según NIST

La política basada en “mínimo ocho caracteres, mayúscula, minúscula y número” favorece cambios predecibles y no mide bien cuánto tardaría un atacante en adivinar la contraseña. NIST SP 800-63B-4 prohíbe imponer reglas de composición y exige comparar la contraseña completa con una lista de valores comunes, esperados o comprometidos. Para contraseña de un solo factor exige mínimo 15 caracteres; permite un mínimo menor —al menos ocho— si la contraseña solo forma parte de MFA. También recomienda aceptar longitudes de 64 caracteres o más, permitir password managers y autofill, y no exigir cambios periódicos salvo evidencia de compromiso. Se debe limitar la tasa de intentos online.

Para la base de datos, NIST recomienda un esquema de hash de contraseñas aprobado/actualizado, salt y costo de trabajo elegido tan alto como resulte práctico sin degradar el servicio; el costo se debe elevar con el tiempo. Esto reduce la velocidad de pruebas offline, a diferencia de aplicar SHA-256 una sola vez. Si hay evidencia de que una contraseña se comprometió, NIST requiere forzar su cambio; no recomienda rotaciones arbitrarias del calendario. Fuente: [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) y [FAQ oficial de cambios entre ediciones](https://pages.nist.gov/800-63-4-Implementation-Resources/faqs/index.html).

### P4 — PBKDF2 y mil GPUs

Root no aparece porque el caso sitúa su contraseña fuera del diccionario entregado de 49 candidatos. PBKDF2 aumenta el trabajo por intento, pero ese no es el motivo observado de que el diccionario no tenga match.

El benchmark publicado para Hashcat y una RTX 4090 reporta 8.865,7 kH/s en PBKDF2-HMAC-SHA256 con 999 iteraciones (modo 10900). Escalando idealmente en proporción inversa a las iteraciones: 8.865.700 × 999 / 200.000 = 44.284 intentos/s por GPU. Referencias: [benchmark RTX 4090 de Hashcat](https://gist.github.com/Chick3nman/32e662a5bb63bc4f51b847bb422222fd) y [módulo oficial 10900](https://github.com/hashcat/hashcat/blob/master/src/modules/module_10900.c). La escala inversa es una aproximación, no una medición directa a 200.000 iteraciones.

Con 49 candidatos y 1.000 GPU, como máximo 49 GPU verifican un candidato cada una en paralelo. El tiempo ideal de ese lote es 1 / 44.284 s = 22,58 μs, antes de planificación e inicialización; las otras 951 GPU no reducen la latencia por intento. En una sola GPU, los 49 candidatos tardarían aproximadamente 0,001106 s. Cálculo reproducible: evidencia/calcular_p4_gpu.py y evidencia/salidas/calculo-p4-1000-gpus.txt. No se ejecutó cracking en GPU ni se midió una flota real.

### P5 — Respuesta al incidente y almacenamiento futuro

1. **Activar el proceso de gestión:** declarar el incidente, avisar al responsable de respuesta y a las áreas de seguridad, identidad, legal/privacidad y negocio; nombrar un líder, establecer alcance y registrar decisiones. El primer paso organizativo coordina la respuesta y evita resets improvisados que destruyan contexto.
2. **Preservar y acotar evidencia:** conservar el volcado original y metadatos con acceso restringido, proteger logs de autenticación y de acceso a la base, identificar cuándo y dónde se expuso y determinar qué cuentas/algoritmos/salts quedaron afectados.
3. **Contener el acceso:** exigir cambio de contraseña a las cuentas afectadas, invalidar sesiones/tokens de recuperación y revocar credenciales relacionadas que pudieran haberse reutilizado. Priorizar cuentas privilegiadas y actividad sospechosa; no reutilizar contraseñas anteriores.
4. **Notificar y recuperar:** informar a responsables y usuarios afectados conforme al plan y obligaciones aplicables; verificar accesos anómalos, restaurar el servicio con verificadores seguros y monitorear intentos de reutilización o credential stuffing.
5. **Corregir y aprender:** revisar la causa de la exposición, cerrar el canal, registrar la línea de tiempo y actualizar controles. NIST SP 800-61 Rev. 3 recomienda integrar respuesta y recuperación al programa de gestión de riesgo ([NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)).

Para almacenamiento futuro: usar un esquema aprobado para password verifiers, con salt aleatorio único y costo medido/tuneado a la capacidad del verificador; registrar versión del esquema y parámetros para permitir aumentarlos. Aplicar política de longitud y blocklist de NIST, y migrar los verificadores heredados al autenticar o al forzar un reset. No guardar contraseñas en claro ni usar un hash rápido de integridad como una sola ronda de SHA-256.

## 6. Conclusión

PhantomCorp debe tratar el volcado como incidente: coordinar la respuesta, preservar evidencia, invalidar sesiones y forzar el cambio de credenciales afectadas.<br>
Para nuevas claves, usar PBKDF2-HMAC-SHA-256 conforme al esquema aprobado aplicable, con salt aleatorio único por cuenta.<br>
Ajustar y versionar el costo de derivación con mediciones del servidor; elevarlo cuando la capacidad lo permita.<br>
Exigir mínimo 15 caracteres para contraseña de un solo factor, bloquear contraseñas comprometidas y abandonar reglas de composición periódica.<br>
Migrar hashes heredados gradualmente, forzar cambio si hay compromiso y nunca usar un hash rápido de integridad como almacenamiento de contraseñas.
