# Entregable — Lab Extra 4: Cracking de contraseñas

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Guadalupe Gómez (@guadagomezgg8), Lautaro Mariño (@lautaromarino0), Fernando Cagliero (@Ferca19)

**Estado parcial:** solo están completos los apartados asignados a Lorenzo: P2, P3, P5 y conclusión. Guadalupe debe aportar `cracker.py` y sus pruebas; Lautaro, R1–R3/loot/evidencia; Fernando, P1/P4 y mediciones. No se han inspeccionado los hashes ni se han presentado flags. Estado observado: 0/3.

**Declaración de uso de IA — Lorenzo:** usé ChatGPT/Codex para estructurar las respuestas asignadas y consultar las publicaciones oficiales de NIST citadas abajo. Revisé las recomendaciones contra NIST SP 800-63B-4 y SP 800-61 Rev. 3. No usé IA para estimar benchmarks ni inventar resultados de cracking. Declaraciones de los demás integrantes: pendientes.

---

## 1. Tabla de resultados

Pendiente: asignada a Lautaro. No se presentan resultados de R1–R3 ni del usuario `root` en este aporte.

## 2. Medición de velocidad (P1)

Pendiente: asignada a Fernando. No se realizaron mediciones en este aporte.

## 3. El loot

Pendiente: asignado a Lautaro. Este bloque no inspeccionó archivos `.enc` ni contraseñas recuperadas.

## 4. Las flags

`evidencia/salidas/status-extra4.txt` conserva el estado observado: R1–R3 pendientes, 0/3.

## 5. Preguntas P1–P5

### P1 — Medición

Pendiente: asignada a Fernando.

### P2 — ¿Para qué sirve el salt?

Un salt es un valor aleatorio distinto para cada contraseña, almacenado junto con el verificador. No necesita ser secreto. Al incorporarlo antes del hash, dos usuarios con la misma contraseña producen hashes diferentes; una tabla precalculada para contraseñas sin salt ya no sirve directamente. El atacante tiene que calcular candidatos para cada salt/cuenta por separado, por lo que también pierde la ventaja de reutilizar un único cómputo para todas las cuentas.

El salt no añade entropía a una contraseña débil ni impide probar palabras de diccionario contra un usuario concreto: solo cambia el cálculo necesario. La resistencia offline depende además de una función de derivación para contraseñas con costo configurado alto. NIST requiere almacenar verificadores como hashes salados con un esquema adecuado y costo tan alto como sea práctico ([NIST SP 800-63B-4, §3.1.1](https://pages.nist.gov/800-63-4/sp800-63b.html)).

### P3 — Política de contraseñas según NIST

La política basada en “mínimo ocho caracteres, mayúscula, minúscula y número” favorece cambios predecibles y no mide bien cuánto tardaría un atacante en adivinar la contraseña. NIST SP 800-63B-4 prohíbe imponer reglas de composición y exige comparar la contraseña completa con una lista de valores comunes, esperados o comprometidos. Para contraseña de un solo factor exige mínimo 15 caracteres; permite un mínimo menor —al menos ocho— si la contraseña solo forma parte de MFA. También recomienda aceptar longitudes de 64 caracteres o más, permitir password managers y autofill, y no exigir cambios periódicos salvo evidencia de compromiso. Se debe limitar la tasa de intentos online.

Para la base de datos, NIST recomienda un esquema de hash de contraseñas aprobado/actualizado, salt y costo de trabajo elegido tan alto como resulte práctico sin degradar el servicio; el costo se debe elevar con el tiempo. Esto reduce la velocidad de pruebas offline, a diferencia de aplicar SHA-256 una sola vez. Si hay evidencia de que una contraseña se comprometió, NIST requiere forzar su cambio; no recomienda rotaciones arbitrarias del calendario. Fuente: [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html) y [FAQ oficial de cambios entre ediciones](https://pages.nist.gov/800-63-4-Implementation-Resources/faqs/index.html).

### P4 — PBKDF2 y mil GPUs

Pendiente: asignada a Fernando. No se hará la extrapolación sin sus mediciones/supuestos GPU.

### P5 — Respuesta al incidente y almacenamiento futuro

1. **Activar el proceso de gestión:** declarar el incidente, avisar al responsable de respuesta y a las áreas de seguridad, identidad, legal/privacidad y negocio; nombrar un líder, establecer alcance y registrar decisiones. El primer paso organizativo coordina la respuesta y evita resets improvisados que destruyan contexto.
2. **Preservar y acotar evidencia:** conservar el volcado original y metadatos con acceso restringido, proteger logs de autenticación y de acceso a la base, identificar cuándo y dónde se expuso y determinar qué cuentas/algoritmos/salts quedaron afectados.
3. **Contener el acceso:** exigir cambio de contraseña a las cuentas afectadas, invalidar sesiones/tokens de recuperación y revocar credenciales relacionadas que pudieran haberse reutilizado. Priorizar cuentas privilegiadas y actividad sospechosa; no reutilizar contraseñas anteriores.
4. **Notificar y recuperar:** informar a responsables y usuarios afectados conforme al plan y obligaciones aplicables; verificar accesos anómalos, restaurar el servicio con verificadores seguros y monitorear intentos de reutilización o credential stuffing.
5. **Corregir y aprender:** revisar la causa de la exposición, cerrar el canal, registrar la línea de tiempo y actualizar controles. NIST SP 800-61 Rev. 3 recomienda integrar respuesta y recuperación al programa de gestión de riesgo ([NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)).

Para almacenamiento futuro: usar un esquema aprobado para password verifiers, con salt aleatorio único y costo medido/tuneado a la capacidad del verificador; registrar versión del esquema y parámetros para permitir aumentarlos. Aplicar política de longitud y blocklist de NIST, y migrar los verificadores heredados al autenticar o al forzar un reset. No guardar contraseñas en claro ni usar un hash rápido de integridad como una sola ronda de SHA-256.

## 6. Conclusión

PhantomCorp debe tratar el volcado como incidente: coordinar la respuesta, preservar evidencia, invalidar sesiones y forzar el cambio de credenciales afectadas.  
Para nuevas claves, usar PBKDF2-HMAC-SHA-256 conforme al esquema aprobado aplicable, con salt aleatorio único por cuenta.  
Ajustar y versionar el costo de derivación con mediciones del servidor; elevarlo cuando la capacidad lo permita.  
Exigir mínimo 15 caracteres para contraseña de un solo factor, bloquear contraseñas comprometidas y abandonar reglas de composición periódica.  
Migrar hashes heredados gradualmente, forzar cambio si hay compromiso y nunca usar un hash rápido de integridad como almacenamiento de contraseñas.
