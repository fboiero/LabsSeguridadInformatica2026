# Informe — Laboratorio 03 · Autenticación

**Grupo:** 12 · **Integrantes:** Gerbaudo, Mateo (@gerbaudo19), Mariatti, Matias (@matiasmariatticasc), Colque Condo, Luis Alvaro (@ColqueAlvaro), Rodriguez, Gonzalo (@Gonza149)

## 0. Declaración de uso de IA

*Herramienta:* Gemini (Antigravity).
*Uso:* Investigación de fuentes sobre el incidente de LinkedIn 2012 y redacción técnica de la Parte A.
*Partes afectadas:* Solo la Sección 1 (Parte A) y la configuración del grupo (commit de @matiasmariatticasc). Las partes de código y teoría de la Parte B quedan intactas para el equipo.
*Verificación:* Se validó que los detalles técnicos del incidente correspondan históricamente a la fuga de 2012 (6.5 millones de cuentas) y que la falla explotada haya sido el uso exclusivo de SHA-1 sin salt.

## 1. Parte A — Análisis de la brecha: LinkedIn 2012

**El Caso:**
En junio de 2012, un atacante publicó un archivo en un foro ruso que contenía 6.5 millones de contraseñas pertenecientes a usuarios de LinkedIn. El sistema de LinkedIn prometía resguardar la confidencialidad en las credenciales de autenticación, asegurando teóricamente que un atacante no pudiera leer las claves originales aunque robara la base de datos.

**La Falla:**
LinkedIn no guardaba las contraseñas en texto plano, sino que las pasaba por la función criptográfica de hash SHA-1. El gravísimo error fue implementarlo **sin salt**. Al aplicar un hash simple y directo `SHA1(contraseña)`, contraseñas idénticas producían hashes idénticos, sin ningún componente aleatorio por usuario, y la velocidad de cálculo era inmediata.

**Cómo se explotó:**
Al carecer de *salt*, los atacantes no necesitaron romper las contraseñas una por una. Utilizaron **Rainbow Tables** (bases de datos gigantes precalculadas que mapean millones de palabras y contraseñas comunes a su respectivo hash SHA-1). Con esta técnica y fuerza bruta acelerada por GPU, en cuestión de días lograron revertir más del 60% de los hashes robados obteniendo las contraseñas en texto claro. Al hacerse públicas, estos datos facilitaron ataques de *credential stuffing* en miles de otras plataformas.

**La Forma Correcta:**
Para guardar contraseñas nunca se debe usar un hash rápido (como MD5, SHA-1 o SHA-256). LinkedIn debió utilizar algoritmos de derivación de claves diseñados específicamente para hacer lento el proceso (como **bcrypt**, **Argon2** o **PBKDF2**). Estos estándares añaden automáticamente un **salt aleatorio único** por usuario antes de procesar el texto (inutilizando las *rainbow tables*) e implementan **iteraciones** computacionales para ralentizar drásticamente la fuerza bruta con GPUs.

**Fuentes:**
- [1] Goodin, D. (2012). *8 million leaked passwords connected to LinkedIn*. Ars Technica. https://arstechnica.com/information-technology/2012/06/8-million-leaked-passwords-connected-to-linkedin/ (Fuente Secundaria).
- [2] Zetter, K. (2012). *LinkedIn Confirms Password Breach; Offers Few Details*. WIRED. https://www.wired.com/2012/06/linkedin-password-breach/ (Fuente Secundaria).

## 2. Parte B.1 — Contraseñas (por qué salt por usuario, por qué muchas iteraciones)

## 3. Parte B.2 — TOTP (por qué frena el robo de contraseña; qué NO protege)

## 4. Bitácora de comandos
