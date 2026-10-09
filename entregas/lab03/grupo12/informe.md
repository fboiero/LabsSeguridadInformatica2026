# Informe — Laboratorio 03 · Autenticación

**Grupo:** 12 · **Integrantes:** Gerbaudo, Mateo (@gerbaudo19), Mariatti, Matias (@matiasmariatticasc), Colque Condo, Luis Alvaro (@ColqueAlvaro), Rodriguez, Gonzalo (@Gonza149)

## 0. Declaración de uso de IA

*Herramienta:* Gemini (Antigravity).
*Uso:* Investigación de fuentes sobre el incidente de LinkedIn 2012 y redacción técnica de la Parte A; redacción de la teoría de la Parte B.1 (salt por usuario e iteraciones).
*Partes afectadas:* Sección 1 (Parte A), la configuración del grupo (commit de @matiasmariatticasc) y la Sección 2 (Parte B.1, desarrollo teórico). El código (`src/`) y las secciones B.2 y Bitácora quedan intactas para el equipo.
*Verificación:* Se validó que los detalles técnicos del incidente correspondan históricamente a la fuga de 2012 (6.5 millones de cuentas) y que la falla explotada haya sido el uso exclusivo de SHA-1 sin salt; y que los conceptos de la Parte B.1 (unicidad del salt, inutilización de las rainbow tables y factor de costo de PBKDF2/bcrypt/scrypt/Argon2) respondan a lo pedido por el enunciado.

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

**¿Por qué un *salt* por usuario?**
El *salt* es un valor aleatorio y **único** que se genera para cada cuenta y se
combina con la contraseña antes de hashearla. Su razón de ser se ve con dos
usuarios que eligen la misma contraseña, por ejemplo `123456`:

- **Sin salt**, `SHA1("123456")` da el **mismo hash** para ambos. Quien robe la base
  ve al instante que comparten contraseña y, peor aún, **resuelve ese hash una sola
  vez** y se lleva las dos cuentas de golpe (y todas las que usen esa clave). Peor
  todavía: existen *rainbow tables*, tablas gigantes precalculadas de
  hash→contraseña para funciones **sin** salt, que revierten el hash por simple
  búsqueda en vez de por cómputo. Ese fue, justamente, el error de LinkedIn (Parte A).
- **Con salt por usuario**, cada cuenta recibe un valor aleatorio distinto, así que
  `hash("123456" + salt_A) ≠ hash("123456" + salt_B)`. Dos usuarios con la misma
  contraseña muestran hashes completamente diferentes. Esto **inhabilita las
  rainbow tables** (habría que precalcularlas para cada salt posible) y obliga al
  atacante a atacar **cuenta por cuenta**, sin poder amortizar el esfuerzo entre
  varias víctimas. El salt **no es secreto** (se guarda junto al hash en la base);
  su trabajo no es ocultar la contraseña sino garantizar **unicidad**.

**¿Por qué muchas iteraciones?**
Las funciones de hash "de propósito general" (MD5, SHA-1, SHA-256) están
optimizadas para ser **rápidas**: una GPU moderna calcula del orden de **miles de
millones** de SHA-1 por segundo. Perfecto para verificar archivos; desastroso para
contraseñas, porque el atacante con GPUs puede barrer una wordlist enorme en
minutos (otra vez, LinkedIn).

Las funciones de derivación de claves (**PBKDF2**, **bcrypt**, **scrypt**,
**Argon2**) agregan un **factor de costo**: repiten el hasheado miles o cientos de
miles de veces. Para el usuario legítimo el costo es despreciable (hashea su
contraseña una sola vez al iniciar sesión), pero para el atacante que debe probar
**millones** de candidatos, cada intento cuesta N veces más cómputo. Con
suficientes iteraciones —y, en Argon2/scrypt, además un coste de memoria para
frenar el paralelismo de las GPUs—, un ataque que antes tardaba minutos pasa a ser
inviable. El parámetro se elige para que el login del usuario siga siendo rápido en
el hardware actual y se **sube con el tiempo** a medida que el hardware se abarata.

## 3. Parte B.2 — TOTP (por qué frena el robo de contraseña; qué NO protege)

## 4. Bitácora de comandos
