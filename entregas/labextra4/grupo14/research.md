# Research — Lab Extra 4: Cracking de contraseñas (Opción B — la herramienta profesional)

**Grupo:** 14 · **Declaración de uso de IA:** usamos IA para redactar y
organizar; los datos de benchmarks se contrastaron con documentación de hashcat.

## 1. Paralelización en GPU y velocidades

hashcat ejecuta el kernel del algoritmo en miles de núcleos de GPU en paralelo,
cada uno probando candidatos distintos; por eso escala con hardware. Órdenes de
magnitud típicos en GPUs de gama alta: **MD5 ≈ 10¹⁰–10¹¹ h/s**, SHA-256 ≈ 10⁹,
mientras que **bcrypt ≈ 10⁴–10⁵ h/s** y **Argon2** aún menos. La diferencia es
intencional: bcrypt/argon2 tienen costo (y memoria, en argon2) por intento, lo
que neutraliza la ventaja de la GPU. Nuestro `cracker.py` en CPU hace ~10⁶ sha256/s;
hashcat en GPU es ~1.000× más rápido para hashes rápidos.

## 2. Mask y combinator vs. nuestras reglas

- **Mask attack** (`-a 3`): fuerza bruta guiada por una plantilla de charset por
  posición (p.ej. `?u?l?l?l?d?d?d?d` = mayús+3 minús+4 dígitos). Recorre un
  espacio estructurado sin diccionario.
- **Combinator** (`-a 1`): concatena cada palabra de un diccionario con cada
  palabra de otro (o del mismo). Útil para passphrases.
- Nuestro `aplicar_reglas()` es una versión mínima de **rules** (`-r`): aplica
  transformaciones a cada lemma (sufijo de año/número, capitalize). hashcat trae
  reglosets enormes (best64, dive) y las corre en GPU.

## 3. Rainbow tables y por qué el salt las mata

Una rainbow table es un índice precalculado de hash→contraseña que cambia cómputo
por memoria. Con un **salt único por usuario**, el mismo password produce hashes
distintos: la tabla precalculada deja de servir y el atacante vuelve a tener que
hashear candidato por candidato, por cuenta.

## Pregunta de cierre

Aun con el algoritmo correcto, el crackeo sigue siendo posible si la contraseña
es débil/predecible (el algoritmo lento solo sube el costo, no lo vuelve
infinito) y si no se compara contra listas de contraseñas filtradas en el alta;
por eso la defensa real combina **algoritmo lento + política de passphrases +
bloqueo de contraseñas conocidas**.
