# Informe — Laboratorio 03 · Autenticación

**Grupo:** 10 · **Integrantes:** Belén Rocío Ramello — @belramello · Carolina Paula Corazza — @carocor1 · Chiara Agustina Kordek — @chiarakordek · Juan Pablo Saby — @JuanSaby

## 0. Declaración de uso de IA

## 1. Parte A — Análisis de la brecha: credential stuffing

### 1.1 El caso

### 1.2 Qué se guardó o comparó mal

### 1.3 Cómo se explotó

### 1.4 La forma correcta

### 1.5 Relación con lo que implementamos

## 2. Parte B.1 — Contraseñas

### 2.1 Decisiones de implementación

### 2.2 Preguntas de análisis

## 3. Parte B.2 — TOTP

### 3.1 Decisiones de implementación

### 3.2 Preguntas de análisis

## 4. Bitácora de comandos

### 4.1 Bitácora de comandos

### 4.2 Pruebas y medición

#### Pruebas automatizadas

Se agregó `src/pruebas_auth.py`, que usa únicamente `unittest` y otros módulos de la biblioteca estándar. Importa el `auth.py` de la misma carpeta, sin reemplazar sus funciones ni simular resultados. Incluye 15 métodos de prueba:

- Cinco vectores TOTP con HMAC-SHA-1 y seis dígitos, derivados de los vectores de ocho dígitos del apéndice B de RFC 6238; se conservan los ceros iniciales. También se verifica el vector de ocho dígitos para `t=59`. [1]
- Igualdad de códigos para `t=30` y `t=59`, y cambio entre `t=59` y `t=60`, con el secreto de prueba. Ambos primeros tiempos pertenecen a la misma ventana de 30 segundos. La desigualdad del segundo caso es un resultado esperado para ese secreto y esos tiempos, no una garantía de que nunca existan colisiones entre ventanas. [1]
- Dos registros distintos para la misma contraseña con salt aleatorio; formato de cuatro campos y prefijo `pbkdf2_sha256`; parámetros predeterminados del laboratorio y derivación contrastada con `hashlib.pbkdf2_hmac`. [4]
- Reproducción del registro con salt fijo; aceptación de la contraseña correcta; rechazo de una incorrecta y de un registro con un carácter hexadecimal del hash alterado.
- Ocho subcasos de registros mal formados: campos faltantes o sobrantes, algoritmo desconocido, iteraciones no numéricas y salt o hash no hexadecimales.

**Estado real de la ejecución:** la base revisada, commit `aa37fe0`, todavía contiene los tres `TODO` de `auth.py`. Por eso las pruebas no pasan: las llamadas a `hash_password`, `verify_password` y `totp` lanzan `NotImplementedError`. No se modificó `auth.py`. Los 22 errores corresponden a 14 métodos con un error cada uno y un método con ocho subcasos con error; no son 22 métodos diferentes.

Se ejecutó `python src/pruebas_auth.py` desde `entregas/lab03/grupo10/`, en Windows PowerShell; la segunda ejecución usó `PYTHONUTF8=1` en el subproceso para conservar los acentos. Extracto literal del resumen de esa segunda ejecución (se omiten las trazas repetidas):

```text
----------------------------------------------------------------------
Ran 15 tests in 0.010s

FAILED (errors=22)
```

Código de salida real: **1**. Mensajes de excepción observados:

```text
NotImplementedError: Completá hash_password()
NotImplementedError: Completá verify_password()
NotImplementedError: Completá totp()
```

Para repetirlo en Git Bash, desde `entregas/lab03/grupo10/`:

```sh
export PYTHONUTF8=1
python src/pruebas_auth.py
echo "Código de salida: $?"
```

#### Vectores de TOTP

Secreto ASCII público de prueba: `12345678901234567890`; HMAC-SHA-1, paso de 30 segundos y origen temporal cero. RFC 6238 publica los resultados de ocho dígitos; los de seis se obtienen tomando sus últimos seis dígitos, de acuerdo con el truncamiento decimal. [1] La columna «obtenido» corresponde a llamadas reales a `auth.totp`, no a valores copiados del RFC como si se hubieran ejecutado correctamente.

| t (segundos) | Dígitos | Esperado | Obtenido en `auth.totp` |
|---:|---:|:---:|:---|
| 59 | 6 | `287082` | `NotImplementedError` |
| 1111111109 | 6 | `081804` | `NotImplementedError` |
| 1111111111 | 6 | `050471` | `NotImplementedError` |
| 1234567890 | 6 | `005924` | `NotImplementedError` |
| 2000000000 | 6 | `279037` | `NotImplementedError` |
| 59 | 8 | `94287082` | `NotImplementedError` |

**Pendiente de integración:** cuando esté disponible la implementación de Belén, volver a ejecutar las pruebas y actualizar la salida y la columna «obtenido». Estas pruebas funcionales no demuestran por sí solas una comparación en tiempo constante ni la calidad estadística del generador de salt; esas propiedades necesitan además revisión de la implementación.

#### Medición del costo de PBKDF2

La medición es independiente del core pendiente: se llamó directamente a `hashlib.pbkdf2_hmac('sha256', ...)`, no a `auth.hash_password`. Se usaron datos públicos de laboratorio: contraseña `b'Phantom-2026!'`, salt fijo hexadecimal `00112233445566778899aabbccddeeff` (16 bytes) y clave derivada de 32 bytes. Mantenerlos constantes permite variar solo las iteraciones; el salt fijo es exclusivo del experimento, no una recomendación para almacenar contraseñas. [4]

**Equipo medido:** AMD Ryzen 7 5700U with Radeon Graphics, 8 núcleos y 16 procesadores lógicos; Windows 11, compilación 26300; Python 3.12.10 de 64 bits y OpenSSL 3.0.16. Se obtuvo el modelo mediante `Get-CimInstance Win32_Processor` y las versiones mediante `sys.version`, `platform.platform()` y `ssl.OPENSSL_VERSION`.

**Método:** un solo proceso con llamadas secuenciales, sin paralelizar intentos ni usar GPU. Para cada configuración se hicieron tres llamadas de calentamiento, excluidas del tiempo, y siete lotes medidos con `time.perf_counter()`. [5] Cada lote tuvo 100.000 llamadas para una iteración, 1.000 llamadas para 1.000 iteraciones y cinco llamadas para 200.000 iteraciones. Se dividió el tiempo de cada lote por su cantidad de llamadas y se calculó la media de los siete valores. El tiempo incluye el bucle y la llamada desde Python, pero no la generación del salt, el formato del registro ni la comparación de hashes de `verify_password`.

Para la proyección se tomó **N = 14.344.392 entradas**, cantidad de líneas de `rockyou.txt` mostrada en la documentación de Kali. [3] No se descargó ni se recorrió esa lista: se calculó el tiempo de probarla completa contra **un solo hash/salt**, con la tasa secuencial observada y sin detenerse antes por encontrar una coincidencia.

- `tiempo por intento = media(tiempo del lote / llamadas del lote)`.
- `intentos por segundo = 1 / tiempo por intento`.
- `tiempo para la lista completa = N × tiempo por intento`.

| Iteraciones | Tiempo medio por intento (ms) | Desviación estándar entre lotes (ms por intento) | Intentos/s | Tiempo estimado para 14.344.392 entradas |
|---:|---:|---:|---:|---|
| 1 | 0,011923 | 0,000221 | 83.872,83 | 171,03 s ≈ 2,85 min |
| 1.000 | 1,467827 | 0,064494 | 681,28 | 21.055,08 s ≈ 5,85 h |
| 200.000 | 278,464126 | 11,347980 | 3,59 | 3.994.398,58 s ≈ 46,23 días |

Los tiempos son mediciones locales; las duraciones de la lista son **extrapolaciones**, no tiempos de un ataque ejecutado. Se redondeó solo al presentar la tabla. Con una iteración, el costo fijo del bucle y de la llamada influye proporcionalmente más, por lo que no se debe esperar que el cociente de tiempos sea exactamente el cociente de iteraciones. La carga del equipo, las frecuencias del procesador, el código y la longitud de los candidatos también pueden cambiar las tasas.

**Reproducción del núcleo del experimento:** el script de medición se ejecutó desde una carpeta temporal fuera del repositorio, para no agregarlo a la entrega. Este bloque permite repetir el mismo método desde Git Bash sin crear otro archivo; imprimirá nuevos resultados, que pueden diferir de los anteriores:

```sh
python - <<'PY'
import hashlib
import statistics
import time

password = b"Phantom-2026!"
salt = bytes.fromhex("00112233445566778899aabbccddeeff")
n = 14_344_392
for iters, llamadas in ((1, 100_000), (1_000, 1_000), (200_000, 5)):
    for _ in range(3):
        hashlib.pbkdf2_hmac("sha256", password, salt, iters, dklen=32)
    muestras = []
    for _ in range(7):
        inicio = time.perf_counter()
        for _ in range(llamadas):
            hashlib.pbkdf2_hmac("sha256", password, salt, iters, dklen=32)
        muestras.append((time.perf_counter() - inicio) / llamadas)
    media = statistics.mean(muestras)
    print(f"{iters=}, segundos/intento={media:.12f}, "
          f"desviacion={statistics.stdev(muestras):.12f}, "
          f"intentos/s={1 / media:.6f}, segundos/lista={n * media:.6f}")
PY
```

#### Interpretación frente a un atacante

En este equipo, pasar de una a 200.000 iteraciones multiplicó el costo medido por aproximadamente **23.356**. Las iteraciones encarecen cada candidato y reducen los intentos que pueden realizarse en un tiempo dado. El salt, en cambio, separa los hashes de usuarios diferentes y evita reutilizar tablas precalculadas; no sustituye al factor de trabajo. [2]

OWASP advierte que un atacante puede usar GPU y otros recursos para evaluar candidatos en paralelo. Por lo tanto, los 46,23 días **no son una predicción para una GPU ni una garantía de seguridad**: no se midió ninguna GPU y no se atribuye una tasa a un modelo no probado. El experimento demuestra el costo creciente en este entorno, no la velocidad máxima de un atacante. Aumentar el costo tampoco convierte una contraseña débil en fuerte: si está entre las primeras candidatas, puede encontrarse mucho antes de recorrer toda la lista; si no está en ella, recorrerla completa no la recupera. [2]

Se midieron 200.000 iteraciones porque son las predeterminadas del laboratorio, **no porque constituyan una recomendación actual para producción**. La guía de OWASP consultada recomienda 600.000 iteraciones para PBKDF2-HMAC-SHA-256 y prioriza Argon2id para diseños nuevos; también exige equilibrar seguridad, tiempo de autenticación y carga del servidor. [2] No se cambió el parámetro de `auth.py` ni se instalaron bibliotecas externas.

#### Fuentes de la sección 4.2

Referencias abiertas y contrastadas para esta sección. Su numeración es local hasta que se integren en la lista general de «Fuentes consultadas».

- **[1] [PRIMARIA]** M'Raihi, D., Machani, S., Pei, M., & Rydell, J. (2011). *TOTP: Time-Based One-Time Password Algorithm* (RFC 6238, §§4–5 y apéndice B). RFC Editor. https://www.rfc-editor.org/rfc/rfc6238.txt
- **[2] [PRIMARIA]** OWASP Foundation. (s. f.). *Password Storage Cheat Sheet*. OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — Respalda salt, factor de trabajo, ataques con GPU y recomendaciones de configuración.
- **[3] [PRIMARIA]** Kali Linux. (2026, 25 de mayo). *wordlists*. Kali Linux Tools. https://www.kali.org/tools/wordlists/ — El ejemplo de `wc -l` documenta 14.344.392 líneas en `rockyou.txt`.
- **[4] [PRIMARIA]** Python Software Foundation. (s. f.). *hashlib — Secure hashes and message digests*. Python 3.12 Documentation. https://docs.python.org/3.12/library/hashlib.html#hashlib.pbkdf2_hmac — Documenta PBKDF2-HMAC, sus parámetros y el tamaño de la salida.
- **[5] [PRIMARIA]** Python Software Foundation. (s. f.). *time — Time access and conversions*. Python 3.12 Documentation. https://docs.python.org/3.12/library/time.html#time.perf_counter — Documenta el contador de alta resolución y el uso de diferencias para medir duraciones.

## Cierre

### Dificultades encontradas

### Distribución del trabajo

### Fuentes consultadas
