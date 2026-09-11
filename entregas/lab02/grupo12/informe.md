# Informe — Laboratorio 02 · Criptografía

**Grupo:** 12 · **Integrantes:** Gerbaudo, Mateo (14157 — @gerbaudo19), Mariatti, Matias (13293 — @matiasmariatticasc), Colque Condo, Luis Alvaro (14994 — @ColqueAlvaro), Rodriguez, Gonzalo (15310 — @Gonza149) · **Fecha:** 2026-05-11

**Caso Parte A:** Sony PS3 (ECDSA) — reutilización del nonce `k` (#2)

## 0. Declaración de uso de IA

*Herramienta:* Muse Spark (OpenCode) para estructurar el análisis y contrastar fuentes.
*Uso:* redacción de Parte A (§1) a partir de fuentes primarias indicadas abajo, y verificación de la fórmula de recuperación de clave.
*Partes afectadas:* Solo §1 Parte A (este commit, autor @gerbaudo19). El resto del informe queda para los otros integrantes.
*Verificación:* se contrastó cada afirmación con las 3 fuentes citadas en §1.5; las fórmulas se verificaron contra FIPS 186-4 §4 y RFC 6979.

## 1. Parte A — Análisis de la falla: Sony PS3 y ECDSA

### A.1 — Qué prometía el sistema

La PS3 implementaba una cadena de confianza basada en ECDSA (curva P-256): solo Sony, poseedor de la clave privada `d`, podía firmar ejecutables (`EBOOT.BIN`), firmwares y loaders. La consola verificaba cada binario con la clave pública correspondiente y rechazaba todo lo no firmado. La propiedad garantizada era **autenticidad e integridad del código**: el usuario tenía la garantía de que el código ejecutado provenía de Sony y no había sido modificado [1][3].

### A.2 — Cuál fue el mal uso concreto

La falla no estaba en ECDSA como algoritmo, sino en su uso. En ECDSA cada firma `(r,s)` de un mensaje `m` requiere un nonce `k` único, secreto y nunca reutilizado:

```
k aleatorio en [1, n-1]
r = (k·G)_x mod n
s = k⁻¹(H(m) + d·r) mod n
```

Sony generó `k` de forma estática/constante para todas las firmas, en lugar de aleatorio por firma o determinístico por mensaje [1]. El equipo fail0verflow lo detectó en el CCC 27C3 (2010) al observar que `r` se repetía idéntico en firmas de binarios distintos: si `k` se repite, `r` se repite [1]. Un sistema seguro debe generar `k` con un CSPRNG (`secrets` en Python) o mejor determinísticamente con `RFC 6979 HMAC(k,d,H(m))` [2]; Sony no hizo ninguno.

Este es el error clásico que distingue "algoritmo roto" de "uso roto": ECDSA seguía siendo seguro, pero su condición de seguridad más básica fue violada.

### A.3 — Qué propiedad se rompió y cómo se explotó

Se rompió la **autenticidad** (y con ella la integridad autorizada): al conocer `k` reutilizado, un atacante recupera la clave privada `d` de Sony y puede firmar cualquier código como si fuera Sony.

Explotación concreta con dos firmas distintas `(r,s1)` y `(r,s2)` sobre mensajes `m1,m2` con el mismo `k` y mismo `r`:

```
k = (H(m1) - H(m2)) · (s1 - s2)⁻¹ mod n
d = (s·k - H(m)) · r⁻¹ mod n
```

Con `d` obtenida, el atacante firma su propio `EBOOT.BIN` o custom firmware y la PS3 lo acepta como legítimo. De ahí el "PS3 Epic Fail": jailbreak permanente, carga de Linux y homebrew sin necesidad de exploit de hardware, demostrado por fail0verflow y popularizado por Geohot en enero de 2011 [1][3]. La confidencialidad del sistema también colapsa indirectamente, porque el control de acceso entero dependía de esa firma.

### A.4 — La forma correcta de haberlo hecho

Sony debió generar `k` único e impredecible por cada firma, ya sea con un generador criptográficamente seguro (CSPRNG) con suficiente entropía, o preferentemente de forma determinística según **RFC 6979** (`k = HMAC-DRBG(d, H(m))`), que deriva `k` de la clave privada y el hash del mensaje sin estado aleatorio [2]. Con `k` distinto por mensaje, `r` nunca se repite y la deducción de `d` es computacionalmente inviable. Una línea de defensa adicional es validar en tests que `r` no se repita entre firmas.

### 1.5 Fuentes

[1] fail0verflow — "Console Hacking 2010 — PS3 Epic Fail", 27th Chaos Communication Congress (27C3), Berlín, 29-dic-2010. Slides y video en media.ccc.de. Demostración de `r` constante y recuperación de clave privada de Sony.
[2] NIST FIPS PUB 186-4 §4.2 / IETF RFC 6979 (Pornin, 2013) — Deterministic Usage of DSA and ECDSA. Especifica generación de `k` y requisito de unicidad; explica construcción `k = HMAC(d, H(m))`.
[3] N. Piotrowski et al. / Geohot — análisis público enero 2011 de la cadena de confianza PS3 (bootldr → lv0 → lv2) y publicación de clave privada ECDSA de Sony tras el fallo, citado en cobertura técnica de la época.

## 2. Parte B.1 — Romper el XOR

*(A cargo de P2 — Mariatti, Matias. Completar con clave hallada `0x37`, mensaje en claro `Memo interno PhantomCorp...` y explicación de por qué clave de 1 byte es trivial por fuerza bruta 256 intentos + scoring por frecuencia.)*

## 3. Parte B.2 — Autenticación

*(A cargo de P3/P4)*
**B.2.1 length-extension · B.2.2 cómo lo resuelve HMAC · B.2.3 tiempo constante**

## 4. Bitácora

```bash
# Parte A no requiere ejecución - análisis documental con fuentes [1][2][3]
# Verificación de Parte B (para P2/P3 cuando implementen):
# cd entregas/lab02/grupo12
# python data/generar_datos.py
# python src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
# python src/cripto.py mac --clave secreta --msg "pago 100" --modo ingenuo
# python src/cripto.py mac --clave secreta --msg "pago 100" --modo hmac
```
