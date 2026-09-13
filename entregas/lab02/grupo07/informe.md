# Informe — Laboratorio 02 · Criptografía

> Copiala a `entregas/lab02/grupoXX/informe.md`. Borrá las notas en cursiva.

**Grupo:** 07
**Integrantes:** Lorenzo Blanc — @LoloBlanc · Fernando Cagliero — @Ferca19 · Guadalupe Gómez — @guadagomezgg8 · Lautaro Mariño — @lautaromarino0
**Fecha:** 12/09/2026

## 0. Declaración de uso de IA

**¿El grupo usó asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes del entregable afectó | Cómo se verificó que lo devuelto era correcto | Claude (Anthropic) — Cowork | Búsqueda y contraste de fuentes sobre derivación de claves (PBKDF2, bcrypt, scrypt, Argon2); asistencia en la redacción del mini-research y en el script de medición. | `research.md` (tema C) y `src/kdf_demo.py`. | Se accedió a cada una de las fuentes citadas y comprobó el dato afirmado en cada una; los tiempos publicados salen de ejecutar `python3 src/kdf_demo.py`; el texto fue revisado y reformulado antes de commitear. Detalle en la declaración al final de `research.md`. |
|---|---|---|---|
|

*El grupo declara que comprende el contenido íntegro de lo entregado y que puede explicar y defender oralmente cualquier parte del código y del análisis, independientemente de la asistencia recibida.*

## 1. Parte A — Análisis de la falla

**Caso:** _(el asignado)_
**A.1 — Qué prometía · A.2 — El mal uso · A.3 — Propiedad rota y explotación · A.4 — Lo correcto**

## 2. Parte B.1 — Romper el XOR

**Clave hallada:** `0x37` (55 en decimal)

**Mensaje en claro:**

> Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

**Salida del comando:**

```
$ python src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
clave=0x37
Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.
```

**Por qué falla el cifrado clásico:**

El cifrado se pudo romper porque la clave utilizada era de solo 1 byte, por lo que existen únicamente 2⁸ = 256 claves posibles. Esto hace que probar todas las combinaciones mediante fuerza bruta sea prácticamente instantáneo. Una vez generado cada candidato, se puede determinar cuál es el texto correcto mediante análisis de frecuencia: un texto en español contiene muchos espacios, vocales y letras frecuentes, por lo que el candidato correcto obtiene un puntaje mayor al comparar sus bytes con un conjunto de caracteres esperados. En cambio, al utilizar una clave incorrecta, los bytes resultantes presentan una distribución mucho menos compatible con el lenguaje natural.

El problema, entonces, no es que XOR sea una operación débil, sino que se utilizó una clave demasiado corta para ofrecer seguridad frente a un ataque de fuerza bruta. Esto también se relaciona con el principio de Kerckhoffs: el algoritmo puede ser conocido públicamente y la seguridad debe depender de la clave; en este caso, una clave de solo 8 bits no ofrece suficiente seguridad. Para evitar este problema sería necesario utilizar una clave suficientemente larga y generada de forma aleatoria; por ejemplo, una clave de 16 bytes tendría 2¹²⁸ posibilidades, haciendo inviable una búsqueda exhaustiva. Además, durante las pruebas observamos que dos claves diferentes podían producir el mismo texto con las mayúsculas y minúsculas invertidas, como ocurrió con `MEMO INTERNO PHANTOMCORP` y `Memo interno PhantomCorp`. Esto se debe a que, en ASCII, una letra mayúscula y su correspondiente minúscula difieren en un solo bit, por lo que dos claves que difieren en ese bit producen el mismo texto con el caso cambiado.

## 3. Parte B.2 — Autenticación

**B.2.1 length-extension · B.2.2 cómo lo resuelve HMAC · B.2.3 tiempo constante**

## 4. Bitácora

```bash
python data/generar_datos.py
python src/cripto.py xor --texto hola --clave K
python src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
python src/verificar.py
```
