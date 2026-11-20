# Entregable — Lab Extra 3: Defendé PhantomCorp

**Grupo:** 07 · **Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero
(@Ferca19), Guadalupe Gómez (@guadagomezgg8) y Lautaro Mariño
(@lautaromarino0) · **Fecha:** 19/11/2026 (America/Buenos_Aires)

## Declaración de uso de IA

Fernando Cagliero (@Ferca19) usó OpenAI Codex para revisar la copia vulnerable,
implementar D4/D5, preparar una prueba local acotada y redactar P4. La evidencia
registra el resultado real del verificador: 2/5 (D4 y D5 aprobadas); no se
declaran aprobadas las defensas que corresponden a otros bloques.

## 1. Tabla de defensas (antes → después)

| Defensa | Ataque que funcionaba | Fix aplicado | Verificación |
|---|---|---|---|
| D1 | Pendiente de integración del equipo. | Pendiente. | El verificador todavía la detecta vulnerable. |
| D2 | Pendiente de integración del equipo. | Pendiente. | El verificador todavía la detecta vulnerable. |
| D3 | Pendiente de integración del equipo. | Pendiente. | El verificador todavía la detecta vulnerable. |
| D4 | `admin'--` y ` OR 1=1` podían alterar la consulta de login. | `server.py` usa `?` y enlaza `(user, pwd)` como parámetros SQLite; los datos dejan de formar parte del texto SQL. | Ambos bypasses devuelven 401; el usuario válido y contraseña legítima devuelven 200. Salida: [`verificacion-d4-d5.txt`](evidencia/salidas/verificacion-d4-d5.txt). |
| D5 | `archivo=../../etc/passwd` podía salir del directorio público. | Se calcula `realpath` del destino y la raíz, y `commonpath` exige que el destino permanezca dentro de la raíz, incluso tras decodificar la query y resolver segmentos/enlaces. | El traversal directo, codificado y un nombre con prefijo similar quedan bloqueados; `manual.txt` sigue descargándose. Salida: [`verificacion-d4-d5.txt`](evidencia/salidas/verificacion-d4-d5.txt). |

## 2. Regresión funcional

El harness local comprueba `GET /` (200), login legítimo de `admin`
(`sup3r-s3cr3t0`, 200), ambos intentos de SQLi (401) y descarga de
`manual.txt` (200), además de los casos de traversal. Comando y salida:
[`comandos.txt`](evidencia/comandos.txt) y
[`verificacion-d4-d5.txt`](evidencia/salidas/verificacion-d4-d5.txt).

## 3. Evidencia de progreso

La corrida registrada del verificador termina en **2/5**: D4 y D5 pasan; D1,
D2 y D3 continúan vulnerables. No se presenta una corrida inicial 0/5, una
corrida final 5/5 ni `ctf status extra3`, porque no se ejecutaron/capturaron
como parte de este bloque. Deben añadirse al integrar los aportes del equipo.

## 4. Preguntas P1–P5

**P1:** pendiente de integración del equipo.

**P2:** pendiente de integración del equipo.

**P3:** pendiente de integración del equipo.

**P4 — por qué `user.replace("'", "")` no alcanza.** El reemplazo intenta
reconocer una parte de la sintaxis SQL y depende de una lista incompleta de
caracteres y formas de escritura. No separa de manera fiable el dato del
código: comentarios, operadores, codificaciones, diferencias entre motores y
otros contextos de consulta pueden dejar variantes sin cubrir. Además, la
validación y el escape manual son fáciles de aplicar de forma inconsistente.
Una consulta parametrizada conserva fija la estructura SQL y transmite el
usuario y la contraseña por separado como valores; el motor no los interpreta
como operadores ni cláusulas. Esa separación es la defensa estructural. El
parche D4 usa esta forma y la evidencia bloquea los dos payloads del verificador.

**P5:** pendiente de integración del equipo.

## 5. Conclusión

Pendiente de integración grupal.
