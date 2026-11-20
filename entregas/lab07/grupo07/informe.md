# Informe — Laboratorio 07 · Explotación

**Grupo:** 07 · **Fecha de preparación:** 19/11/2026

**Integrantes:** Lorenzo Blanc (@LoloBlanc), Fernando Cagliero (@Ferca19), Guadalupe Gómez (@guadagomezgg8) y Lautaro Mariño (@lautaromarino0).

## 0. Declaración de uso de IA

| Integrante | Herramienta, uso y verificación |
|---|---|
| Fernando Cagliero | OpenAI Codex para redactar y revisar P3, P4 y el mini-research, y preparar el informe y el borrador del PR. Se contrastaron los conceptos con documentación oficial de Python, SQLite, PostgreSQL y MITRE ATT&CK. El ejemplo parametrizado se ejecutó en una base SQLite en memoria con datos ficticios. Pendiente la revisión personal de Fernando. |
| Lorenzo Blanc | Pendiente de su declaración. |
| Guadalupe Gómez | Pendiente de su declaración. |
| Lautaro Mariño | Pendiente de su declaración. |

## 1. Flags capturadas

Estado del checkout local al 19/11/2026 (UTC−03:00). La captura consolidada del grupo queda pendiente. [Salida cruda](evidencia/salidas/status-07-local.txt).

```text
  ╭────────────────────────────────────────────────────────────╮
  │                     PROGRESO · LAB 07                      │
  ╰────────────────────────────────────────────────────────────╯

   ·  R1     SQLi - bypass de autenticacion
   ·  R2     SQLi - extraccion de datos con UNION
   ·  R3     Inyeccion de comandos (RCE)
   ·  R4     Path traversal / LFI
   ·  R5     IDOR - control de acceso roto

  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  0/5 (0%)

[ctf status] código de salida: 1
```

## 2. Tabla de explotación

| Vuln | Payload usado | Consulta/comando/ruta resultante | Impacto | Defensa concreta |
|---|---|---|---|---|
| SQLi auth (R1) · Lorenzo | Pendiente | | | |
| SQLi UNION (R2) · Lorenzo | Pendiente | | | |
| Command injection (R3) · Lautaro | Pendiente | | | |
| Path traversal (R4) · Lautaro | Pendiente | | | |
| IDOR (R5) · Guadalupe | Pendiente | | | |

## 3. Preguntas de análisis

### P1 — Por qué funciona el bypass

Pendiente del aporte de Guadalupe y de la evidencia de R1.

### P2 — Por qué el UNION necesita igual número de columnas

Pendiente del aporte de Guadalupe y de la evidencia de R2.

### P3 — Qué sigue después del RCE

Tras conseguir ejecución remota de comandos, un posible objetivo del atacante sería la **persistencia**. Buscaría conservar acceso al sistema si se cierra la sesión inicial, se reinicia el proceso o se corrige el punto de entrada. La viabilidad depende de los permisos de la cuenta que ejecuta la aplicación, del aislamiento del contenedor y de qué estado conserva el entorno entre reinicios. [MITRE ATT&CK — Persistence](https://attack.mitre.org/tactics/TA0003/).

En R3, la consigna plantea ejecución en el contexto del servicio. La salida cruda de Lautaro queda pendiente para precisar qué se observó. Persistencia, privilegios elevados y acceso al host son impactos distintos que requerirían evidencia adicional.

Desde la defensa, una ejecución inesperada justifica correlacionar los registros HTTP con la actividad de procesos y revisar cambios en el entorno. Si se confirma un compromiso, corresponde aislar la instancia, preservar los registros y corregir la construcción del comando antes de restaurar el servicio desde una imagen confiable.

### P4 — Por qué parametrizar evita la SQLi

Al concatenar texto de un formulario con la consulta, ese texto llega al motor como parte de la instrucción SQL. Con una consulta parametrizada, la aplicación define la instrucción con marcadores y pasa los datos por separado. En SQLite, el motor prepara la instrucción y vincula cada valor al marcador que le corresponde. Si el usuario escribe una comilla, el motor la usa como parte del valor a comparar. El filtro de la consulta conserva su estructura. [SQLite — Binding Values To Prepared Statements](https://www.sqlite.org/c3ref/bind_blob.html).

En el login, la aplicación puede buscar el usuario con `WHERE nombre = ?` y verificar la contraseña contra el hash almacenado. En el buscador, el texto de búsqueda también se pasa como parámetro del filtro. En ambos casos la defensa reside en cómo el controlador entrega el valor al motor y admite texto legítimo como `O'Reilly` sin editarlo. El mini-research incluye un ejemplo comprobado con `sqlite3`. [Python — How to use placeholders to bind values in SQL queries](https://docs.python.org/3/library/sqlite3.html#how-to-use-placeholders-to-bind-values-in-sql-queries).

### P5 — Dónde va el control de acceso del IDOR

Pendiente del aporte de Guadalupe y de la evidencia de R5.

## 4. Bitácora de comandos

La bitácora registra la consulta inicial de progreso. Los comandos y las salidas de los cinco retos quedan pendientes de los operadores indicados en la tabla. [Bitácora](evidencia/comandos.txt).
