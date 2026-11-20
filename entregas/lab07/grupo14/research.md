# Mini-research — Laboratorio 07

**Tema elegido:**
- [x] **A.** Consultas parametrizadas / prepared statements: cómo separan datos de código y por qué eliminan la SQLi de raíz (con ejemplo en un lenguaje).
- [ ] **B.** sqlmap por dentro
- [ ] **C.** Un caso real de RCE por command injection
- [ ] **D.** Broken Access Control (OWASP A01)

> Redactado con asistencia de Claude Code (ver declaración de IA en `informe.md`) a partir de
> conocimiento general. **Las fuentes NO fueron abiertas desde esta sesión: el grupo debe
> verificarlas antes de entregar.** El ejemplo de código sí se ejecutó (`src/demo_sqli_local.py`),
> sobre una base de datos propia, en un ejercicio didáctico ajeno al entorno del lab.

## Desarrollo

**El problema.** Cuando el código arma una consulta pegando texto del usuario a un string SQL, el motor recibe un único string y lo parsea entero: cualquier carácter de control de SQL dentro del valor del usuario (comillas, comentarios) altera la gramática de la consulta completa. Esto es CWE-89 y cae bajo OWASP A03:2021 (Injection).

**La solución.** Una *prepared statement* separa dos fases: (1) *prepare* — el motor (o el driver) recibe el texto SQL con marcadores de posición, lo parsea y fija su estructura antes de conocer los valores; (2) *execute* — los valores se envían aparte y se ligan a los marcadores como datos tipados. Los valores nunca vuelven a interpretarse como SQL, así que no existe un carácter "especial" que haya que escapar. Según el driver, el ligado ocurre en el servidor de base de datos (prepared statements nativos) o el driver escapa de forma segura del lado cliente; en ambos casos la API garantiza que el valor queda como literal. Como beneficio adicional, el plan de ejecución puede reutilizarse entre llamadas (ventaja de rendimiento, no solo de seguridad).

**Ejemplo (Python, módulo `sqlite3` de la librería estándar, ejecutado localmente en `src/demo_sqli_local.py`):**

La versión que arma el texto de la consulta concatenando el input directamente queda vulnerable: un valor de usuario que contenga una comilla y un comentario de SQL altera la condición completa y permite entrar como el usuario administrador sin conocer su clave. La versión que usa marcadores de posición y pasa los valores como una tupla aparte, en cambio, trata ese mismo texto como un simple valor de búsqueda que no matchea ninguna fila. La ejecución real de ambas variantes, con la misma entrada, se reproduce en `informe.md`, sección 4.1.

**Límites y buenas prácticas.** Los marcadores de posición solo reemplazan *valores*; nombres de tabla/columna y la dirección de un `ORDER BY` deben salir de una lista blanca, porque no se pueden pasar como parámetro. No sirve parametrizar una parte de la consulta y luego seguir concatenando SQL dinámico en otra parte. Complementar con mínimo privilegio en la cuenta de base de datos, uso correcto de ORMs (evitar construir SQL crudo con concatenación aunque el ORM lo permita), no exponer mensajes de error de SQL al usuario final, y hash con sal para las contraseñas. Validar la forma de la entrada es útil como defensa adicional, pero no sustituye parametrizar; escapar caracteres a mano es frágil y depende del motor.

## Fuentes (mín. 3, verificables; no abiertas en esta sesión)

1. OWASP Cheat Sheet Series, "SQL Injection Prevention Cheat Sheet" — https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
2. OWASP Top 10:2021, "A03:2021 – Injection" — https://owasp.org/Top10/A03_2021-Injection/
3. MITRE, CWE-89 "Improper Neutralization of Special Elements used in an SQL Command" — https://cwe.mitre.org/data/definitions/89.html
4. Documentación oficial de Python, módulo `sqlite3` (sección sobre marcadores de posición en consultas) — https://docs.python.org/3/library/sqlite3.html

## Reflexión

La falla de fondo no es "la comilla": es mezclar en un mismo canal los datos y las instrucciones. Parametrizar restituye esa separación directamente en la API de acceso a datos, y por eso funciona en los casos donde el filtrado manual de caracteres siempre termina perdiendo alguno. El mismo principio — no construir código ejecutable concatenando texto del usuario — es la razón de fondo detrás de evitar invocar una shell con comandos armados a mano, o de resolver rutas de archivo contra una base fija en vez de concatenar directamente. Lo específico de PhantomCorp queda pendiente de validar hasta que el grupo pueda correr el entorno con Docker.
