# Mini-research — Laboratorio 07

**Grupo:** 09
**Tema elegido:** **B.** sqlmap por dentro: cómo detecta la inyección
(boolean-based, time-based, error-based) y qué significa cada técnica.

---

## Desarrollo

### Qué hace sqlmap, en una frase

sqlmap no "adivina" una inyección: la **confirma empíricamente**. Manda al
parámetro objetivo una serie de payloads diseñados para que, si hay SQLi,
la respuesta del servidor cambie de forma predecible y medible. Si el cambio
ocurre exactamente como predice la hipótesis, hay inyección; si no, prueba la
siguiente técnica. Es, en esencia, el mismo método manual del R1/R2 de este
lab, pero sistematizado y con decenas de variantes de sintaxis para distintos
motores de base de datos (MySQL, PostgreSQL, SQLite, MSSQL, Oracle...).

### Las técnicas de detección

**1. Error-based.** sqlmap inyecta un payload que **fuerza un error de sintaxis
SQL a propósito** cuando la base de datos intenta ejecutar la parte inyectada
(por ejemplo, forzar una conversión de tipo inválida que incluye, dentro del
mensaje de error, el resultado de una subconsulta). Si la aplicación devuelve
el mensaje de error de la base de datos en la respuesta HTTP —como hace
`/buscar` en este lab, que manda `f"Error SQL: {e}"` al cliente—, sqlmap puede
**leer datos directamente del texto del error**, sin necesidad de inferir nada
bit a bit. Es la técnica más rápida cuando la app es "verbosa" con los errores
(exactamente la pista que da el R2 del lab: "el servidor es verboso con los
errores SQL a propósito").

**2. Boolean-based (blind).** Cuando la app **no** muestra errores ni
resultados distinguibles, sqlmap inyecta una condición que es forzosamente
`TRUE` (`' AND 1=1--`) y después una que es forzosamente `FALSE` (`' AND
1=2--`), y compara las dos respuestas HTTP (tamaño, contenido, código de
estado). Si la página cambia de forma consistente entre el caso `TRUE` y el
`FALSE` —por ejemplo, la vista de "resultados encontrados" contra "sin
resultados"—, esa diferencia binaria es el canal de fuga: sqlmap la usa para
extraer datos **carácter por carácter**, preguntando repetidamente cosas como
"¿el primer carácter del nombre de la tabla es mayor que 'm' en ASCII?" hasta
reconstruir el valor completo. Es lenta (muchísimas requests) pero funciona
incluso cuando la aplicación no filtra absolutamente nada visible.

**3. Time-based (blind).** La variante para cuando ni siquiera hay una
diferencia visible entre `TRUE` y `FALSE` (por ejemplo, la página se ve
idéntica en ambos casos). sqlmap inyecta una condición que, si es verdadera,
dispara una función de **retraso** de la base de datos (`SLEEP(5)` en MySQL,
`WAITFOR DELAY '0:0:5'` en MSSQL, `pg_sleep(5)` en PostgreSQL). Si la respuesta
HTTP demora esos 5 segundos, la condición era verdadera; si responde al
instante, era falsa. El **tiempo de respuesta** se convierte en el único canal
de información. Es la técnica más lenta de todas (cada bit de dato cuesta
segundos reales), y la que se usa cuando las otras dos fallan — es el último
recurso, no el primero.

**4. UNION-based y stacked queries (relacionadas).** sqlmap también prueba la
técnica que usamos a mano en el R2: si logra que el número de columnas
coincida (lo prueba con `ORDER BY` creciente, como describimos en la P2 del
informe), anexa un `UNION SELECT` y **lee los datos directamente en la
respuesta**, sin tener que inferir bit a bit. Cuando el motor lo permite,
también prueba *stacked queries* (`; INSERT ...`, `; DROP ...`): varias
sentencias separadas por `;` en un mismo request, lo que puede escalar de
"leer datos" a "modificar la base" o incluso ejecutar comandos del sistema
operativo (en MSSQL, vía `xp_cmdshell`).

### Por qué prueba en ese orden (y por qué importa)

sqlmap prioriza las técnicas de menor costo (error-based, boolean-based rápido)
antes de caer a las lentas (time-based), porque cada técnica de inferencia
"ciega" cuesta exponencialmente más requests que una donde el dato sale
directo en la respuesta. En este lab, el endpoint `/buscar` es prácticamente
el caso ideal para sqlmap: error-based porque el servidor manda el error SQL
crudo, y UNION-based porque además hay una salida de datos legible. Entenderlo
a mano primero (como pide el lab) es lo que permite leer el output de sqlmap
con criterio: cuando dice "the back-end DBMS is SQLite" y "parameter 'q' is
vulnerable (error-based)", no es magia — es exactamente lo que nosotros vimos
en el `Error SQL: ...` del R2 al mandar un payload mal formado.

---

## Fuentes (mín. 3, verificables)

- sqlmap — documentación oficial del proyecto, técnicas de detección:
  https://github.com/sqlmapproject/sqlmap/wiki/Techniques
- OWASP Foundation — "Testing for SQL Injection" (OTG-INPVAL-005), explica
  error-based, boolean-based y time-based blind SQLi:
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
- PortSwigger Web Security Academy — "Blind SQL injection", con ejemplos
  concretos de boolean-based y time-based (incluye `SLEEP()`/`pg_sleep()`):
  https://portswigger.net/web-security/sql-injection/blind
- MITRE — CWE-89 (SQL Injection), para la clasificación formal de la falla
  que sqlmap explota: https://cwe.mitre.org/data/definitions/89.html

---

## Reflexión (3–5 líneas)

Antes de este research, "sqlmap encontró la inyección" era una caja negra.
Ahora entendemos que sqlmap hace, de forma sistemática y con mucha más
paciencia que una persona, exactamente el mismo razonamiento que hicimos a
mano en el R1 y el R2: formular una hipótesis (¿esto es código o dato?),
mandar un payload que la pone a prueba, y leer la diferencia en la respuesta
(un error, un cambio de contenido, un retraso). La diferencia entre un
pentester que "sabe sqlmap" y uno que entiende SQLi es que el segundo puede
leer el output técnico de la herramienta —qué técnica usó, por qué— y
confirmar manualmente cuando algo no cierra, en vez de confiar a ciegas en el
reporte automatizado.
