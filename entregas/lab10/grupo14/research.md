# Mini-research — Laboratorio 10

**Tema elegido:**
- [ ] **A.** IDS/IPS por firmas vs por anomalía (Snort/Suricata): fortalezas y límites.
- [x] **B.** Técnicas de evasión de WAF (ofuscación, encoding, case, comentarios).
- [ ] **C.** SIEM y correlación de logs: cómo se detecta lo que ninguna firma ve.
- [ ] **D.** MITRE ATT&CK: la táctica Defense Evasion y sus técnicas.

> Redactado con asistencia de Claude Code (ver declaración de IA en `informe.md`) a partir de
> conocimiento general. **Las fuentes deben ser verificadas por el grupo antes de entregar**
> (no se accedió a ellas desde esta sesión).

## Desarrollo

Un WAF filtra tráfico HTTP comparando requests contra reglas (firmas/regex) o modelos. La evasión
aprovecha que **el WAF y la aplicación interpretan el mismo request de forma distinta**: lo que para
el WAF es una cadena inofensiva, para el backend (o la base de datos) es un ataque.

Técnicas habituales:

- **Case:** `UnIoN SeLeCt`; falla si la regla distingue mayúsculas.
- **Comentarios SQL como separador:** `UNION/**/SELECT`; falla si la regla exige un espacio. En MySQL
  existen comentarios ejecutables (`/*!50000UNION*/`).
- **Whitespace alternativo:** tab, `%0a`, `%0d`, `%a0`, `+`.
- **Encoding:** URL-encoding, doble URL-encoding, Unicode, HTML entities; falla si el WAF no decodifica
  tantas veces como la app.
- **Fragmentación y HTTP Parameter Pollution:** repartir el payload en varios parámetros que la app une.
- **Cambiar metadatos:** User-Agent, headers (`X-Forwarded-For`), orden de headers.
- **Low-and-slow:** espaciar requests para quedar bajo los umbrales.
- **Alternativas sin la palabra clave:** inyección blind/time-based que no usa `UNION`.

Defensas: **normalizar antes de inspeccionar** (decode, quitar comentarios, colapsar espacios,
minúsculas), reglas por comportamiento y puntuación de anomalías (modo anomaly scoring del OWASP Core
Rule Set), parsear SQL en vez de regex y, sobre todo, corregir la app (consultas parametrizadas): el
WAF es una capa de mitigación, no un reemplazo del arreglo. En MITRE ATT&CK, esto corresponde a la
táctica Defense Evasion (TA0005), en particular "Obfuscated Files or Information" (T1027).

## Fuentes (mín. 3)

1. OWASP Core Rule Set — documentación (https://coreruleset.org/docs/): anomaly scoring y reglas de SQLi.
2. OWASP, "SQL Injection Bypassing WAF" (https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF).
3. MITRE ATT&CK, TA0005 Defense Evasion (https://attack.mitre.org/tactics/TA0005/) y T1027.
4. Ley 26.388 (delitos informáticos), por el marco legal de practicar evasión solo en el lab.

## Reflexión

Una firma que exige un espacio literal es una apuesta a que el atacante no conozca SQL: sirve contra
automatismos básicos y falla contra cualquiera que lea la regla. El WAF compra tiempo y visibilidad,
pero la corrección real está en la aplicación, y sin analistas leyendo logs ni reglas de correlación,
lo que la firma no ve, nadie lo ve. (La evasión se trabajó solo en teoría hasta poder correr el entorno.)
