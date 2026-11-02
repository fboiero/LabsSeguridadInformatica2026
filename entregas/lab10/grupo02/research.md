# Research — Lab 10 · Detección y evasión

Material de apoyo del `informe.md`. Cómo detecta un IDS por firmas, cómo se evade y
qué lo complementa.

---

## 1. Encuadre (MITRE ATT&CK)

- **Lado rojo:** Defense Evasion — `TA0005`. Técnicas relevantes:
  - `T1027` Obfuscated Files or Information (ofuscar el payload: `UNION/**/SELECT`).
  - `T1070`/evasión de logging y firmas; manipular la User-Agent para no matchear
    `scanner-ua`.
- **Lado azul:** disciplina de *Detection* — IDS/WAF por firmas, logging de seguridad
  y correlación (análisis de un SIEM/SOC).

---

## 2. IDS/WAF por firmas: cómo funciona

Un IDS/WAF por firmas compara cada request contra un **ruleset** de patrones conocidos
y alerta cuando algo matchea. Es como un antivirus: rápido y certero contra lo
**conocido**, ciego ante lo que su firma no describe exactamente.

Ruleset observado en el lab:

| Firma | Patrón |
|---|---|
| `scanner-ua` | User-Agent contiene `sqlmap\|nikto\|nmap\|dirb` |
| `path-traversal` | la ruta contiene `../` |
| `git-probe` | la ruta contiene `/.git` |
| `sqli-union` | el query matchea `/union\s+select/` (exige un espacio) |

---

## 3. Técnicas de evasión usadas

| Firma | Técnica de evasión | Por qué funciona |
|---|---|---|
| `scanner-ua` | Suplantar la User-Agent por la de un navegador (`curl -A "Mozilla/5.0 ..."`) | La firma mira la identidad declarada, un header que el cliente controla |
| `sqli-union` | Comentario SQL inline en vez de espacio: `UNION/**/SELECT` | `/**/` no es whitespace, así que no matchea `\s+`; el motor SQL igual lo interpreta como separador |

Otras evasiones clásicas (no necesarias en el lab, pero relevantes): codificación
URL/doble-URL, mayúsculas/minúsculas mezcladas (`UNiOn`), funciones (`CHAR()`,
concatenación), saltos de línea, y técnicas *low-and-slow* para no superar umbrales de
tasa.

---

## 4. El límite de las firmas y qué las complementa

Una firma persigue un blanco infinito: por cada patrón bloqueado existe otra
codificación con el mismo efecto. Endurecerla (normalizar input antes de evaluar,
contemplar comentarios y encoding) sube el costo de evadir pero no lo elimina. Lo que
realmente cierra el hueco:

1. **Detección por comportamiento/anomalías:** tasa de requests, recorrido secuencial,
   ratio de 404, en lugar de patrones fijos.
2. **Análisis humano (SOC):** correlacionar eventos y encontrar la aguja en el pajar
   (el R5: la alerta estaba en el log desde el minuto cero; faltó quien la mirara).
3. **Defensa en la raíz:** consultas parametrizadas (el payload nunca se interpreta
   como SQL), validación de entrada y mínimo privilegio — no depender del patrón.

---

## 5. Referencias

- MITRE ATT&CK — Defense Evasion (TA0005): https://attack.mitre.org/tactics/TA0005/
- MITRE ATT&CK — T1027 Obfuscated Files or Information: https://attack.mitre.org/techniques/T1027/
- OWASP — SQL Injection / WAF bypass:
  https://owasp.org/www-community/attacks/SQL_Injection
- OWASP — SQL Injection Prevention Cheat Sheet (consultas parametrizadas):
  https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- OWASP — Web Security Testing Guide (Testing for SQLi / evasion):
  https://owasp.org/www-project-web-security-testing-guide/

> Uso responsable: la evasión de detección se practicó exclusivamente contra el IDS del
> lab de la cátedra. Evadir la detección de sistemas ajenos agrava el delito
> informático (Ley 26.388). El objetivo fue entender la defensa, no burlar la de nadie.
