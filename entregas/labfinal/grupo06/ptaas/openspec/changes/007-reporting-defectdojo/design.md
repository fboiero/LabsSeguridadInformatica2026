# Design — Change 007: informe completo y exportación a DefectDojo

Redactado por P5 en reemplazo de P1 (tasks 1.1 y 1.2), con acuerdo de P1, el
2026-11-18. La revisión cruzada (1.3) la hace otra persona.

## Contexto

Ya existe:

- `harness/reporting.py`: `Finding`, validación de CWE / CVSS / remediación y
  `deliver(report, reviewer_approved)`.
- `harness/reporting_p3.py` (P3, tasks 2.3 y 2.4): CVSS v4.0 estricto, EPSS sin
  inventar (`unknown` si falta) y estructura PTES §7 con resumen ejecutivo.
  Decisiones en `p3/proposal.md`; este diseño las toma como dadas.
- `tests/test_reporting_gates.py` (P2, tasks 3.1 y 3.3).
- Change 006: el loop C deja en la bitácora un registro `validation.result` por
  hallazgo y un `sandbox.response` por intento, con hash del cuerpo.

Falta: armar el informe **desde la bitácora** (no desde lo que declare un
agente), versionarlo, entregarlo con una aprobación humana real y exportarlo.

Criterio general, igual que en 006: **falla cerrado**. Si un dato no se puede
respaldar con la bitácora, el informe no se genera o el hallazgo queda
"no validado"; nunca al revés.

## Decisiones

### 1. El estado de validación sale de la bitácora

| Opción | Problema |
|---|---|
| Usar `Finding.validation_status` tal como llega | Un agente puede declarar "validated" sin haber validado nada |
| **Derivarlo del registro `validation.result` del loop C** | Ninguno: es lo que realmente pasó |

**Elegida:** el estado de cada hallazgo se toma del último `validation.result`
de la bitácora para ese `finding_id`:

- `validated` → "validado en sandbox", con verificación, versión y referencias;
- `not_validated` → "no validado", con el motivo del loop C;
- sin registro, o `PENDING_HITL` → "no validado (sin aprobación)".

Si un `Finding` dice `validated` y la bitácora no lo respalda, la generación
falla indicando el hallazgo.

**Un hallazgo no validado de severidad alta** no se descarta ni se rebaja: se
lista igual y el resumen ejecutivo lo menciona aparte como "requiere
validación". Ocultarlo sería peor que no haberlo validado.

### 2. Referencias a la evidencia

Cada hallazgo lleva como evidencia los **hashes** de sus entradas en la
bitácora (`Entry.hash` del contrato de P1). Al generar el informe:

1. se verifica la cadena completa (`verify()`); si falla, no se genera;
2. se comprueba que cada referencia exista en la bitácora; si una no existe, no
   se genera.

El informe incluye el hash de la última entrada de la bitácora usada (cabeza).
Con eso, "lo exportado es reproducible a partir de la bitácora" se puede
comprobar: misma bitácora hasta esa cabeza → mismo informe.

### 3. Versionado: el informe se identifica por su hash

- El informe tiene `version` (entero, empieza en 1) y `report_hash`: SHA-256 del
  contenido canónico (hallazgos, estados, referencias, cabeza de bitácora). El
  Markdown se genera a partir de ese contenido; no entra en el hash.
- Mismas entradas → mismo hash.
- Si cambia un hallazgo después de generado, se genera una **versión nueva**
  con otro hash. Las versiones anteriores no se modifican.

### 4. Entrega con aprobación registrada, ligada al hash

Hoy `deliver(report, reviewer_approved=True)` acepta un booleano que cualquier
código puede pasar. Se agrega una entrega que consulta una aprobación
**registrada por una persona en la CLI de 006**, ligada al `report_hash`:

```text
python -m harness.validation_cli --store <aprobaciones> approve-delivery <engagement> --report-hash <hash> --reviewer "<nombre>" --reason "<motivo>"
```

- Sin aprobación: el informe queda en `REPORT` y se registra `PENDING_HITL`.
- Aprobación de otro hash (otra versión del informe): se rechaza.
- La aprobación y la entrega quedan en la bitácora.

`deliver(report, reviewer_approved)` se conserva porque la usan los tests de P2
y P3; el recorrido de un comando (3.5) usa solo la entrega con aprobación
registrada. Es un riesgo conocido (ver Riesgos).

### 5. Datos sensibles: se rechaza, no se redacta

Antes de generar, se buscan en todo el contenido del informe patrones de datos
sensibles:

- valores de cookies de sesión (`PHPSESSID=…`, `token=…`, `Set-Cookie:`);
- encabezados `Authorization:` y tokens tipo JWT (`eyJ…`);
- `password`/`passwd`/`secret` seguidos de un valor;
- claves privadas (`-----BEGIN … PRIVATE KEY-----`);
- el canario de la verificación de reflexión (`ptaas` + 8 hex).

Si aparece alguno, la generación **falla indicando el patrón y el hallazgo**.
No se redacta automáticamente: igual que la bitácora de P1, se rechaza, porque
una redacción automática puede fallar en silencio. La lista de patrones vive en
el código y se amplía con un delta.

### 6. Exportación a DefectDojo: archivo en formato de importación

Decisión del plan (sección 6.5): se exporta un JSON con el formato de
importación genérico de DefectDojo; la API real solo si sobra tiempo. Los
nombres exactos de los campos se verifican contra la documentación oficial
antes de implementar.

- **Solo se exporta un informe entregado** (con aprobación registrada para ese
  hash). Exportar es sacar información del sistema.
- **Qué sale:** título, activo, CWE, vector CVSS v4.0, EPSS (o `unknown`),
  estado de validación, remediación, referencias de bitácora y un identificador
  estable por hallazgo.
- **Qué no sale:** cuerpos de respuesta, encabezados, cookies, el canario,
  nombres de personas (solo el rol "Reviewer") y rutas locales.
- **Severidad:** el contrato `Finding` no trae puntaje CVSS y P3 decidió no
  calcularlo. El exportador no inventa una severidad: usa la que venga en el
  hallazgo si tiene fuente; si no, marca el hallazgo con la etiqueta
  `severity-unknown` y usa el valor mínimo que acepte el formato, dejando
  explícito en la descripción que la severidad no fue calculada. Esta decisión
  se revisa cuando el change 005 aporte puntajes.
- **Duplicados entre corridas:** el identificador estable es el SHA-256 de
  (activo, CWE, verificación o título normalizado). DefectDojo puede usarlo para
  deduplicar; dentro del informe, dos hallazgos con el mismo identificador se
  unen y se juntan sus referencias.

### 7. Procedencia de cada etapa

El recorrido de un comando (3.5) tiene etapas reales y, mientras falte el
change 005, una etapa simulada. El informe declara la **procedencia** de cada
etapa (`real` / `fixture`) en su encabezado y en el JSON.

Un informe con alguna etapa `fixture` se marca como **DEMO**: se puede generar
y leer, pero **no se puede entregar ni exportar**. Así no hay forma de presentar
un resultado simulado como un pentest real.

### 8. Divulgación (ISO/IEC 29147)

El informe incluye una sección de divulgación con receptor, canal, fecha de
entrega y plazo de remediación acordado. Los valores que no estén en el RoE
quedan `unknown`; no se inventan. Al ser un laboratorio, el receptor es el
responsable del lab declarado en el RoE.

## Reparto de tasks

| Task | Responsable | Requirement del delta |
|---|---|---|
| 1.1, 1.2 | P5 (en reemplazo de P1) | — |
| 1.3 | Otra persona | — |
| 2.1, 2.2 | P5 | Estado respaldado, referencias verificables, versionado |
| 2.3, 2.4 | P3 (hecho) | `p3/proposal.md` |
| 2.5 | P5 | Exportación |
| 2.6 | P5 | Entrega con aprobación registrada |
| 3.1, 3.3 | P2 (hecho) | Spec `reporting` vigente |
| 3.2 | P1 | Estado respaldado por la bitácora |
| 3.4 | P1 | Sin datos sensibles |
| 3.5 | P5 | Procedencia de etapas |
| 3.6 | P1 | Archivado |

## Qué no cubre este change

- Cálculo del puntaje CVSS v4.0.
- DefectDojo real (API), salvo que sobre tiempo.
- Hallazgos reales: dependen del change 005.

## Riesgos

- **`deliver` con booleano sigue existiendo.** Se mantiene por compatibilidad;
  la mitigación es que el recorrido de un comando no lo use y que un test lo
  verifique. Retirarlo queda para un change posterior.
- **Bitácora en memoria:** hasta que exista la persistencia SQLite (002), la
  verificación de referencias se hace sobre el almacén en memoria del recorrido.
- **Detección de datos sensibles por patrones:** no es exhaustiva. Por eso se
  combina con no exportar cuerpos ni encabezados en ningún caso.
