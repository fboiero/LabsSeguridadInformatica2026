# Informe técnico PTaaS - Grupo 07

**Seguridad Informática. Corte funcional: 20/11/2026, commit 261bbee.**
Integrantes y legajos: [INTEGRANTES.md](INTEGRANTES.md).

## 1. Resumen ejecutivo

Extendimos el kit PTaaS de la cátedra para organizar una revisión de seguridad
autorizada: relevar, relacionar información, analizar, comprobar un caso e informar.
El recorrido integrado ejecuta subfinder, HTTPX, ZAP y Nuclei en la red Docker
interna del laboratorio, consulta snapshots locales y utiliza verificaciones
inertes del catálogo. La bitácora queda en SQLite y el informe se exporta como
Markdown y JSON local.

El caso preparado comprueba que DVWA no envía Content-Security-Policy (CSP) en
`/login.php`. Confirma esa ausencia, no una intrusión. El candidato se carga
manualmente y no se presenta como descubrimiento autónomo del sistema.

Las comprobaciones dieron 170 tests aprobados, 20/20 evaluaciones golden y 90/90
tareas de los changes 002-007. Son resultados acotados, no una garantía de
seguridad completa. No se evaluó un LLM en vivo ni se importó a DefectDojo remoto.

## 2. Alcance y arquitectura

El objetivo de las corridas es `dvwa.lab.test`, en `lab_lab`, una red Docker
`internal` con subred `10.99.0.0/28`. Juice Shop forma parte del laboratorio, pero
el caso validado de esta entrega corresponde a DVWA. El RoE excluye `10.99.0.5`,
delimita fases y horarios y establece el responsable de revisión.

Toda acción de herramienta pasa por `Harness.invoke`: kill switch, token vivo,
alcance y fase, gate cuando corresponde, adaptador y registro. Los tokens los
emite `TokenIssuer`; `EngagementGuard` impide mezclarlos entre engagements. Los
adaptadores usan argumentos acotados, límites de tiempo y salidas estructuradas.

Los loops A y B finalizan por estabilidad, falta de información o topes. El loop C
requiere una decisión explícita para parametrizar una comprobación del catálogo.
Entregar el informe requiere otra decisión, vinculada al contenido versionado.

<!-- pagina -->

## 3. Implementación y decisiones

| Change | Responsable | Resultado |
|---|---|---|
| 002 | Lautaro | SQLite append-only, cadena de hashes y CLI audit verify; 14/14 |
| 003 | Guadalupe | Parser RoE, exclusiones y tokens por fase; 14/14 |
| 004 | Lorenzo | Adaptadores de reconocimiento y loop A; 15/15 |
| 005 | Lorenzo | Snapshots, correlación, análisis y loop B; 17/17 |
| 006 | Fernando | Gate, catálogo y sandbox Docker del loop C; 15/15 |
| 007 | Fernando | Informe, exportación local e integración; 15/15 |

Lorenzo agregó la ejecución real de herramientas de A/B y registró ambas corridas
integradas en `evidencia/lorenzo/`. Fernando conectó la persistencia del 002 a
`harness.run`. El archivo SQLite se determina por engagement, se verifica al
reabrir, conserva el historial y se cierra incluso ante fallos.

Las decisiones principales fueron:

- Restar exclusiones al emitir el token y normalizar fechas en UTC.
- Mantener un modo fixture para tests y uno Docker explícito. El modo Docker no
  vuelve silenciosamente a fixtures si falla una herramienta.
- Usar fuentes offline y devolver `null` o `unknown` cuando no existe evidencia
  exacta para un CVE, score o contexto ATT&CK.
- Curar cinco templates GET de Nuclei con hashes en allow-list y sin OAST.
- Crear workers en la red interna y eliminarlos al terminar o fallar.
- Ligar las decisiones a engagement, hallazgo, PoC, parámetros y modo; para la
  entrega, al hash del informe. Cambiar el contenido invalida la decisión previa.

Las specs archivadas están en `ptaas-kit/openspec/specs/`; el diseño y las tareas,
en `ptaas-kit/openspec/changes/`. Las revisiones documentales fueron asistidas por
Codex a pedido de Lorenzo, según `docs/revisiones-cierre.md`. Ese registro no
atribuye lecturas personales a los integrantes ni aprobaciones académicas.

<!-- pagina -->

## 4. Resultados y comprobaciones

| Comprobación | Resultado | Evidencia dentro de ptaas-kit/ |
|---|---|---|
| Suite del código | 170 passed | evidencia/lorenzo/cierre/pytest.txt |
| Evaluaciones golden | 20/20 | evidencia/lorenzo/cierre/evals.txt |
| Avance 002-007 | 90/90 | evidencia/lorenzo/cierre/progress.txt |
| Sin decisiones | Validación y entrega PENDING_HITL | evidencia/lorenzo/integracion-real-pending/ |
| Decisiones explícitas de prueba | validated y exported_local_json | evidencia/lorenzo/integracion-real-approved/ |
| Verificador SQLite | OK sobre ambas bases | audit.db y audit-verify.txt de cada corrida |

HTTPX identificó tecnologías de DVWA; la correlación no encontró coincidencias
exactas de CVE en los snapshots. ZAP y Nuclei ejecutaron comprobaciones reales.
El análisis terminó `inconclusive` por falta de nueva información vinculada al
candidato. No se transformaron alertas genéricas en confirmaciones automáticas.

Las 20 evaluaciones cubren, entre otros casos, CVE ausente, evidencia insuficiente,
EPSS desconocido, falta o vencimiento de aprobación, cambio de parámetros, activo
o modo y PoC fuera de catálogo. Evalúan respuestas guardadas y reglas; no miden
la calidad de decisiones de un modelo en vivo.

## 5. Red team del control y mutation checks

Los tests cubren reutilización de token en otra fase o engagement, ventanas con
zonas distintas, CIDR excesivo y descubrimiento fuera de alcance sin sondeo activo.
También se comprueban rechazo de red pública y limpieza de workers tras timeout.

Guadalupe documentó cinco mutaciones detectadas del 003. En 002, omitir la
comparación del hash hizo fallar dos tests. En 006/007, eliminar el gate de
validación o de entrega hizo fallar sus pruebas: ver `evidencia/lautaro/` y
`evidencia/fernando/mutation-checks.json`. No se declaran mutation checks de 004/005.

Un archivo alterado en una copia de prueba devuelve `CORRUPTA`. Además, durante
el cierre se comprobó el límite de truncado final descrito en la página siguiente.

<!-- pagina -->

## 6. Hallazgo del laboratorio

**F-CSP-001: ausencia de Content-Security-Policy en DVWA.**

- Activo: `http://dvwa.lab.test/login.php`.
- Origen del candidato: manual, identificado como tal en la procedencia.
- Comprobación: `POC-CSP-001`, versión 1.0.0, lectura de una respuesta HTTP.
- Resultado: `validated`, detalle `sin Content-Security-Policy`, modo `sandbox`.
- Referencia de bitácora:
  `d463012600461e6129f69c87ff6aff183209ff57850cbb9bf7b22e32b8efdce7`.
- Evidencia: `evidencia/lorenzo/integracion-real-approved/validation-evidence.json`.
- Clasificación usada por el kit: CWE-693; severidad Info provisional.

El kit incluye el vector base de ejemplo
`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N`.
Se valida su sintaxis; no se calcula score ni se presenta ese vector como una
valoración humana final del impacto. EPSS queda desconocido, sin CVE confirmada.

La falta de CSP elimina una posible capa de protección del navegador, pero la
comprobación no demuestra XSS ni acceso indebido. La remediación propuesta es
definir una política CSP adecuada para la aplicación y verificarla con sus flujos
legítimos; no se aplicó una corrección al objetivo vulnerable de práctica.

## 7. Riesgos y límites

El hash del RoE identifica contenido, no es firma criptográfica. La CLI registra
nombre y motivo del revisor, pero no autentica su identidad. Las decisiones de las
corridas aprobadas son explícitas de prueba automatizada, no decisiones personales
de compañeros. La exportación a DefectDojo es JSON local, sin importación remota.

SQLite serializa hilos de una misma instancia; no garantiza varios procesos
escritores. Si alguien puede desactivar triggers y borrar el último registro, la
cadena restante puede verificar: falta un hash final o conteo protegido fuera del
archivo. El experimento de cierre pasó de 20 a 19 filas y verificó OK en una copia;
el original quedó intacto. No se promete detectar todo borrado.

Mypy conserva 39 errores anteriores en ocho archivos. Los tests y el lint focal
aprobados no significan que ese control estricto esté aprobado. El checklist 100 %
de 002-007 no elimina estos límites ni acredita revisión humana individual.

<!-- pagina -->

## 8. Reproducibilidad y demo

Desde `entregas/final/grupo07/ptaas-kit/`, con Python 3.12 y las dependencias de
`requirements-dev.txt`, la verificación sin tráfico es:

```bash
python -X utf8 -m pytest -q
python -X utf8 evals/run_evals.py --mode golden
python -X utf8 tools/progress.py
python -m harness.audit verify evidencia/lorenzo/integracion-real-approved/audit.db
```

Para repetir la ejecución real se requieren Docker Desktop o Engine, las imágenes
de las herramientas disponibles localmente y la red interna de `lab/docker-compose.yml`.
El ejecutor usa `--pull=never`. El RoE de ejemplo vence el 20/11/2026 a las 23:00
de Argentina: fuera de esa ventana debe prepararse una autorización vigente;
el bloqueo por fecha es el comportamiento esperado.

```bash
docker compose -f lab/docker-compose.yml up -d
python -m harness.run --roe roe/roe-lab.example.yaml --tools-mode docker --validation-mode sandbox --output .demo-output-entrega --approvals .demo-output-entrega/approvals.json
```

Ese comando conserva los gates pendientes. La corrida aprobada ya registrada usa
`--approve F-CSP-001 --approve delivery`, con `--reviewer` y `--reason` explícitos
que identifican una prueba técnica; el comando completo está en el README de
`evidencia/lorenzo/integracion-real-approved/`. Esas decisiones no se habilitan por
defecto y se evalúan por contenido. No se recomienda copiar aprobaciones entre
corridas.

La [demo sin audio](presentacion/demo-ptaas.mp4) dura 1:33. Reproduce resultados
auténticos capturados para facilitar su lectura. [El guion](presentacion/guion-completo.pdf)
incluye las frases por tiempo de Lautaro. Los archivos de herramientas, validación,
bitácora e informe permiten contrastar cada afirmación sin depender del video.

## 9. Fuentes y autoría

La arquitectura y los contratos iniciales proceden del kit de la cátedra, ubicado
en `labs/labfinal-practico-integrador/ptaas-kit/`. Las extensiones se desarrollaron
en la copia del grupo y se conservan sus commits. Las decisiones de herramientas
están en `ptaas-kit/docs/tool-selection.md`; trazabilidad y criterios en las specs,
el plan de 15 días y la rúbrica del kit. La [retrospectiva](retrospectiva.md)
contiene la declaración de IA de los cuatro integrantes y ejemplos comprobables.
