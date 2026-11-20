# Design — Change 008

## 1. Loop B de P4 sin cambios
Se usa `run_detection_p4` con `capabilities={"zap.baseline_scan"}`. Su parámetro
`candidate_count` se completa con 1 por activo: el "candidato" del loop B es el
activo que el recon confirmó con evidencia (httpx). Con la correlación por CVE
sin datos (ver propuesta), es la única fuente de candidatos respaldada por
evidencia. La parada la decide `decide_detection` de P4: evidencia recolectada,
dos rondas sin evidencia o tope.

## 2. Gate propio para el análisis activo
ZAP baseline es una acción activa distinta del recon: hace spider y solicitudes
pasivas sobre el objetivo. Se agrega el gate `active_analysis`, aprobado con la
CLI (`approve-gate <engagement> active_analysis`). El recorrido lo materializa
como `Guard.approve("zap.baseline_scan", host)` solo para los activos relevados.

## 3. Vectores CVSS: asignados por el analista, con aprobación
ZAP no entrega CVSS v4.0 y los hallazgos de configuración no tienen CVE, así que
NVD no aplica. El vector lo asigna el analista, como en cualquier pentest. Para
que no sea una decisión silenciosa de la IA:
- vive en `harness/zap_mapping.yaml`, con `approved_by` y `approved_at`;
- el cargador rechaza la tabla sin aprobación o aprobada por un agente;
- cada vector se valida con `validate_cvss4` (P3);
- el informe indica que el vector fue asignado por el analista.

Las alertas informativas de ZAP (riesgo 0) no generan hallazgos. Una alerta con
riesgo ≥ 1 sin entrada en la tabla se descarta con registro en la bitácora: sin
vector aprobado no puede pasar el gate del informe.

## 4. Datos que salen de ZAP
Título, CWE (`cweid`), remediación (`solution`, sin HTML y acotada) y la ruta de
la primera instancia sobre el activo. No se guarda el cuerpo de las respuestas.

## 5. Ejecución de ZAP
Contenedor efímero de la imagen fijada por P4 (digest), en la red interna del
lab, sin capacidades, con el reporte JSON en la carpeta de la corrida. Se rechaza
el reporte si alguna instancia apunta a un host distinto del objetivo.
