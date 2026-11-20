# Diseño — Change 005: correlación, análisis y loop B

## Snapshots sin red

NVD, EPSS y el mapa CWE se versionan como archivos JSON locales con fecha y URL de origen. Los adapters `cve.lookup`, `epss.lookup` y `cwe.map` consultan solo esos snapshots; no hacen requests HTTP ni completan datos ausentes. La correlación requiere coincidencia exacta contra aliases de producto y versión registrados en el snapshot, y conserva referencias al activo, tecnología, fuente y fecha del feed.

Los CVSS de versiones distintas no se reutilizan como CVSS v4. Si el snapshot no trae CVSS v4, el score numérico queda `null`; no se extrapola ni se inventa. Un mapeo ATT&CK es contextual y solo sale de una relación explícita revisada del mapa local; en otro caso queda `null`/`unknown`.

## CandidateFinding

Por cada coincidencia exacta se construye un candidato con evidencia de activo, tecnología detectada, registro NVD y, si existe, EPSS y CWE. Sin evidencia del activo y fuente no se instancia `CandidateFinding`. La deduplicación usa (activo, CVE; si no hay CVE, activo y CWE) y fusiona referencias en orden estable.

## Análisis y allow-list

ZAP se ejecuta como baseline pasivo con duración y timeout acotados; el reporte JSON se escribe en una ruta temporal. Nuclei recibe únicamente archivos listados en `templates/allowlist/manifest.json`, con SHA-256 verificado, solicitudes GET y sin OAST. Las plantillas se revisan manualmente, no se descargan en runtime. Ambos adaptadores se llaman por `Harness.invoke` en fase ANALYZE.

## Loop B y prioridad

`DetectionLoop` agrega evidencia de los adapters a candidatos y usa `decide_detection`. Termina si el candidato se resuelve, pasan dos iteraciones sin evidencia nueva o se alcanza `policy.yaml`. Al parar por falta de ganancia, el estado es `inconclusive` con justificación y referencias preservadas. La prioridad usa solo CVSS v4 presente, EPSS presente y criticidad 1–5; si falta CVSS v4, no se emite un score.

## Límites

Los tests consumen JSONL/reports de fixtures y snapshots offline. No ejecutan ZAP, Nuclei ni solicitudes a targets. La corrida real de análisis requiere los servicios del lab aislado; no se declarará hecha con los fixtures.
