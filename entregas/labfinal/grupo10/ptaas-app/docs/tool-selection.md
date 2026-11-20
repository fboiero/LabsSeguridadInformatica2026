# Selección de herramientas — Grupo 10

| Herramienta | Por qué se usa | Control / alternativa |
|---|---|---|
| Python + Pydantic | Autorización determinista, contratos de agentes y validación reproducible | El modelo no controla alcance, expiración ni gates. Reglas explícitas en lugar de decisiones en lenguaje natural. |
| SQLite + SHA-256 | Bitácora local transaccional con verificación sin servicio externo | Fail-closed; sin anclaje externo no certifica completitud ni autenticidad. No se guardan secretos ni respuestas crudas. |
| Git local | Referencia inmutable al estado, informe y comprobantes históricos | Lectura de objetos del commit fijado, sin checkout, sin buscar flags y sin descargar objetos. No demuestra una nueva ejecución. |
| Bandit | Análisis estático del Python propio, separado de la ejecución de agentes | El operador genera el JSON; el modelo recibe solo categorías sanitizadas. No es prueba de explotabilidad. |
| MITRE ATT&CK | Clasifica comportamientos respaldados por telemetría | Extracto Enterprise 17.1 y fixtures. Sin logs no se asigna una técnica. No es un escáner. |
| OpenCode stateless | Generación con modelo por rol, sin acceso a terminal o herramientas | Fixture offline como modo explícito; sin fallback silencioso. No se envían artefactos crudos. |
| Docker | Aísla la validación documental de la entrega | Imagen fijada por digest, `--network none`, solo lectura y sin privilegios. No es el `Sender` de validación contra el activo. |
| DefectDojo Generic Findings Import | Formato estándar para entregar resultados localmente | [Especificación oficial](https://docs.defectdojo.com/supported_tools/parsers/file/generic/). Actualmente produce cero hallazgos confirmados; no importa ni publica, no reimportar sobre una evaluación existente como si fuera un escaneo. |
| pytest / Ruff / mypy | Regresión, lint y tipos | Los escenarios se vinculan con tests concretos. Esto no reemplaza la revisión independiente. |
