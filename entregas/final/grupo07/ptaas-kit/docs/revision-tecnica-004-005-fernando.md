# Revisión técnica asistida — 004/005

Base revisada: origin/final-grupo07@2e55625. Revisión realizada por Codex en la
sesión de Fernando; confirmación personal de Fernando pendiente. Se dejan las
tareas 1.3 sin marcar hasta esa confirmación.

Se leyeron los diseños y contratos de ReconLoop, Correlator y DetectionLoop,
los adaptadores y las pruebas. La base integrada pasó 150 tests y 20/20 golden.
Después de conectar el comando a los módulos del equipo, pasó 152 tests.

Observaciones para la integración:
- HTTPX fixture informa PHP y Apache sin versión. Correlator devuelve cero
  coincidencias CVE; se conserva ese dato, sin agregar tecnologías inventadas.
- Las alertas fixture de 005 no contienen un vínculo explícito con F-CSP-001.
  DetectionLoop lo deja inconcluso. La semilla CSP es manual, no una detección
  atribuible a ZAP/Nuclei; se valida aparte con catálogo y gate humano.
- Se conserva el modo fixture de los runners; el comando no ejecuta subfinder,
  httpx, ZAP ni Nuclei contra la red. La validación Docker es una fase separada.
- Las corridas reales pendientes de 004/005 no se marcan hechas por tener código
  integrado ni por esta validación aislada en DVWA. Audit verify de 002 sigue pendiente.
- Las referencias textuales del candidato de 005 se conservan en pipeline-evidence.json;
  el informe de 007 utiliza referencias hash reales de la validación en bitácora.

No se detectó un conflicto de interfaces que impida integrar estos módulos.
La demo completa sigue siendo mixta: fixtures A/B, snapshots offline y validación
C real opcional. Eso se indica en la terminal, el reporte y la presentación.
