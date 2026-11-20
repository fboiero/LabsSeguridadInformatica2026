# Tasks — Change 007

## Spec y diseño
- [x] 1.1 `design.md`: estructura del informe, versionado, qué sale hacia DefectDojo
- [x] 1.2 Delta de `reporting` con ≥ 4 Requirements nuevos
- [ ] 1.3 Revisión cruzada

## Implementación
- [x] 2.1 Tests que fallan para armado del informe desde hallazgos y bitácora
- [x] 2.2 Construcción del informe con referencias a evidencia en bitácora
- [x] 2.3 Validación de vectores CVSS v4.0 y presentación junto a EPSS
- [x] 2.4 Resumen ejecutivo y estructura PTES §7
- [x] 2.5 Exportación a DefectDojo o a su formato de importación
- [x] 2.6 Gate de entrega conectado a la CLI de aprobación

## Verificación
- [x] 3.1 Test: hallazgo sin CWE/CVSS/remediación → falla indicando el campo
- [x] 3.2 Test: estado "validado" vs "no validado" visible en el informe
- [x] 3.3 Test: entrega sin aprobación → rechazada
- [x] 3.4 Test: el informe no contiene datos sensibles del lab (lista de patrones)
- [ ] 3.5 Recorrido end-to-end con un solo comando contra el lab
- [ ] 3.6 Archivar el delta en `openspec/specs/reporting/spec.md`

Revisión 1.3 y archivado 3.6 pendientes de Lautaro. El 002 ya está conectado a `harness.run`: bitácora SQLite por engagement, reapertura y verificación con `harness.audit verify`. 3.5 sigue pendiente: 004/005 están integrados con fixtures; HTTPX, Nuclei y ZAP tienen corridas reales independientes en `evidencia/lorenzo/`, pero todavía no alimentan el recorrido completo con herramientas reales. La validación real en Docker está verificada. El candidato CSP de la demo sigue siendo manual; la nueva alerta real de ZAP no se conecta automáticamente al loop C. Evidencia de integración del 002: `evidencia/fernando/integracion-002/`.
