# Línea base del perfil implementado

Los deltas locales siguen siendo la fuente de verdad; este índice no los
archiva ni declara implementada la línea base completa de la cátedra.

- Núcleo: [audit-log](../changes/002-audit-persistence/specs/audit-log/spec.md), [tool-adapters](../changes/002-audit-persistence/specs/tool-adapters/spec.md), [agent-contracts](../changes/002-audit-persistence/specs/agent-contracts/spec.md) y [authorization](../changes/003-roe-and-tokens/specs/authorization/spec.md).
- Perfil defensivo: [attack-mapping](../changes/008-defensive-attack-pilot/specs/attack-mapping/spec.md), [defensive-reporting](../changes/009-defensive-reporting/specs/defensive-reporting/spec.md), [evidence-intake](../changes/010-phantomcorp-evidence/specs/evidence-intake/spec.md), [evidence-quality](../changes/011-evidence-quality/specs/evidence-quality/spec.md) y [defensive-delivery](../changes/012-defensive-delivery/specs/defensive-delivery/spec.md).
- Cobertura local: `scenario-tests.tsv` vincula cada Scenario local con un test.
  `python -m pytest -q tests/test_spec_traceability.py` verifica el inventario.

Fuera de esta línea base: recorrido activo del laboratorio, loop de validación
de explotabilidad, integración de herramientas del kit y archivo docente de
changes 004–007. No se trasladan pruebas de fixtures a esos requisitos.
