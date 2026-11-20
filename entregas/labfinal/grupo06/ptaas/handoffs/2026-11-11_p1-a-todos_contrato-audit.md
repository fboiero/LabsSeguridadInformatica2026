# Traspaso · P1 → Todos · 2026-11-11 · contrato de la bitácora (audit)

**Task:** 002 · 5.4 (contrato, previo a la tarea 2.2)   **PR / commit:** a5170fe (contrato) · 1a0647b (test en rojo)
**Qué entrego:** firma de `harness/audit.py`: `append(data) -> Entry`, `verify() -> VerifyResult`, `verificar_cadena(entries)`, `validar_evento(data)`, y el fake `InMemoryAuditStore`.
**Cómo se usa:** `store = InMemoryAuditStore(); e = store.append({"engagement": "eng-1", "action": "httpx.probe", "target": "10.0.0.5", "result": "OK"})`. Si el evento trae `password`, `secreto`, `contenido`, etc., lanza `EventoSensible` y no deja registro. Test que lo cubre: `tests/test_audit_persistence.py`.
**Qué todavía no funciona:** no hay persistencia en disco (tarea 2.2), ni verificador por CLI (2.4), ni `verify(path)`. Firma decidida: `verify()` sin argumentos; el archivo se fija al abrir el almacén (ver design.md).
**Qué tenés que confirmar antes de usarlo:**
- Que los eventos de tus módulos no llevan claves sensibles (la lista está en `CLAVES_SENSIBLES`).
- Que `seq` no entra en el hash: solo `prev` y los campos del evento.

**Revisó (persona):** _pendiente — la completa quien recibe._
