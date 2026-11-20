# 003 — Reglas de engagement y tokens

**Borrador para revisión del Grupo 10.** Próximo paso del checkpoint 1;
no modifica autorizaciones existentes ni habilita acciones.

- Definir un documento RoE local y tipado: identificador, alcance explícito,
  fases autorizadas, ventana horaria y aprobación humana.
- Diseñar la emisión determinista de un token acotado a una fase y con TTL
  limitado por la política y el fin de la ventana. El modelo no emite tokens.
- Diseñar escenarios negativos: falta de alcance, CIDR público, ventana invertida
  y fase no autorizada; documentar también el caso permitido.
- Probar los casos con adaptadores inertes y conservar los resultados en bitácora.

Siguiente paso: validar este alcance con el grupo, escribir `design.md` y deltas
Given/When/Then, y preparar los tests antes de cambiar el harness.
