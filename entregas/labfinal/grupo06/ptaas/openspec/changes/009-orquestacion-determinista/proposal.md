# Change 009 — Orquestación determinista propia (en lugar de LangGraph)

Responsable: P5. Fecha: 2026-11-19.

## Por qué
El kit propone LangGraph para orquestar, pero lo deja abierto: "LangGraph para
orquestar (propuesto) … **A confirmar por cada equipo en su `design.md`**; no se
probó en el kit" (`docs/marco-teorico.md`, tabla de decisiones), y lo lista como
desafío de extensión (C1 en `docs/desafios-extension.md`). La tarea 001 · 2.2 pedía
"loop A conectado a LangGraph". El grupo orquestó con código propio
(`harness/pipeline.py`) y esta decisión no estaba escrita.

## Qué cambia
- Se registra la decisión con su alternativa, su costo y los tests que muestran que
  no se perdió el control (formato que pide el kit para cambiar una decisión).
- Se corrigen los documentos que listaban LangGraph como elegido:
  `docs/tool-selection.md`, `openspec/project.md`, `CLAUDE.md` y `AGENTS.md`.
- No cambia código ni comportamiento.
