# Final PTaaS - Grupo 07

Entrega del desafío PTaaS del kit de la cátedra, dentro del laboratorio final.
La evidencia de esta entrega corresponde a PTaaS; no se presentan como realizados
los cuatro hitos del final clásico.

## Material para corregir

- [Integrantes y reparto](INTEGRANTES.md).
- [Informe técnico](informe.md) y [versión PDF](informe.pdf).
- [Retrospectiva y declaración de uso de IA](retrospectiva.md).
- [Código, specs, tests y evidencias](ptaas-kit/README.md).
- [Demo grabada sin audio](presentacion/demo-ptaas.mp4), 1 minuto y 33 segundos.
- [Presentación en PDF](presentacion/presentacion.pdf).
- [Guion completo, incluido el video de Lautaro](presentacion/guion-completo.pdf).
- [Nueva presentación editable en Canva](https://www.canva.com/design/DAHbd6NzSTw/CzW6lbKxqJmNPVHneTeUcQ/edit).
- [Informe compartido en Google Docs](https://docs.google.com/document/d/14C42-21I6AuCr8_LLdOyXkIbpFSt_H_yoKqvk6JoML4/edit).

Los archivos versionados permiten consultar la entrega aunque los enlaces externos
pidan iniciar sesión. El video reproduce de forma legible resultados auténticos
capturados, no una ejecución en vivo ni un modelo de IA tomando decisiones.

## Resultado y alcance

Corte funcional `261bbee`: 170 tests, 20/20 evaluaciones golden y 90/90 tareas de
002 a 007. Se repiten las comprobaciones del cierre en
`ptaas-kit/evidencia/fernando/cierre-pr/`.

Reconocimiento y análisis ejecutan herramientas Docker reales; correlación con
snapshots offline; candidato CSP manual; validación real DVWA; exportación JSON
local. Sin decisiones explícitas se conservan los gates `PENDING_HITL`. Las
decisiones de las corridas aprobadas se identifican como pruebas automatizadas.

El 100 % corresponde al checklist 002-007. No afirma un LLM en vivo, importación a
DefectDojo remoto, revisión personal de todos los compañeros ni ausencia de deuda
técnica. Mypy conserva 39 errores anteriores, documentados en el informe.

## Verificar sin Docker ni tráfico de red

Desde `entregas/final/grupo07/ptaas-kit/`, con Python 3.12:

```bash
python -m venv .venv
# Activar .venv según el sistema operativo.
python -m pip install -r requirements-dev.txt
python -X utf8 -m pytest -q
python -X utf8 evals/run_evals.py --mode golden
python -X utf8 tools/progress.py
python -m harness.audit verify evidencia/lorenzo/integracion-real-pending/audit.db
python -m harness.audit verify evidencia/lorenzo/integracion-real-approved/audit.db
```

Para repetir las corridas reales, ver los comandos y requisitos en el
[informe](informe.md). El RoE de ejemplo tiene fecha 20/11/2026: fuera de esa
ventana el bloqueo es correcto; una nueva corrida requiere autorización vigente.

## Evidencias principales

- [Corrida real sin aprobaciones](ptaas-kit/evidencia/lorenzo/integracion-real-pending/README.md).
- [Corrida real con decisiones explícitas de prueba](ptaas-kit/evidencia/lorenzo/integracion-real-approved/README.md).
- [Integración SQLite de Fernando](ptaas-kit/evidencia/fernando/integracion-002/README.md).
- [Revisiones documentales asistidas](ptaas-kit/docs/revisiones-cierre.md).
- [Límite de la bitácora comprobado durante el cierre](ptaas-kit/evidencia/fernando/cierre-pr/limite-bitacora-002.json).

## Ubicación y validación de la PR

Se respeta `entregas/final/grupo07/`, la ubicación indicada por el enunciado del
final. El workflow general de la cátedra usa actualmente una expresión que solo
acepta `entregas/lab.../grupo.../`; por eso puede rechazar esta entrega por ruta.
La PR solicita al mantenedor resolver esa incompatibilidad. No se modifica el
workflow ni se reubica la entrega para eludirlo.
