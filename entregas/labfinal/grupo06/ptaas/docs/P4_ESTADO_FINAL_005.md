# Estado de entrega — Persona 4 / Change 005

## Implementación realizada

- Cliente offline NVD con integridad SHA-256.
- Cliente offline EPSS.
- Mapeo CWE y normalización ATT&CK cuando existe fuente.
- Correlador de candidatos con referencias de evidencia.
- Adaptador ZAP baseline no destructivo.
- Adaptador Nuclei con control de allow-list.
- Orquestación de Loop B.
- Evaluaciones de correlación y análisis.
- Verificación estática de cinco templates Nuclei.

## Verificación automatizada

- Tests completos: True
- Evaluaciones golden: True
- Preflight de templates: True

Evidencias:
- entrega/evidencia/salidas/p4-pytest-final.txt
- entrega/evidencia/salidas/p4-evals-final.txt
- entrega/evidencia/salidas/p4-preflight-final.txt
- entrega/evidencia/salidas/p4-template-preflight.json

## Pendientes externos

- Revisión cruzada del Change 005 por P3.
- Aprobación humana de los cinco templates Nuclei.
- Ejecución real de ZAP en el laboratorio autorizado.
- Ejecución real de Nuclei en el laboratorio autorizado.
- Integración definitiva de deltas OpenSpec tras su aprobación.

## Limitaciones

Las pruebas automatizadas no sustituyen las corridas reales
de herramientas ni las aprobaciones humanas.

Los cinco templates fueron verificados estáticamente,
pero no están aprobados para ejecución.

Las evaluaciones golden no equivalen a evaluaciones live.

## Evidencia ZAP baseline ? DVWA

- Objetivo: dvwa.lab.test
- Entorno: Docker, red interna lab_lab.
- Resultado: OK.
- Alertas: 11, todav?a no validadas.
- Fallos ZAP: 0.
- Reporte: evidencia/zap/zap-dvwa-baseline.json
- Log: evidencia/zap/zap-dvwa-baseline.log
- Auditor?a: evidencia/zap/zap-dvwa-audit.json
