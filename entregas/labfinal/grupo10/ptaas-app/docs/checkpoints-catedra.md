# Cátedra — pendientes del Grupo 10

Fuentes: [enunciado][enunciado], [plan de 15 días][plan], [rúbrica propuesta][rubrica]
y [hoja de ruta del práctico][hoja]. MITRE y Bandit son extras, no reemplazan
los entregables del kit ni acreditan una corrida sobre el laboratorio.

| Hito | Evidencia que pide el kit | Pendiente del grupo |
|---|---|---|
| Checkpoint 1 | `002` y `003`; matriz de invariantes, ≥10 pruebas adversariales del guard; demo de 5 minutos RoE → token → permitir/bloquear. | Demo y matriz listas para el perfil inerte. Juan Saby registró la versión revisada (`0e820ac`) de `002` sin observaciones y confirmó con el grupo el cierre técnico de `003`; el archivado formal se realiza al integrar la PR. |
| Checkpoint 2 | `004` y `005`; recon → correlación → análisis en el laboratorio aislado, bitácora verificable y selección de herramientas justificada. | [Selección documentada](tool-selection.md) y [corrida defensiva A → B → C](evidencia-loops.md) con Juice Shop real y bitácora verificada estructuralmente. El traspaso B → C usó un adaptador de la corrida. |
| Checkpoint 3 | `006` y `007`; sandbox efímero del flujo, gates humanos, informe y exportación DefectDojo (o formato de importación). | El [sandbox validó el recibo real](evidencia-loops.md). En DefectDojo local pasaron la [importación del archivo y la publicación por API autenticada](entrega-defensiva.md). La instancia docente es condicional. No hay un change `006` en `ptaas-app`; el sandbox documental se sigue en `014`. |
| Entrega | Specs actualizadas; changes `002`–`007` archivados; 100% de tareas y cada Scenario con test; demo de 10 minutos; informe técnico de 3–5 páginas y retrospectiva sobre la IA. | La evidencia defensiva cubre el recorrido y el escalado en C. No acredita el orquestador de entrega ni escalado independiente en A y B para «Logrado». El archivado sigue pendiente; `002` se archiva al integrar por PR, no antes. |

El enunciado habla de DVWA/Juice Shop para PTaaS. El práctico clásico habla de
PhantomCorp y la hoja de ruta publica **04/12/2026** para «engagement + informe».
No consta que eso fije la fecha de PTaaS o que PTaaS reemplace al clásico.
Preguntar al docente: «¿PTaaS sustituye al final clásico o es adicional? ¿Qué
laboratorio, fechas, evidencias de checkpoints y modalidad de entrega aplica al Grupo 10?»

[enunciado]: ../../../../../labs/labfinal-practico-integrador/ptaas-kit/docs/enunciado-alumnos.md
[plan]: ../../../../../labs/labfinal-practico-integrador/ptaas-kit/docs/plan-15-dias.md
[rubrica]: ../../../../../labs/labfinal-practico-integrador/ptaas-kit/docs/rubrica-evaluacion.md
[hoja]: ../../../../../docs/presentaciones/estado-hoja-de-ruta/generar.js

Trazabilidad: [matriz I1–I8](matriz-invariantes.md) e [índice de specs y tests locales](../openspec/specs/README.md).
