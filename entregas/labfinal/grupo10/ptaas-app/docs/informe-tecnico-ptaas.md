# Informe técnico — PTaaS Grupo 10

**Versión:** entrega PTaaS para laboratorio autorizado, pendiente de aprobación docente.

## Resumen ejecutivo

La plataforma limita al modelo a decisiones estructuradas, valida la autorización
por código y conserva un registro auditable de las acciones inertes. Procesó el
registro histórico del Grupo 10 de PhantomCorp y cotejó los cuatro hitos con
comprobantes: el estado y sus comprobantes coinciden. No volvió a ejecutar los
hitos ni confirmó personalmente los hallazgos técnicos. Las alertas de Bandit
se presentan como preliminares, sin asignar CWE o CVSS a partir de metadatos insuficientes.

## Arquitectura y metodología

1. La demo de control carga reglas de engagement YAML e intercambia un token por fase
   de vigencia corta. El scope guard, la allowlist, el kill switch y los gates son código.
2. SQLite registra intentos antes de llamar al adaptador inerte; si el intento no se
   puede persistir no se ejecuta. La cadena detecta alteraciones estructurales, no
   reescrituras completas ni truncamiento final consistente sin anclaje externo.
3. El perfil documental lee los objetos de Git fijados por commit y sólo extrae
   marcadores de estado. Bandit entra como informe estático preexistente y MITRE
   como piloto independiente de clasificación defensiva de telemetría.
4. Los modelos reciben categorías y referencias acotadas. Se descartan decisiones
   inventadas o con referencias ajenas. El borrador se valida en Docker sin red.
5. Una persona revisa el borrador y sus decisiones; el hash de ambos vincula la
   aprobación a esa versión. No identifica al aprobador. La exportación es local.
6. El loop A mantiene un `AssetGraph`; el loop B usa snapshots offline y una
   allowlist de templates; el loop C usa el catálogo inerte y un `Sender` real.

## Resultados y evidencia

- El clásico histórico registra R1–R4 en `labfinal-grupo10`, commit `bf8f681`.
  El paquete local incluye referencias al estado y a cada comprobante archivado.
- La matriz de [invariantes](matriz-invariantes.md) explica qué está demostrado.
  El estado histórico y la bitácora de la demo inerte no son la misma evidencia.
- En la comparación del lote cerrado, Astra, Sol y Terra acertaron 20/20 cada uno.
  Una corrida por modelo no permite comparar capacidad de detección ni estimar costos.
- El formato Generic Findings Import se prueba sin inventar hallazgos. No se
  validó una importación contra una instancia de DefectDojo.
- `POC-CSP-001` se ejecutó contra Juice Shop real, obtuvo HTTP 200 y validó CSP
  ausente. El recibo es `runs/juice-poc-real-20261118-204806-csp.json`.
- El Loop A real obtuvo HTTP 200, estabilizó el `AssetGraph` en dos rondas y
  registró cuatro eventos en bitácora. Recibo:
  `runs/juice-recon-real-20261118-210744.json`.

## Riesgos, límites y retrospectiva

### Evaluaciones reproducibles

| Evaluación | Resultado | Alcance |
|---|---|---|
| Golden y negativos | 21/21 | Contratos y procedencia, con proveedor de respuestas fijas. |
| Mutaciones dirigidas | 3/3 detectadas | Orden del plan, referencias de análisis y procedencia del reporte. |

No son mediciones de detección de vulnerabilidades ni una comparación en vivo
de versiones de prompts. Al omitir el control de procedencia del informe, el
evaluador detecta que podrían pasar referencias ajenas, un CVE inventado en
prosa u omisiones de activos. Esto justifica mantener el veredicto en código,
en lugar de confiar en el texto del modelo.

### Observación de endurecimiento de Juice Shop

En `GET /`, HTTP 200, la comprobación inerte observó ausencia de la cabecera
`Content-Security-Policy`. Es una medida de defensa en profundidad; el recibo
no demuestra ejecución de código ni impacto explotable. Recomendación: definir
una política acorde a los recursos de la aplicación, observar primero con
`Content-Security-Policy-Report-Only`, y luego aplicar y verificar la política.
No se asigna CVSS ni EPSS a partir de este único dato. Los dos CVE de los
snapshots son registros de muestra, no asociaciones verificadas con Juice Shop.

La [demo de defensa](guion-entrega.md) reúne cinco recibos y calcula SHA-256
de sus bytes. No reconstruye eventos descartados por la bitácora en memoria,
no repite las operaciones y no acredita una corrida integrada A/B/C.

Se descartó la salida que inventaba candidatos y se añadieron pruebas para alertas
omitidas y referencias cruzadas. El modelo fue útil para resumir y abstenerse, pero
las salidas estuvieron condicionadas por casos acotados. Por eso los controles y
el veredicto de consistencia son deterministas. No se ejecuta explotación,
validación de exploits nuevos ni escaneo autónomo fuera de allowlists; el gate de
validación es humano y determinista. DefectDojo queda pendiente de una instancia
provista por la cátedra. Véanse [selección de herramientas](tool-selection.md) y
[estado de la entrega](checkpoints-catedra.md).
