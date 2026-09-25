# Informe — Laboratorio 04 · Marcos normativos y gestión

**Grupo:** 06 · **Integrantes:** 

| Nombre y apellido | Usuario de GitHub |
|---|---|
| Martín Beccereca | martinbeccereca |
| Belén Benito | belubenito01 |
| Alejo José De Miguel | AlejoDM |
| Tomás Giudici | TomasGiudici |
| Carolina Suppo | carosuppo |


## 0. Declaración de uso de IA

**Herramienta: Claude Code**
- **Finalidad del uso:** Apoyo en la redacción del informe. 
- **Partes generadas o asistidas:** Sección 1 — A.1 y A.2.
- **Verificación:** Las fuentes citadas fueron visitadas y verificadas antes de citarla.

## 1. Parte A — Marco aplicado

### A.1 — Marco elegido y por qué

Elegimos el **NIST Cybersecurity Framework (CSF)**, en su versión vigente
**CSF 2.0** (publicada en febrero de 2024). Dos razones concretas para este
escenario:

1. **Es de acceso libre y gratuito.** ISO/IEC 27001 es un estándar que hay
   que comprar para leer el texto completo del Anexo A; el NIST CSF se
   publica y actualiza en `nist.gov/cyberframework` sin costo, lo que importa
   para una PyME como PhantomCorp que recién está armando su gestión de
   seguridad y no tiene presupuesto para certificarse.
2. **Su estructura por funciones es más rápida de aplicar a un diagnóstico
   inicial que un sistema de gestión completo.** ISO 27001 exige construir
   un SGSI (Sistema de Gestión de Seguridad de la Información) con
   políticas, alcance y auditoría formal, lo que representa un proceso de gestión, no un diagnóstico puntual. El NIST CSF, en cambio, organiza los resultados de
   ciberseguridad en funciones de alto nivel pensadas para razonar rápido
   sobre "qué le falta a esta organización", que es exactamente lo que pide
   este ejercicio.

CSF 2.0 define **seis** funciones: **Gobernar (Govern)**, **Identificar
(Identify)**, **Proteger (Protect)**, **Detectar (Detect)**, **Responder
(Respond)** y **Recuperar (Recover)**.

La función **Govern** es la incorporación nueva de la versión 2.0 respecto de la 1.1, y organiza la
estrategia y las políticas de seguridad que orientan a las otras cinco.
Para el mapeo de A.2 usamos las cinco funciones operativas que menciona el
propio enunciado (Identify/Protect/Detect/Respond/Recover); lo señalamos
porque **Govern** también aplicaría acá, ya que la ausencia de una política de
contraseñas formal es, en rigor, tanto un problema de *Protect* como de
*Govern*. Sin embargo, mantuvimos el mapeo uno a uno para no forzar una sexta
debilidad que el enunciado no pide.

### A.2 — Mapeo de cinco debilidades a funciones del NIST CSF

| # | Debilidad del escenario | Función NIST CSF | Por qué esta función |
|---|---|---|---|
| 1 | No hay inventario ni clasificación formal de los datos sensibles que maneja (nombres, DNI, números de tarjeta) | **Identify** | *Identify* es la función que cubre entender los activos, los datos y el contexto de riesgo de la organización. Sin saber con precisión qué dato crítico se tiene y dónde vive, no se puede priorizar ninguna otra medida, ya que es la base de la que dependen las demás cuatro. |
| 2 | No tiene MFA ni política de contraseñas para el acceso remoto de empleados | **Protect** | *Protect* cubre las salvaguardas que reducen la probabilidad de que un evento de ciberseguridad ocurra, y el control de acceso e identidad es el ejemplo canónico de esta función. |
| 3 | El servidor web público y los accesos remotos no muestran evidencia de monitoreo o registro de actividad | **Detect** | *Detect* es identificar eventos de ciberseguridad cuando ocurren. Sin logging ni monitoreo sobre los dos puntos de entrada más expuestos (el servidor público y el acceso remoto), un atacante podría estar adentro sin que nadie se entere. |
| 4 | No tiene un plan de respuesta a incidentes | **Respond** | *Respond* cubre las acciones a tomar durante y después de un incidente detectado. Sin un plan, aun si *Detect* funcionara, la organización improvisaría en el peor momento posible. |
| 5 | Los backups están en un único disco físico en la oficina, sin redundancia ni copia externa | **Recover** | *Recover* cubre restaurar capacidades y servicios después de un incidente. Un backup en un solo disco en el mismo edificio es un punto único de fallo: un incendio, un robo o un ransomware que cifre también ese disco deja a PhantomCorp sin forma de recuperarse. |

Fuente: National Institute of Standards and Technology. (2024). *The NIST
Cybersecurity Framework (CSF) 2.0* (NIST CSWP 29).
https://doi.org/10.6028/NIST.CSWP.29, documento oficial disponible también en
https://www.nist.gov/cyberframework.

---

### A.3 — Respuesta al riesgo
## 2. Parte B — Riesgo cuantitativo (ranking por ALE; ROI del control #1; un riesgo a aceptar/transferir)

### B.1 — Interpretación del ranking por ALE

Al ejecutar:

`python src/riesgo.py priorizar --archivo riesgos.json`

se obtuvo el siguiente ranking:

1. Compromiso de credenciales de empleados por falta de MFA y políticas de contraseñas débiles: **ALE = $36.000**.
2. Exfiltración masiva de datos sensibles mediante una vulnerabilidad en el servidor web público: **ALE = $28.000**.
3. Intrusión persistente y movimiento lateral no detectado por falta de logging y monitoreo centralizado: **ALE = $22.500**.
4. Pérdida irrecuperable de datos por ransomware o siniestro físico debido a un único backup local: **ALE = $15.000**.
5. Interrupción operativa por falta de un plan formal de respuesta a incidentes: **ALE = $9.000**.

En términos generales, el ranking coincide con la intuición, ya que el compromiso de credenciales aparece como el riesgo con mayor pérdida anual esperada. La falta de MFA y una política de contraseñas débil, combinadas con el acceso remoto de empleados, aumentan la frecuencia estimada de este tipo de incidente. Aunque su SLE es de $30.000, su ARO de 1,2 hace que alcance el ALE más alto, de $36.000.

Sin embargo, el ranking también muestra un caso que puede resultar menos intuitivo. La pérdida irrecuperable de datos por ransomware o un siniestro físico tiene el SLE más alto de todos los riesgos, de $100.000, pero aparece recién en cuarto lugar porque su ARO es de 0,15. Esto demuestra que un riesgo con consecuencias muy graves no necesariamente tendrá el ALE más alto si su frecuencia anual estimada es baja.

Por lo tanto, el ranking por ALE permite considerar conjuntamente el impacto económico y la frecuencia estimada, en lugar de priorizar los riesgos únicamente por la gravedad de un incidente individual.

### B.2 — Control para el riesgo con mayor ALE

El riesgo ubicado en primer lugar es el compromiso de credenciales de empleados por falta de MFA y políticas de contraseñas débiles en el acceso remoto.

Los valores actuales son:

- **SLE:** $30.000
- **ARO:** 1,2
- **ALE actual:** $30.000 × 1,2 = **$36.000**

Como control proponemos implementar autenticación multifactor (MFA) para las cuentas de los empleados y, especialmente, para los accesos remotos.

Para realizar el análisis económico estimamos un costo anual de implementación y mantenimiento del control de **$10.000**. También estimamos que la implementación de MFA permitiría reducir el ARO de 1,2 a 0,2 eventos por año.

Manteniendo el mismo SLE:

**ALE posterior = $30.000 × 0,2 = $6.000**

La reducción anual esperada de las pérdidas sería:

**$36.000 - $6.000 = $30.000**

Aplicando la fórmula utilizada para evaluar el control:

**ROI = (ALE antes - ALE después - costo del control) / costo del control**

**ROI = ($36.000 - $6.000 - $10.000) / $10.000 = 2,0**

El ROI estimado es entonces de **2,0**, equivalente a un **200 %** respecto del costo del control. Bajo estas estimaciones, consideramos conveniente implementar MFA, ya que la reducción anual esperada de las pérdidas supera el costo anual estimado del control.

Tanto el costo de $10.000 como el ARO posterior de 0,2 son estimaciones realizadas para este análisis. En una situación real deberían determinarse utilizando costos concretos de implementación y datos históricos de incidentes de la organización.

### B.3 — Riesgo a aceptar o transferir

Un riesgo que podría evaluarse para una estrategia de **aceptación** es la interrupción operativa prolongada y la improvisación ante incidentes por falta de un plan formal de respuesta.

Sus valores son:

- **SLE:** $15.000
- **ARO:** 0,6
- **ALE:** $9.000

Este riesgo presenta el ALE más bajo de los cinco analizados. Podría aceptarse si la organización determina que el costo de aplicar controles adicionales para reducirlo supera el beneficio económico esperado y si el nivel de riesgo se encuentra dentro de su tolerancia al riesgo.

Aceptar un riesgo no significa ignorarlo. La decisión debería quedar documentada y el riesgo tendría que revisarse periódicamente para comprobar que su frecuencia o impacto no hayan aumentado.

En este caso, la aceptación se plantea como una posible respuesta a partir de los valores utilizados en el ejercicio. En una situación real también deberían analizarse las consecuencias operativas, legales y reputacionales antes de tomar la decisión definitiva.

## 3. Anexo — tu riesgos.json

```json
[
  {
    "nombre": "Compromiso de credenciales de empleados por falta de MFA y política de contraseñas débiles en acceso remoto",
    "sle": 30000.0,
    "aro": 1.2
  },
  {
    "nombre": "Exfiltración masiva de datos sensibles de clientes (nombres, DNI, tarjetas) vía vulnerabilidad en servidor web público",
    "sle": 80000.0,
    "aro": 0.35
  },
  {
    "nombre": "Intrusión persistente y movimiento lateral no detectado por ausencia de logging y monitoreo centralizado",
    "sle": 45000.0,
    "aro": 0.5
  },
  {
    "nombre": "Pérdida irrecuperable de datos por Ransomware o siniestro físico debido a backup único en disco local sin copia externa",
    "sle": 100000.0,
    "aro": 0.15
  },
  {
    "nombre": "Interrupción operativa prolongada e improvisación ante incidentes por falta de un plan formal de respuesta",
    "sle": 15000.0,
    "aro": 0.6
  }
]
```
