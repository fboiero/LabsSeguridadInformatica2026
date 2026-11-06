# Mini-research — Laboratorio 04

**Tema elegido:** D — Análisis de riesgo cuantitativo vs cualitativo.

- [ ] **A.** ISO/IEC 27001: qué es un SGSI y el ciclo PDCA.
- [ ] **B.** NIST Cybersecurity Framework: las cinco funciones y cómo se usan.
- [ ] **C.** Ley 26.388 y marco legal argentino de delitos informáticos.
- [x] **D.** Análisis de riesgo cuantitativo vs cualitativo: ventajas y límites.

## Desarrollo

### 1. Qué pregunta responde cada enfoque

El análisis de riesgos ayuda a decidir qué situaciones requieren tratamiento y
con qué prioridad. NIST SP 800-30 distingue evaluaciones **cualitativas**,
**cuantitativas** y **semicuantitativas**. La elección depende del propósito,
los datos disponibles y la forma de comunicar el resultado. [1]

El enfoque cualitativo describe probabilidad e impacto mediante categorías
como bajo, medio o alto. Facilita conversar con responsables del negocio, pero
necesita criterios explícitos: dos evaluadores pueden entender algo distinto
por «impacto alto». También puede dejar varios riesgos empatados. Asignar
números del 1 al 5 a esas categorías produce una escala semicuantitativa;
no convierte automáticamente el resultado en dinero ni demuestra que un nivel
4 represente el doble de pérdida que un nivel 2. [1]

El enfoque cuantitativo emplea magnitudes con unidades y significado, como
pérdida monetaria por evento y frecuencia anual. Sirve para comparar costos
y reducción de pérdidas, pero exige explicar supuestos y calidad de datos.
Usar muchos decimales no vuelve confiable una estimación. [1]

### 2. Ventajas y límites al aplicarlos

| Aspecto | Cualitativo | Cuantitativo |
|---|---|---|
| Resultado | Categorías comprensibles para decidir. | Magnitudes monetarias, frecuencias o distribuciones. |
| Ventaja | Permite una evaluación inicial con criterios compartidos. | Permite comparar tratamientos mediante costos y pérdidas esperadas. |
| Dificultad | Ambigüedad de las etiquetas y menor diferenciación entre riesgos. | Esfuerzo de estimación y posible apariencia de precisión. |
| Control de calidad | Definir cada categoría y justificar la asignación. | Registrar fuentes, unidades, supuestos e incertidumbre. |

La comparación resume los criterios de NIST [1][2]. No hay una división entre
«cualitativo = opinión» y «cuantitativo = certeza»: ambos requieren juicio y
evidencia. NIST IR 8286A recomienda describir escenarios concretos e impactos
primarios y secundarios, y contempla estimaciones por rangos y simulaciones
Monte Carlo para representar incertidumbre. Una simulación tampoco corrige
por sí sola datos de entrada equivocados. [2]

### 3. ALE y ROSI en el modelo del laboratorio

ENISA presenta el análisis de la inversión en seguridad como reducción de
pérdidas esperadas. El modelo que usamos es: [3]

```text
SLE = pérdida estimada por evento                 [USD/evento]
ARO = frecuencia anual esperada                  [eventos/año]
ALE = SLE × ARO                                  [USD/año]
ROSI = (ALE antes − ALE después − costo anual) / costo anual
```

Aquí ARO es una **frecuencia**, que puede superar 1 si se esperan varios
eventos por año; no es siempre la probabilidad de «al menos un incidente».
ENISA incluye un ejemplo con ARO = 5. Los costos y pérdidas deben referirse
al mismo período. Un ROSI positivo expresa conveniencia bajo las estimaciones
usadas, no un ahorro garantizado ni ingresos efectivamente cobrados. ENISA
advierte que estimar incidentes y eficacia introduce aproximaciones. [3]

El ALE resume una media, no la peor pérdida ni su distribución. En nuestro
`riesgos.json`, R4 tiene SLE de USD 400.000 y ARO de 0,01: su ALE es USD 4.000.
Ese promedio coincide con perder USD 4.000 una vez por año, aunque las
consecuencias para la continuidad serían diferentes. Por eso el cuarto lugar
de R4 no demuestra que pueda aceptarse sin evaluar la capacidad de soportar
el siniestro. Es una interpretación de los datos del grupo, no una predicción.

### 4. Sensibilidad: cuándo cambia la decisión sobre MFA

Tomamos los supuestos de B.2: SLE de R1 = USD 250.000, costo del control =
USD 4.440/año y eficacia del 90 %. Conservamos SLE y costo y variamos únicamente
ARO. Los resultados son cálculos propios, reproducidos con `riesgo.py`:

| Escenario supuesto | ARO antes | ALE antes (USD/año) | ALE después (USD/año) | ROSI |
|---|---:|---:|---:|---:|
| Base de la entrega | 0,30 | 75.000 | 7.500 | 14,203 |
| Frecuencia menor | 0,05 | 12.500 | 1.250 | 1,534 |
| Frecuencia muy baja | 0,01 | 2.500 | 250 | −0,493 |

El punto de equilibrio es `ARO = 4440 / (250000 × 0,90) ≈ 0,01973`.
Por debajo, la reducción esperada no cubre ese costo bajo este modelo.
La inversión sigue siendo favorable en el segundo escenario, pero deja de
serlo en el tercero. Los escenarios no son intervalos de confianza ni se
les asignó una probabilidad: muestran qué supuesto puede cambiar la decisión.

Para reproducir el tercer caso desde la carpeta del grupo:

```text
python3 -B src/riesgo.py ale --sle 250000 --aro 0.01
2500.00
python3 -B src/riesgo.py ale --sle 250000 --aro 0.001
250.00
python3 -B src/riesgo.py roi --antes 2500 --despues 250 --costo 4440
-0.493
```

Los porcentajes de un informe sobre empresas que **ya sufrieron brechas** no
equivalen a la frecuencia anual de incidentes de PhantomCorp. Del mismo modo,
una tasa de fallas de discos de otra población requiere justificar su traslado
al disco de esta oficina. En nuestra entrega, los ARO son hipótesis para el
ejercicio y deben validarse con datos propios antes de decidir una inversión
real. Esto aplica el criterio de disponibilidad y confiabilidad de datos de
NIST IR 8286A al caso estudiado. [2]

### 5. De un ranking a una decisión de gestión

NIST IR 8286B vincula la priorización y la respuesta con el apetito y la
tolerancia al riesgo de la organización. Aceptar un riesgo exige que permanezca
dentro de los límites establecidos y que se siga monitoreando; no significa
olvidarlo. También considera evitar, mitigar y transferir, y revisar el riesgo
residual después del tratamiento. [4]

Aplicado a PhantomCorp, proponemos usar una evaluación cualitativa inicial
para describir escenarios y consecuencias, y cuantificar luego los riesgos
que compiten por el presupuesto. Para R4, combinaríamos el SLE catastrófico
con la evaluación de respaldos externos y de una transferencia financiera
parcial, como plantea B.3. Un ROSI aislado no decide cuánto riesgo puede
soportar la empresa. Esta es una propuesta del grupo basada en [4].

Además, R1 y R2 pueden formar parte del mismo incidente: una intrusión puede
terminar en ransomware. Al agregar pérdidas hay que evitar contar dos veces
los mismos costos. La dependencia por sí sola no impide sumar pérdidas
esperadas si representan componentes distintos; el problema es superponer
escenarios y conceptos. El ranking individual del script no resuelve esa
modelización. NIST IR 8286B trata la agregación como una actividad adicional
a la priorización inicial. [4]

## Fuentes (mín. 3)

1. NIST (2012). [SP 800-30 Rev. 1 — Guide for Conducting Risk Assessments](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-30r1.pdf).
   §2.3.2, pp. 14–15: enfoques cuantitativo, cualitativo y semicuantitativo.
2. NIST (2025). [IR 8286A Rev. 1 — Identifying and Estimating Cybersecurity Risk for Enterprise Risk Management](https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8286Ar1.pdf).
   §2.2.4 y §2.3: impactos, selección del método, estimación e incertidumbre.
3. ENISA (2012). [Introduction to Return on Security Investment](https://www.enisa.europa.eu/sites/default/files/publications/Return%20On%20Security%20Investment.pdf).
   §3 y §4, pp. 4–8: SLE, ARO, ALE, ROSI y límites de las estimaciones.
4. NIST (2025). [IR 8286B-upd1 — Prioritizing Cybersecurity Risk for Enterprise Risk Management](https://nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8286B-upd1.pdf).
   §2.2, §2.3 y §2.5: priorización, respuestas, tolerancia y preparación para agregar riesgos.

Las cuatro fuentes son documentos primarios; se consultaron las versiones
indicadas. Los importes de los ejemplos provienen del modelo ficticio del
grupo y no son cifras universales publicadas por NIST o ENISA.

## Reflexión

El aporte del enfoque cuantitativo fue obligarnos a mostrar qué sostiene la
prioridad de R1 y qué tendría que cambiar para revisar la inversión en MFA.
El escenario con ROSI negativo es especialmente útil: permite discutir un
supuesto que puede verificarse, en lugar de presentar el control como rentable
en cualquier circunstancia. A la vez, R4 muestra que ordenar por promedio
anual puede dejar abajo una pérdida que la empresa no soportaría.

Usaríamos ambos enfoques en secuencia y revisaríamos el análisis cuando haya
nuevos datos: primero describir el daño y los límites aceptables; después,
comparar alternativas con cifras y sensibilidad. En una defensa del trabajo,
la conclusión que podemos sostener es que el cálculo funciona para los
supuestos declarados. Para afirmar que las estimaciones describen a una
empresa real faltarían su historial, condiciones de operación y evidencia
de la eficacia efectiva de los controles.

**Uso de IA:** Fernando Cagliero (@Ferca19) utilizó OpenAI Codex para localizar
y contrastar fuentes, organizar el desarrollo y asistir en la redacción.
Durante esta sesión se consultaron los cuatro documentos, se recalcularon
los ejemplos con `src/riesgo.py` y `decimal.Decimal`, y se ejecutó la
autoevaluación de la cátedra. La sensibilidad es un ejercicio determinista;
no se realizó una simulación Monte Carlo ni una medición de PhantomCorp.
