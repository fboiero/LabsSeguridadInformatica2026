# Mini-research — Laboratorio 04

**Tema elegido:** D
- [ ] **A.** ISO/IEC 27001: qué es un SGSI y el ciclo PDCA.
- [ ] **B.** NIST Cybersecurity Framework: las cinco funciones y cómo se usan.
- [ ] **C.** Ley 26.388 y marco legal argentino de delitos informáticos.
- [x] **D.** Análisis de riesgo cuantitativo vs cualitativo: ventajas y límites.

## Desarrollo

### Qué es "evaluar un riesgo"
Evaluar un riesgo es combinar dos cosas: **qué tan probable** es que una amenaza
explote una debilidad y **cuánto daño** haría si pasa. La diferencia entre los
enfoques está en *cómo se expresan* esos dos factores. NIST SP 800-30 Rev. 1
(§2.3.2) reconoce tres enfoques: cuantitativo, cualitativo y semicuantitativo, y
dice explícitamente que cada uno tiene ventajas y desventajas y que la elección
depende de la cultura de la organización y de cómo maneja la incertidumbre.

### Enfoque cualitativo
Usa categorías no numéricas: *muy bajo, bajo, medio, alto, muy alto*. La
herramienta típica es la **matriz probabilidad × impacto** (el "mapa de calor"),
donde cada riesgo cae en una celda de color.

- **Ventajas:** es rápido, no necesita datos históricos y es fácil de comunicar a
  la dirección. SP 800-30 lo destaca justamente por eso: "supports communicating
  risk results to decision makers".
- **Límites:** el rango de valores es chico, así que cuesta priorizar entre
  riesgos de la misma celda: dos riesgos "altos" pueden diferir 10 veces en costo
  real. Además, si las categorías no están bien definidas, dos expertos con
  experiencias distintas llegan a resultados muy diferentes. No sirve para
  responder "¿cuánto conviene gastar en este control?".

### Enfoque cuantitativo
Usa números con significado propio, normalmente plata y frecuencia:

- **SLE** (*Single Loss Expectancy*): pérdida esperada por un evento.
- **ARO** (*Annualized Rate of Occurrence*): cuántas veces por año esperamos que pase.
- **ALE = SLE × ARO**: pérdida anual esperada.

Con el ALE se puede calcular el **ROI de un control**:
`(ALE antes − ALE después − costo anual) / costo anual`. Si da mayor que cero, el
control se paga solo. Modelos más elaborados como **Open FAIR** (estándar de The
Open Group, formado por la taxonomía O-RT y el método de análisis O-RA)
descomponen el riesgo en frecuencia de eventos de pérdida y magnitud de pérdida,
y trabajan con rangos y distribuciones en lugar de un único número.

- **Ventajas:** según SP 800-30 es el enfoque que mejor sostiene el **análisis
  costo-beneficio** de las respuestas al riesgo. Permite comparar riesgos
  heterogéneos en la misma unidad (pesos o dólares) y habla el idioma de finanzas.
- **Límites:** depende de datos que casi nunca existen. ¿Cuál es el ARO de un
  ransomware en una pyme? Si la cifra es una estimación subjetiva disfrazada de
  número, el resultado tiene **falsa precisión**: SP 800-30 advierte que el rigor
  "is significantly lessened when subjective determinations are buried within the
  quantitative assessments". También es más caro: requiere tiempo de expertos y,
  a veces, herramientas.

### Enfoque semicuantitativo (el punto medio)
Usa escalas o rangos numéricos (1–10, 0–100) sin un significado fuera de la
evaluación. Permite ordenar mejor que el cualitativo y se traduce fácil a
palabras ("95 = muy alto"), pero el juicio experto queda más a la vista y los
rangos tienen que estar bien definidos.

### Cómo lo combinamos en este lab
NIST CSF 2.0 pide en **GV.RM-06** "a standardized method for calculating,
documenting, categorizing, and prioritizing cybersecurity risks": no impone un
enfoque, pide que el método sea consistente. En la práctica, lo razonable es un
**híbrido**: un filtro cualitativo rápido sobre todos los riesgos y un análisis
cuantitativo (ALE/ROI) solo sobre los pocos donde hay que decidir una inversión
grande. Es lo que hicimos en la Parte B con `riesgo.py`.

| | Cualitativo | Cuantitativo |
|---|---|---|
| Unidad | Categorías (bajo…alto) | Plata y frecuencia |
| Datos necesarios | Pocos, juicio experto | Históricos, estimaciones calibradas |
| Fortaleza | Comunicar, cubrir mucho rápido | Costo-beneficio, comparar controles |
| Debilidad | Poca resolución, subjetivo | Falsa precisión, costoso |

## Fuentes (mín. 3)
1. NIST SP 800-30 Rev. 1, *Guide for Conducting Risk Assessments* (2012), §2.3.2
   "Assessment Approaches". https://csrc.nist.gov/pubs/sp/800/30/r1/final
2. NIST CSWP 29, *The NIST Cybersecurity Framework (CSF) 2.0* (2024), subcategorías
   GV.RM-06 e ID.RA-04/05/06. https://doi.org/10.6028/NIST.CSWP.29
3. The Open Group, *Open FAIR Body of Knowledge* (estándares O-RT y O-RA).
   https://www.opengroup.org/certifications/openfair
4. NIST IR 8286, *Integrating Cybersecurity and Enterprise Risk Management (ERM)*
   (2020; reemplazado por la Rev. 1), uso de registros de riesgo.
   https://csrc.nist.gov/pubs/ir/8286/final

## Reflexión
Al armar `riesgos.json` vimos el límite del enfoque cuantitativo en carne propia:
el ARO de cada riesgo lo estimamos nosotros, y moverlo un poco cambia el ranking.
Igual, poner números nos obligó a explicitar los supuestos, algo que una matriz
de colores esconde. La conclusión es que el número no es la verdad: es una
hipótesis que se puede discutir y corregir, y eso ya es mejor que una corazonada.
