# Mini-research — Laboratorio 04

**Grupo:** 02

**Tema elegido:**
- [ ] **A.** ISO/IEC 27001: qué es un SGSI y el ciclo PDCA.
- [ ] **B.** NIST Cybersecurity Framework: las cinco funciones y cómo se usan.
- [ ] **C.** Ley 26.388 y marco legal argentino de delitos informáticos.
- [x] **D.** Análisis de riesgo cuantitativo vs cualitativo: ventajas y límites.

## Desarrollo

### 1. Qué es cada enfoque

Analizar un riesgo es estimar qué tan probable es un evento y cuánto daño causaría. La diferencia entre los enfoques está en cómo se expresan esas dos cosas.

- **Cualitativo:** usa categorías descriptivas, como bajo, medio y alto, o muy bajo a muy alto. El resultado suele mostrarse en una matriz de riesgo o mapa de calor.
- **Cuantitativo:** usa números, normalmente dinero para el impacto y frecuencia por año para la probabilidad. Es el enfoque que usamos en este laboratorio con **SLE** (pérdida por evento), **ARO** (eventos por año) y **ALE** (SLE × ARO).
- **Semicuantitativo:** asigna escalas numéricas (por ejemplo de 0 a 10 o de 1 a 100) a las categorías. Busca más detalle que el cualitativo sin exigir los datos del cuantitativo.

La guía NIST SP 800-30 Rev. 1 no impone uno solo: presenta los tres como opciones válidas y pide que la organización elija según su contexto y su tolerancia al riesgo, y que lo aplique de manera consistente.

### 2. Ventajas y límites del enfoque cualitativo

**Ventajas.** Es rápido, no requiere datos históricos ni conocimientos estadísticos, y es fácil de explicar a personas no técnicas. Sirve para una primera clasificación cuando una organización recién empieza.

**Límites.** Las categorías son ambiguas: dos personas pueden entender "alto" de forma distinta, y es difícil comparar evaluaciones hechas en distintos momentos. Además, Cox (2008) mostró que las matrices de riesgo, que son la herramienta cualitativa más usada, tienen problemas matemáticos: solo logran comparar sin ambigüedad una pequeña parte de los pares de riesgos y pueden asignar una calificación más alta a un riesgo que en realidad es menor. Su conclusión es que la clasificación de una matriz no es una base sólida para decidir dónde invertir en contramedidas.

### 3. Ventajas y límites del enfoque cuantitativo

**Ventajas.** Expresa el riesgo en dinero, que es el idioma de quienes aprueban el presupuesto. Permite comparar riesgos distintos con la misma unidad, ordenarlos y justificar una inversión con una cuenta, como el ROI de la Parte B: un control que evita $15.000 por año y cuesta $9.000 se puede defender con números. Modelos como FAIR (Factor Analysis of Information Risk), creado por Jack Jones, estandarizado por The Open Group y promovido por el FAIR Institute, formalizan este enfoque y lo extienden con rangos y simulaciones (Monte Carlo) en lugar de valores únicos.

**Límites.**
- **Falta de datos.** Estimar el ARO y el SLE de un ataque informático es difícil: hay pocos datos históricos confiables, y muchos de los números salen del juicio de expertos.
- **Falsa precisión.** Un resultado como "$30.000" parece exacto, pero depende de estimaciones inciertas. Si se presenta sin aclarar la incertidumbre, da una confianza que no corresponde.
- **Costos intangibles.** El daño reputacional, la pérdida de confianza de los clientes o el impacto legal son difíciles de convertir en dinero.
- **Costo del análisis.** Hacerlo bien lleva tiempo y conocimientos que una organización pequeña puede no tener.

### 4. ¿Cuál conviene?

No se trata de elegir uno y descartar el otro. Los enfoques se complementan: el cualitativo sirve para identificar y filtrar rápido, y el cuantitativo para decidir con más cuidado sobre los riesgos que más importan o que requieren una inversión. Para quien recién empieza, el semicuantitativo suele ser un punto intermedio razonable. Lo importante es dejar escritos los supuestos y aplicar el método de forma consistente.

## Fuentes (mín. 3)

1. Ross, R. S. (2012). *Guide for Conducting Risk Assessments*. NIST Special Publication 800-30 Revision 1. National Institute of Standards and Technology. https://www.nist.gov/publications/guide-conducting-risk-assessments (DOI: https://doi.org/10.6028/NIST.SP.800-30r1)
2. Cox, L. A. (2008). What's Wrong with Risk Matrices? *Risk Analysis*, 28(2), 497–512. Society for Risk Analysis.
3. FAIR Institute. *What is FAIR?* https://www.fairinstitute.org/what-is-fair
4. Center for Internet Security. *FAIR: A Framework for Revolutionizing Your Risk Analysis.* https://www.cisecurity.org/insights/blog/fair-a-framework-for-revolutionizing-your-risk-analysis

## Reflexión

Hacer la Parte B nos mostró de forma concreta las dos caras del enfoque cuantitativo.

**A favor:** el cálculo cambió nuestra intuición. Los backups en la oficina nos parecían una catástrofe y resultaron el riesgo de menor ALE ($3.000), mientras que la falta de política de contraseñas, que parecía menor, tuvo un ALE de $15.000 por su alta frecuencia. Sin números, probablemente habríamos priorizado al revés. El ROI también nos dio un criterio para decidir cuándo conviene gastar y cuándo aceptar o transferir un riesgo.

**En contra:** todos nuestros valores de SLE, ARO y costos son estimaciones propias, no datos medidos. Al hacer la sensibilidad de B.2 vimos que el ROI del control pasa de 0.667 a 0.111 si el ARO baja solo a 0.2, y es negativo si baja solo a 0.25. Es decir, una decisión que parecía clara depende mucho de un número que estimamos nosotros. Por eso concluimos que el resultado de ALE debe leerse como un orden de magnitud para comparar opciones, no como una predicción exacta, y que conviene acompañarlo con rangos y análisis de sensibilidad. Si tuviéramos que mejorar nuestro trabajo, estimaríamos cada valor como un rango (mínimo, probable y máximo) en lugar de un único número, como propone FAIR.

---

*Uso de IA:* se utilizó Claude (Anthropic) para buscar fuentes.El grupo leyó las fuentes citadas, verificó los datos y adaptó el texto.