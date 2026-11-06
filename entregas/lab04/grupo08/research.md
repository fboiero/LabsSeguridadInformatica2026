# Mini-research — Laboratorio 04

**Tema elegido:**

- [ ] **A.** ISO/IEC 27001: qué es un SGSI y el ciclo PDCA.
- [ ] **B.** NIST Cybersecurity Framework: las cinco funciones y cómo se usan.
- [ ] **C.** Ley 26.388 y marco legal argentino de delitos informáticos.
- [x] **D.** Análisis de riesgo cuantitativo vs cualitativo: ventajas y límites.

---

## Planteo y postura del grupo

En la Parte B del informe priorizamos los riesgos de PhantomCorp con números: SLE, ARO y ALE. En la mayoría de las organizaciones, sin embargo, el riesgo se evalúa con una **matriz de calor**: probabilidad "baja/media/alta" contra impacto "bajo/medio/alto", y un color por casillero. La pregunta es si una forma es mejor que la otra, o si sirven para cosas distintas.

Nuestra postura es que el análisis cualitativo sirve para **empezar** (es rápido y no exige datos), pero que cuando hay que decidir **cuánto invertir** hace falta el cuantitativo, porque una matriz de colores no permite calcular si un control se paga. Y que el cuantitativo tampoco es la verdad: un ALE es una estimación, y su utilidad depende de que se expliciten los supuestos y se pruebe qué pasa si están mal.

---

## Desarrollo

### 1. Qué es cada enfoque

NIST distingue tres enfoques de evaluación de riesgo [1]:

- **Cualitativo:** usa categorías o niveles no numéricos ("bajo", "medio", "alto").
- **Cuantitativo:** usa números cuyo significado y proporcionalidad se mantienen fuera del contexto de la evaluación. Un ALE de 20.000 dólares es el doble que uno de 10.000, en cualquier empresa.
- **Semicuantitativo:** usa escalas o números representativos (por ejemplo, del 1 al 5) que solo tienen sentido dentro de esa evaluación. Un "4" de impacto no es el doble de un "2".

Las normas de gestión no imponen uno solo. ISO 31000 define el riesgo como el "efecto de la incertidumbre sobre los objetivos" [2], e ISO/IEC 27005, la guía de gestión de riesgos que acompaña a ISO 27001, deja que cada organización elija su método de evaluación [3]. En la práctica, la mayoría elige el cualitativo.

### 2. Por qué gusta el cualitativo, y su problema

El cualitativo es rápido, no requiere datos históricos y es fácil de comunicar a la dirección: un mapa con casilleros rojos se entiende de un vistazo. Para un primer relevamiento, como el mapeo de debilidades de nuestra Parte A, alcanza.

El problema aparece cuando se lo usa para **decidir**. Cox analizó matemáticamente las matrices de riesgo y mostró que pueden asignar el mismo color a riesgos que difieren mucho en su valor esperado, e incluso dar una calificación más alta a un riesgo cuantitativamente **menor**; en algunos casos concluye que son "peores que inútiles", porque ordenan los riesgos peor que el azar [4]. El origen es la compresión de rangos: "probabilidad alta" puede abarcar desde 30 % hasta 90 %, e "impacto medio" desde mil hasta cien mil dólares, y todo eso cae en el mismo casillero.

A esto se suma que las palabras se interpretan distinto. Para una persona "probable" es 60 %; para otra, 90 %. Dos evaluadores pueden marcar el mismo casillero queriendo decir cosas muy diferentes, y la matriz lo esconde.

### 3. Qué agrega el cuantitativo

La ventaja central del enfoque cuantitativo es que habla el idioma de la decisión: **dinero**. Con un ALE se puede calcular el ROI de un control, que es lo que hicimos en la Parte B: el control para el robo de la base de clientes cuesta 15.000 por año, baja el ALE de 75.000 a 12.000 y da un ROI de 3,2. Con una matriz, lo único que podríamos haber dicho es que el riesgo pasa de "rojo" a "amarillo", sin saber si valía la pena pagarlo.

Hubbard y Seiersen sostienen que el riesgo de ciberseguridad se puede medir aunque los datos sean escasos: en lugar de puntajes, proponen estimar **rangos** con expertos entrenados para estimar bien ("calibrados") y combinarlos con simulaciones de Monte Carlo, que muestran la probabilidad de perder más de cierto monto en lugar de un único número [5]. El modelo FAIR, estandarizado por The Open Group, va en la misma dirección: descompone el riesgo en la frecuencia de los eventos de pérdida y la magnitud de cada pérdida, y cada factor se puede estimar y discutir por separado [6].

### 4. Lo que aprendimos aplicándolo

Hacer el análisis cuantitativo en la Parte B nos mostró sus límites en primera persona:

- **Los números son supuestos.** Ningún SLE ni ARO de nuestro `riesgos.json` sale de datos reales de PhantomCorp. La precisión de "75.000,00" es engañosa: la incertidumbre real es mucho mayor.
- **El ALE trata a los riesgos como independientes.** El compromiso de una cuenta remota quedó tercero en el ranking, pero es la puerta de entrada de los dos primeros. El ALE no ve que un riesgo habilita a otro.
- **El promedio esconde la cola.** Un ALE de 3.000 para la pérdida del disco de backup puede ser "un evento de 60.000 cada 20 años", pero ese evento, si coincide con otro, puede cerrar la empresa. El ALE iguala riesgos frecuentes y chicos con riesgos raros y catastróficos.

La herramienta que mejor nos funcionó contra esto fue el **análisis de sensibilidad**: recalculamos el ROI suponiendo que el riesgo era tres veces menos frecuente, y el control seguía conviniendo (ROI 0,4). Eso nos dio más confianza en la decisión que el número original.

---

## Tensión y límites

1. **Sin datos, el cuantitativo puede ser una ilusión de precisión.** Un número con decimales parece más confiable que un color, aunque los dos salgan de la misma intuición. Si no se declaran los supuestos, el cuantitativo puede ser más peligroso que el cualitativo, porque convence más.
2. **El costo de hacerlo bien.** Calibrar expertos, recolectar datos de incidentes y correr simulaciones lleva tiempo y conocimiento que una PyME como PhantomCorp probablemente no tiene. Para muchas organizaciones, un enfoque semicuantitativo bien definido (con rangos numéricos explícitos detrás de cada nivel) es un punto medio razonable.
3. **No todo se traduce bien a dinero.** El daño a la reputación, la pérdida de confianza de los clientes o las consecuencias legales para las personas cuyos datos se filtraron son difíciles de expresar como un SLE, y forzarlo puede subestimarlos.

---

## Reflexión

Antes de este lab pensábamos que "cuantitativo" quería decir "exacto". Ahora lo vemos al revés: el valor del enfoque cuantitativo no está en que el número sea correcto, sino en que obliga a escribir los supuestos, permite discutirlos y deja probar qué pasa si están mal. Una matriz de colores no se puede auditar; un `riesgos.json` sí. Para la práctica profesional nos quedamos con una regla simple: cualitativo para relevar, cuantitativo (con rangos y sensibilidad) para decidir inversiones.

---

## Fuentes

1. National Institute of Standards and Technology. (2012). *Guide for conducting risk assessments* (NIST SP 800-30 Rev. 1). https://doi.org/10.6028/NIST.SP.800-30r1 — **Primaria**.
2. International Organization for Standardization. (2018). *ISO 31000:2018 — Risk management — Guidelines*. https://www.iso.org/standard/65694.html — **Primaria** (norma).
3. International Organization for Standardization. (2022). *ISO/IEC 27005:2022 — Information security, cybersecurity and privacy protection — Guidance on managing information security risks*. https://www.iso.org/standard/80585.html — **Primaria** (norma).
4. Cox, L. A. (2008). What's wrong with risk matrices? *Risk Analysis, 28*(2), 497–512. https://doi.org/10.1111/j.1539-6924.2008.01030.x — **Arbitrada**.
5. Hubbard, D. W., & Seiersen, R. (2016). *How to measure anything in cybersecurity risk*. Wiley. — **Secundaria** (libro).
6. The Open Group. (2013). *Risk Taxonomy (O-RT), Version 2.0* (Open FAIR). https://publications.opengroup.org/c13k — **Primaria** (estándar).

---

## Declaración de uso de asistentes de IA

**¿Se usaron asistentes de IA en este trabajo?** Sí.

| Herramienta | Para qué se usó | Qué partes afectó | Cómo se verificó |
|---|---|---|---|
| Claude (Anthropic) | Búsqueda de fuentes y borrador de la redacción. | Todo el mini-research. | Abrimos cada fuente para confirmar que existe y que dice lo que se le atribuye. Los ejemplos de la sección 4 salen de nuestra propia Parte B y de correr `src/riesgo.py`. El grupo revisó el texto y puede explicar cada parte. |
