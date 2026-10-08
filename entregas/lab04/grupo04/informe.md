# Informe — Laboratorio 04 · Marcos normativos y gestión

**Grupo:** Grupo 04  
**Integrantes:**
- Uriel Olivero — `@uRIELoLIVERO`
- Jeremias Antunez — `@JereAntunez`
- Facundo Anil — `@FacundoAnil4`
- Matias Lelli — `@LelliMatias`
---

## 0. Declaración de uso de IA

- **Herramienta:** Claude (Anthropic).
- **Para qué se usó:** 
  - Asistencia en la revisión del desarrollo de las funciones del esqueleto de código. 
  - Armado de riesgos.json, y como asistente para el desarrollo del informe y del mini-research.
- **Partes originadas con asistencia:** 
  - `src/riesgo.py`
  - `riesgos.json`
  - `informe.md` y `research.md`
- **Cómo se verificó:**
  1. Se ejecutaron los tres comandos de ejemplo del enunciado y dieron los valores
     esperados (`20000.00` y `0.875`; `priorizar` imprime el ranking).
  2. Los ALE y ROI del informe se recalcularon a mano y con el propio script
     (ver los comandos incluidos en B.2 y B.3).
  3. Cada identificador de control del NIST CSF 2.0 citado (GV.PO-01, PR.AA-03,
     PR.DS-11, RS.MA-01, etc.) se contrastó con el texto oficial del documento
     NIST CSWP 29, Apéndice A, para no citar controles inexistentes.
  4. Se confirmó que las tres fuentes del `research.md` existen y que sus DOI
     corresponden a los documentos citados.
  5. Los valores de SLE y ARO son **supuestos de modelado** (no hay datos reales
     de una empresa ficticia); se declaran como tales en B.1.

---

## 1. Parte A — Marco aplicado

### A.1 — Marco elegido y por qué

Elegimos el **NIST Cybersecurity Framework 2.0** (NIST CSWP 29, febrero de 2024).

- Es un marco de **gestión de riesgo orientado a resultados**, no una norma
  certificable: describe *qué* resultados lograr y no *cómo*. PhantomCorp parte
  casi de cero (sin MFA, sin política de contraseñas, sin plan de respuesta);
  el CSF permite definir un **perfil actual** y un **perfil objetivo** y cerrar
  la brecha por etapas, sin el costo y la formalidad de montar un SGSI
  certificable como el de ISO/IEC 27001.
- Sus seis funciones (**Govern, Identify, Protect, Detect, Respond, Recover**)
  cubren el escenario completo: faltan políticas (Govern), salvaguardas
  (Protect), monitoreo (Detect), respuesta (Respond) y recuperación (Recover).
- La versión 2.0 agrega **Govern** respecto de la 1.1. Es la función más
  relevante acá, porque la ausencia total de políticas es un problema de gobierno
  antes que técnico.
- El propio documento (sección 5) dice que una organización puede manejar un
  riesgo **mitigándolo, transfiriéndolo, evitándolo o aceptándolo**, que son las
  cuatro respuestas que pide la consigna. Además, la subcategoría **GV.RM-06**
  pide "un método estandarizado para calcular, documentar, categorizar y
  priorizar riesgos de ciberseguridad": en este laboratorio ese método es el
  cálculo de ALE de la Parte B.

### A.2 y A.3 — Debilidades → controles del marco → respuesta al riesgo

| # | Debilidad del escenario | Función / categoría / subcategoría NIST CSF 2.0 | Control concreto propuesto | Respuesta | Justificación |
|---|---|---|---|---|---|
| 1 | **No hay MFA** (empleados con acceso remoto) | **Protect — PR.AA** (Identity Management, Authentication, and Access Control). **PR.AA-03**: usuarios, servicios y hardware son autenticados | MFA (TOTP) en VPN/acceso remoto y en cuentas administrativas | **Mitigar** | Es el riesgo de mayor ALE (B.1) y el control es barato y actúa directamente sobre la probabilidad (ARO). |
| 2 | **No hay política de contraseñas** | **Govern — GV.PO-01** (política para gestionar riesgos de ciberseguridad, comunicada y aplicada) + **Protect — PR.AA-01** (identidades y credenciales gestionadas) | Política escrita: largo mínimo, no reutilización, gestor de contraseñas, bloqueo por intentos fallidos; almacenamiento con hash lento (PBKDF2, como en el Lab 03) | **Mitigar** | Costo casi nulo (un documento y configuración): no hay razón económica para aceptar este riesgo. |
| 3 | **No hay plan de respuesta a incidentes** | **Respond — RS.MA-01** (se ejecuta el plan de respuesta una vez declarado el incidente), **RS.MI-01** (contener), **RS.CO-02** (notificar a las partes interesadas); **Identify — ID.IM-04** (planes de respuesta establecidos, comunicados, mantenidos y mejorados) | Plan de IR con roles, contactos, criterios de severidad, comunicación y simulacro anual | **Mitigar** | No evita el incidente, pero reduce el **SLE** al acortar el tiempo de contención y evita decisiones improvisadas. |
| 4 | **Backups en un disco en la oficina** | **Protect — PR.DS-11** (backups creados, protegidos, mantenidos y probados); **Recover — RC.RP-03** (se verifica la integridad de los backups antes de restaurar); **PR.IR-02** (activos protegidos de amenazas ambientales) | Regla 3-2-1: copia fuera del sitio e inmutable, cifrada, con pruebas de restauración periódicas | **Mitigar** (ransomware) + **Transferir** (desastre físico, ver B.3) | El mismo disco sufre incendio, robo y ransomware. Se mitiga con ingeniería lo que es frecuente y se transfiere por seguro el residuo catastrófico de baja frecuencia. |
| 5 | **Servidor web público** sin hardening ni monitoreo | **Protect — PR.PS-02** (software mantenido/parcheado), **PR.PS-06** (desarrollo seguro), **PR.PS-04** (se generan logs); **Detect — DE.CM-01** (monitoreo de redes) y **DE.CM-09** (monitoreo de hardware y software) | Parcheo, consultas parametrizadas, WAF, segmentar la base de datos, logs centralizados con alertas | **Mitigar** | Es la superficie más expuesta a internet y conecta con la base de clientes; el ALE de $36.000/año justifica invertir. |
| 6 | **Datos de clientes con DNI y tarjetas** almacenados | **Identify — ID.AM-07** (inventario de datos); **Protect — PR.DS-01** (confidencialidad e integridad de datos en reposo) | Inventariar los datos; **no almacenar datos de tarjeta**: delegar el cobro en una pasarela de pagos (tokenización); cifrar el resto | **Evitar** (tarjetas) / **Mitigar** (DNI) | La mejor forma de no perder datos de tarjetas es no tenerlos: se elimina el riesgo en vez de gestionarlo. El DNI sí es necesario para el negocio, así que se protege. |

*Cobertura de funciones:* Govern (fila 2), Identify (3 y 6), Protect (1, 2, 4, 5, 6),
Detect (5), Respond (3), Recover (4). Todas las funciones del marco quedan
representadas.

---

## 2. Parte B — Riesgo cuantitativo

### B.1 — Ranking por ALE

Comando: `python src/riesgo.py priorizar --archivo riesgos.json`

| # | ALE (USD/año) | SLE | ARO | Riesgo |
|--:|--:|--:|--:|---|
| 1 | 60.000 | 120.000 | 0,50 | Filtración de datos por acceso remoto sin MFA |
| 2 | 36.000 | 90.000 | 0,40 | Explotación del servidor web público (SQLi) |
| 3 | 24.000 | 80.000 | 0,30 | Ransomware que cifra servidores y backups |
| 4 | 21.000 | 30.000 | 0,70 | Cuentas comprometidas por contraseñas débiles |
| 5 | 20.000 | 40.000 | 0,50 | Falta de plan de respuesta (sobrecosto del incidente) |
| 6 | 3.000 | 150.000 | 0,02 | Pérdida física de la oficina con el backup adentro |
| | **164.000** | | | **ALE total anual** |

*Nota metodológica:* PhantomCorp es ficticia, así que los SLE y ARO son
**estimaciones de modelado** razonadas (por ejemplo, un ARO de 0,5 equivale a un
evento cada dos años), no mediciones. Lo que se evalúa es el método: con otros
valores el ranking puede cambiar, pero el procedimiento de decisión es el mismo.

**¿Coincide con la intuición? ¿Dónde no?**

- **Coincide** en el primer lugar: el acceso remoto sin MFA es el vector más
  frecuente y da acceso directo a los datos de clientes.
- **No coincide** en dos puntos:
  1. El **ransomware** suele "dar más miedo" y quedó tercero. Su SLE es alto,
     pero su ARO (0,30) es menor que el de los ataques a credenciales o al sitio
     web.
  2. La **pérdida física** tiene el SLE más grande de todos (150.000) y sin
     embargo es la última: un evento catastrófico pero raro pesa poco *anualizado*.
- Los riesgos #4 y #5 tienen un ALE casi igual (~20.000) pero distinta
  naturaleza: el #4 se reduce bajando la **frecuencia** (ARO) y el #5 bajando el
  **impacto** (SLE). El ranking dice *cuánto* pesa cada riesgo, no *cómo* tratarlo.
- **Límite del método:** el ALE promedia. Un riesgo con ARO bajo puede ser
  inaceptable igual si su SLE supera lo que la empresa puede absorber (riesgo de
  continuidad del negocio), por eso el #6 no se ignora: se transfiere (B.3).
- **Plan de acción que surge del ranking:** (1) MFA + política de contraseñas
  (cubre #1 y #4), (2) hardening y monitoreo del servidor web (#2), (3) backups
  fuera de sitio e inmutables (#3), (4) plan de IR (#5), (5) seguro (#6).

### B.2 — Control para el riesgo #1

- **Riesgo #1:** filtración por acceso remoto sin MFA. ALE actual: **60.000**
  (SLE 120.000 × ARO 0,50).
- **Control propuesto:** MFA (TOTP) en VPN y cuentas privilegiadas, política de
  contraseñas con gestor corporativo y capacitación anti-phishing (PR.AA-03,
  PR.AA-01, PR.AT-01).
- **Costo anual estimado:** **9.000** (licencias del gestor de contraseñas,
  soporte y capacitación, más la amortización de la implementación inicial).
- **ALE resultante:** el SLE no cambia (si hay filtración, el daño sigue siendo
  120.000), pero el ARO baja de 0,50 a 0,10 → ALE = 120.000 × 0,10 = **12.000**.

```bash
python src/riesgo.py roi --antes 60000 --despues 12000 --costo 9000
# -> 4.333
```

**ROI = (60.000 − 12.000 − 9.000) / 9.000 = 4,33 (433 %).**
**Sí conviene:** el control evita 48.000 de pérdida esperada por año y cuesta
9.000, con un beneficio neto de 39.000/año. Además la decisión es **robusta**:
aunque el control fuera solo la mitad de efectivo (ARO 0,30 → ALE 36.000), el ROI
sería (24.000 − 9.000) / 9.000 = 1,67, todavía positivo.

### B.3 — Un riesgo para transferir (no mitigar)

**Riesgo:** pérdida física de la oficina (incendio / inundación / robo) con el
disco de backup adentro. SLE 150.000, ARO 0,02 (un evento cada 50 años),
ALE **3.000**.

- **Mitigar con controles propios es mala inversión.** Un control físico
  completo (sala ignífuga, detección y supresión, vigilancia; relacionado con
  PR.IR-02) costaría unos 10.000/año y bajaría el ALE a 500:

  ```bash
  python src/riesgo.py roi --antes 3000 --despues 500 --costo 10000
  # -> -0.750   (se gastan 10.000 para evitar 2.500)
  ```

- **Transferir sí conviene.** Una póliza que cubra el daño patrimonial por
  ~1.500/año deja como pérdida residual esperada solo el deducible (~500):

  ```bash
  python src/riesgo.py roi --antes 3000 --despues 500 --costo 1500
  # -> 0.667
  ```

- **Por qué es la respuesta correcta:** es un evento raro, de gran impacto y cuyo
  costo financiero se puede trasladar a un tercero. Transferir no elimina el
  riesgo (queda el deducible y la interrupción del negocio), pero es el
  tratamiento más barato. Se complementa con la fila 4 de A.3: la copia
  **fuera del sitio** evita perder los *datos* aunque se pierda el edificio, algo
  que el seguro no devuelve.
- **¿Por qué no aceptar?** Aceptar sería razonable si el SLE fuera tolerable para
  la empresa. Con 150.000 de pérdida potencial sobre una organización chica, no
  lo es, aunque el ALE anualizado sea bajo.

---

## 3. Anexo — `riesgos.json`

Archivo `riesgos.json` en este mismo directorio (6 riesgos con `nombre`, `sle` y
`aro`). Se procesa con:

```bash
python src/riesgo.py priorizar --archivo riesgos.json
```
