# Laboratorio 04 
Seguridad Informática · Unidad 4 · UTN Facultad Regional Villa María · 2026

**Grupo:** 10

| Integrante | Legajo | GitHub |
|---|---:|---|
| Belén Rocío Ramello | 15226 | [@belramello](https://github.com/belramello) |
| Carolina Paula Corazza | 15239 | [@carocor1](https://github.com/carocor1) |
| Chiara Agustina Kordek | 14719 | [@chiarakordek](https://github.com/chiarakordek) |
| Juan Pablo Saby | 15026 | [@JuanSaby](https://github.com/JuanSaby) |

## 0. Declaración de uso de IA

Se consultó **opencode** para aclarar dudas y recibir apoyo puntual en la
redacción y organización de algunos apartados del informe y la mini-research.
El grupo ejecutó los comandos del enunciado, comparó los resultados obtenidos
(ALE=20000.00, ROI=0.875 y el ranking de `priorizar`) y revisó el contenido.

## 1. Parte A — Marco aplicado

### A.1 — Marco elegido

Para esta parte se eligio el **NIST Cybersecurity Framework (CSF)**. El principal
motivo fue que PhantomCorp arrancó de bastante cero: sin MFA, sin política de
contraseñas, sin plan de incidentes. Cuando una empresa está en ese punto, el
problema no es conseguir una certificación, es poner orden, y las 5 funciones
del CSF (Identify, Protect, Detect, Respond, Recover) nos permitieron encarar
eso de manera directa. Además es un marco gratuito y de uso público, y al ser de
*resultados* y no de pasos obligatorios, no obliga a una estructura pesada como
la que pide un SGSI. Si más adelante PhantomCorp crece y le exigen certificarse,
se puede migrar a ISO 27001 con todo este trabajo ya encaminado.

### A.2 — Mapeo de debilidades a funciones/controles

Se repasó el escenario y se identificaron cinco debilidades. La falta de MFA y la falta de política de contraseñas se agrupan en una sola, la autenticación débil, porque ambas corresponden a la misma categoría del marco (PR.AC, gestión de identidades, autenticación y control de acceso) y se resuelven en conjunto. Los identificadores corresponden a las subcategorías del NIST CSF 1.1 [1].

| # | Debilidad del escenario | Función/control del marco |
|---|---|---|
| 1 | Autenticación débil: no hay MFA ni política de contraseñas | Protect — PR.AC-1 (gestión de identidades y credenciales) y PR.AC-7 (autenticación acorde al riesgo, por ejemplo multifactor) |
| 2 | No hay plan de respuesta a incidentes | Protect — PR.IP-9 (planes de respuesta y recuperación vigentes y gestionados); Respond — RS.RP-1 (ejecución del plan de respuesta) |
| 3 | Backups en un solo disco de la oficina | Protect — PR.IP-4 (copias de seguridad realizadas, mantenidas y probadas); Recover — RC.RP-1 (ejecución del plan de recuperación) |
| 4 | Acceso remoto de empleados sin controles | Protect — PR.AC-3 (gestión del acceso remoto) |
| 5 | Servidor web público con datos de tarjetas | Protect — PR.DS-1 (protección de los datos almacenados) |

La mayoría cayó en Protect, que es lo esperable: el problema de fondo de PhantomCorp es que no protege nada de lo que tiene.

### A.3 — Respuesta al riesgo

Acá se trató de no caer en "mitigar todo", porque no siempre es lo correcto ni lo más barato. Quedamos así:

| # | Debilidad | Respuesta | Justificación |
|---|---|---|---|
| 1 | Autenticación débil (sin MFA ni política de contraseñas) | **Mitigar** | El MFA es barato y corta los accesos con credenciales robadas, porque la contraseña sola deja de alcanzar. Se complementa con una política alineada con NIST: contraseñas de al menos 15 caracteres cuando son el único factor (8 si se usan con MFA), comparación contra una lista de contraseñas comunes o comprometidas y cambio obligatorio solo ante evidencia de compromiso, no de forma periódica [2]. El costo es bajo frente al riesgo que evita. |
| 2 | Sin plan de respuesta a incidentes | **Mitigar** | Sin plan, un incidente chico se te escala mal: nadie sabe a quién avisar ni cómo contener. Un procedimiento documentado y probado con un simulacro es poco costo frente a las horas de caída que te ahorra. |
| 3 | Backup en un solo disco | **Mitigar** | Un único disco en la oficina desaparece con un incendio, un robo o una falla. Con la regla 3-2-1 (una copia fuera del sitio) y probando que la restauración funciona, el riesgo de perder todo baja un montón. |
| 4 | Acceso remoto sin controles | **Aceptar** | Son 2 o 3 empleados remotos, con equipo corporativo y una VPN básica: el impacto de una comprometida es bajo. Lo dejamos como riesgo aceptado y documentado, revisado cada año. Si el teletrabajo crece, pasa a mitigar. |
| 5 | Web pública con datos de tarjetas | **Transferir** | Si se fuga un lote de tarjetas, la responsabilidad legal y el resarcimiento son billetes que una pyme no absorbe sola. Por eso lo transferimos con un seguro de ciberriesgo que cubra multas e indemnizaciones. |

#### Fuentes de la Parte A

- **[1] [PRIMARIA]** National Institute of Standards and Technology. (2018, 16 de abril). *Framework for Improving Critical Infrastructure Cybersecurity, Version 1.1*. https://doi.org/10.6028/NIST.CSWP.04162018 — Funciones y subcategorías PR.AC-1, PR.AC-3, PR.AC-7, PR.DS-1, PR.IP-4, PR.IP-9, RS.RP-1 y RC.RP-1.
- **[2] [PRIMARIA]** National Institute of Standards and Technology. (2025). *Digital Identity Guidelines: Authentication and Authenticator Management* (NIST SP 800-63B-4, §3.1.1.2). https://pages.nist.gov/800-63-4/sp800-63b.html — Longitud mínima de contraseñas, comparación contra listas de contraseñas comprometidas y prohibición de exigir cambios periódicos.

## 2. Parte B — Riesgo cuantitativo

### B.1 — Ranking por ALE

| # | Riesgo | ALE |
|---|---|---|
| 1 | Fuga de datos de tarjetas | $50 000 |
| 2 | Acceso no autorizado por falta de MFA | $40 000 |
| 3 | Interrupción del sitio web (ransomware/DDoS) | $40 000 |
| 4 | Pérdida total del backup | $30 000 |
| 5 | Credencial comprometida de empleado remoto | $9 000 |

El puesto 1 nos confirmó lo que intuíamos: la fuga de tarjetas es lo más caro
porque arrastra multas y problemas legales, no solo la pérdida directa. Donde la
intuición no nos alcanzaba fue en el empate de $40 000 entre el acceso no
autorizado y la interrupción: son riesgos de naturaleza distinta con el mismo
peso. El acceso no autorizado es menos frecuente pero pega fuerte; la
interrupción es más común pero cada evento duele menos. Si no lo hubiéramos
medido, probablemente hubiéramos priorizado el más "ruidoso" y no el más caro.

> **Nota sobre los números.** El escenario no trae valores, así que los
> estimamos con criterio realista. *SLE* es lo que se pierde por evento, *ARO*
> cuántas veces al año pasa, *ALE* = SLE × ARO. Para la fuga de tarjetas se
> estimaron ~50.000 registros × $10 + multas y abogados → SLE $500.000, con
> ARO 0,1 (1 vez cada 10 años). El acceso no autorizado (SLE $80.000, ARO 0,5)
> asume un robo de credenciales cada 2 años; la interrupción (SLE $20.000,
> ARO 2) asume 2 ataques por año de impacto moderado; la pérdida del backup
> (SLE $150.000, ARO 0,2) un incendio/robo cada 5 años; y la credencial remota
> (SLE $30.000, ARO 0,3) el caso más acotado. Son valores supuestos: el lab
> evalúa el método aplicado y que sean creíbles, no un número exacto.

### B.2 — ROI del control sobre el riesgo #1

Para la fuga de tarjetas propusimos "cifrado de datos en tránsito y en reposo +
WAF en el servidor web + tokenización del número de tarjeta" (no guardar el PAN
aunque el sistema se caiga).

- ALE antes: $50 000
- ALE después (estimado): $10 000
- Costo anual (licencias, auditoría, mantenimiento): $15 000
- ROI = (50 000 − 10 000 − 15 000) / 15 000 = **1,67**

El control se paga casi 1,7 veces por año, así que la decisión fue clara:
**conviene hacerlo**.

#### Reproducción del cálculo con `src/riesgo.py`

Los siguientes comandos se ejecutaron desde `entregas/lab04/grupo10/`.
Primero se comprobó el ALE anterior con el SLE de $500 000 y el ARO de 0,1
registrados para el riesgo #1 en `riesgos.json`:

```console
$ python src/riesgo.py ale --sle 500000 --aro 0.1
50000.00
```

Después se calculó el ROI con los valores del control de esta sección:

```console
$ python src/riesgo.py roi --antes 50000 --despues 10000 --costo 15000
1.667
```

La salida real `1.667` es el redondeo a tres decimales de
`(50000 - 10000 - 15000) / 15000 = 1,666…`; coincide con el **1,67**
redondeado a dos decimales que se presentó arriba. No se modificaron los
cálculos ni los parámetros. El ALE posterior de $10 000 y el costo anual de
$15 000 siguen siendo estimaciones: ejecutar el programa comprueba la
aritmética, no valida esos supuestos.

**Diferencia con el ejemplo del README:** allí se usa
`ale --sle 50000 --aro 0.4`, que devuelve `20000.00`, y
`roi --antes 20000 --despues 5000 --costo 8000`, que devuelve `0.875`.
También se ejecutaron esos comandos para contrastarlos. Son un ejemplo de uso
distinto, no los parámetros ni el ROI del control elegido en B.2.

### B.3 — Un riesgo a aceptar o transferir (no mitigar)

Se eligio la credencial comprometida de un empleado con acceso remoto (ALE
$9 000). Con tan pocos empleados remotos, equipo corporativo y VPN, mitigarlo
en serio (enclaves por usuario, monitoreo 24/7) costaría más plata que la
pérdida que evita. Lo dejamos documentado como riesgo **aceptado** y con
revisión anual: si el teletrabajo escala, el ALE sube y se revisa la decisión.

Igual, la Parte A y la B se pueden combinar como doble opción: el riesgo de las
tarjetas (A.3, #5) también se puede **transferir** con un seguro de ciberriesgo,
pagando una prima fija para que la aseguradora absorba la pérdida puntual.

## 3. Anexo — riesgos.json

```json
[
  {"nombre": "Fuga de datos de tarjetas por servidor web público sin protección", "sle": 500000, "aro": 0.1},
  {"nombre": "Acceso no autorizado por falta de MFA", "sle": 80000, "aro": 0.5},
  {"nombre": "Interrupción del sitio web por ransomware o DDoS", "sle": 20000, "aro": 2.0},
  {"nombre": "Pérdida total de datos por backup único en la oficina", "sle": 150000, "aro": 0.2},
  {"nombre": "Credencial comprometida de un empleado con acceso remoto", "sle": 30000, "aro": 0.3}
]
```
