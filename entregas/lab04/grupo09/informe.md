# Lab 04 — Marcos normativos y riesgo cuantitativo

**Escenario:** PhantomCorp guarda datos de clientes (nombres, DNI, tarjetas). Tiene un
servidor web público, empleados con acceso remoto, y backups en un disco en la oficina.
No tiene MFA, ni política de contraseñas, ni plan de respuesta a incidentes.

---

## Parte A — Aplicar un marco

### A.1 — Marco elegido y por qué

Elijo **NIST Cybersecurity Framework (CSF)**.

Razones:

- PhantomCorp es una organización chica, sin un área de seguridad formal ni certificaciones
  previas. NIST CSF es más liviano para arrancar que ISO 27001: no exige un SGSI formal
  (políticas documentadas, comité de riesgo, auditorías de certificación) para ser útil,
  simplemente da un lenguaje común y una checklist de funciones.
- Las cinco funciones del framework (**Identify, Protect, Detect, Respond, Recover**)
  mapean de forma casi 1 a 1 contra las debilidades que se describen en el enunciado
  (control de acceso, monitoreo, respuesta a incidentes, backups), lo que hace mucho más
  directa la priorización de qué atacar primero.
- ISO 27001 sería la opción correcta si PhantomCorp necesitara demostrarle *cumplimiento*
  a un tercero (por ejemplo, para un contrato B2B que exige certificación). Como acá el
  objetivo es diagnosticar y priorizar remediaciones internas rápido, NIST CSF encaja mejor.

### A.2 y A.3 — Mapeo de debilidades a funciones del framework y respuesta al riesgo

| # | Debilidad del escenario | Función NIST CSF | Categoría (ejemplo) | Respuesta al riesgo | Justificación |
|---|---|---|---|---|---|
| 1 | Servidor web público expone datos de clientes (nombres, DNI, **tarjetas**) sin que se mencione clasificación de datos ni reducción del alcance de lo que se guarda | **Identify** | ID.AM (Asset Management) / ID.RA (Risk Assessment) | **Evitar** | La forma más barata y efectiva de bajar este riesgo no es "protegerlo mejor", es dejar de tener el activo peligroso: no almacenar el número de tarjeta completo, tercerizar el cobro a una pasarela de pago (Mercado Pago, Stripe, etc.) certificada PCI-DSS. Si no se guarda el dato, no hay riesgo de fuga de ese dato. Es la única debilidad de la tabla donde "evitar" (eliminar la actividad riesgosa) es más razonable que invertir en mitigarla. |
| 2 | No hay MFA ni política de contraseñas para empleados con acceso remoto ni para el servidor web | **Protect** | PR.AC (Identity Management, Authentication and Access Control) | **Mitigar** | Es un control barato (MFA vía apps gratuitas/SSO, política de contraseñas es solo configuración) frente al impacto de un acceso remoto comprometido a datos de tarjetas/DNI. Costo bajo, beneficio alto → mitigar es la respuesta obvia. |
| 3 | No hay ninguna capacidad de monitoreo/detección mencionada (nada de logs, alertas, ni visibilidad sobre accesos anómalos) | **Detect** | DE.CM (Security Continuous Monitoring) | **Mitigar** | Sin detección, un incidente puede pasar semanas sin descubrirse, multiplicando el daño (más registros exfiltrados, más tiempo del atacante adentro). Herramientas básicas de logging/alertas son de costo moderado y mejoran mucho el tiempo de detección. |
| 4 | No hay plan de respuesta a incidentes | **Respond** | RS.RP (Response Planning) | **Mitigar** | Un plan de respuesta (roles, contactos, pasos de contención, comunicación a clientes/autoridad de protección de datos) cuesta principalmente tiempo de armarlo y ensayarlo, no dinero. Reduce directamente el tiempo y el caos operativo durante un incidente real, así que mitigar es claramente conveniente. |
| 5 | Backups en un único disco físico en la misma oficina (sin copia offsite, sin cifrado mencionado, sin prueba de restauración) | **Recover** | RC.RP (Recovery Planning) | **Mitigar** | Un solo disco en el mismo edificio no protege contra incendio, robo o ransomware que cifre también el backup. Pasar a una regla 3-2-1 (una copia offsite/cloud, cifrada, con restauración probada periódicamente) es de costo bajo/medio comparado con el riesgo de pérdida total de datos de clientes. |

---

## Parte B — Cuantificar y priorizar

### `riesgos.json` usado

```json
[
  {"nombre": "Compromiso de cuentas por falta de MFA (acceso remoto)", "sle": 40000, "aro": 2},
  {"nombre": "Filtracion de datos de tarjetas por vulnerabilidad en servidor web", "sle": 250000, "aro": 0.3},
  {"nombre": "Perdida de backups por incendio o robo (disco unico en oficina)", "sle": 100000, "aro": 0.2},
  {"nombre": "Corte de conectividad a internet (ISP)", "sle": 6000, "aro": 5}
]
```

Salida de `python3 src/riesgo.py priorizar --archivo riesgos.json`:

```
  80000.00  Compromiso de cuentas por falta de MFA (acceso remoto)
  75000.00  Filtracion de datos de tarjetas por vulnerabilidad en servidor web
  30000.00  Corte de conectividad a internet (ISP)
  20000.00  Perdida de backups por incendio o robo (disco unico en oficina)
```

### B.1 — Ranking por ALE. ¿Coincide con la intuición?

En parte sí y en parte no.

- **Coincide:** la filtración de datos de tarjetas queda arriba, como esperaría cualquiera
  dado que PhantomCorp guarda datos de tarjetas y DNI: es el escenario "titular de noticia"
  (fuga de datos, multas, daño reputacional).
- **No coincide:** el compromiso de cuentas por falta de MFA queda **primero**, superando
  incluso a la filtración de tarjetas, a pesar de tener un SLE mucho más chico (40.000 vs
  250.000). La intuición tiende a anclarse en el evento más "grave" en términos absolutos
  (fuga masiva de tarjetas), pero como la falta de MFA hace que los intentos de
  comprometer una cuenta sean *frecuentes* (ARO=2, dos veces por año es realista sin MFA),
  el costo *esperado por año* termina siendo mayor. El ALE corrige ese sesgo: no importa
  solo "qué tan grave sería si pasa", sino "qué tan seguido va a pasar".
- Otro punto no intuitivo: la pérdida de backups queda **última**, pese a que "perder todos
  los backups" suena catastrófico. Al tener ARO bajo (0.2, un evento cada 5 años
  aproximadamente), su ALE es menor que el corte de conectividad del ISP, que es mucho
  menos dramático pero mucho más frecuente (ARO=5).

### B.2 — Riesgo #1: control propuesto, costo, ALE resultante y ROI

**Riesgo #1:** Compromiso de cuentas por falta de MFA (ALE actual = 80.000).

**Control propuesto:** Implementar MFA obligatorio (app autenticadora) para todo acceso
remoto y para cuentas de administración del servidor web, junto con bloqueo de cuentas
tras intentos fallidos.

- SLE se mantiene en 40.000 (si igual se compromete una cuenta con MFA bypaseado por
  ingeniería social, el impacto por evento no cambia demasiado).
- ARO baja de 2 a 0.3 (MFA no elimina el riesgo, pero hace mucho más difícil el acceso
  no autorizado con solo una contraseña robada).
- ALE después del control = 40.000 × 0.3 = **12.000**.
- Costo anual estimado del control (licencias de MFA + soporte/config inicial
  prorrateado): **10.000**.

```
python3 src/riesgo.py roi --antes 80000 --despues 12000 --costo 10000
# -> 5.800
```

**ROI = 5.8** (580%). Con un ROI muy por encima de 0, el control se paga muchas veces
sobre su costo: **conviene claramente implementarlo**. Incluso si las estimaciones de
costo o de ARO residual fueran pesimistas por un margen amplio, seguiría siendo positivo.

### B.3 — Un riesgo para aceptar o transferir (no mitigar)

**Riesgo:** Corte de conectividad a internet (ISP) — ALE = 30.000.

Por qué no conviene mitigar: el único control real para bajar este riesgo de forma
significativa sería contratar un segundo enlace de internet con otro proveedor
(redundancia), lo cual suele costar en el orden de varios miles de dólares/pesos por mes
solo en el segundo enlace, más el equipamiento (router/failover). Eso fácilmente supera
o iguala el ALE actual de 30.000/año, dando un ROI cercano a cero o negativo.

En cambio, tiene más sentido:

- **Aceptar** el riesgo si el negocio puede tolerar cortes ocasionales (por ejemplo, si el
  servidor web no es el único canal de venta, o los cortes duran poco), documentando la
  decisión y revisándola si la frecuencia empeora.
- **Transferir** parcialmente el riesgo negociando un SLA con penalidad económica con el
  propio ISP, o contratando un seguro de continuidad de negocio que cubra pérdidas por
  caída de conectividad.

En ningún caso conviene gastar en mitigar activamente (redundancia propia) cuando el
costo del control supera la pérdida anual esperada que se busca evitar.
