# Informe — Laboratorio 04 · Marcos normativos y gestión

**Grupo:** 14 · **Integrantes:** Fede Peron — @fedeeperon · Laureano Gomez Redondo — @Laureano-GR · Martín Cesano — @martincesano · Martín Gaido — @martingaidoo · Valentina Chiapero — @valechiapero

## 0. Declaración de uso de IA

- **Herramienta:** Claude (Anthropic), a través de Claude Code.
- **Para qué:** proponer la implementación de `ale`, `roi_control` y `priorizar`;
  armar un primer borrador del mapeo debilidad → subcategoría NIST CSF, de los
  valores de SLE/ARO de `riesgos.json` y del mini-research; revisar la redacción.
- **Qué partes:** `src/riesgo.py` (los tres TODO), `riesgos.json`, `research.md`
  y las secciones 1 y 2 de este informe.
- **Cómo lo verificamos:**
  - Corrimos `python3 src/verificar.py` (3 OK) y los ejemplos del enunciado
    (`ale` → 20000.00, `roi` → 0.875).
  - Cada ID de subcategoría citado (PR.AA-03, PR.DS-11, etc.) se buscó y se
    comparó con el texto oficial de NIST CSWP 29 (CSF 2.0), para no citar
    controles que no existen.
  - Las citas del research se compararon con NIST SP 800-30 Rev. 1, §2.3.2.
  - Los valores de SLE/ARO son estimaciones nuestras para un escenario ficticio.
    Discutimos los supuestos de cada uno (ver Parte B).

## 1. Parte A — Marco aplicado

### A.1 — Marco elegido: NIST Cybersecurity Framework 2.0

Elegimos **NIST CSF 2.0** (NIST CSWP 29, 2024) por tres razones:

1. **Está pensado para cualquier tamaño de organización y no es certificable.**
   PhantomCorp parece una pyme sin área de seguridad. Lo que necesita primero es
   un diagnóstico de brechas y un plan, no una auditoría de certificación como
   la de ISO/IEC 27001.
2. **Está organizado por resultados** (*outcomes*), en seis funciones: Govern,
   Identify, Protect, Detect, Respond y Recover. Las debilidades del escenario se
   reparten justo entre esas funciones. Así se ve de un vistazo que PhantomCorp
   casi no tiene nada en Respond ni en Recover.
3. **Incorpora la gestión de riesgo dentro del marco:** GV.RM-04 (opciones de
   respuesta al riesgo), GV.RM-06 (método estandarizado para calcular y
   priorizar) e ID.RA-06 (elegir y seguir respuestas). Eso conecta directo con la
   Parte B.

> Nota: el enunciado habla de "cinco funciones", que es el CSF 1.1. La versión
> 2.0 agregó **Govern (GV)** como sexta función. Usamos los IDs de la 2.0.

### A.2 — Cinco debilidades → funciones y subcategorías del marco

| # | Debilidad del escenario | Función | Subcategoría CSF 2.0 (texto oficial resumido) | Control concreto que proponemos |
|---|---|---|---|---|
| D1 | Empleados con acceso remoto **sin MFA** | Protect | **PR.AA-03**: usuarios, servicios y hardware están autenticados · **PR.IR-01**: redes y entornos protegidos de acceso lógico no autorizado | VPN con MFA obligatorio (app TOTP o llave FIDO2); cerrar todo acceso remoto directo (RDP/SSH expuestos) |
| D2 | **Sin política de contraseñas** | Govern + Protect | **GV.PO-01**: política de gestión de riesgos de ciberseguridad establecida, comunicada y aplicada · **PR.AA-01**: identidades y credenciales gestionadas por la organización | Política escrita (largo mínimo, no reutilizar, bloqueo ante filtradas), gestor de contraseñas corporativo, baja de cuentas al irse un empleado |
| D3 | **Sin plan de respuesta a incidentes** | Identify + Respond | **ID.IM-04**: planes de respuesta a incidentes establecidos, comunicados, mantenidos y mejorados · **RS.MA-01**: el plan se ejecuta en coordinación con terceros relevantes | Plan escrito con roles, contactos y pasos; ejercicio de mesa una vez por año; contrato de respuesta con un tercero |
| D4 | **Backups en un disco en la oficina** | Protect + Recover | **PR.DS-11**: backups creados, protegidos, mantenidos y probados · **RC.RP-03**: se verifica la integridad de los backups antes de restaurar | Esquema 3-2-1: copia fuera del sitio e inmutable (nube con versionado/bloqueo) y prueba de restauración trimestral |
| D5 | **Datos de clientes (nombres, DNI, tarjetas) en el servidor web público** | Identify + Protect | **ID.AM-07**: inventario de datos y metadatos para tipos de datos designados · **PR.DS-01**: confidencialidad, integridad y disponibilidad de los datos en reposo protegidas | Inventario de qué datos sensibles hay y dónde; no almacenar tarjetas (tokenizar con un procesador de pagos); cifrar los DNI en reposo y sacar la base del servidor expuesto |

### A.3 — Respuesta al riesgo para cada debilidad

La respuesta se elige por el costo del control frente a la pérdida que evita
(ID.RA-06 / GV.RM-04), no por reflejo. Por eso no todo es "mitigar":

| # | Respuesta | Justificación |
|---|---|---|
| D1 | **Mitigar** | El MFA es barato (pocos dólares por usuario al mes) y corta el vector de entrada más común del ransomware, el riesgo #2 de la Parte B (ALE USD 45.000). No hay forma razonable de evitarlo, porque el negocio necesita acceso remoto. Tampoco conviene transferirlo: el seguro igual exigiría MFA. |
| D2 | **Mitigar** | Una política y un gestor de contraseñas cuestan casi nada frente al ALE de USD 30.000 por toma de cuentas. Además, el MFA de D1 baja el impacto de una contraseña filtrada. |
| D3 | **Transferir** (en parte) + mitigar lo mínimo | Una pyme no puede sostener un equipo de respuesta propio. Contratamos un **ciberseguro que incluya un equipo de respuesta a incidentes**: así transferimos el costo financiero y conseguimos expertos. El contrato tiene que dejar los requisitos por escrito (GV.SC-05). Lo que no se transfiere es tener un plan propio (ID.IM-04) que diga a quién llamar en la primera hora: eso lo hacemos nosotros. |
| D4 | **Mitigar** | Una copia fuera del sitio cuesta poco y es lo que convierte un ransomware en "restauramos en un día" en vez de "perdimos todo". Aceptar este riesgo sería un error, aunque su ALE solo sea bajo (ver B.1). |
| D5 | **Evitar** (tarjetas) + mitigar (DNI) | La forma más segura de proteger números de tarjeta es **no guardarlos**: los pagos pasan por un procesador certificado PCI DSS y PhantomCorp solo guarda un token. Así eliminamos la actividad riesgosa, no solo la reducimos. Los nombres y DNI sí hacen falta para el negocio: esos se mitigan cifrándolos y sacándolos del servidor público. |

La cuarta respuesta posible, **aceptar**, la aplicamos a la caída del sitio web
(ver B.3), donde el control cuesta más que la pérdida que evita.

## 2. Parte B — Riesgo cuantitativo

Montos en USD por año. Supuestos de cada estimación:

| Riesgo | SLE | Por qué ese SLE | ARO | Por qué ese ARO |
|---|---:|---|---:|---|
| R1 Filtración de tarjetas y DNI | 300.000 | Forense, notificación a clientes, multas de las marcas de tarjeta por incumplir PCI DSS, reemisión de tarjetas, pérdida de clientes | 0,25 | Servidor público sin parchear ni monitorear: una vez cada 4 años |
| R2 Ransomware por acceso remoto sin MFA | 150.000 | Una a dos semanas sin operar, reconstrucción de equipos, posible extorsión | 0,30 | Acceso remoto con solo contraseña es la puerta más atacada: una vez cada ~3 años |
| R3 Toma de cuentas por contraseñas débiles | 25.000 | Fraude o abuso de una cuenta, limpieza y reseteo | 1,20 | Pasa seguido (phishing, reutilización): algo más de una vez por año |
| R4 Pérdida del disco de backups | 60.000 | Datos que no se pueden reconstruir y horas de recarga manual | 0,10 | Robo, incendio o falla en la oficina: una vez cada 10 años |
| R5 Caída o defacement del sitio | 8.000 | Ventas perdidas en uno o dos días y daño de imagen | 0,50 | Una vez cada 2 años |

### B.1 — Ranking por ALE

```text
$ python3 src/riesgo.py priorizar --archivo riesgos.json
      75000.00  Filtracion de datos de tarjetas y DNI por compromiso del servidor web publico
      45000.00  Ransomware que entra por el acceso remoto de empleados sin MFA
      30000.00  Toma de cuentas de empleados por contrasenas debiles o reutilizadas
       6000.00  Perdida del disco de backups de la oficina (robo, incendio o falla)
       4000.00  Caida o defacement del sitio web publico (DDoS o vandalismo)
```

**¿Coincide con la intuición?** En parte.

- **Coincide:** que la filtración de tarjetas quede primera. Es el activo más
  sensible y el más expuesto, y su impacto (PCI DSS más clientes) es enorme.
- **No coincide (1):** la toma de cuentas (R3) nos parecía un riesgo "menor", y
  queda casi pegada al ransomware. Cada evento cuesta poco, pero pasa seguido:
  un SLE bajo con un ARO alto suma mucho. Una matriz cualitativa la habría
  dejado en "medio" y la habríamos subestimado.
- **No coincide (2):** los backups (R4) intuitivamente eran críticos, y quedan
  anteúltimos con solo USD 6.000. Esto muestra un **límite del modelo**: el
  ALE trata cada riesgo como independiente, pero los backups no son solo un
  riesgo, son el control que reduce el SLE del ransomware (R2). Sin un backup
  fuera del sitio, el SLE de R2 sería bastante mayor. Por eso en A.3 decidimos
  mitigar D4 aunque su ALE propio sea bajo.
- **Sensibilidad:** si el ARO de R2 subiera de 0,30 a 0,50, el ransomware
  (75.000) empataría con R1. Los ARO son lo menos confiable del cálculo (ver
  research).

### B.2 — Control para el riesgo #1 y su ROI

**Riesgo #1:** filtración de tarjetas y DNI (ALE USD 75.000).

**Control propuesto** (la respuesta "evitar + mitigar" de D5):

| Componente | Costo anual estimado |
|---|---:|
| Procesador de pagos certificado PCI DSS con tokenización: PhantomCorp deja de guardar números de tarjeta | 12.000 (comisiones y cuota) |
| WAF administrado delante del servidor web | 6.000 |
| Parcheo mensual y escaneo de vulnerabilidades (PR.PS-02, ID.RA-01) | 8.000 |
| Cifrado de DNI en reposo y migración de la base a un servidor interno | 4.000 |
| **Total** | **30.000** |

**ALE después del control:**

- **SLE:** baja de 300.000 a 80.000. Sin tarjetas no hay multas PCI ni
  reemisión; quedan los costos por los DNI, que además están cifrados.
- **ARO:** baja de 0,25 a 0,15, por el WAF y el parcheo.
- **ALE después:** 80.000 × 0,15 = **USD 12.000**.

```text
$ python3 src/riesgo.py roi --antes 75000 --despues 12000 --costo 30000
1.100
```

**ROI = (75.000 − 12.000 − 30.000) / 30.000 = 1,10.** Cada dólar invertido evita
USD 2,10 de pérdida esperada, o sea que recupera el dólar y deja USD 1,10 de
ganancia. **Conviene.** Además, tiene margen: aunque el SLE residual fuera
120.000 (ALE 18.000), el ROI seguiría siendo positivo (0,90).

### B.3 — Un riesgo para aceptar: caída o defacement del sitio (R5)

- **ALE actual:** 8.000 × 0,5 = USD 4.000.
- **Control evaluado:** un servicio anti-DDoS/CDN premium a USD 6.000 por año,
  que bajaría el ARO a 0,125 (ALE después: USD 1.000).

```text
$ python3 src/riesgo.py roi --antes 4000 --despues 1000 --costo 6000
-0.500
```

**ROI = −0,50:** el control cuesta USD 6.000 para evitar USD 3.000 de pérdida
esperada. **No conviene mitigar.** La respuesta correcta es **aceptar** el
riesgo, con tres condiciones:

1. Dejarlo **documentado** como riesgo aceptado, dentro de la tolerancia definida
   por la dirección (GV.RM-02) y en el registro de riesgos (ID.RA-06).
2. Hacer lo gratuito: usar el plan básico del CDN y un monitor de disponibilidad
   que avise si el sitio se cae.
3. Revisarlo si cambia el negocio. Si el sitio empieza a concentrar ventas, sube
   el SLE y la cuenta puede dar distinto.

Un caso aparte es el **riesgo residual del ransomware (R2)**: aun con MFA y
backups queda un remanente. Ese remanente se **transfiere** con el ciberseguro
de D3, porque un evento poco frecuente pero caro es justo lo que cubre un seguro.

### Bitácora

```bash
cd entregas/lab04/grupo14
python3 src/verificar.py                                   # 3 OK
python3 src/riesgo.py ale --sle 50000 --aro 0.4            # 20000.00
python3 src/riesgo.py roi --antes 20000 --despues 5000 --costo 8000   # 0.875
python3 src/riesgo.py priorizar --archivo riesgos.json     # ranking B.1
python3 src/riesgo.py roi --antes 75000 --despues 12000 --costo 30000 # 1.100 (B.2)
python3 src/riesgo.py roi --antes 4000 --despues 1000 --costo 6000    # -0.500 (B.3)
```

## 3. Anexo — tu riesgos.json

```json
[
  {"nombre": "Filtracion de datos de tarjetas y DNI por compromiso del servidor web publico", "sle": 300000, "aro": 0.25},
  {"nombre": "Ransomware que entra por el acceso remoto de empleados sin MFA", "sle": 150000, "aro": 0.3},
  {"nombre": "Toma de cuentas de empleados por contrasenas debiles o reutilizadas", "sle": 25000, "aro": 1.2},
  {"nombre": "Perdida del disco de backups de la oficina (robo, incendio o falla)", "sle": 60000, "aro": 0.1},
  {"nombre": "Caida o defacement del sitio web publico (DDoS o vandalismo)", "sle": 8000, "aro": 0.5}
]
```
