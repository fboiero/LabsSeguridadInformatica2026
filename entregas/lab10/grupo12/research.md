# Mini-research — Laboratorio 10 · Detección y Evasión

**Grupo:** 12  
**Autor:** Mateo Gerbaudo (@gerbaudo19)  
**Fecha:** 30 de Octubre de 2026

---

**Tema elegido:**
- [x] **A.** IDS/IPS por firmas vs por anomalía (Snort/Suricata): fortalezas y límites.
- [ ] **B.** Técnicas de evasión de WAF (ofuscación, encoding, case, comentarios).
- [ ] **C.** SIEM y correlación de logs: cómo se detecta lo que ninguna firma ve.
- [ ] **D.** MITRE ATT&CK: la táctica Defense Evasion y sus técnicas.

---

## 1. Introducción y Marco Teórico

La protección perimetral e interna de las redes modernas depende en gran medida de sistemas de detección y prevención de intrusiones (**IDS/IPS**, *Intrusion Detection and Prevention Systems*). Dos de las implementaciones de código abierto más consolidadas y adoptadas a nivel de industria son **Snort** (desarrollado por Sourcefire/Cisco) y **Suricata** (mantenido por la *Open Information Security Foundation* - OISF).

A nivel conceptual, los motores de inspección profunda de paquetes (*Deep Packet Inspection* - DPI) operan bajo dos filosofías analíticas diametralmente opuestas:
1. **Detección basada en Firmas / Conocimiento (*Signature-based / Misuse Detection*):** Modela el comportamiento malicioso conocido mediante reglas determinísticas predefinidas.
2. **Detección basada en Anomalías / Comportamiento (*Anomaly-based / Behavioral Detection*):** Modela el comportamiento benigno esperado (*baseline*) y alerta ante cualquier desviación estadística o heurística de dicho patrón.

El presente trabajo analiza la arquitectura técnica de ambas aproximaciones en Snort y Suricata, sus mecanismos de operación, sus fortalezas relativas y sus límites intrínsecos, prestando especial atención al dilema operativo entre sensibilidad, especificidad y la fatiga de alertas (*Alert Fatigue*) en los centros de operaciones de seguridad (SOC).

---

## 2. Desarrollo Técnico

### 2.1 Detección basada en Firmas: Snort y Suricata

Los motores basados en firmas descomponen los paquetes de red (Capa 3 a Capa 7) y evalúan su contenido contra una base de reglas (*Ruleset*) estructurada en formato de tuplas condicionales.

#### Estructura y sintaxis de una regla Snort/Suricata
Una firma típica consta de un encabezado (*Rule Header*) que define la acción, protocolo, direcciones IP y puertos, seguido de un conjunto de opciones (*Rule Options*):

```text
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"ET WEB_SPECIFIC_APPS PhantomCorp SQLi UNION SELECT Attempt";
    flow:established,to_server;
    content:"UNION",nocase;
    http_uri;
    content:"SELECT",nocase,distance:0;
    http_uri;
    pcre:"/union(?:\/\*.*?\*\/|\s)+select/Ui";
    reference:cve,2024-XXXX;
    classtype:web-application-attack;
    sid:2098001;
    rev:1;
)
```

#### Mecanismos de procesamiento y preprocesadores
Para evitar que variaciones superficiales del protocolo evadan las firmas, tanto Snort 3 como Suricata incorporan una cadena de **preprocesadores y analizadores de flujo (*Stream Reassembly & Protocol Decoders*)**:
- **Reensamblado TCP y desfragmentación IP:** Previene evasiones basadas en fragmentación de paquetes (ataques tipo *Fragroute* o *Ptacek-Newsham* de 1998) reconstruyendo el flujo de bytes antes de evaluarlo.
- **Normalización HTTP (*HTTP Preprocessor / LibHTP*):** Transforma la carga útil decodificando entidades URL (`%20` $\rightarrow$ espacio), caracteres Unicode de doble byte y secuencias de escape de directorio (`/admin/../` $\rightarrow$ `/`) antes de contrastar los contenidos.

#### Fortalezas de la detección por firmas:
- **Cero ambigüedad ante amenazas conocidas:** Si un payload coincide con una firma estricta (ej. un exploit público conocido con shellcode invariante o un CVE documentado), la detección es instantánea y con tasa de falsos positivos virtualmente nula.
- **Bajo costo computacional:** La búsqueda de cadenas múltiples (*Aho-Corasick* o *Hyperscan* de Intel) permite inspeccionar millones de paquetes por segundo en hardware estándar sin incurrir en latencias prohibitivas.
- **Trazabilidad y reproducibilidad forense:** Cada alerta generada se asocia unívocamente a un identificador de firma (`SID`), permitiendo al analista del SOC conocer con exactitud qué vulnerabilidad o vector se disparó.

#### Límites intrínsecos de las firmas:
- **Cero protección contra amenazas desconocidas (*Zero-Days*):** Si no existe una regla escrita con anterioridad, el ataque atraviesa el sensor sin generar la menor sospecha.
- **Fragilidad ante el polimorfismo y la ofuscación:** Como se demostró experimentalmente en el Laboratorio 10, basta alterar un carácter o sustituir un espacio por un comentario inline (`/**/`) para que una expresión regular ingenua falle en dispararse.
- **Sobrecarga de mantenimiento:** Mantener actualizados rulesets masivos (como *Emerging Threats Pro* o *Talos Community Rules*) requiere suscripciones activas y un esfuerzo continuo de actualización y sintonización (*tuning*).

---

### 2.2 Detección basada en Anomalías y Comportamiento

La detección por anomalía no busca el "patrón del virus", sino que define qué es lo normal en la red y dispara eventos cuando el tráfico observado se aleja de esa norma.

#### Técnicas operativas en IDS/IPS modernos:
1. **Anomalías de Protocolo / RFC Conformance:** El IDS valida que los paquetes respeten estrictamente las especificaciones RFC (ej. longitudes de cabecera HTTP estándar, valores válidos en los flags TCP, tamaños de ventana coherentes). Herramientas como Suricata implementan parsers basados en Rust que descartan tráfico malformado que suele ser precursor de escaneos o ataques de denegación de servicio.
2. **Líneas Base Estadísticas (*Statistical Baselines & Thresholds*):** Se monitorean métricas continuas por host o por segmento de red: volumen de paquetes por segundo, tasa de respuestas SYN/ACK, proporción de peticiones `POST` vs `GET`, y tasa de errores `4xx`/`5xx`.
3. **Modelos Heurísticos y Machine Learning (UEBA):** Algoritmos no supervisados (agrupamiento K-Means, modelos de aislamiento *Isolation Forests* o redes neuronales recurrentes) que aprenden los horarios habituales de trabajo, transferencias de datos típicas y secuencias lógicas de interacción de los usuarios.

#### Fortalezas de la detección por anomalías:
- **Capacidad de detectar ataques novedosos y Zero-Days:** Una intrusión nunca antes vista generará patrones anómalos (como un volumen inusual de datos exfiltrados por DNS o un pico de conexiones salientes hacia IPs no catalogadas) sin requerir firma previa.
- **Independencia del payload exacto:** No depende de que el atacante use un string específico, lo que neutraliza técnicas básicas de ofuscación de código o cifrado de payloads.

#### Límites críticos de la detección por anomalías:
- **Tasa elevada de Falsos Positivos:** Cualquier cambio legítimo en la operatoria del negocio (un despliegue de software, una campaña masiva de marketing, una migración de base de datos) altera la línea base y dispara oleadas de alertas falsas.
- **Vulnerabilidad al aprendizaje adversario (*Creeping / Poisoning Attacks*):** Si el atacante introduce su actividad maliciosa de forma extremadamente gradual y prolongada (*low-and-slow*), el motor de anomalías incorpora el comportamiento hostil como parte de la "nueva normalidad".
- **Dificultad de interpretación para el analista:** Una alerta del tipo *"Desviación estadística del 18% en entropía de flujo UDP"* no le indica al analista qué ataque está ocurriendo ni qué mitigar de inmediato, requiriendo un triaje humano considerablemente más complejo.

---

### 2.3 Matriz Comparativa: Firmas vs. Anomalía

| Criterio | IDS basado en Firmas (Snort / Suricata tradicional) | IDS basado en Anomalías / Comportamiento (Suricata Flow Engine / Zeek) |
|---|---|---|
| **Eficacia ante ataques conocidos** | Máxima (100% de efectividad con reglas actualizadas) | Media-Alta (depende de la distorsión que cause el ataque) |
| **Eficacia ante Zero-Days / Evasiones** | Muy baja / Nula | Alta (detecta síntomas y desviaciones comportamentales) |
| **Tasa de Falsos Positivos** | Extremadamente baja (si la regla está bien calibrada) | Moderada a Muy Alta (sensible a fluctuaciones legítimas) |
| **Costo Computacional / Rendimiento** | Bajo a Medio (optimizado por motores de regex como Hyperscan) | Alto (requiere cálculo de estados, estadísticas y ventanas de tiempo) |
| **Resistencia a Evasión Sintáctica** | Pobre (sensible a ofuscación, encoding y sintaxis polimórfica) | Fuerte (ignora la sintaxis cruda y evalúa el impacto/patrón global) |
| **Explicabilidad de la Alerta** | Inmediata (específica el CVE, regla y payload detectado) | Opaca (requiere correlación manual de telemetría secundaria) |

---

### 2.4 El dilema operativo: Sensibilidad, Especificidad y "Alert Fatigue"

En teoría de la detección de señales, la efectividad de un sistema defensivo se describe a través de la matriz de confusión:

```text
                           REALIDAD DEL TRÁFICO
                    Ataque Real           Tráfico Benigno
                ┌─────────────────────┬─────────────────────┐
  Alerta IDS    │ Verdadero Positivo  │   Falso Positivo    │
                │       (VP)          │        (FP)         │
                ├─────────────────────┼─────────────────────┤
  Sin Alerta    │   Falso Negativo    │ Verdadero Negativo  │
                │   (FN / Evasión)    │       (VN)          │
                └─────────────────────┴─────────────────────┘
```

Donde:
- **Sensibilidad (*Recall / True Positive Rate*):** $\frac{VP}{VP + FN}$. Representa la capacidad del sistema de no dejar pasar ningún ataque.
- **Especificidad (*True Negative Rate*):** $\frac{VN}{VN + FP}$. Representa la capacidad del sistema de no molestar a los analistas con tráfico benigno.

El trade-off es inexorable:
1. Si aumentamos la **sensibilidad** para evitar cualquier falso negativo (evasión), relajando las reglas o reduciendo los umbrales de alerta, la tasa de **falsos positivos (FP)** se dispara exponencialmente.
2. Un volumen excesivo de falsos positivos conduce directamente al colapso operativo del SOC por **fatiga de alertas (*Alert Fatigue*)**: los analistas humanos, abrumados por miles de notificaciones irrelevantes por turno, comienzan a ignorar alertas, a cerrarlas sin investigación o a desactivar reglas críticas.
3. El resultado paradójico es que un sistema hiper-sensible termina siendo **más inseguro**, ya que la intrusión real (el Verdadero Positivo) queda sepultada en el ruido masivo de alertas benignas —exactamente el escenario modelado en el Reto R5 del Laboratorio 10—.

---

## 3. Fuentes Consultadas

1. **Roesch, M. (1999).** *Snort - Lightweight Intrusion Detection for Networks.* Proceedings of the 13th USENIX Conference on System Administration (LISA '99), pp. 229–238.  
   *Referencia fundacional sobre la arquitectura modular de detección por firmas en tiempo real e inspección de paquetes.*  
   Disponible en: https://www.usenix.org/legacy/event/lisa99/full_papers/roesch/roesch.pdf

2. **Open Information Security Foundation (OISF). (2024).** *Suricata User Guide: Rule Management, Multi-Threading, and Advanced Protocol Inspection.* Documentación oficial de Suricata v7.x.  
   *Análisis técnico de preprocesadores HTTP (LibHTP), detección de anomalías de flujo y aceleración de reglas mediante motores multihilo y Rust.*  
   Disponible en: https://docs.suricata.io/en/latest/

3. **Cisco Talos Intelligence Group. (2023).** *Writing Effective Snort Rules: Performance Optimization and Evasion Prevention.* Talos Security Whitepapers.  
   *Guía técnica sobre diseño de firmas robustas, impacto computacional del uso de expresiones regulares PCRE y mitigación de evasiones por comentarios y encoding.*  
   Disponible en: https://talosintelligence.com/resources/documents

4. **Sommer, R., & Paxson, V. (2010).** *Outside the Closed World: On Using Machine Learning for Network Intrusion Detection.* 2010 IEEE Symposium on Security and Privacy (S&P), pp. 305–316. IEEE Computer Society.  
   *Artículo seminal sobre por qué la detección de intrusiones puramente basada en anomalías falla en entornos reales debido al costo asimétrico de los falsos positivos y la falta de una línea base estática.*  
   Disponible en: https://www.icir.org/robin/papers/oakland10-ml.pdf

---

## 4. Reflexión Crítica

La experiencia práctica del Laboratorio 10 desmitifica una de las creencias más extendidas en la gestión de seguridad: la idea de que adquirir e instalar un IDS o WAF de última generación resuelve por sí solo la seguridad perimetral.

Durante el desarrollo de los retos ofensivos comprobamos lo sencillo que resulta engañar a una regla estática: bastó reemplazar un espacio por un comentario SQL inline (`/**/`) para que una inyección `UNION SELECT` completamente funcional fuera aceptada con un `200 OK` benigno, o modificar un parámetro de cabecera (`User-Agent`) para desaparecer del radar de la firma `scanner-ua`. Esto confirma la tesis central de Sommer y Paxson: **las firmas operan sobre la sintaxis, mientras que la vulnerabilidad reside en la semántica del destino**.

Por otra parte, desde la perspectiva defensiva (Blue Team) en el análisis de logs del SOC (Reto R5), se puso en evidencia el peligro de la desconexión entre la detección y la respuesta: la intrusión externa a `/etc/passwd` estaba efectivamente registrada en el log, pero al tratarse de un IDS pasivo que solo emitía un registro dentro de cientos de líneas benignas, el servidor entregó el archivo sensible con un código 200 sin bloquear la conexión.

La principal conclusión técnica es que **no existe la regla perfecta ni la herramienta mágica**:
- Las firmas son indispensables como primer filtro higiénico para frenar el 95% del ruido y los escaneos masivos no calificados.
- Los modelos de anomalía y el análisis comportamental son necesarios para capturar desviaciones estructurales y movimientos laterales.
- Pero la verdadera seguridad radica en la **resiliencia de la arquitectura (defensa en profundidad)**: si la aplicación valida sus datos en el servidor mediante consultas parametrizadas (*Prepared Statements*) y restringe los permisos del sistema de archivos, el ataque fracasará aunque la firma del IDS no se dispare; y si el SOC cuenta con automatización (SOAR) y correlación de eventos en tiempo real, el incidente se contendrá antes de convertirse en una catástrofe pericial.
