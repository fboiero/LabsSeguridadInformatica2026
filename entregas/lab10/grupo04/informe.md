# Informe — Laboratorio 10 · Detección y evasión

**Grupo:** 04 · **Asignatura:** Seguridad Informática 2026 · UTN FRVM.
Integrantes y legajos: [INTEGRANTES.md](INTEGRANTES.md).

**Resultado:** cinco retos resueltos y validados con el motor del curso.
Las pruebas se realizaron exclusivamente contra `phantomcorp` en la red Docker
`cyberlab_labnet`, sin publicar puertos ni atacar sistemas de terceros.

## 0. Declaración de uso de IA

Se utilizó OpenCode con el asistente GPT-6.1 Sol para interpretar la consigna,
ejecutar solicitudes al entorno local, validar flags, redactar este informe y el
mini-research, consultar fuentes y preparar una propuesta de firma con pruebas.
El texto y el código fueron generados con esa asistencia. La verificación técnica
consistió en contrastar respuestas HTTP reales, validar las flags mediante el
verificador oficial y ejecutar las pruebas de la propuesta. No se atribuyen estas
ejecuciones a integrantes individuales ni se inventan contribuciones Git.
La asistencia no sustituye la revisión y comprensión del trabajo por el grupo.

## 1. Flags capturadas y evidencia

| Reto | Flag obtenida | Evidencia |
|---|---|---|
| R1 | `FLAG{soc_log_access}` | [Acceso al SOC](evidencias/01-soc.txt) |
| R2 | `FLAG{detection_triggered}` | [Detección scanner-ua](evidencias/02-scanner.txt) |
| R3 | `FLAG{signature_ruleset}` | [Ruleset](evidencias/03-reglas.txt) |
| R4 | `FLAG{signature_evaded}` | [Evasión con comentarios](evidencias/05-comentarios.txt) |
| R5 | `FLAG{intrusion_in_the_noise}` | [Registro inicial](evidencias/01-soc.txt) |

Captura textual real de `./ctf status 10`:

```text
   ✓  R1     Acceso a la vista del SOC
   ✓  R2     Disparar una deteccion (te vieron)
   ✓  R3     Conocer el ruleset del IDS
   ✓  R4     Evadir una firma de deteccion
   ✓  R5     Encontrar la intrusion en el ruido

  ██████████████████████████████  5/5 (100%)

[ OK ] ¡Lab 10 COMPLETO! Ponete las pilas con la próxima unidad.
```

Salida completa: [09-status.txt](evidencias/09-status.txt).
Es una captura de salida de consola, no una fotografía de pantalla.

### Procedimiento reproducible

Desde la raíz del repositorio, con Docker Desktop iniciado:

```bash
docker compose -p cyberlab --project-directory . \
  -f entorno/docker-compose.yml \
  -f labs/lab10-deteccion-evasion/entorno/target.compose.yml up -d --build
docker exec cyberlab-attacker curl -sS -i http://phantomcorp/soc
docker exec cyberlab-attacker curl -sS -i -A sqlmap http://phantomcorp/
docker exec cyberlab-attacker curl -sS -i http://phantomcorp/soc/reglas
docker exec cyberlab-attacker curl -sS -i --get \
  --data-urlencode 'q=UNION/**/SELECT' http://phantomcorp/api
docker exec cyberlab-attacker sh -c 'curl -sS http://phantomcorp/soc | grep ALERT'
./ctf submit 10 R1 'FLAG{soc_log_access}'
./ctf submit 10 R2 'FLAG{detection_triggered}'
./ctf submit 10 R3 'FLAG{signature_ruleset}'
./ctf submit 10 R4 'FLAG{signature_evaded}'
./ctf submit 10 R5 'FLAG{intrusion_in_the_noise}'
./ctf status 10
```

Se usó Compose directamente como equivalente al Makefile porque esta terminal no
tenía `make` disponible. En Windows se invocó Docker mediante su ruta completa en
`C:\Program Files\Docker\Docker\resources\bin\docker.exe` y `ctf` con Bash.

### Interpretación de los resultados

- **R1:** `/soc` respondió HTTP 200 y mostró el registro de eventos y la flag.
- **R2:** la UA `sqlmap` produjo HTTP 403 y nombró la firma `scanner-ua`.
  Es detección con bloqueo: el servicio simula también una función de IPS/WAF.
- **R3:** se observaron `scanner-ua`, `path-traversal`, `git-probe` y `sqli-union`.
- **R4:** `UNION/**/SELECT` obtuvo HTTP 200 y la flag de evasión.
  Adicionalmente, `--data-urlencode 'q=UNION SELECT'` también pasó: el espacio
  viaja codificado y la firma inspecciona la query sin decodificar.
  No se afirma haber ejecutado SQL: el target reconoce cadenas y devuelve flags,
  pero no tiene un motor SQL que pruebe explotación o extracción de datos.
- **R5:** antes de provocar nuestra alerta ya figuraba:

  ```text
  185.220.101.42 - GET /admin/../../etc/passwd 200 ALERT[path-traversal]
  ```

  El registro está entre `item=73` e `item=74`, rodeado por 120 eventos benignos.
  La ruta intenta salir del directorio mediante `../` y alcanzar `/etc/passwd`.
  La IP y el recurso distinguen el evento del tráfico de catálogo, pero la IP
  por sí sola no atribuye identidad ni autoría. El 200 justifica priorizar la
  investigación; no demuestra que se haya entregado el archivo.

**Limitación del simulador:** el código del target genera `/soc` estáticamente
(`server.py`, función `_log_soc`) y no agrega las solicitudes de las pruebas.
Aunque R2 diga «logueada», no hay persistencia dinámica demostrada. R5 ya contiene
una alerta: aquí falla el seguimiento operativo, no la existencia de una firma.
Las evidencias inicial y final permiten comprobar esta limitación.

## 2. Tabla de firmas

| Firma | Cómo se evade | Cómo se mejora la detección |
|---|---|---|
| scanner-ua | Reemplazar la UA `sqlmap` por `Mozilla/5.0`: en la misma ruta cambia de 403 a 200. Esto evade la identificación por UA, no demuestra que un ataque completo pase otras firmas. | Correlacionar frecuencia, rutas, errores, parámetros, sesión y comportamiento. Usar la UA como señal de bajo peso, no como identidad ni autorización. Ajustar umbrales para no penalizar usuarios detrás de NAT. |
| sqli-union | Sustituir espacios por comentarios: `UNION/**/SELECT`. También pasan espacios codificados porque el IDS revisa la query cruda. | Parsear parámetros y decodificar con la misma semántica que la aplicación; reconocer separadores SQL y variantes de mayúsculas. Probar falsos positivos y negativos. Complementar con consultas parametrizadas y mínimos privilegios en la base. |

## 3. Preguntas P1–P5

### P1. ¿Por qué las firmas son evadibles? ¿Qué las complementa?

Una firma reconoce una representación o conjunto limitado de patrones, no toda
la intención ni la semántica de una operación. Si el backend y el detector
interpretan distinto el encoding o los separadores, dos cadenas diferentes pueden
tener un significado equivalente y solo una coincidir con la firma. También
quedan fuera técnicas nuevas y abusos de lógica de negocio. Las complementan
análisis de comportamiento, anomalías respecto de una línea base, correlación
entre fuentes, revisión humana y prevención en la aplicación. Ninguno es infalible:
deben medirse cobertura, falsos positivos y costo de respuesta.

### P2. Reescritura de la regla y límites

La regla original es `union\s+select`, insensible a mayúsculas: `\s+` incluye
espacios, tabulaciones y saltos, pero no comentarios SQL. Además, actúa sobre la
consulta sin decodificar. La propuesta es decodificar cada valor de parámetro una
vez y buscar:

```regex
(?is)\bunion(?:\s|/\*.*?\*/)+select\b
```

`i` permite variar mayúsculas y `s` permite comentarios multilínea. El separador
admite espacios o comentarios repetidos y `\b` limita coincidencias parciales.
La implementación local está en [verificar_firma.py](verificar_firma.py).
Las pruebas ejecutadas incluyen siete variantes positivas y cuatro controles
negativos: [resultado](evidencias/10-tests.txt), dos métodos de prueba, todos OK.

No es una firma perfecta ni un parche instalado. Una cadena de texto que cite
`UNION SELECT` puede disparar un falso positivo; una SQLi sin UNION queda fuera.
La decodificación debe coincidir con el backend, sin decodificar repetidamente
«hasta que no cambie». También deben limitarse tamaños y costo de evaluación
de expresiones regulares. En producción convienen análisis específico del
protocolo/dialecto, pruebas amplias y consultas parametrizadas como prevención.

### P3. ¿Por qué la User-Agent es una detección débil?

La declara el cliente y puede cambiarla libremente. Un atacante puede fingir un
navegador, y una herramienta legítima de auditoría puede anunciarse como scanner.
Miraría el contenido normalizado, acceso a recursos sensibles, secuencias de
rutas, tasas, errores, autenticación y autorización. Correlacionaría por cuenta,
sesión, origen y ventana temporal, sin confiar únicamente en IP o cabeceras.
Un ataque lento exige ventanas más amplias; no basta con detectar ráfagas.

### P4. ¿Cómo detectar automáticamente R5?

R5 ya está marcado `ALERT[path-traversal]`: falta convertir el registro en una
notificación asignada y atendida. Proponemos recolectar eventos del servidor y
WAF en un SIEM, normalizar campos y generar un caso de alta prioridad cuando se
observe traversal hacia un archivo sensible, elevando prioridad si hay HTTP 2xx.
Debe notificarse al SOC con responsable y plazo de atención, deduplicar sin
ocultar eventos y conservar evidencia. No se debería esperar un umbral de muchos
intentos para este acceso sensible. Se confirmaría impacto con logs de aplicación,
auditoría de archivos y contexto de respuesta; no solo con el estado HTTP.
Además hay que implementar logging dinámico real, restringir el SOC y alertar
si deja de llegar telemetría. Registrar no equivale a detectar y responder.

### P5. Relación entre ataque, agentes y defensa

El reconocimiento y la explotación (05–08) explican qué acciones dejan señales y
qué impacto podrían tener. Los agentes (09) pueden repetir pruebas, pero también
amplifican errores y ruido si no tienen alcance, límites y supervisión. La defensa
(10) muestra qué observa realmente el control y dónde tiene puntos ciegos.
Un atacante autorizado que entiende esas señales evalúa controles con evidencia,
no solo obtiene una flag. Un defensor que entiende el ataque puede construir
detecciones sobre su significado y validar su cobertura con pruebas controladas.
El ciclo útil es probar, observar, mejorar y volver a probar; siempre dentro de
la autorización y preservando trazabilidad. Esta relación conceptual no afirma
que se hayan ejecutado los labs 05–09 durante esta entrega.

## 4. Bitácora y verificación

| Orden | Acción ejecutada | Resultado |
|---|---|---|
| 1 | Iniciar los contenedores del Lab 10 | Atacante y PhantomCorp disponibles en la red del curso |
| 2 | Consultar SOC antes de las pruebas | 200, R1 y evento preexistente R5 |
| 3 | Solicitud con UA sqlmap | 403, firma scanner-ua, R2 |
| 4 | Consultar ruleset | 200, R3 y cuatro firmas |
| 5 | Enviar query con espacio codificado | 200, evasión por falta de normalización |
| 6 | Enviar query con comentario SQL | 200, R4 |
| 7 | Solicitud con UA de navegador y SOC final | 200; el SOC conserva el registro estático |
| 8 | Validar flags con ctf | Cinco retos aceptados, estado 5/5 |
| 9 | Ejecutar pruebas de la firma propuesta | Dos tests OK, once casos comprobados |
| 10 | Consultar fuentes primarias | OWASP, NIST y CISA para el research |

La propuesta y sus pruebas son locales: no se reemplazó el detector del target.
El límite de reversión de esta entrega son los archivos de `entregas/lab10/grupo04/`;
el progreso de flags se conserva aparte en `.progreso/10.done`, ignorado por Git.
Los cambios se guardan en la rama `lab10-grupo04`, sin alterar los enunciados.
Los commits técnicos no sustituyen las contribuciones propias de cada integrante. La participación individual
y el PR son tareas de proceso del grupo; no se simulan con identidades ajenas.

## Referencias

- [Consigna del Lab 10](../../../labs/lab10-deteccion-evasion/README.md).
- [Código del simulador](../../../labs/lab10-deteccion-evasion/entorno/phantomcorp/server.py),
  firmas y método `do_GET`; revisado para explicar resultados, no para obtener flags.
- Fuentes externas y reflexión: [research.md](research.md).
