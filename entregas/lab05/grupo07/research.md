# Mini-research — Laboratorio 05

**Grupo:** 07 · **Autor:** Fernando Cagliero — @Ferca19

- [x] **Tema elegido: modo debug de Werkzeug expuesto**, a partir del servicio
  de desarrollo del puerto 8080 de PhantomCorp.

## Desarrollo

En la evidencia capturada por Guadalupe, el 8080 anuncia
`Server: Werkzeug/2.0.1 Python/3.9.2` y su `/status` informa
`version: 0.9.3-DEV`, `debug: true`. La primera versión identifica el servidor;
la segunda corresponde a la aplicación. Esta combinación permite fundamentar
un hallazgo de exposición de un servicio presentado como desarrollo, sin
inventar un CVE para PhantomCorp.

**Qué hace peligroso al depurador.** La documentación de la versión **2.0.1**
de Werkzeug describe un middleware que muestra la traza de una excepción y,
opcionalmente, una consola interactiva. Con `evalex` habilitado, permite
ejecutar Python en el contexto de los marcos de esa traza y examinar variables.
Si un atacante accede a esa funcionalidad, podría utilizar los permisos y
recursos del proceso de la aplicación; no implica automáticamente privilegios
de administrador. El PIN agrega una barrera, pero el propio proveedor advierte
que no asegura completamente el depurador y prohíbe su uso en producción. [1]

**Qué demuestra nuestro recon.** La transcripción confirma metadatos expuestos
y un estado declarado de debug. No contiene una traza interactiva, una consola
abierta ni ejecución de comandos. Por lo tanto, el riesgo de ejecución remota
es **condicional** a que el depurador interactivo esté realmente habilitado y
alcanzable. Un campo JSON llamado `debug` no demuestra por sí solo esas
condiciones. Tampoco un banner demuestra que una instalación sea explotable:
hay que comprobar configuración, componentes y alcance de cada vulnerabilidad.

**Por qué importa sin CVE.** MITRE describe **CWE-489, Active Debug Code**, como
la entrega de un producto con código de depuración activo. Puede introducir
entradas imprevistas y exponer información sensible; el impacto depende del
caso. CWE identifica un tipo de debilidad, no un CVE particular ni un puntaje
CVSS. Lo usamos como marco conceptual, sin afirmar que el contenido de
`/status` pruebe todas las capacidades del depurador. [3]

**Cómo reducir la exposición.** La guía de Flask indica usar un servidor WSGI
de producción en lugar del servidor de desarrollo, su depurador y su recargador;
la advertencia también vale para despliegues privados. [2] Para PhantomCorp
proponemos retirar la instancia DEV accesible por 8080, desactivar debug y
restringir el endpoint de estado a lo necesario. La comprobación posterior
debería confirmar que esa instancia ya no es alcanzable desde la red del
atacante, mientras la aplicación legítima sigue funcionando. Ocultar el banner
sería complementario: no deshabilita una función peligrosa que siga disponible.

## Fuentes

1. Pallets. [Werkzeug 2.0.1 — Debugging Applications](https://github.com/pallets/werkzeug/blob/2.0.1/docs/debug.rst).
   Documentación de la versión anunciada: consola, `evalex` y límites del PIN.
2. Pallets. [Flask — Deploying to Production](https://flask.palletsprojects.com/en/stable/deploying/).
   Diferencia entre desarrollo y despliegue mediante un servidor WSGI.
3. MITRE. [CWE-489 — Active Debug Code](https://cwe.mitre.org/data/definitions/489.html).
   Definición, consecuencias y eliminación del código de depuración al desplegar.

## Reflexión (3–5 líneas)

El hallazgo útil relaciona evidencia, condiciones e impacto, no solo una versión.
En este lab podemos sostener la exposición de metadatos y el debug declarado.
La ejecución remota queda como riesgo potencial que exigiría otra comprobación.
Como defensor retiraría la instancia DEV antes de limitarme a ocultar sus headers.

**Uso de IA:** Fernando utilizó OpenAI Codex para localizar y contrastar las
tres fuentes, organizar el análisis y asistir en la redacción. Se cotejaron las
afirmaciones con la transcripción del informe y con la documentación original,
incluida la versión 2.0.1. La revisión es documental; no se repitió el recon
ni se probó la explotación del depurador.
