# Mini-research — Laboratorio 11

**Tema elegido:** B

- [ ] **A.** Volatility 3: cómo se captura un volcado de RAM (LiME, avml) y qué
  plugins se usan para procesos, red y credenciales.
- [x] **B.** Orden de volatilidad (RFC 3227) y por qué define el orden de captura.
- [ ] **C.** Cadena de custodia: requisitos legales y por qué una evidencia mal
  manejada se cae en un juicio.
- [ ] **D.** IOCs y su ciclo de vida: cómo se comparten (STIX/TAXII, MISP) y cómo
  se usan para detectar el mismo ataque en otros sistemas.

## Desarrollo

### Qué es el orden de volatilidad

La RFC 3227 (BCP 55) es la guía de buenas prácticas de la IETF para recolectar y
archivar evidencia. Su idea central es simple: la evidencia no dura lo mismo en todos
lados, así que hay que empezar por la que se pierde primero. Como ejemplo para un
sistema típico, propone este orden, de más a menos volátil [1, sección 2.1]:

1. Registros y caché.
2. Tabla de ruteo, caché ARP, tabla de procesos, estadísticas del kernel y memoria.
3. Sistemas de archivos temporales.
4. Disco.
5. Logging remoto y datos de monitoreo relevantes para el sistema.
6. Configuración física y topología de red.
7. Medios de archivo.

La lista es un ejemplo, no una receta cerrada: el criterio es la expectativa de vida
del dato. Por eso la misma RFC pide no apagar el equipo hasta terminar la recolección.
Además de perder lo volátil, el atacante pudo haber modificado los scripts de inicio o
de apagado para destruir evidencia [1, sección 2.2].

### Por qué define el orden de captura

Toda recolección cambia algo en el sistema. La NIST SP 800-86 lo dice sin vueltas: cada
acción sobre el equipo, sea de una persona o del propio sistema operativo, casi con
seguridad altera los datos volátiles [2, sección 5.2.1]. Copiar el disco primero, por
ejemplo, significa dejar corriendo el sistema mientras esos datos se van perdiendo.
Apagar para "analizar con calma" es peor, y hasta desconectar el equipo de la red puede
eliminar información importante [2, sección 5.2.1].

Esto genera una tensión real entre contener y preservar. Desconectar corta el daño, pero
puede destruir justo lo que explica el incidente. La recomendación de NIST es tener los
criterios definidos de antemano, para decidir rápido si se preservan los datos volátiles
[2, sección 5.2.1]. Tampoco hay que seguir la lista a ciegas: NIST propone priorizar
según la importancia del dato y su volatilidad relativa en cada situación
[2, sección 5.2.1].

Capturar en vivo tampoco es confiar en el sistema. La RFC pide no confiar en sus
programas y correr las herramientas desde un medio protegido [1, sección 2.2]. NIST agrega
una advertencia importante: en un sistema totalmente comprometido, un rootkit a nivel de
kernel puede devolver datos falsos incluso a herramientas forenses de usuario
[2, sección 5.2.1.1].

### Cómo se traduce a herramientas

En Linux, el volcado de RAM se hace con una herramienta aparte, porque Volatility 3 no
adquiere memoria. Su documentación da AVML como ejemplo [3]. Después, Volatility 3 analiza
la imagen con plugins como `linux.pslist` (procesos) y `linux.bash` (historial) [3]. Esta
separación también es una lección de método: primero se fija el dato volátil y recién
después se lo analiza, sobre una copia, con la tranquilidad que da el hash.

### Aplicación al caso PhantomCorp

El caso muestra el orden de volatilidad funcionando en contra del atacante:

- **Memoria (captura de las 02:30 UTC):** el `nc` hacia `45.13.37.7:4444` en estado
  ESTABLISHED y el historial con el comando de exfiltración. El atacante había corrido
  `history -c`, pero la evidencia sobrevivió en la RAM.
- **Temporales:** `/tmp/.p` y `/tmp/.exfil/clientes.tar.gz`, que podrían desaparecer con
  un reinicio o una limpieza. Quedaron registrados en el listado de disco.
- **Disco:** el webshell, el binario SUID, la tarea de `cron` y el usuario backdoor.
- **Logs locales:** `auth.log` falló la verificación de hash. La RFC ubica el logging
  remoto como otra fuente; en este caso, una copia remota permitiría comparar lo que el
  archivo local ya no muestra.

Si el primer respondedor hubiera apagado el servidor, se habría perdido la prueba de que el
canal al C2 seguía activo. Y eso cambia la respuesta: no es lo mismo investigar un
incidente terminado que uno con el atacante todavía conectado.

## Fuentes

1. D. Brezinski y T. Killalea, *Guidelines for Evidence Collection and Archiving*,
   RFC 3227 / BCP 55, IETF, febrero de 2002.
   <https://www.rfc-editor.org/rfc/rfc3227>
2. K. Kent, S. Chevalier, T. Grance y H. Dang, *Guide to Integrating Forensic Techniques
   into Incident Response*, NIST SP 800-86, agosto de 2006.
   <https://doi.org/10.6028/NIST.SP.800-86>
3. The Volatility Foundation, *Volatility 3 Documentation — Linux Tutorial*.
   <https://volatility3.readthedocs.io/en/latest/getting-started-linux-tutorial.html>

## Reflexión

Nuestra conclusión es que el orden de volatilidad no es una lista para memorizar, sino una
decisión bajo presión: cada minuto de contención o de análisis tiene un costo en evidencia.
Por eso conviene definir el procedimiento antes del incidente. Durante el ataque ya no hay
tiempo para discutirlo, y un error, como apagar el equipo por reflejo, no se puede deshacer.

También nos queda un límite claro: capturar en el orden correcto no garantiza que el dato sea
verdadero. Un sistema comprometido puede mentir, y un log local puede ser alterado. Por eso
la conclusión forense tiene que apoyarse en la correlación de fuentes independientes, y no
en un único artefacto.
