# Mini-research — Laboratorio 06

**Grupo:** 06
**Tema elegido:** B. Wordlists de enumeración: qué son, cómo se eligen y por qué una mala wordlist hace fallar la enumeración.

## Desarrollo

Una wordlist es una lista de nombres candidatos (directorios, archivos, parámetros, usuarios) que una herramienta prueba uno por uno contra un servidor. Herramientas como `dirb` o `gobuster` hacen una solicitud por palabra y reportan las que reciben una respuesta distinta de `404`. OWASP describe esta técnica como adivinación a ciegas: pasar una lista de nombres comunes por un motor de solicitudes para descubrir archivos y directorios que la aplicación no enlaza [2].

La colección más usada es SecLists, un repositorio mantenido por Daniel Miessler, Jason Haddix, Ignacio Portal y g0tmi1k que reúne listas de usuarios, contraseñas, URLs, patrones de datos sensibles y payloads de fuzzing, entre otras [1]. Para descubrir contenido web hay listas generales y otras específicas de un producto o tecnología.

La elección importa porque la herramienta solo encuentra lo que está en la lista. En nuestro laboratorio, `dirb` con `common.txt` (4612 palabras) encontró `/admin` y `/backup`. `gobuster` con `big.txt` (20470 palabras) encontró exactamente las mismas dos rutas: cuadruplicar la lista no agregó nada. En cambio, ninguna de las dos encontró `/api/users` ni `/.git/config`, que sí existían. Ninguna de las dos reportó `/api`, y sin encontrar ese directorio no había desde dónde seguir hacia `/api/users`, que está un nivel más abajo. En el caso del `.git`, la pista vino de saber cómo se despliegan los sitios, no de la lista. Con el archivo default de R5 pasó lo mismo: los nombres genéricos en la raíz (`/readme.txt`, `/changelog`) devolvieron `404`, y tampoco lo encontraron las listas de productos conocidos que trae `dirb`. Apareció recién al armar una lista propia a partir del fingerprinting: 23 nombres default combinados con directorios con el nombre del producto. De 253 rutas, solo respondió `/phantomcms/VERSION`, y el directorio `/phantomcms/` en sí da `404`, así que ninguna enumeración de directorios lo habría descubierto.

Por eso una wordlist mala hace fallar la enumeración de dos formas. Si es demasiado chica o genérica, deja afuera rutas que existen y da una falsa sensación de que no hay nada más. Si es enorme y no tiene relación con el objetivo, multiplica las solicitudes (más tiempo, más ruido en los logs del defensor) sin mejorar el resultado, como mostró `big.txt`. Las herramientas profesionales combinan la lista con lo que observan en el sitio. Burp Suite, por ejemplo, además de sus listas propias, prueba en cada directorio nuevo los nombres que ya encontró en el sitio, deriva variantes de nombres descubiertos (si encuentra `AnnualReport2018`, prueba `AnnualReport2019`) y prueba otras extensiones de archivos existentes para encontrar copias de respaldo [3]. OWASP recomienda lo mismo: inferir nombres no publicados a partir de la convención de nombres del contenido visible [2].

También hay que interpretar bien las respuestas. Un `403`, como el de `/admin`, indica que la ruta existe aunque no se pueda leer. Un `200` confirma una respuesta, pero no siempre un recurso útil: algunos servidores responden `200` a cualquier ruta y obligan a filtrar por tamaño o contenido.

## Fuentes

1. Miessler, D., Haddix, J., Portal, I. y g0tmi1k. «[SecLists](https://github.com/danielmiessler/SecLists)». Repositorio en GitHub.
2. OWASP. «[WSTG-CONF-04: Review Old Backup and Unreferenced Files for Sensitive Information](https://owasp.github.io/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information)». *Web Security Testing Guide*.
3. PortSwigger. «[Content discovery](https://portswigger.net/burp/documentation/desktop/tools/engagement-tools/content-discovery)». Documentación de Burp Suite Professional.

Fuentes consultadas el 30/10/2026.

## Reflexión

Comparar `common.txt` con `big.txt` nos mostró que una lista más grande no encuentra más si no tiene los nombres correctos, y que varios hallazgos del laboratorio (`/.git/config`, `/api/users`, `/phantomcms/VERSION`) no salieron de una wordlist genérica. La lista sirve para cubrir lo obvio rápido; después hay que pensar, a partir de lo que se ve y del producto identificado, qué otras rutas tendrían sentido.
