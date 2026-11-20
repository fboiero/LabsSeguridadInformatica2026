# Informe — Laboratorio 02 · Criptografía

**Grupo:** 06 · **Integrantes:**

| Nombre y apellido  | Legajo | Usuario de GitHub |
| ------------------ | ------ | ----------------- |
| Martín Beccereca   | 15154  | @martinbeccereca  |
| María Belén Benito | 14625  | @belubenito603    |
| Alejo De Miguel    | 15138  | @AlejoDM          |
| Tomás Giudici      | 14977  | @TomasGiudici     |
| Carolina Suppo     | 15057  | @carosuppo        |

**Fecha:** 16/10/2026

## 0. Declaración de uso de IA

- **Google Antigravity (Gemini 3.7 Flash):** se utilizó para estructurar
  inicialmente el informe en Markdown. Su uso se limitó a la organización del
  documento; no se le atribuye la verificación de afirmaciones técnicas o
  históricas.

- **Claude Code:** se utilizó como apoyo para redactar y organizar el
  mini-research sobre derivación de claves desde contraseñas. Las fuentes
  incluidas fueron revisadas y se corrigieron las afirmaciones que no contaban
  con respaldo suficiente.

- **Codex:** se utilizó para revisar el formato Markdown, ordenar la
  bibliografía, comprobar la correspondencia entre citas y fuentes, y revisar
  la coherencia técnica de las explicaciones y de la bitácora.

## 1. Parte A — Análisis de la falla

**Caso:** Adobe 2013: almacenamiento reversible de contraseñas, pistas en texto claro y cifrado determinista.

### A.1 — Qué protegía el sistema

Adobe ID administraba credenciales de cuentas de clientes. Por lo tanto, las
contraseñas y los datos asociados debían preservarse de modo que una persona sin
autorización no pudiera recuperar ni reutilizar las credenciales.

En su comunicado del 3 de octubre de 2013, Adobe informó que atacantes habían
accedido a IDs de clientes y contraseñas cifradas. También comunicó la extracción
de datos de pedidos de aproximadamente 2,9 millones de clientes, incluidos
nombres, números de tarjetas de crédito o débito cifrados y fechas de vencimiento
[1].

Una investigación posterior de la Office of the Privacy Commissioner of Canada
registró que la información accedida incluía nombres de usuario, contraseñas
cifradas, pistas de contraseña en texto claro, nombres, direcciones, correos
electrónicos y números de tarjetas cifrados [2, párr. 11].

### A.2 — Mal uso criptográfico

El problema relevante para las contraseñas no fue una ruptura criptanalítica
demostrada de 3DES, sino el diseño de almacenamiento:

- Se usó un mecanismo reversible para contraseñas, cuando un sistema de
  autenticación normalmente necesita verificar una contraseña, no recuperarla.
- Las pistas de contraseña se guardaron en texto claro. La autoridad canadiense
  observó que algunas podían contener la contraseña o una indicación muy directa
  de ella [2, párr. 17].
- Contraseñas idénticas producían el mismo resultado cifrado. Esto permitió
  agrupar cuentas con la misma contraseña y relacionar algunas de ellas con las
  pistas expuestas [2, párr. 17]. Un informe contemporáneo de CERT-FR describió
  el esquema como cifrado reversible, presumiblemente 3DES, y señaló ECB y la
  ausencia de salt [3, sección 4].

No se afirma aquí que se haya comprobado una clave global única, porque las
fuentes consultadas no lo demuestran.

### A.3 — Propiedad afectada y explotación

La propiedad afectada fue principalmente la **confidencialidad** de las
credenciales. La filtración permitió a terceros obtener contraseñas cifradas,
pistas en texto claro y otros datos de cuenta. La combinación de pistas y
criptogramas repetidos redujo la dificultad de identificar contraseñas frecuentes
o evidentes.

El riesgo posterior era el acceso no autorizado a cuentas cuya contraseña pudiera
inferirse y, si la misma contraseña se reutilizaba en otros servicios, el riesgo
de reutilización de credenciales. Las fuentes consultadas permiten afirmar ese
riesgo; no permiten afirmar, sin evidencia adicional, que se haya accedido a
todas las cuentas afectadas.

---

### A.4 — Medida correcta

Las contraseñas deben almacenarse mediante una función de hashing adaptativa y
lenta para contraseñas, con un salt único por contraseña; no mediante cifrado
reversible. OWASP recomienda Argon2id cuando está disponible y, según el
contexto, alternativas como scrypt, bcrypt o PBKDF2 [4, “Password Hashing
Algorithms”].

---

## 2. Parte B.1 — Romper el XOR

Para el archivo de reto, la clave recuperada es `0x37` y el texto claro es:

> Memo interno PhantomCorp: la clave del wifi de invitados es
> Phantom-Guest-2026. No compartir fuera de la empresa.

Una clave de un byte tiene 8 bits, por lo que existen:

`2^8 = 256` claves posibles.

El programa prueba esas 256 posibilidades y asigna mayor puntaje a los resultados
con letras y espacios. En este archivo, ese criterio selecciona el texto claro
correcto. El problema no es la operación XOR por sí sola: es reutilizar una clave
de solo un byte, lo que deja un espacio de búsqueda exhaustiva muy pequeño.

---

## 3. Parte B.2 — Autenticación

### B.2.1 — Length-extension

La construcción `SHA-256(clave || mensaje)` no es una MAC adecuada. SHA-256
procesa el mensaje por bloques y aplica padding al finalizar. Si una persona
atacante conoce un mensaje y el digest correspondiente, puede tratar el digest
como estado intermedio y calcular un valor para:

`mensaje || padding || contenido_agregado`

sin conocer la clave, siempre que conozca o estime correctamente la longitud de
la clave para reconstruir el padding. No puede modificar arbitrariamente el
mensaje original: el ataque permite extenderlo al final.

Por ejemplo, un sistema que autenticara
`usuario=123&accion=consultar` podría ser vulnerable si interpreta como válida
la extensión `&admin=true`.

### B.2.2 — Cómo lo resuelve HMAC

HMAC usa dos aplicaciones de la función hash:

`H((K0 ⊕ opad) || H((K0 ⊕ ipad) || mensaje))`

donde `K0` es la clave ajustada al tamaño de bloque, e `ipad` y `opad` son
constantes diferentes. La construcción estándar está definida en RFC 2104,
sección 2 [5].

El digest externo no permite calcular un HMAC de un mensaje extendido sin volver
a aplicar la capa externa con la clave secreta. Por eso, HMAC-SHA-256 no hereda
el ataque de extensión de longitud de la concatenación ingenua.

### B.2.3 — Comparación en tiempo constante

`hmac.compare_digest()` está diseñada para evitar comparaciones con cortocircuito
dependientes del contenido; Python recomienda usarla al comparar un digest
recibido externamente para reducir el riesgo de ataques de temporización [6].

Por ejemplo, si una comparación ordinaria detiene su recorrido ante el primer
carácter distinto, respuestas ligeramente más lentas para prefijos correctos
podrían ayudar a inferir un MAC carácter por carácter. La comparación constante
reduce esa señal.

La reducción no es absoluta: Python advierte que una diferencia de tipo o
longitud puede filtrar esos metadatos. En este programa se comparan dos cadenas
hexadecimales de HMAC-SHA-256, por lo que ambas deben tener 64 caracteres.

## 4. Bitácora

Comandos y salidas obtenidos en una terminal Bash con Python 3:

```bash
$ python3 src/cripto.py xor --texto hola --clave K
2324272a

$ python3 src/cripto.py romper --hex $(cat data/muestra/reto_xor.hex)
clave=0x37
Memo interno PhantomCorp: la clave del wifi de invitados es Phantom-Guest-2026. No compartir fuera de la empresa.

$ python3 src/cripto.py mac --clave secreta --msg "pago 100" --modo ingenuo
a8cc54c07b3acb7470c25ab9eea5234bfa2562e37298eee275e39a457004b725

$ python3 src/cripto.py mac --clave secreta --msg "pago 100" --modo hmac
5ec4a52407221836a66e8d654d914aaa4b18bd31cf31907348bcd292677b902e
```

---

## 5. Fuentes consultadas

1. Arkin, Brad. “Important Customer Security Announcement.” Adobe,
   3 de octubre de 2013.  
   https://blog.adobe.com/en/publish/2013/10/03/important-customer-security-announcement

2. Office of the Privacy Commissioner of Canada. “PIPEDA Report of Findings
   #2014-015: After a Significant Adobe Data Breach…”, 2014, párrs. 10–17 y
   31–36.  
   https://www.priv.gc.ca/en/opc-actions-and-decisions/investigations/investigations-into-businesses/2014/pipeda-2014-015/

3. CERT-FR. “Compromission d’Adobe et fuite de mots de passe”, sección 4, 2013.  
   https://www.cert.ssi.gouv.fr/actualite/CERTA-2013-ACT-046

4. OWASP Foundation. “Password Storage Cheat Sheet”, secciones “Background” y
   “Password Hashing Algorithms”. Consultado el 16/10/2026.  
   https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

5. Krawczyk, H.; Bellare, M.; Canetti, R. “HMAC: Keyed-Hashing for Message
   Authentication.” RFC 2104, febrero de 1997, sección 2.
   DOI: 10.17487/RFC2104.  
   https://www.rfc-editor.org/rfc/rfc2104.html

6. Python Software Foundation. “hmac — Keyed-Hashing for Message
   Authentication”, apartado `hmac.compare_digest`.  
   https://docs.python.org/3/library/hmac.html
