# Mini-research — Laboratorio 07

**Tema elegido:** A — Consultas parametrizadas / prepared statements

## Desarrollo

### El problema de fondo

Toda inyección SQL nace del mismo error: el servidor arma el texto de la
consulta **mezclando dos cosas que deberían estar separadas** — el código
SQL que escribió el programador, y el dato que escribió el usuario — en un
único string, y le pasa ese string completo al motor para que lo interprete
de punta a punta. El motor no tiene forma de distinguir "esto lo puso el
programador" de "esto lo mandó un usuario externo": para él, todo es
sintaxis SQL por igual. Si el dato del usuario contiene comillas, `--`,
`UNION`, o cualquier palabra clave de SQL, esos caracteres **se interpretan
como código**, no como texto literal.

### Cómo funciona una consulta parametrizada

Una consulta parametrizada rompe esa mezcla desde el diseño, en dos pasos
separados:

1. **Preparación (prepare):** el driver envía al motor la consulta con
   placeholders fijos (`?` en SQLite, `%s` en psycopg2/MySQL,
   `:nombre` en otros). El motor **compila esa estructura una sola vez** —
   sabe exactamente qué forma tiene la consulta, sin conocer todavía los
   valores reales.
2. **Ejecución (bind + execute):** recién en este paso se envían los
   valores, **por un canal separado** del protocolo de comunicación con la
   base de datos (no concatenados al texto SQL). El motor los sustituye en
   los placeholders tratándolos siempre como **datos literales de un tipo
   específico**, nunca como fragmentos de sintaxis a ejecutar.

```python
# Vulnerable (lo que tiene server.py en /login y /buscar):
sql = f"SELECT user, rol FROM users WHERE user='{user}' AND pass='{pw}'"
cursor.execute(sql)

# Parametrizado:
cursor.execute(
    "SELECT user, rol FROM users WHERE user=? AND pass=?",
    (user, pw)
)
```

Con la versión parametrizada, si `user` llega como `admin' --`, el motor no
ve ahí una comilla que cierra un string ni un comentario SQL: ve,
literalmente, el string de 11 caracteres `admin' --`, y busca un usuario
que se llame exactamente así. Como no existe, la consulta no devuelve nada
— el "ataque" simplemente no tiene efecto.

### Por qué es mejor que "escapar comillas"

Una defensa más primitiva (y frágil) es escapar manualmente los caracteres
peligrosos antes de concatenar — por ejemplo, reemplazar cada `'` por
`''`. El problema es que esta técnica depende de que el programador
**anticipe correctamente todos los caracteres y codificaciones
peligrosas** para el motor específico que está usando, y hay múltiples
formas históricas de evadir un escapado mal implementado (codificaciones
alternativas, caracteres multibyte, funciones del motor poco conocidas).
La parametrización no tiene ese problema porque **no depende de filtrar
nada**: el dato nunca llega a interpretarse como código, sea cual sea su
contenido exacto.

### Un matiz: parametrizar no cubre todo

Es importante notar que la parametrización protege los **valores** que van
en una consulta (lo que aparece después de `WHERE`, `VALUES`, etc.), pero
**no** protege elementos de la estructura misma de la query — por ejemplo,
nombres de tablas o columnas dinámicos, o la dirección de un `ORDER BY`
(`ASC`/`DESC`). Esos casos, si vienen de input de usuario, necesitan
validarse con listas blancas (whitelist) de valores permitidos, porque no
se pueden pasar como parámetro bindeado.

### Contraste directo con el lab

El propio `server.py` de PhantomCorp muestra las dos caras: `/login` y
`/buscar` concatenan el input a mano (vulnerables a R1 y R2), pero
`/perfil` sí usa parametrización correctamente:

```python
fila = DB.execute("SELECT id,user,rol,nota_privada FROM users WHERE id=?", (pid,)).fetchone()
```

Esto confirma algo importante: SQLite **soporta** parametrización sin
problema — el fallo de R1/R2 no es una limitación de la base de datos, es
una decisión de código puntual en esos dos endpoints. Basta con que un solo
endpoint de una aplicación grande quede mal escrito para abrir una
vulnerabilidad crítica, aunque el resto del sistema siga buenas prácticas.

### Por qué sigue siendo tan común en producción

A pesar de ser una corrección simple de aplicar, la inyección SQL se
mantiene año tras año en el top de OWASP. Algunas razones documentadas en
la industria:

- **Código legacy:** sistemas viejos escritos antes de que la
  parametrización fuera práctica estándar, que nunca se refactorizaron.
- **ORMs usados incorrectamente:** muchos frameworks modernos parametrizan
  automáticamente, pero exponen "escapes" para SQL crudo (`raw query`) que,
  si se usan con input de usuario sin cuidado, reintroducen el problema.
- **Presión de tiempo / deuda técnica:** es más rápido escribir un
  f-string que configurar bien la query parametrizada, sobre todo en
  prototipos que después terminan en producción sin revisión de seguridad.

## Fuentes (mín. 3, verificables)

1. OWASP Cheat Sheet Series — *SQL Injection Prevention Cheat Sheet*
   (sección sobre prepared statements / parameterized queries).
2. Documentación oficial de Python — módulo `sqlite3`, sección sobre uso de
   placeholders (`?`) en `execute()`.
3. OWASP Top 10 2021 — *A03:2021-Injection* (por qué la parametrización es
   la mitigación primaria recomendada para esta categoría).

## Reflexión (3–5 líneas)

Lo que más nos llamó la atención es la distancia entre lo simple que es la
corrección (cambiar un f-string por un placeholder) y lo grave del
impacto — un bypass de login completo con un payload de 11 caracteres.
Ver en el propio código del lab que `/perfil` sí estaba bien escrito y
`/login`/`/buscar` no, nos mostró que no alcanza con "saber la teoría": hay
que aplicarla de forma consistente en *cada* endpoint, porque un solo punto
débil compromete todo el sistema. Nos quedó claro por qué esta categoría
sigue en el top de OWASP: no es un problema de herramientas complejas, sino
de un hábito de codificación que hay que internalizar desde el día uno.