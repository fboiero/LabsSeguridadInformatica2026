# Mini-research — Laboratorio 08

**Tema elegido:** **C.** Gestión de secretos: por qué los `.env` en el server son un problema y qué los reemplaza (vaults, variables de entorno efímeras, etc.).

## Desarrollo

### El problema concreto que vimos en el lab

En el R2 de este lab el loot salió solo: un `cat /var/www/.env` devolvió, en texto plano, el host de la base interna, el usuario `phantom_app` y la contraseña `Ph@ntom-DB-2024`. No hizo falta romper nada: el secreto estaba en un archivo legible (`chmod 644`) por cualquier usuario del sistema, incluido el `operador` sin privilegios en el que caímos. Ese `.env` fue lo que después nos habilitó el pivoting al host interno. Es el caso de manual de **almacenamiento de credenciales en texto claro** (CWE-312, *Cleartext Storage of Sensitive Information*) y, cuando el secreto queda escrito en el código o en un archivo versionado, de **credenciales embebidas** (CWE-798, *Use of Hard-coded Credentials*) [1].

### Por qué el `.env` en el server es un problema

El patrón del archivo `.env` nació de una buena idea: el principio del *Twelve-Factor App*, que dice que la configuración (y los secretos) debe estar **separada del código** y vivir en el entorno, no hardcodeada en los fuentes [2]. El problema no es la idea, es cómo degeneró en la práctica:

1. **Es un archivo plano en disco.** Cualquier proceso o usuario con permiso de lectura lo ve. En un host comprometido —exactamente nuestro escenario— es lo primero que un atacante lee. No hay cifrado, no hay control de acceso por secreto, no hay registro de quién lo leyó.
2. **Se filtra al control de versiones.** El error más común y más caro: alguien commitea el `.env` (o una API key hardcodeada) a git. Una vez que entró al historial, **borrarlo del árbol actual no lo saca**: sigue en los commits viejos, recuperable con `git log -p`. Los informes anuales de GitGuardian sobre *secrets sprawl* documentan millones de secretos filtrados cada año en repositorios públicos de GitHub por esta vía [3].
3. **No rota ni expira.** Una contraseña en un `.env` suele quedar fija durante años. Si se filtra, es válida hasta que un humano se acuerde de cambiarla a mano en todos lados. No hay caducidad automática.
4. **No deja rastro de uso.** Si alguien roba la credencial del `.env` y la usa, no hay forma de distinguir ese uso del legítimo: el secreto no está asociado a una identidad ni a una auditoría.

### Qué lo reemplaza

La defensa no es "esconder mejor el `.env`", sino cambiar el modelo: que el secreto **no viva en disco en claro** y que su acceso sea **controlado, auditado y temporal**. Las opciones, de menor a mayor madurez:

- **Gestores de secretos (vaults).** Un servicio central —HashiCorp Vault, AWS Secrets Manager, Azure Key Vault, Google Secret Manager— guarda los secretos cifrados y los entrega bajo demanda a identidades autenticadas, con política de acceso por secreto y auditoría de cada lectura [4]. La aplicación pide el secreto en tiempo de ejecución en vez de leerlo de un archivo.
- **Secretos dinámicos / de vida corta.** La capacidad más potente de un vault moderno: en lugar de una contraseña de base de datos fija, Vault genera credenciales **efímeras** y únicas por cliente, con un *lease* (tiempo de vida) corto, y las revoca automáticamente al vencer [4]. Si se filtran, sirven minutos, no años. Esto ataca de raíz los puntos 3 y 4 de arriba.
- **Inyección efímera en memoria.** En contenedores y Kubernetes, el secreto se monta en el proceso al arrancar (como variable de entorno o en un `tmpfs` en RAM), no en el filesystem persistente. El *OWASP Secrets Management Cheat Sheet* recomienda además no dejar el secreto accesible más allá del proceso que lo necesita, cifrar en reposo y en tránsito, y **rotar** periódicamente [5].
- **Barreras en el pipeline (defensa en profundidad).** Antes de que el secreto llegue a ningún lado: `.env`, claves y `*.key` en `.gitignore` desde el primer commit, y escaneo automático de secretos (Gitleaks, TruffleHog, git-secrets) como hook de pre-commit y en CI, que bloquea el push si detecta un patrón de token o contraseña [3], [5].

### Mitigación aplicada a nuestro caso

Si PhantomCorp hubiera consumido la credencial de la DB desde un vault con secretos dinámicos en vez de un `/var/www/.env`, el `cat` del R2 no habría devuelto nada útil: no habría contraseña en disco, y aunque la hubiera, sería efímera y estaría atada a una identidad auditada. El pivoting del R4 seguiría necesitando la ruta de red, pero ya no tendría la llave servida en bandeja.

## Fuentes (mín. 3, verificables)

1. MITRE — **CWE-798: Use of Hard-coded Credentials** y **CWE-312: Cleartext Storage of Sensitive Information**. https://cwe.mitre.org/data/definitions/798.html y https://cwe.mitre.org/data/definitions/312.html
2. **The Twelve-Factor App — III. Config** (configuración y secretos en el entorno, separados del código). https://12factor.net/config
3. **GitGuardian — State of Secrets Sprawl** (informe anual sobre secretos filtrados en GitHub público). https://www.gitguardian.com/state-of-secrets-sprawl-report-2024
4. **HashiCorp Vault — Documentation** (secretos estáticos vs. dinámicos, *leases* y revocación). https://developer.hashicorp.com/vault/docs
5. **OWASP — Secrets Management Cheat Sheet**. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Reflexión (3–5 líneas)

Lo que más nos quedó es que el `.env` del R2 no fue una falla "de hacking" sino una decisión de diseño: pusieron un secreto fijo, en claro, en un archivo que cualquiera en el host podía leer, y encima nos abrió el camino al pivoting. La solución no es esconderlo mejor, es que el secreto deje de existir en disco: un vault con credenciales de vida corta convierte un robo de contraseña de "válido para siempre" en "válido cinco minutos y auditado". Y la lección barata —`.gitignore` más un escáner de secretos en el pipeline— es la que evita el 90% de estos papelones antes de que lleguen a producción.
