# Recolección de evidencia de PhantomCorp

El recolector determinista busca `r1.json` a `r4.json` en una carpeta de staging
indicada explícitamente por el operador. No lista el resto, no llama a un modelo,
no consulta PhantomCorp y no lee el artefacto crudo. No usa una carpeta compartida,
sincronizada ni modificable por terceros: prepará un staging local estable y no
lo modifiques durante la ejecución. Los chequeos de enlaces no sustituyen ese
aislamiento. No incluyas credenciales, flags ni datos de clientes.

Ejemplo **sintético** de `r1.json`, en UTF-8 sin BOM:

```json
{"version":1,"lab":"phantomcorp","milestone":"R1","source":"synthetic_fixture","captured_at":"2026-11-18T18:00:00Z"}
```

Para evidencia real, `source` puede ser `operator_review_note` o
`lab_export_metadata`. En el segundo caso incluí `original_sha256` en minúsculas
para referenciar el original sin copiar su contenido. El borrador separa ese
hash declarado del hash calculado sobre el JSON importado. `captured_at` es la
fecha de origen declarada y `collected_at` es la fecha de importación.

Desde `ptaas`, con la carpeta de entrada y el directorio de salida ya creados:

```powershell
.\.venv\Scripts\python.exe -B -m runtime.phantomcorp_evidence --approved-dir runs/phantomcorp-staging --output runs/phantomcorp-borrador.json
```

`artifact_received` significa que llegaron metadatos válidos; `missing`, que
faltan; `rejected`, que el archivo esperado incumplió el contrato. Un rechazo
genera el borrador parcial y devuelve código 3. Nunca se sobrescribe la salida.
Todos los hitos quedan sin acreditar. Este inventario no sustituye la revisión
humana de las fuentes originales ni el informe requerido por la cátedra.
