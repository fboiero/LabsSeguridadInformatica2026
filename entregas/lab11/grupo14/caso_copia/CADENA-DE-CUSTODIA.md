# Cadena de custodia — copia de trabajo de la evidencia

`caso_copia/` es la **copia de trabajo** de `labs/lab11-forensia/caso/`. Toda la
investigación se hace acá; la evidencia original no se modifica.

## Cómo se prepara la copia

Los hashes de `evidencia.sha256` corresponden a los bytes tal como están
guardados en git (saltos de línea **LF**). En Windows, con `core.autocrlf=true`,
el checkout convierte los archivos a **CRLF** y *todos* los hashes dejan de
coincidir aunque nadie haya tocado nada. Para que la verificación sea válida hay
que copiar la evidencia con sus bytes originales y evitar la conversión:

```bash
# desde la raíz del repo: copiar cada archivo tal como está en git (LF)
D=entregas/lab11/grupo14/caso_copia
for f in $(git ls-files labs/lab11-forensia/caso); do
  rel=${f#labs/lab11-forensia/caso/}
  mkdir -p "$D/$(dirname "$rel")"
  git show HEAD:"$f" > "$D/$rel"
done

# impedir que git convierta los saltos de línea en esta carpeta
printf '* -text\n' > "$D/.gitattributes"
```

El `.gitattributes` con `* -text` fija el comportamiento: git no convierte nada
dentro de `caso_copia/`, en ninguna máquina del grupo.

> En Linux/macOS (`autocrlf` desactivado) alcanza con `cp -r`. El procedimiento
> de arriba funciona en cualquier sistema y es el que se usa en el grupo.

## Cómo se verifica

```bash
cd entregas/lab11/grupo14/caso_copia
sha256sum -c evidencia.sha256        # macOS: shasum -a 256 -c evidencia.sha256
```

Antes de analizar, confirmar que el archivo que se abre tiene saltos LF
(`file logs/access.log` no debe decir *CRLF*).

## Resultado de la verificación

| Archivo | Estado |
|---|---|
| `disco/etc/passwd.snippet` | OK |
| `disco/listado.txt` | OK |
| `disco/var/www/uploads/shell.php.evidencia.txt` | OK |
| `logs/access.log` | OK |
| **`logs/auth.log`** | **FAILED** |
| `memoria/bash_history.txt` | OK |
| `memoria/lsof.txt` | OK |
| `memoria/netstat.txt` | OK |
| `memoria/pslist.txt` | OK |

**Hallazgo (R5):** `logs/auth.log` fue alterado después de la captura. El hash
registrado en `evidencia.sha256` es
`0000decafbad0000f1e2d3c4b5a6978800112233445566778899aabbccddeeff`; el archivo
actual hashea distinto
(`7d18039d128d0df7a245ca02f469ea02cd1d4f205a24fb33c5bcf7041b66e9ab`). Ese archivo se trata como
**no confiable** y su alteración se documenta en el informe (sección *Cadena de
custodia*). Sin esa documentación la evidencia queda invalidada.
