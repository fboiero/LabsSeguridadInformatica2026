#!/usr/bin/env bash
# Ejecutar desde Git Bash: bash entregas/labextra2/grupo10/evidencia/reproducir-r1.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
EVIDENCIA="$ROOT/entregas/labextra2/grupo10/evidencia"
TEMP_ROOT="$(cygpath -u "$LOCALAPPDATA")/Temp/opencode"
CASO="$(mktemp -d "$TEMP_ROOT/labextra2-r1.XXXXXX")"

# No cambiar la configuración global ni el caso preexistente.
export GIT_CONFIG_COUNT=3
export GIT_CONFIG_KEY_0=core.autocrlf GIT_CONFIG_VALUE_0=false
export GIT_CONFIG_KEY_1=commit.gpgsign GIT_CONFIG_VALUE_1=false
export GIT_CONFIG_KEY_2=core.hooksPath GIT_CONFIG_VALUE_2=/dev/null
unset GIT_AUTHOR_NAME GIT_AUTHOR_EMAIL GIT_AUTHOR_DATE
unset GIT_COMMITTER_NAME GIT_COMMITTER_EMAIL GIT_COMMITTER_DATE

# Conservar el contenido UTF-8 del generador; convertir únicamente CRLF a LF.
sed 's/\r$//' "$ROOT/labs/labextra2-git-forense/caso/generar-caso.sh" > "$CASO/generar-caso.sh"
bash "$CASO/generar-caso.sh"
cd "$CASO/repo-delata"
mkdir -p "$EVIDENCIA/salidas"
git --no-pager log --oneline > "$EVIDENCIA/salidas/historia-r1.txt"
git --no-pager log -p > "$EVIDENCIA/salidas/historia-diffs-r1.txt"
git --no-pager log -p -- config.py > "$EVIDENCIA/salidas/r1.txt"
git --no-pager log --format='%h | %H | %an <%ae> | %aI | %s' -- config.py > "$EVIDENCIA/salidas/timeline-r1.txt"
printf 'Repo generado: %s\n' "$PWD"
cat "$EVIDENCIA/salidas/timeline-r1.txt"
