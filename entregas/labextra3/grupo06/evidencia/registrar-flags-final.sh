#!/usr/bin/env bash
# Registra solo flags emitidas por verificar-defensa.py; no modifica el manifiesto.
set -eo pipefail

CTF_ROOT="$(pwd)"
export CTF_ROOT
source "$CTF_ROOT/bin/lib/ui.sh"
source "$CTF_ROOT/bin/lib/check.sh"

compat_manifest="$(mktemp)"
trap 'rm -f "$compat_manifest"' EXIT
tr -d '\r' < "$CTF_ROOT/labs/labextra3-hardening/retos.manifest" > "$compat_manifest"

_manifest_path() {
    printf '%s' "$compat_manifest"
}

lab="$CTF_ROOT/labs/labextra3-hardening"
ctf_submit "$lab" extra3 D1 'FLAG{def_banner_neutralizado}'
ctf_submit "$lab" extra3 D2 'FLAG{def_debug_apagado}'
ctf_submit "$lab" extra3 D3 'FLAG{def_rutas_blindadas}'
ctf_submit "$lab" extra3 D4 'FLAG{def_sqli_parametrizado}'
ctf_submit "$lab" extra3 D5 'FLAG{def_traversal_bloqueado}'
ctf_status "$lab" extra3
