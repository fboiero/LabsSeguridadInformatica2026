#!/usr/bin/env bash
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

ctf_submit "$CTF_ROOT/labs/labextra3-hardening" extra3 D3 'FLAG{def_rutas_blindadas}'
ctf_status "$CTF_ROOT/labs/labextra3-hardening" extra3 || test "$?" -eq 1
