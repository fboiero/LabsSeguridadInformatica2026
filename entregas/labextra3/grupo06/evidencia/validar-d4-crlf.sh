#!/usr/bin/env bash
set -eo pipefail
export CTF_ROOT='/c/Users/Muhammed/Desktop/Facultad/Seguridad Laboratorios/LabsSeguridadInformatica2026'
source "$CTF_ROOT/bin/lib/ui.sh"
source "$CTF_ROOT/bin/lib/check.sh"
compat_manifest="$(mktemp)"
trap 'rm -f "$compat_manifest"' EXIT
tr -d '\r' < "$CTF_ROOT/labs/labextra3-hardening/retos.manifest" > "$compat_manifest"
_manifest_path() { printf '%s' "$compat_manifest"; }
ctf_submit "$CTF_ROOT/labs/labextra3-hardening" extra3 D4 'FLAG{def_sqli_parametrizado}'
ctf_status "$CTF_ROOT/labs/labextra3-hardening" extra3 || test "$?" -eq 1
