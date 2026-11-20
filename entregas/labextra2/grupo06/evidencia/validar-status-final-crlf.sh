#!/usr/bin/env bash
set -eo pipefail
CTF_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
export CTF_ROOT
source "$CTF_ROOT/bin/lib/ui.sh"
source "$CTF_ROOT/bin/lib/check.sh"
compat_manifest="$(mktemp)"
trap 'rm -f "$compat_manifest"' EXIT
tr -d '\r' < "$CTF_ROOT/labs/labextra2-git-forense/retos.manifest" > "$compat_manifest"
_manifest_path() { printf '%s' "$compat_manifest"; }
ctf_submit "$CTF_ROOT/labs/labextra2-git-forense" extra2 R1 'FLAG{git_log_no_olvida}'
ctf_submit "$CTF_ROOT/labs/labextra2-git-forense" extra2 R2 'FLAG{git_reflog_rescata}'
ctf_submit "$CTF_ROOT/labs/labextra2-git-forense" extra2 R3 'FLAG{git_rama_abandonada}'
ctf_status "$CTF_ROOT/labs/labextra2-git-forense" extra2
