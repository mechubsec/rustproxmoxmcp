#!/bin/sh
# Behavioural test: the installer's file helpers refuse non-regular paths,
# leave the pointed-to file untouched, and create files through install(1).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
installer="$here/../install.sh"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Pull only the helper definitions out of the installer so they can run
# without the root/OS checks.
awk '
    /^(die|require_regular_file|install_generated_file|empty_token_store|random_key_32)\(\)/ { keep = 1 }
    keep { print }
    keep && /^}/ { keep = 0 }
' "$installer" > "$work/helpers.sh"
# shellcheck disable=SC2034  # read by the sourced helpers
SERVICE_USER=$(id -un)
# shellcheck disable=SC2034
SERVICE_GROUP=$(id -gn)
# shellcheck disable=SC1091
. "$work/helpers.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }

run_helper() ( "$@" ) >/dev/null 2>&1

# Fresh create: regular file, requested mode.
target="$work/fresh.json"
run_helper install_generated_file 0600 "$target" empty_token_store || fail "fresh create"
if [ ! -f "$target" ] || [ -L "$target" ]; then fail "fresh target not a regular file"; fi
[ "$(stat -c %a "$target")" = 600 ] || fail "fresh target mode"

# Existing regular file is preserved.
echo keep > "$work/existing"
run_helper install_generated_file 0600 "$work/existing" empty_token_store || fail "existing file"
[ "$(cat "$work/existing")" = keep ] || fail "existing file overwritten"

# Planted entries: dangling symlink, symlink to canary, directory.
for kind in dangling live dir; do
    canary="$work/canary-$kind"
    echo canary > "$canary"
    chmod 0644 "$canary"
    path="$work/planted-$kind"
    case $kind in
        dangling) ln -s "$work/does-not-exist" "$path" ;;
        live) ln -s "$canary" "$path" ;;
        dir) mkdir "$path" ;;
    esac
    if run_helper install_generated_file 0600 "$path" random_key_32; then
        fail "$kind: helper did not refuse"
    fi
    [ "$(cat "$canary")" = canary ] || fail "$kind: canary modified"
    [ "$(stat -c %a "$canary")" = 644 ] || fail "$kind: canary mode changed"
    [ ! -e "$work/does-not-exist" ] || fail "$kind: wrote through dangling link"
done

# The installer must route its root-written files through the helpers.
grep -q 'install_generated_file 0600 /var/lib/proxmoxmcp/tokens.json' "$installer" || fail "tokens.json not routed through helper"
grep -q 'install_generated_file 0600 /etc/proxmoxmcp/audit-hmac.key' "$installer" || fail "audit key not routed through helper"

echo "PASS: installer path guard"
