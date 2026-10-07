#!/usr/bin/env bash
# Build a Debian 13 LXC tarball.
# Output: dist/rust-proxmoxmcp_<version>_<arch>.tar.gz and a .sha256 sidecar.
#
# packaging/lxc/install.sh is run from the extracted directory and looks for
# ./rust-proxmoxmcp plus packaging/... relative to that directory. The archive
# root is that directory. The installer copies the binary to /usr/local/bin.
#
# A binary linked against a newer glibc than Debian 13 will not start there.
# Set PROXMOXMCP_PACKAGE_SKIP_BUILD=1 to package a binary already built for
# that target (for example one taken from the release image) instead of
# compiling on this machine.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
    printf 'package-lxc: %s\n' "$*" >&2
    exit 1
}

# The binary crate inherits [workspace.package].version. An explicit
# version = "..." in [package] wins if inheritance is ever dropped.
read_crate_version() {
    local crate="crates/rust-proxmoxmcp/Cargo.toml"
    [[ -f "$crate" ]] || fail "missing $crate"
    if awk '
        /^\[package\]$/ { in_pkg = 1; next }
        /^\[/ { in_pkg = 0 }
        in_pkg && /^version\.workspace[[:space:]]*=[[:space:]]*true[[:space:]]*$/ { found = 1 }
        END { exit found ? 0 : 1 }
    ' "$crate"; then
        awk '
            /^\[workspace\.package\]$/ { in_ws = 1; next }
            /^\[/ { in_ws = 0 }
            in_ws && /^version[[:space:]]*=[[:space:]]*"/ {
                if (match($0, /"[^"]+"/)) {
                    print substr($0, RSTART + 1, RLENGTH - 2)
                    exit
                }
            }
        ' Cargo.toml
    else
        awk '
            /^\[package\]$/ { in_pkg = 1; next }
            /^\[/ { in_pkg = 0 }
            in_pkg && /^version[[:space:]]*=[[:space:]]*"/ {
                if (match($0, /"[^"]+"/)) {
                    print substr($0, RSTART + 1, RLENGTH - 2)
                    exit
                }
            }
        ' "$crate"
    fi
}

if [[ -n "${PROXMOXMCP_PACKAGE_VERSION:-}" ]]; then
    VERSION="$PROXMOXMCP_PACKAGE_VERSION"
else
    VERSION="$(read_crate_version)"
fi
[[ -n "$VERSION" ]] || fail "could not read the version from crates/rust-proxmoxmcp/Cargo.toml"
[[ "$VERSION" =~ ^[0-9A-Za-z][0-9A-Za-z.+_-]*$ ]] || fail "version is not a safe package name component"

case "$(uname -m)" in
    x86_64) DEFAULT_ARCH=amd64 ;;
    aarch64 | arm64) DEFAULT_ARCH=arm64 ;;
    *) DEFAULT_ARCH="$(uname -m)" ;;
esac
ARCH="${PROXMOXMCP_PACKAGE_ARCH:-$DEFAULT_ARCH}"
[[ "$ARCH" =~ ^[0-9A-Za-z][0-9A-Za-z._-]*$ ]] || fail "arch is not a safe package name component"

OUTPUT_DIR="${PROXMOXMCP_PACKAGE_OUTPUT_DIR:-dist}"

if [[ "${PROXMOXMCP_PACKAGE_SKIP_BUILD:-0}" != "1" ]]; then
    echo ">> Building release binary..."
    cargo build --release --locked -p rust-proxmoxmcp
fi

TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN="${TARGET_DIR}/release/rust-proxmoxmcp"
[[ -x "$BIN" && ! -L "$BIN" ]] || fail "missing executable $BIN (build it, or place a prebuilt binary there and set PROXMOXMCP_PACKAGE_SKIP_BUILD=1)"

STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

PKG="rust-proxmoxmcp_${VERSION}_${ARCH}"
PKGROOT="$STAGING/$PKG"

install -d -m 0755 \
    "$PKGROOT/packaging/lxc" \
    "$PKGROOT/packaging/systemd" \
    "$PKGROOT/packaging/examples"

install -m 0755 "$BIN" "$PKGROOT/rust-proxmoxmcp"
install -m 0755 packaging/lxc/install.sh "$PKGROOT/packaging/lxc/install.sh"
install -m 0644 packaging/systemd/rust-proxmoxmcp.service "$PKGROOT/packaging/systemd/rust-proxmoxmcp.service"
install -m 0644 packaging/systemd/rust-proxmoxmcp.sysusers "$PKGROOT/packaging/systemd/rust-proxmoxmcp.sysusers"
install -m 0644 packaging/systemd/rust-proxmoxmcp.tmpfiles "$PKGROOT/packaging/systemd/rust-proxmoxmcp.tmpfiles"
install -m 0644 packaging/systemd/ssdf-evidence.conf.example "$PKGROOT/packaging/systemd/ssdf-evidence.conf.example"
install -m 0644 packaging/examples/clusters.example.json "$PKGROOT/packaging/examples/clusters.example.json"

mkdir -p "$OUTPUT_DIR"
DIST_DIR="$(cd "$OUTPUT_DIR" && pwd)"
TARBALL="$DIST_DIR/${PKG}.tar.gz"

tar -czf "$TARBALL" -C "$STAGING" "$PKG"
(
    cd "$DIST_DIR"
    sha256sum "${PKG}.tar.gz" > "${PKG}.tar.gz.sha256"
)

echo ">> Wrote $TARBALL"
echo ">> Wrote ${TARBALL}.sha256"
