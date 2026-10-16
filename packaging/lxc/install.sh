#!/bin/sh
# POSIX shell installer for rust-proxmoxmcp on Debian 13 LXC.
set -eu

die() {
    printf 'rust-proxmoxmcp installer: %s\n' "$*" >&2
    exit 1
}

SERVICE_USER=proxmoxmcp
SERVICE_GROUP=proxmoxmcp

# Refuse any existing path that is not a plain file. Called immediately before
# every create/chmod/chown of a root-written file.
require_regular_file() {
    if [ -L "$1" ] || { [ -e "$1" ] && [ ! -f "$1" ]; }; then
        die "$1 is not a regular file; refusing"
    fi
}

# Create a file from a generator command (which writes to stdout) if absent.
# Content goes to a private temp file and is placed with install(1), which
# replaces rather than follows whatever sits at the destination.
install_generated_file() {
    mode=$1
    target=$2
    shift 2
    require_regular_file "$target"
    if [ ! -e "$target" ]; then
        gen_tmp=$(mktemp) || die "mktemp failed"
        if ! "$@" > "$gen_tmp"; then
            rm -f "$gen_tmp"
            die "failed to generate $target"
        fi
        if ! install -m "$mode" -o "$SERVICE_USER" -g "$SERVICE_GROUP" "$gen_tmp" "$target"; then
            rm -f "$gen_tmp"
            die "failed to install $target"
        fi
        rm -f "$gen_tmp"
    fi
}

empty_token_store() {
    printf '{"version":1,"tokens":[]}\n'
}

random_key_32() {
    head -c 32 /dev/urandom
}

# Prove whether systemd's IPAddress* filters actually attach here, rather than
# assuming the unit's declaration means anything. systemd implements them with
# cgroup eBPF and FAILS OPEN when it cannot load the program -- typical in an
# unprivileged LXC without host delegation -- so the unit can declare a full
# egress policy while enforcing none of it. `systemd-analyze security` reads the
# declaration and cannot tell the difference.
#
# Informational by default: a runtime that withholds BPF is a legitimate
# deployment, and the operator needs to know rather than be blocked. Set
# PROXMOXMCP_REQUIRE_EGRESS_FILTER=1 to make a non-enforcing host fatal.
egress_probe_unknown() {
    require=$1
    reason=$2
    printf '%s\n' "egress filter: UNKNOWN ($reason)" >&2
    # Strict mode must not accept what it could not measure. An unmeasurable
    # host is exactly as unguaranteed as a non-enforcing one.
    if [ "$require" = 1 ]; then
        die 'PROXMOXMCP_REQUIRE_EGRESS_FILTER=1 and egress enforcement could not be determined'
    fi
    return 0
}

report_egress_enforcement() {
    require=${PROXMOXMCP_REQUIRE_EGRESS_FILTER:-0}
    probe_unit="rust-proxmoxmcp-egress-probe-$$"
    unit_path="/etc/systemd/system/rust-proxmoxmcp.service"

    if ! command -v systemd-run >/dev/null; then
        egress_probe_unknown "$require" 'systemd-run unavailable; cannot probe'
        return $?
    fi

    # Two independent conditions have to hold, and conflating them is how the
    # previous version overstated its result:
    #   1. the host can attach the cgroup BPF program at all, and
    #   2. the *installed* unit actually declares an egress policy.
    # A transient probe only establishes (1). If the installer preserved a
    # customized unit with no IPAddressDeny, (1) alone would still have printed
    # ENFORCED and satisfied the strict flag over a service filtering nothing.
    counters=''
    if systemd-run --quiet --collect --unit="$probe_unit" \
        --property=IPAccounting=yes --property=RemainAfterExit=yes \
        /bin/true >/dev/null 2>&1
    then
        counters=$(systemctl show "$probe_unit.service" -p IPEgressBytes --value 2>/dev/null || printf '')
        systemctl stop "$probe_unit.service" >/dev/null 2>&1 || true
        systemctl reset-failed "$probe_unit.service" >/dev/null 2>&1 || true
    else
        egress_probe_unknown "$require" 'probe unit would not start; run as root to determine'
        return $?
    fi

    if [ -z "$counters" ] || [ "$counters" = '[no data]' ]; then
        printf '%s\n' \
            'egress filter: NOT ENFORCED' \
            '  systemd cannot attach its cgroup BPF program here, so the IPAddressAllow/' \
            '  IPAddressDeny lines in rust-proxmoxmcp.service have no effect. This is normal in' \
            '  an unprivileged LXC. The unit still applies every other sandbox directive.' \
            '  Move the control outward to whatever layer sees this workload'"'"'s packets --' \
            '  guest firewall, host nftables, NetworkPolicy, or cloud security group -- and' \
            '  deny 169.254.0.0/16 plus the local subnet except your resolver, allow 443 out.' \
            '  README.md, "Enforcing it where systemd cannot", has the per-runtime' \
            '  mechanism and a verification command.' >&2
        if [ "$require" = 1 ]; then
            die 'PROXMOXMCP_REQUIRE_EGRESS_FILTER=1 and systemd IP filtering is not enforced here'
        fi
        return 0
    fi

    # (1) holds. Now (2): does the unit that was actually installed carry a
    # policy for the kernel to enforce?
    if ! grep -Eq '^[[:space:]]*IPAddressDeny[[:space:]]*=[[:space:]]*[^[:space:]]' "$unit_path"; then
        printf '%s\n' \
            'egress filter: NO POLICY' \
            "  This host can enforce systemd IP filtering, but $unit_path declares no" \
            '  IPAddressDeny. A preserved customized unit overrides the packaged policy;' \
            '  re-install or add the directives by hand.' >&2
        if [ "$require" = 1 ]; then
            die 'PROXMOXMCP_REQUIRE_EGRESS_FILTER=1 and the installed unit declares no egress policy'
        fi
        return 0
    fi

    printf '%s\n' 'egress filter: ENFORCED'
    return 0
}

# Refuse if not root
if [ "$(id -u)" -ne 0 ]; then
    echo "error: this installer must run as root" >&2
    exit 1
fi

# Refuse if not Debian 13
if [ ! -f /etc/os-release ]; then
    echo "error: /etc/os-release not found; cannot verify OS" >&2
    exit 1
fi

# shellcheck disable=SC1091
. /etc/os-release

if [ "${ID:-}" != "debian" ] || [ "${VERSION_ID:-}" != "13" ]; then
    echo "error: this installer requires Debian 13 (detected: ${ID:-unknown} ${VERSION_ID:-unknown})" >&2
    exit 1
fi

echo "==> Installing rust-proxmoxmcp"

# Install runtime dependencies
echo "    Installing runtime dependencies..."
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates
apt-get clean
rm -rf /var/lib/apt/lists/*

# Create service user and directories via systemd
if [ ! -f packaging/systemd/rust-proxmoxmcp.sysusers ]; then
    echo "error: packaging/systemd/rust-proxmoxmcp.sysusers not found" >&2
    exit 1
fi
if [ ! -f packaging/systemd/rust-proxmoxmcp.tmpfiles ]; then
    echo "error: packaging/systemd/rust-proxmoxmcp.tmpfiles not found" >&2
    exit 1
fi

echo "    Creating proxmoxmcp system user..."
systemd-sysusers packaging/systemd/rust-proxmoxmcp.sysusers

echo "    Creating directories..."
systemd-tmpfiles --create packaging/systemd/rust-proxmoxmcp.tmpfiles

# Install the binary
if [ ! -f rust-proxmoxmcp ]; then
    echo "error: rust-proxmoxmcp binary not found in current directory" >&2
    exit 1
fi
echo "    Installing binary to /usr/local/bin/rust-proxmoxmcp..."
install -m 0755 -o root -g root rust-proxmoxmcp /usr/local/bin/rust-proxmoxmcp

# /etc/proxmoxmcp and secrets directory already created by tmpfiles

# Install example config files only if absent
require_regular_file /etc/proxmoxmcp/clusters.json
if [ ! -e /etc/proxmoxmcp/clusters.json ]; then
    echo "    Installing example clusters.json..."
    if [ -f packaging/examples/clusters.example.json ]; then
        install -m 0600 -o proxmoxmcp -g proxmoxmcp packaging/examples/clusters.example.json /etc/proxmoxmcp/clusters.json
    else
        echo "    warning: packaging/examples/clusters.example.json not found; skipping" >&2
    fi
else
    echo "    /etc/proxmoxmcp/clusters.json exists; not overwriting"
fi

# tokens.json moved from /etc/proxmoxmcp to /var/lib/proxmoxmcp (#22).
#
# Create an empty store ONLY when no legacy store exists. The runtime prefers an
# existing primary, so writing an empty file here while the live tokens are still
# at the legacy path would shadow them: the service starts and rejects every
# existing bearer token. A silent auth wipe on upgrade is worse than a refusal.
#
# The file is never copied automatically — that would leave a duplicate secret
# behind, which is what the stale-secret scan exists to flag.
require_regular_file /var/lib/proxmoxmcp/tokens.json
if [ ! -e /var/lib/proxmoxmcp/tokens.json ]; then
    if [ -e /etc/proxmoxmcp/tokens.json ]; then
        printf '%s\n' ">> Not creating /var/lib/proxmoxmcp/tokens.json: a token store already exists at"
        printf '%s\n' ">> /etc/proxmoxmcp/tokens.json. The server reads it via the legacy fallback and warns."
        printf '%s\n' ">> Migrate it deliberately, then remove the old copy:"
        printf '%s\n' ">>   install -m 0600 -o proxmoxmcp -g proxmoxmcp /etc/proxmoxmcp/tokens.json /var/lib/proxmoxmcp/tokens.json"
        printf '%s\n' ">>   rm /etc/proxmoxmcp/tokens.json"
    else
        install_generated_file 0600 /var/lib/proxmoxmcp/tokens.json empty_token_store
    fi
else
    echo "    /var/lib/proxmoxmcp/tokens.json exists; not overwriting"
fi

# Generate audit HMAC key if absent. Never regenerate — a new key breaks
# verification of every prior audit record.
require_regular_file /etc/proxmoxmcp/audit-hmac.key
if [ ! -e /etc/proxmoxmcp/audit-hmac.key ]; then
    echo "    Generating audit HMAC key..."
    install_generated_file 0600 /etc/proxmoxmcp/audit-hmac.key random_key_32
else
    echo "    /etc/proxmoxmcp/audit-hmac.key exists; preserving (never regenerate)"
fi

# Install systemd unit
if [ -f packaging/systemd/rust-proxmoxmcp.service ]; then
    echo "    Installing systemd unit..."
    install -m 0644 -o root -g root packaging/systemd/rust-proxmoxmcp.service /etc/systemd/system/rust-proxmoxmcp.service
    systemctl daemon-reload
    report_egress_enforcement
else
    echo "    warning: packaging/systemd/rust-proxmoxmcp.service not found; skipping unit install" >&2
fi

echo ""
echo "==> Installation complete"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/proxmoxmcp/clusters.json with your cluster details"
echo "  2. Write each cluster's API token secret to /etc/proxmoxmcp/secrets/<cluster>.token"
echo "     (mode 0600, owned by proxmoxmcp). Alternatively, use token_secret_env and"
echo "     create /etc/proxmoxmcp/secrets.env with KEY=value lines."
if [ -e /var/lib/proxmoxmcp/tokens.json ]; then
    echo "  3. Mint a token, e.g.:"
    echo "       rust-proxmoxmcp token add --tokens-file /var/lib/proxmoxmcp/tokens.json \\"
    echo "           --name reader --devices '*' --tools '*' --guests '*' --actions read"
    echo "     Omit --guests only for a token that will call cluster-scoped tools alone;"
    echo "     without it the token cannot address individual guests."
    echo "     For a token that will call approve_proxmox_change_set, add --actor-type human;"
    echo "     agent and unattributed callers are refused."
elif [ -e /etc/proxmoxmcp/tokens.json ]; then
    echo "  3. The token store is at the legacy /etc/proxmoxmcp/tokens.json."
    echo "     Migrate it first (see above), or mint tokens directly into the legacy store:"
    echo "       rust-proxmoxmcp token add --tokens-file /etc/proxmoxmcp/tokens.json \\"
    echo "           --name reader --devices '*' --tools '*' --guests '*' --actions read"
    echo "     WARNING: Tokens in the legacy store cannot be modified while the service"
    echo "     runs with ProtectSystem=strict. Migrate to /var/lib for full write capability."
    echo "     For a token that will call approve_proxmox_change_set, add --actor-type human;"
    echo "     agent and unattributed callers are refused."
else
    echo "  3. Mint a token, e.g.:"
    echo "       rust-proxmoxmcp token add --tokens-file /var/lib/proxmoxmcp/tokens.json \\"
    echo "           --name reader --devices '*' --tools '*' --guests '*' --actions read"
    echo "     Omit --guests only for a token that will call cluster-scoped tools alone;"
    echo "     without it the token cannot address individual guests."
    echo "     For a token that will call approve_proxmox_change_set, add --actor-type human;"
    echo "     agent and unattributed callers are refused."
fi
echo "  4. (Optional) Configure TLS certificates at /etc/proxmoxmcp/tls/{fullchain,privkey}.pem"
echo "  5. Start the service: systemctl start rust-proxmoxmcp"
echo "  6. Enable on boot: systemctl enable rust-proxmoxmcp"
echo ""
echo "IMPORTANT: Before upgrading, snapshot this container in Proxmox."
echo "           A failed upgrade can be reverted by rolling back to the snapshot."
echo ""
