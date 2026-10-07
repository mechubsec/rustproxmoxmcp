# How to set up a rust-proxmoxmcp LXC from scratch

Builds one Proxmox LXC running `rust-proxmoxmcp`, in either **lab mode** or
**two-person** mode. Written from a rebuild performed on 2026-09-07, not from
memory: every command here was run, and the two failures that occurred are in
[Troubleshooting](#troubleshooting) with their exact error text.

Two rigs are normally built as a pair, because they test different things:

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation for protected guests only; ordinary guests still require a second principal | lab work on protected guests, single-operator change sets |
| **two-person** (no flag) | a second principal must approve before apply, for all guests | anything that must prove the approval gate holds |

Never point a lab-mode server at production clusters. `--lab-mode` is the
*protection* override, not a blanket waiver: on a lab-mode server a
**protected** guest is approved on creation with no second principal, while an
**ordinary** guest still requires one and self-approval is refused. That
inversion surprises people.

## 0. Before you start

You need:

- A Proxmox node, a container template, and a free VMID and IP.
- **The credentials the server will use.** Four files: `clusters.json`,
  `tokens.json`, `mcp-rig.secret`, and a per-cluster token file in
  `secrets/<cluster>.token`. The token store lives at
  `/var/lib/proxmoxmcp/tokens.json` by default (or
  `/etc/proxmoxmcp/tokens.json` on pre-0.9.0 rigs, a legacy fallback the runtime
  still recognizes). Building the container is the easy part; these are the part
  you cannot regenerate. If you are rebuilding an existing rig, back them up
  first — see [Rebuilding](#rebuilding-an-existing-rig).

Check the template is present:

```bash
pveam list local | grep debian-13
# local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst
```

## 1. Get a binary that will actually run

**Do not `cargo build --release` on your workstation and copy the binary in.**
glibc is forward-incompatible: a binary linked against a newer glibc will not
start on an older one, and it fails at service start with a loader error *after*
the old binary has been replaced — an outage, not a build failure.

Take the binary from the release image, which CI builds against the right glibc,
and place it where the packager looks:

```bash
mkdir -p target/release
docker create --name px ghcr.io/mechubsec/rustproxmoxmcp:0.10.0
docker cp px:/usr/local/bin/rust-proxmoxmcp target/release/rust-proxmoxmcp
docker rm px
chmod 0755 target/release/rust-proxmoxmcp
```

No docker? On the Proxmox host, `skopeo` is available:

```bash
skopeo copy docker://ghcr.io/mechubsec/rustproxmoxmcp:0.10.0 dir:/tmp/img
```

Then find the layer containing `usr/local/bin/rust-proxmoxmcp` and untar it
into `target/release/rust-proxmoxmcp`.

## 2. Assemble the install package

`scripts/package-lxc.sh` writes `dist/rust-proxmoxmcp_<version>_<arch>.tar.gz`
and a `.sha256` sidecar. The version comes from the crate manifest.

```bash
PROXMOXMCP_PACKAGE_SKIP_BUILD=1 ./scripts/package-lxc.sh
```

Omit `PROXMOXMCP_PACKAGE_SKIP_BUILD` only when this machine's toolchain is the
one that should build the binary. The extracted directory is the versioned
package root. The binary sits at that root, not under `bin/` or
`usr/local/bin`, because that is where `packaging/lxc/install.sh` looks for it:

```
rust-proxmoxmcp_<version>_<arch>/
  rust-proxmoxmcp
  packaging/systemd/rust-proxmoxmcp.service
  packaging/systemd/rust-proxmoxmcp.sysusers
  packaging/systemd/rust-proxmoxmcp.tmpfiles
  packaging/systemd/ssdf-evidence.conf.example
  packaging/examples/clusters.example.json
  packaging/lxc/install.sh
```

The installer is `#!/bin/sh`, not bash. Invoke it as `bash ./packaging/lxc/install.sh`
(or `sh`) from the extracted directory.

## 3. Create the container

`nesting=1` is **required**. systemd 257 degrades badly in an unprivileged LXC
without it.

```bash
pct create 616 local:vztmpl/debian-13-standard_13.1-2_amd64.tar.zst \
    --hostname test-twoperson-proxmox \
    --cores 1 --memory 512 --swap 512 \
    --rootfs local-lvm:4 \
    --unprivileged 1 --features nesting=1 \
    --net0 name=eth0,bridge=vmbr0,firewall=1,gw=192.0.2.1,ip=192.0.2.10/24,type=veth \
    --onboot 0 --ostype debian \
    --tags "disposable;test;twoperson"

pct start 616
```

For the lab-mode pair, substitute `617`, `test-labmode-proxmox`, `192.0.2.11`,
and the tag `labmode`.

512 MB and one core is enough. The tags matter: `disposable` is what marks a
guest as safe to destroy, and the fleet's own safety rules key on it.

## 4. Install

```bash
pct push 616 dist/rust-proxmoxmcp_0.10.0_amd64.tar.gz /tmp/pkg.tar.gz
pct exec 616 -- bash -lc 'cd /tmp && tar xzf pkg.tar.gz && cd rust-proxmoxmcp_0.10.0_amd64 && bash ./packaging/lxc/install.sh'
```

`install.sh` creates the `proxmoxmcp` service user, installs the binary and the
unit, and stops there. **The service will not start yet** — it has no
configuration, and it says so.

## 5. Configuration and credentials

**This server needs FOUR files**, and a missing one costs a restart each:

```
/etc/proxmoxmcp/clusters.json
/var/lib/proxmoxmcp/tokens.json
/etc/proxmoxmcp/mcp-rig.secret
/etc/proxmoxmcp/secrets/<cluster>.token
```

The token store's canonical location is `/var/lib/proxmoxmcp/tokens.json` (the
installer seeds an empty store there). The runtime still recognizes
`/etc/proxmoxmcp/tokens.json` as a legacy fallback, **but only when the
canonical store does not exist**. Restoring to the wrong path produces an empty
token store: the service loads the seeded canonical file and rejects every
existing bearer token.

Two real failures happened here during the rebuild this document is written from:

1. `configuration error: file /etc/proxmoxmcp/mcp-rig.secret: No such file or directory`
   — that file was not restored.
2. The service started cleanly but rejected every bearer token with no file
   error, because the real `tokens.json` was restored to
   `/etc/proxmoxmcp/tokens.json` while `install.sh` had already seeded an empty
   store at `/var/lib/proxmoxmcp/tokens.json`. The canonical store exists, so it
   shadows the legacy path — the runtime never falls back to `/etc`, and the
   server loads zero tokens.

**Read the drop-in first to learn where it expects each file**, rather than
assuming a default location. Restore everything before the first start.

Place the credentials:

```bash
pct push 616 clusters.json        /etc/proxmoxmcp/clusters.json
pct push 616 tokens.json          /var/lib/proxmoxmcp/tokens.json
pct push 616 mcp-rig.secret       /etc/proxmoxmcp/mcp-rig.secret
pct push 616 example-cluster.token /etc/proxmoxmcp/secrets/example-cluster.token
```

Then fix ownership and modes. **Do this for every credential file at once.** The
server refuses to start on any file that is group- or world-readable, and it
checks them one at a time — so getting this wrong costs you one restart per file:

```bash
pct exec 616 -- bash -lc '
    install -d -o proxmoxmcp -g proxmoxmcp -m 0700 /etc/proxmoxmcp/secrets
    chown -R proxmoxmcp:proxmoxmcp /etc/proxmoxmcp
    chown -R proxmoxmcp:proxmoxmcp /var/lib/proxmoxmcp
    for f in clusters.json mcp-rig.secret secrets/*.token; do
        [ -f "/etc/proxmoxmcp/$f" ] && chmod 0600 "/etc/proxmoxmcp/$f"
    done
    [ -f /var/lib/proxmoxmcp/tokens.json ] && chmod 0600 /var/lib/proxmoxmcp/tokens.json
'
```

All four files must be 0600 and owned by `proxmoxmcp`.

## 6. The site drop-in

The shipped unit binds `127.0.0.1` and is deliberately conservative. Site
configuration goes in a drop-in, which keeps the shipped unit replaceable.

**Why a drop-in matters:** The shipped unit carries the seccomp posture
(`SystemCallFilter`, `SystemCallErrorNumber`). Replacing it wholesale silently
loses that hardening.

**`install.sh` does NOT create `/etc/systemd/system/rust-proxmoxmcp.service.d/`**;
create it first:

```bash
pct exec 616 -- mkdir -p /etc/systemd/system/rust-proxmoxmcp.service.d
```

`/etc/systemd/system/rust-proxmoxmcp.service.d/override.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/rust-proxmoxmcp \
    --clusters-file /etc/proxmoxmcp/clusters.json \
    --tokens-file /var/lib/proxmoxmcp/tokens.json \
    --waivers-file /etc/proxmoxmcp/waivers.json \
    --state-file /var/lib/proxmoxmcp/changeset-state.json \
    --transport streamable-http \
    --host 127.0.0.1 \
    --port 30031 \
    --allowed-host 127.0.0.1:30031 \
    --allowed-origin http://127.0.0.1:30031 \
    --audit-format json \
    --audit-log-file /var/lib/proxmoxmcp/audit.jsonl \
    --audit-journald
```

The empty `ExecStart=` is required: it clears the shipped one before setting a
new one.

**For lab mode, add `--lab-mode` to the `ExecStart` line.** That single flag is
the whole difference between the two rigs.

`--state-file` persists change-set and operation state across restarts. Without
it the coordinator keeps state in memory only, and every approval, preview and
in-flight apply is lost on restart — the server still starts and warns loudly
at boot, but do not run this drop-in without it.

This drop-in binds `127.0.0.1` only, same as the shipped unit. **Do not add
`--allow-insecure-bind` with a non-loopback `--host` to reach this server from
another host on the LAN** — that combination accepts a plaintext HTTP bind on a
real network interface, and every MCP bearer token and Proxmox API secret this
server handles would then cross the network unencrypted. To reach it from
another host, either:

- Put a TLS-terminating reverse proxy (nginx, Caddy, ...) in front of this
  loopback listener, forwarding to `127.0.0.1:30031`; or
- Configure the listener's own TLS directly with `--tls-cert` and `--tls-key`,
  then bind a real interface without `--allow-insecure-bind`.

Either way, update `--allowed-host` and `--allowed-origin` to the address
clients actually dial once one of those is in place — they are checked before
any bind mode is decided, so plaintext-on-LAN never becomes the only way to
satisfy them.

`--allowed-host` specifies the HTTP **Host** authorities the server will answer
for (the addresses clients actually dial). Requests to other addresses are
refused with **421 MISDIRECTED_REQUEST**.

`--allowed-origin` specifies trusted browser application origins, checked
against the `Origin` header. Mismatches return **403 FORBIDDEN**. Set it to the
origin of the browser client that will call this server. **The scheme must
match the server's TLS configuration**: a plaintext loopback listener takes
`http://` origins; an HTTPS console origin requires TLS on the listener or the
reverse proxy in front of it. If there is no browser client yet, the value must
still be present — any single well-formed origin satisfies that requirement
with no effect on non-browser MCP clients (curl, SDK calls), which send no
`Origin` header and are never matched. Replace it with the real client origin
before a browser client is pointed at the server.

Then:

```bash
pct exec 616 -- bash -lc 'systemctl daemon-reload && systemctl enable --now rust-proxmoxmcp.service'
```

## 7. Verify

Check the four things that actually matter:

```bash
# 1. it is running the version you think
pct exec 616 -- /usr/local/bin/rust-proxmoxmcp --version

# 2. the seccomp posture comes from the SHIPPED unit, not a local patch
pct exec 616 -- systemctl show rust-proxmoxmcp.service -p SystemCallErrorNumber --value   # 1 (EPERM)
pct exec 616 -- grep -l SystemCallErrorNumber /etc/systemd/system/rust-proxmoxmcp.service

# 3. the filter is actually installed, read from the kernel rather than systemd
pid=$(pct exec 616 -- systemctl show -p MainPID --value rust-proxmoxmcp.service)
pct exec 616 -- grep -E '^Seccomp' /proc/$pid/status                                      # Seccomp: 2

# 4. it is serving, and refusing unauthenticated callers
pct exec 616 -- curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30031/mcp \
     -H 'content-type: application/json' -d '{}'                                          # 401
```

`401` is the success case here: the transport is up and authentication is being
enforced. A `000` means nothing is listening on that address or port.

### Why the `SystemCallErrorNumber` check matters for this server

**Before v0.9.1, this server shipped NO `SystemCallErrorNumber` directive**, so a
denied syscall raised SIGSYS and killed the process mid-request instead of
returning `EPERM`. v0.9.1 is the release that fixes it, and reading it back from
the unit is how you prove the fix is present.

Checking it matters for every mecmcp-family server, but for `rust-proxmoxmcp`
this check is also how you know you are running 0.9.1 or later.

The installer reports `egress filter: NOT ENFORCED` in unprivileged LXC. That is
expected and true — systemd cannot enforce `IPAddressDeny` in an unprivileged
container, and the installer says so. It is not a fault.

## 8. Final step: stop the rig

Test rigs are stopped by default. They are started only when needed, and stopped
again at completion. Use `pct shutdown` rather than `pct stop` — a hard stop can
interrupt a state write and leave an operation unreconciled.

```bash
pct shutdown 616
```

## Rebuilding an existing rig

Back the credentials out **before** destroying anything. `pct mount` reads a
stopped container's filesystem without starting it:

```bash
pct mount 616
cp -a /var/lib/lxc/616/rootfs/etc/proxmoxmcp           /root/backup-616/etc-proxmoxmcp
cp -a /var/lib/lxc/616/rootfs/var/lib/proxmoxmcp      /root/backup-616/var-lib-proxmoxmcp
cp -a /var/lib/lxc/616/rootfs/etc/systemd/system/rust-proxmoxmcp.service.d /root/backup-616/
pct config 616 > /root/backup-616/pct-config.txt
pct unmount 616
```

`pct-config.txt` is worth keeping: it is the network, resources and tags you will
want to reproduce. Back up **both** `/etc/proxmoxmcp` and `/var/lib/proxmoxmcp`:
the token store is at `/var/lib`, and a rebuild seeds an empty canonical store
there that shadows any legacy `/etc/proxmoxmcp/tokens.json` left behind.

Restoring `tokens.json` rather than minting fresh tokens keeps existing clients
working — the secrets are hashed and cannot be recovered, so re-minting means
reconfiguring every client that talks to this rig.

## Troubleshooting

Both of these were hit during the rebuild this document is written from.

**`configuration error: file /etc/proxmoxmcp/mcp-rig.secret: No such file or directory`**  
That file was not restored. Step 5 names all four required files. Missing even
one prevents startup.

**Service starts cleanly but rejects every bearer token, no file error**  
The token store was restored to `/etc/proxmoxmcp/tokens.json`, but `install.sh`
seeded an empty store at `/var/lib/proxmoxmcp/tokens.json`. The canonical store
exists, so it shadows the legacy `/etc` path — the runtime never falls back, and
the server loads zero tokens. Symptom: authentication rejected with no "no such
file" error. Restore `tokens.json` to `/var/lib/proxmoxmcp/` instead, or remove
the empty seeded file if the legacy path holds the real store.

**`non-loopback bind '0.0.0.0' requires at least one --allowed-origin`**  
An off-loopback listener must supply at least one `--allowed-origin`, even when
no browser client exists yet. Any single well-formed origin (e.g.,
`http://console.example.org`) satisfies the startup requirement with no effect
on non-browser clients. Replace it with the real client origin before a browser
client is pointed at the server.

**Service active but every call returns 421 MISDIRECTED_REQUEST**  
`--allowed-host` does not match the HTTP `Host` header (the address clients
actually dial). Add the exact host and port they use.

**Browser requests return 403 FORBIDDEN, "Origin '...' is not allowed"**  
The browser's `Origin` header is not in the `--allowed-origin` allowlist. Add the
browser application's origin (e.g., `http://console.example.org`). Non-browser
MCP clients are unaffected.
