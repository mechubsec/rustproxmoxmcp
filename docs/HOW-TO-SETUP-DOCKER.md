# How to run rust-proxmoxmcp in Docker

Runs the server as a container in either **lab mode** or **two-person** mode.
Written from a working setup built on 2026-09-07: every command here was run,
and the two failures that occurred are in [Troubleshooting](#troubleshooting)
with their exact error text.

| mode | approvals | use it for |
|---|---|---|
| **lab mode** (`--lab-mode`) | waived on creation for **protected** guests only; ordinary guests still require a second principal | single-operator work on protected guests |
| **two-person** (no flag) | a second principal must approve before apply | anything that must prove the approval gate holds |

The server announces lab mode at startup, as a `WARN`:

```
lab mode enabled: change sets for protected guests are approved on creation with no second principal.
Records carry approval_waiver=lab-mode. Do not run this against production devices.
```

If you see that line and did not intend it, stop and fix the flag.

## What the image presets, and what you can override

`ENTRYPOINT` carries what must always hold — the config and credential paths:

```
--clusters-file /etc/proxmoxmcp/clusters.json
--tokens-file   /var/lib/proxmoxmcp/tokens.json
```

`CMD` carries what an operator is expected to replace:

```
--transport streamable-http
--host      127.0.0.1
--port      30031
```

Docker **appends** your arguments to `ENTRYPOINT` but **replaces** `CMD`
outright. So passing `--host 0.0.0.0` swaps out the whole `CMD` line — supply
`--transport` and `--port` alongside it — while the two config paths survive and
must **not** be passed again. Repeating one is a clap error
(`cannot be used multiple times`).

Before #85 the bind flags were in `ENTRYPOINT` too, which made the documented
`--host` override impossible and forced a `--entrypoint` workaround. That is
fixed; no example below needs it.

## 1. Prepare host paths

```bash
mkdir -p proxmox-docker/secrets proxmox-docker/state
cd proxmox-docker
```

`clusters.json` — follows `packaging/examples/clusters.example.json`. Note it
references a **separate secret file** per cluster via `token_secret_file`:

```json
{
  "version": 1,
  "devices": {
    "pve-demo": {
      "endpoint": "https://192.0.2.10:8006",
      "token_id": "mcp-automation@pve!mcp",
      "token_secret_file": "/etc/proxmoxmcp/secrets/pve-demo.token",
      "protected_vmids": [100, 101],
      "protected_tags": ["protected"]
    }
  },
  "policy": {
    "resource_cache_ttl_secs": 10
  }
}
```

`token_id` is a dedicated, non-root Proxmox user carrying a purpose-built
least-privilege role — never `root@pam`, which bypasses Proxmox's ACL system
entirely and so cannot be constrained by anything in this file. See
[README § The Proxmox-side token: least privilege, not `root@pam`](../README.md#the-proxmox-side-token-least-privilege-not-rootpam)
for the exact `pveum` commands and the privilege-to-tool mapping.

**`token_secret_file` must be the in-container path**, not the host path. The
file lives at `secrets/pve-demo.token` on the host and is mounted to
`/etc/proxmoxmcp/secrets`.

Create the Proxmox API token secret file:

```bash
echo -n "your-proxmox-api-token-secret" > secrets/pve-demo.token
```

Mint a bearer token for MCP clients. The binary can do this on the host:

```bash
rust-proxmoxmcp token add --tokens-file ./tokens.json \
    --name my-client --devices '*' --tools '*'
```

The secret prints **once** and is stored hashed. Note the CLI's hint: a token
minted without `--guests` cannot use guest-addressed tools. Grant that with
`--guests '*'` or a selector (`vmid:X`, `tag:Y`, `pool:Z`).

If this token will call `approve_proxmox_change_set`, add `--actor-type
human`: the server refuses approvals from any token whose actor type is
`agent` or unset. See [README § Change control](../README.md#change-control).

Then lock the modes down:

```bash
chmod 0600 clusters.json tokens.json secrets/*.token
```

## 2. Ownership: two options

The container process is UID 65532 and must read the config and write the state
directory.

**For a real deployment**, give it ownership:

```bash
sudo chown -R 65532:65532 clusters.json tokens.json secrets state
```

**For local testing without root**, run the container as yourself instead. The
files stay owned by you and nothing needs `sudo`:

```bash
--user "$(id -u):$(id -g)"
```

Both are shown below. The second is what the examples here were verified with.

## 3. Run it — two-person mode

Pin the image by **immutable digest**, not mutable tag. If the tag is republished,
the same documented command runs different bytes with no visible change. Pull the
image first (RepoDigests is empty if the image has not been pulled), then capture
the complete pinned reference:

```bash
docker pull ghcr.io/mechubsec/rustproxmoxmcp:0.10.0
image=$(docker inspect ghcr.io/mechubsec/rustproxmoxmcp:0.10.0 \
    --format '{{index .RepoDigests 0}}')
```

The resolved digest should be recorded wherever the deployment is tracked, since
that value identifies the exact bytes. On subsequent runs, use the recorded
digest directly (`image=ghcr.io/...@sha256:<recorded digest>`) or compare the
freshly resolved one against it and stop on mismatch — re-resolving the tag runs
whatever that tag points at today, which may be different bytes.

**Verify the signature before running it.** Every image pushed by the
`Release image` workflow is signed keylessly with
[cosign](https://github.com/sigstore/cosign) via GitHub Actions OIDC — no key
pair exists anywhere. Verification pins the signing identity to that exact
workflow, so a signature from anywhere else (a fork, a different repo, a local
build) fails:

```bash
cosign verify \
  --certificate-identity-regexp '^https://github\.com/mechubsec/rustproxmoxmcp/\.github/workflows/release-image\.yml@refs/(tags/v[0-9]+\.[0-9]+\.[0-9]+|heads/main)$' \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$image"
```

A failure here means do not run it, not "probably fine."

```bash
docker run -d --name proxmox-twoperson \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30033:30031 \
  -v "$PWD/clusters.json:/etc/proxmoxmcp/clusters.json:ro" \
  -v "$PWD/secrets:/etc/proxmoxmcp/secrets:ro" \
  -v "$PWD/state:/var/lib/proxmoxmcp" \
  -v "$PWD/tokens.json:/var/lib/proxmoxmcp/tokens.json:ro" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30031 \
  --allow-insecure-bind \
  --state-file /var/lib/proxmoxmcp/changeset-state.json \
  --allowed-host 127.0.0.1:30033 --allowed-host localhost:30033 \
  --allowed-origin http://127.0.0.1:30033 --allowed-origin http://localhost:30033
```

The `-p 127.0.0.1:30033:30031` publish binds only to loopback on the host.
Reaching this server from another host requires BOTH a non-loopback publish
(`-p 30033:30031` or `-p 0.0.0.0:30033:30031`) AND TLS with the allow-lists
updated to the externally dialled authority, or a TLS-terminating reverse proxy
in front of the loopback endpoint — Host and Origin header validation is not a
network boundary.

`--state-file` persists change-set and operation state across restarts. Without
it the coordinator keeps state in memory only, and every approval, preview and
in-flight apply is lost when the container restarts. Mount the host `state`
directory on `/var/lib/proxmoxmcp` (the image volume), the same mount
`server.json` publishes. That directory is where the image keeps change-set
state and the audit key, so mount the directory itself, not a subdirectory.
The token file is a separate read-only mount at `/var/lib/proxmoxmcp/tokens.json`.
Configuration under `/etc/proxmoxmcp` stays read-only.

## 4. Run it — lab mode

Identical but for `--lab-mode`, and a different published port so both can run
side by side. Use the same `$image` variable captured above:

```bash
docker run -d --name proxmox-labmode \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:30043:30031 \
  -v "$PWD/clusters.json:/etc/proxmoxmcp/clusters.json:ro" \
  -v "$PWD/secrets:/etc/proxmoxmcp/secrets:ro" \
  -v "$PWD/state:/var/lib/proxmoxmcp" \
  -v "$PWD/tokens.json:/var/lib/proxmoxmcp/tokens.json:ro" \
  "$image" \
  --transport streamable-http --host 0.0.0.0 --port 30031 \
  --allow-insecure-bind \
  --state-file /var/lib/proxmoxmcp/changeset-state.json \
  --allowed-host 127.0.0.1:30043 --allowed-host localhost:30043 \
  --allowed-origin http://127.0.0.1:30043 --allowed-origin http://localhost:30043 \
  --lab-mode
```

**Note the port asymmetry, because it catches people.** The server always
listens on `30031` *inside* the container; `-p 30043:30031` publishes it as
30043 on the host. But `--allowed-host` and `--allowed-origin` are matched
against the `Host` and `Origin` headers the **client** sends, and the client is
talking to 30043. So those flags carry the *published* port, not the internal
one. Get this wrong and the server starts cleanly and then refuses every request
with `421`.

Lab mode waives approval on creation for **protected** guests and records
`approval_waiver=lab-mode`; an ordinary guest still requires a second
principal. Never point it at a production cluster.

## 5. Verify

```bash
docker ps --filter name=proxmox- --format '{{.Names}} {{.Status}}'

curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30033/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:30043/mcp \
     -H 'content-type: application/json' -d '{}'    # 401
```

**`401` is the success case**: the transport is up and authentication is being
enforced. `000` means nothing is listening — check `docker logs`. A `421` means
the allow-lists do not match the address the client used.

Confirm the mode is what you intended:

```bash
docker logs proxmox-labmode 2>&1 | grep -i 'lab mode'
```

## 6. Stop

```bash
docker stop proxmox-twoperson proxmox-labmode
docker rm proxmox-twoperson proxmox-labmode
```

`docker stop` sends SIGTERM and waits, which lets the server finish in-flight
work and flush its state. Avoid `docker kill` for anything holding change-set
state: a process killed mid-write leaves an operation non-terminal, and the next
caller finds the guest blocked.

## Troubleshooting

All of these were hit while writing this document or during the 2026-09-07 rig
rebuild.

**`error: the argument '--clusters-file <PATH>' cannot be used multiple times`**
You passed a flag the `ENTRYPOINT` already sets. `--clusters-file` and
`--tokens-file` are preset and must not be repeated; only the `CMD` flags
(`--transport`, `--host`, `--port`) are yours to supply. See the section at the
top of this document.

**`token file /etc/proxmoxmcp/tokens.json: No such file or directory`**
The tokens file is mounted to the wrong path. The image expects
`/var/lib/proxmoxmcp/tokens.json` by default, but some deployments use
`/etc/proxmoxmcp/tokens.json`. Check which path your `--tokens-file` flag
points to and mount the file there. This inconsistency is tracked in
mechubsec/mecmcp#356.

**`421` on every request after the server starts cleanly**
The `--allowed-host` and `--allowed-origin` values do not match the address
the client is using. These flags match against the headers the **client**
sends, not the internal listen address. If the container publishes
`-p 30043:30031`, the client talks to 30043 on the host, so the allow-lists
must carry 30043. Check `docker logs` for the exact header values the server
received.

**Permission denied reading the inventory or writing state** — the container
process is UID 65532 and does not own your files. Either `chown -R 65532:65532`
them, or run with `--user "$(id -u):$(id -g)"` as shown above.

**Container exits immediately with no log output** — check `docker logs` on the
stopped container: `docker ps -a --filter name=proxmox-`. Startup validation
failures print and exit before the transport is up, so the container is gone by
the time you look for it with plain `docker ps`.
