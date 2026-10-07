<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">rustproxmoxmcp</h1>

<p align="center"><strong>One Rust MCP server for many Proxmox VE clusters</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

> **Unofficial / community project.** This is an independent community project and does not claim affiliation with or endorsement by Proxmox Server Solutions GmbH. Product names and trademarks are used only to identify the systems with which the software interoperates.

---

## Status: 0.10.0 — the tool surface is complete but for two gaps

**50 callable tools**: 31 read, 18 `low`, and `apply_proxmox_change_set` as the
single `destructive` entry point. Seven further names --- `delete_vm`,
`delete_container`, `delete_snapshot`, `delete_backup`, `delete_iso`,
`restore_backup`, `rollback_snapshot` --- are **authorization scopes, not
tools**: a token grants them by name and reaches them through
`plan_proxmox_destroy`. `KNOWN_TOOLS` therefore holds 57 entries.

### What is still missing

- **`execute_vm_command`.** Deliberate. The design spec makes it conditional on
  `mecmcp-policy` compiling an allow/deny rule set over the command subject, and
  that is not wired. Arbitrary command execution inside every guest is remote
  code execution as a tool call; it ships with a policy engine or not at all.
- **Restore to a *new* VMID.** `restore_backup` exists but is not equivalent to
  the third-party server's: the plan resolves an **existing** guest and the
  apply passes `force=true`, so a same-shaped call overwrites rather than
  creates. This is the gap most likely to be missed, because the tool exists and
  the call succeeds.

Both are tracked in #57. Everything else the third-party `proxmox-mcp` offers
has an equivalent here --- see `docs/MIGRATING-FROM-PROXMOX-MCP.md`, which also
lists the arguments that changed shape.

### Change control

Destructive work goes through plan → approve → apply. The plan renders a
server-generated preview and records the action; the approval binds the plan
digest over `(owner, device, expected fingerprint, actions)`; the apply
re-checks the guest's fingerprint and refuses one that moved.

Two things worth stating plainly, because both are easy to assume wrongly:

- **The approval binds the preview.** Since mecmcp 0.23.0 the approval digest
  covers the stored preview's hash alongside the plan, so an approver commits to
  the exact text they were shown as well as to the operation and its parameters.
  The coordinator refuses any later write that swaps or drops that preview once
  an approval exists (#56).

  This reverses what earlier revisions of this section said. Before 0.23.0 the
  preview was stored with its own hash but was not part of the digest, so an
  approver committed to the action and the preview was merely rendered from it.
- **`--lab-mode` is the *protection* override, not a blanket waiver.** It
  supplies the override a protected guest needs, so on a lab-mode server a
  **protected** guest is approved on creation with no second principal, while an
  **ordinary** guest still requires one and self-approval is refused. That
  inversion surprises people.

`--waivers-file` (default `/etc/proxmoxmcp/waivers.json`, mode 0600,
service-owned) carries time-boxed operator waivers. Both overrides originate
outside the tool call: **there is deliberately no `grant_waiver` tool and no
`force` argument**, because an override a caller can pass is not an override.

- **A waiver lifts protection only, never the second approver.** A matching
  waiver lets a plan against a protected guest proceed past the protection
  gate; the resulting change set still goes through the normal
  plan → approve → apply flow and still needs a distinct human approver (or
  `--lab-mode`, which is the one path that also waives approval). The
  waiver's reason and ticket are printed in the stored preview so the
  approver can see why protection was lifted before deciding whether to
  also approve.

#### `waivers.json` schema

```json
{
  "version": 1,
  "waivers": [
    {
      "cluster": "pve3",
      "vmid": 905,
      "until": "2026-12-31T23:59:59Z",
      "reason": "decommission per CHG-1234",
      "ticket": "CHG-1234",
      "ops": ["destroy_guest"],
      "principal": "ops-token"
    }
  ]
}
```

- **`ops` is required and non-empty.** A waiver file version 1 entry with no
  `ops` field, or an empty list, is refused at load -- the server will not
  start with a waiver that covers no operation. This is a breaking,
  intentionally fail-closed change from pre-MEC-447 waiver files, which had
  no `ops` field at all: re-add every entry with the exact operation(s) it
  should cover before upgrading.
- **`principal` is optional.** When set, the waiver only matches that one
  token name; when absent, it matches any caller. This names the token that
  **plans** the operation, not the one that approves or applies it --
  `approve_proxmox_change_set` and `get_proxmox_change_set` evaluate the
  waiver against the planner recorded on the change set, because the
  two-person rule requires the approver to be a distinct principal from the
  planner. A `principal`-bound waiver therefore refuses an apply run by a
  caller other than the planner, which is the intended fail-closed outcome,
  not a bug.
- **The `op` strings `ops` must name** depend on which path the waiver
  covers:
  - A destructive operation planned through `plan_proxmox_destroy`: the
    `op` argument passed to that call (`destroy_guest`, `delete_snapshot`,
    `rollback_snapshot`, `delete_backup`, `delete_iso`, `restore_backup`,
    `migrate`, `update_vm_config`).
  - A service-interrupting `low`-tier tool (for example `stop_vm`,
    `stop_container`, `reboot_vm`): the tool's own name.
  - An HA rule change planned through `plan_ha_rule_change`: `ha_rule_`
    followed by that call's `op` (`ha_rule_create`, `ha_rule_update`,
    `ha_rule_delete`).
  - A firewall change planned through `plan_firewall_change`: `firewall_`
    followed by the object and the operation (`firewall_rule_create`,
    `firewall_options_update`, `firewall_ipset_entry_delete`).
  - A restore that targets a *new* VMID (`restore_backup_new_vmid`): the
    fixed string `restore_new_vmid`, naming the archive owner guest the
    waiver protects, not the new VMID.

  A waiver that misspells or omits the operation it was meant for matches
  nothing -- the call is refused the same as if no waiver existed.

- **`approve_proxmox_change_set` requires a human approver token.** The
  server passes the caller's token `actor_type` through to mecmcp, which
  refuses any approval from an `agent` or unattributed (stdio) caller --
  only `actor_type: human` can approve. Mint the approver's token with
  `rust-proxmoxmcp token add ... --actor-type human`. `actor_type` is a
  claim the operator makes at mint time, not something the server proves;
  a token tagged `human` but handed to an LLM agent defeats the gate.

### What's implemented

- **Multi-cluster inventory:** One server, many clusters. Each cluster gets its own API token and protection policy.
- **Two-stage authorization:**
  1. **Stage 1** (before the catalog call): Bearer token validation, tool and cluster scope checks.
  2. **Stage 2** (guest-addressed tools only): Guest resolution, grant evaluation (VMID range, tag, pool selectors), and fail-closed protection.
- **Protection union:** A guest is protected if it appears in `protected_vmids` **or** carries a tag from `protected_tags`. A protected guest is refused by every destructive and service-interrupting tool unless a waiver or lab mode supplies an override. (Read tools see protected guests normally.)
- **A guest-addressed tool never accepts the node from the caller.** It resolves it on every call, and again at apply, because guests migrate. Node-, storage- and task-scoped tools (`get_node_status`, `get_storage`, `list_backups`, `list_isos`, `list_templates`, `list_tasks`, `get_task_status`, `download_iso`, `get_node_firewall_rules`, `get_node_firewall_options`) do take a `node`, because a node is what they address --- there is no guest to resolve one from. The exception that matters is `create_vm`/`create_container`: they name a *guest* but the guest does not exist yet, so the caller supplies the node, and it is the one place a guest-addressed call can reach the wrong host. `stop_task` is deliberately not in that list: it reads the node from the UPID.
- **Catalog-driven dispatch:** Every read tool's HTTP method, path template, query flag, and type filter is declared once in `catalog.rs`.
- **In-flight recovery:** A change set left `Applying` with a task handle is re-probed at startup, so an apply interrupted by a restart resolves rather than staying unresolved forever.
- **SIGHUP reload:** `systemctl reload` reloads `clusters.json` in place without dropping in-flight calls. A failed reload logs and retains the previous snapshot.
- **Per-cluster CA pinning:** Each cluster can name a `ca_pem_path`. There is **no insecure-skip-verify at any layer**, so a cluster with a private CA needs its CA installed and must be addressed by a name its certificate covers.
- **Audit logging:** JSON-structured logs with optional PII redaction (HMAC-keyed or drop). Every tool call logs cluster, guest, tier, and protection status.

### The 31 read tools

| Tool | Scope | Description |
|------|-------|-------------|
| `get_cluster_status` | cluster | Quorum and node membership |
| `get_nodes` | cluster | All nodes with status and resource totals |
| `get_node_status` | node | Detailed status for one node |
| `get_vms` | cluster | All QEMU guests with node, status, tags (paginated: `offset`/`limit`, default 500, max 700) |
| `get_containers` | cluster | All LXC guests with node, status, tags (paginated: `offset`/`limit`, default 500, max 700) |
| `get_vm_config` | guest (QEMU only) | Configuration including Proxmox digest, with `description`/`cicustom`/`args` content redacted on a best-effort basis -- credential-shaped text is stripped, but this is not a safe place to store secrets (sshkeys and network config preserved) |
| `get_container_config` | guest (LXC only) | Configuration including Proxmox digest, with `description`/`cicustom`/`args` content redacted on a best-effort basis -- credential-shaped text is stripped, but this is not a safe place to store secrets (sshkeys and network config preserved) |
| `get_container_ip` | guest (LXC only) | Network interfaces and addresses |
| `get_guest_status` | guest | Current runtime status |
| `list_snapshots` | guest | Snapshots of one guest |
| `get_storage` | node | Storage backends visible to one node |
| `list_backups` | storage | Backup archives on one storage backend (paginated: `offset`/`limit`, default 500, max 700) |
| `list_isos` | storage | ISO images on one storage backend |
| `list_templates` | storage | Container templates on one storage backend |
| `list_tasks` | node | Recent tasks on one node (not paginated -- Proxmox applies its own server-side window, typically the 50 most recent) |
| `get_task_status` | task | Status of one task by UPID |
| `get_proxmox_change_set` | change set | One change set's state and preview |
| `get_cluster_firewall_rules` | cluster | Cluster-wide firewall rules |
| `get_cluster_firewall_options` | cluster | Cluster-wide firewall options (enable, default policy) |
| `list_firewall_security_groups` | cluster | Security groups defined on the cluster |
| `get_firewall_security_group_rules` | cluster + group | Rules contained in one security group |
| `list_firewall_ipsets` | cluster | Cluster-wide IPSets |
| `get_firewall_ipset_entries` | cluster + ipset | CIDR entries in one cluster-wide IPSet |
| `list_firewall_aliases` | cluster | Cluster-wide firewall address aliases |
| `get_node_firewall_rules` | node | Firewall rules on one node |
| `get_node_firewall_options` | node | Firewall options on one node |
| `get_guest_firewall_rules` | guest | Firewall rules of one guest |
| `get_guest_firewall_options` | guest | Firewall options of one guest |
| `list_guest_firewall_aliases` | guest | Firewall address aliases of one guest |
| `list_guest_firewall_ipsets` | guest | IPSets defined on one guest |
| `get_guest_firewall_ipset_entries` | guest + ipset | CIDR entries in one IPSet of one guest |

The three type-specific reads refuse the other guest type by name rather than
addressing an endpoint that cannot exist.

Firewall reads mirror the scopes Proxmox itself exposes: node-level firewall
config has rules and options but no aliases, IPSets or security groups —
those exist only at cluster and guest scope. Firewall writes use
`plan_firewall_change`, `approve_firewall_change` and `apply_firewall_change`.
A firewall write without an approved change set is refused. Lab-mode and
two-person approval follow the same rules as the other governed writes:
`--lab-mode` approves a plan for a protected guest with no second principal,
while an ordinary guest, and a cluster or node firewall, still require one.

**Pagination:** `get_vms`, `get_containers` and `list_backups` have no bound
on cluster/node/storage size and can exceed the MCP result's 512 KiB cap on
a large deployment. They take an optional `offset` and `limit` (default
500, max 700 -- sized to stay comfortably under the cap) and return
`{items, total, offset, limit, has_more}` rather than a bare array, so a
caller can tell a short list from one that needs another page. A `limit`
above 700 is refused, not silently clamped. Pages are not a snapshot: each
call re-fetches the full upstream list and is sorted by `vmid` (guests) or
`volid` (backups) before slicing, so a record only shifts pages if it's
created or deleted between calls, never from reordering. `list_tasks` is
deliberately *not* paginated here: Proxmox's `/nodes/{node}/tasks` applies
its own server-side window with no total this client can learn, so a page
on top of it would misreport a truncated list as complete.

### The 18 low tools

Lifecycle: `start_vm`, `stop_vm`\*, `shutdown_vm`\*, `reset_vm`\*,
`start_container`, `stop_container`\*, `restart_container`\*.

Provisioning: `create_vm`, `create_container`, `clone_vm`, `download_iso`,
`resize_disk`, `create_snapshot`, `create_backup`,
`update_container_resources`\*.

Tasks and change sets: `stop_task`\*, `plan_proxmox_destroy`,
`approve_proxmox_change_set`.

\* interrupts a running guest. That axis is tracked separately from the tier: a
tool can be `low` and still take a service down, and the protection gate applies
to both.

Notes that catch people out:

- `create_container` defaults to `unprivileged=1`. Proxmox reads an omitted
  field as privileged, so silence must not select the dangerous option.
- Config keys that reach the hypervisor are refused: `hookscript`, `args`, `mpN`
  host mounts, `hostpciN`/`usbN`/`devN`/`serialN`/`parallelN` passthrough, raw
  `lxc.*`, and any value carrying an absolute host path. A create is a `low`
  operation and must not become code execution on the node.
- A create refuses a VMID that already exists. Proxmox restores a backup by
  POSTing to the same endpoint, so without that check a `low` create could
  overwrite a live guest.
- `resize_disk` grows only. Shrinking is unsupported here **and in Proxmox** ---
  `qm resize` and `pct resize` reject a reduction.
- Container stops are immediate. There is no graceful LXC path: `shutdown_vm` is
  QEMU-only.

## Changing a token's scopes

`token set-scopes` changes a token's device, tool, guest, and action scopes
**without reissuing its secret**, so no client is reconfigured:

```
rust-proxmoxmcp token set-scopes --tokens-file <PATH> --name <NAME> \
  [--devices <CSV|*>] [--tools <CSV|*>] \
  [--guests <SELECTORS|*>] [--actions read,low,destructive] [--yes]
```

An omitted `--devices`/`--tools` leaves that scope unchanged. `--guests` and
`--actions` replace the grant **wholesale** rather than merging — a guest grant
is a scope where "I meant to replace it" must not silently mean "I added to
it" — and `--actions` alone is refused, because a grant carries both halves and
inventing the other would grant reach nobody named.

Widening is a privilege escalation and is confirmed interactively unless
`--yes` is passed; narrowing is not, because reducing a scope cannot grant
anything.

**`--tools '*'` does not reach a mutating tool.** `WRITE_TOOLS` is deliberately
excluded from the tool wildcard, so `start_vm` and its peers must be named
explicitly or the preflight refuses with `403 insufficient_scope`.

## Authorization model

### Stage 1: Bearer token and scope

Every streamable-HTTP call carries a bearer token. The token store (`tokens.json`) binds the token to:
- A **tool scope** (`tools: ["*"]` or `tools: ["get_nodes", "get_vms"]`)
- A **device scope** (`devices: ["*"]` or `devices: ["pve3"]`)
- A **grant** (see stage 2)

Stage 1 refuses:
- An invalid or missing bearer token (unless `--allow-no-auth` on loopback)
- A tool not in the token's `tools` list
- A cluster not in the token's `devices` list
- Any tool in `WRITE_TOOLS` that a wildcard scope tried to reach. `tools: ["*"]` deliberately excludes that registry, so a wildcard token reaches no mutating tool: each must be named explicitly.

Tokens with no `grant` key are **refused for guest-addressed tools**. This is fail-closed: a token that declares no guest selector must not become a wildcard.

### Stage 2: Guest resolution and protection

Guest-addressed tools resolve the VMID to a `GuestFacts` record (name, node, type, tags, pool) and evaluate the token's **grant**:

```json
{
  "guests": ["vmid:600-699", "tag:disposable", "pool:test-vms"],
  "actions": ["read"]
}
```

A guest is in scope when **any** selector term matches. The server then checks the **protection union**:

- A guest is protected if it appears in the cluster's `protected_vmids` **or** carries a tag from `protected_tags` (default: `["protected"]`).
- A protected guest **cannot be addressed by any mutating tool**, even with `"guests": ["*"]`.
- Read tools see protected guests normally.

If the guest is out of scope or the action tier (`read`/`low`/`destructive`) is not in the token's grant, the server refuses with a non-leaking error: "authorization failed" with no guest details.

## Configuration

### Cluster inventory: `clusters.json`

```json
{
  "version": 1,
  "devices": {
    "pve3": {
      "endpoint": "https://pve3.example.org:8006",
      "token_id": "mcp-automation@pve!mcp",
      "token_secret_env": "PVE_PVE3_TOKEN",
      "protected_vmids": [905, 906, 907],
      "protected_tags": ["protected"]
    }
  },
  "policy": {
    "resource_cache_ttl_secs": 10
  }
}
```

**Note:** The top-level key is `devices`, not `clusters` — this is the canonical envelope from `mecmcp-inventory`, and the server reads each entry as a cluster.

**Credentials never appear in this file.** Each cluster references its API token secret through one of two mechanisms:

- **`token_secret_file`** (default): Points to a separate file like `/etc/proxmoxmcp/secrets/<cluster>.token`. This is the stronger option — the file is read through the same hardened loader as `clusters.json` and `tokens.json` (0600, regular file, owned by the service user, `O_NOFOLLOW`), and the credential never enters the process environment where it could surface in crash dumps or `/proc/<pid>/environ`.
- **`token_secret_env`**: Names an environment variable. Supported via `EnvironmentFile=-/etc/proxmoxmcp/secrets.env` in the systemd unit (the `-` prefix makes a missing file non-fatal). The environment-variable path is weaker because the credential becomes readable from the process environment.

Both are loaded through `mecmcp-secret` into an `OutboundSecret` that is zeroized on drop and implements neither `Debug` nor `Serialize`.

### The Proxmox-side token: least privilege, not `root@pam`

`token_id` names a Proxmox API token, and that token's *Proxmox-side*
privileges are a second authorization boundary this server does not control.
Stage 1 and stage 2 (above) gate what an MCP caller can do; they say nothing
about what the underlying Proxmox credential is allowed to do once a request
reaches the cluster. Handing this server a `root@pam!...` token collapses that
second boundary: `root@pam` is Proxmox's hardcoded superuser and bypasses ACL
checks entirely — see
[Proxmox VE's own user management documentation](https://pve.proxmox.com/wiki/User_Management)
— so no role, no path scoping, and nothing in `clusters.json` can constrain
it. A bug in this server, a stolen token, or an over-broad `grant` in
`tokens.json` would then fail open onto full cluster control instead of
failing closed onto a bounded role.

Create a dedicated, non-root user in the `pve` realm instead, with a custom
role that carries only the privileges this server's tools actually use:

```sh
# A role scoped to exactly what rustproxmoxmcp's tools call, no more.
pveum role add ProxmoxMcp -privs "VM.Audit,Sys.Audit,Datastore.Audit,VM.PowerMgmt,VM.Snapshot,VM.Snapshot.Rollback,VM.Backup,VM.Clone,VM.Config.Disk,VM.Config.CPU,VM.Config.Memory,VM.Allocate,Datastore.AllocateSpace,Datastore.AllocateTemplate,Sys.AccessNetwork"

# A service account with no interactive password -- it is only ever reached
# through its API token.
pveum user add mcp-automation@pve --comment "rustproxmoxmcp service account"

# Grant the role cluster-wide (`/`), matching this server's own reach: guests
# migrate between nodes and clusters.json addresses a whole cluster, not one
# VM or pool. An operator who wants to scope one token to one pool of guests
# can grant ProxmoxMcp at `/pool/<name>` instead and mint a separate token per
# pool; that is a deployment choice this server does not require.
pveum acl modify / --users mcp-automation@pve --roles ProxmoxMcp

# --privsep 0: the token carries exactly the user's own permissions, so the
# role above is the token's complete privilege set with nothing left to grant
# or forget on a separate token-level ACL.
pveum user token add mcp-automation@pve mcp --privsep 0
```

The last command prints the token secret once. Put it in the file
`token_secret_file` points to (or the variable `token_secret_env` names) —
never in `clusters.json` itself.

Every privilege in `ProxmoxMcp` maps to specific tools this server registers.
Nothing else is granted: no `Sys.PowerMgmt` (node reboot), no `VM.Console` or
`Sys.Console`, no `VM.Migrate`, no `Pool.*`/`Group.Allocate`/`Realm.Allocate`/
`Permissions.Modify` — this server never calls the Proxmox endpoints those
privileges guard.

| Privilege | Tool(s) that need it |
|-----------|----------------------|
| `VM.Audit` | Every guest-scoped read: `get_vms`, `get_containers`, `get_vm_config`, `get_container_config`, `get_container_ip`, `get_guest_status`, `list_snapshots`, `get_guest_firewall_rules`, `get_guest_firewall_options`, `list_guest_firewall_aliases`, `list_guest_firewall_ipsets`, `get_guest_firewall_ipset_entries`, and the guest resolve/fingerprint read every plan and apply performs |
| `Sys.Audit` | `get_cluster_status`, `get_nodes`, `get_node_status`, `list_tasks`, `get_task_status`, `get_cluster_firewall_rules`, `get_cluster_firewall_options`, `list_firewall_security_groups`, `get_firewall_security_group_rules`, `list_firewall_ipsets`, `get_firewall_ipset_entries`, `list_firewall_aliases`, `get_node_firewall_rules`, `get_node_firewall_options` |
| `Datastore.Audit` | `get_storage`, `list_backups`, `list_isos`, `list_templates` |
| `VM.PowerMgmt` | `start_vm`, `stop_vm`, `shutdown_vm`, `reset_vm`, `start_container`, `stop_container`, `restart_container` |
| `VM.Snapshot` | `create_snapshot`, `delete_snapshot` (an apply-time `plan_proxmox_destroy` op) |
| `VM.Snapshot.Rollback` | `rollback_snapshot` (an apply-time op) |
| `VM.Backup` | `create_backup`, `restore_backup` (an apply-time op) |
| `VM.Clone` | `clone_vm` |
| `VM.Config.Disk` | `resize_disk` |
| `VM.Config.CPU`, `VM.Config.Memory` | `update_container_resources` (cores vs. memory/swap) |
| `VM.Config.Network` | Guest firewall apply (`apply_firewall_change` for one guest). Proxmox checks this on `/vms/{vmid}` |
| `VM.Allocate` | `create_vm`, `create_container`, `delete_vm`/`delete_container` (the `destroy_guest` apply-time op), and `restore_backup` when it overwrites an existing VMID |
| `Datastore.AllocateSpace` | `create_vm`/`create_container` (disk allocation), `create_backup`, `delete_backup` |
| `Datastore.AllocateTemplate` | `download_iso` (the destination storage) |
| `Datastore.Allocate` | `delete_iso`. **Optional add-on, not in the base role** — see below |
| `Sys.AccessNetwork` | `download_iso` (`download-url`), granted on `/nodes/{node}`. `API2/Storage/Status.pm` accepts either this privilege scoped to the node, or `Sys.Audit`+`Sys.Modify` on `/` — the node-scoped grant is the one that does not also hand out node reboot/network/disk-wipe access. `Sys.AccessNetwork` for `download-url` requires PVE 8+; on older clusters use the broader `Sys.Audit`+`Sys.Modify` pair on `/` instead |

`Datastore.Allocate` is deliberately **not** in the role above. `delete_iso`
is the only tool that needs it, and Proxmox's `API2/Storage/Content.pm`
delete handler checks it on the *storage*, not on a single ISO volume — there
is no Proxmox privilege that grants "delete this one ISO" without also
granting "modify or remove this storage's definition." Granting it at `/`
(as the base role does) makes the token an admin of every storage in the
cluster: it could delete a storage definition cluster-wide, repoint one, or
add a new NFS/CIFS/PBS mount that every node then connects to. If this
deployment needs `delete_iso`, scope the grant to the one storage that holds
ISOs instead of the whole cluster:

```sh
# Optional: only if delete_iso must work. Scoped to one storage, not `/` —
# still lets the token edit or remove *that storage's* definition, but not
# any other storage in the cluster.
pveum role add ProxmoxMcpIsoDelete -privs "Datastore.Allocate"
pveum acl modify /storage/<iso-storage> --users mcp-automation@pve --roles ProxmoxMcpIsoDelete
```

`Sys.Modify` on `/` is deliberately **not** in the role above. Cluster and
node firewall apply needs it (cluster objects on `/`, a node's firewall on
`/nodes/{node}`), and `stop_task` needs it when `API2/Tasks.pm` is stopping a
task the caller does not own. This server's own tasks always belong to its
own token, so stopping those needs nothing extra. Plan and approve of a
firewall change only read (`Sys.Audit` or `VM.Audit`). `Sys.Modify` at `/` is
a broad node-admin grant — node network config, disk init and wipe, `apt`,
and more — so add it only when this token must apply a cluster or node
firewall change, or stop tasks that *other* principals started:

```sh
pveum role modify ProxmoxMcp -privs "...,Sys.Modify" # append to the existing list
```

**Unverified, check on a lab PVE before relying on it in production:**
`create_vm`, `create_container`, and `clone_vm` calls that attach a network
device likely also need `SDN.Use` on the bridge on PVE 8+. This role list has
not been exercised against SDN-managed bridges; if your cluster uses them,
test a plan/apply cycle against a disposable guest first.

`plan_proxmox_destroy`, `approve_proxmox_change_set` and
`get_proxmox_change_set` issue no Proxmox API call of their own beyond the
guest-resolve read (`VM.Audit`, already listed above) — approval is local
bookkeeping in this server's own change-set store. The Proxmox privilege a
plan will need is whichever row above names its `op`, and that privilege is
only spent when `apply_proxmox_change_set` actually executes it.

### Token store: `tokens.json`

```json
{
  "version": 1,
  "tokens": {
    "demo-reader": {
      "hash": "$argon2id$v=19$m=...",
      "grant": {
        "guests": ["vmid:600-699"],
        "actions": ["read"]
      },
      "tools": ["*"],
      "devices": ["pve3"]
    }
  }
}
```

Mint a token with `rust-proxmoxmcp token add <name>`. The plaintext token is printed once and never recoverable. Pass `--actor-type human` for any token that will approve change sets -- see [Change control](#change-control).

**IMPORTANT:** A token without a `grant` key is refused for guest-addressed tools. To grant read access to all guests:

```json
"grant": {
  "guests": ["*"],
  "actions": ["read"]
}
```

## CLI flags

`rust-proxmoxmcp` inherits every flag from `mecmcp_runtime::cli::Cli` (transport, bind, TLS, allowed hosts/origins, audit) and adds exactly one:

- `--clusters-file <path>` — Cluster inventory (default: `/etc/proxmoxmcp/clusters.json`)

For streamable-HTTP, either `--tokens-file` or `--allow-no-auth` is required. The latter permits unauthenticated read requests on loopback only; write tools remain denied.

Run `rust-proxmoxmcp --help` for the complete list.

## Installation

See [docs/HOW-TO-SETUP-LXC.md](docs/HOW-TO-SETUP-LXC.md) for step-by-step instructions on building a rust-proxmoxmcp LXC from scratch. For Docker, see [docs/HOW-TO-SETUP-DOCKER.md](docs/HOW-TO-SETUP-DOCKER.md).

### Run with Docker

For an interactive stdio server, prepare `clusters.json`, `tokens.json`, a
`secrets/` directory, and a writable `state/` directory. The inventory uses
the canonical `devices` envelope:

```json
{
  "version": 1,
  "devices": {
    "pve-demo": {
      "endpoint": "https://198.51.100.10:8006",
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

The token store and secret file contain placeholder credentials until you
replace them with values created for your Proxmox deployment. They must be
regular files with mode `0600`, owned by UID/GID `65532:65532` (the image's
runtime user); the mounted state directory must also be writable by that UID:

```bash
chmod 0600 tokens.json secrets/pve-demo.token
chown 65532:65532 tokens.json secrets/pve-demo.token state

docker run --rm -i \
  -v "$PWD/clusters.json:/etc/proxmoxmcp/clusters.json:ro" \
  -v "$PWD/tokens.json:/var/lib/proxmoxmcp/tokens.json:ro" \
  -v "$PWD/secrets:/etc/proxmoxmcp/secrets:ro" \
  -v "$PWD/state:/var/lib/proxmoxmcp/state:rw" \
  ghcr.io/mechubsec/rustproxmoxmcp:latest \
  --transport stdio
```

The command preserves the image's `ENTRYPOINT` paths and replaces its HTTP
`CMD` with stdio, so this invocation leaves inbound HTTP and TLS off. See the
[Docker how-to](docs/HOW-TO-SETUP-DOCKER.md) for the two-person and lab-mode
streamable-HTTP setup.

`packaging/lxc/install.sh` is a POSIX installer targeting Debian 13 LXC. The installer:
- Creates the `proxmoxmcp` system user
- Installs the binary to `/usr/local/bin/rust-proxmoxmcp`
- Installs example config files to `/etc/proxmoxmcp` (mode 0600, owned by `proxmoxmcp`) **only if absent**
- Installs the hardened systemd unit with `ProtectSystem=strict` and `ReadWritePaths=/var/lib/proxmoxmcp`
- Prints next steps and a reminder to snapshot the container before upgrading

**Before upgrading:** Snapshot the container in Proxmox. A failed upgrade can be reverted by rolling back to the snapshot.

## Development notes

### Crate structure

- `rust-proxmoxmcp-core`: Domain logic (inventory, resolution, authorization, catalog). No server or transport.
- `rust-proxmoxmcp`: The binary. Assembles the transport, loads the inventory, and serves the catalog.

### The `testing` feature

The core crate has a non-default `testing` feature that pulls in `rcgen`, `rustls`, `tokio-rustls`, and `tempfile` to build mock HTTPS servers for the test suite. This machinery is **not** compiled into the release binary.

## Sibling servers

| | [rustjunosmcp](https://github.com/mechubsec/rustjunosmcp) | [rustpanosmcp](https://github.com/mechubsec/rustpanosmcp) | [rustmistmcp](https://github.com/mechubsec/rustmistmcp) | [rustunifimcp](https://github.com/mechubsec/rustunifimcp) | [rustsdcmcp](https://github.com/mechubsec/rustsdcmcp) | rustproxmoxmcp |
|---|---|---|---|---|---|---|
| Vendor | Juniper Junos / SRX | Palo Alto PAN-OS | Juniper Mist | Ubiquiti UniFi Network | HPE Juniper Security Director Cloud | Proxmox VE |
| Transport | NETCONF over SSH | HTTPS XML-API | HTTPS REST | HTTPS REST | HTTPS REST | HTTPS REST |
| Status | shipping, v0.25.0 | shipping, v0.14.0 | foundation built, read-only live-tenant acceptance passed | in production | pre-release (v0.1.0-lab) | shipping, v0.10.0 |

All six consume `mecmcp` — the shared Rust crate family underneath mechub's per-vendor MCP servers.

## Audit forwarding to the event store

The audit trail does not stay on this host. This server follows the family
standard — [AUDIT-FORWARDING-STANDARD.md](https://github.com/mechubsec/mecmcp/blob/main/docs/AUDIT-FORWARDING-STANDARD.md).

An audit record that only exists on the machine that produced it is not an audit
trail: it is a log file on a box whose operator is the party the record is about.

### Emission (in effect now)

```
--audit-format json \
--audit-log-file /var/lib/proxmoxmcp/audit.jsonl
```

JSON is mandatory. The `text` format is for reading in a terminal and is not a
parse target. The file is the operator-facing artifact and must be rotated — the
server never truncates it itself, but it keeps the file handle
`mecmcp_audit::init_tracing` returns and reopens it by path on `SIGHUP`, so
rotation is lossless as long as the rotator renames the file and signals the
process.

A ready-to-install fragment ships at
[`packaging/logrotate/rust-proxmoxmcp-audit`](packaging/logrotate/rust-proxmoxmcp-audit):

```
/var/lib/proxmoxmcp/audit.jsonl {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    su proxmoxmcp proxmoxmcp
    postrotate
        systemctl kill -s HUP rust-proxmoxmcp.service >/dev/null 2>&1 || true
    endscript
}
```

**Rename + reopen, not `copytruncate`.** `SIGHUP` reopens the audit file by
path alongside the existing `clusters.json`/`tokens.json` hot reload, so
`postrotate` renames the file and signals the process; every write after that
lands in a fresh inode at the same path. Nothing written before the rename is
truncated and nothing written after it is lost — `copytruncate` copies the
file and then truncates it in place, which drops whatever is written in the
gap between those two steps.

### Transport (specified, not yet implemented)

Records are written directly into SSDF's `ssdf.audit` as **hash-chained** rows,
per SSDF's merged evidence contract, so that deleting or editing a row is
detectable. Tracked in [mecmcp#292](https://github.com/mechubsec/mecmcp/issues/292).

A cheaper syslog path was designed and rejected: it works, but the records are
unchained, and every other link here is tamper-evident by construction — plan
digests bind approvals, approvals name a distinct principal, and
`token_verified_fields` separates vouched-for provenance from asserted. An
unchained final hop would discard that guarantee exactly where an auditor needs
it. The reasoning is recorded in the standard.

### Reading the result

`token_verified_fields` names the provenance fields the **token** vouched for.
The rest of that group — `client_name`, `model_id`, `session_id` — is
client-asserted and authenticated by nothing. Do not read them as equivalent.

`request_id` correlates the transport event, the handler event, and (on Junos)
the device commit comment.

## License

## Operations and Security

### Egress filtering

The packaged unit declares `IPAddressDeny` and `IPAddressAllow` to control
egress. However, **systemd cannot enforce these directives in an unprivileged
LXC** — every guest in this fleet is one. systemd implements them with cgroup
BPF and fails open when it cannot load the program, so the unit can declare a
full egress policy while enforcing none of it. `systemd-analyze security` reads
the declaration and cannot tell the difference.

The installer probes actual enforcement and prints one of four verdicts:

- `egress filter: ENFORCED` — the host attaches the BPF program *and* the
  installed unit declares a policy
- `egress filter: NOT ENFORCED` — the host cannot attach it; guidance follows
- `egress filter: NO POLICY` — the host could enforce, but the installed unit
  declares no `IPAddressDeny` (a preserved customized unit overrides the
  packaged one; re-install to restore it)
- `egress filter: UNKNOWN` — the probe could not run; nothing is claimed

Both conditions matter. A host-capability check alone would report success over
a service filtering nothing.

The probe uses IP accounting, which rides the same BPF attachment, so a
populated counter proves the filter attached. Check it any time:

```console
systemctl show rust-proxmoxmcp.service -p IPEgressBytes --value
```

`[no data]` means the egress directives are doing nothing. Set
`PROXMOXMCP_REQUIRE_EGRESS_FILTER=1` to make the installer refuse anything short
of `ENFORCED` — including `UNKNOWN`, since an unmeasurable host is exactly as
unguaranteed as a non-enforcing one.

#### Enforcing it where systemd cannot

Any result other than `ENFORCED` means the unit directives are **unproven**, and
the control should move outward — to whatever layer actually sees this
workload's packets. `NOT ENFORCED` and `NO POLICY` mean they are demonstrably
doing nothing; `UNKNOWN` means nothing was measured and they may well be
working. Do not treat the last as the first.

The policy does not change with the runtime (though the unit allows RFC 1918 to
reach Proxmox API endpoints):

1. deny `169.254.0.0/16` and `fd00:ec2::254` — cloud metadata, the route from a
   compromised HTTP client to a stolen credential
2. deny link-local (`fe80::/10`) — not used by any supported target
3. deny the local subnet **except** your DNS resolver — blocks lateral movement
   while keeping name resolution working (not currently declared in this
   server's unit; add via drop-in if needed)

The mechanism does. Configure it with your platform's own documentation rather
than a recipe here — these are the layers, not instructions:

| Runtime | Layer that sees this workload's packets |
|---|---|
| Proxmox LXC / VM | per-guest interface firewall |
| libvirt / KVM | `nwfilter` on the guest interface |
| Kubernetes | `NetworkPolicy` egress, on a CNI that implements it |
| Cloud instance | in-guest packet filter for **both** metadata addresses, plus security groups for everything else |
| Bare metal, VM with working systemd | the unit directives; this section does not apply |

Two properties are worth checking whatever you choose, because both are common
and both produce a control that reads as present and is not:

- **Some layers accept egress policy without enforcing it.** Container network
  attachment and some CNI implementations are the usual cases.
- **Cloud metadata often bypasses the cloud firewall.** On EC2, IMDS traffic is
  handled below the security group and NACL layer, so an egress rule there does
  not block it. This applies to the IPv6 endpoint too — `fd00:ec2::254` is ULA
  rather than link-local, so it is easy to file mentally under "ordinary routed
  traffic the firewall sees", and it is not. The control has to be in-guest, or
  IMDS disabled outright. Consult your provider's current metadata-hardening
  guidance; it changes, and getting it wrong is silent.

Whichever you pick, a rule that has not been exercised from inside the workload
is an assumption. Verify it, and re-verify after a reboot — in-kernel firewall
rules are not persistent unless you made them so.


Licensed under [MIT](LICENSE).
