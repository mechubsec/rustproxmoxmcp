# Migrating from the third-party `proxmox-mcp`

For operators moving off the third-party server (LXC 970, tagged
`notmechub;protected`) to `rust-proxmoxmcp`.

Retirement here means **ceasing to depend on 970**, not acting on the guest.
It is not ours to modify.

## The behavioural difference that matters

The third-party server **deletes on a single call**. This one makes destruction
a governed change set:

```
plan_proxmox_destroy → approve_proxmox_change_set → apply_proxmox_change_set
```

The plan renders a server-generated preview and records the operation; the
approval binds the **plan digest**, which covers `(owner, device, expected
fingerprint, actions)`; and applying re-checks the guest's fingerprint.

**Know what the fingerprint covers before relying on it.** It is computed over
`cluster`, `vmid`, `name`, `kind`, `node`, `status`, `tags`, `config_digest`
and `disks`. `config_digest` and `disks` are read from the guest's live
configuration at both plan and apply, so a configuration-only change --
Proxmox's own config digest moving, or a disk being resized, added, or
removed -- also invalidates the fingerprint. What the re-check catches is a
guest that was renamed, migrated, stopped or started, retagged, reconfigured,
or replaced by one with different identity metadata.

`--lab-mode` waives the second principal for a single-operator lab, and
`--waivers-file` carries time-boxed operator waivers — both originate outside
the tool call, because an override a caller can pass is not an override.

Be precise about what the approval covers, because earlier drafts of this guide
have twice described it wrongly. **The preview is part of the digest.** Since
mecmcp 0.23.0 the approval digest covers the stored preview's hash alongside the
plan, so an approver is cryptographically committing to the exact text they were
shown as well as to the operation and its parameters, and the coordinator
refuses any later write that swaps or drops that preview.

Before 0.23.0 that was not so: the preview was stored with its own hash, which
stopped it being edited afterwards, but it was not hashed into the approval.

That is the reason to migrate. Everything below is the mechanics.

## Tool mapping

### Same name, same meaning

`get_cluster_status` · `get_nodes` · `get_node_status` · `get_vms` ·
`get_containers` · `get_vm_config` · `get_container_config` ·
`get_container_ip` · `get_storage` · `list_backups` · `list_isos` ·
`list_snapshots` · `list_templates` · `start_vm` · `stop_vm` ·
`shutdown_vm` · `reset_vm` · `start_container` · `stop_container` ·
`restart_container` · `create_snapshot` · `create_backup` · `clone_vm` ·
`resize_disk`

Guest-addressed tools take `(cluster, vmid)` only. **The node is never
accepted from the caller** — it is resolved on every call, because accepting a
node is how a request addresses the wrong guest after a migration.

### Reached through the change-set flow instead of directly

| third-party | here |
|---|---|
| `delete_vm` | `plan_proxmox_destroy` with `op: "destroy_guest"` |
| `delete_container` | `plan_proxmox_destroy` with `op: "destroy_guest"` |
| `delete_snapshot` | `op: "delete_snapshot"`, `snapname` |
| `rollback_snapshot` | `op: "rollback_snapshot"`, `snapname` |
| `delete_backup` | `op: "delete_backup"`, `storage` + `volid` + `storage_node` |
| `delete_iso` | `op: "delete_iso"`, `storage` + `volid` + `storage_node` |
| `restore_backup` | `op: "restore_backup"`, `volid` |
| `restore_backup` to a new VMID | `plan_restore_new_vmid` → `approve_proxmox_change_set` → `apply_restore_new_vmid`, with scope `restore_backup_new_vmid` |

Then `approve_proxmox_change_set` and `apply_proxmox_change_set`.

`delete_backup` and `delete_iso` also require `storage_node`: `local` is
node-local storage, so the same volid on two nodes names two different volumes.

Each operation additionally authorises against **its own tool name** — a token
allowlisted for `plan_proxmox_destroy` and `apply_proxmox_change_set` but not
`delete_backup` cannot select `op: "delete_backup"`. Name the operations you
need in the token scope, not just the two handlers.

### No equivalent, by decision

| third-party | why |
|---|---|
| `cancel_job` | use `stop_task` with the UPID. Restores, destroys and rollbacks are refused: stopping one half-way leaves a guest that is neither its old self nor its new one |
| `create_vm` | `create_vm`. Config keys are forwarded as given; those that reach the host are refused, and a VMID that already exists is refused rather than restored over |
| `create_container` | `create_container`, which defaults to `unprivileged=1` |
| `download_iso` | `download_iso`. Requires an unrestricted guest scope: a storage belongs to no guest |
| `update_container_resources` | `update_container_resources`. Cores apply immediately; memory and swap take effect at the next start |
| `get_job` | use `get_task_status` with the UPID |
| `list_jobs` | use `list_tasks` for a node |
| `poll_job` | applies follow their UPID to completion within the call; a crashed apply is re-probed at startup |
| `retry_job` | **none.** A failed apply needs a fresh plan — the change set is terminal, and retrying one whose receipt is already written would carry an empty digest and principal |
| `execute_vm_command` | **none.** Deliberate: the design spec makes it conditional on `mecmcp-policy` compiling an allow/deny rule set over the command subject, which is not wired. Arbitrary command execution inside every guest is remote code execution as a tool call, and it ships with a policy engine or not at all. Tracked in #57 |
One genuine gap remains, and a caller that depends on it has to change rather
than be shimmed. **You can cut over for everything else as of 0.8.0** — but
read the `restore_backup` note first, because plain restore does not fail
loudly when given the incumbent's new-VMID semantics: it does the wrong thing
successfully.

### Here but not there

`get_guest_status` · `get_task_status` · `list_tasks` ·
`plan_proxmox_destroy` · `get_proxmox_change_set` ·
`approve_proxmox_change_set` · `apply_proxmox_change_set`

## Before you cut over

1. **Name every tool in the token scope.** `tools: ["*"]` deliberately
   **excludes** `WRITE_TOOLS`, so a wildcard token reaches no mutating tool.
   Use `token set-scopes --name N --tools ...` — it changes scopes without
   reissuing the secret.
2. **Scope the destructive *operations*, not just the three change-set tools.**
   Plan and apply authorise a second time against the selected operation's own
   name -- `delete_vm`, `delete_container`, `delete_snapshot`,
   `rollback_snapshot`, `delete_backup`, `delete_iso`, `restore_backup`,
   `restore_backup_new_vmid`. A
   token holding only `plan_proxmox_destroy`, `approve_proxmox_change_set` and
   `apply_proxmox_change_set` is refused at plan time. These names are
   authorisation scopes, not callable tools: there is no `delete_vm` tool.
3. **Grant the action tiers you need.** `read`, `low`, `destructive`. A grant
   carrying only `read` cannot call `start_vm` however its tool scope reads.
4. **Pass `--state-file`.** Without it, change sets live in memory and every
   approval is lost on restart. The packaged unit passes
   `${STATE_DIRECTORY}/changeset-state.json`.
5. **Check `protected_vmids` and `protected_tags`.** A protected guest refuses
   anything that would interrupt or destroy it without a waiver — including
   `stop_vm`. Snapshots and backups still work, which is deliberate.

## Arguments the new tools take differently

These four are the ones a shim gets wrong. Unknown fields are **refused** as of
0.8.0 rather than dropped, so an old-shaped call fails loudly instead of
succeeding with almost none of itself applied -- but the mapping still has to
be done.

| third-party call | what changes |
|---|---|
| `create_vm(node, vmid, name, cpus, memory, ...)` | the guest settings move **inside `config`**: `{"cluster","node","vmid","config":{"name":"web","cores":"2","memory":"2048"}}`. At the top level they were ignored, which produced a default, diskless VM. |
| `create_container(..., ostemplate, ...)` | same move. `ostemplate` inside `config`, or the container is created with no template. |
| `update_container_resources(memory, swap, disk_gb)` | `memory_mb` and `swap_mb`, and **there is no disk field** -- grow a disk with `resize_disk`. A mixed call naming `cores` and `memory` used to apply only the cores and report success. |
| `download_iso(checksum)` | `checksum_algorithm` has **no default** here. 970 assumed `sha256`; this server refuses a checksum without its algorithm rather than skipping verification silently. |

## Options the same-named tool no longer takes

A tool with the same name is not always the same call. These options exist on
the third-party server and have no equivalent here, so a request carrying them
either fails to parse or silently does something else:

| tool | option that is gone | what happens instead |
|---|---|---|
| `stop_vm` | `graceful` | always an immediate stop. `shutdown_vm` is the graceful path and it is **QEMU only** |
| `stop_container` | `graceful` | always an immediate stop, and **there is no graceful LXC path at all** — `shutdown_vm` refuses a container |
| `create_snapshot` | `vmstate` | the snapshot never includes RAM state |
| `clone_vm` | `pool`, `snapname`, target storage and node placement | `snapname` being ignored means the clone takes **current state, not the requested snapshot**. The clone lands where Proxmox defaults it; `full` is the only copy control |

`clone_vm` also renames its arguments: the third-party `source_vmid` and
`target_vmid` are `vmid` and `newid` here.

`restore_backup` has **opposite target semantics**. The third-party tool treats
the `vmid` as a *new* restore target and exposes `storage` and `unique`; here the
plain restore path resolves an **existing** guest by that VMID and the apply
always passes `force=true`, overwriting it. Use the separate
`plan_restore_new_vmid` → `approve_proxmox_change_set` → `apply_restore_new_vmid`
flow for a new VMID; its token scope is `restore_backup_new_vmid`. A caller
expecting the incumbent's behaviour from plain `restore_backup` would overwrite
a live guest instead of creating one.

## Two behaviours that will surprise a 970 caller

- **`stop_vm` on a protected guest is refused.** The third-party server has no
  such concept. Snapshotting and starting a protected guest are still allowed:
  protection means "do not take this down", not "do not back it up".
- **A shrinking `resize_disk` is refused, and there is no supported
  alternative here.** Only the `+N` form is accepted, because an absolute size
  may be smaller than the current disk and this server cannot know the current
  size.

  There is no supported path anywhere. Proxmox rejects a reduction too --
  `qm resize` and `pct resize` only grow -- so this guide names no alternative
  rather than sending you somewhere that also refuses. Forcing it at the
  volume layer is how the guest gets corrupted.

  Do **not** reach for `plan_proxmox_destroy`: it takes only a cluster and a
  vmid and deletes the whole guest. An earlier draft of this guide suggested
  it, which would have turned a disk-shrink request into a VM deletion for
  anyone following the text literally.
