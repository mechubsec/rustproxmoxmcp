# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.1] - 2026-10-08

### Added

- Release images are also pushed to Docker Hub (`docker.io/mechub/rustproxmoxmcp`),
  alongside the existing GHCR image, with the same tags.

### Changed

- Docker run examples mount the host state directory at `/var/lib/proxmoxmcp`
  and pass `--state-file /var/lib/proxmoxmcp/changeset-state.json`, matching
  `server.json`.

## [0.11.0] - 2026-10-07

### Added

- Official MCP Registry listing (`io.github.mechubsec/rustproxmoxmcp`): the image
  carries the `io.modelcontextprotocol.server.name` ownership label and the repo
  ships `server.json` for the stdio Docker invocation.
- `scripts/package-lxc.sh` builds a Debian 13 LXC tarball at
  `dist/rust-proxmoxmcp_<version>_<arch>.tar.gz` with a `.sha256` sidecar.
  The version comes from the crate manifest (`PROXMOXMCP_PACKAGE_VERSION`
  overrides it). `PROXMOXMCP_PACKAGE_SKIP_BUILD=1` packages a binary that
  was already built.
- Firewall rules, options, aliases, IPSets and security groups are changed
  through `plan_firewall_change`, `approve_firewall_change` and
  `apply_firewall_change`. A write without an approved change set is refused.
  Lab-mode and two-person approval follow the same rules as other governed
  writes.

### Security

Fixes from the MEC-446/MEC-1163 authorization audit (F1-F4, L1-L3):

- **F1:** `delete_backup`/`restore_backup` and restore-to-a-new-VMID now
  bind the archive to the guest it actually belongs to, checked at both
  plan and apply, instead of trusting the volid's filename convention.
- **F2:** `approve_proxmox_change_set` and `get_proxmox_change_set` now
  check the approver's guest scope and destructive tier against the
  change set's target, not only against the caller's own grant.
- **F3:** `create_vm`/`create_container` config now goes through an
  allowlist of cloud-init, sizing, metadata, network and new-volume disk
  keys, closing the gap where a disk key's `import-from` or an
  existing-volume reference could attach another guest's volume with no
  approval step.
- **F4:** a waiver now lifts *protection* only. Previously a waiver that
  matched a protected guest's `plan_proxmox_destroy` also skipped the
  second human approver via `waive_approval_operator`; it now leaves the
  change set `Planned`, and the normal approve/apply flow -- including
  the human-approver requirement -- still applies. `--lab-mode` is
  unaffected: it is still a blanket single-operator waiver by design.
  `approve_proxmox_change_set` and `get_proxmox_change_set` evaluate a
  `principal`-bound waiver against the change set's recorded planner, not
  the caller approving or reading it -- checking it against the approver
  would have made a `principal`-bound waiver permanently unapprovable,
  since the two-person rule requires the approver to be a distinct
  principal from the planner. The preview for every non-destroy
  destructive operation (`delete_snapshot`, `rollback_snapshot`,
  `delete_backup`, `restore_backup`, `migrate`, `update_vm_config`,
  `delete_iso`) now shows the same `protected`/`waiver` lines the
  guest-destroy preview already did, so the human approver can see why
  protection was lifted for those operations too.
- **L1:** `delete_iso` now requires the caller's guest scope to be
  unrestricted (`*`), since the ISO it names is not bound to any guest
  the token's scope could be checked against.
- **L2:** cluster- and node-wide read tools now require an unrestricted
  guest scope, closing the gap where a guest-narrowed token could read
  data about guests outside its scope via a cluster-wide listing.
- **L3:** the guest-resolve cache is now dropped before any call that can
  interrupt a guest (not only before a destructive plan), so a call that
  changes guest state is never authorized against a stale cached read.

**Breaking:** `waivers.json` entries now require a non-empty `ops` list
naming the operation(s) the waiver covers; an entry with no `ops` field,
or an empty list, is refused at load and the server will not start. See
[README § `waivers.json` schema](README.md#waiversjson-schema) for the
exact `op` strings each call path expects, and for `principal`, the new
optional field that narrows a waiver to one token name.

### Changed

- **Re-pinned the `mecmcp-*` crates from `v0.23.0` to `v0.24.1`** (MEC-449).
  Brings in mecmcp#390 (the human-approver gate: `ChangesetCoordinator::approve_change_set`
  now takes an `approver_actor_type: mecmcp_audit::ActorType` and refuses
  anything but `Human`), mecmcp#377 (`/healthz` and `/readyz`, unauthenticated
  and always mounted), mecmcp#387 (`mecmcp-http`'s configured private CA now
  replaces the public root store instead of adding to it, and
  `mecmcp-transport`'s `test_harness`/`test_client` moved behind a `test-util`
  feature -- this server's dev-dependency now enables it), and MEC-347
  (`LimitsConfig::default()` now rate-limits by default: 50 requests/second and
  a burst of 100 per IP, 20/s and a burst of 40 per token).
- **`approve_proxmox_change_set` now passes the caller's server-verified
  actor type through to mecmcp's `ChangesetCoordinator::approve_change_set`.**
  A change set cannot be approved by a caller whose token declares
  `actor_type: agent`, or by an unattributed (stdio) caller -- only a
  distinct `actor_type: human` principal can approve.
  **Upgrading:** every token minted before this release has `actor_type:
  unknown` and can no longer approve change sets. Re-mint each approver's
  token with `rust-proxmoxmcp token add ... --actor-type human`; other
  tokens are unaffected. See [README § Change control](README.md#change-control).
- **Container images now publish to `ghcr.io/mechubsec/rustproxmoxmcp`** —
  the repo moved to the mechubsec organization, and images are renamed to
  match. Older tags were copied from the previous name.
- Raised MSRV to 1.89 (family-wide decision).
- **Added 14 read-only firewall tools** (MEC-453): rules, options, IPSets,
  aliases and security groups at cluster, node and guest scope, matching the
  scopes Proxmox itself exposes (node-level firewall has no aliases, IPSets
  or security groups — those exist only at cluster and guest scope). All are
  declared in `catalog.rs` and dispatched through the existing generic read
  executor; none are in `WRITE_TOOLS`, so read-only is enforced in code, not
  convention. Prerequisite for governed firewall writes.
- **Supply-chain hardening** (MEC-452): the Docker build now runs
  `cargo build --locked`; `Release image` SHA-pins every GitHub Action, runs
  `cargo deny check advisories licenses` in addition to `bans sources`
  (surfaced and allowed `webpki-root-certs`' CDLA-Permissive-2.0 data
  license, already allowed by mecmcp and rustjunosmcp), generates a
  CycloneDX SBOM per release as an artifact, and keylessly cosign-signs the
  pushed image by digest via GitHub OIDC. `CI` adds an MSRV job that checks
  the workspace at the declared 1.89 floor with a freshly resolved
  lockfile.
- **BREAKING: added pagination to `get_vms`, `get_containers` and
  `list_backups`** (MEC-479). A dense large cluster (or a storage backend
  with a long retention window) could exceed the MCP result's 512 KiB cap
  and refuse outright with no way to retry at a smaller page (found by
  MEC-456's lab test at ~1,000 QEMU guests). The three tools now take an
  optional `offset`/`limit` (default 500, max 700) and return
  `{items, total, offset, limit, has_more}` instead of a bare array. Pages
  are sorted by `vmid`/`volid` so records don't shift between calls as the
  cluster changes. `list_tasks` was evaluated for the same treatment but is
  *not* paginated (MEC-871): Proxmox's `/nodes/{node}/tasks` already applies
  its own server-side window with no discoverable total, so a client-side
  pagination envelope on top of it would misreport a truncated list as
  complete.

### Added

- **`/readyz` now reports real Proxmox cluster reachability** (MEC-983,
  closes #115). Each configured cluster gets a background poller that calls
  its API on a 30-second interval; a single fixed-name `ReadinessCheck`
  flips `/readyz` to 503 if any configured cluster is unreachable, instead
  of the endpoint reporting ready unconditionally because no check was ever
  wired in. `/readyz` is unauthenticated, so the response never identifies
  which cluster failed — that detail goes to the server log only.

## [0.10.0] - 2026-09-16

This is a **minor version** rather than a patch because the ENTRYPOINT/CMD split
changes the contract for operators running the container with their own arguments.
An `ENTRYPOINT` exec-form array holds the fixed binary path, and a `CMD` holds
its default arguments — which `docker run` overrides when the user supplies their
own. The previous single-directive form made every container override a
FROM-dependent rebuild.

The headline reason for the release is a rustls security update closing
RUSTSEC-2026-0285, a TLS 1.3 boundary-crossing vulnerability rated CVSS 5.3.

### Security

- **Updated rustls from 0.23.44 to 0.23.45**, closing **RUSTSEC-2026-0285**
  (#98). TLS 1.3 handshake messages could be accepted across encryption-level
  boundaries, allowing a network attacker to inject handshake messages during the
  cleartext phase that would be processed as if they arrived after the handshake
  completed. Rated CVSS 5.3 MEDIUM. This server terminates TLS, so the exposure
  was direct.

### Changed

- **The Dockerfile now uses separate `ENTRYPOINT` and `CMD` directives** (#88),
  so operators can override arguments without patching the image. `ENTRYPOINT`
  holds the binary path `["/usr/local/bin/rust-proxmoxmcp"]` and `CMD` holds
  the default flags (empty, letting the binary read its own defaults).
  `docker run <image> --port 3131` now works as written; the previous form
  required `--entrypoint` or a rebuild.
- **Adopted the mecmcp package conformance check** (#89), which gates on the
  presence of the security policy, license, README, changelog, and uninstalled-
  command audit. The gate ensures release artifacts carry the operator-facing
  documentation. R5 (the uninstalled-command filter) was later corrected to
  anchor the pattern (#366), and R6 was fixed to continue after an earlier rule
  fails (#367).
- Re-pinned `rmcp` from 3.2.0 to 3.4.0 (#99), which renames the internal
  `ServerInfo` type to `ServerConfig`. No wire-format or API surface change; the
  rename is compile-time only.
- Updated Rust builder base image from `1469a27` to `ebd900b` (#90).
- Updated distroless runtime base image from `c31ff9a` to `54df941` (#92).
- Updated `reqwest` from 0.13.4 to 0.13.5 (#96).
- Updated `uuid` from 1.26.0 to 1.26.1 (#93).
- Updated `trybuild` from 1.0.120 to 1.0.121 (#97).
- Pinned the conformance action from floating to a commit digest (#91).

### Fixed

- **Corrected the LXC setup guide to add `--allowed-origin` and fix the
  `--tokens-file` path** (#86). The guide previously omitted the origin
  allowlist, which would cause streamable-HTTP handshake refusals from any
  client not on `localhost`, and pointed at the wrong tokens file.
- **Redacted a real Proxmox node name from the LXC guide** (#87). The example
  output included a production node name where a placeholder was intended.

### Documentation

- **Added a complete LXC-from-scratch setup guide** (#84), explaining how to
  build a Debian 13 container, extract the glibc-compatible binary from the
  release image, and install the systemd unit and sysusers config.

## [0.9.1] - 2026-09-06

### Fixed

- **The shipped systemd unit now sets `SystemCallErrorNumber=EPERM`**, so a denied
  syscall returns `EPERM` rather than killing the server with `SIGSYS`. Without it,
  systemd's default raises `SIGSYS` and terminates the process mid-request — which
  is exactly what happened to `rustunifimcp` during a change-set state write
  (mecmcp#351), and this server had the same exposure. An `EPERM` denial is silent
  at the systemd layer; visibility depends on the application handling the errno
  rather than discarding it. This brings the unit into compliance with the fleet
  seccomp standard agreed in mecmcp#354.

## [0.9.0] - 2026-09-01

This is a **minor version** rather than a patch because claim-before-apply
changes the semantics of the apply path. An operation is now claimed before
sending the request, spending the approval before anything reaches the cluster.

The approval digest change from mecmcp 0.23.0 does not invalidate any live
approval on LXC 971 `prod-proxmoxmcp`. The only change set in state `Approved`
on that deployment is a `probe-verify` / `probe-approver` test targeting guest
640, and it expired 2026-08-26 22:19Z.

### Security

- **`delete_backup` and `delete_iso` are separately authorized tools, but both
  dispatched to the same Proxmox endpoint.** Nothing tied the volid's content
  kind to the tool being invoked, so a token holding only `delete_iso` could
  pass `local:backup/vzdump-lxc-950.tar.zst` and delete a backup. The preview
  an approver reads calls it an ISO and says "It can be downloaded again",
  which is false for a backup.
- **Nothing bound the volid's storage prefix to the `storage` parameter**, so
  the two could name different backends.
- Both are now validated at plan time via `validate_volid_for_operation`, which
  checks content kind *and* binds the storage prefix to the `storage` argument.
  A mismatched volid never reaches an approver. A defence-in-depth check also
  runs at apply for records that predate this fix, placed *before* the
  apply-intent evidence write so a refusal does not leave the evidence chain at
  intent with no outcome for an operation that never left the process.
- **The apply-time check only fired when the fields it reads were present**,
  leaving the same hole it was written to close. An action carrying neither
  volid nor storage would reach `execute_destructive`, where a `missing` error
  produces `Malformed` after apply intent has been written. No result receipt
  follows, and the trail reads "the request may have been sent, go and look"
  for an operation that never left the process.
- `missing_required_fields` now names every field an operation needs, checked
  before the intent write and returned through `tool_error` so the refusal is
  definitive. It covers `snapname` too: `delete_snapshot` and
  `rollback_snapshot` strand the chain the same way. `build_destroy_action`
  requires all of these at plan time, so a record planned by this version
  cannot be incomplete -- the exposure is exactly the older, imported and
  hand-written records the apply-time check exists for.
- The validator treated `""` as present. `build_destroy_action` filters empty
  strings at plan time, so an action carrying one was never planned by this
  version -- and calling it present sends it to `expand_path`, which rejects
  the empty segment as `Malformed`, landing in the same stranded-chain state.
  Presence now means non-empty, matching planning.
- Both volid validators parsed `storage:kind/name` for `kind` alone and
  discarded the other two components unchecked, so `:backup/x`,
  `local:backup/` and `local:iso/` all validated. An empty prefix is now
  rejected *before* the storage comparison in `validate_volid_for_operation`,
  because an empty `storage` argument would otherwise let `":iso/x"` bind to
  nothing and read as a match. Planning could previously record and solicit
  approval for a volid that cannot address a volume.

### Changed

- Re-pinned the `mecmcp-*` crates from `v0.21.0` to `v0.23.0`. 0.23.0 binds a
  change set's preview digest into its approval digest, so an approval now
  vouches for the exact preview a reviewer saw. The coordinator refuses any
  write that would swap or drop a preview once an approval exists.
- Dependabot will no longer attempt to bump the git-pinned `mecmcp-*` crates,
  which was causing the weekly cargo run to fail. The mecmcp version is
  deliberately moved by hand in a `chore/mecmcp-<version>` PR that re-pins
  every file at once.
- Updated `uuid` from 1.25.0 to 1.26.0.
- Updated Rust builder image.
- Updated distroless runtime base image.

### Fixed

- `a_change_set_without_a_stored_preview_cannot_be_applied` was passing for the
  wrong reason after the bump. mecmcp 0.23.0 refuses the preview strip the test
  used for setup, so the test failed before it reached the behaviour it exists
  to check. It now persists the state a pre-0.23.0 binary would have written --
  approved, previewless, carrying a v4 approval digest -- and confirms apply
  still refuses it. Verified by sabotage: with the guard disabled, the test
  fails.
- **A second apply of the same approved change set could issue a second
  destroy.** mecmcp 0.22.0 made `claim_change_set_for_apply` the only legal
  `Approved -> Applying` transition, but `apply_proxmox_change_set` still sent
  the destroy first and moved the record afterwards. On 0.23.0 that write is
  refused, and because the refusal was logged rather than returned, the record
  stayed `Approved` and re-appliable while the guest was already gone. The
  apply now claims the change set before `execute_destructive`, so the approval
  is spent before anything reaches the cluster and a losing claimant is refused
  with nothing sent. The UPID write that follows is an `Applying -> Applying`
  field update, so the handle still lands before polling.
- The claim is taken **before** the apply-intent evidence record, so evidence is
  only emitted by the caller that actually holds the approval. Written the other
  way round, two callers racing would both durably record that execution began
  while only one could proceed, leaving a receipt-less intent for the loser. If
  the intent record then fails to persist, the claimed change set is settled to
  `Failed` rather than described as still approved, which it no longer is.
- **Every** operation is claimed with `ApplyHandle::None`, not just the
  handleless ones. The claim necessarily precedes the request, so there is a
  window where the DELETE has been accepted but its UPID is not yet persisted.
  A record claimed as `Expected` sits in that window as `Applying` with no
  `task_id` and `apply_without_handle = false` -- exactly the combination the
  coordinator converts to `Failed` at startup, asserting that a destroy which
  may well have succeeded did not. Handleless keeps it `Applying` instead:
  detectable, not recoverable, a human goes and looks. Once the UPID is stored
  the record carries a real handle, which recovery re-probes rather than
  settling.
- A path-segment field that cannot form a URL path segment is refused at plan
  time, via a new `guests::validate_path_segment` that asks
  `mecmcp_openapi::expand_path` rather than re-implementing its grammar. That
  distinction matters: a hand-written byte check catches `/` and a backslash but
  accepts `%2f`, `%252f`, `.` and `..`, all of which `expand_path` rejects. It
  rejects them at apply, though -- by which point the change set is planned,
  approved and claimed, and a local failure is indistinguishable from an
  unparseable response, so the record was left claimed and the guest blocked.
  `volid` is exempt: it is a query parameter, and `local:backup/vzdump-...` is
  well formed.
- The same fields are re-checked at apply, before the claim, for the same reason
  the volids already were: a change set approved by the previous release was
  planned before this validation existed and can still carry a snapshot named
  `a/b` or a storage node of `..`. Caught after the claim it would strand the
  record in `Applying` with nothing sent; caught before it, the change set is
  simply refused.
- Moved off the yanked `chacha20` 0.10.1. It arrives through `rand -> rmcp ->
  mecmcp-server`, and `cargo-deny` fails the advisories check on a yanked
  crate. This is a lockfile-only move; 0.10.2 satisfies the same requirement.

### Documentation

- **The README and the migration guide said the opposite of what is now true.**
  Both stated plainly that the preview is not hashed into the digest and that an
  approver commits only to the action -- accurate before 0.23.0, and exactly
  backwards after it. Both now say the approval binds the preview, and both keep
  a sentence saying what the previous behaviour was, since operators who read
  the old text were told something specific about what their approval covered.
  The `TODO: implement preview binding` comment in the plan path is resolved and
  replaced with a description of where the binding actually happens.
- The apply-intent failure path reports the settlement that actually happened.
  If the settle write also fails the record is still `Applying`, and telling the
  caller to plan again would be wrong -- the claim is still held.

### Added

- `an_approval_is_spent_by_the_first_apply_and_cannot_destroy_twice`, which
  applies the same approval twice and asserts exactly one DELETE reaches the
  cluster. Verified by reverting the fix: without the claim, the second apply
  succeeds. No existing test covered this -- the broken write was logged, not
  returned, so the whole suite stayed green.
- `an_approved_change_set_will_not_give_up_its_preview`, covering the new
  coordinator-level binding directly, and asserting the refused write does not
  partially apply.

## [0.8.2] - 2026-08-27

### Security

- **Takes mecmcp 0.21.0, which stops `RUST_LOG` switching the audit trail off**
  ([mecmcp#330](https://github.com/mechubsec/mecmcp/issues/330)). The
  environment filter was attached to the tracing registry, where it decides
  whether an event exists at all, so it gated the audit file and journald sinks
  as well as the console. A `RUST_LOG` naming a target — the ordinary way to
  turn up logging for one crate — produced a filter that did not enable the
  `audit` target, and every `target: "audit"` event was discarded while the
  operation it described still happened.

  This server is where the defect was measured: widening a token's scope with
  `token set-scopes --yes` wrote one audit line with `RUST_LOG` unset and
  **zero** under `RUST_LOG=rust_proxmoxmcp=debug`. The token store was updated
  both times and stderr stayed empty, so nothing recorded the widening.

  No configuration change is needed. Anyone who has been debugging this server
  with a target-specific `RUST_LOG` should assume the audit trail has gaps for
  those periods.

## [0.8.1] - 2026-08-26

Three defects, two of them found by using 0.8.0 against live hardware rather
than by testing it. No tool-surface change, so no token needs re-minting.

### Fixed

- **`get_vm_config` and `get_container_config` failed on every call.**
  `serve_read` supplied `kind` unconditionally, and both paths name the guest
  type themselves -- `/nodes/{node}/qemu/{vmid}/config` and the LXC equivalent
  -- so `mecmcp-openapi` refused with *"parameter 'kind' does not appear in the
  template"*. Neither tool had a test anywhere in the suite. `kind` now travels
  only when the template asks for it, and a path naming one guest type refuses
  the other by name instead of addressing an endpoint that cannot exist.
- **A destroy plan succeeded for a guest that could never be destroyed.**
  Proxmox destroys only a stopped guest, and this server sends `purge` without
  `force`. The plan succeeded, a second principal approved it, and the apply
  failed -- spending the approval and requiring the same person to be asked
  again. Refused at plan time now, naming the prerequisite. A *confirmed*
  `stopped` is required: `/cluster/resources` can report `unknown`, and treating
  that as good enough would hand out the same unusable plan.
- **A plan could be built from a stale snapshot.** The fingerprint a plan
  records is what apply re-checks, so planning from a cached read produced a
  change set describing state the guest had already left -- exactly what happens
  when a caller stops a guest and plans immediately. The plan now invalidates
  before resolving, as apply already did.

### Notes

`--lab-mode` is the *protection* override, not a blanket waiver: on a lab-mode
server a **protected** guest is approved on creation with no second principal,
while an **ordinary** guest still requires one and self-approval is refused.
The README now says so, along with the real tool surface -- it had been claiming
0.3 and a read-only server.

## [0.8.0] - 2026-08-26

Five tools. **Two gaps against the third-party server remain** -- see below;
the opening of an earlier draft of this entry said one, which was wrong.

**Re-mint or widen your tokens**: `KNOWN_TOOLS` grows by five, and a token
minted against 0.7.1 carries none of the new scopes.

**Arguments are not the same shape as 970's**, and unknown fields are now
refused rather than ignored. A call written for the old server would otherwise
have succeeded having applied almost none of it.

**Two gaps remain, not one.**

`execute_vm_command` is deliberately absent: the design spec makes it
conditional on `mecmcp-policy` compiling an allow/deny rule set over the command
subject, and that is not wired yet.

`restore_backup` is present but **not equivalent**. The third-party tool takes
`vmid` as a *new* restore target and offers `storage` and `unique`; here the
plan resolves an **existing** guest and the apply passes `force=true`, so the
same-shaped call overwrites a live guest rather than creating one.
Restore-to-a-new-VMID has no equivalent. Do not read "five tools shipped" as
"parity reached" -- see #57.

### Added

- **`create_vm`** and **`create_container`**, over the `create_guest` primitive
  that had shipped in 0.7.0 with no tool calling it. `create_container`
  defaults to `unprivileged=1`.
- **`download_iso`**, over `download_url`. Requires an unrestricted guest scope:
  a storage belongs to no guest, so no selector this grant carries can narrow
  it.
- **`update_container_resources`** -- cores, memory and swap on an LXC guest.
  Cores apply immediately; memory and swap take effect at the next start, and
  the response says so rather than implying the change is live.
- **`stop_task`** -- cancel a running Proxmox task.

### Security

- **A `low` create could restore over an existing guest.** Proxmox restores a
  backup by POSTing to the *same* endpoint a create uses; the difference is
  three form fields (`archive`, `force`, `restore`). Because config keys were
  forwarded verbatim, a token holding only `create_vm` could send them and
  overwrite a live guest, skipping the destructive tier, the protection check
  and change-set approval entirely. A create now refuses a VMID that already
  exists, which closes the class rather than the one spelling of it, and the
  restore controls are refused by name.
- **Host-reaching config is refused**: `hookscript` and `args` run on the node,
  `mpN` mounts a host path into a container, `hostpciN`/`usbN`/`devN`/`serialN`/
  `parallelN` pass host devices through, and `lxc.*` can express all of them.
  Values are checked too -- `scsi0` stays valid for `local-lvm:32` and is
  refused for `/dev/sdb`.
- **`unprivileged` is handled by value, not by key.** Proxmox reads an omitted
  field as `0`, so refusing the key outright had permitted *only* privileged
  containers. `1` is accepted, `0` refused, and a container gets `1` when the
  caller says nothing.
- **`stop_task` applies the protection gate.** A UPID's worker id names the
  guest for guest-addressed work, and cancelling that interrupts the guest, so
  it authorises the VMID exactly as every other interrupting tool does.
  Guest-addressability is decided by worker **kind**, not by whether the id is
  numeric -- `cephdestroyosd:3` is an OSD, and reading it as guest 3 would let
  a token scoped to 3 cancel node work.
- **`stop_task` reads the node from the handle.** It had taken a `node`
  argument; a mismatched one addresses a path the task does not live at, and
  Proxmox reports a successful cancel having stopped nothing.
- **Rollbacks are not interruptible.** They rewrite a guest in place exactly as
  restores and destroys do, and the partial-state guard had not listed them.
- Download URLs are redacted in the audit record. A presigned URL carries its
  authorisation in the userinfo or query string, and the audit target is
  durable.

### Fixed

- `checksum_verified` claimed what the call cannot know: Proxmox verifies inside
  the download task, so a mismatch surfaces later as a failed task. Renamed to
  `checksum_verification_requested`.
- The existence check refreshes the cluster snapshot first. A guest destroyed
  moments earlier still sat in the cache, so a freed VMID reported as taken for
  the rest of the TTL.
- A node job with no worker id -- `aptupdate::root@pam:` -- can be cancelled.
  The strict UPID parse rejects the empty field, so the one tool that exists to
  cancel those had refused them.
- `stop_task`'s audit event keeps the guest and its protection verdict. A
  protected guest interrupted under a waiver had left no evidence of why it was
  allowed.

## [0.7.1] - 2026-08-26

**No tool ships in this release.** The MCP tool surface is byte-identical to
0.7.0 -- verified, not assumed. Upgrading changes nothing an MCP client can
call, and no token needs re-minting.

What lands is the `guest_exec` core primitive, its tests, and the cutover
documentation. `execute_vm_command` parity is **not** delivered: nothing
calls `guest_exec`, so it is unreachable from the tool surface. The branch
was titled "guest_exec behind a change set" and it is not behind one, because
it is not behind anything. Wiring it to the destructive change-set flow is
tracked in #57.

Versioned as a patch on the operator-facing view, where nothing changed.
Consumers of the `rust-proxmoxmcp-core` **library** do see an additive public
function, which by strict semver would be a minor bump.

### Security

- **The fingerprint re-check at apply was a no-op inside the resource-cache
  window.** `GuestIndex` caches `/cluster/resources` for
  `resource_cache_ttl_secs` (default 10s), and the apply handler never dropped
  it. Plan and apply therefore read the *same* cached snapshot and the
  comparison could not fail: a guest renamed, migrated, stopped, started, or
  newly tagged `protected` between approval and apply compared equal and was
  acted on. Apply now invalidates the snapshot before re-resolving.

  The existing test passed only because its harness invalidated the cache
  itself. A second test now moves the guest **without** invalidating -- what
  Proxmox actually does -- and it fails against the old handler.

- **A fetch that began before an invalidation can no longer republish stale
  state.** `GuestIndex::resolve` inserted last-write-wins, so an in-flight
  `/cluster/resources` request that started before the change could land after
  the invalidation and put the pre-change snapshot back. Apply resolves twice
  -- once for protection, once inside `authorize` where the fingerprint is
  computed -- so the second read could consume that reinserted snapshot and
  match, defeating the invalidation above. A generation counter now refuses an
  insert from any fetch that started before the last invalidation.

  The comparison happens **inside** the write-locked critical section. Doing
  it before taking the lock left a time-of-check/time-of-use gap in which an
  invalidation could bump the generation and clear the map, after which the
  insert would republish pre-change state on the strength of an already-stale
  comparison. It is correct only because invalidation bumps the generation
  before it takes that lock.

  Covered by a test that parks a request mid-flight against the mock server
  and invalidates around it, rather than hoping for the interleaving. The mock
  gained a `captured_count` signal for this: `request_count` rises when a
  request is *recorded*, which is before its route is read, so a test
  synchronising on it can swap the route first and hand the parked request the
  post-change body -- passing for the wrong reason.

- **Invalidation is cluster-scoped.** `invalidate()` cleared every cluster's
  snapshot, so applying to one cluster evicted still-valid state for all the
  others and made their next operation pay a fetch that could fail if that
  cluster was briefly unreachable. Apply now uses `invalidate_cluster`.

### Added

- `guests::guest_exec` -- run a command inside a QEMU guest through the guest
  agent. Strictly more powerful than `destroy_vm`, which is why the intended
  wiring is a change set and why shipping it unreachable is the conservative
  state rather than a gap to paper over.
- `docs/MIGRATING-FROM-PROXMOX-MCP.md` -- the cutover guide from the
  third-party `proxmox-mcp` server, including the UPID/task mapping that
  replaces its job model.

### Fixed

- **Seven corrections to the migration guide**, three of them serious enough
  to mislead an operator into damage or a failed cutover:
  - It claimed `execute_vm_command` maps to `op: "guest_exec"` with a
    `command` argument. No such mapping exists: `PlanDestroyArgs` has no
    `command` field and `build_destroy_action` rejects `guest_exec`.
  - It still told operators to shrink a disk "from the Proxmox UI or CLI".
    Proxmox refuses a reduction too, so the guide now names no alternative.
  - It promised "a guest that changed after approval is refused". The
    fingerprint sends `config_digest` and `disks` **empty** at both plan and
    apply, so a configuration-only change does not move it. The guarantee is
    now stated as what it actually covers.
  - `delete_backup` and `delete_iso` rows omitted the required `storage_node`.
  - The token checklist omitted that plan and apply authorise a second time
    against each destructive operation's own scope name.
  - Options that silently vanished with a same-named tool are now listed:
    `graceful` on stop, `vmstate` on snapshot, clone placement.
  - Every parity gap is now named in the guide, with a plain instruction not
    to cut over until #57 closes.
  - `shutdown_vm` is QEMU-only, so containers have no graceful stop at all;
    the guide said otherwise.
  - `clone_vm` silently ignores `snapname`, cloning current state rather than
    the requested snapshot, and renames `source_vmid`/`target_vmid`.
- The approval does not bind the preview text (#56), stated in the guide
  rather than implied.

## [0.7.0] - 2026-08-26

Provisioning. Two tools become reachable -- `clone_vm` and `resize_disk` --
and the guards a create needs that a guest-addressed operation never did.

### Added

- **`clone_vm`** and **`resize_disk`**. Both names were already in
  `WRITE_TOOLS` at 0.6.0 but absent from `KNOWN_TOOLS`, so no token could be
  granted them. **Re-mint or widen your tokens** to use them: a token minted
  against 0.6.0 carries neither scope.
- `clone_guest`, `create_guest`, `download_url` and `resize_disk` primitives.
  `create_guest` and `download_url` have **no tool calling them yet** -- see
  issue #57 for what still stands between this server and retiring the
  third-party one.

### Security

- **A clone can no longer escape its token's guest scope.** `authorize_low`
  checked the *source* and nothing looked at `newid`, so a token scoped to
  `vmid:600-699` could clone 606 into 800 -- creating a guest outside its
  grant, and probing which VMIDs were free while doing it. Only the grant
  terms a bare number can answer participate: `*` and `vmid:`. A `tag:` or
  `pool:` grant cannot admit a creation destination, because the new guest's
  tags are whatever the caller sets, which would let a token choose its own
  scope.
- **A create is checked against `protected_vmids`.** The protection union is
  evaluated against a resolved guest, so a pinned VMID was unenforced at
  exactly the moment it was cheapest to enforce -- the VMID does not exist
  yet. Letting a create claim a pinned number means the next `delete_vm`
  against it is refused for protecting a guest nobody intended to protect.

### Fixed

- **The resize refusal no longer names an action that destroys the guest.**
  It directed a shrink to `plan_proxmox_destroy`, which takes a cluster and a
  vmid and deletes the whole guest -- it has no disk or size field. The
  correction went through four revisions: the schema description still named
  the change-set flow after the error message stopped, and the replacement
  advice ("use the Proxmox UI or CLI") was itself unsupported, because
  `qm resize` and `pct resize` reject a reduction too. It now states that
  shrinking is unsupported here *and* in Proxmox, and names only the retry
  that works.
- **The resize audit event keeps its task handle.** It was empty when the
  resize answered synchronously.
- A synchronous resize returning `null` is a completed resize, not a failure.
- A container names itself `hostname` and a VM names itself `name`. Proxmox
  ignores the wrong spelling silently, so a clone would have succeeded under
  the wrong name with nobody told.
- A download checksum is verified only when algorithm and value are both
  present; one alone is ignored. They now travel together or not at all.
- **A `+` prefix is no longer enough to classify a resize as growing.** The
  check was `starts_with('+') && len >= 2`, so `+banana`, `++8G` and `+-8G`
  all entered the low tier on the strength of being two bytes long -- the
  opposite of the documented fail-closed behaviour for unclassifiable input.
  The whole delta is now read as a positive size. `+0G` is not a grow either,
  since it adds nothing.

## [0.6.0] - 2026-08-26

Completes the destructive tier. 0.3 built the change-set machinery and wired
**one** of the eight destructive tools through it; the remaining six now go
through the same plan -> approve -> apply path rather than beside it.

### Added

- **`plan_proxmox_destroy` takes an `op`** — `destroy_guest` (the default),
  `delete_snapshot`, `rollback_snapshot`, `delete_backup`, `delete_iso`,
  `restore_backup` — with the parameters each needs. Required at **plan** time,
  because the action is what the digest covers: anything left undecided then is
  something the approver cannot review.
- `destroy_vm`, `delete_snapshot`, `rollback_snapshot`, `delete_volume` and
  `restore_backup` primitives.

### Security

- **Each operation authorises against its own tool name.** A token allowlisted
  for `plan_proxmox_destroy` and `apply_proxmox_change_set` could previously
  select any operation, which made `WRITE_TOOLS` naming each destructive tool
  separately meaningless. Checked at plan **and** at apply, because a scope can
  be narrowed between the two and the apply is the call that acts.
- **The preview describes the operation that will run.** It previously rendered
  a guest destroy for every operation, so an approver reviewing a rollback,
  restore or volume deletion was shown `DESTROY <guest>`. The two that *replace*
  state now say so: a rollback and a restore both warn that everything written
  since the snapshot is lost.
- **A volume is addressed on its own node.** `local` is node-local storage, so
  `local:backup/x` on two nodes names two different volumes; the node is now
  part of the action rather than derived from whichever guest the vmid names.

### Fixed

- **A synchronous deletion no longer fails after succeeding.** Some storage
  types delete without a task and return no handle; parsing that as a UPID
  reported failure for a volume already gone, wrote no receipt, and left the
  record retryable against something that no longer existed.
- **A change set with no stored preview is refused.** The preview is written to
  the store *after* the record is created, so a failed second write left a
  record that both approve and apply accepted. Approve did worse than accept
  it: it substituted the literal string `"(no preview)"` and recorded an
  approval over text no operator could have read. Approve and apply now both
  refuse a previewless record, and a plan that cannot persist its preview
  fails rather than returning a change-set id.
- **The operation scopes are grantable.** The per-operation authorisation above
  demanded tool names the token CLI rejected as unknown, so no token could be
  minted that could plan or apply **any** destructive operation. The seven
  operation names are now accepted as authorisation-only scopes, and a test
  asserts every operation scope can be granted through the supported CLI.

### What the approval actually binds

Stated plainly, because the 0.3 README overstated it. The plan digest covers
`(owner, device, expected fingerprint, actions)` and the approval binds that
digest. **The preview is not hashed into it.** It is stored with its own digest,
so the text an approver read cannot be edited afterwards without the store
refusing it — but what an approver commits to is the operation and its
parameters, not the prose describing them.

### Backward compatibility

`op` defaults to `destroy_guest`, so a caller written against 0.5 keeps working.
A change set planned under 0.3 recorded `op: "destroy"`, and that spelling still
dispatches: a plan made then must not become unexecutable because the name
changed.

## [0.5.0] - 2026-08-25

The daily driver. **`KNOWN_TOOLS` goes 20 -> 29**, and change-set state is
persisted for the first time.

Issue #46 calls this milestone "0.4"; the crate was already at 0.4.0 when that
issue was written, so it ships as 0.5.0. The milestone numbering in #47-#49
is one behind the version for the same reason.

### Added

- **Seven lifecycle tools** — `start_vm`, `stop_vm`, `shutdown_vm`,
  `reset_vm`, `start_container`, `stop_container`, `restart_container`.
- **`create_snapshot` and `create_backup`.** `create_backup` defaults to
  vzdump `mode=snapshot`, the only mode that does not interrupt the guest.
- **`--state-file`**, the spelling `mecmcp/docs/PACKAGING.md` standardises.
  The packaged unit passes `${STATE_DIRECTORY}/changeset-state.json`.
- **Startup recovery.** An apply that was in flight when the process stopped
  is re-probed before serving, closing the "detectable but not recoverable"
  limitation 0.3 documented.
- **`token set-scopes`** changes a token's device, tool, guest and action
  scopes **without reissuing its secret**, so no client is reconfigured. The
  alternatives all mint a new one: `rotate` preserves scopes and changes the
  secret, `revoke`+`add` does the same, and hand-editing `tokens.json` skips
  every validation.

  Widening is a privilege escalation and is confirmed interactively unless
  `--yes` is passed; narrowing is not, because reducing a scope cannot grant
  anything. Every change is written to the audit trail through a sink that
  `RUST_LOG` cannot silence — a target-specific filter previously suppressed
  it while the widening still applied.

  Note that `--tools '*'` does **not** reach a mutating tool: `WRITE_TOOLS` is
  excluded from the wildcard, so the nine tools above must be named explicitly
  in a token scope.

### Fixed

- **Change-set state is persisted at all.** `new_with_default_coordinator`
  passed `None` as the state path, so the coordinator kept everything in
  memory: every approval, preview and operation record was lost on restart,
  and had been since 0.1. `StateDirectory=proxmoxmcp` had been provisioning a
  0700 directory all along with nothing writing to it.

### Changed — protection now covers interrupting calls

The protection gate keyed on `tier == Destructive`, which was
indistinguishable from "everything disruptive" while destructive tools were
the only mutating tools. Adding `stop_vm` made the difference real: a
protected guest would have been stoppable by a routine low-tier call.

The axis is **service interruption, not mutation**, and it is deliberately
orthogonal to `Tier` — the tier answers "does this destroy data", interruption
answers "does this take the guest down".

| on a protected guest | |
|---|---|
| `stop_vm` `shutdown_vm` `reset_vm` `stop_container` `restart_container` | **refused** without a waiver or `--lab-mode` |
| `start_vm` `start_container` `create_snapshot` `create_backup` | allowed |

The second row is the point: all five guests upgraded on 2026-08-25 are
`protected`, and snapshotting them beforehand is the most common operation in
this lab.

### Upgrade note

`mecmcp` 0.19.0 -> 0.20.0.

**Rolling back during an apply needs the state file restored alongside the
binary** — the Proxmox snapshot path the fleet already uses.

The reason is the field, not the envelope version. `ChangeSetRecord` is
`deny_unknown_fields`, so a binary predating 0.20.0 rejects the **whole state
file** — not the one record — the moment any change set carries `task_id`.
`task_id` raises the file's minimum to version 2, but an in-flight apply is by
definition an approved change set, and a real approval already forces version 4
(or 3 with a waiver), so the file such a rollback meets is normally well past
version 2 anyway.

A deployment that never applies keeps writing files the older binary reads.

## [0.4.0] - 2026-08-25

### Added

- **SSDF evidence pipeline** (mecmcp#292). Mutating operations now emit
  execution evidence, including around the destroy path, and the evidence is
  flushed even when serving ends in an error. Receipts name the executor.

### Security

- **Tier-2 hardening.** `tokens.json` moves to `/var/lib`, the systemd unit is
  sandboxed, the audit HMAC key is guarded, and stale secrets are scanned for.
- **The legacy token store is no longer shadowed by an empty one.** An upgrade
  that found an empty primary could previously mask a populated legacy store,
  which reads as "every credential was rejected" rather than as a packaging
  fault.
- **Token paths compare byte-for-byte**, not by `Path` equality, and the legacy
  fallback is restricted to the canonical path only.
- Packaging now probes real egress enforcement rather than implying it.

### Changed

- **`mecmcp` 0.11.0 -> 0.19.0.** That is the jump from the v0.3.2 baseline;
  0.17.0 was an intermediate untagged step.

### Upgrade note — rolling back needs the state file, not just the binary

`mecmcp-changeset` state carries a schema version. v0.3.2 links 0.11.0, whose
reader accepts **v1-v3 only**. 0.4.0 links 0.19.0, which accepts v1-v4 and
**stamps v4 on any write to a store holding a real approval**.

Once this release has written such a store, reinstalling the 0.3.2 binary alone
will not start — it rejects the state file with `unsupported changeset state
version 4`. **Roll back with the Proxmox snapshot**, which restores `/var/lib`
along with the binary. A binary-only downgrade is not a rollback path.
- `rmcp` 3.1.2 -> 3.1.4.
- Pinned toolchain moved to 1.98.0, alongside the builder image, with a CI
  toolchain-pin guard and a Docker build in CI.
- Dependabot now watches the Dockerfile. `reqwest` 0.12 -> 0.13, `rcgen` 0.13 ->
  0.14.

### Note on the version

Minor rather than patch: this release adds the evidence pipeline, which is a
feature, not a fix.

## [0.3.2] - 2026-08-19

### Added

- **`--lab-mode` now announces itself at startup.** The flag was applied
  silently, so the only way to tell a lab-mode server from a two-person one was
  to read its unit file or `/proc/<pid>/cmdline`. Every sibling server in the
  family prints this banner; auditing the fleet at a glance depends on it.

## [0.3.1] - 2026-08-18

### Fixed

- **`tools/list` now carries the cache descriptor** (`ttlMs`, `cacheScope`) a
  2026-07-28 client validates. Because this server overrides `list_tools` to
  filter by token scope, it did not inherit the fields rmcp's generated handler
  supplies, and a client on the new protocol rejected the reply outright —
  reported as "tools fetch failed" against a healthy server.
- Took h2 0.4.17 for RUSTSEC-2026-0258.

### Documentation

- Documented audit forwarding and where the trail goes.

## [0.3.0] - 2026-08-15

### Added

- **Destructive operations are under change-set control.** `delete_container`
  and its siblings go through create/approve/apply rather than executing on
  call, following the Proxmox UPID task to completion.
- **`--lab-mode` and `--waivers-file`**, matching the rest of the family:
  single-operator mode waives the distinct-approver rule, and waivers are
  recorded rather than implied.

### Fixed

- **`--allow-insecure-bind` was parsed and never wired into the transport**, so
  the server could not bind plaintext off-loopback at all. It hid because every
  deployed server uses TLS. Now covered by a test that binds `0.0.0.0:0`.

## [0.1.2] - 2026-08-14

### Changed

- Converged on mecmcp v0.9.1 (from v0.8.8).

### Added

- CI and security workflows: gitleaks with default rules loaded, `cargo-deny`
  with a `[sources]` section, and fixtures marked exempt from secret scanning.

### Fixed

- Hardened the `testing` feature guard against fail-open.

## [0.1.1] - 2026-08-13

### Fixed

Five defects found by installing and running release 0.1.0 against a live Proxmox VE cluster:

- **Blocker:** A fresh install could not mint its first token. The installer seeded `tokens.json` with a JSON object (`{"version": 1, "tokens": {}}`) where the loader requires an array (`{"version": 1, "tokens": []}`). Fixed by changing the installer to write the correct envelope.
- **Blocker:** `token add` had no way to set a token's guest grant, so no mintable token could call guest-addressed tools. Added `--guests <selector>` and `--actions <tier>` flags to `rust-proxmoxmcp token add`.
- SIGHUP reloaded the cluster inventory but not the token store, so minting a token and reloading the service appeared to do nothing until a full restart. Fixed by adding `TokenStore` to the `ReloadableState` struct.
- A missing credential file or unreadable CA certificate reported "malformed proxmox response", pointing operators at their Proxmox cluster instead of their filesystem. Fixed by surfacing the underlying I/O error as a configuration error in the reload handler.
- The example inventory (`clusters.example.json`) named a `ca_pem_path` the installer never creates, breaking startup for any cluster with a publicly-trusted certificate. Fixed by removing the key from the example; `ca_pem_path` is now documented as optional and only needed for private CAs.

## [0.1.0] - 2026-08-12

### Added

- **Multi-cluster inventory:** One server process serves many Proxmox VE clusters from a single `clusters.json` file. Each cluster entry specifies its endpoint, API token reference, optional per-cluster CA certificate, and protection policy.
- **Complete read-only catalog:** 16 tools covering cluster status, nodes, guests (QEMU and LXC), storage, backups, ISO images, templates, snapshots, and tasks.
  - Cluster-scoped: `get_cluster_status`, `get_nodes`, `get_vms`, `get_containers`
  - Node-scoped: `get_node_status`, `get_storage`, `list_tasks`
  - Guest-scoped: `get_vm_config`, `get_container_config`, `get_container_ip` (LXC only), `get_guest_status`, `list_snapshots`
  - Storage-scoped: `list_backups`, `list_isos`, `list_templates`
  - Task-scoped: `get_task_status`
- **Two-stage authorization:**
  - Stage 1: Bearer token validation, tool and cluster scope checks (via `mecmcp-auth::authorize_call`)
  - Stage 2 (guest tools only): Guest resolution, grant evaluation (`GuestFacts` against `ProxmoxGrant`), and fail-closed protection enforcement
- **Protection union:** A guest is protected if it appears in `protected_vmids` **or** carries a tag from `protected_tags`. Protected guests cannot be addressed by mutating tools (when implemented), even with wildcard grants.
- **`AuthorizedGuest`:** A type-level authorization proof that a guest passed stage-2 checks. Constructors are `pub(crate)` so guest-addressed catalog calls cannot bypass authorization.
- **Complete `WRITE_TOOLS` registry:** The full mutating catalog is declared in `tier::WRITE_TOOLS` (23 tools across `low` and `destructive` tiers). None are implemented in this release; the registry exists so `authorize_call` refuses them before any catalog lookup.
- **Catalog-driven dispatch:** Every tool's HTTP method, path template, query flag, and type filter is declared once in `catalog.rs`. The runtime resolves `{node}` and `{vmid}` path parameters without per-tool client code.
- **Per-cluster CA pinning:** Each cluster can specify `ca_pem_path` to trust a private CA. No `--insecure` flag exists.
- **SIGHUP reload:** `systemctl reload rust-proxmoxmcp` (or `kill -HUP <pid>`) reloads `clusters.json` in place, invalidates the guest index cache, and logs the result. A failed reload retains the previous snapshot and does not stop the server.
- **Hardened systemd unit:** `ProtectSystem=strict` with `ReadWritePaths=/var/lib/proxmoxmcp` only. `/etc/proxmoxmcp` is read-only to the service process, making inventory edits a root operation.
- **LXC packaging:** `packaging/lxc/install.sh` — a POSIX installer for Debian 13 that creates the service user, installs the binary, writes example configs (only if absent), and installs the systemd unit.
- **Audit logging:** JSON-structured logs with optional PII redaction. Every tool call logs cluster, guest, tier, and protection status.
- **Comprehensive test suite:** 78 tests including:
  - Client retry, bearer token assembly, catalog integrity
  - Authorization stage 1 and stage 2, including out-of-scope and protected-guest refusals
  - Guest resolution, type filtering, protection union
  - Adversarial cases: a token with no grant is refused; `get_container_ip` refuses QEMU guests; protected guests cannot be reached by mutating tools
  - Compile-fail tests ensuring `AuthorizedGuest::new` is not public

### Not Included

- **No mutating tools.** Every destructive operation (`delete_vm`, `delete_container`, `delete_snapshot`, `delete_backup`, `restore_backup`, `rollback_snapshot`) and low-tier operation (`clone_vm`, `create_snapshot`, `create_backup`, start/stop/reset lifecycle) is registered in `WRITE_TOOLS` but unimplemented. Deferred to release 0.2.
- **No override or lab mode.** `--lab-mode`, `--waivers-file`, and the `lab_unrestricted` token flag belong to release 0.3's change-control surface and are deliberately absent.
- **No task streaming or UPID polling.** Task lifecycle (wait-for-completion, progress streaming) is deferred to release 0.2.
- **No lab validation against a real Proxmox cluster.** All 78 tests pass against mock HTTPS servers; the code has not been run against a live Proxmox VE cluster.

### Notes

- The existing deployment (three Python MCP servers, one per cluster endpoint) **remains in service**. This release does not replace it.
- The cluster inventory file uses the top-level key `devices` (the canonical envelope from `mecmcp-inventory`), not `clusters`. Each entry is read as a cluster.
- A bearer token with no `grant` key is refused for guest-addressed tools. This is fail-closed: a grantless token must not become a wildcard.
- The `rust-proxmoxmcp-core` crate has a non-default `testing` feature that pulls in mock-server machinery (`rcgen`, `rustls`, `tokio-rustls`, `tempfile`). This is **not** compiled into the release binary.

[0.1.1]: https://github.com/mechubsec/rustproxmoxmcp/releases/tag/v0.1.1
[0.1.0]: https://github.com/mechubsec/rustproxmoxmcp/releases/tag/v0.1.0
