//! The MCP tool surface for release 0.1: reads only.

mod change_set;
mod firewall_change_set;
mod ha_change_set;
mod restore_change_set;

use mecmcp_auth::{CallerCtx, ScopeSet};
use mecmcp_server::{
    AuthorizationError, OutputRedaction, ResultFormat, ResultLimits, authorize_call,
    caller_from_extensions, filter_tools_for_scope, tool_error, tool_result,
};
use rmcp::{
    RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Implementation, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerConfig,
    },
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use rust_proxmoxmcp_core::{
    Intent, ProxmoxGrant, catalog::read_tool, client::ProxmoxClient, guests::LifecycleVerb,
    inventory::ClusterInventory, resolve::GuestIndex, selector::GuestType, tier::WRITE_TOOLS,
};
use schemars::JsonSchema;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Tool names that exist only as an authorization scope.
///
/// No `#[tool]` handler answers to these — the generic `plan_proxmox_destroy`
/// and `apply_proxmox_change_set` handlers do the work. They are in
/// `KNOWN_TOOLS` so the token CLI accepts them as a scope, and in `WRITE_TOOLS`
/// so a wildcard token does not reach them.
///
/// Enumerated rather than left implicit because two invariants have to know
/// about them: every other `KNOWN_TOOLS` entry must have a handler, and must
/// fall into a known tier category. Naming the exception keeps both checks
/// meaningful for everything else.
#[cfg_attr(not(test), allow(dead_code))]
const AUTHORIZATION_ONLY_TOOLS: &[&str] = &[
    "create_firewall_alias",
    "create_firewall_group",
    "create_firewall_group_rule",
    "create_firewall_ipset",
    "create_firewall_ipset_entry",
    "create_firewall_rule",
    "create_ha_rule",
    "delete_backup",
    "delete_container",
    "delete_firewall_alias",
    "delete_firewall_group",
    "delete_firewall_group_rule",
    "delete_firewall_ipset",
    "delete_firewall_ipset_entry",
    "delete_firewall_rule",
    "delete_ha_rule",
    "delete_iso",
    "delete_snapshot",
    "delete_vm",
    "migrate_container",
    "migrate_vm",
    "restore_backup",
    "restore_backup_new_vmid",
    "rollback_snapshot",
    "update_firewall_alias",
    "update_firewall_group_rule",
    "update_firewall_ipset_entry",
    "update_firewall_options",
    "update_firewall_rule",
    "update_ha_rule",
    "update_vm_config",
];

/// The concrete tool name a destructive operation authorises against.
///
/// `plan_proxmox_destroy` and `apply_proxmox_change_set` are generic handlers.
/// Authorising only those would let a token allowlisted for them select any
/// operation — `op: "delete_backup"` from a token never granted
/// `delete_backup` — which defeats the point of `WRITE_TOOLS` naming each
/// destructive tool separately.
///
/// So the operation maps to its own tool name and that scope is enforced too,
/// at plan and again at apply. Both, because a scope can be narrowed between
/// the two, and the apply is the call that acts.
///
/// `destroy_guest` maps by the *resolved* guest type, because `delete_vm` and
/// `delete_container` are distinct scopes in `WRITE_TOOLS` and the dispatch
/// calls a different primitive for each. Mapping both to `delete_vm` would
/// deny a token granted `delete_container` its own containers, and let a token
/// granted only `delete_vm` delete them.
const fn tool_for_op(op: &str, kind: GuestType) -> Option<&'static str> {
    match op.as_bytes() {
        b"destroy_guest" | b"destroy" => Some(match kind {
            GuestType::Lxc => "delete_container",
            GuestType::Qemu => "delete_vm",
        }),
        b"delete_snapshot" => Some("delete_snapshot"),
        b"rollback_snapshot" => Some("rollback_snapshot"),
        b"delete_backup" => Some("delete_backup"),
        b"delete_iso" => Some("delete_iso"),
        b"restore_backup" => Some("restore_backup"),
        b"migrate" => Some(match kind {
            GuestType::Lxc => "migrate_container",
            GuestType::Qemu => "migrate_vm",
        }),
        // QEMU-only, but named as one tool regardless of `kind`: the plan
        // handler refuses a non-QEMU guest before this is reached, so there
        // is no second guest type for this to distinguish the way
        // `destroy_guest` distinguishes `delete_vm`/`delete_container`.
        b"update_vm_config" => Some("update_vm_config"),
        _ => None,
    }
}

/// Render the preview an approver reviews for one destructive action.
///
/// Operation-specific by necessity. `render_preview` produces a guest-destroy
/// description, so reusing it showed `DESTROY` for a rollback, a restore and a
/// volume deletion alike — an approver would have been asked to sign off on
/// something other than what would run.
///
/// Carries its own `protected`/`waiver` lines rather than delegating to
/// `render_preview`'s, because only `destroy_guest`/`destroy` go through
/// that renderer -- every other operation here (`delete_snapshot`,
/// `rollback_snapshot`, `delete_backup`, `restore_backup`, `migrate`,
/// `update_vm_config`, `delete_iso`) used to have no protection or waiver
/// line at all. Since a matching waiver no longer auto-approves the change
/// set (see the F4 fix), the human approver is the real gate, and they must
/// be told when they are signing off on a protected guest.
fn render_destructive_preview(
    action: &change_set::DestroyAction,
    guest_name: &str,
    node: &str,
    protected: bool,
    protection_summary: &str,
    override_: &rust_proxmoxmcp_core::protect::Override,
) -> String {
    use rust_proxmoxmcp_core::protect::Override;

    let target = format!(
        "{} (vmid {}, {}, node {})",
        guest_name, action.vmid, action.cluster, node
    );
    let body = match action.op.as_str() {
        "destroy_guest" | "destroy" => {
            format!(
                "DESTROY {target}\n  The guest and its disks are removed. This cannot be undone."
            )
        }
        "delete_snapshot" => format!(
            "DELETE SNAPSHOT '{}' of {target}\n  The snapshot is removed. The guest is untouched.",
            action.snapname.as_deref().unwrap_or("?")
        ),
        "rollback_snapshot" => format!(
            "ROLLBACK {target} to snapshot '{}'\n  \
             OVERWRITES the guest's current state. Everything written since that \
             snapshot is lost. This is not a deletion — it is a replacement.",
            action.snapname.as_deref().unwrap_or("?")
        ),
        "delete_backup" => format!(
            "DELETE BACKUP '{}' on storage '{}' at node '{}'\n  \
             The archive is removed. A backup cannot be re-created from the guest \
             as it was when the backup was taken.",
            action.volid.as_deref().unwrap_or("?"),
            action.storage.as_deref().unwrap_or("?"),
            action.storage_node.as_deref().unwrap_or("?")
        ),
        "delete_iso" => format!(
            "DELETE ISO '{}' on storage '{}' at node '{}'\n  \
             The image is removed. It can be downloaded again.",
            action.volid.as_deref().unwrap_or("?"),
            action.storage.as_deref().unwrap_or("?"),
            action.storage_node.as_deref().unwrap_or("?")
        ),
        "restore_backup" => format!(
            "RESTORE {target} from '{}'\n  \
             OVERWRITES the guest with the archive's contents. Unlike a rollback \
             there is no snapshot of the pre-restore state unless one was taken.",
            action.volid.as_deref().unwrap_or("?")
        ),
        "migrate" => {
            let mode = if action.online {
                "LIVE (guest stays running throughout)"
            } else {
                "OFFLINE (guest must be stopped)"
            };
            let disks = if action.with_local_disks {
                " Node-local disks are copied along with the guest."
            } else {
                ""
            };
            format!(
                "MIGRATE {target} to node '{}'\n  {mode} migration.{disks}",
                action.target_node.as_deref().unwrap_or("?")
            )
        }
        "update_vm_config" => {
            let rendered = action.config.as_ref().map_or_else(String::new, |config| {
                config
                    .iter()
                    .map(|(key, value)| {
                        // Cloud-init secrets must not appear in a preview an
                        // approver reads, or that is printed into audit logs
                        // and change-set state on disk.
                        if key.eq_ignore_ascii_case("cipassword") {
                            format!("{key}=<redacted>")
                        } else {
                            format!("{key}={value}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            });
            format!(
                "UPDATE CONFIG {target}\n  Sets: {rendered}\n  \
                 Proxmox merges these into the guest's existing config; keys not listed \
                 here are unchanged.",
            )
        }
        other => format!("UNKNOWN OPERATION '{other}' on {target}"),
    };

    // protected/waiver lines, mirroring `render_preview`'s: always present,
    // so an absent line never has to be read as "not applicable".
    let protected_line = if protected {
        format!("  protected  yes — {protection_summary}")
    } else {
        "  protected  no".to_owned()
    };
    let waiver_line = match override_ {
        Override::None => "  waiver     none".to_owned(),
        Override::Waiver { reason, ticket, .. } => {
            if let Some(ticket) = ticket {
                format!("  waiver     {ticket} — {reason}")
            } else {
                format!("  waiver     {reason}")
            }
        }
        Override::LabMode => "  waiver     lab-mode".to_owned(),
    };

    format!("{body}\n{protected_line}\n{waiver_line}")
}

/// Build and validate the action a destructive plan will record.
///
/// Each operation names exactly the parameters it needs, and a missing one is
/// refused here rather than defaulted at apply time. The action is what the
/// change-set digest covers, so anything not decided now is something the
/// approver cannot have reviewed.
fn build_destroy_action(
    args: &change_set::PlanDestroyArgs,
) -> Result<change_set::DestroyAction, String> {
    let require = |value: &Option<String>, name: &str| -> Result<String, String> {
        value
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned()
            .ok_or_else(|| format!("{} requires {name}", args.op))
    };

    // For the fields that become URL *path segments*, non-empty is not enough.
    // `mecmcp_openapi::expand_path` refuses a segment carrying a structural
    // byte, and it does so at apply time -- after the change set has been
    // planned, approved and claimed. Rejecting it here keeps that state
    // unreachable: the plan fails before anything is recorded, rather than an
    // approved change set failing locally and leaving a claimed record whose
    // outcome is, on its face, unknown.
    //
    // Not applied to `volid`, which is a query parameter and legitimately
    // contains '/' -- `local:backup/vzdump-...` is a well-formed volid.
    let require_segment = |value: &Option<String>, name: &str| -> Result<String, String> {
        let value = require(value, name)?;
        // Delegates to `expand_path`, so this is the same grammar the request
        // path enforces rather than a second, weaker copy of it.
        rust_proxmoxmcp_core::guests::validate_path_segment(&value, name)
            .map_err(|error| format!("{} refuses {name}: {error}", args.op))?;
        Ok(value)
    };

    let mut storage_node = None;
    let mut target_node = None;
    let mut config = None;
    let (snapname, storage, volid) = match args.op.as_str() {
        // What 0.3 planned, and still the default.
        "destroy_guest" => (None, None, None),
        "migrate" => {
            target_node = Some(require_segment(&args.target_node, "target_node")?);
            (None, None, None)
        }
        "update_vm_config" => {
            if args.config.is_empty() {
                return Err("update_vm_config requires config".to_owned());
            }
            if let Some(message) = reject_unsafe_vm_config(&args.config) {
                return Err(message);
            }
            config = Some(args.config.clone());
            (None, None, None)
        }
        "delete_snapshot" | "rollback_snapshot" => (
            Some(require_segment(&args.snapname, "snapname")?),
            None,
            None,
        ),
        "delete_backup" | "delete_iso" => {
            // `local` is node-local storage, so the node is part of the
            // volume's identity rather than a detail of where to send the
            // request. Required at plan time and recorded in the action, so
            // apply cannot derive it from whichever guest the vmid names.
            storage_node = Some(require_segment(&args.storage_node, "storage_node")?);
            let storage_val = require_segment(&args.storage, "storage")?;
            let volid_val = require(&args.volid, "volid")?;

            // Validate content kind matches operation at plan time, before any
            // approval is issued. Without this, a token scoped for delete_iso
            // could plan to delete backups by passing a backup/ volid.
            let expected_kind = match args.op.as_str() {
                "delete_backup" => "backup",
                "delete_iso" => "iso",
                _ => unreachable!("matched arm checks these exhaustively"),
            };
            rust_proxmoxmcp_core::guests::validate_volid_for_operation(
                &volid_val,
                &storage_val,
                expected_kind,
            )
            .map_err(|error| error.to_string())?;

            (None, Some(storage_val), Some(volid_val))
        }
        // No storage: the archive volid names its own storage, and accepting a
        // second one invites the two to disagree.
        "restore_backup" => {
            let volid_val = require(&args.volid, "volid")?;
            // Validate it's a backup volid. restore_backup uses the volid to
            // name the archive, and the storage is embedded in the volid itself
            // (e.g., local:backup/x), so there's no separate storage parameter
            // to bind against. We validate only the content kind.
            rust_proxmoxmcp_core::guests::validate_volid_kind(&volid_val, "backup")
                .map_err(|error| error.to_string())?;
            (None, None, Some(volid_val))
        }
        other => {
            return Err(format!(
                "unknown destructive operation '{other}'; expected one of \
                 destroy_guest, delete_snapshot, rollback_snapshot, delete_backup, \
                 delete_iso, restore_backup, migrate, update_vm_config"
            ));
        }
    };

    Ok(change_set::DestroyAction {
        op: args.op.clone(),
        cluster: args.cluster.clone(),
        vmid: args.vmid,
        snapname,
        storage,
        volid,
        storage_node,
        target_node,
        online: args.online,
        with_local_disks: args.with_local_disks,
        config,
    })
}

/// The operation-required fields an action does not carry.
///
/// Mirrors the `missing(...)` arms of `execute_destructive`, which is the only
/// other place these requirements are written down. That function reports an
/// absent field as `ProxmoxError::Malformed`, and `Malformed` is not in the
/// `definitive` set -- so an incomplete record reaching it writes apply intent,
/// fails, and emits no result receipt. The chain is then stranded at intent,
/// which reads as "the request may have been sent, go and look", for an
/// operation that never left the process.
///
/// `build_destroy_action` requires all of these at plan time, so a record
/// planned by this version cannot be incomplete. The exposure is exactly the
/// records the apply-time checks exist for: planned by an older version,
/// imported, or hand-written.
fn missing_required_fields(action: &change_set::DestroyAction) -> Vec<&'static str> {
    // Present means non-empty, matching `build_destroy_action`, whose `require`
    // closure filters empty strings out at plan time. Treating `""` as present
    // here would send an action that planning would have refused on to
    // `expand_path`, which rejects the empty segment as `Malformed` -- after
    // the intent write, which is the state this whole check exists to avoid.
    let present = |field: &Option<String>| field.as_ref().is_some_and(|v| !v.is_empty());

    // Each arm declares what its operation needs, in the order
    // `execute_destructive` asks for them, so the two can be read side by side.
    let required: Vec<(&'static str, bool)> = match action.op.as_str() {
        // `destroy_guest`/`destroy` name the guest and nothing else.
        "destroy_guest" | "destroy" => Vec::new(),
        "delete_snapshot" | "rollback_snapshot" => {
            vec![("snapname", present(&action.snapname))]
        }
        "delete_backup" | "delete_iso" => vec![
            ("storage", present(&action.storage)),
            ("volid", present(&action.volid)),
            ("storage_node", present(&action.storage_node)),
        ],
        "restore_backup" => vec![("volid", present(&action.volid))],
        "migrate" => vec![("target_node", present(&action.target_node))],
        "update_vm_config" => vec![(
            "config",
            action.config.as_ref().is_some_and(|c| !c.is_empty()),
        )],
        // An unrecognised op is already refused by `tool_for_op` before this
        // runs; naming fields for it here would be guesswork.
        _ => Vec::new(),
    };

    required
        .into_iter()
        .filter(|(_, present)| !present)
        .map(|(name, _)| name)
        .collect()
}

/// The guest type a catalog path names, when it names one.
///
/// `/nodes/{node}/qemu/{vmid}/config` is a QEMU-only endpoint; the type is part
/// of the path rather than a parameter. Paths that template `{kind}` serve both
/// and return `None`.
fn kind_named_in(path: &str) -> Option<&'static str> {
    if path.contains("/qemu/") {
        return Some("qemu");
    }
    if path.contains("/lxc/") {
        return Some("lxc");
    }
    None
}

/// Whether an operation needs the guest stopped before Proxmox will do it.
///
/// A destroy is refused outright by Proxmox while the guest runs, because this
/// server sends `purge` and never `force` -- deliberately, since forcing would
/// silently widen "destroy this" into "kill it first, then destroy it", which
/// is not what an approver read.
///
/// The volume operations do not touch the guest, and a rollback or restore
/// stops it as part of the operation, so neither is listed.
fn destroy_requires_a_stopped_guest(op: &str) -> bool {
    matches!(op, "destroy_guest" | "destroy")
}

/// Refuse `delete_iso` for a token whose guest scope is narrowed.
///
/// `delete_iso` names a vmid only so the usual guest-scope and protection
/// machinery has something to check, but the ISO it deletes lives on
/// node/cluster storage that every guest shares -- it is not actually scoped
/// to that vmid. A token narrowed to `vmid:600-699` naming any in-scope guest
/// could otherwise delete an ISO relied on by guests outside its scope,
/// including ones it could never touch directly. `download_iso` already
/// requires an unrestricted scope for the same reason (see its handler); this
/// closes the equivalent hole on the delete side.
fn require_unrestricted_scope_for_delete_iso(
    op: &str,
    grant: &rust_proxmoxmcp_core::grant::ProxmoxGrant,
) -> Result<(), String> {
    if op == "delete_iso" && !grant.is_unrestricted_guest_scope() {
        return Err(
            "delete_iso deletes from storage that is not scoped to any guest, so it requires a \
             caller whose guest scope is '*'. This caller is narrowed to specific guests and \
             cannot be checked against a storage."
                .to_owned(),
        );
    }
    Ok(())
}

/// Refuse a migration plan Proxmox would refuse anyway, before an approval is
/// spent on it.
///
/// A live migration (`online`) needs a running guest to migrate live; an
/// offline one needs the guest already stopped, since neither this server nor
/// (for LXC) stock Proxmox negotiates a stop/restart on the caller's behalf
/// for an *offline* request -- only `online` on a container asks Proxmox for
/// its own stop/migrate/restart cycle. Checked here for the same reason
/// [`destroy_requires_a_stopped_guest`] is checked before planning: discovering
/// this at apply spends a second principal's approval on an operation that
/// cannot succeed.
fn migrate_precondition(online: bool, status: &str) -> Result<(), String> {
    if online && status != "running" {
        return Err(format!(
            "guest reports status '{status}'; a live migration (online) requires a running \
             guest. Start it first, or plan an offline migration instead."
        ));
    }
    if !online && status != "stopped" {
        return Err(format!(
            "guest reports status '{status}'; an offline migration requires a stopped guest. \
             Stop it first, or plan with online: true for a live migration."
        ));
    }
    Ok(())
}

/// Principal recorded on a receipt written by startup recovery.
///
/// The executor of an apply is the token that called
/// `apply_proxmox_change_set`, which is not the approver — two-person control
/// exists so those differ. When the process that knew the executor dies before
/// writing the receipt, that identity is simply gone, and no field on the
/// change set carries it. An explicit marker says so; reusing the approver
/// would put a name on a destructive execution that person did not perform.
const RECOVERED_EXECUTOR: &str = "unknown:recovered-at-startup";

/// Poll a Proxmox task to completion and return its exit status text.
///
/// Shared by every apply path that issues a vendor task and must wait for
/// it -- `apply_change_set` and `apply_restore_new_vmid` -- so the polling
/// cadence and its error handling exist in one place rather than diverging
/// between them. Evidence-writing is deliberately not folded in here: each
/// caller records its own apply-intent and result-receipt against its own
/// change-set record and device string, which this function has no access to.
async fn poll_proxmox_task(
    client: &ProxmoxClient,
    node: &str,
    upid_str: &str,
) -> Result<String, Box<CallToolResult>> {
    let token = tokio_util::sync::CancellationToken::new();
    let config = mecmcp_job::PollConfig {
        first_interval: std::time::Duration::from_secs(1),
        max_interval: std::time::Duration::from_secs(8),
        multiplier: 2,
        deadline: std::time::Duration::from_secs(300),
    };

    let poll_node = node.to_owned();
    let poll_upid = upid_str.to_owned();
    match mecmcp_job::poll_until_ready(&token, config, |_attempt| {
        let node = poll_node.clone();
        let upid_str = poll_upid.clone();
        async move {
            // URL-encode the UPID for the path.
            let upid_encoded = upid_str.replace(':', "%3A");
            let path = format!("/api2/json/nodes/{node}/tasks/{upid_encoded}/status");
            let data = client
                .get_json(&path, &[], &[])
                .await
                .map_err(|error| format!("task status request failed: {error}"))?;

            let status = data
                .get("status")
                .and_then(|v| v.as_str())
                .ok_or_else(|| "status field missing or not a string".to_string())?;

            if status == "running" {
                Ok(mecmcp_job::Probe::Pending)
            } else if status == "stopped" {
                let exitstatus = data
                    .get("exitstatus")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| "exitstatus field missing or not a string".to_string())?;
                Ok(mecmcp_job::Probe::Ready(exitstatus.to_owned()))
            } else {
                Err(format!("unexpected task status: {status}"))
            }
        }
    })
    .await
    {
        Ok(exitstatus) => Ok(exitstatus),
        Err(mecmcp_job::PollError::Cancelled { attempts }) => Err(Box::new(tool_error(format!(
            "polling cancelled after {attempts} attempt(s)"
        )))),
        Err(mecmcp_job::PollError::DeadlineExceeded { attempts, deadline }) => {
            Err(Box::new(tool_error(format!(
                "polling exceeded its {deadline:?} deadline after {attempts} attempt(s)"
            ))))
        }
        Err(mecmcp_job::PollError::Probe { attempts, source }) => Err(Box::new(tool_error(
            format!("probe failed on attempt {attempts}: {source}"),
        ))),
        Err(mecmcp_job::PollError::Config(error)) => Err(Box::new(tool_error(format!(
            "invalid poll configuration: {error}"
        )))),
    }
}

/// Result size limits for MCP tool responses.
const RESULT_LIMITS: ResultLimits = ResultLimits {
    max_text_bytes: 512 * 1024,
    max_json_bytes: 512 * 1024,
};

/// Records returned by a paginated list tool when `limit` is omitted.
///
/// MEC-479: `get_vms`/`get_containers` and `list_backups` have no
/// server-side page size of their own -- Proxmox's `/cluster/resources` and
/// storage `content` endpoints don't take `start`/`limit`, so this executor
/// fetches the full upstream array and pages it here rather than pushing
/// pagination down per-endpoint (which would give the one generic
/// `serve_read` two different behaviors for no real gain, since fetching the
/// full array is what `MAX_RESPONSE_BYTES` already tolerates -- the binding
/// constraint is the *result* cap below, not the upstream fetch).
///
/// `list_tasks` is deliberately not in this list: `/nodes/{node}/tasks` *is*
/// server-side windowed by Proxmox (a few hundred most recent, by default),
/// with no way for this client to learn the true total. A client-side
/// pagination envelope on top of that window would report `has_more: false`
/// once Proxmox's own cutoff is reached, claiming a complete task history
/// that silently drops everything Proxmox already dropped. `list_tasks`
/// stays a bare array (MEC-871, from Percy's review of MEC-479's PR); pushing
/// real `start`/`limit` down to Proxmox for this endpoint is tracked as a
/// separate follow-up.
///
/// At ~540 bytes per pretty-printed `get_vms` record (MEC-456's lab
/// measurement), 500 records is ~270 KB, leaving headroom under
/// `RESULT_LIMITS.max_json_bytes` for the pagination envelope and any wider
/// record shape (`list_backups` entries run larger).
const DEFAULT_PAGE_LIMIT: u32 = 500;

/// Largest `limit` a caller may request explicitly.
///
/// 700 records is ~378 KB of `get_vms`-shaped pretty JSON -- comfortably
/// under the 512 KiB cap, with room to spare for narrower record shapes to
/// use if they choose. A caller asking for more is refused rather than
/// silently clamped, so a page size that would risk crossing the cap is
/// never issued without the caller having asked for it, and refused, in
/// plain terms.
const MAX_PAGE_LIMIT: u32 = 700;

/// Resolve and validate `offset`/`limit` for a paginated read tool.
///
/// # Errors
///
/// Returns a tool error when `limit` is zero or exceeds [`MAX_PAGE_LIMIT`].
fn resolve_page(
    offset: Option<u32>,
    limit: Option<u32>,
) -> Result<(u32, u32), Box<CallToolResult>> {
    let limit = limit.unwrap_or(DEFAULT_PAGE_LIMIT);
    if limit == 0 {
        return Err(Box::new(tool_error("limit must be at least 1")));
    }
    if limit > MAX_PAGE_LIMIT {
        return Err(Box::new(tool_error(format!(
            "limit {limit} exceeds the maximum of {MAX_PAGE_LIMIT}; request a smaller page"
        ))));
    }
    Ok((offset.unwrap_or(0), limit))
}

/// One page of a list tool's results.
///
/// `total` and `has_more` are what let a caller stop paging: a MCP client
/// cannot otherwise tell a short list from a truncated one, and this server's
/// house rule is to fail closed rather than truncate silently -- so a page
/// says exactly how much was left out, and lets the caller ask for it.
#[derive(Debug, serde::Serialize)]
struct Page {
    items: Vec<serde_json::Value>,
    /// Total records available upstream, after any type/content filter.
    total: usize,
    offset: u32,
    limit: u32,
    /// Whether records remain beyond this page.
    has_more: bool,
}

/// Sort a page-bound array by a stable per-record key, so a record's
/// position (and therefore which page it lands on) doesn't depend on
/// Proxmox's undocumented, unstable array order.
///
/// Without this, a guest created, destroyed or migrated between two
/// `offset` calls -- or a backup pruned by vzdump -- can shift the window
/// and skip or duplicate a record across pages with no sign to the caller
/// (MEC-871, finding 2). Sorting cannot fix a record deleted between page
/// calls; it only stops *reordering* from causing skips.
///
/// Dispatches on which key field the first record carries: `vmid` for
/// `get_vms`/`get_containers`, `volid` for `list_backups`. Records missing
/// the key sort last rather than panicking on a shape this code doesn't
/// expect.
fn sort_for_paging(array: &mut [serde_json::Value]) {
    let Some(first) = array.first() else {
        return;
    };
    if first.get("vmid").is_some() {
        array.sort_by_key(|item| {
            item.get("vmid")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(u64::MAX)
        });
    } else if first.get("volid").is_some() {
        array.sort_by(|a, b| {
            let key = |v: &serde_json::Value| {
                v.get("volid")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_owned()
            };
            key(a).cmp(&key(b))
        });
    }
}

/// Slice a filtered upstream array into one page.
///
/// # Errors
///
/// Returns a tool error if `value` is not a JSON array -- defensive, since
/// every catalog entry this is called for returns one, but a Proxmox
/// response shape changing underneath this code must not panic on `expect`.
fn paginate(
    value: serde_json::Value,
    offset: u32,
    limit: u32,
) -> Result<Page, Box<CallToolResult>> {
    let Some(mut array) = value.as_array().cloned() else {
        return Err(Box::new(tool_error(
            "upstream response is not a list; cannot paginate",
        )));
    };
    sort_for_paging(&mut array);
    let total = array.len();
    let start = (offset as usize).min(total);
    let end = start.saturating_add(limit as usize).min(total);
    let items = array[start..end].to_vec();
    let has_more = end < total;
    Ok(Page {
        items,
        total,
        offset,
        limit,
        has_more,
    })
}

/// Every tool registered by this release. Kept sorted; asserted against the
/// catalog by a test so the two cannot drift.
pub const KNOWN_TOOLS: &[&str] = &[
    "apply_firewall_change",
    "apply_ha_rule_change",
    "apply_proxmox_change_set",
    "apply_restore_new_vmid",
    "approve_firewall_change",
    "approve_ha_rule_change",
    "approve_proxmox_change_set",
    "clone_vm",
    "create_backup",
    "create_container",
    "create_firewall_alias",
    "create_firewall_group",
    "create_firewall_group_rule",
    "create_firewall_ipset",
    "create_firewall_ipset_entry",
    "create_firewall_rule",
    "create_ha_rule",
    "create_snapshot",
    "create_vm",
    "delete_backup",
    "delete_container",
    "delete_firewall_alias",
    "delete_firewall_group",
    "delete_firewall_group_rule",
    "delete_firewall_ipset",
    "delete_firewall_ipset_entry",
    "delete_firewall_rule",
    "delete_ha_rule",
    "delete_iso",
    "delete_snapshot",
    "delete_vm",
    "download_iso",
    "get_cluster_firewall_options",
    "get_cluster_firewall_rules",
    "get_cluster_status",
    "get_container_config",
    "get_container_ip",
    "get_containers",
    "get_firewall_change_set",
    "get_firewall_ipset_entries",
    "get_firewall_security_group_rules",
    "get_guest_firewall_ipset_entries",
    "get_guest_firewall_options",
    "get_guest_firewall_rules",
    "get_guest_status",
    "get_ha_rule",
    "get_ha_rule_change_set",
    "get_node_firewall_options",
    "get_node_firewall_rules",
    "get_node_status",
    "get_nodes",
    "get_proxmox_change_set",
    "get_storage",
    "get_task_status",
    "get_vm_config",
    "get_vms",
    "list_backups",
    "list_firewall_aliases",
    "list_firewall_ipsets",
    "list_firewall_security_groups",
    "list_guest_firewall_aliases",
    "list_guest_firewall_ipsets",
    "list_ha_rules",
    "list_isos",
    "list_snapshots",
    "list_tasks",
    "list_templates",
    "migrate_container",
    "migrate_vm",
    "plan_firewall_change",
    "plan_ha_rule_change",
    "plan_proxmox_destroy",
    "plan_restore_new_vmid",
    "reset_vm",
    "resize_disk",
    "restart_container",
    "restore_backup",
    "restore_backup_new_vmid",
    "rollback_snapshot",
    "shutdown_vm",
    "start_container",
    "start_vm",
    "stop_container",
    "stop_task",
    "stop_vm",
    "update_container_resources",
    "update_firewall_alias",
    "update_firewall_group_rule",
    "update_firewall_ipset_entry",
    "update_firewall_options",
    "update_firewall_rule",
    "update_ha_rule",
    "update_vm_config",
];

/// Arguments for a cluster-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ClusterArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
}

/// Arguments for a node-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct NodeArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
}

/// Arguments for a read scoped to one HA rule.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct HaRuleArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// HA rule id, as reported by `list_ha_rules`.
    pub rule: String,
}

/// Arguments for a cluster-scoped, paginated read.
///
/// Kept separate from [`ClusterArgs`] rather than adding `offset`/`limit`
/// there, so `get_cluster_status` and `get_nodes` -- which return a handful
/// of records and cannot exceed the result cap -- don't advertise pagination
/// parameters that would do nothing.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagedClusterArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Zero-based index of the first record to return. Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
    /// Maximum records to return. Defaults to 500, capped at 700 so a
    /// pretty-printed page stays comfortably under the MCP result's 512 KiB
    /// limit.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for a guest-scoped read.
///
/// There is deliberately no `node` field. Guests migrate between nodes, and the
/// server resolves the current one on every call; accepting a node from the
/// caller is how a request addresses the wrong guest after a migration.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GuestArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id, unique within the cluster.
    pub vmid: u32,
}

/// Arguments for cloning one guest.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct CloneArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Guest to clone from.
    pub vmid: u32,
    /// VMID for the new guest. Must not be a protected pin.
    pub newid: u32,
    /// Name or hostname for the clone. Optional.
    #[serde(default)]
    pub name: Option<String>,
    /// Full copy rather than a linked clone.
    ///
    /// Defaults to a full copy: a linked clone shares base storage with its
    /// source, so deleting the source later breaks the clone. The cheaper
    /// option should be asked for, not assumed.
    #[serde(default = "default_true")]
    pub full: bool,
}

/// A download URL with its credentials removed, for the audit record.
///
/// A presigned or private URL carries its authorisation in the userinfo or the
/// query string. The audit log is durable and may be shipped onward, so the
/// full URL must not go into it -- the origin and path are what an auditor
/// needs to know what was fetched.
fn redact_download_url(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority_and_path, query) = match rest.split_once('?') {
        Some((head, _)) => (head, true),
        None => (rest, false),
    };
    // Anything before an '@' in the authority is userinfo.
    let authority_and_path = match authority_and_path.split_once('/') {
        Some((authority, path)) => {
            let authority = authority.rsplit('@').next().unwrap_or(authority);
            format!("{authority}/{path}")
        }
        None => authority_and_path
            .rsplit('@')
            .next()
            .unwrap_or(authority_and_path)
            .to_owned(),
    };
    let suffix = if query { "?<redacted>" } else { "" };
    if scheme.is_empty() {
        format!("{authority_and_path}{suffix}")
    } else {
        format!("{scheme}://{authority_and_path}{suffix}")
    }
}

/// Config key families `create_vm`/`create_container` accept, by exact match
/// (case-insensitive).
///
/// `create_guest` forwards arbitrary key/value pairs to Proxmox, which is what
/// lets one function serve both QEMU and LXC without modelling either. That
/// passthrough was previously safe only if every dangerous key was named on a
/// denylist -- `archive`/`restore`/`force` (turn a create into a *restore*:
/// `guests::restore_backup` posts to the same endpoint with the same body
/// shape, so a token holding only `create_vm` could overwrite an existing
/// guest, skipping the destructive tier, the protection check and change-set
/// approval entirely), `hookscript`/`args` (run on the node), `mpN`/
/// `hostpciN`/`usbN`/`devN`/`serialN` (host mounts and device passthrough),
/// `lxc.*` (raw LXC config expressing all of the above), and `cicustom`
/// (cloud-init snippets from storage) -- but a denylist only refuses what it
/// names, and it missed the one that matters most: a disk key
/// (`scsiN`/`ideN`/`rootfs`/...) can carry `import-from=<volid>` or name an
/// existing volume directly (`local-lvm:vm-905-disk-0`), attaching another
/// guest's disk to a brand-new vmid with no approval step at all. An
/// allowlist of the cloud-init, sizing, metadata and network families this
/// tool exists for, plus disk keys restricted to a *new* allocation (checked
/// separately in `reject_unsafe_config`), closes that and every future
/// denylist gap by construction.
const ALLOWED_CREATE_CONFIG_KEYS: &[&str] = &[
    // cloud-init
    "ciuser",
    "sshkeys",
    "nameserver",
    "searchdomain",
    "citype",
    "ciupgrade",
    // sizing
    "cores",
    "sockets",
    "memory",
    "balloon",
    "cpu",
    "numa",
    "swap",
    // metadata
    "name",
    "hostname",
    "description",
    "tags",
    "onboot",
    "startup",
    "agent",
    // boot/platform -- no device, host path, or other-guest reach
    "ostype",
    "arch",
    "bios",
    "scsihw",
    "boot",
    "machine",
    "vga",
    "features",
    // container privilege flag; value-checked separately
    "unprivileged",
    // container template image; value-checked separately (must be a vztmpl
    // volid, not an arbitrary path)
    "ostemplate",
    // LXC default mountpoint storage, and the plural cloud-init key some
    // callers send instead of `sshkeys` -- both are plain strings with no
    // device, host path, or other-guest reach
    "storage",
    "ssh-public-keys",
];

/// Key prefixes `create_vm`/`create_container` accept unconditionally, where
/// Proxmox numbers the key.
const ALLOWED_CREATE_CONFIG_PREFIXES: &[&str] = &["ipconfig", "net"];

/// Disk key prefixes a create may allocate a *new* volume under, where
/// Proxmox numbers the key.
const CREATE_DISK_KEY_PREFIXES: &[&str] = &["scsi", "ide", "sata", "virtio"];

/// Disk keys a create may allocate a new volume under by exact match.
const CREATE_DISK_KEY_EXACT: &[&str] = &["rootfs", "efidisk0", "tpmstate0"];

/// Whether `key` names a disk a create may allocate a new volume under.
fn is_create_disk_key(lower: &str) -> bool {
    CREATE_DISK_KEY_EXACT.contains(&lower)
        || CREATE_DISK_KEY_PREFIXES.iter().any(|prefix| {
            lower
                .strip_prefix(prefix)
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Whether `key` is inside `create_vm`/`create_container`'s allowlist.
fn is_allowed_create_config_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    ALLOWED_CREATE_CONFIG_KEYS.contains(&lower.as_str())
        || ALLOWED_CREATE_CONFIG_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        || is_create_disk_key(&lower)
}

/// Whether `value` contains a Proxmox volume name (`vm-<n>-...` or
/// `base-<n>-...`) anywhere in it, not just as the whole field.
///
/// `import-from=local-lvm:vm-905-disk-0` is the spelling `disk_value_is_new_allocation`
/// exists to catch via its option-name check; this is the same fact checked
/// independent of which option carries it; Proxmox does not require the
/// volume reference to be the value of a key named `import-from` or `file`.
fn contains_volume_reference(value: &str) -> bool {
    for prefix in ["vm-", "base-"] {
        let mut rest = value;
        while let Some(idx) = rest.find(prefix) {
            let after = &rest[idx + prefix.len()..];
            let digits = after.len() - after.trim_start_matches(|c: char| c.is_ascii_digit()).len();
            if digits > 0 && after[digits..].starts_with('-') {
                return true;
            }
            rest = &rest[idx + prefix.len()..];
        }
    }
    false
}

/// Whether a disk key's value allocates a *new* volume rather than
/// referencing an existing one.
///
/// Proxmox's grammar is `<storage>:<size-or-volref>[,opt=val,...]`. A fresh
/// allocation's leading field is a bare size in GB (`32`, `32.5`); an
/// existing volume's is a Proxmox volume name (`vm-905-disk-0`,
/// `base-905-disk-0`), and `import-from=<volid>` names a second volume
/// entirely outside the leading field. Refusing anything but a bare numeric
/// leading field, with no `import-from`/`file` option and no volume name
/// anywhere in the value, closes all three spellings by construction: an
/// unqualified disk key otherwise lets a 'low' create attach, import, or
/// alias another guest's disk -- going around the guest scope a 'low' tier,
/// which was never meant to reach any guest but the new one, promises.
fn disk_value_is_new_allocation(value: &str) -> bool {
    let Some((_, rest)) = value.split_once(':') else {
        return false;
    };
    let mut fields = rest.split(',');
    let Some(size) = fields.next() else {
        return false;
    };
    if size.is_empty() || !size.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
        return false;
    }
    for field in fields {
        let option_key = field
            .split_once('=')
            .map_or(field, |(key, _)| key)
            .trim()
            .to_ascii_lowercase();
        if option_key == "import-from" || option_key == "file" {
            return false;
        }
    }
    !contains_volume_reference(value)
}

/// Whether a disk value is a cloud-init drive, an empty cdrom, or an ISO
/// attached read-only -- the three disk-key shapes real Proxmox creates send
/// that are not a size-based new allocation, and that still carry no path to
/// another guest's data: a cloud-init drive is server-managed and empty at
/// create time, an empty cdrom names no volume at all, and an ISO's content
/// kind is checked the same way `restore_backup`'s volid is, via
/// `validate_volid_kind`.
fn disk_value_is_allowed_media(value: &str) -> bool {
    if value == "none,media=cdrom" {
        return true;
    }
    if let Some((storage, rest)) = value.split_once(':')
        && !storage.is_empty()
        && rest == "cloudinit"
    {
        return true;
    }
    if let Some((volid, rest)) = value.split_once(',')
        && rest == "media=cdrom"
        && rust_proxmoxmcp_core::guests::validate_volid_kind(volid, "iso").is_ok()
    {
        return true;
    }
    false
}

/// Config key families `update_vm_config` accepts, by exact match
/// (case-insensitive).
///
/// An allowlist, not a denylist: `update_vm_config` reaches Proxmox's
/// `POST .../qemu/{vmid}/config`, which accepts far more than these families
/// (disk attach/import, `delete`/`revert`, host device passthrough, node-run
/// scripts, boot-media changes, the protection flag). Enumerating what this
/// tool refuses missed real cases -- `delete=protection` removes the
/// protection flag without ever naming it, and a disk key can attach or
/// `import-from` another guest's volume, going around the guest scope this
/// server promises. An allowlist of the cloud-init, sizing and metadata
/// families this tool exists for closes that gap by construction: anything
/// not named here is refused, whatever Proxmox later adds.
///
/// `cipassword` is deliberately not here -- see its own refusal in
/// `reject_unsafe_vm_config`.
const ALLOWED_VM_CONFIG_KEYS: &[&str] = &[
    // cloud-init
    "ciuser",
    "sshkeys",
    "nameserver",
    "searchdomain",
    "citype",
    "ciupgrade",
    // sizing
    "cores",
    "sockets",
    "memory",
    "balloon",
    "cpu",
    "numa",
    // metadata
    "name",
    "description",
    "tags",
    "onboot",
    "startup",
    "agent",
];

/// Key prefixes `update_vm_config` accepts, where Proxmox numbers the key
/// (`ipconfig0`, `ipconfig1`, ...).
///
/// `netN` is handled separately in `reject_unsafe_vm_config`, because it is
/// accepted only conditionally (firewall left on), not unconditionally like
/// these.
const ALLOWED_VM_CONFIG_PREFIXES: &[&str] = &["ipconfig"];

/// Whether `key` is inside `update_vm_config`'s allowlist, either by exact
/// match or by an allowed prefix followed by a Proxmox index.
fn is_allowed_vm_config_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    ALLOWED_VM_CONFIG_KEYS.contains(&lower.as_str())
        || ALLOWED_VM_CONFIG_PREFIXES.iter().any(|prefix| {
            lower
                .strip_prefix(prefix)
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()))
        })
}

/// Config keys whose value carries an absolute host path in any
/// comma-separated field, under any key.
///
/// Proxmox storage references are `storage:spec`; an absolute path names the
/// hypervisor's own filesystem rather than a guest disk or a cloud-init
/// value. Shared between `reject_unsafe_config` (guest creation) and
/// `reject_unsafe_vm_config` (QEMU config update). Pure key-name logic, with
/// no dependency on `Self`.
fn config_host_paths(config: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    config
        .iter()
        .filter(|(_, value)| {
            value.split(',').any(|field| {
                let candidate = field.split_once('=').map_or(field, |(_, v)| v);
                candidate.starts_with('/')
            })
        })
        .map(|(key, _)| key.clone())
        .collect()
}

/// Refuse config `update_vm_config` must not be able to express.
///
/// Four checks: `cipassword` refused outright, an allowlist of key families
/// (anything not in `ALLOWED_VM_CONFIG_KEYS`/`ALLOWED_VM_CONFIG_PREFIXES` and
/// not a `netN` key is refused), `netN` accepted only when its value
/// explicitly keeps the per-interface firewall on, and an absolute host path
/// in any surviving value as defense in depth.
///
/// The key check is an allowlist rather than a denylist: a denylist here
/// previously missed `delete=<key>` (removes a key, including `protection`,
/// without ever naming it as a value), `firewall=off`/`firewall=false`
/// (Proxmox accepts more boolean spellings than `firewall=0`), a bare `netN`
/// with no `firewall=` field at all (Proxmox defaults an unspecified
/// interface firewall to off), and disk/media keys (`scsiN`, `ideN`, ...,
/// including `import-from`, which can pull another guest's volume into this
/// one, going around the guest scope this server promises). An allowlist of
/// the cloud-init, sizing and metadata families this tool exists for closes
/// all of those by construction instead of enumerating each one.
///
/// Returns the refusal text, or `None` when nothing is refused. A free
/// function rather than a `ProxmoxServer` method, because `build_destroy_action`
/// -- which validates a plan's config at the point the change-set action is
/// built, before any `CallToolResult` exists to return -- needs to call it
/// too.
fn reject_unsafe_vm_config(config: &std::collections::BTreeMap<String, String>) -> Option<String> {
    if let Some(key) = config
        .keys()
        .find(|key| key.eq_ignore_ascii_case("cipassword"))
    {
        return Some(format!(
            "config field '{key}' is refused: a cloud-init password would be stored in \
             plaintext in the change-set record until it is pruned. Use 'sshkeys' for \
             cloud-init authentication instead."
        ));
    }

    let disallowed: Vec<String> = config
        .keys()
        .filter(|key| {
            let lower = key.to_ascii_lowercase();
            !lower.starts_with("net") && !is_allowed_vm_config_key(key)
        })
        .cloned()
        .collect();
    if !disallowed.is_empty() {
        return Some(format!(
            "config field(s) {} are refused: a config update accepts only cloud-init, sizing \
             and metadata keys, plus 'netN' with its firewall left on. Disk, media, device \
             passthrough, 'delete'/'revert', host-run scripts, boot-media and protection \
             changes are outside this tool's mandate. Set them from the Proxmox UI if you \
             genuinely need them.",
            disallowed.join(", ")
        ));
    }

    if let Some(net_key) = config.iter().find_map(|(key, value)| {
        let is_net = key.to_ascii_lowercase().starts_with("net");
        let firewall_on = value
            .split(',')
            .any(|field| field.trim().eq_ignore_ascii_case("firewall=1"));
        (is_net && !firewall_on).then(|| key.clone())
    }) {
        return Some(format!(
            "config field '{net_key}' must explicitly set 'firewall=1'. A config update must \
             not leave the guest's per-interface firewall unset or disabled -- Proxmox \
             defaults an interface with no 'firewall=' field to off. Change it from the \
             Proxmox UI if a disabled firewall is intended."
        ));
    }

    let host_pathed = config_host_paths(config);
    if !host_pathed.is_empty() {
        return Some(format!(
            "config field(s) {} carry an absolute host path. A guest disk is named \
             'storage:spec'; a path names the hypervisor's own filesystem, which a config \
             update must not reach.",
            host_pathed.join(", ")
        ));
    }

    None
}

/// Arguments for changing an LXC guest's resource allocation.
// Unknown fields are refused rather than ignored. The third-party
// server takes these arguments in a different shape, and serde
// dropping what it does not recognise would let an old-shaped call
// succeed having applied almost none of it -- a create with no disk,
// a container with no template, a resource change that moved only
// the field whose name happened to match.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContainerResourceArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
    /// CPU cores. Applied to a running container immediately.
    #[serde(default)]
    pub cores: Option<u32>,
    /// Memory in MiB. Takes effect at the next start.
    #[serde(default)]
    pub memory_mb: Option<u32>,
    /// Swap in MiB. Takes effect at the next start.
    #[serde(default)]
    pub swap_mb: Option<u32>,
}

/// Arguments for stopping a running task.
// Unknown fields are refused rather than ignored. The third-party
// server takes these arguments in a different shape, and serde
// dropping what it does not recognise would let an old-shaped call
// succeed having applied almost none of it -- a create with no disk,
// a container with no template, a resource change that moved only
// the field whose name happened to match.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StopTaskArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Task handle, as returned by any tool that starts one.
    ///
    /// The node is read from the handle rather than accepted as an argument. A
    /// UPID names the node that owns the task, and a caller-supplied node that
    /// disagreed would address a path the task does not live at -- Proxmox
    /// would answer cheerfully and stop nothing.
    pub upid: String,
}

/// Arguments for creating a guest from scratch.
// Unknown fields are refused rather than ignored. The third-party
// server takes these arguments in a different shape, and serde
// dropping what it does not recognise would let an old-shaped call
// succeed having applied almost none of it -- a create with no disk,
// a container with no template, a resource change that moved only
// the field whose name happened to match.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateGuestArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node to create the guest on. Required: there is no guest to resolve.
    pub node: String,
    /// VMID for the new guest. Must be free and within the token's scope.
    pub vmid: u32,
    /// Proxmox config keys, forwarded as given.
    ///
    /// QEMU and LXC diverge enough that a shared type would be a union of two
    /// half-populated things, so this stays untyped. `hookscript` and `args`
    /// are refused: both execute on the node rather than in the guest.
    #[serde(default)]
    pub config: std::collections::BTreeMap<String, String>,
}

/// Arguments for downloading an image to a storage.
// Unknown fields are refused rather than ignored. The third-party
// server takes these arguments in a different shape, and serde
// dropping what it does not recognise would let an old-shaped call
// succeed having applied almost none of it -- a create with no disk,
// a container with no template, a resource change that moved only
// the field whose name happened to match.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DownloadIsoArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node whose storage receives the file. `local` is node-local, so the
    /// same storage name on two nodes is two different places.
    pub node: String,
    /// Storage identifier.
    pub storage: String,
    /// Filename to write.
    pub filename: String,
    /// Source URL.
    pub url: String,
    /// Content type. `iso` or `vztmpl`.
    #[serde(default = "default_download_content")]
    pub content: String,
    /// Checksum algorithm, e.g. `sha256`.
    ///
    /// Proxmox verifies only when the algorithm and value are both present and
    /// silently ignores one without the other, so this server refuses a lone
    /// half rather than letting a caller believe a checksum was checked.
    #[serde(default)]
    pub checksum_algorithm: Option<String>,
    /// Checksum value. Travels with `checksum_algorithm`.
    #[serde(default)]
    pub checksum: Option<String>,
}

/// Images are the overwhelmingly common case.
fn default_download_content() -> String {
    "iso".to_owned()
}

/// Arguments for resizing one guest disk.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ResizeArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
    /// Disk to resize, e.g. `rootfs`, `scsi0`.
    pub disk: String,
    /// New size: `+8G` to grow by.
    ///
    /// Only the `+` form is treated as growing. An absolute value may be
    /// smaller than the current disk, which destroys data, so it is refused.
    /// Shrinking is not supported: `qm resize` and `pct resize` reject a
    /// reduction, so there is no supported path to it from here either.
    pub size: String,
}

/// Arguments for taking a snapshot of one guest.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct SnapshotArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id, unique within the cluster.
    pub vmid: u32,
    /// Snapshot name, as it will appear in `list_snapshots`.
    pub snapname: String,
    /// Optional free-text description. An empty one is omitted.
    #[serde(default)]
    pub description: Option<String>,
}

/// Arguments for backing up one guest.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct BackupArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id, unique within the cluster.
    pub vmid: u32,
    /// Target storage, as reported by `get_storage`.
    pub storage: String,
    /// vzdump mode: `snapshot`, `suspend`, or `stop`.
    ///
    /// Defaults to `snapshot`, the only mode that does not interrupt the
    /// guest — which is what keeps `create_backup` out of the interrupting
    /// set and therefore usable on a protected guest.
    #[serde(default = "default_backup_mode")]
    pub mode: String,
    /// Optional compression: `zstd`, `lzo`, `gzip`.
    #[serde(default)]
    pub compress: Option<String>,
}

/// vzdump's non-interrupting mode.
fn default_backup_mode() -> String {
    "snapshot".to_owned()
}

/// A clone is a full copy unless the caller asks otherwise.
const fn default_true() -> bool {
    true
}

/// Arguments for a storage-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct StorageArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
    /// Storage backend name.
    pub storage: String,
}

/// Arguments for a storage-scoped, paginated read.
///
/// Kept separate from [`StorageArgs`]: `list_isos` and `list_templates` share
/// this endpoint but are out of MEC-479's scope, and should not carry unused
/// pagination parameters until they need them too.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PagedStorageArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
    /// Storage backend name.
    pub storage: String,
    /// Zero-based index of the first record to return. Defaults to 0.
    #[serde(default)]
    pub offset: Option<u32>,
    /// Maximum records to return. Defaults to 500, capped at 700 so a
    /// pretty-printed page stays comfortably under the MCP result's 512 KiB
    /// limit.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// Arguments for a task-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct TaskArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Node name as reported by `get_nodes`.
    pub node: String,
    /// Proxmox task UPID.
    pub upid: String,
}

/// Arguments for a cluster firewall security-group-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FirewallGroupArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Security group name, as reported by `list_firewall_security_groups`.
    pub group: String,
}

/// Arguments for a cluster firewall IPSet-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct FirewallIpsetArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// IPSet name, as reported by `list_firewall_ipsets`.
    pub name: String,
}

/// Arguments for a guest firewall IPSet-scoped read.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct GuestFirewallIpsetArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id, unique within the cluster.
    pub vmid: u32,
    /// IPSet name, as reported by `list_guest_firewall_ipsets`.
    pub name: String,
}

/// The MCP server.
#[derive(Clone)]
pub struct ProxmoxServer {
    #[allow(dead_code)]
    clusters: Arc<ClusterInventory>,
    clients: Arc<BTreeMap<String, ProxmoxClient>>,
    index: Arc<GuestIndex>,
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
    /// SSDF evidence recorder, when the pipeline is configured.
    ///
    /// Held here as well as on the coordinator because the apply path does not
    /// go through `commit_operation` -- it issues the destroy directly -- and
    /// that is the only coordinator call that emits `apply_intent` and
    /// `result_receipt`. Proposal and approval come from the coordinator;
    /// execution has to come from here.
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
    lab_mode: bool,
    /// Whether direct-commit tools (the interrupting lifecycle verbs,
    /// `clone_vm`, `create_vm`, `create_container`, `resize_disk`, and
    /// `create_backup`) may run without change-set approval. Set via
    /// `--allow-direct-commit`; off by default.
    direct_commit: mecmcp_audit::DirectCommitPolicy,
    tool_router: ToolRouter<Self>,
}

impl ProxmoxServer {
    /// Build the server over a loaded inventory and its per-cluster clients.
    ///
    /// **`coordinator` and `evidence` must share one recorder.** The
    /// coordinator emits proposal and approval; this server emits apply intent
    /// and the receipt, because the apply path issues the destroy directly and
    /// never reaches `commit_operation`. A coordinator built without the
    /// recorder produces execution records whose proposal context is missing,
    /// and one built with a *different* recorder splits a single change across
    /// two chains -- both verify as valid chains, so neither is reported.
    /// [`new_with_default_coordinator`](Self::new_with_default_coordinator)
    /// builds both from one recorder and is the safe entry point.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clusters: Arc<ClusterInventory>,
        clients: Arc<BTreeMap<String, ProxmoxClient>>,
        index: Arc<GuestIndex>,
        coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
        direct_commit: mecmcp_audit::DirectCommitPolicy,
    ) -> Self {
        Self {
            clusters: clusters.clone(),
            clients: clients.clone(),
            index: index.clone(),
            coordinator,
            evidence,
            waivers,
            lab_mode,
            direct_commit,
            tool_router: Self::proxmox_tool_router(),
        }
    }

    /// Build the server with a default in-memory coordinator.
    ///
    /// # Errors
    ///
    /// Returns an error if the coordinator cannot be created.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_default_coordinator(
        clusters: Arc<ClusterInventory>,
        clients: Arc<BTreeMap<String, ProxmoxClient>>,
        index: Arc<GuestIndex>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
        evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
        direct_commit: mecmcp_audit::DirectCommitPolicy,
        state_file: Option<&std::path::Path>,
        approval_digest_key: Option<mecmcp_changeset::ApprovalDigestKey>,
    ) -> Result<Self, mecmcp_changeset::CoordinatorError> {
        let coordinator = change_set::build_coordinator(
            state_file,
            lab_mode,
            evidence.clone(),
            approval_digest_key,
        )?;
        Ok(Self::new(
            clusters,
            clients,
            index,
            coordinator,
            waivers,
            lab_mode,
            evidence,
            direct_commit,
        ))
    }

    /// The change-set coordinator backing this server.
    ///
    /// Exposed so callers -- integration tests in particular -- can inspect or
    /// construct store states the tool surface itself cannot produce, such as a
    /// record whose preview is absent.
    ///
    /// Unused by the binary target, which is why it carries the allow: the
    /// integration tests are separate crates and do not count as uses here.
    #[allow(dead_code)]
    pub fn coordinator(&self) -> &Arc<mecmcp_changeset::ChangesetCoordinator> {
        &self.coordinator
    }

    /// Recover the caller's context, or `None` on the stdio path.
    fn caller(context: &RequestContext<RoleServer>) -> Option<CallerCtx<ProxmoxGrant>> {
        caller_from_extensions::<ProxmoxGrant>(&context.extensions).cloned()
    }

    /// Look up the client for a cluster the caller is entitled to reach.
    fn client_for(&self, cluster: &str) -> Result<&ProxmoxClient, Box<CallToolResult>> {
        self.clients
            .get(cluster)
            .ok_or_else(|| Box::new(tool_error(format!("unknown cluster: {cluster}"))))
    }

    /// Enforce the direct-commit gate for a tool that mutates a guest in one
    /// call with no change-set approval, and audit the outcome.
    ///
    /// Refuses unless the server was started with `--allow-direct-commit`.
    /// Unlike the tier/grant/protection authorization above, which logs
    /// through this crate's own `tracing`-based audit convention, this emits
    /// its event through `mecmcp_audit::AuditScope` -- the same mechanism
    /// `mecmcp_audit::DirectCommitPolicy::check` requires and the one every
    /// other mecmcp server uses for the identical gate, so direct-commit
    /// records share one shape across the fleet. The `AuditScope` is dropped
    /// (and so emits) whether `check` allows or refuses the call.
    ///
    /// # Errors
    /// Returns the boxed `CallToolResult` [`tool_error`] renders for
    /// [`mecmcp_audit::DirectCommitRefused`], for a handler to `return *result`.
    fn gate_direct_commit(
        &self,
        caller: Option<&CallerCtx<ProxmoxGrant>>,
        tool: &'static str,
        action: &'static str,
        target: &str,
    ) -> Result<(), Box<CallToolResult>> {
        let mut scope = match caller {
            Some(ctx) => {
                mecmcp_audit::AuditScope::from_caller(ctx, tool, action, vec![target.to_owned()])
            }
            None => mecmcp_audit::AuditScope::stdio(tool, action, vec![target.to_owned()]),
        };
        match self.direct_commit.check(&mut scope) {
            Ok(()) => {
                scope.succeed();
                Ok(())
            }
            Err(error) => Err(Box::new(tool_error(error))),
        }
    }

    /// Authorize every guest an HA rule change touches, as a destructive call.
    ///
    /// An HA `node-affinity`/`resource-affinity` rule directs the HA manager
    /// to move the guests it names, so writing one is gated like `plan_proxmox_destroy`
    /// is for each of those guests: the token must carry the `destructive`
    /// action tier, each guest must be inside its guest scope, and a guest
    /// that is protected (live `protected` tag or inventory pin) is refused
    /// unless a waiver or lab mode overrides it -- the same
    /// [`destructive_allowed`] rule, through the same `GuestIndex::authorize`.
    /// Unlike a destroy plan, an override here never waives the change set's
    /// second-principal approval; it only lets the guest check pass.
    ///
    /// The guests checked are the union of the ones the action names and the
    /// ones the rule currently names (`resources`, or `services` on older
    /// payloads), so an update or delete cannot reach a guest the token could
    /// not have named itself. A named vmid with no guest behind it is held to
    /// the creation rule instead: inside the token's scope by number and not
    /// an inventory pin.
    ///
    /// [`destructive_allowed`]: rust_proxmoxmcp_core::protect::destructive_allowed
    ///
    /// # Errors
    /// Returns the boxed `CallToolResult` to `return *result` from a handler.
    async fn authorize_ha_rule_guests(
        &self,
        client: &ProxmoxClient,
        cluster: &str,
        caller: Option<&CallerCtx<ProxmoxGrant>>,
        action: &ha_change_set::HaRuleAction,
        existing: Option<&serde_json::Value>,
    ) -> Result<(), Box<CallToolResult>> {
        use rust_proxmoxmcp_core::protect::{
            DestructiveAttempt, Override, creation_allowed, destructive_allowed, protection_of,
        };

        require_ha_rule_destructive_tier(caller)?;
        let grant = resolve_grant(caller)?;

        // An `update` or `delete` also authorizes the rule's *existing*
        // guests (`guests_touched` merges them in below), and the per-guest
        // error names the vmid. A narrowed token could plan a delete of a
        // rule it may not read (`list_ha_rules`/`get_ha_rule` already refuse
        // it that membership) and learn the same thing from the refusal.
        // Gate the same way those reads do: only a token with the
        // unrestricted guest scope may touch a rule's existing membership.
        if matches!(action.op.as_str(), "update" | "delete") && !grant.is_unrestricted_guest_scope()
        {
            return Err(Box::new(tool_error(format!(
                "changing an HA rule with op '{}' requires a caller whose guest scope is '*' -- \
                 its existing membership is not filtered by guest scope, same as \
                 list_ha_rules and get_ha_rule. This caller is narrowed to specific guests and \
                 cannot be checked against it.",
                action.op
            ))));
        }

        let vmids = ha_change_set::guests_touched(action, existing)
            .map_err(|error| Box::new(tool_error(error)))?;

        // Fresh state, for the same reason `plan_destroy` drops the cache: a
        // `protected` tag added seconds ago must be seen.
        self.index.invalidate_cluster(cluster);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        for vmid in vmids {
            match self.index.resolve(client, cluster, vmid).await {
                Ok(guest) => {
                    let protection = protection_of(client.cluster(), Some(&guest), false);
                    let override_ = destructive_allowed(
                        &protection,
                        &self.waivers,
                        cluster,
                        vmid,
                        now_unix,
                        self.lab_mode,
                        DestructiveAttempt {
                            op: &format!("ha_rule_{}", action.op),
                            principal: caller.map(|ctx| ctx.token_name.as_str()),
                        },
                    );
                    let override_applies = !matches!(override_, Override::None);
                    self.index
                        .authorize(
                            client,
                            cluster,
                            vmid,
                            &grant,
                            Intent::destructive(override_applies),
                        )
                        .await
                        .map_err(|error| {
                            Box::new(tool_error(format!("HA rule names guest {vmid}: {error}")))
                        })?;
                }
                Err(rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }) => {
                    if !grant.allows_new_vmid(vmid) {
                        // Same text the `Ok` arm's `authorize` call produces
                        // for a guest that exists but is out of scope: an
                        // absent vmid and an out-of-scope one must be
                        // indistinguishable to the caller, or a narrowed
                        // token could loop this over the id space and use
                        // the wording as an existence oracle -- exactly what
                        // this PR closes for every other guest-addressed call.
                        return Err(Box::new(tool_error(format!(
                            "HA rule names guest {vmid}: {}",
                            rust_proxmoxmcp_core::ProxmoxError::guest_out_of_scope(cluster)
                        ))));
                    }
                    if !creation_allowed(client.cluster(), vmid) {
                        return Err(Box::new(tool_error(format!(
                            "HA rule names vmid {vmid}, a protected pin on cluster {cluster}"
                        ))));
                    }
                }
                Err(error) => {
                    return Err(Box::new(tool_error(format!(
                        "could not resolve guest {vmid} named by the HA rule: {error}"
                    ))));
                }
            }
        }
        Ok(())
    }
}

/// Convert an [`AuthorizationError`] into a tool error, without routing its
/// `Display` text (which always opens with `token '{name}' ...`) through
/// [`tool_error`] directly.
///
/// `tool_error` redacts unconditionally as of mecmcp v0.25.0 (MEC-1020), and
/// mecmcp-redact's scrubber treats "token" as a trigger that consumes the
/// rest of the line, so the upstream message's own token name would nuke the
/// tool name callers rely on (`"not authorized for tool 'migrate_container'"`)
/// along with it. Rebuilding the message from the error's structured fields,
/// omitting the token name entirely, keeps the useful part intact -- the name
/// was never meant to reach the model anyway (see `resolve_grant`).
fn authz_tool_error(error: AuthorizationError) -> CallToolResult {
    let message = match error {
        AuthorizationError::ToolNotInScope { tool, .. } => {
            format!("not authorized for tool '{tool}'")
        }
        AuthorizationError::TargetNotInScope { tool, .. } => {
            format!("not authorized for the requested target (tool '{tool}')")
        }
    };
    tool_error(message)
}

/// Resolve the grant for a guest-addressed call.
///
/// Distinguishes two cases:
/// - `caller` is `None` (stdio path, no bearer token): returns the wildcard read-only grant
/// - `caller` is `Some` with `grant: None` (authenticated token that declared no scope): refuses
///
/// # Errors
///
/// Returns a `CallToolResult` error when an authenticated token carries no guest selector.
fn resolve_grant(
    caller: Option<&CallerCtx<ProxmoxGrant>>,
) -> Result<ProxmoxGrant, Box<CallToolResult>> {
    match caller {
        None => Ok(rust_proxmoxmcp_core::ProxmoxGrant::read_only()),
        Some(ctx) => ctx.grant.clone().ok_or_else(|| {
            // `tool_error` redacts unconditionally as of mecmcp v0.25.0
            // (MEC-1020) and mecmcp-redact's scrubber treats "token" as a
            // trigger that consumes the rest of the string, so there is no
            // wording of this message that keeps both the word "token" and
            // anything after it. Log the token name to the audit target
            // instead -- an operator who needs to find it in tokens.json
            // greps the audit log, not the tool response.
            tracing::warn!(
                target: "audit",
                event = "grant_missing_selector",
                token_name = %ctx.token_name,
                "token has no 'guests' selector configured; refusing"
            );
            Box::new(tool_error(
                "the caller for this request has no 'guests' selector configured",
            ))
        }),
    }
}

/// Cheap, no-network refusal of an HA rule change from a token lacking the
/// `destructive` action tier.
///
/// Split out of `ProxmoxServer::authorize_ha_rule_guests` so `plan_ha_rule_change`
/// and `apply_ha_rule_change` can call it before `fetch_rule` -- a token this
/// clearly disqualified must be refused before any request reaches the
/// cluster, not merely after a GET already went out. `authorize_ha_rule_guests`
/// still runs the same check itself once guests are known; the repeat costs
/// nothing (no network call) and keeps that function safe to call on its own.
///
/// # Errors
/// Returns the boxed `CallToolResult` to `return *result` from a handler.
fn require_ha_rule_destructive_tier(
    caller: Option<&CallerCtx<ProxmoxGrant>>,
) -> Result<(), Box<CallToolResult>> {
    use rust_proxmoxmcp_core::grant::ProxmoxAction;

    let grant = resolve_grant(caller)?;
    if !grant.allows_action(ProxmoxAction::Destructive) {
        return Err(Box::new(tool_error(
            "changing an HA rule requires the 'destructive' action tier, which this caller \
             does not carry",
        )));
    }
    Ok(())
}

/// Derive a scope description from the caller's tool and device scopes.
fn scope_desc(caller: Option<&CallerCtx<ProxmoxGrant>>) -> &'static str {
    caller
        .map(|c| match (&c.tools, &c.devices) {
            (ScopeSet::Wildcard, ScopeSet::Wildcard) => "global",
            (ScopeSet::Wildcard, ScopeSet::Allowlist(_)) => "device-scoped",
            (ScopeSet::Allowlist(_), _) => "tool-scoped",
        })
        .unwrap_or("stdio")
}

/// Object keys whose *value*, wherever it appears in a read response, is
/// free text an operator controls rather than structure this server relies
/// on. Proxmox does not distinguish "operator note" from "secret dump" in
/// any of these: guest `description`/`cicustom`/`args`, snapshot and backup
/// `description`/`notes`, and the `comment` field on firewall rules,
/// aliases, IPSets and security groups. All of them are seen in practice
/// carrying pasted credentials.
const FREE_TEXT_KEYS: &[&str] = &[
    "description",
    "comment",
    "comments",
    "notes",
    "cicustom",
    "args",
];

/// Redact every [`FREE_TEXT_KEYS`] value anywhere in a read response before
/// it reaches the model, recursing through nested objects and arrays so a
/// single call covers both a single guest config and a list of firewall
/// rules or IPSet entries.
///
/// Each matching string is run through `mecmcp_redact::redact_text` rather
/// than dropped outright, so a legitimate non-secret note survives while a
/// credential-shaped substring does not; `redact_text` is a denylist-and-
/// shape scrubber, so content in a format it does not recognise still
/// passes through (see the tool descriptions this feeds).
///
/// `sshkeys` is deliberately excluded: it carries a guest's authorized
/// public keys, which are not secret.
pub(crate) fn redact_free_text_fields(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, field) in map.iter_mut() {
                if FREE_TEXT_KEYS.contains(&key.as_str())
                    && let Some(text) = field.as_str()
                {
                    *field = serde_json::Value::String(mecmcp_redact::redact_text(text));
                    continue;
                }
                redact_free_text_fields(field);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items.iter_mut() {
                redact_free_text_fields(item);
            }
        }
        _ => {}
    }
}

impl ProxmoxServer {
    /// Execute one catalog-declared read.
    ///
    /// Guest-scoped tools resolve the guest and run stage-2 authorization,
    /// yielding an `AuthorizedGuest` whose node fills the `{node}` parameter.
    /// Cluster- and node-scoped tools take their parameters from the request.
    ///
    /// `requires_unrestricted_guest_scope` is for a tool that names no guest
    /// and returns a listing shared across every guest on a storage or a node
    /// (backups, ISOs, templates, tasks) rather than one guest's own data. A
    /// grant narrowed to specific guests has no selector that can narrow such
    /// a listing, so -- exactly as `download_iso` and node-level `stop_task`
    /// already require for the same reason -- it is refused outright rather
    /// than silently handed the run of everyone's data. Set `false` for a
    /// tool that either names a guest via `vmid` or returns nothing
    /// guest-attributable at all (`get_cluster_status`, `get_nodes`).
    ///
    /// `page`, when `Some`, slices the filtered upstream array into one page
    /// (see [`paginate`]) rather than returning it whole. `None` preserves the
    /// original behavior for tools too small to ever need it.
    #[allow(clippy::too_many_arguments)]
    async fn serve_read(
        &self,
        tool: &'static str,
        cluster: &str,
        extra_params: &[(&str, &str)],
        vmid: Option<u32>,
        requires_unrestricted_guest_scope: bool,
        page: Option<(u32, u32)>,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(cluster), WRITE_TOOLS) {
            return authz_tool_error(error);
        }

        if requires_unrestricted_guest_scope {
            let grant = match resolve_grant(caller.as_ref()) {
                Ok(grant) => grant,
                Err(error) => return *error,
            };
            if !grant.is_unrestricted_guest_scope() {
                return tool_error(format!(
                    "{tool} is not scoped to any single guest -- it lists data shared across \
                     every guest on a storage or a node -- so it requires a caller whose guest \
                     scope is '*'. This caller is narrowed to specific guests and cannot be \
                     checked against it."
                ));
            }
        }

        let Some(entry) = read_tool(tool) else {
            return tool_error(format!("unregistered tool: {tool}"));
        };
        let client = match self.client_for(cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let mut params: Vec<(&str, String)> = extra_params
            .iter()
            .map(|(name, value)| (*name, (*value).to_owned()))
            .collect();

        if let Some(vmid) = vmid {
            let grant = match resolve_grant(caller.as_ref()) {
                Ok(grant) => grant,
                Err(error) => return *error,
            };
            let authorized = match self
                .index
                .authorize(client, cluster, vmid, &grant, Intent::read())
                .await
            {
                Ok(authorized) => authorized,
                Err(error) => return tool_error(error),
            };
            let guest = authorized.guest();
            params.push(("node", guest.node.clone()));
            params.push(("vmid", guest.vmid.to_string()));
            // Only when the template asks for it. `mecmcp-openapi` refuses a
            // parameter with no placeholder, so pushing `kind` unconditionally
            // broke every tool whose path names the guest type itself --
            // get_vm_config and get_container_config hardcode `qemu` and `lxc`,
            // and both failed on every call with "parameter 'kind' does not
            // appear in the template". Neither had a test.
            if entry.path.contains("{kind}") {
                params.push(("kind", guest.r#type.path_segment().to_owned()));
            } else if let Some(required) = kind_named_in(entry.path)
                && required != guest.r#type.path_segment()
            {
                // The path names one guest type, so it may only be used for
                // that type. Without this, no longer sending `kind` would let
                // get_vm_config run against a container and address an endpoint
                // that cannot exist -- an opaque Proxmox error where a plain
                // mismatch message belongs.
                return tool_error(format!(
                    "vmid {} is a {} guest; {tool} reads {} guests only",
                    guest.vmid,
                    guest.r#type.path_segment(),
                    required
                ));
            }

            tracing::info!(
                tool,
                cluster,
                vmid = guest.vmid,
                node = %guest.node,
                guest_name = %guest.name,
                tier = "read",
                protection = %authorized.protection().summary(),
                scope = scope_desc(caller.as_ref()),
                "proxmox read authorized"
            );
        }

        let borrowed: Vec<(&str, &str)> = params
            .iter()
            .map(|(name, value)| (*name, value.as_str()))
            .collect();

        let result = match client.get_json(entry.path, &borrowed, entry.query).await {
            Ok(mut value) => {
                // Apply type_filter if present
                if let Some(filter_type) = entry.type_filter
                    && let Some(array) = value.as_array_mut()
                {
                    array.retain(|item| {
                        item.get("type")
                            .and_then(|v| v.as_str())
                            .is_some_and(|t| t == filter_type.path_segment())
                    });
                }
                // `guest_listing` is set exactly for tools that list guests off
                // `/cluster/resources` (get_vms, get_containers). Those return
                // every guest in the cluster regardless of `vmid`, which is
                // always `None` for them, so the `Some(vmid)` branch above
                // never runs its grant check. A narrowed token must not see
                // guests outside its scope just because the tool it called
                // never named one. Keyed on the explicit flag, not on
                // `type_filter.is_some()`, so a future guest-listing tool with
                // no type filter cannot silently skip this.
                if entry.guest_listing {
                    use rust_proxmoxmcp_core::resolve::parse_resource_guest;

                    let grant = match resolve_grant(caller.as_ref()) {
                        Ok(grant) => grant,
                        Err(error) => return *error,
                    };
                    if !grant.is_unrestricted_guest_scope()
                        && let Some(array) = value.as_array_mut()
                    {
                        array.retain(|item| {
                            parse_resource_guest(item)
                                .is_some_and(|guest| grant.allows_guest(guest.facts()))
                        });
                    }
                }
                redact_free_text_fields(&mut value);
                Ok(value)
            }
            Err(error) => Err(error),
        };

        let value = match result {
            Ok(value) => value,
            Err(error) => return tool_error(error),
        };

        let Some((offset, limit)) = page else {
            return tool_result(
                Ok::<_, String>(value),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        };

        match paginate(value, offset, limit) {
            Ok(page) => tool_result(
                Ok::<_, String>(page),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ),
            Err(error) => *error,
        }
    }
}

#[tool_router(router = proxmox_tool_router, vis = "pub(crate)")]
impl ProxmoxServer {
    #[tool(
        name = "get_cluster_status",
        description = "Cluster quorum and node membership."
    )]
    async fn get_cluster_status(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_cluster_status",
            &args.cluster,
            &[],
            None,
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_nodes",
        description = "All nodes in the cluster with status and resource totals."
    )]
    async fn get_nodes(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read("get_nodes", &args.cluster, &[], None, false, None, &context)
            .await
    }

    #[tool(
        name = "get_node_status",
        description = "Detailed status for one node."
    )]
    async fn get_node_status(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_node_status",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_ha_rules",
        description = "All HA rules (node-affinity and resource-affinity) in the cluster. \
                        Not the deprecated HA groups mechanism."
    )]
    async fn list_ha_rules(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        // HA rules name arbitrary guests (`vm:100`, ...) and the listing is
        // not filtered by the caller's guest scope, so a narrowed token would
        // see guests outside its grant.
        self.serve_read(
            "list_ha_rules",
            &args.cluster,
            &[],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(name = "get_ha_rule", description = "One HA rule by id.")]
    async fn get_ha_rule(
        &self,
        Parameters(args): Parameters<HaRuleArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_ha_rule",
            &args.cluster,
            &[("rule", args.rule.as_str())],
            None,
            // Same as list_ha_rules: a rule names guests the caller's
            // scope may not cover, and the read is not filtered by it.
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_vms",
        description = "QEMU guests across the cluster, with node, status and tags. Paginated: \
                       returns up to `limit` (default 500, max 700) starting at `offset` \
                       (default 0), plus `total` and `has_more` to page through the rest."
    )]
    async fn get_vms(
        &self,
        Parameters(args): Parameters<PagedClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let page = match resolve_page(args.offset, args.limit) {
            Ok(page) => page,
            Err(error) => return *error,
        };
        self.serve_read(
            "get_vms",
            &args.cluster,
            &[],
            None,
            false,
            Some(page),
            &context,
        )
        .await
    }

    #[tool(
        name = "get_containers",
        description = "LXC guests across the cluster, with node, status and tags. Paginated: \
                       returns up to `limit` (default 500, max 700) starting at `offset` \
                       (default 0), plus `total` and `has_more` to page through the rest."
    )]
    async fn get_containers(
        &self,
        Parameters(args): Parameters<PagedClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let page = match resolve_page(args.offset, args.limit) {
            Ok(page) => page,
            Err(error) => return *error,
        };
        self.serve_read(
            "get_containers",
            &args.cluster,
            &[],
            None,
            false,
            Some(page),
            &context,
        )
        .await
    }

    #[tool(
        name = "get_vm_config",
        description = "Configuration of one QEMU guest, including its Proxmox digest. \
                        `description`, `cicustom` and `args` content is redacted on a \
                        best-effort basis (do not store secrets there); sshkeys, \
                        hostname/name, resource allocation, disks and network config \
                        are preserved."
    )]
    async fn get_vm_config(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_vm_config",
            &args.cluster,
            &[],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_container_config",
        description = "Configuration of one LXC guest, including its Proxmox digest. \
                        `description`, `cicustom` and `args` content is redacted on a \
                        best-effort basis (do not store secrets there); sshkeys, \
                        hostname, resource allocation, disks and network config are \
                        preserved."
    )]
    async fn get_container_config(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_container_config",
            &args.cluster,
            &[],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    /// Re-probe every apply that was in flight when this process last stopped.
    ///
    /// Called once at startup. A change set left in `Applying` with a
    /// `task_id` means the previous process started a destructive operation
    /// and died before observing its result. Proxmox kept running it, so the
    /// answer exists — it just has to be asked for.
    ///
    /// Without this the record stays `Applying` forever and an operator has to
    /// read the device to find out what happened. That is the "detectable but
    /// not recoverable" limitation the 0.3 README documented.
    ///
    /// Failures here are logged, never fatal: a server that refuses to start
    /// because one historical task cannot be re-probed is worse than one that
    /// starts and says which change set is still unresolved.
    pub async fn recover_in_flight(&self) {
        let records = self.coordinator.change_sets().await;
        for mut record in records {
            if record.state != mecmcp_changeset::ChangeSetState::Applying {
                // A handle on a settled record means the process died between
                // finishing and clearing it. Nothing to re-probe, but say so:
                // it is evidence about a crash, not noise.
                if record.task_id.is_some() {
                    tracing::warn!(
                        target: "audit",
                        change_set = %record.id,
                        state = ?record.state,
                        "a settled change set still carries a task handle; \
                         the previous process died after finishing"
                    );
                }
                continue;
            }
            let Some(task_id) = record.task_id.clone() else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    device = %record.device,
                    "an apply is stuck in Applying with no task handle; it predates \
                     handle persistence and must be resolved against the device by hand"
                );
                continue;
            };

            let Ok(upid) = rust_proxmoxmcp_core::task::Upid::parse(&task_id) else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    %task_id,
                    "the stored task handle does not parse; cannot re-probe"
                );
                continue;
            };

            // The cluster is on the record: `device` is `{cluster}/{vmid}`, the
            // shape `plan_destroy` writes. Asking every configured client in
            // turn would be worse than unnecessary — a UPID names its node, not
            // its cluster, and two clusters can both have a node of that name,
            // so the first one that answers could be answering about a
            // different task entirely.
            let Some((cluster, _)) = record.device.split_once('/') else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    device = %record.device,
                    "the record's device is not cluster/vmid; cannot choose a client"
                );
                continue;
            };
            let cluster = cluster.to_owned();

            let Some(client) = self.clients.get(&cluster) else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    %cluster,
                    "the record names a cluster this server no longer configures; \
                     leaving it Applying rather than guessing"
                );
                continue;
            };

            let upid_encoded = task_id.replace(':', "%3A");
            let path = format!(
                "/api2/json/nodes/{}/tasks/{upid_encoded}/status",
                upid.node()
            );
            let data = match client.get_json(&path, &[], &[]).await {
                Ok(data) => data,
                Err(error) => {
                    tracing::error!(
                        target: "audit",
                        change_set = %record.id,
                        %cluster,
                        %task_id,
                        %error,
                        "could not read the task status; leaving it Applying"
                    );
                    continue;
                }
            };

            let status = data.get("status").and_then(serde_json::Value::as_str);
            if status == Some("running") {
                // Still going. Leave it alone — this process did not start it
                // and must not adopt a poll loop for it, but the operator can
                // now see which task it is.
                tracing::warn!(
                    target: "audit",
                    change_set = %record.id,
                    %cluster,
                    %task_id,
                    "an apply from a previous process is still running"
                );
                continue;
            }

            // A stopped task without an exit status is an answer this code
            // does not have. Defaulting to "" would classify as failure and
            // assert an outcome nobody observed — the same mistake
            // `load_with_recovery` used to make. Leave it `Applying` and say
            // so; a human can read the task.
            let Some(exitstatus) = data.get("exitstatus").and_then(serde_json::Value::as_str)
            else {
                tracing::error!(
                    target: "audit",
                    change_set = %record.id,
                    %cluster,
                    %task_id,
                    "the task is no longer running but reports no exit status; \
                     leaving it Applying rather than inventing an outcome"
                );
                continue;
            };

            let outcome = rust_proxmoxmcp_core::task::classify_exit_status(exitstatus);
            let succeeded = matches!(outcome, rust_proxmoxmcp_core::task::TaskOutcome::Ok);
            record.state = if succeeded {
                mecmcp_changeset::ChangeSetState::Applied
            } else {
                mecmcp_changeset::ChangeSetState::Failed
            };
            record.task_id = None;

            // Close the evidence chain. Without this the record settles while
            // the chain still ends at apply intent, so the evidence says a
            // destroy was attempted and never says what happened to it.
            if let Some(recorder) = &self.evidence
                && let Err(receipt_error) = recorder.result_receipt(
                    &record.id,
                    &record.id,
                    &record.device,
                    // Not `record.approver`. The approver is who authorised the
                    // change set; the executor is whichever token called
                    // `apply_proxmox_change_set`, and two-person control exists
                    // precisely so those differ. Naming the approver here would
                    // attribute a destructive execution to someone who did not
                    // perform it — a worse defect in an audit trail than
                    // admitting the executor is unknown, which is the honest
                    // answer: the process that knew it died, and nothing
                    // persisted it.
                    RECOVERED_EXECUTOR,
                    succeeded,
                    // Matches the normal path: a nonempty value is serialised
                    // into `error`, so passing the exit status on success
                    // produces a receipt reading `outcome: success` alongside
                    // `error: "OK"`.
                    if succeeded { "" } else { exitstatus },
                )
            {
                tracing::error!(
                    %receipt_error,
                    change_set = %record.id,
                    "recovered outcome not written to the evidence chain"
                );
            }

            tracing::warn!(
                target: "audit",
                change_set = %record.id,
                %cluster,
                %task_id,
                state = ?record.state,
                %exitstatus,
                "recovered an apply that was in flight at shutdown"
            );

            if let Err(error) = self.coordinator.update_change_set(record).await {
                tracing::error!(%error, "could not persist the recovered outcome");
            }
        }
    }

    /// Run one recorded destructive action and return its task handle.
    ///
    /// Dispatches on the action the change set carries, so the work performed
    /// is exactly the work the digest covered.
    ///
    /// `delete_backup` and `delete_iso` share `delete_volume` — Proxmox exposes
    /// both through the same content endpoint — and answer synchronously on
    /// some storage types, so they may have no task handle at all. An empty
    /// handle is returned as `None` rather than as `Some("")`, which would
    /// leave the change set looking recoverable against a task that never
    /// existed.
    async fn execute_destructive(
        &self,
        client: &ProxmoxClient,
        action: &change_set::DestroyAction,
        kind: GuestType,
        node: &str,
        vmid: u32,
    ) -> Result<String, rust_proxmoxmcp_core::ProxmoxError> {
        use rust_proxmoxmcp_core::guests;

        let missing = |name: &str| {
            rust_proxmoxmcp_core::ProxmoxError::Malformed(format!(
                "{} action is missing {name}",
                action.op
            ))
        };

        match action.op.as_str() {
            // 0.3 wrote `op: "destroy"`; a change set planned then and applied
            // now must still work, so both spellings dispatch here.
            "destroy_guest" | "destroy" => match kind {
                GuestType::Lxc => guests::destroy_container(client, node, vmid, true).await,
                GuestType::Qemu => guests::destroy_vm(client, node, vmid, true).await,
            },
            "delete_snapshot" => {
                let snapname = action
                    .snapname
                    .as_deref()
                    .ok_or_else(|| missing("snapname"))?;
                guests::delete_snapshot(client, node, kind, vmid, snapname).await
            }
            "rollback_snapshot" => {
                let snapname = action
                    .snapname
                    .as_deref()
                    .ok_or_else(|| missing("snapname"))?;
                guests::rollback_snapshot(client, node, kind, vmid, snapname).await
            }
            "delete_backup" | "delete_iso" => {
                let storage = action
                    .storage
                    .as_deref()
                    .ok_or_else(|| missing("storage"))?;
                let volid = action.volid.as_deref().ok_or_else(|| missing("volid"))?;
                // The node the action recorded, not the guest's. `local` is
                // node-local storage, so `local:backup/x` on pve2 and on pve3
                // are different volumes that share a name — using whichever
                // node the vmid happens to sit on could delete the wrong one.
                let storage_node = action
                    .storage_node
                    .as_deref()
                    .ok_or_else(|| missing("storage_node"))?;
                if action.op == "delete_backup" {
                    Self::require_backup_owner(client, storage_node, volid, vmid).await?;
                }
                let data = guests::delete_volume(client, storage_node, storage, volid).await?;
                Ok(data.as_str().unwrap_or_default().to_owned())
            }
            "restore_backup" => {
                let volid = action.volid.as_deref().ok_or_else(|| missing("volid"))?;
                Self::require_backup_owner(client, node, volid, vmid).await?;
                guests::restore_backup(client, node, kind, vmid, volid, true).await
            }
            "migrate" => {
                let target_node = action
                    .target_node
                    .as_deref()
                    .ok_or_else(|| missing("target_node"))?;
                guests::migrate_guest(
                    client,
                    node,
                    kind,
                    vmid,
                    target_node,
                    action.online,
                    action.with_local_disks,
                )
                .await
            }
            "update_vm_config" => {
                let config = action.config.as_ref().ok_or_else(|| missing("config"))?;
                guests::update_vm_config(client, node, vmid, config).await
            }
            other => Err(rust_proxmoxmcp_core::ProxmoxError::Malformed(format!(
                "unknown destructive operation '{other}'"
            ))),
        }
    }

    /// Refuse `delete_backup` / `restore_backup` on an archive that does not
    /// belong to `vmid`.
    ///
    /// Neither operation's volid is bound to any in-scope guest anywhere else
    /// in the pipeline: `delete_backup` checks only storage and content kind,
    /// and `restore_backup` checks only content kind. Without this, a token
    /// scoped to its own vmid could name an out-of-scope guest's archive and
    /// delete or restore from it, because the volid's filename convention
    /// (`vzdump-qemu-<vmid>-...`) is never actually checked against the vmid
    /// the token is authorized for. This asks Proxmox which guest really owns
    /// the archive and fails closed if that cannot be established.
    async fn require_backup_owner(
        client: &ProxmoxClient,
        node: &str,
        volid: &str,
        vmid: u32,
    ) -> Result<(), rust_proxmoxmcp_core::ProxmoxError> {
        let owner = rust_proxmoxmcp_core::guests::resolve_backup_owner(client, node, volid)
            .await
            .map_err(|error| {
                rust_proxmoxmcp_core::ProxmoxError::Denied(format!(
                    "could not establish which guest owns backup archive '{volid}': {error}. \
                     Refusing rather than trusting the archive's filename."
                ))
            })?;
        if owner != vmid {
            return Err(rust_proxmoxmcp_core::ProxmoxError::Denied(format!(
                "backup archive '{volid}' belongs to guest {owner}, not {vmid}; refusing an \
                 operation on an archive that does not belong to the named guest"
            )));
        }
        Ok(())
    }

    /// Authorize a restore-into-new-vmid against the archive's real owner,
    /// not just the (necessarily free) destination vmid.
    ///
    /// `restore_new_vmid` has no source guest to resolve scope from the way
    /// every other destructive tool does -- the destination is required to be
    /// free, so the only guest whose scope can matter is whoever the archive
    /// belongs to. Without this, a token scoped to `vmid:600-699` could name
    /// any other guest's backup and read its disks into a vmid it controls.
    ///
    /// The owner is commonly gone by the time an old backup is restored, which
    /// is the entire point of restoring one -- so an owner that no longer
    /// resolves is not itself refused. It falls back to the same bare-number
    /// scope check [`ProxmoxGrant::allows_new_vmid`] uses for a creation
    /// destination: only `*` and `vmid:`/`vmid:range` terms can speak for a
    /// guest with no live tags or pool to match against. An owner that *does*
    /// still resolve gets the full scope and protection check a live guest
    /// gets anywhere else in this server.
    async fn authorize_backup_owner(
        &self,
        client: &ProxmoxClient,
        cluster: &str,
        owner_vmid: u32,
        grant: &ProxmoxGrant,
        volid: &str,
        principal: Option<&str>,
    ) -> Result<(), String> {
        use rust_proxmoxmcp_core::protect::{
            DestructiveAttempt, Override, destructive_allowed, protection_of,
        };

        match self.index.resolve(client, cluster, owner_vmid).await {
            Ok(owner_guest) => {
                if !grant.allows_guest(owner_guest.facts()) {
                    return Err(format!(
                        "backup archive '{volid}' belongs to guest {owner_vmid}, which is \
                         outside this caller's guest scope; a restore may not read from it"
                    ));
                }

                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("time")
                    .as_secs();
                let protection = protection_of(client.cluster(), Some(&owner_guest), false);
                let override_ = destructive_allowed(
                    &protection,
                    &self.waivers,
                    cluster,
                    owner_vmid,
                    now_unix,
                    self.lab_mode,
                    DestructiveAttempt {
                        op: "restore_new_vmid",
                        principal,
                    },
                );
                if protection.is_protected() && matches!(override_, Override::None) {
                    return Err(format!(
                        "backup archive '{volid}' belongs to guest {owner_vmid}, which is \
                         protected ({}); restoring from it needs a waiver",
                        protection.summary()
                    ));
                }
                Ok(())
            }
            Err(rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }) => {
                if grant.allows_new_vmid(owner_vmid) {
                    Ok(())
                } else {
                    Err(format!(
                        "backup archive '{volid}' belongs to guest {owner_vmid}, which no \
                         longer exists and is outside this caller's guest scope; a restore may \
                         not read from it"
                    ))
                }
            }
            Err(error) => Err(format!(
                "could not establish whether guest {owner_vmid} (owner of backup archive \
                 '{volid}') is in scope: {error}"
            )),
        }
    }

    /// Stage 1 + stage 2 authorization for a low-tier guest call.
    ///
    /// Shared by the additive tools, which need the same gate as the
    /// lifecycle verbs but no verb dispatch. Interruption is derived from the
    /// tool name inside `Intent::low`, so an additive tool cannot accidentally
    /// be treated as interrupting or vice versa.
    /// Authorize an operation that names a VMID which does not exist yet.
    ///
    /// [`Self::authorize_low`] cannot serve this: it resolves the guest, and
    /// there is no guest. The protection union is likewise guest-derived, so
    /// [`creation_allowed`] answers the pinned-VMID question instead.
    ///
    /// Returns the client on success.
    ///
    /// [`creation_allowed`]: rust_proxmoxmcp_core::protect::creation_allowed
    async fn authorize_creation(
        &self,
        tool: &'static str,
        cluster: &str,
        vmid: u32,
        context: &RequestContext<RoleServer>,
    ) -> Result<&ProxmoxClient, Box<CallToolResult>> {
        use rust_proxmoxmcp_core::grant::ProxmoxAction;
        use rust_proxmoxmcp_core::protect::creation_allowed;

        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(cluster), WRITE_TOOLS) {
            return Err(Box::new(authz_tool_error(error)));
        }

        let client = self.client_for(cluster)?;
        let grant = resolve_grant(caller.as_ref())?;

        if !grant.allows_action(ProxmoxAction::Low) {
            return Err(Box::new(tool_error(
                "creation requires the 'low' action tier, which this caller does not carry",
            )));
        }

        // The guest scope has to admit the *destination*. Nothing else looks at
        // it, because there is no source guest whose scope could stand in.
        if !grant.allows_new_vmid(vmid) {
            return Err(Box::new(tool_error(format!(
                "vmid {vmid} is outside this caller's guest scope, so it may not be created"
            ))));
        }

        // A pinned VMID is pinned because something important is expected to
        // live there. Letting a create claim it strands the real guest.
        if !creation_allowed(client.cluster(), vmid) {
            return Err(Box::new(tool_error(format!(
                "vmid {vmid} is a protected pin on cluster {cluster} and must not be created"
            ))));
        }

        // The guest must not already exist. This is what makes "create" mean
        // create, and it is load-bearing rather than tidy: Proxmox restores a
        // backup by POSTing to the *same* endpoint this uses, with `archive`,
        // `restore` and `force` added. Refusing those keys stops the obvious
        // spelling; refusing an existing VMID stops the whole class, including
        // whatever the next spelling turns out to be.
        //
        // A protected guest is caught here too, before its tags are ever
        // consulted, because it exists.
        // Drop the cluster snapshot first. A guest destroyed moments ago is
        // still in the cached `/cluster/resources` response -- the apply path
        // reads the guest to fingerprint it, which repopulates the cache, and
        // nothing invalidates after the destroy task finishes. Without this, a
        // VMID that is genuinely free reports as taken for the rest of the TTL,
        // and the error tells the caller to destroy something already gone.
        self.index.invalidate_cluster(cluster);

        match self.index.resolve(client, cluster, vmid).await {
            Ok(existing) => {
                return Err(Box::new(tool_error(format!(
                    "vmid {vmid} already exists on cluster {cluster} as '{}' -- creating cannot \
                     overwrite it. Destroy it through plan_proxmox_destroy first, or choose a free \
                     vmid.",
                    existing.name
                ))));
            }
            Err(rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }) => {}
            Err(error) => {
                // Anything other than a clean "absent" leaves the question
                // unanswered, and a create that cannot prove the VMID is free
                // must not proceed.
                return Err(Box::new(tool_error(format!(
                    "could not establish whether vmid {vmid} is free on cluster {cluster}: {error}"
                ))));
            }
        }

        Ok(client)
    }

    /// Refuse config a `low` create must not be able to express.
    ///
    /// An allowlist of key families, not a denylist -- see
    /// `ALLOWED_CREATE_CONFIG_KEYS` for why -- plus three value checks a key
    /// list alone cannot express: `unprivileged`'s value (not its presence)
    /// decides privilege; a disk key can be perfectly ordinary and still
    /// carry a host path (`scsi0=/dev/sdb`) or another guest's volume
    /// (`scsi0=local-lvm:vm-905-disk-0`) under a key that must stay allowed
    /// for `scsi0=local-lvm:32`.
    fn reject_unsafe_config(
        config: &std::collections::BTreeMap<String, String>,
    ) -> Option<CallToolResult> {
        let offending: Vec<String> = config
            .keys()
            .filter(|key| !is_allowed_create_config_key(key))
            .cloned()
            .collect();
        if !offending.is_empty() {
            return Some(tool_error(format!(
                "config field(s) {} are refused: a 'low' create accepts only cloud-init, sizing, \
                 metadata, network and new-volume disk keys. A restore, host code execution, a \
                 host mount, device passthrough, or an existing-volume reference, none of which \
                 a 'low' create may do. Create the guest without them and set them from the \
                 Proxmox UI if you genuinely need them.",
                offending.join(", ")
            )));
        }

        // `unprivileged` is the one key where the *value* decides, and the
        // default decides against us: Proxmox treats an omitted field as 0,
        // meaning privileged. Refusing the key outright therefore permitted
        // only privileged containers -- the exact opposite of the intent.
        // `unprivileged=1` is the safe setting and is accepted; 0 is refused.
        if let Some(value) = config.get("unprivileged")
            && value.trim() != "1"
        {
            return Some(tool_error(
                "unprivileged=0 creates a privileged container, whose root maps to host root. \
                 Pass unprivileged=1, or omit nothing and let this server pass it for you.",
            ));
        }

        // `ostemplate` is the one other key where the *value* decides: the
        // key names only that a template is being used, not which storage or
        // content kind it comes from, so an arbitrary path or non-template
        // volid would otherwise pass the key allowlist unchecked.
        if let Some(value) = config.get("ostemplate")
            && rust_proxmoxmcp_core::guests::validate_volid_kind(value, "vztmpl").is_err()
        {
            return Some(tool_error(format!(
                "ostemplate '{value}' is not a usable template volid ('<storage>:vztmpl/<name>'). \
                 A 'low' create_container may only reference a template image."
            )));
        }

        let host_pathed = config_host_paths(config);
        if !host_pathed.is_empty() {
            return Some(tool_error(format!(
                "config field(s) {} carry an absolute host path. A guest disk is named \
                 'storage:spec'; a path names the hypervisor's own filesystem, which a 'low' \
                 create must not reach.",
                host_pathed.join(", ")
            )));
        }

        // F3 of the MEC-446/MEC-1163 authorization audit: a disk key's value
        // is otherwise free-form, so `import-from=<volid>` or an existing
        // volume named directly (`local-lvm:vm-905-disk-0`) attaches another
        // guest's disk to this one -- including a protected, out-of-scope
        // guest -- with no approval step, because `create_vm`/
        // `create_container` are 'low' tier and never resolve a source guest
        // to check scope against. See `disk_value_is_new_allocation`.
        let foreign_volume: Vec<String> = config
            .iter()
            .filter(|(key, value)| {
                is_create_disk_key(&key.to_ascii_lowercase())
                    && !disk_value_is_new_allocation(value)
                    && !disk_value_is_allowed_media(value)
            })
            .map(|(key, _)| key.clone())
            .collect();
        if !foreign_volume.is_empty() {
            return Some(tool_error(format!(
                "config field(s) {} must allocate a new volume ('<storage>:<size-in-gb>'), not \
                 reference an existing one: 'import-from', 'file', and a value naming another \
                 guest's volume ('vm-<id>-...'/'base-<id>-...') are refused. A 'low' create must \
                 not be able to attach or import a volume outside the guest it is creating.",
                foreign_volume.join(", ")
            )));
        }

        None
    }

    /// As [`Self::authorize_low`], but the caller supplies whether this
    /// specific call interrupts the guest rather than letting `Intent::low`
    /// derive it from the tool name.
    ///
    /// Only `create_backup` needs this: whether a backup interrupts the guest
    /// depends on its `mode` argument (`tier::backup_interrupts`), not on the
    /// tool name, so `Intent::low_with_override`'s tool-name-derived
    /// `interrupts` would be wrong for `mode: "stop"`. Every other caller
    /// passes `None` and gets the tool-name-derived answer unchanged.
    async fn authorize_low_with_interrupts(
        &self,
        tool: &'static str,
        args: &GuestArgs,
        context: &RequestContext<RoleServer>,
        interrupts_override: Option<bool>,
    ) -> Result<rust_proxmoxmcp_core::AuthorizedGuest, Box<CallToolResult>> {
        use rust_proxmoxmcp_core::protect::{
            DestructiveAttempt, Override, destructive_allowed, protection_of,
        };

        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return Err(Box::new(authz_tool_error(error)));
        }

        let client = self.client_for(&args.cluster)?;
        let grant = resolve_grant(caller.as_ref())?;

        // A protection tag added inside the resolve cache's TTL must be seen
        // before an interrupting call acts on it, same as `plan_destroy` and
        // `authorize_ha_rule_guests` drop the cache ahead of their resolve.
        // A non-interrupting low call (`create_snapshot`, `clone_vm`, ...)
        // does not take the guest out of service, so it keeps the cached
        // answer.
        let interrupts = interrupts_override
            .unwrap_or_else(|| rust_proxmoxmcp_core::tier::interrupts_service(tool));
        if interrupts {
            self.index.invalidate_cluster(&args.cluster);
        }

        // A resolve failure here is not surfaced directly: doing so would
        // tell an out-of-scope caller "not found" before the scope check
        // below ever ran, distinguishing an absent guest from a merely
        // denied one. `authorize` below re-resolves (from cache) and returns
        // the same error either way; this lookup exists only to compute
        // protection for `override_applies` when the guest does exist.
        let (resolved, resolution_failed) =
            match self.index.resolve(client, &args.cluster, args.vmid).await {
                Ok(guest) => (Some(guest), false),
                Err(_) => (None, true),
            };
        let protection = protection_of(client.cluster(), resolved.as_ref(), resolution_failed);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
            DestructiveAttempt {
                op: tool,
                principal: caller.as_ref().map(|ctx| ctx.token_name.as_str()),
            },
        );
        let override_applies = !matches!(override_, Override::None);

        let mut intent = Intent::low_with_override(tool, override_applies);
        if let Some(interrupts) = interrupts_override {
            intent.interrupts = interrupts;
        }

        self.index
            .authorize(client, &args.cluster, args.vmid, &grant, intent)
            .await
            .map_err(|error| Box::new(tool_error(error)))
    }

    /// Stage 1 + stage 2 authorization for a low-tier guest call, with
    /// interruption derived from the tool name via `Intent::low`.
    ///
    /// A thin wrapper over [`Self::authorize_low_with_interrupts`] for every
    /// caller except `create_backup`, whose interruption depends on its
    /// `mode` argument rather than its tool name.
    async fn authorize_low(
        &self,
        tool: &'static str,
        args: &GuestArgs,
        context: &RequestContext<RoleServer>,
    ) -> Result<rust_proxmoxmcp_core::AuthorizedGuest, Box<CallToolResult>> {
        self.authorize_low_with_interrupts(tool, args, context, None)
            .await
    }

    /// Serve one low-tier lifecycle verb.
    ///
    /// Shared by all seven lifecycle tools because the only differences are
    /// the verb, the guest type the tool name implies, and the audit label.
    /// Writing them out seven times would be seven chances to forget the
    /// protection check.
    async fn serve_lifecycle(
        &self,
        tool: &'static str,
        verb: LifecycleVerb,
        required_type: GuestType,
        args: &GuestArgs,
        context: &RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::protect::{
            DestructiveAttempt, Override, destructive_allowed, protection_of,
        };

        let caller = Self::caller(context);
        if let Err(error) = authorize_call(caller.as_ref(), tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        // A protection tag added inside the resolve cache's TTL must be seen
        // before an interrupting verb acts on it, same as `plan_destroy` and
        // `authorize_ha_rule_guests` drop the cache ahead of their resolve.
        // `start_vm`/`start_container` are additive, not disruptive, and keep
        // the cached answer.
        if rust_proxmoxmcp_core::tier::interrupts_service(tool) {
            self.index.invalidate_cluster(&args.cluster);
        }

        // Resolve first so protection can be computed before authorization,
        // exactly as the destroy path does: a waiver or lab mode has to be
        // known before the gate runs, not after it has already refused. A
        // resolve failure is not surfaced here -- see the comment in
        // `authorize_low_with_interrupts` -- so `authorize` below is what
        // decides whether an absent or an out-of-scope guest gets refused,
        // and both get the same error text.
        let (resolved, resolution_failed) =
            match self.index.resolve(client, &args.cluster, args.vmid).await {
                Ok(guest) => (Some(guest), false),
                Err(_) => (None, true),
            };
        let protection = protection_of(client.cluster(), resolved.as_ref(), resolution_failed);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        // Reuses the destroy path's override rules. An interrupting call is not
        // destructive, but the question a waiver answers is the same one:
        // may this protected guest be disrupted right now?
        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
            DestructiveAttempt {
                op: tool,
                principal: caller.as_ref().map(|ctx| ctx.token_name.as_str()),
            },
        );
        let override_applies = !matches!(override_, Override::None);

        let authorized = match self
            .index
            .authorize(
                client,
                &args.cluster,
                args.vmid,
                &grant,
                Intent::low_with_override(tool, override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();
        if guest.r#type != required_type {
            return tool_error(format!(
                "{tool} requires {} guest {}, but it is {}",
                required_type.path_segment(),
                args.vmid,
                guest.r#type.path_segment()
            ));
        }

        // Direct-commit tools run immediately with no change-set approval.
        // Only the interrupting verbs are gated -- `start_vm`/`start_container`
        // are additive, not disruptive, and stay ungated.
        if rust_proxmoxmcp_core::tier::interrupts_service(tool)
            && let Err(result) =
                self.gate_direct_commit(caller.as_ref(), tool, "interrupt", &guest.vmid.to_string())
        {
            return *result;
        }

        let upid = match rust_proxmoxmcp_core::guests::lifecycle(
            client,
            &guest.node,
            guest.r#type,
            guest.vmid,
            verb,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool,
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            guest_name = %guest.name,
            tier = "low",
            interrupts = rust_proxmoxmcp_core::tier::interrupts_service(tool),
            protection = %authorized.protection().summary(),
            override_applied = override_applies,
            scope = scope_desc(caller.as_ref()),
            upid = %upid,
            "proxmox lifecycle call"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "upid": upid,
                "vmid": guest.vmid,
                "node": guest.node,
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "get_container_ip",
        description = "Network interfaces and addresses of one LXC guest."
    )]
    async fn get_container_ip(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        // This tool is LXC-only. We need to resolve the guest first to check its type.
        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_container_ip",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };
        let authorized = match self
            .index
            .authorize(client, &args.cluster, args.vmid, &grant, Intent::read())
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();
        if guest.r#type != GuestType::Lxc {
            return tool_error(format!(
                "get_container_ip requires an LXC guest, but {} is a QEMU VM",
                args.vmid
            ));
        }

        let vmid_str = guest.vmid.to_string();
        let params = vec![("node", guest.node.as_str()), ("vmid", vmid_str.as_str())];

        tracing::info!(
            tool = "get_container_ip",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            guest_name = %guest.name,
            tier = "read",
            protection = %authorized.protection().summary(),
            scope = scope_desc(caller.as_ref()),
            "proxmox read authorized"
        );

        let entry = read_tool("get_container_ip").expect("tool in catalog");
        match client.get_json(entry.path, &params, entry.query).await {
            Ok(value) => tool_result(
                Ok::<_, String>(value),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ),
            Err(error) => tool_error(error),
        }
    }

    #[tool(
        name = "get_guest_status",
        description = "Current runtime status of one guest."
    )]
    async fn get_guest_status(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_guest_status",
            &args.cluster,
            &[],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_snapshots",
        description = "Snapshots of one guest. `description` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn list_snapshots(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_snapshots",
            &args.cluster,
            &[],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_storage",
        description = "Storage backends visible to one node, with usage."
    )]
    async fn get_storage(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_storage",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_backups",
        description = "Backup archives on one storage backend. `notes` content is redacted \
                       (best-effort; do not store secrets here). Paginated: returns up to \
                       `limit` (default 500, max 700) starting at `offset` (default 0), plus \
                       `total` and `has_more` to page through the rest."
    )]
    async fn list_backups(
        &self,
        Parameters(args): Parameters<PagedStorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let page = match resolve_page(args.offset, args.limit) {
            Ok(page) => page,
            Err(error) => return *error,
        };
        self.serve_read(
            "list_backups",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            true,
            Some(page),
            &context,
        )
        .await
    }

    #[tool(name = "list_isos", description = "ISO images on one storage backend.")]
    async fn list_isos(
        &self,
        Parameters(args): Parameters<StorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_isos",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_templates",
        description = "Container templates on one storage backend."
    )]
    async fn list_templates(
        &self,
        Parameters(args): Parameters<StorageArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_templates",
            &args.cluster,
            &[
                ("node", args.node.as_str()),
                ("storage", args.storage.as_str()),
            ],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_tasks",
        description = "Recent tasks on one node. Not paginated: Proxmox's \
                       `/nodes/{node}/tasks` endpoint applies its own server-side \
                       default (typically the 50 most recent) and this tool does not \
                       send `start`/`limit`, so a full page here is Proxmox's default \
                       window, not a complete history."
    )]
    async fn list_tasks(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_tasks",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(name = "get_task_status", description = "Status of one task by UPID.")]
    async fn get_task_status(
        &self,
        Parameters(args): Parameters<TaskArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_task_status",
            &args.cluster,
            &[("node", args.node.as_str()), ("upid", args.upid.as_str())],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_cluster_firewall_rules",
        description = "Cluster-wide firewall rules. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn get_cluster_firewall_rules(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_cluster_firewall_rules",
            &args.cluster,
            &[],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_cluster_firewall_options",
        description = "Cluster-wide firewall options (enable flag, default in/out policy)."
    )]
    async fn get_cluster_firewall_options(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_cluster_firewall_options",
            &args.cluster,
            &[],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_firewall_security_groups",
        description = "Firewall security groups defined on the cluster. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn list_firewall_security_groups(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_firewall_security_groups",
            &args.cluster,
            &[],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_firewall_security_group_rules",
        description = "Rules contained in one firewall security group. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn get_firewall_security_group_rules(
        &self,
        Parameters(args): Parameters<FirewallGroupArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_firewall_security_group_rules",
            &args.cluster,
            &[("group", args.group.as_str())],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_firewall_ipsets",
        description = "Cluster-wide IPSets. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn list_firewall_ipsets(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_firewall_ipsets",
            &args.cluster,
            &[],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_firewall_ipset_entries",
        description = "CIDR entries in one cluster-wide IPSet. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn get_firewall_ipset_entries(
        &self,
        Parameters(args): Parameters<FirewallIpsetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_firewall_ipset_entries",
            &args.cluster,
            &[("name", args.name.as_str())],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_firewall_aliases",
        description = "Cluster-wide firewall address aliases. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn list_firewall_aliases(
        &self,
        Parameters(args): Parameters<ClusterArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_firewall_aliases",
            &args.cluster,
            &[],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_node_firewall_rules",
        description = "Firewall rules on one node. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn get_node_firewall_rules(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_node_firewall_rules",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_node_firewall_options",
        description = "Firewall options on one node."
    )]
    async fn get_node_firewall_options(
        &self,
        Parameters(args): Parameters<NodeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_node_firewall_options",
            &args.cluster,
            &[("node", args.node.as_str())],
            None,
            true,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_guest_firewall_rules",
        description = "Firewall rules of one guest. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn get_guest_firewall_rules(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_guest_firewall_rules",
            &args.cluster,
            &[],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_guest_firewall_options",
        description = "Firewall options of one guest."
    )]
    async fn get_guest_firewall_options(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_guest_firewall_options",
            &args.cluster,
            &[],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_guest_firewall_aliases",
        description = "Firewall address aliases of one guest. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn list_guest_firewall_aliases(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_guest_firewall_aliases",
            &args.cluster,
            &[],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "list_guest_firewall_ipsets",
        description = "IPSets defined on one guest. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn list_guest_firewall_ipsets(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "list_guest_firewall_ipsets",
            &args.cluster,
            &[],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(
        name = "get_guest_firewall_ipset_entries",
        description = "CIDR entries in one IPSet of one guest. `comment` content is redacted (best-effort; do not store secrets here)."
    )]
    async fn get_guest_firewall_ipset_entries(
        &self,
        Parameters(args): Parameters<GuestFirewallIpsetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_read(
            "get_guest_firewall_ipset_entries",
            &args.cluster,
            &[("name", args.name.as_str())],
            Some(args.vmid),
            false,
            None,
            &context,
        )
        .await
    }

    #[tool(name = "start_vm", description = "Start a stopped QEMU guest.")]
    async fn start_vm(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "start_vm",
            LifecycleVerb::Start,
            GuestType::Qemu,
            &args,
            &context,
        )
        .await
    }

    #[tool(
        name = "stop_vm",
        description = "Stop a QEMU guest immediately, without asking the guest OS."
    )]
    async fn stop_vm(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "stop_vm",
            LifecycleVerb::Stop,
            GuestType::Qemu,
            &args,
            &context,
        )
        .await
    }

    #[tool(
        name = "shutdown_vm",
        description = "Ask a QEMU guest's OS to shut down cleanly."
    )]
    async fn shutdown_vm(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "shutdown_vm",
            LifecycleVerb::Shutdown,
            GuestType::Qemu,
            &args,
            &context,
        )
        .await
    }

    #[tool(name = "reset_vm", description = "Hard power-cycle a QEMU guest.")]
    async fn reset_vm(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "reset_vm",
            LifecycleVerb::Reset,
            GuestType::Qemu,
            &args,
            &context,
        )
        .await
    }

    #[tool(name = "start_container", description = "Start a stopped LXC guest.")]
    async fn start_container(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "start_container",
            LifecycleVerb::Start,
            GuestType::Lxc,
            &args,
            &context,
        )
        .await
    }

    #[tool(
        name = "stop_container",
        description = "Stop an LXC guest immediately."
    )]
    async fn stop_container(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "stop_container",
            LifecycleVerb::Stop,
            GuestType::Lxc,
            &args,
            &context,
        )
        .await
    }

    #[tool(name = "restart_container", description = "Reboot an LXC guest.")]
    async fn restart_container(
        &self,
        Parameters(args): Parameters<GuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.serve_lifecycle(
            "restart_container",
            LifecycleVerb::Reboot,
            GuestType::Lxc,
            &args,
            &context,
        )
        .await
    }

    #[tool(
        name = "create_snapshot",
        description = "Take a snapshot of one guest. Additive, so permitted on a protected guest."
    )]
    async fn create_snapshot(
        &self,
        Parameters(args): Parameters<SnapshotArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self
            .authorize_low("create_snapshot", &guest_args, &context)
            .await
        {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };
        let guest = authorized.guest();

        let upid = match rust_proxmoxmcp_core::guests::create_snapshot(
            match self.client_for(&args.cluster) {
                Ok(client) => client,
                Err(result) => return *result,
            },
            &guest.node,
            guest.r#type,
            guest.vmid,
            &args.snapname,
            args.description.as_deref(),
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "create_snapshot",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            tier = "low",
            interrupts = false,
            protection = %authorized.protection().summary(),
            snapname = %args.snapname,
            upid = %upid,
            "proxmox snapshot created"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({ "upid": upid, "vmid": guest.vmid, "node": guest.node })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "create_backup",
        description = "Back up one guest with vzdump. mode: \"snapshot\" (default) is additive and \
                        permitted on a protected guest; \"suspend\" and \"stop\" take the guest out \
                        of service for the duration of the backup and are refused on a protected \
                        guest exactly like stop_vm."
    )]
    async fn create_backup(
        &self,
        Parameters(args): Parameters<BackupArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        if !rust_proxmoxmcp_core::tier::VALID_BACKUP_MODES.contains(&args.mode.as_str()) {
            return tool_error(format!(
                "mode '{}' is not one of snapshot, suspend, or stop",
                args.mode
            ));
        }

        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let interrupts = rust_proxmoxmcp_core::tier::backup_interrupts(&args.mode);
        let authorized = match self
            .authorize_low_with_interrupts("create_backup", &guest_args, &context, Some(interrupts))
            .await
        {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };
        let guest = authorized.guest();

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // Direct-commit tools run immediately with no change-set approval.
        // Gated unconditionally, not only when `mode: "stop"` interrupts the
        // guest: every mode is in the issue's named scope.
        let caller = Self::caller(&context);
        if let Err(result) = self.gate_direct_commit(
            caller.as_ref(),
            "create_backup",
            "backup",
            &guest.vmid.to_string(),
        ) {
            return *result;
        }

        let upid = match rust_proxmoxmcp_core::guests::create_backup(
            client,
            &guest.node,
            guest.vmid,
            &args.storage,
            &args.mode,
            args.compress.as_deref(),
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "create_backup",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            tier = "low",
            interrupts = interrupts,
            protection = %authorized.protection().summary(),
            storage = %args.storage,
            mode = %args.mode,
            upid = %upid,
            "proxmox backup started"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({ "upid": upid, "vmid": guest.vmid, "node": guest.node })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "clone_vm",
        description = "Clone a guest into a new VMID. Additive, so permitted on a protected source."
    )]
    async fn clone_vm(
        &self,
        Parameters(args): Parameters<CloneArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::protect::creation_allowed;

        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self.authorize_low("clone_vm", &guest_args, &context).await {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // The destination must be inside the caller's guest grant.
        //
        // `authorize_low` above checked the *source*; nothing has looked at
        // `newid`. Without this a token scoped to `vmid:600-699` could clone
        // 606 into 800 — creating a guest outside the range it was granted,
        // and probing which VMIDs are free while doing it.
        let grant = match resolve_grant(Self::caller(&context).as_ref()) {
            Ok(grant) => grant,
            Err(result) => return *result,
        };
        if !grant.allows_new_vmid(args.newid) {
            return tool_error(format!(
                "caller scope does not admit vmid {} as a clone destination",
                args.newid
            ));
        }

        // And it must not be a protected pin. The protection union is evaluated
        // against a resolved guest, so it has nothing to say about a VMID that
        // does not exist yet. A pinned VMID is pinned because something is
        // expected to live there; letting a clone claim it means the real guest
        // has nowhere to go and the next delete against that number protects
        // the wrong thing.
        if !creation_allowed(client.cluster(), args.newid) {
            return tool_error(format!(
                "vmid {} is a protected pin in cluster {}; a clone may not claim it",
                args.newid, args.cluster
            ));
        }

        // Direct-commit tools run immediately with no change-set approval.
        let caller = Self::caller(&context);
        if let Err(result) = self.gate_direct_commit(
            caller.as_ref(),
            "clone_vm",
            "clone",
            &args.newid.to_string(),
        ) {
            return *result;
        }

        let guest = authorized.guest();
        let upid = match rust_proxmoxmcp_core::guests::clone_guest(
            client,
            &guest.node,
            guest.r#type,
            guest.vmid,
            args.newid,
            args.name.as_deref(),
            args.full,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "clone_vm",
            cluster = args.cluster,
            vmid = guest.vmid,
            newid = args.newid,
            node = %guest.node,
            tier = "low",
            interrupts = false,
            full = args.full,
            protection = %authorized.protection().summary(),
            upid = %upid,
            "proxmox clone started"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({ "upid": upid, "vmid": args.newid, "node": guest.node })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    /// Shared body for `create_vm` and `create_container`.
    ///
    /// The two differ only in the path segment Proxmox wants, but they stay
    /// separate tools: a caller asking for a container should not have to know
    /// that a `kind` flag exists, and the tool name is what the token scope
    /// names.
    async fn create_guest_inner(
        &self,
        tool: &'static str,
        kind: GuestType,
        args: CreateGuestArgs,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        if let Some(refusal) = Self::reject_unsafe_config(&args.config) {
            return refusal;
        }

        let client = match self
            .authorize_creation(tool, &args.cluster, args.vmid, &context)
            .await
        {
            Ok(client) => client,
            Err(result) => return *result,
        };

        // Proxmox reads an omitted `unprivileged` as 0 -- privileged. Silence
        // must not select the dangerous option, so a container gets 1 unless
        // the caller said otherwise (and `reject_unsafe_config` has already
        // refused their saying 0).
        let mut config_owned = args.config.clone();
        if kind == GuestType::Lxc {
            config_owned
                .entry("unprivileged".to_owned())
                .or_insert_with(|| "1".to_owned());
        }

        let config: Vec<(&str, &str)> = config_owned
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();

        // Direct-commit tools run immediately with no change-set approval.
        let caller = Self::caller(&context);
        if let Err(result) =
            self.gate_direct_commit(caller.as_ref(), tool, "create", &args.vmid.to_string())
        {
            return *result;
        }

        let upid = match rust_proxmoxmcp_core::guests::create_guest(
            client, &args.node, kind, args.vmid, &config,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        // Deliberately no cache invalidation. The POST returns when the
        // create *task* starts, not when the guest appears in
        // `/cluster/resources`, so a refresh raced against it would fetch a
        // snapshot that still lacks the guest and cache that absence for a full
        // TTL -- turning a short wait into a longer one. The response says to
        // follow the task instead.

        tracing::info!(
            target: "audit",
            tool = tool,
            cluster = args.cluster,
            vmid = args.vmid,
            node = %args.node,
            kind = %kind.path_segment(),
            config_keys = %config_owned.keys().cloned().collect::<Vec<_>>().join(","),
            tier = "low",
            interrupts = false,
            upid = %upid,
            "proxmox guest created"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "upid": upid,
                "vmid": args.vmid,
                "node": args.node,
                "kind": kind.path_segment(),
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "update_container_resources",
        description = "Change an LXC guest's cores, memory or swap. Memory and swap take effect at the next start, not immediately."
    )]
    async fn update_container_resources(
        &self,
        Parameters(args): Parameters<ContainerResourceArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        if args.cores.is_none() && args.memory_mb.is_none() && args.swap_mb.is_none() {
            return tool_error(
                "give at least one of cores, memory_mb or swap_mb: a call with none would report \
                 a change that never happened.",
            );
        }

        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self
            .authorize_low("update_container_resources", &guest_args, &context)
            .await
        {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        let guest = authorized.guest();

        // The endpoint is LXC-only. A QEMU guest would 501 from Proxmox with a
        // message about the path, which reads as a server fault rather than a
        // guest-type mismatch.
        if guest.r#type != GuestType::Lxc {
            return tool_error(format!(
                "vmid {} is a QEMU guest; this tool changes LXC allocations only. Resize a VM from \
                 the Proxmox UI or CLI.",
                guest.vmid
            ));
        }

        // Direct-commit tools run immediately with no change-set approval.
        // `update_container_resources` is in `tier::INTERRUPTING_TOOLS` --
        // changing cores takes effect immediately, so it interrupts the
        // container's current allocation the same way stopping it would.
        let caller = Self::caller(&context);
        if let Err(result) = self.gate_direct_commit(
            caller.as_ref(),
            "update_container_resources",
            "interrupt",
            &guest.vmid.to_string(),
        ) {
            return *result;
        }

        if let Err(error) = rust_proxmoxmcp_core::guests::update_container_resources(
            client,
            &guest.node,
            guest.vmid,
            args.cores,
            args.memory_mb,
            args.swap_mb,
        )
        .await
        {
            return tool_error(error);
        }

        tracing::info!(
            target: "audit",
            tool = "update_container_resources",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            tier = "low",
            interrupts = true,
            cores = ?args.cores,
            memory_mb = ?args.memory_mb,
            swap_mb = ?args.swap_mb,
            protection = %authorized.protection().summary(),
            "proxmox container resources changed"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "vmid": guest.vmid,
                "node": guest.node,
                "cores": args.cores,
                "memory_mb": args.memory_mb,
                "swap_mb": args.swap_mb,
                "note": "cores apply immediately; memory and swap take effect at the next start",
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "stop_task",
        description = "Ask Proxmox to stop a running task. Restores and destroys are refused: stopping one half-way leaves a guest that is neither its old self nor its new one."
    )]
    async fn stop_task(
        &self,
        Parameters(args): Parameters<StopTaskArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::grant::ProxmoxAction;
        use rust_proxmoxmcp_core::guests::stopping_task_leaves_partial_state;

        // Checked before authorization, because the answer decides whether this
        // call belongs to the low tier at all — the same reason `resize_disk`
        // classifies its size argument first.
        if stopping_task_leaves_partial_state(&args.upid) {
            return tool_error(format!(
                "task '{}' rewrites a guest in place, so stopping it half-way would leave \
                 something that is neither the old guest nor the new one. Let it finish and \
                 repair the result afterwards. Backups, migrations and downloads can be stopped.",
                args.upid
            ));
        }

        // The node comes from the handle, never the caller. Every other tool
        // here follows that rule because guests migrate; it matters just as
        // much for a task, where a mismatched node addresses a path the task
        // does not live at and Proxmox answers that cheerfully.
        let Some(node) = rust_proxmoxmcp_core::guests::upid_node(&args.upid).map(ToOwned::to_owned)
        else {
            return tool_error(format!(
                "'{}' is not a task handle: a UPID is 'UPID:node:...:worker:id:user:'",
                args.upid
            ));
        };

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "stop_task",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(result) => return *result,
        };

        if !grant.allows_action(ProxmoxAction::Low) {
            return tool_error("stop_task requires the 'low' action tier");
        }

        // A UPID's `id` names the guest for guest-addressed work: `vzdump:617`
        // is a backup *of 617*. Interrupting it interrupts that guest's
        // operation, so it goes through the same authorization every other
        // interrupting tool does, protection gate included. Cancelling a
        // migration of a protected guest is not a node-level act merely because
        // the endpoint happens to be addressed by node.
        // Guest-addressability comes from the worker kind, not from whether the
        // id is a number: `cephdestroyosd:3` is OSD 3, and reading it as guest
        // 3 would let a token scoped to guest 3 cancel node work.
        let authorized = match rust_proxmoxmcp_core::guests::task_guest(&args.upid) {
            Some(task_vmid) => {
                let guest_args = GuestArgs {
                    cluster: args.cluster.clone(),
                    vmid: task_vmid,
                };
                match self.authorize_low("stop_task", &guest_args, &context).await {
                    Ok(authorized) => Some(authorized),
                    Err(result) => return *result,
                }
            }
            None => {
                // Node-level work names no guest, so no selector can narrow it
                // and no protection gate applies. An unrestricted guest scope
                // stands in, as it does for `download_iso`.
                if !grant.is_unrestricted_guest_scope() {
                    return tool_error(format!(
                        "task '{}' is node-level rather than guest-addressed, so it requires a \
                         caller whose guest scope is '*'. This caller is narrowed to specific \
                         guests and cannot be checked against it.",
                        args.upid
                    ));
                }
                None
            }
        };

        // Direct-commit tools run immediately with no change-set approval.
        // `stop_task` is in `tier::INTERRUPTING_TOOLS`: it aborts work in
        // progress, guest-addressed or not, so both branches above are gated
        // the same way the lifecycle verbs are -- the target names the guest
        // when there is one, and the node otherwise.
        let target = match authorized.as_ref() {
            Some(authorized) => authorized.guest().vmid.to_string(),
            None => node.clone(),
        };
        if let Err(result) =
            self.gate_direct_commit(caller.as_ref(), "stop_task", "interrupt", &target)
        {
            return *result;
        }

        if let Err(error) = rust_proxmoxmcp_core::guests::stop_task(client, &node, &args.upid).await
        {
            return tool_error(error);
        }

        // Two call sites rather than one with optional fields. A tracing field
        // is fixed per site, so an `Option` would serialise as the string
        // "Some(617)" or "None" in the JSON audit stream -- neither omitted nor
        // the same type as every other event's `vmid`, which breaks correlation
        // for exactly the queries an audit log exists to answer.
        match authorized.as_ref() {
            Some(authorized) => {
                let guest = authorized.guest();
                tracing::info!(
                    target: "audit",
                    tool = "stop_task",
                    cluster = args.cluster,
                    node = %node,
                    tier = "low",
                    interrupts = true,
                    upid = %args.upid,
                    vmid = guest.vmid,
                    guest = %guest.name,
                    // A protected guest allowed through a waiver or lab mode
                    // has to leave that verdict here, or the trail shows its
                    // operation interrupted with no evidence of why.
                    protection = %authorized.protection().summary(),
                    "proxmox task stop requested"
                );
            }
            None => {
                tracing::info!(
                    target: "audit",
                    tool = "stop_task",
                    cluster = args.cluster,
                    node = %node,
                    tier = "low",
                    interrupts = true,
                    upid = %args.upid,
                    // Not `scope`: that key already carries the caller's
                    // authorization scope elsewhere in this module, and reusing
                    // it here would put a target kind into the field audit
                    // queries group authorization by.
                    task_scope = "node",
                    "proxmox task stop requested"
                );
            }
        }

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "upid": args.upid,
                "node": node,
                "note": "a stop was requested; read the task status to learn whether it stopped",
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "create_vm",
        description = "Create a QEMU guest at a free VMID. Config keys are forwarded to Proxmox as given; 'hookscript' and 'args' are refused because they execute on the node."
    )]
    async fn create_vm(
        &self,
        Parameters(args): Parameters<CreateGuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.create_guest_inner("create_vm", GuestType::Qemu, args, context)
            .await
    }

    #[tool(
        name = "create_container",
        description = "Create an LXC guest at a free VMID. Config keys are forwarded to Proxmox as given; 'hookscript' and 'args' are refused because they execute on the node."
    )]
    async fn create_container(
        &self,
        Parameters(args): Parameters<CreateGuestArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        self.create_guest_inner("create_container", GuestType::Lxc, args, context)
            .await
    }

    #[tool(
        name = "download_iso",
        description = "Download an image to a node's storage. Requires an unrestricted guest scope, because a storage is shared and no guest selector can narrow it."
    )]
    async fn download_iso(
        &self,
        Parameters(args): Parameters<DownloadIsoArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::grant::ProxmoxAction;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "download_iso",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(result) => return *result,
        };

        if !grant.allows_action(ProxmoxAction::Low) {
            return tool_error("download_iso requires the 'low' action tier");
        }

        // A storage names no guest, so `allows_guest` has nothing to match and
        // no selector this grant carries can narrow the call. A narrowed token
        // is therefore refused outright rather than silently granted the run of
        // storage every guest shares. See `is_unrestricted_guest_scope`.
        if !grant.is_unrestricted_guest_scope() {
            return tool_error(
                "download_iso writes to storage that is not scoped to any guest, so it requires a \
                 caller whose guest scope is '*'. This caller is narrowed to specific guests and \
                 cannot be checked against a storage.",
            );
        }

        // Proxmox verifies only when both halves are present and ignores one
        // without the other, which would leave a caller believing a checksum
        // was checked when it was not.
        let checksum = match (args.checksum_algorithm.as_deref(), args.checksum.as_deref()) {
            (Some(algorithm), Some(value)) => Some((algorithm, value)),
            (None, None) => None,
            _ => {
                return tool_error(
                    "checksum and checksum_algorithm travel together: Proxmox ignores one without \
                     the other, so supplying a single half would report a verified download that \
                     was never verified. Give both, or neither.",
                );
            }
        };

        let upid = match rust_proxmoxmcp_core::guests::download_url(
            client,
            &args.node,
            &args.storage,
            &args.content,
            &args.filename,
            &args.url,
            checksum,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "download_iso",
            cluster = args.cluster,
            node = %args.node,
            storage = %args.storage,
            filename = %args.filename,
            url = %redact_download_url(&args.url),
            checksum_verification_requested = checksum.is_some(),
            tier = "low",
            interrupts = false,
            upid = %upid,
            "proxmox image download started"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({
                "upid": upid,
                "node": args.node,
                "storage": args.storage,
                "filename": args.filename,
                // Requested, not observed. The POST returns when the download
                // task starts; Proxmox verifies the checksum inside that task,
                // so a mismatch surfaces as a failed task afterwards. Reporting
                // "verified" here would assert something this call cannot know.
                "checksum_verification_requested": checksum.is_some(),
                "note": "follow the upid with get_task_status; a checksum mismatch fails the task",
            })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "resize_disk",
        description = "Grow a guest disk. Only the '+N' form is accepted. Shrinking is not supported: Proxmox itself rejects a reduction, so there is no path to it here."
    )]
    async fn resize_disk(
        &self,
        Parameters(args): Parameters<ResizeArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::guests::resize_shrinks;

        // Checked before authorization, because the answer decides which tier
        // this call belongs to. A shrink is not a low-tier operation and must
        // not be authorised as one — `authorize_low` would grant it on a
        // `low` action tier the operator never intended for data loss.
        if resize_shrinks(&args.size) {
            return tool_error(format!(
                "size '{}' is not an unambiguous grow, so this server will not perform it. \
                 Only the '+N' form adds capacity; an absolute size may be smaller than the \
                 current disk, which destroys data. Shrinking is not supported here, and \
                 Proxmox does not support it either: `qm resize` and `pct resize` reject a \
                 reduction. Re-issue this call with a '+N' size to grow the disk.",
                args.size
            ));
        }

        let guest_args = GuestArgs {
            cluster: args.cluster.clone(),
            vmid: args.vmid,
        };
        let authorized = match self
            .authorize_low("resize_disk", &guest_args, &context)
            .await
        {
            Ok(authorized) => authorized,
            Err(result) => return *result,
        };

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };
        let guest = authorized.guest();

        // Direct-commit tools run immediately with no change-set approval.
        let caller = Self::caller(&context);
        if let Err(result) = self.gate_direct_commit(
            caller.as_ref(),
            "resize_disk",
            "resize",
            &guest.vmid.to_string(),
        ) {
            return *result;
        }

        let upid = match rust_proxmoxmcp_core::guests::resize_disk(
            client,
            &guest.node,
            guest.r#type,
            guest.vmid,
            &args.disk,
            &args.size,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        tracing::info!(
            target: "audit",
            tool = "resize_disk",
            cluster = args.cluster,
            vmid = guest.vmid,
            node = %guest.node,
            tier = "low",
            interrupts = false,
            disk = %args.disk,
            size = %args.size,
            protection = %authorized.protection().summary(),
            // Empty when the storage answered synchronously. Present or not,
            // it is the only handle correlating this event with the task, so
            // it belongs in the record rather than only in the response.
            upid = %upid,
            "proxmox disk resized"
        );

        tool_result::<_, String>(
            Ok(serde_json::json!({ "upid": upid, "vmid": guest.vmid, "node": guest.node })),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "plan_proxmox_destroy",
        description = "Plan a guest destroy operation for two-principal approval."
    )]
    async fn plan_destroy(
        &self,
        Parameters(args): Parameters<change_set::PlanDestroyArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;
        use rust_proxmoxmcp_core::{
            fingerprint::{GuestState, fingerprint},
            guests::fetch_guest_config_state,
            preview::{PreviewInput, render_preview},
            protect::{DestructiveAttempt, Override, destructive_allowed, protection_of},
        };

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "plan_proxmox_destroy",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        // Drop the cached snapshot before resolving. The fingerprint computed
        // below is what apply re-checks, so planning from a stale read produces
        // a change set that records state the guest has already left -- and the
        // apply then refuses it as changed.
        //
        // That is exactly what a caller does after stopping a guest to satisfy
        // the precondition below: stop, plan immediately, and the plan records
        // `running` because the snapshot is seconds old. Apply is correct to
        // refuse; the plan should not have been built from stale state.
        self.index.invalidate_cluster(&args.cluster);

        // Resolve guest and compute protection to determine override. A
        // resolve failure is not surfaced directly -- `authorize` below
        // re-resolves and is what decides whether an absent guest and an
        // out-of-scope one get refused, with identical error text either way.
        let (resolved, resolution_failed) =
            match self.index.resolve(client, &args.cluster, args.vmid).await {
                Ok(guest) => (Some(guest), false),
                Err(_) => (None, true),
            };
        let protection = protection_of(client.cluster(), resolved.as_ref(), resolution_failed);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
            DestructiveAttempt {
                op: &args.op,
                principal: caller.as_ref().map(|ctx| ctx.token_name.as_str()),
            },
        );

        let override_applies = !matches!(override_, Override::None);

        // Now authorize with the override information.
        let authorized = match self
            .index
            .authorize(
                client,
                &args.cluster,
                args.vmid,
                &grant,
                Intent::destructive(override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();

        // Built before the preview, because the preview describes it.
        let action = match build_destroy_action(&args) {
            Ok(action) => action,
            Err(error) => return tool_error(error),
        };

        // Refuse at plan time rather than relying solely on the apply-time
        // re-check in `execute_destructive`: a `delete_backup`/`restore_backup`
        // volid's filename convention names a vmid, but nothing before this
        // bound it to the vmid the caller is authorized for. Spending a
        // two-person approval on a plan that was never going to touch the
        // named guest's own archive is worse than refusing it here.
        if action.op == "delete_backup" || action.op == "restore_backup" {
            let owner_node = match action.op.as_str() {
                "delete_backup" => action
                    .storage_node
                    .as_deref()
                    .expect("delete_backup always carries storage_node"),
                _ => guest.node.as_str(),
            };
            let volid = action
                .volid
                .as_deref()
                .expect("delete_backup/restore_backup always carry volid");
            if let Err(error) =
                Self::require_backup_owner(client, owner_node, volid, args.vmid).await
            {
                return tool_error(error);
            }
        }

        // Refuse here rather than at apply. Proxmox will not destroy a running
        // guest -- `destroy_vm`/`destroy_container` send `purge` and never
        // `force` -- so planning one produces a change set that cannot succeed.
        //
        // Discovering that at apply is worse than it sounds under two-person
        // control: the plan succeeds, a second person approves it, and only
        // then does it fail. The approval is spent, the change set is terminal,
        // and the same human has to be asked again for the same operation. The
        // guest's state is known here, and the preview already prints it.
        if destroy_requires_a_stopped_guest(&action.op) && guest.status != "stopped" {
            // Confirmed stopped, not merely "not running". `/cluster/resources`
            // can report `unknown` for a guest it cannot read, and treating an
            // unreadable status as good enough would hand out exactly the
            // unusable plan this check exists to prevent.
            return tool_error(format!(
                "guest {} reports status '{}', and Proxmox destroys only a stopped guest. Stop it \
                 with stop_vm or stop_container and confirm it reads 'stopped', then plan again. \
                 Refused here rather than at apply so no approval is spent on an operation that \
                 cannot succeed.",
                guest.vmid, guest.status
            ));
        }

        // Same reasoning, for `migrate`: refuse a plan Proxmox cannot satisfy
        // before an approval is spent on it, rather than after.
        if action.op == "migrate" {
            // `build_destroy_action` requires `target_node` for this op, so
            // the field is always present on an action reaching this point.
            let target_node = action
                .target_node
                .as_deref()
                .expect("migrate action always carries target_node");

            if target_node == guest.node {
                return tool_error(format!(
                    "guest {} is already on node '{}'; nothing to migrate",
                    guest.vmid, guest.node
                ));
            }

            if let Err(error) = migrate_precondition(action.online, &guest.status) {
                return tool_error(error);
            }

            match rust_proxmoxmcp_core::guests::list_node_names(client).await {
                Ok(nodes) => {
                    if !nodes.iter().any(|node| node == target_node) {
                        return tool_error(format!(
                            "target node '{target_node}' is not a member of cluster '{}'; \
                             known nodes: {}",
                            args.cluster,
                            nodes.join(", ")
                        ));
                    }
                }
                Err(error) => return tool_error(format!("listing cluster nodes: {error}")),
            }
        }

        // `update_vm_config` writes to `/qemu/{vmid}/config` specifically --
        // there is no LXC equivalent this tool reaches. Refused here, before
        // any approval is spent, rather than discovered as a 501 from
        // Proxmox at apply time.
        if action.op == "update_vm_config" && guest.r#type != GuestType::Qemu {
            return tool_error(format!(
                "guest {} is a {} guest; update_vm_config only updates QEMU (VM) config. There \
                 is no LXC path here.",
                guest.vmid,
                guest.r#type.path_segment()
            ));
        }

        // The operation's own tool scope, on top of `plan_proxmox_destroy`.
        // Without this a token allowlisted for the generic handlers could
        // select any operation, and `WRITE_TOOLS` naming each destructive tool
        // separately would mean nothing.
        let Some(op_tool) = tool_for_op(&action.op, guest.r#type) else {
            return tool_error(format!("unknown destructive operation '{}'", action.op));
        };
        if let Err(error) =
            authorize_call(caller.as_ref(), op_tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return authz_tool_error(error);
        }

        if let Err(error) = require_unrestricted_scope_for_delete_iso(&action.op, &grant) {
            return tool_error(error);
        }

        // The digest and disk sizes come from the guest's own config, not
        // `/cluster/resources` -- that snapshot is cluster-wide and reports
        // neither. Fetched fresh rather than cached: this is what apply
        // re-checks, and a stale digest here would defeat the fingerprint the
        // same way a stale `/cluster/resources` read once did.
        //
        // Deferred until after the cheap local checks above (volid validation,
        // the stopped-guest check, op-tool scope), so a plan that was always
        // going to be refused for one of those reasons does not first pay for
        // a network round trip.
        let config_state =
            match fetch_guest_config_state(client, &guest.node, guest.r#type, guest.vmid).await {
                Ok(state) => state,
                Err(error) => return tool_error(format!("reading guest config: {error}")),
            };

        // Compute fingerprint.
        let state = GuestState {
            cluster: args.cluster.clone(),
            vmid: guest.vmid,
            name: guest.name.clone(),
            kind: guest.r#type.path_segment().to_owned(),
            node: guest.node.clone(),
            status: guest.status.clone(),
            tags: guest.tags.clone(),
            config_digest: config_state.config_digest,
            disks: config_state.disks,
        };

        let expected_fingerprint = fingerprint(&state);

        // Render preview.
        let preview_input = PreviewInput {
            state: &state,
            protected: protection.is_protected(),
            protection_summary: &protection.summary(),
            override_: &override_,
            snapshots: 0,
            latest_snapshot: None,
            last_backup: None,
            purge_disks: true,
        };

        // The generic renderer describes a guest destroy. For every other
        // operation that is the wrong text, so the approver would be signing
        // off on something other than what runs. The guest-destroy path keeps
        // the richer renderer — it has snapshot and backup context this one
        // does not — and every other operation gets a description of itself.
        let preview_text = if matches!(action.op.as_str(), "destroy_guest" | "destroy") {
            render_preview(&preview_input)
        } else {
            render_destructive_preview(
                &action,
                &guest.name,
                &guest.node,
                protection.is_protected(),
                &protection.summary(),
                &override_,
            )
        };

        // Use the shared coordinator.
        let coordinator = self.coordinator.clone();

        let owner = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());

        let device = format!("{}/{}", args.cluster, args.vmid);
        // Validate the operation and its parameters before anything is
        // recorded. A change set whose action names an operation the apply
        // cannot dispatch is a change set an approver may sign and nobody can
        // execute — worse, one whose parameters are missing would dispatch
        // with defaults the approver never saw.

        // This server has no policy engine in 0.3.
        let policy_signature = "proxmox-no-policy-engine";

        // Created without a preview, then given one by the `update_change_set`
        // below. The binding happens at approve: mecmcp 0.23.0 hashes the
        // stored preview's digest into the approval digest, so the coordinator
        // -- not this call site -- is what ties the two together, and it then
        // refuses any write that would swap or drop the preview afterwards.
        let output = match coordinator
            .create_change_set(
                device.clone(),
                vec![action],
                owner.clone(),
                expected_fingerprint.clone(),
                policy_signature.to_owned(),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return tool_error(format!("create: {error}")),
        };

        // Persist the preview the approver will read, with its own digest.
        //
        // `create_change_set` takes no preview, so this is a second write. What
        // it buys is tamper evidence: `validate_preview` recomputes the digest
        // on load, so the text an approver reviewed cannot be edited afterwards
        // without the store refusing it.
        //
        // The plan digest itself is over (owner, device, fingerprint, actions)
        // and says nothing about this preview text. Cryptographic coverage of
        // the preview comes from the coordinator at approve time: mecmcp
        // 0.23.0 folds this preview's digest into the approval digest, so the
        // approver ends up signing the exact text stored here as well as the
        // plan. See the `create_change_set` call above.
        let Some(mut with_preview) = coordinator
            .change_sets()
            .await
            .into_iter()
            .find(|record| record.id == output.change_set_id)
        else {
            // The record was created a moment ago, so not finding it means the
            // store dropped or evicted it. This used to be a silent skip that
            // returned a *successful* plan for a change set with no preview.
            tracing::error!(
                change_set = %output.change_set_id,
                "the change set could not be read back; the plan is refused"
            );
            return tool_error(
                "plan refused: the change set could not be read back to store its \
                 preview. It has no preview, so approve and apply will refuse it. \
                 Plan the operation again.",
            );
        };

        with_preview.preview = Some(mecmcp_changeset::PreviewRecord {
            digest: mecmcp_changeset::preview_digest(&preview_text),
            artifact: preview_text.clone(),
            job_id: None,
        });
        if let Err(error) = coordinator.update_change_set(with_preview).await {
            // Fail the plan rather than return one whose preview is not in the
            // store. The record itself is left behind and expires on its own —
            // there is no cancel tool — but `approve` and `apply` now refuse a
            // previewless record, so it cannot be acted on in the meantime.
            tracing::error!(
                %error,
                change_set = %output.change_set_id,
                "the preview could not be persisted; the plan is refused"
            );
            return tool_error(format!(
                "plan refused: the preview could not be persisted ({error}). The \
                 change set has no stored preview, so approve and apply will refuse \
                 it. Plan the operation again."
            ));
        }

        // Apply override.
        //
        // A matching operator waiver lifts *protection* -- the same
        // `Override::Waiver` already let this plan past the per-guest
        // protection gate in the `authorize` call above -- but it is not a
        // second principal's decision, so it must not move the change set to
        // `Approved`. The record stays `Planned`: a distinct human still has
        // to call `approve_proxmox_change_set`. `authorize_ha_rule_guests`
        // holds the same line for HA rule changes, and its doc comment says
        // it plainly: an override there "never waives the change set's
        // second-principal approval; it only lets the guest check pass".
        //
        // Earlier this called `coordinator.waive_approval_operator`, which
        // sets the record `Approved` outright -- collapsing two-person
        // control for any caller holding the destructive tier and a waiver,
        // agent tokens included, contrary to this PR's stated intent.
        let output = match override_ {
            Override::Waiver {
                reason,
                ticket,
                until_unix,
            } => {
                tracing::warn!(
                    target: "audit",
                    event = "protection_waived",
                    change_set = %output.change_set_id,
                    %reason,
                    ticket = ticket.as_deref().unwrap_or(""),
                    until_unix,
                    "an operator waiver lifted protection for this plan; a distinct human \
                     approval is still required before it may be applied"
                );
                output
            }
            Override::LabMode => match coordinator
                .waive_approval(
                    output.change_set_id.clone(),
                    device.clone(),
                    owner.clone(),
                    output.digest.clone(),
                )
                .await
            {
                Ok(waived) => waived,
                Err(error) => return tool_error(format!("lab-mode: {error}")),
            },
            Override::None => output,
        };

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "get_proxmox_change_set",
        description = "Retrieve the current state of a change set."
    )]
    async fn get_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::{ChangeSetResponse, DestroyAction};

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        // This tool name and the cluster scope checked above say nothing
        // about which guest the caller may read. A token scoped to one guest
        // could otherwise read any other change set's preview on the same
        // cluster, which leaks the guest's name, node and (for
        // `update_vm_config`) cloud-init values like `sshkeys` and
        // `ipconfigN`. Same two action shapes as `approve_change_set`: an
        // existing guest to resolve and scope-check, or a not-yet-existing
        // restore target that only the grant's new-vmid scope can speak to.
        if let Some(raw_action) = record.actions.first() {
            if let Ok(_action) = serde_json::from_value::<DestroyAction>(raw_action.clone()) {
                if let Err(error) = self
                    .index
                    .authorize(client, &args.cluster, args.vmid, &grant, Intent::read())
                    .await
                {
                    return tool_error(error);
                }
            } else {
                use restore_change_set::RestoreNewVmidAction;

                let action: RestoreNewVmidAction = match serde_json::from_value(raw_action.clone())
                {
                    Ok(action) => action,
                    Err(error) => {
                        return tool_error(format!(
                            "the change set's action could not be read ({error}); it cannot be \
                             read back"
                        ));
                    }
                };
                if !grant.allows_new_vmid(action.target_vmid) {
                    return tool_error(format!(
                        "vmid {} is outside this caller's guest scope",
                        action.target_vmid
                    ));
                }
                // Same authority check `approve_change_set` runs: scope and
                // protection on the owner guest whose archive this would
                // read, not just the target vmid above. The waiver check
                // inside binds to the principal who planned the restore, not
                // this reader -- see the comment on the `approve_change_set`
                // call below.
                if let Err(error) = self
                    .authorize_backup_owner(
                        client,
                        &args.cluster,
                        action.owner_vmid,
                        &grant,
                        &action.volid,
                        Some(record.owner.as_str()),
                    )
                    .await
                {
                    return tool_error(error);
                }
            }
        }

        let preview_text = record
            .preview
            .as_ref()
            .map(|p| p.artifact.clone())
            .unwrap_or_else(|| "(no preview)".to_owned());

        let response = ChangeSetResponse {
            change_set_id: record.id,
            state: format!("{:?}", record.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(record.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "approve_proxmox_change_set",
        description = "Approve a planned change set as a second principal."
    )]
    async fn approve_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::{ChangeSetResponse, DestroyAction};
        use rust_proxmoxmcp_core::protect::{
            DestructiveAttempt, Override, destructive_allowed, protection_of,
        };

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "approve_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        let approver = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());
        // Truthful, not permissive: a stdio caller carries no verified token
        // entry, so its actor type is unknown rather than assumed human. mecmcp's
        // `approve_change_set` refuses anything but `Human` (the house rule that
        // a human approves), which is exactly the outcome an unattributed caller
        // should get.
        let approver_actor_type = change_set::actor_type(caller.as_ref());

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        // A change set with no stored preview must never be approved. Since
        // mecmcp 0.23.0 the approval digest folds in the stored preview's
        // digest, but that binds whatever preview is on record -- it does not
        // require one to exist. This handler used to substitute the literal
        // string "(no preview)" and approve anyway, recording an approval over
        // text no one could read.
        let Some(preview) = record.preview.as_ref() else {
            return tool_error(
                "approval refused: this change set has no stored preview, so there is \
                 nothing to review. Plan the operation again.",
            );
        };

        // The approver must hold the same authority the executor needs, not
        // just the generic approve-tool and cluster scope checked above.
        // Without this, a token scoped to one guest with only `read` could
        // approve a `destroy_guest` change set against any other guest in the
        // cluster -- `approve_change_set` never looked at the approver's own
        // grant, only at whether they held the `approve_proxmox_change_set`
        // tool name. This mirrors the re-check `apply_change_set` and
        // `apply_restore_new_vmid` run, so approve and apply hold the
        // approver and the executor to the same standard.
        //
        // Two action shapes share this tool: `DestroyAction` (plan_destroy --
        // an existing in-scope guest to resolve and protect) and
        // `RestoreNewVmidAction` (plan_restore_new_vmid -- a target vmid that
        // does not exist yet, so there is no guest to resolve or protect).
        // Try the former first; its required `op`/`vmid` fields are absent
        // from the latter's JSON, so a mismatched shape fails to deserialize
        // and falls through.
        let Some(raw_action) = record.actions.first() else {
            return tool_error("the change set records no action".to_owned());
        };
        if let Ok(action) = serde_json::from_value::<DestroyAction>(raw_action.clone()) {
            let (resolved, resolution_failed) =
                match self.index.resolve(client, &args.cluster, args.vmid).await {
                    Ok(guest) => (Some(guest), false),
                    Err(_) => (None, true),
                };
            let protection = protection_of(client.cluster(), resolved.as_ref(), resolution_failed);
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_secs();
            // A waiver binds to the principal who planned the change set, not
            // whoever is approving it -- the two-person rule requires those
            // to be different callers. Evaluating this against the approver's
            // own token name meant any waiver naming a `principal` could
            // never be approved: the approver can never also be the planner.
            let override_ = destructive_allowed(
                &protection,
                &self.waivers,
                &args.cluster,
                args.vmid,
                now_unix,
                self.lab_mode,
                DestructiveAttempt {
                    op: &action.op,
                    principal: Some(record.owner.as_str()),
                },
            );
            let override_applies = !matches!(override_, Override::None);

            let authorized = match self
                .index
                .authorize(
                    client,
                    &args.cluster,
                    args.vmid,
                    &grant,
                    Intent::destructive(override_applies),
                )
                .await
            {
                Ok(authorized) => authorized,
                Err(error) => return tool_error(error),
            };
            let guest = authorized.guest();

            let Some(op_tool) = tool_for_op(&action.op, guest.r#type) else {
                return tool_error(format!(
                    "the change set names an unknown operation '{}'",
                    action.op
                ));
            };
            if let Err(error) =
                authorize_call(caller.as_ref(), op_tool, Some(&args.cluster), WRITE_TOOLS)
            {
                return tool_error(error);
            }

            if let Err(error) = require_unrestricted_scope_for_delete_iso(&action.op, &grant) {
                return tool_error(error);
            }
        } else {
            use restore_change_set::RestoreNewVmidAction;
            use rust_proxmoxmcp_core::grant::ProxmoxAction;
            use rust_proxmoxmcp_core::protect::creation_allowed;

            let action: RestoreNewVmidAction = match serde_json::from_value(raw_action.clone()) {
                Ok(action) => action,
                Err(error) => {
                    return tool_error(format!(
                        "the change set's action could not be read ({error}); \
                         it cannot be approved"
                    ));
                }
            };

            if let Err(error) = authorize_call(
                caller.as_ref(),
                "restore_backup_new_vmid",
                Some(&args.cluster),
                WRITE_TOOLS,
            ) {
                return tool_error(error);
            }
            if !grant.allows_action(ProxmoxAction::Destructive) {
                return tool_error(
                    "restoring into a new vmid requires the 'destructive' action tier, which \
                     this caller does not carry",
                );
            }
            if !grant.allows_new_vmid(action.target_vmid) {
                return tool_error(format!(
                    "vmid {} is outside this caller's guest scope, so a backup may not be \
                     restored into it",
                    action.target_vmid
                ));
            }
            if !creation_allowed(client.cluster(), action.target_vmid) {
                return tool_error(format!(
                    "vmid {} is a protected pin on cluster {} and must not receive a restore",
                    action.target_vmid, args.cluster
                ));
            }
            // The approver's authority over *this* vmid -- scope and
            // protection on the guest whose disks get copied, not just the
            // target vmid checked above. Without this an approver scoped
            // only to the target range, with no read into the owner guest at
            // all, could approve a copy out of a guest they otherwise could
            // never touch. Mirrors the re-check `apply_restore_new_vmid`
            // runs, so approve and apply hold the same standard.
            //
            // The waiver inside binds to the principal who planned the
            // restore, not the approver: the two-person rule requires those
            // to differ, so checking against the approver's own token name
            // would make a principal-bound waiver permanently unapprovable.
            if let Err(error) = self
                .authorize_backup_owner(
                    client,
                    &args.cluster,
                    action.owner_vmid,
                    &grant,
                    &action.volid,
                    Some(record.owner.as_str()),
                )
                .await
            {
                return tool_error(error);
            }
        }

        let output = match coordinator
            .approve_change_set(
                args.change_set_id.clone(),
                device.clone(),
                approver,
                record.digest.clone(),
                approver_actor_type,
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let msg = error.to_string();
                // Reword the self-approval error to match test expectations.
                if msg.contains("owner cannot approve their own") {
                    return tool_error(
                        "self-approval refused: the planner cannot approve their own change set",
                    );
                }
                return tool_error(format!("approve: {error}"));
            }
        };

        let preview_text = preview.artifact.clone();

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "apply_proxmox_change_set",
        description = "Apply an approved change set."
    )]
    async fn apply_change_set(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use rust_proxmoxmcp_core::{
            fingerprint::{GuestState, fingerprint},
            guests::fetch_guest_config_state,
            protect::{DestructiveAttempt, Override, destructive_allowed, protection_of},
        };

        let caller = Self::caller(&context);
        // The evidence records belong to *this* call, not to the change set.
        // `request_id` is the join key transport audit uses, so putting the
        // change-set id there makes two attempts indistinguishable and breaks
        // correlation with the tool call that actually did it. The principal is
        // the caller too: this handler lets a different scoped token apply a set
        // someone else planned, and naming the planner as executor is false.
        let apply_request_id = caller
            .as_ref()
            .map_or_else(|| "stdio".to_owned(), |ctx| ctx.request_id.to_string());
        let apply_principal = caller
            .as_ref()
            .map_or_else(|| "stdio".to_owned(), |ctx| ctx.token_name.clone());
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "apply_proxmox_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let coordinator = self.coordinator.clone();

        let device = format!("{}/{}", args.cluster, args.vmid);
        let mut record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        // Same invariant as `approve_change_set`, enforced again here because
        // approval and apply are separate tools with separate scopes: a record
        // approved by an older binary must still not execute without a preview.
        if record.preview.is_none() {
            return tool_error(
                "apply refused: this change set has no stored preview, so the action it \
                 would take was never recorded for review. Plan the operation again.",
            );
        }

        // Re-resolve and verify fingerprint.
        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        // Drop the cached `/cluster/resources` snapshot before re-resolving.
        //
        // The fingerprint re-check below exists to refuse an apply against a
        // guest that moved since the plan. `GuestIndex` caches that snapshot
        // for `resource_cache_ttl_secs`, so without this the plan and the
        // apply read the *same* cached response and the comparison could not
        // fail -- inside the TTL the whole check was a no-op, and a rename,
        // migration, status change or a newly added `protected` tag would all
        // compare equal.
        //
        // The existing test only caught a move because its harness invalidates
        // the cache itself; production never did. One extra fetch on a
        // destructive apply is not a cost worth trading this for.
        //
        // Scoped to this cluster: a global drop would evict still-valid
        // snapshots for every other cluster, and their next operation would
        // pay a fetch that can fail if that cluster is momentarily
        // unreachable. The generation bump inside is what stops a fetch that
        // started before this point from re-publishing pre-change state.
        self.index.invalidate_cluster(&args.cluster);

        // Resolve guest and compute protection to determine override. A
        // resolve failure is not surfaced directly -- `authorize` below
        // re-resolves and is what decides whether an absent guest and an
        // out-of-scope one get refused, with identical error text either way.
        let (resolved, resolution_failed) =
            match self.index.resolve(client, &args.cluster, args.vmid).await {
                Ok(guest) => (Some(guest), false),
                Err(_) => (None, true),
            };
        let protection = protection_of(client.cluster(), resolved.as_ref(), resolution_failed);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();

        // Peeked from the raw record rather than the typed `action` deserialized
        // below: the override check needs the op before dispatch decides whether
        // the action shape even deserializes, and a waiver must bind to the exact
        // op the approver signed, not a default. A record with no readable `op`
        // is refused outright rather than defaulting to any specific operation
        // string -- defaulting to, say, `"destroy_guest"` would let a waiver
        // scoped to `destroy_guest` admit an apply whose real operation is
        // unknown, which is the opposite of what a waiver's `ops` binding is
        // for. The digest binds the stored actions, so this is not reachable
        // today; refusing it keeps that true if the record shape ever changes.
        let Some(op_for_override) = record
            .actions
            .first()
            .and_then(|value| value.get("op"))
            .and_then(|value| value.as_str())
        else {
            return tool_error(
                "change set refused: its first action has no readable 'op' field, so no \
                 waiver can be bound to the operation it actually names. Plan the operation \
                 again.",
            );
        };

        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            &args.cluster,
            args.vmid,
            now_unix,
            self.lab_mode,
            DestructiveAttempt {
                op: op_for_override,
                principal: caller.as_ref().map(|ctx| ctx.token_name.as_str()),
            },
        );

        let override_applies = !matches!(override_, Override::None);

        // Now authorize with the override information.
        let authorized = match self
            .index
            .authorize(
                client,
                &args.cluster,
                args.vmid,
                &grant,
                Intent::destructive(override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return tool_error(error),
        };

        let guest = authorized.guest();

        // Same source as `plan_destroy`: the guest's own config, fetched
        // fresh, because this is precisely the check that must not compare a
        // cached read against itself.
        let config_state =
            match fetch_guest_config_state(client, &guest.node, guest.r#type, guest.vmid).await {
                Ok(state) => state,
                Err(error) => return tool_error(format!("reading guest config: {error}")),
            };

        let state = GuestState {
            cluster: args.cluster.clone(),
            vmid: guest.vmid,
            name: guest.name.clone(),
            kind: guest.r#type.path_segment().to_owned(),
            node: guest.node.clone(),
            status: guest.status.clone(),
            tags: guest.tags.clone(),
            config_digest: config_state.config_digest,
            disks: config_state.disks,
        };

        let current_fingerprint = fingerprint(&state);

        if current_fingerprint != record.expected_candidate_fingerprint {
            return tool_error(format!(
                "fingerprint changed (expected {}, got {})",
                record.expected_candidate_fingerprint, current_fingerprint
            ));
        }

        // Verify the change set is approved.
        if record.state != mecmcp_changeset::ChangeSetState::Approved {
            return tool_error(format!(
                "change set not approved (state: {:?})",
                record.state
            ));
        }

        // Dispatch on the action the change set recorded, not on the tool
        // name. The digest covers `actions`, so this is the only description of
        // the work that the approver actually signed; reading the operation
        // from anywhere else would let an apply do something the approval did
        // not cover.
        let action: change_set::DestroyAction = match record.actions.first() {
            Some(value) => match serde_json::from_value(value.clone()) {
                Ok(action) => action,
                Err(error) => {
                    return tool_error(format!(
                        "the change set's action could not be read ({error}); \
                         it cannot be applied"
                    ));
                }
            },
            None => return tool_error("the change set records no action".to_owned()),
        };

        // Again at apply. A scope can be narrowed between plan and apply, and
        // the apply is the call that acts — checking only at plan would let a
        // token whose authority was revoked still execute what it had planned.
        let Some(op_tool) = tool_for_op(&action.op, guest.r#type) else {
            return tool_error(format!(
                "the change set names an unknown operation '{}'",
                action.op
            ));
        };
        if let Err(error) =
            authorize_call(caller.as_ref(), op_tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return authz_tool_error(error);
        }

        if let Err(error) = require_unrestricted_scope_for_delete_iso(&action.op, &grant) {
            return tool_error(error);
        }

        // Defense-in-depth: validate volid content kind again at apply time,
        // BEFORE the apply-intent evidence write. Plan-time validation is the
        // primary gate, but this catches any change-set record that bypassed it
        // (imported, manually crafted, or created before the fix shipped).
        // Returned via tool_error so this failure is definitive and writes a
        // failure receipt, rather than being classified as indeterminate and
        // leaving the chain at intent with no outcome.
        // An incomplete record is refused here rather than inside
        // `execute_destructive`, which reports a missing field as `Malformed`
        // -- non-definitive, so it would write apply intent and then emit no
        // outcome at all. Refusing before the intent write keeps the failure
        // definitive and the trail honest. It also means the volid checks below
        // cannot be silently skipped by an action that simply omits the fields
        // they read.
        let absent = missing_required_fields(&action);
        if !absent.is_empty() {
            return tool_error(format!(
                "the change set records a '{}' action without {}; it cannot be applied. \
                 This action predates the field being required, or was imported. \
                 Plan the operation again with plan_proxmox_destroy and have the new \
                 change set approved -- the incomplete record stays approved but \
                 unapplied, and nothing was sent to the cluster.",
                action.op,
                absent.join(", ")
            ));
        }

        match action.op.as_str() {
            "delete_backup" | "delete_iso" => {
                // Guaranteed present by the check above; matched rather than
                // unwrapped so a future edit to that check cannot panic here.
                let (Some(volid), Some(storage)) = (&action.volid, &action.storage) else {
                    return tool_error(format!(
                        "'{}' passed the required-field check without volid and storage",
                        action.op
                    ));
                };
                let expected_kind = match action.op.as_str() {
                    "delete_backup" => "backup",
                    "delete_iso" => "iso",
                    _ => unreachable!(),
                };
                if let Err(error) = rust_proxmoxmcp_core::guests::validate_volid_for_operation(
                    volid,
                    storage,
                    expected_kind,
                ) {
                    return tool_error(format!("volid validation failed at apply: {error}"));
                }
            }
            "restore_backup" => {
                let Some(volid) = &action.volid else {
                    return tool_error(format!(
                        "'{}' passed the required-field check without volid",
                        action.op
                    ));
                };
                if let Err(error) =
                    rust_proxmoxmcp_core::guests::validate_volid_kind(volid, "backup")
                {
                    return tool_error(format!("volid validation failed at apply: {error}"));
                }
            }
            "update_vm_config" => {
                // Defense-in-depth, same reasoning as the volid re-checks
                // above: plan-time validation is the primary gate, but this
                // catches any record that bypassed it (imported, hand-crafted,
                // or planned before this check existed).
                if let Some(config) = &action.config
                    && let Some(message) = reject_unsafe_vm_config(config)
                {
                    return tool_error(format!("config validation failed at apply: {message}"));
                }
            }
            _ => {} // Other operations don't use volids
        }

        // Re-check the path-segment fields, for the same reason the volids
        // above are re-checked: a change set approved by the previous release
        // was planned before that validation existed, so it can still carry a
        // snapshot named `a/b` or a storage node of `..`. `expand_path` would
        // refuse it inside `execute_destructive`, after the claim below has
        // already moved the record to `Applying` -- and a local refusal is
        // indistinguishable there from an unparseable response, so the record
        // would stay claimed and block this guest with nothing having been sent.
        // Checked here, before the claim, the change set is simply refused.
        for (field, value) in [
            ("snapname", action.snapname.as_deref()),
            ("storage", action.storage.as_deref()),
            ("storage_node", action.storage_node.as_deref()),
        ] {
            let Some(value) = value else { continue };
            if let Err(error) = rust_proxmoxmcp_core::guests::validate_path_segment(value, field) {
                return tool_error(format!(
                    "apply refused: {error}. This change set was planned before that check \
                     existed; plan the operation again."
                ));
            }
        }

        // Spend the approval BEFORE anything reaches the cluster.
        //
        // mecmcp 0.22.0 makes `claim_change_set_for_apply` the only legal
        // `Approved -> Applying` transition, and it performs that read and
        // write under one lock. Two concurrent applies can no longer both read
        // `Approved` and both issue a destroy: the second loses the claim and
        // is refused here, before `execute_destructive`.
        //
        // `None` for every operation, including the ones that do answer with a
        // UPID.
        //
        // The claim necessarily happens before the request, so there is a
        // window where the DELETE has been accepted but its UPID has not yet
        // been persisted. A record claimed as `Expected` sits in that window as
        // `Applying` with no `task_id` and `apply_without_handle = false`,
        // which is exactly the combination `ChangesetCoordinator` converts to
        // `Failed` at startup -- asserting that a destroy which may well have
        // succeeded did not. `delete_backup` and `delete_iso` have no handle at
        // all, since `delete_volume` answers synchronously on some storage
        // types.
        //
        // Handleless keeps the record `Applying` instead: detectable, not
        // recoverable, and a human goes and looks. Once the UPID is stored the
        // record carries a real handle, which recovery re-probes rather than
        // settling, so the marker costs nothing after that point.

        // Claimed before the apply-intent record is written, so evidence is
        // only ever emitted by the caller that actually holds the approval. If
        // the intent were written first, two callers racing here would both
        // durably record that execution began while only one could proceed,
        // leaving a receipt-less intent for the loser.
        //
        // Nothing has been sent at this point, so a refusal is safe to report
        // as such -- the guest is untouched.
        record = match self
            .coordinator
            .claim_change_set_for_apply(
                &record.id,
                &record.device,
                mecmcp_changeset::ApplyHandle::None,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                return tool_error(format!(
                    "apply refused: the change set could not be claimed for apply ({error}).                      Another apply may already hold it. Nothing was sent to the cluster."
                ));
            }
        };

        // A guest is about to be destroyed. This is written -- and, with a spool
        // attached, persisted -- *before* the DELETE goes out, and refused if it
        // cannot be. The apply path does not go through `commit_operation`, so
        // nothing else emits it: without this, an approved destroy completes
        // with proposal and approval on the record and no execution evidence at
        // all. A guest destroyed with no record that anyone tried is the exact
        // state this chain exists to rule out, and `purge` makes it permanent.
        if let Some(recorder) = &self.evidence
            && let Err(error) = recorder.apply_intent(
                &apply_request_id,
                &record.id,
                &record.device,
                &apply_principal,
            )
        {
            // The claim above already moved this out of `Approved`, so it
            // cannot honestly be described as retriable while it sits in
            // `Applying`. Settle it before returning: nothing was sent, so
            // `Failed` is the accurate outcome and it frees the operator to
            // plan again.
            let mut abandoned = record.clone();
            abandoned.state = mecmcp_changeset::ChangeSetState::Failed;
            // Report the settlement that actually happened. If this write fails
            // too, `update_change_set` rolls back and the record is still
            // `Applying`; telling the caller to plan again would be wrong,
            // because the claim is still held and a new plan stays blocked.
            let settled = self.coordinator.update_change_set(abandoned).await;
            if let Err(settle_error) = &settled {
                tracing::error!(
                    target: "audit",
                    %settle_error,
                    change_set = %record.id,
                    "claimed change set left in Applying after the intent record failed"
                );
            }
            return tool_error(match settled {
                Ok(()) => format!(
                    "destroy refused: the apply-intent evidence record could not be persisted \
                     ({error}); nothing was sent to the cluster and the change set is now \
                     failed -- plan the operation again"
                ),
                Err(settle_error) => format!(
                    "destroy refused: the apply-intent evidence record could not be persisted \
                     ({error}), and the change set could not then be settled \
                     ({settle_error}). Nothing was sent to the cluster, but the record is \
                     still claimed and reads as applying -- it needs an operator before \
                     this guest can be planned again"
                ),
            });
        }

        let upid_str = match self
            .execute_destructive(client, &action, guest.r#type, &state.node, args.vmid)
            .await
        {
            Ok(upid) => upid,
            Err(error) => {
                // Proxmox answering "no" and the request vanishing are different
                // facts, and the receipt must not conflate them. An `Api`,
                // `Unauthorized`, `Denied` or `NotFound` means the server
                // answered and refused: definitive, and the trail should say so
                // rather than end at an intent with no outcome. A transport
                // failure or an unparseable response means the DELETE may have
                // been accepted -- recording that as a failure would state the
                // guest still exists when it may not, so the chain is left at
                // apply intent, which is what "go and look" looks like here.
                let definitive = matches!(
                    error,
                    rust_proxmoxmcp_core::ProxmoxError::Api { .. }
                        | rust_proxmoxmcp_core::ProxmoxError::Unauthorized
                        | rust_proxmoxmcp_core::ProxmoxError::Denied(_)
                        | rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }
                );
                if definitive {
                    if let Some(recorder) = &self.evidence
                        && let Err(receipt_error) = recorder.result_receipt(
                            &apply_request_id,
                            &record.id,
                            &record.device,
                            &apply_principal,
                            false,
                            &error.to_string(),
                        )
                    {
                        tracing::error!(%receipt_error, "failure receipt not persisted");
                    }
                    record.state = mecmcp_changeset::ChangeSetState::Failed;
                    let _ = self.coordinator.update_change_set(record).await;
                } else {
                    tracing::error!(
                        %error,
                        "the destroy failed without a definitive answer; the outcome is \
                         indeterminate and no result receipt is emitted"
                    );
                }
                return tool_error(error);
            }
        };

        // A storage that deleted synchronously returns no handle. That is a
        // completed operation, not a failure — parsing the empty string as a
        // UPID would report an error for a volume that is already gone, write
        // no success receipt, and leave the record `Approved` and retryable
        // against a volume that no longer exists.
        if upid_str.is_empty() {
            if let Some(recorder) = &self.evidence
                && let Err(receipt_error) = recorder.result_receipt(
                    &apply_request_id,
                    &record.id,
                    &record.device,
                    &apply_principal,
                    true,
                    "",
                )
            {
                tracing::error!(
                    %receipt_error,
                    change_set_id = %record.id,
                    "the operation completed but its result receipt could not be persisted"
                );
            }

            record.state = mecmcp_changeset::ChangeSetState::Applied;
            record.task_id = None;
            if let Err(error) = self.coordinator.update_change_set(record).await {
                tracing::error!(%error, "could not mark the change set applied");
            }

            return tool_result::<_, String>(
                Ok(serde_json::json!({
                    "outcome": "ok",
                    "synchronous": true,
                    "upid": serde_json::Value::Null,
                })),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }

        // Parse the UPID to extract the node for polling.
        // Per spec §7, the node is authoritative: guests migrate, so we must
        // poll the node from the UPID, never a caller-supplied one.
        let upid = match rust_proxmoxmcp_core::task::Upid::parse(&upid_str) {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        // Persist the UPID BEFORE polling (spec §8).
        //
        // The window this closes is between Proxmox accepting the operation and
        // this process observing its result. A crash in that window used to
        // leave the record in `Applying` with nothing recorded about which
        // vendor operation to ask after — detectable, but resolvable only by a
        // human reading the device. With the handle on disk, `recover_in_flight`
        // can re-probe it at startup.
        //
        // A failure to persist is logged rather than fatal: the destructive
        // operation has already been accepted by Proxmox, so refusing here
        // would abandon a running task *and* report failure for something that
        // is going to happen anyway. Losing the handle is worse than the write
        // failing quietly, so it is said loudly instead.
        {
            let mut in_flight = record.clone();
            // Already `Applying` -- the claim above moved it there before the
            // destroy was issued, which is what keeps the approval from being
            // spent twice. This write only attaches the handle, so it is an
            // `Applying -> Applying` field update. `recover_in_flight` looks
            // for `Applying` plus a handle, and both are now on disk.
            in_flight.task_id = Some(upid_str.clone());
            if let Err(error) = self.coordinator.update_change_set(in_flight).await {
                tracing::error!(
                    target: "audit",
                    %error,
                    change_set = %record.id,
                    upid = %upid_str,
                    "task handle not persisted; a crash now leaves this apply unrecoverable"
                );
            }
        }

        // Poll the task to completion.
        let exitstatus = match poll_proxmox_task(client, upid.node(), &upid_str).await {
            Ok(exitstatus) => exitstatus,
            Err(result) => return *result,
        };

        // Classify the exit status using the Task 3 classifier.
        let outcome = rust_proxmoxmcp_core::task::classify_exit_status(&exitstatus);

        // Proxmox answered. A failure is recorded as fully as a success -- a
        // trail that only shows what worked cannot answer the question anyone
        // asks it. This cannot fail closed: the guest is already gone.
        if let Some(recorder) = &self.evidence {
            let succeeded = matches!(outcome, rust_proxmoxmcp_core::task::TaskOutcome::Ok);
            if let Err(error) = recorder.result_receipt(
                &apply_request_id,
                &record.id,
                &record.device,
                &apply_principal,
                succeeded,
                if succeeded { "" } else { &exitstatus },
            ) {
                tracing::error!(
                    %error,
                    change_set_id = %record.id,
                    "the destroy completed but its result receipt could not be persisted; \
                     the evidence chain ends at apply intent"
                );
            }
        }

        match outcome {
            rust_proxmoxmcp_core::task::TaskOutcome::Ok => {
                record.state = mecmcp_changeset::ChangeSetState::Applied;
                // The outcome is known, so the handle has nothing left to
                // recover. Leaving it set would make a finished apply look
                // in-flight to `recover_in_flight` on the next start.
                record.task_id = None;
                if let Err(error) = self.coordinator.update_change_set(record).await {
                    tracing::error!(%error, "could not mark the change set applied");
                }
                let response = serde_json::json!({
                    "outcome": "ok",
                    "upid": upid_str,
                    "exitstatus": exitstatus,
                });
                tool_result(
                    Ok::<_, String>(response),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                )
            }
            rust_proxmoxmcp_core::task::TaskOutcome::Failed(message) => {
                // Finalise the set. `result_receipt` is terminal -- it forgets
                // the change's proposal context -- so leaving this `Approved`
                // invites a retry whose intent and receipt would carry an empty
                // digest and principal, which is worse than refusing the retry.
                // A fresh plan is the correct path after a failed destroy.
                record.state = mecmcp_changeset::ChangeSetState::Failed;
                record.task_id = None;
                if let Err(error) = self.coordinator.update_change_set(record).await {
                    tracing::error!(%error, "could not mark the change set failed");
                }
                tool_error(format!("task failed: {message}"))
            }
        }
    }

    #[tool(
        name = "plan_ha_rule_change",
        description = "Plan an HA rule create, update or delete for two-principal approval."
    )]
    async fn plan_ha_rule_change(
        &self,
        Parameters(args): Parameters<ha_change_set::PlanHaRuleArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;
        use ha_change_set::{
            build_ha_rule_action, ha_rule_device, render_ha_rule_preview, tool_for_ha_op,
        };

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "plan_ha_rule_change",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let action = match build_ha_rule_action(&args) {
            Ok(action) => action,
            Err(error) => return tool_error(error),
        };

        // The operation's own tool scope, on top of `plan_ha_rule_change`. Same
        // reasoning as `tool_for_op`: without this, a token allowlisted only
        // for the generic plan/apply handlers could select any operation.
        let Some(op_tool) = tool_for_ha_op(&action.op) else {
            return tool_error(format!("unknown HA rule operation '{}'", action.op));
        };
        if let Err(error) =
            authorize_call(caller.as_ref(), op_tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return authz_tool_error(error);
        }

        // Refused here, before `fetch_rule`: a token missing the
        // `destructive` tier is refused outright, so no request should reach
        // the cluster on its behalf at all.
        if let Err(result) = require_ha_rule_destructive_tier(caller.as_ref()) {
            return *result;
        }

        let existing = match rust_proxmoxmcp_core::ha_rules::fetch_rule(client, &args.rule).await {
            Ok(existing) => existing,
            Err(error) => return tool_error(format!("reading current rule: {error}")),
        };

        // Refuse a plan Proxmox would refuse anyway, before an approval is
        // spent on it -- the same reasoning as the stopped-guest check on a
        // destroy plan.
        match (action.op.as_str(), existing.is_some()) {
            ("create", true) => {
                return tool_error(format!(
                    "rule '{}' already exists; plan an update instead",
                    args.rule
                ));
            }
            ("update" | "delete", false) => {
                return tool_error(format!(
                    "rule '{}' does not exist; nothing to {}",
                    args.rule, action.op
                ));
            }
            _ => {}
        }

        // Every guest the rule names -- in the requested change and in the
        // rule as it stands -- must be one this token may act on
        // destructively, and must not be protected without an override. A
        // node-affinity or resource-affinity rule makes the HA manager move those guests,
        // so it gets the same guest-scope and protection gate a
        // `plan_proxmox_destroy` of each of them would.
        if let Err(result) = self
            .authorize_ha_rule_guests(
                client,
                &args.cluster,
                caller.as_ref(),
                &action,
                existing.as_ref(),
            )
            .await
        {
            return *result;
        }

        let expected_fingerprint = rust_proxmoxmcp_core::fingerprint::ha_rule_fingerprint(
            &args.cluster,
            &args.rule,
            existing.as_ref(),
        );
        // The preview reaches the model and the change-set store, so the
        // rule's free-text fields get the same redaction a `get_ha_rule` read
        // does. The fingerprint above stays over the raw rule.
        let redacted_existing = existing.clone().map(|mut value| {
            redact_free_text_fields(&mut value);
            value
        });
        let preview_text = render_ha_rule_preview(&action, redacted_existing.as_ref());

        let coordinator = self.coordinator.clone();
        let owner = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());
        let device = ha_rule_device(&args.cluster, &args.rule);
        let policy_signature = "proxmox-no-policy-engine";

        let output = match coordinator
            .create_change_set(
                device,
                vec![action],
                owner,
                expected_fingerprint.clone(),
                policy_signature.to_owned(),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return tool_error(format!("create: {error}")),
        };

        // Persist the preview, as `plan_destroy` does -- see its comment for
        // why this is a second write rather than part of `create_change_set`.
        let Some(mut with_preview) = coordinator
            .change_sets()
            .await
            .into_iter()
            .find(|record| record.id == output.change_set_id)
        else {
            tracing::error!(
                change_set = %output.change_set_id,
                "the change set could not be read back; the plan is refused"
            );
            return tool_error(
                "plan refused: the change set could not be read back to store its \
                 preview. It has no preview, so approve and apply will refuse it. \
                 Plan the operation again.",
            );
        };

        with_preview.preview = Some(mecmcp_changeset::PreviewRecord {
            digest: mecmcp_changeset::preview_digest(&preview_text),
            artifact: preview_text.clone(),
            job_id: None,
        });
        if let Err(error) = coordinator.update_change_set(with_preview).await {
            tracing::error!(
                %error,
                change_set = %output.change_set_id,
                "the preview could not be persisted; the plan is refused"
            );
            return tool_error(format!(
                "plan refused: the preview could not be persisted ({error}). The \
                 change set has no stored preview, so approve and apply will refuse \
                 it. Plan the operation again."
            ));
        }

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "get_ha_rule_change_set",
        description = "Retrieve the current state of an HA rule change set."
    )]
    async fn get_ha_rule_change_set(
        &self,
        Parameters(args): Parameters<ha_change_set::HaChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_ha_rule_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        // The preview below names the rule's guests, which are not filtered
        // by the caller's guest scope -- same reasoning as `list_ha_rules`
        // and `get_ha_rule`. A narrowed token must not read a change set it
        // did not create just because it knows the id.
        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };
        if !grant.is_unrestricted_guest_scope() {
            return tool_error(
                "get_ha_rule_change_set is not scoped to any single guest -- its preview names \
                 the rule's guests -- so it requires a caller whose guest scope is '*'. This \
                 caller is narrowed to specific guests and cannot be checked against it."
                    .to_owned(),
            );
        }

        let coordinator = self.coordinator.clone();
        let device = ha_change_set::ha_rule_device(&args.cluster, &args.rule);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        let preview_text = record
            .preview
            .as_ref()
            .map(|p| p.artifact.clone())
            .unwrap_or_else(|| "(no preview)".to_owned());

        let response = ChangeSetResponse {
            change_set_id: record.id,
            state: format!("{:?}", record.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(record.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "approve_ha_rule_change",
        description = "Approve a planned HA rule change set as a second principal."
    )]
    async fn approve_ha_rule_change(
        &self,
        Parameters(args): Parameters<ha_change_set::HaChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "approve_ha_rule_change",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let approver = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());
        // Same as `approve_change_set`: the actor type comes from the caller's
        // verified token entry, and anything but `Human` is refused by mecmcp.
        let approver_actor_type = change_set::actor_type(caller.as_ref());

        let coordinator = self.coordinator.clone();
        let device = ha_change_set::ha_rule_device(&args.cluster, &args.rule);
        let record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        let Some(preview) = record.preview.as_ref() else {
            return tool_error(
                "approval refused: this change set has no stored preview, so there is \
                 nothing to review. Plan the operation again.",
            );
        };

        let output = match coordinator
            .approve_change_set(
                args.change_set_id.clone(),
                device,
                approver,
                record.digest.clone(),
                approver_actor_type,
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let msg = error.to_string();
                if msg.contains("owner cannot approve their own") {
                    return tool_error(
                        "self-approval refused: the planner cannot approve their own change set",
                    );
                }
                return tool_error(format!("approve: {error}"));
            }
        };

        let preview_text = preview.artifact.clone();

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "apply_ha_rule_change",
        description = "Apply an approved HA rule change set."
    )]
    async fn apply_ha_rule_change(
        &self,
        Parameters(args): Parameters<ha_change_set::HaChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use ha_change_set::{HaRuleAction, missing_required_ha_fields, tool_for_ha_op};

        let caller = Self::caller(&context);
        let apply_request_id = caller
            .as_ref()
            .map_or_else(|| "stdio".to_owned(), |ctx| ctx.request_id.to_string());
        let apply_principal = caller
            .as_ref()
            .map_or_else(|| "stdio".to_owned(), |ctx| ctx.token_name.clone());
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "apply_ha_rule_change",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let coordinator = self.coordinator.clone();
        let device = ha_change_set::ha_rule_device(&args.cluster, &args.rule);
        let mut record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        if record.preview.is_none() {
            return tool_error(
                "apply refused: this change set has no stored preview, so the action it \
                 would take was never recorded for review. Plan the operation again.",
            );
        }

        // Refused here, before `fetch_rule`: same reasoning as the plan
        // handler's early check -- a token missing the `destructive` tier
        // must not cause a request to reach the cluster at all.
        if let Err(result) = require_ha_rule_destructive_tier(caller.as_ref()) {
            return *result;
        }

        // Re-fetch the rule's current state and verify the fingerprint, the
        // same drift check `apply_change_set` runs against a guest.
        let existing = match rust_proxmoxmcp_core::ha_rules::fetch_rule(client, &args.rule).await {
            Ok(existing) => existing,
            Err(error) => return tool_error(format!("reading current rule: {error}")),
        };
        let current_fingerprint = rust_proxmoxmcp_core::fingerprint::ha_rule_fingerprint(
            &args.cluster,
            &args.rule,
            existing.as_ref(),
        );
        if current_fingerprint != record.expected_candidate_fingerprint {
            return tool_error(format!(
                "fingerprint changed (expected {}, got {})",
                record.expected_candidate_fingerprint, current_fingerprint
            ));
        }

        if record.state != mecmcp_changeset::ChangeSetState::Approved {
            return tool_error(format!(
                "change set not approved (state: {:?})",
                record.state
            ));
        }

        let action: HaRuleAction = match record.actions.first() {
            Some(value) => match serde_json::from_value(value.clone()) {
                Ok(action) => action,
                Err(error) => {
                    return tool_error(format!(
                        "the change set's action could not be read ({error}); \
                         it cannot be applied"
                    ));
                }
            },
            None => return tool_error("the change set records no action".to_owned()),
        };

        let Some(op_tool) = tool_for_ha_op(&action.op) else {
            return tool_error(format!(
                "the change set names an unknown operation '{}'",
                action.op
            ));
        };
        if let Err(error) =
            authorize_call(caller.as_ref(), op_tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return authz_tool_error(error);
        }

        let absent = missing_required_ha_fields(&action);
        if !absent.is_empty() {
            return tool_error(format!(
                "the change set records a '{}' action without {}; it cannot be applied. \
                 Plan the operation again with plan_ha_rule_change and have the new \
                 change set approved -- nothing was sent to the cluster.",
                action.op,
                absent.join(", ")
            ));
        }

        // Again at apply, against the rule as it stands now: a grant can be
        // narrowed, or a guest tagged `protected`, between plan and apply,
        // and the apply is the call that acts.
        if let Err(result) = self
            .authorize_ha_rule_guests(
                client,
                &args.cluster,
                caller.as_ref(),
                &action,
                existing.as_ref(),
            )
            .await
        {
            return *result;
        }

        // Spend the approval before anything reaches the cluster, and claim
        // with `ApplyHandle::None`: an HA rule write answers synchronously,
        // so there is never a vendor task to attach.
        record = match coordinator
            .claim_change_set_for_apply(
                &record.id,
                &record.device,
                mecmcp_changeset::ApplyHandle::None,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                return tool_error(format!(
                    "apply refused: the change set could not be claimed for apply ({error}). \
                     Another apply may already hold it. Nothing was sent to the cluster."
                ));
            }
        };

        if let Some(recorder) = &self.evidence
            && let Err(error) = recorder.apply_intent(
                &apply_request_id,
                &record.id,
                &record.device,
                &apply_principal,
            )
        {
            let mut abandoned = record.clone();
            abandoned.state = mecmcp_changeset::ChangeSetState::Failed;
            let settled = coordinator.update_change_set(abandoned).await;
            if let Err(settle_error) = &settled {
                tracing::error!(
                    target: "audit",
                    %settle_error,
                    change_set = %record.id,
                    "claimed change set left in Applying after the intent record failed"
                );
            }
            return tool_error(match settled {
                Ok(()) => format!(
                    "apply refused: the apply-intent evidence record could not be persisted \
                     ({error}); nothing was sent to the cluster and the change set is now \
                     failed -- plan the operation again"
                ),
                Err(settle_error) => format!(
                    "apply refused: the apply-intent evidence record could not be persisted \
                     ({error}), and the change set could not then be settled \
                     ({settle_error}). Nothing was sent to the cluster, but the record is \
                     still claimed and reads as applying -- it needs an operator before \
                     this rule can be planned again"
                ),
            });
        }

        let result = match action.op.as_str() {
            "create" => {
                let fields = rust_proxmoxmcp_core::ha_rules::HaRuleFields {
                    rule_type: action.rule_type.as_deref().unwrap_or_default(),
                    resources: action.resources.as_deref().unwrap_or_default(),
                    nodes: action.nodes.as_deref(),
                    affinity: action.affinity.as_deref(),
                    strict: action.strict,
                    comment: action.comment.as_deref(),
                    disable: action.disable,
                };
                rust_proxmoxmcp_core::ha_rules::create_rule(client, &action.rule, &fields).await
            }
            "update" => {
                let digest = existing
                    .as_ref()
                    .and_then(|value| value.get("digest"))
                    .and_then(|value| value.as_str());
                let empty_resources: Vec<String> = Vec::new();
                let fields = rust_proxmoxmcp_core::ha_rules::HaRuleFields {
                    rule_type: "",
                    resources: action.resources.as_deref().unwrap_or(&empty_resources),
                    nodes: action.nodes.as_deref(),
                    affinity: action.affinity.as_deref(),
                    strict: action.strict,
                    comment: action.comment.as_deref(),
                    disable: action.disable,
                };
                rust_proxmoxmcp_core::ha_rules::update_rule(client, &action.rule, &fields, digest)
                    .await
            }
            "delete" => rust_proxmoxmcp_core::ha_rules::delete_rule(client, &action.rule).await,
            other => Err(rust_proxmoxmcp_core::ProxmoxError::Malformed(format!(
                "unknown HA rule operation '{other}'"
            ))),
        };

        match result {
            Ok(()) => {
                if let Some(recorder) = &self.evidence
                    && let Err(receipt_error) = recorder.result_receipt(
                        &apply_request_id,
                        &record.id,
                        &record.device,
                        &apply_principal,
                        true,
                        "",
                    )
                {
                    tracing::error!(
                        %receipt_error,
                        change_set_id = %record.id,
                        "the operation completed but its result receipt could not be persisted"
                    );
                }

                record.state = mecmcp_changeset::ChangeSetState::Applied;
                record.task_id = None;
                if let Err(error) = coordinator.update_change_set(record).await {
                    tracing::error!(%error, "could not mark the change set applied");
                }

                tool_result::<_, String>(
                    Ok(serde_json::json!({ "outcome": "ok" })),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                )
            }
            Err(error) => {
                // Same distinction `apply_change_set` draws: the cluster
                // answering "no" and the request vanishing are different
                // facts, and only the first is safe to record as a failure.
                let definitive = matches!(
                    error,
                    rust_proxmoxmcp_core::ProxmoxError::Api { .. }
                        | rust_proxmoxmcp_core::ProxmoxError::Unauthorized
                        | rust_proxmoxmcp_core::ProxmoxError::Denied(_)
                        | rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }
                );
                if definitive {
                    if let Some(recorder) = &self.evidence
                        && let Err(receipt_error) = recorder.result_receipt(
                            &apply_request_id,
                            &record.id,
                            &record.device,
                            &apply_principal,
                            false,
                            &error.to_string(),
                        )
                    {
                        tracing::error!(%receipt_error, "failure receipt not persisted");
                    }
                    record.state = mecmcp_changeset::ChangeSetState::Failed;
                    let _ = coordinator.update_change_set(record).await;
                } else {
                    tracing::error!(
                        %error,
                        "the HA rule write failed without a definitive answer; the outcome \
                         is indeterminate and no result receipt is emitted"
                    );
                }
                tool_error(error)
            }
        }
    }

    #[tool(
        name = "plan_restore_new_vmid",
        description = "Plan restoring a backup archive into a new VMID, for two-principal approval."
    )]
    async fn plan_restore_new_vmid(
        &self,
        Parameters(args): Parameters<restore_change_set::PlanRestoreNewVmidArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;
        use restore_change_set::{build_restore_new_vmid_action, render_restore_new_vmid_preview};
        use rust_proxmoxmcp_core::grant::ProxmoxAction;
        use rust_proxmoxmcp_core::protect::creation_allowed;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "plan_restore_new_vmid",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }
        // The operation's own tool scope, on top of `plan_restore_new_vmid`.
        // Same reasoning as `tool_for_op`: without this, a token allowlisted
        // only for the generic plan handler could restore into a new vmid
        // regardless of whether it was separately granted that.
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "restore_backup_new_vmid",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        if !grant.allows_action(ProxmoxAction::Destructive) {
            return tool_error(
                "restoring into a new vmid requires the 'destructive' action tier, which this \
                 caller does not carry",
            );
        }

        // Checked before any network call: an iso or template volid is not a
        // backup archive and resolving its "owner" against a backup content
        // listing would produce a confusing not-found rather than this clear
        // refusal. `build_restore_new_vmid_action` re-validates this, but
        // that happens after owner resolution below, which needs to know
        // this is a backup volid first.
        if let Err(error) = rust_proxmoxmcp_core::guests::validate_volid_kind(&args.volid, "backup")
        {
            return tool_error(error.to_string());
        }

        // Resolve the archive's real owner from Proxmox's own storage content
        // listing, before this plan's identity even exists. The volid's
        // filename conventionally names a vmid, but that is a convention a
        // caller can type, not a binding the server checked -- without this,
        // a token scoped to its own vmid range could copy another guest's
        // disks into a vmid it controls merely by naming that guest's
        // archive.
        let owner_vmid = match rust_proxmoxmcp_core::guests::resolve_backup_owner(
            client,
            &args.node,
            &args.volid,
        )
        .await
        {
            Ok(owner_vmid) => owner_vmid,
            Err(error) => {
                return tool_error(format!(
                    "could not establish which guest owns backup archive '{}': {error}. \
                     Refusing rather than trusting the archive's filename.",
                    args.volid
                ));
            }
        };

        if let Err(error) = self
            .authorize_backup_owner(
                client,
                &args.cluster,
                owner_vmid,
                &grant,
                &args.volid,
                caller.as_ref().map(|ctx| ctx.token_name.as_str()),
            )
            .await
        {
            return tool_error(error);
        }

        let action = match build_restore_new_vmid_action(&args, owner_vmid) {
            Ok(action) => action,
            Err(error) => return tool_error(error),
        };

        // The destination vmid has to be inside the token's guest scope.
        // Nothing else looks at it, because there is no source guest whose
        // scope could stand in -- the same reasoning `authorize_creation`
        // documents for `create_vm`/`create_container`.
        if !grant.allows_new_vmid(action.target_vmid) {
            return tool_error(format!(
                "vmid {} is outside this caller's guest scope, so a backup may not be restored \
                 into it",
                action.target_vmid
            ));
        }

        if !creation_allowed(client.cluster(), action.target_vmid) {
            return tool_error(format!(
                "vmid {} is a protected pin on cluster {} and must not receive a restore",
                action.target_vmid, args.cluster
            ));
        }

        // The destination vmid must be free. Checked here, before any
        // approval is spent, rather than discovered at apply: a second
        // principal approving a plan that can never succeed wastes their
        // approval on nothing. Mirrors `authorize_creation`'s existence check
        // for `create_vm`/`create_container`.
        self.index.invalidate_cluster(&args.cluster);
        match self
            .index
            .resolve(client, &args.cluster, action.target_vmid)
            .await
        {
            Ok(existing) => {
                return tool_error(format!(
                    "vmid {} already exists on cluster {} as '{}' -- restoring into it would \
                     overwrite an existing guest. Use restore_backup for a same-vmid restore, \
                     or choose a free vmid.",
                    action.target_vmid, args.cluster, existing.name
                ));
            }
            Err(rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }) => {}
            Err(error) => {
                return tool_error(format!(
                    "could not establish whether vmid {} is free on cluster {}: {error}",
                    action.target_vmid, args.cluster
                ));
            }
        }

        let expected_fingerprint = rust_proxmoxmcp_core::fingerprint::restore_target_fingerprint(
            &args.cluster,
            action.target_vmid,
        );
        let preview_text = render_restore_new_vmid_preview(&action);

        let coordinator = self.coordinator.clone();
        let owner = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());
        let device = format!("{}/{}", args.cluster, action.target_vmid);
        let policy_signature = "proxmox-no-policy-engine";

        let output = match coordinator
            .create_change_set(
                device,
                vec![action],
                owner,
                expected_fingerprint.clone(),
                policy_signature.to_owned(),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return tool_error(format!("create: {error}")),
        };

        // Persist the preview, as `plan_destroy` does -- see its comment for
        // why this is a second write rather than part of `create_change_set`.
        let Some(mut with_preview) = coordinator
            .change_sets()
            .await
            .into_iter()
            .find(|record| record.id == output.change_set_id)
        else {
            tracing::error!(
                change_set = %output.change_set_id,
                "the change set could not be read back; the plan is refused"
            );
            return tool_error(
                "plan refused: the change set could not be read back to store its \
                 preview. It has no preview, so approve and apply will refuse it. \
                 Plan the operation again.",
            );
        };

        with_preview.preview = Some(mecmcp_changeset::PreviewRecord {
            digest: mecmcp_changeset::preview_digest(&preview_text),
            artifact: preview_text.clone(),
            job_id: None,
        });
        if let Err(error) = coordinator.update_change_set(with_preview).await {
            tracing::error!(
                %error,
                change_set = %output.change_set_id,
                "the preview could not be persisted; the plan is refused"
            );
            return tool_error(format!(
                "plan refused: the preview could not be persisted ({error}). The \
                 change set has no stored preview, so approve and apply will refuse \
                 it. Plan the operation again."
            ));
        }

        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint,
            preview: preview_text,
            expected_digest: Some(output.digest),
        };

        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "apply_restore_new_vmid",
        description = "Apply an approved restore-to-new-vmid change set."
    )]
    async fn apply_restore_new_vmid(
        &self,
        Parameters(args): Parameters<change_set::ChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use restore_change_set::RestoreNewVmidAction;
        use rust_proxmoxmcp_core::grant::ProxmoxAction;
        use rust_proxmoxmcp_core::protect::creation_allowed;

        let caller = Self::caller(&context);
        let apply_request_id = caller
            .as_ref()
            .map_or_else(|| "stdio".to_owned(), |ctx| ctx.request_id.to_string());
        let apply_principal = caller
            .as_ref()
            .map_or_else(|| "stdio".to_owned(), |ctx| ctx.token_name.clone());
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "apply_restore_new_vmid",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let client = match self.client_for(&args.cluster) {
            Ok(client) => client,
            Err(result) => return *result,
        };

        let coordinator = self.coordinator.clone();
        let device = format!("{}/{}", args.cluster, args.vmid);
        let mut record = match coordinator.change_set(&args.change_set_id, &device).await {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };

        if record.preview.is_none() {
            return tool_error(
                "apply refused: this change set has no stored preview, so the action it \
                 would take was never recorded for review. Plan the operation again.",
            );
        }

        let action: RestoreNewVmidAction = match record.actions.first() {
            Some(value) => match serde_json::from_value(value.clone()) {
                Ok(action) => action,
                Err(error) => {
                    return tool_error(format!(
                        "the change set's action could not be read ({error}); \
                         it cannot be applied"
                    ));
                }
            },
            None => return tool_error("the change set records no action".to_owned()),
        };

        if action.target_vmid != args.vmid {
            return tool_error(
                "the change set's recorded target vmid does not match the vmid given here; \
                 it cannot be applied",
            );
        }

        // Again at apply: a scope can be narrowed between plan and apply, and
        // the apply is the call that acts. This repeats the full grant check
        // from `plan_restore_new_vmid` -- tool-name authorization alone is
        // not enough, because a token can hold the `apply_restore_new_vmid`
        // and `restore_backup_new_vmid` tool scopes while its guest scope no
        // longer covers this vmid, or while it no longer carries the
        // `destructive` action tier, or while the vmid has since been pinned
        // in `clusters.json`.
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "restore_backup_new_vmid",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }

        let grant = match resolve_grant(caller.as_ref()) {
            Ok(grant) => grant,
            Err(error) => return *error,
        };

        if !grant.allows_action(ProxmoxAction::Destructive) {
            return tool_error(
                "restoring into a new vmid requires the 'destructive' action tier, which this \
                 caller does not carry",
            );
        }

        if !grant.allows_new_vmid(action.target_vmid) {
            return tool_error(format!(
                "vmid {} is outside this caller's guest scope, so a backup may not be restored \
                 into it",
                action.target_vmid
            ));
        }

        if !creation_allowed(client.cluster(), action.target_vmid) {
            return tool_error(format!(
                "vmid {} is a protected pin on cluster {} and must not receive a restore",
                action.target_vmid, args.cluster
            ));
        }

        // Re-verify the archive still belongs to the owner this change set
        // was planned and digested against, then re-run the same scope and
        // protection check `plan_restore_new_vmid` ran -- a scope can be
        // narrowed, or a waiver can expire, between plan and apply, and this
        // is the call that actually copies the owner's disks.
        match rust_proxmoxmcp_core::guests::resolve_backup_owner(
            client,
            &action.node,
            &action.volid,
        )
        .await
        {
            Ok(owner_vmid) if owner_vmid == action.owner_vmid => {}
            Ok(owner_vmid) => {
                return tool_error(format!(
                    "backup archive '{}' now belongs to guest {owner_vmid}, not the {} it was \
                     planned against; the archive's ownership changed since this was planned. \
                     Plan the operation again.",
                    action.volid, action.owner_vmid
                ));
            }
            Err(error) => {
                return tool_error(format!(
                    "could not re-establish which guest owns backup archive '{}': {error}. \
                     Refusing rather than trusting the previously recorded owner.",
                    action.volid
                ));
            }
        }
        if let Err(error) = self
            .authorize_backup_owner(
                client,
                &args.cluster,
                action.owner_vmid,
                &grant,
                &action.volid,
                caller.as_ref().map(|ctx| ctx.token_name.as_str()),
            )
            .await
        {
            return tool_error(error);
        }

        let kind = match action.kind.as_str() {
            "qemu" => GuestType::Qemu,
            "lxc" => GuestType::Lxc,
            other => {
                return tool_error(format!(
                    "the change set records an unknown guest kind '{other}'; it cannot be \
                     applied"
                ));
            }
        };

        // The drift check for this operation. There is no guest to
        // fingerprint -- that is the point of this operation -- so what can
        // actually have changed since the plan is whether the vmid is still
        // free, and that is what is re-checked here, against live cluster
        // state, rather than only through the (necessarily constant)
        // fingerprint value below.
        self.index.invalidate_cluster(&args.cluster);
        match self
            .index
            .resolve(client, &args.cluster, action.target_vmid)
            .await
        {
            Ok(existing) => {
                return tool_error(format!(
                    "vmid {} now exists on cluster {} as '{}' -- it was free when this was \
                     planned and is no longer. Plan the operation again against a free vmid.",
                    action.target_vmid, args.cluster, existing.name
                ));
            }
            Err(rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }) => {}
            Err(error) => {
                return tool_error(format!(
                    "could not confirm vmid {} is still free on cluster {}: {error}",
                    action.target_vmid, args.cluster
                ));
            }
        }

        let current_fingerprint = rust_proxmoxmcp_core::fingerprint::restore_target_fingerprint(
            &args.cluster,
            action.target_vmid,
        );
        if current_fingerprint != record.expected_candidate_fingerprint {
            return tool_error(format!(
                "fingerprint changed (expected {}, got {})",
                record.expected_candidate_fingerprint, current_fingerprint
            ));
        }

        if record.state != mecmcp_changeset::ChangeSetState::Approved {
            return tool_error(format!(
                "change set not approved (state: {:?})",
                record.state
            ));
        }

        record = match self
            .coordinator
            .claim_change_set_for_apply(
                &record.id,
                &record.device,
                mecmcp_changeset::ApplyHandle::None,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                return tool_error(format!(
                    "apply refused: the change set could not be claimed for apply ({error}). \
                     Another apply may already hold it. Nothing was sent to the cluster."
                ));
            }
        };

        if let Some(recorder) = &self.evidence
            && let Err(error) = recorder.apply_intent(
                &apply_request_id,
                &record.id,
                &record.device,
                &apply_principal,
            )
        {
            let mut abandoned = record.clone();
            abandoned.state = mecmcp_changeset::ChangeSetState::Failed;
            let settled = self.coordinator.update_change_set(abandoned).await;
            if let Err(settle_error) = &settled {
                tracing::error!(
                    target: "audit",
                    %settle_error,
                    change_set = %record.id,
                    "claimed change set left in Applying after the intent record failed"
                );
            }
            return tool_error(match settled {
                Ok(()) => format!(
                    "apply refused: the apply-intent evidence record could not be persisted \
                     ({error}); nothing was sent to the cluster and the change set is now \
                     failed -- plan the operation again"
                ),
                Err(settle_error) => format!(
                    "apply refused: the apply-intent evidence record could not be persisted \
                     ({error}), and the change set could not then be settled \
                     ({settle_error}). Nothing was sent to the cluster, but the record is \
                     still claimed and reads as applying -- it needs an operator before \
                     this vmid can be planned again"
                ),
            });
        }

        // `force=0`, not `force=1`: the vacancy re-check above and this POST
        // are two separate requests, so a guest created on this vmid in
        // between them must make Proxmox itself refuse the write atomically
        // rather than let it silently overwrite whatever now holds the vmid.
        let upid_str = match rust_proxmoxmcp_core::guests::restore_backup(
            client,
            &action.node,
            kind,
            action.target_vmid,
            &action.volid,
            false,
        )
        .await
        {
            Ok(upid) => upid,
            Err(error) => {
                let definitive = matches!(
                    error,
                    rust_proxmoxmcp_core::ProxmoxError::Api { .. }
                        | rust_proxmoxmcp_core::ProxmoxError::Unauthorized
                        | rust_proxmoxmcp_core::ProxmoxError::Denied(_)
                        | rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }
                );
                if definitive {
                    if let Some(recorder) = &self.evidence
                        && let Err(receipt_error) = recorder.result_receipt(
                            &apply_request_id,
                            &record.id,
                            &record.device,
                            &apply_principal,
                            false,
                            &error.to_string(),
                        )
                    {
                        tracing::error!(%receipt_error, "failure receipt not persisted");
                    }
                    record.state = mecmcp_changeset::ChangeSetState::Failed;
                    let _ = self.coordinator.update_change_set(record).await;
                } else {
                    tracing::error!(
                        %error,
                        "the restore failed without a definitive answer; the outcome is \
                         indeterminate and no result receipt is emitted"
                    );
                }
                return tool_error(error);
            }
        };

        if upid_str.is_empty() {
            // `restore_backup` always answers with a UPID from a real
            // Proxmox; an empty string here would be an undocumented
            // synchronous answer. Treated the same way `apply_change_set`
            // treats a genuinely synchronous write, since there is then no
            // task to poll.
            if let Some(recorder) = &self.evidence
                && let Err(receipt_error) = recorder.result_receipt(
                    &apply_request_id,
                    &record.id,
                    &record.device,
                    &apply_principal,
                    true,
                    "",
                )
            {
                tracing::error!(
                    %receipt_error,
                    change_set_id = %record.id,
                    "the operation completed but its result receipt could not be persisted"
                );
            }
            record.state = mecmcp_changeset::ChangeSetState::Applied;
            record.task_id = None;
            if let Err(error) = self.coordinator.update_change_set(record).await {
                tracing::error!(%error, "could not mark the change set applied");
            }
            return tool_result::<_, String>(
                Ok(serde_json::json!({
                    "outcome": "ok",
                    "synchronous": true,
                    "upid": serde_json::Value::Null,
                })),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            );
        }

        let upid = match rust_proxmoxmcp_core::task::Upid::parse(&upid_str) {
            Ok(upid) => upid,
            Err(error) => return tool_error(error),
        };

        {
            let mut in_flight = record.clone();
            in_flight.task_id = Some(upid_str.clone());
            if let Err(error) = self.coordinator.update_change_set(in_flight).await {
                tracing::error!(
                    target: "audit",
                    %error,
                    change_set = %record.id,
                    upid = %upid_str,
                    "task handle not persisted; a crash now leaves this apply unrecoverable"
                );
            }
        }

        let exitstatus = match poll_proxmox_task(client, upid.node(), &upid_str).await {
            Ok(exitstatus) => exitstatus,
            Err(result) => return *result,
        };

        let outcome = rust_proxmoxmcp_core::task::classify_exit_status(&exitstatus);

        if let Some(recorder) = &self.evidence {
            let succeeded = matches!(outcome, rust_proxmoxmcp_core::task::TaskOutcome::Ok);
            if let Err(error) = recorder.result_receipt(
                &apply_request_id,
                &record.id,
                &record.device,
                &apply_principal,
                succeeded,
                if succeeded { "" } else { &exitstatus },
            ) {
                tracing::error!(
                    %error,
                    change_set_id = %record.id,
                    "the restore completed but its result receipt could not be persisted; \
                     the evidence chain ends at apply intent"
                );
            }
        }

        match outcome {
            rust_proxmoxmcp_core::task::TaskOutcome::Ok => {
                record.state = mecmcp_changeset::ChangeSetState::Applied;
                record.task_id = None;
                if let Err(error) = self.coordinator.update_change_set(record).await {
                    tracing::error!(%error, "could not mark the change set applied");
                }
                let response = serde_json::json!({
                    "outcome": "ok",
                    "upid": upid_str,
                    "exitstatus": exitstatus,
                    "vmid": action.target_vmid,
                    "node": action.node,
                });
                tool_result(
                    Ok::<_, String>(response),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                )
            }
            rust_proxmoxmcp_core::task::TaskOutcome::Failed(message) => {
                record.state = mecmcp_changeset::ChangeSetState::Failed;
                record.task_id = None;
                if let Err(error) = self.coordinator.update_change_set(record).await {
                    tracing::error!(%error, "could not mark the change set failed");
                }
                tool_error(format!("task failed: {message}"))
            }
        }
    }

    #[tool(
        name = "plan_firewall_change",
        description = "Plan a firewall change. The firewall is not changed until the change set is approved and applied."
    )]
    async fn plan_firewall_change(
        &self,
        Parameters(args): Parameters<firewall_change_set::PlanFirewallArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;

        let caller = Self::caller(&context);
        let prepared = match self.prepare_firewall_plan(&args, caller.as_ref()).await {
            Ok(prepared) => prepared,
            Err(error) => return *error,
        };
        match self.record_firewall_plan(prepared).await {
            Ok(response) => tool_result(
                Ok::<ChangeSetResponse, String>(response),
                ResultFormat::PrettyJson,
                RESULT_LIMITS,
                OutputRedaction::Apply,
            ),
            Err(error) => *error,
        }
    }

    #[tool(
        name = "get_firewall_change_set",
        description = "Read the state of a firewall change set, including the preview stored at plan time."
    )]
    async fn get_firewall_change_set(
        &self,
        Parameters(args): Parameters<firewall_change_set::FirewallChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "get_firewall_change_set",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }
        let device = match firewall_change_set::device_for_lookup(&args) {
            Ok(device) => device,
            Err(error) => return tool_error(error),
        };
        if let Err(error) = self.authorize_firewall_read(&args, caller.as_ref()).await {
            return *error;
        }
        let record = match self
            .coordinator
            .change_set(&args.change_set_id, &device)
            .await
        {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };
        let preview_text = record
            .preview
            .as_ref()
            .map(|preview| preview.artifact.clone())
            .unwrap_or_else(|| "(no preview)".to_owned());
        let response = ChangeSetResponse {
            change_set_id: record.id,
            state: format!("{:?}", record.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview_text,
            expected_digest: Some(record.digest),
        };
        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "approve_firewall_change",
        description = "Approve a planned firewall change set as a second principal."
    )]
    async fn approve_firewall_change(
        &self,
        Parameters(args): Parameters<firewall_change_set::FirewallChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        use change_set::ChangeSetResponse;
        use firewall_change_set::{action_matches_lookup, tool_for_firewall_op};

        let caller = Self::caller(&context);
        if let Err(error) = authorize_call(
            caller.as_ref(),
            "approve_firewall_change",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return authz_tool_error(error);
        }
        let device = match firewall_change_set::device_for_lookup(&args) {
            Ok(device) => device,
            Err(error) => return tool_error(error),
        };
        if let Err(error) = require_firewall_destructive_tier(caller.as_ref()) {
            return *error;
        }
        let record = match self
            .coordinator
            .change_set(&args.change_set_id, &device)
            .await
        {
            Ok(record) => record,
            Err(error) => return tool_error(format!("get: {error}")),
        };
        let Some(preview) = record.preview.as_ref() else {
            return tool_error(
                "approval refused: this change set has no stored preview, so there is \
                 nothing to review. Plan the operation again.",
            );
        };
        let action = match firewall_action_from_record(&record) {
            Ok(action) => action,
            Err(error) => return tool_error(error),
        };
        if !action_matches_lookup(&action, &args) {
            return tool_error("the change set does not address this firewall object".to_owned());
        }
        if let Err(error) = self
            .authorize_firewall_mutation(
                &args,
                &action,
                caller.as_ref(),
                Some(record.owner.as_str()),
            )
            .await
        {
            return *error;
        }
        let Some(op_tool) = tool_for_firewall_op(&action.object, &action.op) else {
            return tool_error(format!(
                "the change set names an unknown firewall operation '{}'",
                action.op
            ));
        };
        if let Err(error) =
            authorize_call(caller.as_ref(), op_tool, Some(&args.cluster), WRITE_TOOLS)
        {
            return authz_tool_error(error);
        }
        let approver = caller
            .as_ref()
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());
        let approver_actor_type = change_set::actor_type(caller.as_ref());
        let output = match self
            .coordinator
            .approve_change_set(
                args.change_set_id.clone(),
                device,
                approver,
                record.digest.clone(),
                approver_actor_type,
            )
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let msg = error.to_string();
                if msg.contains("owner cannot approve their own") {
                    return tool_error(
                        "self-approval refused: the planner cannot approve their own change set",
                    );
                }
                return tool_error(format!("approve: {error}"));
            }
        };
        let response = ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint: record.expected_candidate_fingerprint,
            preview: preview.artifact.clone(),
            expected_digest: Some(output.digest),
        };
        tool_result(
            Ok::<_, String>(response),
            ResultFormat::PrettyJson,
            RESULT_LIMITS,
            OutputRedaction::Apply,
        )
    }

    #[tool(
        name = "apply_firewall_change",
        description = "Apply an approved firewall change set. Refuses a change set that is not approved, or whose firewall object has changed since the plan."
    )]
    async fn apply_firewall_change(
        &self,
        Parameters(args): Parameters<firewall_change_set::FirewallChangeSetArgs>,
        context: RequestContext<RoleServer>,
    ) -> CallToolResult {
        let caller = Self::caller(&context);
        let ready = match self.prepare_firewall_apply(&args, caller.as_ref()).await {
            Ok(ready) => ready,
            Err(error) => return *error,
        };
        self.finish_firewall_apply(ready).await
    }
}

struct GuestFirewallGate {
    node: String,
    kind: String,
    protected: bool,
    summary: String,
    override_: rust_proxmoxmcp_core::protect::Override,
}

struct FirewallApplyReady {
    cluster: String,
    record: mecmcp_changeset::ChangeSetRecord,
    action: rust_proxmoxmcp_core::firewall::FirewallAction,
    live_node: Option<String>,
    live_kind: Option<String>,
    request_id: String,
    principal: String,
}

fn require_firewall_destructive_tier(
    caller: Option<&CallerCtx<ProxmoxGrant>>,
) -> Result<(), Box<CallToolResult>> {
    let grant = resolve_grant(caller)?;
    if grant.allows_action(rust_proxmoxmcp_core::ProxmoxAction::Destructive) {
        Ok(())
    } else {
        Err(Box::new(tool_error(
            "changing a firewall requires the 'destructive' action tier, which this caller \
             does not carry",
        )))
    }
}

fn require_shared_firewall_scope(grant: &ProxmoxGrant) -> Result<(), Box<CallToolResult>> {
    if grant.is_unrestricted_guest_scope() {
        Ok(())
    } else {
        Err(Box::new(tool_error(
            "a cluster or node firewall change is not scoped to one guest, so it requires a \
             caller whose guest scope is '*'. This caller is narrowed to specific guests and \
             cannot be checked against it.",
        )))
    }
}

fn firewall_action_from_record(
    record: &mecmcp_changeset::ChangeSetRecord,
) -> Result<rust_proxmoxmcp_core::firewall::FirewallAction, String> {
    let value = record
        .actions
        .first()
        .ok_or_else(|| "the change set records no action".to_owned())?;
    serde_json::from_value(value.clone()).map_err(|error| {
        format!("the change set's action could not be read ({error}); it cannot be applied")
    })
}

impl ProxmoxServer {
    async fn gate_guest_firewall(
        &self,
        client: &rust_proxmoxmcp_core::client::ProxmoxClient,
        cluster: &str,
        vmid: u32,
        caller: Option<&CallerCtx<ProxmoxGrant>>,
        waiver_op: &str,
        waiver_principal: Option<&str>,
    ) -> Result<GuestFirewallGate, Box<CallToolResult>> {
        use rust_proxmoxmcp_core::protect::{
            DestructiveAttempt, Override, destructive_allowed, protection_of,
        };

        self.index.invalidate_cluster(cluster);
        let grant = resolve_grant(caller)?;
        let (resolved, resolution_failed) = match self.index.resolve(client, cluster, vmid).await {
            Ok(guest) => (Some(guest), false),
            Err(_) => (None, true),
        };
        let protection = protection_of(client.cluster(), resolved.as_ref(), resolution_failed);
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_secs();
        let override_ = destructive_allowed(
            &protection,
            &self.waivers,
            cluster,
            vmid,
            now_unix,
            self.lab_mode,
            DestructiveAttempt {
                op: waiver_op,
                principal: waiver_principal,
            },
        );
        let override_applies = !matches!(override_, Override::None);
        let authorized = match self
            .index
            .authorize(
                client,
                cluster,
                vmid,
                &grant,
                Intent::destructive(override_applies),
            )
            .await
        {
            Ok(authorized) => authorized,
            Err(error) => return Err(Box::new(tool_error(error))),
        };
        let guest = authorized.guest();
        Ok(GuestFirewallGate {
            node: guest.node.clone(),
            kind: guest.r#type.path_segment().to_owned(),
            protected: protection.is_protected(),
            summary: protection.summary(),
            override_,
        })
    }

    async fn authorize_firewall_read(
        &self,
        args: &firewall_change_set::FirewallChangeSetArgs,
        caller: Option<&CallerCtx<ProxmoxGrant>>,
    ) -> Result<(), Box<CallToolResult>> {
        let grant = resolve_grant(caller)?;
        if args.scope != "guest" {
            return require_shared_firewall_scope(&grant);
        }
        let Some(vmid) = args.vmid else {
            return Err(Box::new(tool_error("guest firewall change requires vmid")));
        };
        let client = self.client_for(&args.cluster)?;
        self.index.invalidate_cluster(&args.cluster);
        match self
            .index
            .authorize(client, &args.cluster, vmid, &grant, Intent::read())
            .await
        {
            Ok(_) => Ok(()),
            Err(error) => Err(Box::new(tool_error(error))),
        }
    }

    async fn authorize_firewall_mutation(
        &self,
        args: &firewall_change_set::FirewallChangeSetArgs,
        action: &rust_proxmoxmcp_core::firewall::FirewallAction,
        caller: Option<&CallerCtx<ProxmoxGrant>>,
        waiver_principal: Option<&str>,
    ) -> Result<(), Box<CallToolResult>> {
        let grant = resolve_grant(caller)?;
        if action.scope != "guest" {
            return require_shared_firewall_scope(&grant);
        }
        let Some(vmid) = action.vmid else {
            return Err(Box::new(tool_error("guest firewall change has no vmid")));
        };
        let client = self.client_for(&args.cluster)?;
        let waiver_op = firewall_change_set::firewall_waiver_op(action);
        self.gate_guest_firewall(
            client,
            &args.cluster,
            vmid,
            caller,
            &waiver_op,
            waiver_principal,
        )
        .await?;
        Ok(())
    }

    async fn prepare_firewall_plan(
        &self,
        args: &firewall_change_set::PlanFirewallArgs,
        caller: Option<&CallerCtx<ProxmoxGrant>>,
    ) -> Result<firewall_change_set::PreparedFirewallPlan, Box<CallToolResult>> {
        use firewall_change_set::{
            PreparedFirewallPlan, build_firewall_action, existence_error, fingerprint_firewall,
            firewall_device, firewall_protection_lines, firewall_waiver_op,
            render_firewall_preview, tool_for_firewall_op,
        };
        use rust_proxmoxmcp_core::firewall::{LiveFirewall, observe};
        use rust_proxmoxmcp_core::protect::Override;

        if let Err(error) = authorize_call(
            caller,
            "plan_firewall_change",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return Err(Box::new(authz_tool_error(error)));
        }
        let mut action = match build_firewall_action(args) {
            Ok(action) => action,
            Err(error) => return Err(Box::new(tool_error(error))),
        };
        let Some(op_tool) = tool_for_firewall_op(&action.object, &action.op) else {
            return Err(Box::new(tool_error(format!(
                "unknown firewall operation '{}'",
                action.op
            ))));
        };
        if let Err(error) = authorize_call(caller, op_tool, Some(&args.cluster), WRITE_TOOLS) {
            return Err(Box::new(authz_tool_error(error)));
        }
        require_firewall_destructive_tier(caller)?;
        let grant = resolve_grant(caller)?;
        if action.scope != "guest" {
            require_shared_firewall_scope(&grant)?;
        }
        let client = self.client_for(&args.cluster)?;
        let (live_node, live_kind, protected, summary, override_) = if action.scope == "guest" {
            let vmid = action
                .vmid
                .ok_or_else(|| Box::new(tool_error("guest firewall change has no vmid")))?;
            let waiver_op = firewall_waiver_op(&action);
            let principal = caller.map(|ctx| ctx.token_name.as_str());
            let gate = self
                .gate_guest_firewall(client, &args.cluster, vmid, caller, &waiver_op, principal)
                .await?;
            action.guest_type = Some(gate.kind.clone());
            (
                Some(gate.node),
                Some(gate.kind),
                gate.protected,
                gate.summary,
                gate.override_,
            )
        } else {
            (None, None, false, String::new(), Override::None)
        };
        let observed = match observe(
            client,
            &action,
            LiveFirewall {
                node: live_node.as_deref(),
                guest_kind: live_kind.as_deref(),
            },
        )
        .await
        {
            Ok(observed) => observed,
            Err(error) => {
                return Err(Box::new(tool_error(format!(
                    "reading current firewall: {error}"
                ))));
            }
        };
        if let Some(error) = existence_error(&action, &observed) {
            return Err(Box::new(tool_error(error)));
        }
        if matches!(action.op.as_str(), "update" | "delete") {
            action.digest = observed.digest.clone();
        }
        let fingerprint = fingerprint_firewall(
            &action,
            live_node.as_deref(),
            live_kind.as_deref(),
            observed.body.as_ref(),
        );
        let (protected_line, waiver_line) =
            firewall_protection_lines(&action.scope, protected, &summary, &override_);
        let preview = render_firewall_preview(&action, &observed, &protected_line, &waiver_line);
        let device = match firewall_device(&action) {
            Ok(device) => device,
            Err(error) => return Err(Box::new(tool_error(error))),
        };
        let owner = caller
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned());
        Ok(PreparedFirewallPlan {
            action,
            fingerprint,
            preview,
            device,
            owner,
            waive_for_lab_mode: matches!(override_, Override::LabMode),
        })
    }

    async fn record_firewall_plan(
        &self,
        prepared: firewall_change_set::PreparedFirewallPlan,
    ) -> Result<change_set::ChangeSetResponse, Box<CallToolResult>> {
        use change_set::ChangeSetResponse;

        let coordinator = self.coordinator.clone();
        let output = match coordinator
            .create_change_set(
                prepared.device.clone(),
                vec![prepared.action],
                prepared.owner.clone(),
                prepared.fingerprint.clone(),
                "proxmox-no-policy-engine".to_owned(),
            )
            .await
        {
            Ok(output) => output,
            Err(error) => return Err(Box::new(tool_error(format!("create: {error}")))),
        };
        let Some(mut with_preview) = coordinator
            .change_sets()
            .await
            .into_iter()
            .find(|record| record.id == output.change_set_id)
        else {
            tracing::error!(
                change_set = %output.change_set_id,
                "the change set could not be read back; the plan is refused"
            );
            return Err(Box::new(tool_error(
                "plan refused: the change set could not be read back to store its \
                 preview. It has no preview, so approve and apply will refuse it. \
                 Plan the operation again.",
            )));
        };
        with_preview.preview = Some(mecmcp_changeset::PreviewRecord {
            digest: mecmcp_changeset::preview_digest(&prepared.preview),
            artifact: prepared.preview.clone(),
            job_id: None,
        });
        if let Err(error) = coordinator.update_change_set(with_preview).await {
            tracing::error!(
                %error,
                change_set = %output.change_set_id,
                "the preview could not be persisted; the plan is refused"
            );
            return Err(Box::new(tool_error(format!(
                "plan refused: the preview could not be persisted ({error}). The \
                 change set has no stored preview, so approve and apply will refuse \
                 it. Plan the operation again."
            ))));
        }
        let output = if prepared.waive_for_lab_mode {
            match coordinator
                .waive_approval(
                    output.change_set_id.clone(),
                    prepared.device.clone(),
                    prepared.owner.clone(),
                    output.digest.clone(),
                )
                .await
            {
                Ok(waived) => waived,
                Err(error) => return Err(Box::new(tool_error(format!("lab-mode: {error}")))),
            }
        } else {
            output
        };
        Ok(ChangeSetResponse {
            change_set_id: output.change_set_id,
            state: format!("{:?}", output.state),
            expected_fingerprint: prepared.fingerprint,
            preview: prepared.preview,
            expected_digest: Some(output.digest),
        })
    }

    async fn prepare_firewall_apply(
        &self,
        args: &firewall_change_set::FirewallChangeSetArgs,
        caller: Option<&CallerCtx<ProxmoxGrant>>,
    ) -> Result<FirewallApplyReady, Box<CallToolResult>> {
        use firewall_change_set::{
            action_matches_lookup, fingerprint_firewall, revalidate_firewall_action,
            tool_for_firewall_op,
        };
        use rust_proxmoxmcp_core::firewall::{LiveFirewall, observe};

        if let Err(error) = authorize_call(
            caller,
            "apply_firewall_change",
            Some(&args.cluster),
            WRITE_TOOLS,
        ) {
            return Err(Box::new(authz_tool_error(error)));
        }
        let device = match firewall_change_set::device_for_lookup(args) {
            Ok(device) => device,
            Err(error) => return Err(Box::new(tool_error(error))),
        };
        let record = match self
            .coordinator
            .change_set(&args.change_set_id, &device)
            .await
        {
            Ok(record) => record,
            Err(error) => return Err(Box::new(tool_error(format!("get: {error}")))),
        };
        if record.preview.is_none() {
            return Err(Box::new(tool_error(
                "apply refused: this change set has no stored preview, so the action it \
                 would take was never recorded for review. Plan the operation again.",
            )));
        }
        if record.state != mecmcp_changeset::ChangeSetState::Approved {
            return Err(Box::new(tool_error(format!(
                "change set not approved (state: {:?})",
                record.state
            ))));
        }
        require_firewall_destructive_tier(caller)?;
        let action = match firewall_action_from_record(&record) {
            Ok(action) => action,
            Err(error) => return Err(Box::new(tool_error(error))),
        };
        if !action_matches_lookup(&action, args) {
            return Err(Box::new(tool_error(
                "the change set does not address this firewall object".to_owned(),
            )));
        }
        if let Err(error) = revalidate_firewall_action(&action) {
            return Err(Box::new(tool_error(format!(
                "the change set records a '{}' action that cannot be applied ({error}). \
                 Plan the operation again. Nothing was sent to the cluster.",
                action.op
            ))));
        }
        let Some(op_tool) = tool_for_firewall_op(&action.object, &action.op) else {
            return Err(Box::new(tool_error(format!(
                "the change set names an unknown firewall operation '{}'",
                action.op
            ))));
        };
        if let Err(error) = authorize_call(caller, op_tool, Some(&args.cluster), WRITE_TOOLS) {
            return Err(Box::new(authz_tool_error(error)));
        }
        self.authorize_firewall_mutation(args, &action, caller, Some(record.owner.as_str()))
            .await?;
        let client = self.client_for(&args.cluster)?;
        let (live_node, live_kind) = if action.scope == "guest" {
            let vmid = action
                .vmid
                .ok_or_else(|| Box::new(tool_error("guest firewall change has no vmid")))?;
            let waiver_op = firewall_change_set::firewall_waiver_op(&action);
            let gate = self
                .gate_guest_firewall(
                    client,
                    &args.cluster,
                    vmid,
                    caller,
                    &waiver_op,
                    Some(record.owner.as_str()),
                )
                .await?;
            if action.guest_type.as_deref() != Some(gate.kind.as_str()) {
                return Err(Box::new(tool_error(
                    "the guest type changed after the plan; the change set is refused",
                )));
            }
            (Some(gate.node), Some(gate.kind))
        } else {
            (None, None)
        };
        let observed = match observe(
            client,
            &action,
            LiveFirewall {
                node: live_node.as_deref(),
                guest_kind: live_kind.as_deref(),
            },
        )
        .await
        {
            Ok(observed) => observed,
            Err(error) => {
                return Err(Box::new(tool_error(format!(
                    "reading current firewall: {error}"
                ))));
            }
        };
        let current = fingerprint_firewall(
            &action,
            live_node.as_deref(),
            live_kind.as_deref(),
            observed.body.as_ref(),
        );
        if current != record.expected_candidate_fingerprint {
            return Err(Box::new(tool_error(format!(
                "fingerprint changed (expected {}, got {current})",
                record.expected_candidate_fingerprint
            ))));
        }
        let request_id =
            caller.map_or_else(|| "stdio".to_owned(), |ctx| ctx.request_id.to_string());
        let principal = caller.map_or_else(|| "stdio".to_owned(), |ctx| ctx.token_name.clone());
        Ok(FirewallApplyReady {
            cluster: args.cluster.clone(),
            record,
            action,
            live_node,
            live_kind,
            request_id,
            principal,
        })
    }

    async fn finish_firewall_apply(&self, ready: FirewallApplyReady) -> CallToolResult {
        use rust_proxmoxmcp_core::firewall::{LiveFirewall, execute};

        let FirewallApplyReady {
            cluster,
            mut record,
            action,
            live_node,
            live_kind,
            request_id,
            principal,
        } = ready;
        let client = match self.client_for(&cluster) {
            Ok(client) => client,
            Err(error) => return *error,
        };
        let coordinator = self.coordinator.clone();
        record = match coordinator
            .claim_change_set_for_apply(
                &record.id,
                &record.device,
                mecmcp_changeset::ApplyHandle::None,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(error) => {
                return tool_error(format!(
                    "apply refused: the change set could not be claimed for apply ({error}). \
                     Another apply may already hold it. Nothing was sent to the cluster."
                ));
            }
        };
        if let Some(recorder) = &self.evidence
            && let Err(error) =
                recorder.apply_intent(&request_id, &record.id, &record.device, &principal)
        {
            let mut abandoned = record.clone();
            abandoned.state = mecmcp_changeset::ChangeSetState::Failed;
            let settled = coordinator.update_change_set(abandoned).await;
            return tool_error(match settled {
                Ok(()) => format!(
                    "apply refused: the apply-intent evidence record could not be persisted \
                     ({error}); nothing was sent to the cluster and the change set is now \
                     failed -- plan the operation again"
                ),
                Err(settle_error) => format!(
                    "apply refused: the apply-intent evidence record could not be persisted \
                     ({error}), and the change set could not then be settled \
                     ({settle_error}). Nothing was sent to the cluster, but the record is \
                     still claimed and reads as applying"
                ),
            });
        }
        let result = execute(
            client,
            &action,
            LiveFirewall {
                node: live_node.as_deref(),
                guest_kind: live_kind.as_deref(),
            },
        )
        .await;
        match result {
            Ok(()) => {
                if let Some(recorder) = &self.evidence
                    && let Err(receipt_error) = recorder.result_receipt(
                        &request_id,
                        &record.id,
                        &record.device,
                        &principal,
                        true,
                        "",
                    )
                {
                    tracing::error!(
                        %receipt_error,
                        change_set_id = %record.id,
                        "the operation completed but its result receipt could not be persisted"
                    );
                }
                record.state = mecmcp_changeset::ChangeSetState::Applied;
                record.task_id = None;
                if let Err(error) = coordinator.update_change_set(record).await {
                    tracing::error!(%error, "could not mark the change set applied");
                }
                tool_result::<_, String>(
                    Ok(serde_json::json!({ "outcome": "ok" })),
                    ResultFormat::PrettyJson,
                    RESULT_LIMITS,
                    OutputRedaction::Apply,
                )
            }
            Err(error) => {
                let definitive = matches!(
                    error,
                    rust_proxmoxmcp_core::ProxmoxError::Api { .. }
                        | rust_proxmoxmcp_core::ProxmoxError::Unauthorized
                        | rust_proxmoxmcp_core::ProxmoxError::Denied(_)
                        | rust_proxmoxmcp_core::ProxmoxError::NotFound { .. }
                );
                if definitive {
                    if let Some(recorder) = &self.evidence
                        && let Err(receipt_error) = recorder.result_receipt(
                            &request_id,
                            &record.id,
                            &record.device,
                            &principal,
                            false,
                            &error.to_string(),
                        )
                    {
                        tracing::error!(%receipt_error, "failure receipt not persisted");
                    }
                    record.state = mecmcp_changeset::ChangeSetState::Failed;
                    let _ = coordinator.update_change_set(record).await;
                } else {
                    tracing::error!(
                        %error,
                        "the firewall write failed without a definitive answer; the outcome \
                         is indeterminate and no result receipt is emitted"
                    );
                }
                tool_error(error)
            }
        }
    }
}

/// Wrap a filtered tool list in the result shape a 2026-07-28 client accepts.
///
/// `ListToolsResult::with_all_items` leaves `ttl_ms` and `cache_scope` unset and
/// both are omitted on the wire; a client on that protocol validates the result
/// and rejects it, which surfaces as "tools fetch failed" against a server that
/// is healthy and answering in milliseconds. Servers that do not override
/// `list_tools` get these from rmcp's generated handler — this one filters by
/// scope, so it supplies them itself.
///
/// Gated on the negotiated version exactly as rmcp does: the fields belong to
/// 2026-07-28 and later, and a strict legacy client rejects what it did not
/// negotiate.
///
/// `private` where rmcp's unfiltered list says `public`, because this list is
/// per token: a cache keyed only on the URL must not serve one caller's
/// permitted surface to another.
fn listed_tools(tools: Vec<rmcp::model::Tool>, cache_hints: bool) -> ListToolsResult {
    let listed = ListToolsResult::with_all_items(tools);
    if cache_hints {
        listed
            .with_ttl_ms(0)
            .with_cache_scope(rmcp::model::CacheScope::Private)
    } else {
        listed
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ProxmoxServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "rust-proxmoxmcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(
                "Proxmox VE MCP server. Guest-addressed tools take (cluster, vmid); \
                 the server resolves the node itself because guests migrate.",
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, rmcp::ErrorData> {
        let caller = caller_from_extensions::<ProxmoxGrant>(&context.extensions);
        let all_tools = self.tool_router.list_all();
        let visible = filter_tools_for_scope(all_tools, caller, WRITE_TOOLS);
        // `with_all_items` leaves `ttl_ms` and `cache_scope` unset, and both
        // are omitted on the wire. A 2026-07-28 client validates the tools/list
        // result and rejects one without them — reported as "tools fetch
        // failed" against a server that is otherwise healthy and fast. Servers
        // that do not override `list_tools` get these from rmcp's generated
        // handler; this one filters by scope, so it supplies them itself.
        //
        // `private`: the list is per token, so a cache keyed only on the URL
        // must not serve one caller's surface to another.
        let cache_hints = context
            .protocol_version()
            .is_some_and(|version| version >= rmcp::model::ProtocolVersion::V_2026_07_28);
        Ok(listed_tools(visible, cache_hints))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tools_includes_read_catalog_and_changeset_tools() {
        // Read tools from catalog.
        let read_tools: std::collections::HashSet<&str> = rust_proxmoxmcp_core::catalog::READ_TOOLS
            .iter()
            .map(|tool| tool.name)
            .collect();

        // Changeset tools added in Task 6, plus the restore-to-new-vmid plan
        // and apply wrappers: they are dedicated tools because there is no
        // guest to resolve/authorize against, but `get_proxmox_change_set`
        // and `approve_proxmox_change_set` are reused unmodified for them.
        let changeset_tools = [
            "plan_proxmox_destroy",
            "get_proxmox_change_set",
            "approve_proxmox_change_set",
            "apply_proxmox_change_set",
            "plan_ha_rule_change",
            "get_ha_rule_change_set",
            "approve_ha_rule_change",
            "apply_ha_rule_change",
            "plan_firewall_change",
            "get_firewall_change_set",
            "approve_firewall_change",
            "apply_firewall_change",
            "plan_restore_new_vmid",
            "apply_restore_new_vmid",
        ];

        // Low-tier tools added in 0.4. Listed rather than derived from
        // WRITE_TOOLS, because that registry deliberately names tools no
        // release has registered yet — deriving from it would let this test
        // pass for a tool that does not exist.
        let low_tools = [
            "clone_vm",
            "create_backup",
            "create_container",
            "create_snapshot",
            "create_vm",
            "download_iso",
            "reset_vm",
            "resize_disk",
            "stop_task",
            "restart_container",
            "shutdown_vm",
            "start_container",
            "start_vm",
            "stop_container",
            "stop_vm",
            "update_container_resources",
        ];

        for tool in KNOWN_TOOLS {
            assert!(
                read_tools.contains(tool)
                    || changeset_tools.contains(tool)
                    || low_tools.contains(tool)
                    || AUTHORIZATION_ONLY_TOOLS.contains(tool),
                "{tool} is in KNOWN_TOOLS but not in READ_TOOLS, changeset, low-tier, \
                 or authorization-only tools"
            );
        }

        // Every low-tier tool is registered, and every one is in WRITE_TOOLS so
        // a wildcard token cannot reach it.
        for tool in &low_tools {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "low-tier tool {tool} missing from KNOWN_TOOLS"
            );
            assert!(
                rust_proxmoxmcp_core::tier::WRITE_TOOLS.contains(tool),
                "low-tier tool {tool} is not in WRITE_TOOLS, so a wildcard token would reach it"
            );
        }

        // Verify changeset tools are present.
        for tool in &changeset_tools {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "changeset tool {tool} missing from KNOWN_TOOLS"
            );
        }
    }

    #[test]
    fn changeset_write_tools_are_registered() {
        let changeset_write = [
            "plan_proxmox_destroy",
            "approve_proxmox_change_set",
            "apply_proxmox_change_set",
        ];
        for tool in &changeset_write {
            assert!(
                KNOWN_TOOLS.contains(tool),
                "changeset write tool {tool} must be registered"
            );
        }
    }

    #[test]
    fn known_tools_is_sorted_so_review_diffs_stay_readable() {
        let mut sorted = KNOWN_TOOLS.to_vec();
        sorted.sort_unstable();
        assert_eq!(KNOWN_TOOLS, sorted.as_slice());
    }

    #[test]
    fn every_known_tool_has_a_registered_handler() {
        // KNOWN_TOOLS is hand-maintained; the router is generated from #[tool]
        // attributes. Nothing else in the build makes them agree.
        let router = ProxmoxServer::proxmox_tool_router();
        let registered: std::collections::BTreeSet<String> = router
            .list_all()
            .into_iter()
            .map(|tool| tool.name.into_owned())
            .collect();
        for name in KNOWN_TOOLS {
            // The authorization-only names deliberately have no handler: the
            // generic plan/apply handlers do the work, and these exist so a
            // token can be scoped to one operation rather than all of them.
            if AUTHORIZATION_ONLY_TOOLS.contains(name) {
                continue;
            }
            assert!(
                registered.contains(*name),
                "{name} is in KNOWN_TOOLS but has no #[tool] handler"
            );
        }
        // Compare against the names that actually have handlers: the
        // authorization-only entries are in KNOWN_TOOLS by design and the
        // router will never list them.
        let handler_names = KNOWN_TOOLS
            .iter()
            .filter(|name| !AUTHORIZATION_ONLY_TOOLS.contains(*name))
            .count();
        assert_eq!(
            registered.len(),
            handler_names,
            "router has tools absent from KNOWN_TOOLS"
        );
    }

    #[test]
    fn authenticated_token_without_grant_is_refused() {
        use mecmcp_auth::{ActorType, ScopeSet};

        // An authenticated caller (Some) with no grant (grant: None) must be refused.
        // This is the grantless-token case: a token that omits the 'grant' key in
        // tokens.json produces CallerCtx { grant: None, ... }.
        let grantless_caller = CallerCtx {
            token_name: "test-grantless-token".to_owned(),
            grant: None,
            tools: ScopeSet::Wildcard,
            devices: ScopeSet::Wildcard,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: ActorType::Agent,
            client_name: None,
            model_id: None,
            session_id: None,
            request_id: uuid::Uuid::new_v4(),
        };

        let result = resolve_grant(Some(&grantless_caller));
        assert!(
            result.is_err(),
            "grantless authenticated token must be refused, not granted wildcard access"
        );

        // mecmcp v0.25.0's `tool_error` redacts unconditionally (MEC-1020),
        // with no opt-out, and mecmcp-redact's scrubber treats "token" (and
        // "credential") as a trigger that consumes the rest of the string --
        // so `resolve_grant`'s message avoids that word entirely ("caller",
        // not "token") rather than ship a half-redacted response. The token
        // name was never meant to reach the model either way; it only
        // reaches the audit log (`resolve_grant`'s `tracing::warn!`), not
        // the tool response.
        let error_result = result.expect_err("already checked is_err");
        let error_text = format!("{error_result:?}");
        assert!(
            !error_text.contains("test-grantless-token"),
            "the token name must not reach the model: {error_text}"
        );
        assert!(
            !error_text.contains("REDACTED"),
            "this message carries no secret, so rewording around the denylisted word \
             should have kept it from being redacted: {error_text}"
        );
    }

    #[test]
    fn stdio_path_gets_wildcard_read_grant() {
        // The stdio path (caller = None, no bearer token) gets the wildcard read grant.
        let grant = resolve_grant(None).expect("stdio path should succeed");
        assert_eq!(
            grant.guests.len(),
            1,
            "read_only grant should have one selector"
        );
        // The read_only grant is constructed as guests: ["*"], actions: [Read]
    }

    /// A minimal server for exercising `gate_direct_commit` directly. No test
    /// here ever sends a request to the fake endpoint: the gate itself never
    /// touches `clients`, `index` or the coordinator, so this just needs to
    /// satisfy the constructor.
    fn minimal_server(direct_commit: mecmcp_audit::DirectCommitPolicy) -> ProxmoxServer {
        static CRYPTO_PROVIDER: std::sync::Once = std::sync::Once::new();
        CRYPTO_PROVIDER.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });

        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let clusters_path = temp_dir.path().join("clusters.json");
        let secret_path = temp_dir.path().join("secret.txt");
        std::fs::write(&secret_path, "test-secret").expect("write secret file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                .expect("set secret file permissions");
        }

        let inventory_json = serde_json::json!({
            "version": 1,
            "devices": {
                "test": {
                    "endpoint": "https://127.0.0.1:8006",
                    "token_id": "test@pam!test",
                    "token_secret_file": secret_path.to_str().expect("secret path"),
                    "protected_vmids": []
                }
            },
            "policy": { "resource_cache_ttl_secs": 300 }
        });
        std::fs::write(
            &clusters_path,
            serde_json::to_string_pretty(&inventory_json).expect("serialize"),
        )
        .expect("write clusters.json");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&clusters_path, std::fs::Permissions::from_mode(0o600))
                .expect("set clusters.json permissions");
        }

        let clusters =
            Arc::new(ClusterInventory::load(&clusters_path).expect("load clusters.json"));
        let mut clients = BTreeMap::new();
        for name in clusters.names() {
            let cluster = clusters.get(&name).expect("get cluster");
            clients.insert(
                name.clone(),
                ProxmoxClient::new(cluster).expect("build client"),
            );
        }
        let index = Arc::new(GuestIndex::new(std::time::Duration::from_secs(300)));
        let waivers = Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty());

        ProxmoxServer::new_with_default_coordinator(
            clusters,
            Arc::new(clients),
            index,
            waivers,
            false,
            None,
            direct_commit,
            None,
            None,
        )
        .expect("build server")
    }

    /// `gate_direct_commit`'s `caller == None` branch builds an
    /// `AuditScope::stdio` rather than `AuditScope::from_caller` -- the path a
    /// real stdio session (no bearer token, so `Self::caller` returns `None`)
    /// takes. Every end-to-end direct-commit test drives HTTP with a bearer
    /// token, so without this, that branch never runs at all.
    #[test]
    fn gate_direct_commit_refuses_over_stdio_with_no_caller_context() {
        let server = minimal_server(mecmcp_audit::DirectCommitPolicy::new(false));

        let result = server.gate_direct_commit(None, "stop_vm", "interrupt", "600");
        assert!(
            result.is_err(),
            "the stdio path must be refused with no --allow-direct-commit, same as HTTP"
        );
    }

    /// The same stdio path succeeds once the operator has accepted the risk.
    #[test]
    fn gate_direct_commit_allows_over_stdio_with_the_flag_on() {
        let server = minimal_server(mecmcp_audit::DirectCommitPolicy::new(true));

        let result = server.gate_direct_commit(None, "stop_vm", "interrupt", "600");
        assert!(
            result.is_ok(),
            "the stdio path must succeed with --allow-direct-commit, same as HTTP"
        );
    }
}

#[cfg(test)]
mod tools_list_cache_tests {
    use super::listed_tools;

    /// A 2026-07-28 client rejects a tools/list without these, and the failure
    /// reads as an unreachable server rather than a malformed reply.
    #[test]
    fn a_modern_client_gets_a_private_cache_descriptor() {
        let listed = listed_tools(Vec::new(), true);
        assert_eq!(
            listed.ttl_ms,
            Some(0),
            "a 2026-07-28 client rejects a tools/list without ttlMs"
        );
        assert_eq!(
            listed.cache_scope,
            Some(rmcp::model::CacheScope::Private),
            "the list is filtered per token, so it must not be shared"
        );
    }

    /// The fields are not part of the older result shape, and a strict legacy
    /// client rejects what it did not negotiate.
    #[test]
    fn a_legacy_client_gets_no_cache_descriptor() {
        let listed = listed_tools(Vec::new(), false);
        assert_eq!(listed.ttl_ms, None);
        assert_eq!(listed.cache_scope, None);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod destructive_action_tests {
    use super::build_destroy_action;
    use crate::server::change_set::PlanDestroyArgs;

    fn args(op: &str) -> PlanDestroyArgs {
        PlanDestroyArgs {
            cluster: "pve3".to_owned(),
            vmid: 617,
            op: op.to_owned(),
            snapname: None,
            storage: None,
            volid: None,
            storage_node: None,
            target_node: None,
            online: false,
            with_local_disks: false,
            config: std::collections::BTreeMap::new(),
        }
    }

    /// A caller written against 0.3 passed no `op` and meant a destroy. Serde
    /// fills the default, so that plan must still build the same action.
    #[test]
    fn the_default_operation_is_a_guest_destroy() {
        let action = build_destroy_action(&args("destroy_guest")).unwrap();
        assert_eq!(action.op, "destroy_guest");
        assert_eq!(action.vmid, 617);
        assert!(action.snapname.is_none());
    }

    /// Each operation names exactly what it needs, refused at plan time rather
    /// than defaulted at apply time — the action is what the digest covers, so
    /// anything undecided now is something the approver cannot review.
    #[test]
    fn a_missing_parameter_is_refused_at_plan_time() {
        for (op, missing) in [
            ("delete_snapshot", "snapname"),
            ("rollback_snapshot", "snapname"),
            ("delete_backup", "storage"),
            ("restore_backup", "volid"),
        ] {
            let error = build_destroy_action(&args(op)).expect_err("must be refused");
            assert!(
                error.contains(missing),
                "{op}: the refusal must name the missing parameter, got: {error}"
            );
        }
    }

    /// An empty string is not a parameter.
    #[test]
    fn an_empty_parameter_counts_as_missing() {
        let mut a = args("delete_snapshot");
        a.snapname = Some(String::new());
        assert!(build_destroy_action(&a).is_err());
    }

    /// A typo must not become a change set nobody can execute.
    #[test]
    fn an_unknown_operation_is_refused_with_the_valid_set() {
        let error = build_destroy_action(&args("delete_everything")).expect_err("refused");
        assert!(error.contains("unknown destructive operation"), "{error}");
        assert!(
            error.contains("rollback_snapshot"),
            "the refusal should list what is valid, got: {error}"
        );
    }

    /// `restore_backup` takes no storage: the archive volid names its own, and
    /// accepting a second one invites the two to disagree.
    #[test]
    fn restore_takes_the_volid_alone() {
        let mut a = args("restore_backup");
        a.volid = Some("local:backup/vzdump-lxc-617.tar.zst".to_owned());
        a.storage = Some("ignored".to_owned());
        let action = build_destroy_action(&a).unwrap();
        assert!(
            action.storage.is_none(),
            "a storage passed to restore must not reach the action"
        );
        assert_eq!(
            action.volid.as_deref(),
            Some("local:backup/vzdump-lxc-617.tar.zst")
        );
    }

    /// A path segment carrying '/' expands to a different URL than the one
    /// approved, and `expand_path` refuses it -- but only at apply time, by
    /// which point the change set is planned, approved and claimed. Refusing at
    /// plan time keeps that state unreachable.
    #[test]
    fn an_unusable_path_segment_is_refused_at_plan_time() {
        // Not just a raw '/': an encoded separator is one decode away from
        // one, and a relative component walks the path somewhere else
        // entirely. A hand-rolled byte check would have accepted all four of
        // the latter cases, which is why this delegates to `expand_path`.
        for (field, value) in [
            ("storage_node", "pve2/bad"),
            ("storage", "local/bad"),
            ("storage", "%2f"),
            ("storage", "%252f"),
            ("storage_node", "."),
            ("storage_node", ".."),
        ] {
            let mut a = args("delete_backup");
            a.storage_node = Some("pve2".to_owned());
            a.storage = Some("local".to_owned());
            a.volid = Some("local:backup/vzdump-lxc-617.tar.zst".to_owned());
            match field {
                "storage_node" => a.storage_node = Some(value.to_owned()),
                _ => a.storage = Some(value.to_owned()),
            }
            let error =
                build_destroy_action(&a).expect_err("a path segment containing '/' must not plan");
            assert!(
                error.contains(field),
                "the refusal must name the offending field: {error}"
            );
        }
    }

    /// The same rule must not reach `volid`, which is a query parameter and
    /// legitimately contains '/'.
    #[test]
    fn a_volid_may_still_contain_a_separator() {
        let mut a = args("delete_backup");
        a.storage_node = Some("pve2".to_owned());
        a.storage = Some("local".to_owned());
        a.volid = Some("local:backup/vzdump-lxc-617.tar.zst".to_owned());
        let action = build_destroy_action(&a).expect("a well-formed volid plans");
        assert_eq!(
            action.volid.as_deref(),
            Some("local:backup/vzdump-lxc-617.tar.zst")
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod destructive_scope_tests {
    use super::{build_destroy_action, render_destructive_preview, tool_for_op};
    use crate::server::change_set::PlanDestroyArgs;
    use rust_proxmoxmcp_core::protect::Override;
    use rust_proxmoxmcp_core::selector::GuestType;

    /// Every operation authorises against its own tool name, so a token
    /// allowlisted only for the generic handlers cannot select any operation
    /// it likes.
    #[test]
    fn every_operation_maps_to_its_own_tool() {
        for (op, tool) in [
            ("destroy_guest", "delete_vm"),
            ("destroy", "delete_vm"),
            ("delete_snapshot", "delete_snapshot"),
            ("rollback_snapshot", "rollback_snapshot"),
            ("delete_backup", "delete_backup"),
            ("delete_iso", "delete_iso"),
            ("restore_backup", "restore_backup"),
        ] {
            assert_eq!(tool_for_op(op, GuestType::Qemu), Some(tool), "{op}");
        }
        assert_eq!(tool_for_op("delete_everything", GuestType::Qemu), None);
    }

    /// Every mapped tool is in WRITE_TOOLS, or the scope check would be
    /// authorising against a name a wildcard token already reaches.
    #[test]
    fn every_mapped_tool_is_excluded_from_the_wildcard() {
        for op in [
            "destroy_guest",
            "delete_snapshot",
            "rollback_snapshot",
            "delete_backup",
            "delete_iso",
            "restore_backup",
        ] {
            let tool = tool_for_op(op, GuestType::Qemu).unwrap();
            assert!(
                rust_proxmoxmcp_core::tier::WRITE_TOOLS.contains(&tool),
                "{tool} is not in WRITE_TOOLS, so a wildcard token would reach it"
            );
        }
    }

    fn action(
        op: &str,
        snapname: Option<&str>,
        volid: Option<&str>,
    ) -> super::change_set::DestroyAction {
        super::change_set::DestroyAction {
            op: op.to_owned(),
            cluster: "pve3".to_owned(),
            vmid: 617,
            snapname: snapname.map(ToOwned::to_owned),
            storage: Some("local".to_owned()),
            volid: volid.map(ToOwned::to_owned),
            storage_node: Some("pve2".to_owned()),
            target_node: None,
            online: false,
            with_local_disks: false,
            config: None,
        }
    }

    /// The preview must describe the operation that will run. Reusing the
    /// guest-destroy renderer showed `DESTROY` for a rollback, a restore and a
    /// volume delete alike — an approver would have signed off on a different
    /// operation than the one recorded.
    #[test]
    fn each_operation_previews_as_itself() {
        let cases = [
            ("delete_snapshot", "DELETE SNAPSHOT"),
            ("rollback_snapshot", "ROLLBACK"),
            ("delete_backup", "DELETE BACKUP"),
            ("delete_iso", "DELETE ISO"),
            ("restore_backup", "RESTORE"),
        ];
        for (op, expected) in cases {
            let text = render_destructive_preview(
                &action(op, Some("snap"), Some("local:backup/x")),
                "g",
                "pve2",
                false,
                "",
                &Override::None,
            );
            assert!(text.starts_with(expected), "{op}: {text}");
            assert!(
                !text.starts_with("DESTROY"),
                "{op} previewed as a guest destroy"
            );
        }
    }

    /// The two that replace state rather than remove an object must say so.
    /// An approver reading "delete" for a rollback would not know that
    /// everything written since the snapshot is lost.
    #[test]
    fn replacing_operations_warn_that_state_is_overwritten() {
        let rollback = render_destructive_preview(
            &action("rollback_snapshot", Some("s"), None),
            "g",
            "pve2",
            false,
            "",
            &Override::None,
        );
        assert!(rollback.contains("OVERWRITES"), "{rollback}");
        let restore = render_destructive_preview(
            &action("restore_backup", None, Some("local:backup/x")),
            "g",
            "pve2",
            false,
            "",
            &Override::None,
        );
        assert!(restore.contains("OVERWRITES"), "{restore}");
    }

    /// Finding C (MEC-1191 re-review): every non-destroy destructive op used
    /// to carry no protection or waiver line, so the README's claim that
    /// "the waiver's reason and ticket are printed in the stored preview"
    /// was false for this renderer. Since a matching waiver no longer
    /// auto-approves (F4), the human approver reading this text is the only
    /// gate left, and they must be told the guest is protected.
    #[test]
    fn a_protected_guest_shows_protection_and_waiver_in_a_non_destroy_preview() {
        let text = render_destructive_preview(
            &action("rollback_snapshot", Some("s"), None),
            "g",
            "pve2",
            true,
            "tag:protected",
            &Override::Waiver {
                reason: "test waiver".to_owned(),
                ticket: Some("TEST-1".to_owned()),
                until_unix: 4102444800,
            },
        );
        assert!(text.contains("protected  yes"), "{text}");
        assert!(text.contains("tag:protected"), "{text}");
        assert!(text.contains("waiver"), "{text}");
        assert!(text.contains("TEST-1"), "{text}");

        let unprotected = render_destructive_preview(
            &action("rollback_snapshot", Some("s"), None),
            "g",
            "pve2",
            false,
            "",
            &Override::None,
        );
        assert!(unprotected.contains("protected  no"), "{unprotected}");
        assert!(unprotected.contains("waiver     none"), "{unprotected}");
    }

    /// A volume's node is part of its identity, because `local` is node-local.
    #[test]
    fn a_volume_operation_requires_its_storage_node() {
        let args = PlanDestroyArgs {
            cluster: "pve3".to_owned(),
            vmid: 617,
            op: "delete_backup".to_owned(),
            snapname: None,
            storage: Some("local".to_owned()),
            volid: Some("local:backup/x".to_owned()),
            storage_node: None,
            target_node: None,
            online: false,
            with_local_disks: false,
            config: std::collections::BTreeMap::new(),
        };
        let error = build_destroy_action(&args).expect_err("storage_node is required");
        assert!(error.contains("storage_node"), "{error}");
    }
    /// An incomplete record must be named as incomplete, not carried past the
    /// apply-intent write.
    ///
    /// `execute_destructive` reports an absent field as `ProxmoxError::Malformed`,
    /// which is not in the `definitive` set, so reaching it means apply intent
    /// is written and no result receipt ever follows -- the chain reads as
    /// "may have been sent" for an operation that never left the process.
    ///
    /// This covers the classifier only. The apply path itself needs a
    /// coordinator and a client, so the ordering against the intent write is
    /// held by the call site rather than by this test.
    #[test]
    fn a_volume_action_without_its_storage_node_is_named_incomplete() {
        let mut incomplete = action("delete_backup", None, Some("local:backup/x"));
        incomplete.storage_node = None;
        assert_eq!(
            super::missing_required_fields(&incomplete),
            vec!["storage_node"]
        );
    }

    /// An empty string is not a value. `build_destroy_action` filters empty
    /// strings out at plan time, so an action carrying one was never planned by
    /// this version -- and treating it as present sends it to `expand_path`,
    /// which rejects the empty segment as `Malformed` after the intent write.
    ///
    /// The `None`-only drift guard below did not catch this; empty and absent
    /// have to be tested separately.
    #[test]
    fn an_empty_required_field_counts_as_missing() {
        let mut empty = action("delete_snapshot", Some(""), None);
        assert_eq!(super::missing_required_fields(&empty), vec!["snapname"]);

        empty = action("delete_backup", None, Some("local:backup/x"));
        empty.storage_node = Some(String::new());
        assert_eq!(super::missing_required_fields(&empty), vec!["storage_node"]);
    }

    /// The same defect reaches every operation with a required field, not just
    /// the volume ones the volid work was about.
    #[test]
    fn a_snapshot_action_without_its_snapname_is_named_incomplete() {
        let incomplete = action("delete_snapshot", None, None);
        assert_eq!(
            super::missing_required_fields(&incomplete),
            vec!["snapname"]
        );

        let incomplete = action("rollback_snapshot", None, None);
        assert_eq!(
            super::missing_required_fields(&incomplete),
            vec!["snapname"]
        );
    }

    /// Every absent field is reported at once, so an operator fixing a record
    /// is not sent round the loop one field at a time.
    #[test]
    fn every_absent_field_is_reported_together() {
        let mut incomplete = action("delete_iso", None, None);
        incomplete.storage = None;
        incomplete.storage_node = None;
        assert_eq!(
            super::missing_required_fields(&incomplete),
            vec!["storage", "volid", "storage_node"]
        );
    }

    /// A complete action, and one that needs no extra fields, must pass.
    #[test]
    fn a_complete_action_is_not_reported_as_incomplete() {
        assert!(
            super::missing_required_fields(&action("delete_backup", None, Some("local:backup/x")))
                .is_empty()
        );
        assert!(
            super::missing_required_fields(&action("restore_backup", None, Some("local:backup/x")))
                .is_empty()
        );
        assert!(
            super::missing_required_fields(&action("delete_snapshot", Some("s"), None)).is_empty()
        );
        // 0.3 spelled it `destroy`; both spellings name the guest and nothing else.
        assert!(super::missing_required_fields(&action("destroy_guest", None, None)).is_empty());
        assert!(super::missing_required_fields(&action("destroy", None, None)).is_empty());
    }

    /// Anything `build_destroy_action` requires at plan time, the apply-time
    /// check must also require -- otherwise a record planned by a future
    /// version could strand the chain the same way. Drift guard.
    #[test]
    fn the_apply_check_requires_what_planning_requires() {
        for (op, required) in [
            ("destroy_guest", &[][..]),
            ("delete_snapshot", &["snapname"][..]),
            ("rollback_snapshot", &["snapname"][..]),
            ("delete_backup", &["storage", "volid", "storage_node"][..]),
            ("delete_iso", &["storage", "volid", "storage_node"][..]),
            ("restore_backup", &["volid"][..]),
            ("migrate", &["target_node"][..]),
            ("update_vm_config", &["config"][..]),
        ] {
            let stripped = super::change_set::DestroyAction {
                op: op.to_owned(),
                cluster: "pve3".to_owned(),
                vmid: 617,
                snapname: None,
                storage: None,
                volid: None,
                storage_node: None,
                target_node: None,
                online: false,
                with_local_disks: false,
                config: None,
            };
            assert_eq!(
                super::missing_required_fields(&stripped),
                required.to_vec(),
                "{op} disagrees with what planning requires"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod grantable_scope_tests {
    use super::{KNOWN_TOOLS, tool_for_op};
    use rust_proxmoxmcp_core::selector::GuestType;

    /// Every name the scope check demands must be grantable through the token
    /// CLI, which validates against `KNOWN_TOOLS`.
    ///
    /// This is the test that was missing. The check landed without it and made
    /// the whole destructive tier unusable: `token add --tools delete_snapshot`
    /// was refused as an unknown tool, and a wildcard excludes these by design,
    /// so no token could plan or apply *any* destructive operation. The unit
    /// tests passed throughout because they build tokens directly and never
    /// cross the CLI's validation.
    #[test]
    fn every_operation_scope_is_grantable() {
        for op in [
            "destroy_guest",
            "destroy",
            "delete_snapshot",
            "rollback_snapshot",
            "delete_backup",
            "delete_iso",
            "restore_backup",
        ] {
            for kind in [GuestType::Lxc, GuestType::Qemu] {
                let tool = tool_for_op(op, kind).unwrap();
                assert!(
                    KNOWN_TOOLS.contains(&tool),
                    "{op} authorises against '{tool}', which the token CLI rejects as unknown"
                );
            }
        }
    }

    /// ...and every one of them stays excluded from the tool wildcard, or
    /// making them grantable would have handed them to every `*` token.
    #[test]
    fn grantable_does_not_mean_reachable_by_wildcard() {
        for op in ["destroy_guest", "delete_snapshot", "restore_backup"] {
            for kind in [GuestType::Lxc, GuestType::Qemu] {
                let tool = tool_for_op(op, kind).unwrap();
                assert!(
                    rust_proxmoxmcp_core::tier::WRITE_TOOLS.contains(&tool),
                    "{tool} became reachable by a wildcard token"
                );
            }
        }
    }

    /// A container destroy and a VM destroy are different scopes. Mapping both
    /// to `delete_vm` denied a `delete_container` token its own containers, and
    /// let a `delete_vm` token delete them.
    #[test]
    fn a_guest_destroy_authorises_against_its_guest_type() {
        assert_eq!(
            tool_for_op("destroy_guest", GuestType::Lxc),
            Some("delete_container")
        );
        assert_eq!(
            tool_for_op("destroy_guest", GuestType::Qemu),
            Some("delete_vm")
        );
        // The 0.3 spelling maps the same way.
        assert_eq!(
            tool_for_op("destroy", GuestType::Lxc),
            Some("delete_container")
        );
    }
}
