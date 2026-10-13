//! Destructive change-set lifecycle for Proxmox guests.
//!
//! Provides the plan → approve → apply workflow with two-principal control,
//! fingerprint verification, and operator waiver support. The state machine,
//! persistence, and digest validation come from `mecmcp-changeset`; this module
//! handles Proxmox-specific concerns: protection evaluation, fingerprint binding,
//! preview generation, and guest resolution.

use mecmcp_changeset::{ChangesetCoordinator, CoordinatorError, OperationLimits};
use rust_proxmoxmcp_core::ProxmoxGrant;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

/// Map a caller's server-verified `mecmcp_auth::ActorType` to the
/// `mecmcp_audit::ActorType` mecmcp's `approve_change_set` requires.
///
/// `None` -- no authenticated caller context, i.e. the stdio transport --
/// maps to `Unknown` rather than `Human`. Inventing `Human` for an
/// unattributed caller would let stdio silently satisfy the human-approver
/// gate; `Unknown` is the honest fact, and `approve_change_set` refuses it
/// exactly like it refuses `Agent`.
pub(crate) fn approver_identity(
    caller: Option<&mecmcp_auth::CallerCtx<ProxmoxGrant>>,
) -> mecmcp_changeset::ApproverIdentity {
    // No verified-approver assertion path is wired into this server, so the
    // identity is always token-asserted; strict mode cannot be satisfied.
    mecmcp_changeset::ApproverIdentity::TokenAsserted {
        principal: caller
            .map(|ctx| ctx.token_name.clone())
            .unwrap_or_else(|| "stdio".to_owned()),
        actor_type: actor_type(caller),
    }
}

/// The caller token's bound IdP identity, recorded on the change set so the
/// coordinator can refuse the same human approving their own plan.
pub(crate) fn owner_subject(
    caller: Option<&mecmcp_auth::CallerCtx<ProxmoxGrant>>,
) -> Option<mecmcp_changeset::OwnerSubject> {
    caller
        .and_then(|ctx| ctx.oidc_subject.as_ref())
        .map(|s| mecmcp_changeset::OwnerSubject {
            issuer: s.issuer.clone(),
            subject: s.subject.clone(),
        })
}

pub(crate) fn actor_type(
    caller: Option<&mecmcp_auth::CallerCtx<ProxmoxGrant>>,
) -> mecmcp_audit::ActorType {
    match caller {
        Some(ctx) => match ctx.actor_type {
            mecmcp_auth::ActorType::Human => mecmcp_audit::ActorType::Human,
            mecmcp_auth::ActorType::Agent => mecmcp_audit::ActorType::Agent,
            mecmcp_auth::ActorType::Unknown => mecmcp_audit::ActorType::Unknown,
        },
        None => mecmcp_audit::ActorType::Unknown,
    }
}

/// Arguments for planning a destroy operation.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct PlanDestroyArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
    /// Which destructive operation to plan.
    ///
    /// `destroy_guest` (the default, and what 0.3 planned),
    /// `delete_snapshot`, `rollback_snapshot`, `delete_backup`, `delete_iso`,
    /// `restore_backup`, `migrate`, or `update_vm_config`.
    ///
    /// Defaults to `destroy_guest` so a caller written against 0.3 keeps
    /// working: this argument did not exist, and every plan meant a destroy.
    #[serde(default = "default_destructive_op")]
    pub op: String,
    /// Snapshot name, for `delete_snapshot` and `rollback_snapshot`.
    #[serde(default)]
    pub snapname: Option<String>,
    /// Storage backend, for `delete_backup` and `delete_iso`.
    #[serde(default)]
    pub storage: Option<String>,
    /// Volume id, for `delete_backup`, `delete_iso` and `restore_backup`.
    #[serde(default)]
    pub volid: Option<String>,
    /// Node whose storage holds the volume, for `delete_backup` and
    /// `delete_iso`.
    ///
    /// Required for those, because `local` is node-local: the same volid on
    /// two nodes names two different volumes.
    #[serde(default)]
    pub storage_node: Option<String>,
    /// Destination node, for `migrate`. Required for that operation.
    #[serde(default)]
    pub target_node: Option<String>,
    /// Live-migrate, for `migrate`. Defaults to `false` (offline).
    ///
    /// For a QEMU guest this is Proxmox's own `online` migration. For an LXC
    /// guest, stock Proxmox has no live migration path; this instead requests
    /// Proxmox's `restart` mode, which stops, migrates and restarts the
    /// container as one operation rather than refusing because it is running.
    #[serde(default)]
    pub online: bool,
    /// Copy node-local disks along with the guest, for `migrate` of a QEMU
    /// guest whose disks are not on shared storage. Ignored for LXC, which
    /// always migrates its volumes. Defaults to `false`.
    #[serde(default)]
    pub with_local_disks: bool,
    /// Proxmox QEMU config keys to set, for `update_vm_config`. Merged into
    /// the guest's existing config; keys not named here are unchanged.
    ///
    /// Cloud-init fields (`ciuser`, `cipassword`, `sshkeys`, `ipconfigN`, ...)
    /// are ordinary QEMU config keys from Proxmox's point of view, so they
    /// travel through this same map rather than a separate cloud-init
    /// argument -- there is no vendor distinction for this tool to preserve.
    #[serde(default)]
    pub config: BTreeMap<String, String>,
}

/// What a plan means when the caller does not say.
fn default_destructive_op() -> String {
    "destroy_guest".to_owned()
}

/// Arguments for retrieving or manipulating a change set.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ChangeSetArgs {
    /// Change set identifier.
    pub change_set_id: String,
    /// Inventory name of the cluster.
    pub cluster: String,
    /// Numeric guest id.
    pub vmid: u32,
}

/// Output from plan/get operations.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ChangeSetResponse {
    /// Change set identifier.
    pub change_set_id: String,
    /// Current state.
    pub state: String,
    /// Expected fingerprint at plan time.
    pub expected_fingerprint: String,
    /// Server-rendered preview of the operation.
    pub preview: String,
    /// Approval digest for the approver to provide.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_digest: Option<String>,
}

/// Action for a destructive operation.
///
/// `op` is the discriminant and the remaining fields are its parameters, absent
/// when the operation does not take them. Serialised into the change set's
/// `actions`, so the digest covers exactly what will be executed — an apply
/// that dispatched on anything not in here could act on something the approver
/// never saw.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DestroyAction {
    /// Operation type.
    pub op: String,
    /// Cluster name.
    pub cluster: String,
    /// Guest VMID.
    pub vmid: u32,
    /// Snapshot name, for the snapshot operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapname: Option<String>,
    /// Storage backend, for the volume operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
    /// Volume id, for the volume operations and restore.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volid: Option<String>,
    /// Node the storage lives on, for the volume operations.
    ///
    /// Recorded rather than derived from the guest at apply. `local` is
    /// node-local storage, so `local:backup/x` on pve2 and on pve3 are
    /// different volumes that happen to share a name. Deriving the node from
    /// whichever guest the vmid names could delete the same-named volume on
    /// the wrong host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_node: Option<String>,
    /// Destination node, for `migrate`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_node: Option<String>,
    /// Live-migrate, for `migrate`. See [`PlanDestroyArgs::online`].
    #[serde(default)]
    pub online: bool,
    /// Copy node-local disks, for `migrate` of a QEMU guest.
    #[serde(default)]
    pub with_local_disks: bool,
    /// Config keys to set, for `update_vm_config`. See
    /// [`PlanDestroyArgs::config`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<BTreeMap<String, String>>,
}

/// Build a coordinator for change-set lifecycle operations.
///
/// # Errors
///
/// Returns an error if the coordinator cannot load existing state.
pub(crate) fn build_coordinator(
    state_path: Option<&std::path::Path>,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    approval_digest_key: Option<mecmcp_changeset::ApprovalDigestKey>,
) -> Result<Arc<ChangesetCoordinator>, CoordinatorError> {
    let limits = OperationLimits {
        max_operations: 100,
        max_change_sets: 100,
        max_actions_per_set: 10,
        max_change_set_bytes: 1024 * 1024,
        max_state_bytes: 10 * 1024 * 1024,
        max_targets_per_set: 10,
        max_preview_bytes: 256 * 1024,
    };
    let approval_ttl = Duration::from_secs(3600);
    // `load_with_key` verifies any on-disk v6 approval digest against the key
    // and stores it on the returned coordinator for future signs; it must not
    // also be passed to `with_approval_digest_key` afterwards, or the two
    // copies could drift.
    let mut coordinator = ChangesetCoordinator::load_with_key(
        state_path,
        limits,
        approval_ttl,
        lab_mode,
        approval_digest_key,
    )?;
    if let Some(recorder) = evidence {
        coordinator = coordinator.with_evidence(recorder);
    }
    Ok(Arc::new(coordinator))
}

// Tool handlers are in mod.rs, integrated with the main proxmox_tool_router.
// This module provides the types and helper functions.

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::build_coordinator;

    /// A key passed through `build_coordinator` must produce the keyed v6
    /// approval digest.
    #[tokio::test]
    async fn an_approval_digest_key_passed_to_build_coordinator_produces_a_keyed_digest() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state_path = dir.path().join("changeset-state.json");
        let key = b"a-sufficiently-long-test-key".as_slice();

        let coordinator = build_coordinator(
            Some(&state_path),
            false,
            None,
            Some(mecmcp_changeset::ApprovalDigestKey::new(key)),
        )
        .expect("coordinator with a configured key");

        let created = coordinator
            .create_change_set(
                "cluster-a/vm-100".to_string(),
                vec![serde_json::json!({"action": "set", "target": "/test"})],
                "alice".to_string(),
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                "policy-sig".to_string(),
                None,
            )
            .await
            .expect("create");
        coordinator
            .approve_change_set(
                created.change_set_id.clone(),
                "cluster-a/vm-100".to_string(),
                &mecmcp_changeset::ApproverIdentity::TokenAsserted {
                    principal: "bob".to_string(),
                    actor_type: mecmcp_audit::ActorType::Human,
                },
                created.digest.clone(),
            )
            .await
            .expect("approve");

        let state = mecmcp_changeset::persistence::read_state_with_key(
            &state_path,
            10 * 1024 * 1024,
            Some(key),
        )
        .expect("read back with the same key");
        let approval = state.change_sets[&created.change_set_id]
            .approval
            .as_ref()
            .expect("approval");
        assert_eq!(
            approval.digest_version, 7,
            "a key passed through build_coordinator must produce a v7 (keyed, \
             approver-mechanism-bound) digest, not an unkeyed one"
        );

        drop(coordinator);
        let unkeyed_read =
            mecmcp_changeset::persistence::read_state_with_key(&state_path, 10 * 1024 * 1024, None);
        assert!(
            unkeyed_read.is_err(),
            "a v6 digest produced through build_coordinator must not verify without the key"
        );
    }
}
