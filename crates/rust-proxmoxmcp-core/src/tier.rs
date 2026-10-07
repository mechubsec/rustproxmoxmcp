//! Action-class tiering.
//!
//! Tier is a property of the tool, declared once here, and it selects the code
//! path. It is never a value a caller passes: a `force: true` argument is not a
//! guardrail, because a sufficiently confident caller sets it.
//!
//! `WRITE_TOOLS` is complete from release 0.1 even though releases 0.2 and 0.3
//! register the tools it names. `ScopeSet::allows_tool` excludes this registry
//! from the tool wildcard, so it is the only thing standing between a
//! `"tools": ["*"]` token and write authority the day those tools appear.

use crate::grant::ProxmoxAction;

/// Action class of a tool.
///
/// The boundary is **data loss, not disruption**: a stop is `Low` because it
/// destroys nothing, even though it takes a guest out of service. Whether a
/// tool interrupts service is a separate question, answered by
/// [`interrupts_service`], because the two drive different controls — the tier
/// drives the grant action, interruption drives protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Observation only.
    Read,
    /// Disruptive but reversible.
    Low,
    /// Irreversible.
    Destructive,
}

impl Tier {
    /// The grant action this tier requires.
    #[must_use]
    pub const fn action(self) -> ProxmoxAction {
        match self {
            Self::Read => ProxmoxAction::Read,
            Self::Low => ProxmoxAction::Low,
            Self::Destructive => ProxmoxAction::Destructive,
        }
    }
}

/// Low-tier tools that take a running guest out of service.
///
/// Reversible, and `Low` by action — nothing is destroyed — but a protected
/// guest must not be taken down by a routine call, so these respect protection
/// exactly as a destructive call does and need the same waiver or `--lab-mode`.
///
/// This is deliberately *not* folded into [`Tier`]. The tier boundary is data
/// loss; this is service interruption. Merging them would make `stop_vm` look
/// like a different action class than it is, and an operator who granted `low`
/// does expect to be able to stop an unprotected guest.
///
/// The complement matters as much as the list: `start_vm` and `create_snapshot`
/// *add* something and stay safe on a protected guest. `create_backup` is the
/// same in its default `snapshot` mode, but not in `suspend` or `stop` mode --
/// see [`backup_interrupts`], which answers the per-call question this list
/// cannot. Snapshotting protected guests before an upgrade is the most common
/// operation in this lab, and refusing it would make the tool useless for the
/// case it exists to serve.
pub const INTERRUPTING_TOOLS: &[&str] = &[
    "reset_vm",
    "restart_container",
    "shutdown_vm",
    "stop_container",
    "stop_task",
    "stop_vm",
    "update_container_resources",
];

/// Whether a tool takes a running guest out of service.
///
/// A destructive tool is not listed here — it is held back by its tier — so
/// this answers only the low-tier question.
#[must_use]
pub fn interrupts_service(tool: &str) -> bool {
    INTERRUPTING_TOOLS.contains(&tool)
}

/// The only `mode` values vzdump's `create_backup` endpoint accepts.
///
/// Checked before authorization so an unrecognised value is refused outright
/// rather than classified by a `.trim() == "stop"`-style comparison that a
/// value like `"STOP"` or a stray argument could slip past -- see
/// [`backup_interrupts`]'s fail-closed note.
pub const VALID_BACKUP_MODES: &[&str] = &["snapshot", "suspend", "stop"];

/// Whether a `create_backup` call with this `mode` takes the guest out of
/// service for the duration of the backup.
///
/// `create_backup` is not, and cannot be, a member of [`INTERRUPTING_TOOLS`]:
/// that list answers a per-*tool* question, and whether a backup interrupts
/// the guest depends on `mode`, a per-*call* argument. vzdump's `stop` mode
/// stops the guest before dumping it, and `suspend` pauses it for longer than
/// a live snapshot would -- both exactly as disruptive as `stop_vm` -- while
/// only `snapshot` does not take it out of service. Treating `create_backup`
/// as uniformly non-interrupting (as [`interrupts_service`] would, since it is
/// absent from [`INTERRUPTING_TOOLS`]) would let `mode: "stop"` or
/// `mode: "suspend"` bypass the protection and direct-commit gates that a
/// plain `stop_vm` call cannot.
///
/// Callers must reject any `mode` outside [`VALID_BACKUP_MODES`] before
/// calling this: an unrecognised value has to fail closed rather than be
/// guessed at here, so this function assumes it has already been validated
/// and never itself refuses.
#[must_use]
pub fn backup_interrupts(mode: &str) -> bool {
    matches!(mode.trim(), "stop" | "suspend")
}

/// Tools excluded from a wildcard tool scope. Complete as of spec §4.3.
pub const WRITE_TOOLS: &[&str] = &[
    // low
    "approve_firewall_change",
    "approve_ha_rule_change",
    "approve_proxmox_change_set",
    "clone_vm",
    "create_backup",
    "create_container",
    "create_snapshot",
    "create_vm",
    "download_iso",
    "plan_firewall_change",
    "plan_ha_rule_change",
    "plan_proxmox_destroy",
    "plan_restore_new_vmid",
    "reset_vm",
    "restart_container",
    "shutdown_vm",
    "start_container",
    "start_vm",
    "stop_container",
    "stop_task",
    "stop_vm",
    "update_container_resources",
    // low or destructive depending on direction; classified at call time
    "resize_disk",
    // destructive
    "apply_firewall_change",
    "apply_ha_rule_change",
    "apply_proxmox_change_set",
    "apply_restore_new_vmid",
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
    // deferred to 0.5, registered here so a wildcard never reaches it
    "execute_vm_command",
];

/// Tools whose tier is `Destructive`.
const DESTRUCTIVE_TOOLS: &[&str] = &[
    "apply_firewall_change",
    "apply_ha_rule_change",
    "apply_proxmox_change_set",
    "apply_restore_new_vmid",
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
    "execute_vm_command",
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

/// Classify a tool.
///
/// Returns `None` for a name this server does not register. An unknown tool is
/// unclassified rather than defaulted to [`Tier::Read`]; defaulting would make
/// a future tool readable by omission.
///
/// `resize_disk` reports [`Tier::Low`] here and is re-classified at call time
/// from the sign of its size argument — a shrink destroys data and a grow does
/// not. See `crate::catalog` for where that happens in release 0.2.
#[must_use]
pub fn tier_of(tool: &str) -> Option<Tier> {
    if DESTRUCTIVE_TOOLS.contains(&tool) {
        return Some(Tier::Destructive);
    }
    if WRITE_TOOLS.contains(&tool) {
        return Some(Tier::Low);
    }
    // Change-set inspection tools are Read-tier but not Proxmox API calls.
    if tool == "get_proxmox_change_set"
        || tool == "get_ha_rule_change_set"
        || tool == "get_firewall_change_set"
    {
        return Some(Tier::Read);
    }
    crate::catalog::read_tool(tool).map(|_| Tier::Read)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_read_tool_classifies_as_read() {
        for tool in crate::catalog::READ_TOOLS {
            assert_eq!(tier_of(tool.name), Some(Tier::Read), "tool {}", tool.name);
        }
    }

    #[test]
    fn every_write_tool_classifies_as_low_or_destructive() {
        for tool in WRITE_TOOLS {
            let tier = tier_of(tool).unwrap_or_else(|| panic!("unclassified tool {tool}"));
            assert_ne!(tier, Tier::Read, "tool {tool} classified as read");
        }
    }

    #[test]
    fn destroy_and_restore_are_destructive() {
        assert_eq!(tier_of("delete_vm"), Some(Tier::Destructive));
        assert_eq!(tier_of("delete_container"), Some(Tier::Destructive));
        assert_eq!(tier_of("restore_backup"), Some(Tier::Destructive));
        assert_eq!(tier_of("rollback_snapshot"), Some(Tier::Destructive));
    }

    #[test]
    fn stop_is_low_because_the_tier_boundary_is_data_loss_not_disruption() {
        assert_eq!(tier_of("stop_vm"), Some(Tier::Low));
    }

    #[test]
    fn no_read_tool_appears_in_the_write_registry() {
        for tool in crate::catalog::READ_TOOLS {
            assert!(
                !WRITE_TOOLS.contains(&tool.name),
                "read tool {} is in WRITE_TOOLS",
                tool.name
            );
        }
    }

    #[test]
    fn an_unknown_tool_is_unclassified_rather_than_defaulting_to_read() {
        assert_eq!(tier_of("wipe_everything"), None);
    }
}

#[cfg(test)]
mod interruption_tests {
    use super::{Tier, interrupts_service, tier_of};

    /// The five tools that take a running guest out of service.
    #[test]
    fn stopping_a_guest_interrupts_service() {
        for tool in [
            "stop_vm",
            "shutdown_vm",
            "reset_vm",
            "stop_container",
            "restart_container",
        ] {
            assert!(interrupts_service(tool), "{tool} takes a guest down");
        }
    }

    /// The complement is the point. Snapshotting a protected guest before an
    /// upgrade is the most common operation in this lab; if protection refused
    /// it, the tool would be useless for the case it exists to serve.
    #[test]
    fn adding_something_does_not_interrupt_service() {
        for tool in [
            "start_vm",
            "start_container",
            "create_snapshot",
            "create_backup",
        ] {
            assert!(
                !interrupts_service(tool),
                "{tool} adds rather than interrupts and must stay available on a protected guest"
            );
        }
    }

    /// Interruption is orthogonal to the tier. A stop is still `Low` — it
    /// destroys nothing — which is what `stop_is_low_because_the_tier_boundary
    /// _is_data_loss_not_disruption` pins. This asserts the two axes disagree
    /// on purpose, so a later refactor cannot quietly merge them.
    #[test]
    fn interruption_is_not_the_tier_boundary() {
        assert_eq!(tier_of("stop_vm"), Some(Tier::Low));
        assert!(interrupts_service("stop_vm"));

        assert_eq!(tier_of("create_snapshot"), Some(Tier::Low));
        assert!(!interrupts_service("create_snapshot"));
    }

    /// A destructive tool is held back by its tier, not by this list, so it
    /// must not appear here — otherwise the reason a call was refused becomes
    /// ambiguous.
    #[test]
    fn destructive_tools_are_not_listed_as_interrupting() {
        for tool in super::DESTRUCTIVE_TOOLS {
            assert!(
                !interrupts_service(tool),
                "{tool} is destructive; its tier already refuses a protected guest"
            );
        }
    }
}

#[cfg(test)]
mod backup_interrupt_tests {
    use super::{VALID_BACKUP_MODES, backup_interrupts};

    /// `mode: "stop"` stops the guest before dumping it, and `mode: "suspend"`
    /// pauses it for the duration of the dump -- both exactly as disruptive as
    /// `stop_vm` -- so both must classify as interrupting even though
    /// `create_backup` itself is not in `INTERRUPTING_TOOLS`.
    #[test]
    fn stop_and_suspend_modes_interrupt() {
        assert!(backup_interrupts("stop"));
        assert!(backup_interrupts("suspend"));
    }

    /// `snapshot` does not take the guest out of service, which is what keeps
    /// `create_backup` usable on a protected guest in its default mode.
    #[test]
    fn snapshot_mode_does_not_interrupt() {
        assert!(!backup_interrupts("snapshot"));
    }

    /// Whitespace must not change the answer, matching `resize_shrinks`'s
    /// house style for free-text arguments.
    #[test]
    fn surrounding_whitespace_does_not_flip_the_classification() {
        assert!(backup_interrupts("  stop  "));
        assert!(backup_interrupts("  suspend  "));
        assert!(!backup_interrupts("  snapshot  "));
    }

    /// A case variant or stray value is exactly what `VALID_BACKUP_MODES`
    /// exists to catch before this function ever sees it: `"STOP"` does not
    /// match the `stop` arm of `backup_interrupts` and would silently
    /// classify as non-interrupting if a caller skipped the allowlist check.
    #[test]
    fn a_mode_outside_the_allowlist_would_misclassify_if_unchecked() {
        assert!(!VALID_BACKUP_MODES.contains(&"STOP"));
        assert!(!backup_interrupts("STOP"));
    }

    #[test]
    fn the_allowlist_is_exactly_the_three_vzdump_modes() {
        assert_eq!(VALID_BACKUP_MODES, &["snapshot", "suspend", "stop"]);
    }
}

#[cfg(test)]
mod resize_tests {
    use crate::guests::resize_shrinks;

    /// The delta form is the only unambiguous grow.
    #[test]
    fn a_positive_delta_grows() {
        for size in ["+8G", "+1024M", "+1T"] {
            assert!(!resize_shrinks(size), "{size} adds capacity");
        }
    }

    /// An absolute value may be smaller than the current disk, and this
    /// function cannot know the current size. Treating it as a shrink gets the
    /// call refused, which the caller can retry as an explicit `+N`; treating
    /// it as a grow would let a shrink past the gate entirely.
    #[test]
    fn an_absolute_size_is_treated_as_shrinking() {
        for size in ["32G", "8G", "1024M"] {
            assert!(
                resize_shrinks(size),
                "{size} could be smaller than the current disk"
            );
        }
    }

    /// A `+` prefix is not by itself a grow. Each of these starts with one and
    /// names no amount to add; the previous length check admitted every one of
    /// them to the low tier.
    #[test]
    fn a_malformed_delta_is_treated_as_shrinking() {
        for size in [
            "+banana", "++8G", "+-8G", "+", "+G", "+.", "+8X", "+8.G", "+.5G", "+8..0G",
        ] {
            assert!(
                resize_shrinks(size),
                "{size} does not name an amount to add"
            );
        }
    }

    /// Zero adds nothing, so it is not a grow either.
    #[test]
    fn a_zero_delta_is_not_a_grow() {
        for size in ["+0", "+0G", "+0.0G", "+00M"] {
            assert!(resize_shrinks(size), "{size} adds no capacity");
        }
    }

    /// The forms Proxmox actually accepts must still classify as growing.
    #[test]
    fn well_formed_deltas_grow() {
        for size in ["+8G", "+1024M", "+1T", "+8g", "+0.5G", "+512", "+1.25T"] {
            assert!(!resize_shrinks(size), "{size} adds capacity");
        }
    }

    /// A negative delta is unambiguously a shrink.
    #[test]
    fn a_negative_delta_shrinks() {
        assert!(resize_shrinks("-8G"));
    }

    /// Unclassifiable input errs toward the safer answer.
    #[test]
    fn a_malformed_size_is_treated_as_shrinking() {
        for size in ["", "+", "  ", "banana", "8"] {
            assert!(
                resize_shrinks(size),
                "{size:?} cannot be shown to grow, so it must not be treated as low tier"
            );
        }
    }

    /// Whitespace must not change the answer.
    #[test]
    fn surrounding_whitespace_does_not_flip_the_classification() {
        assert!(!resize_shrinks("  +8G  "));
        assert!(resize_shrinks("  32G  "));
    }
}
