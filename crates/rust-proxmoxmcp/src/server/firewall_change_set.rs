//! Change-set lifecycle for Proxmox firewall objects.
//!
//! Plan, approve and apply are the only path that writes a firewall rule,
//! options object, alias, IPSet or security group. This module validates the
//! caller's arguments, names the device key and renders the preview. The
//! server module owns the coordinator calls.

use rust_proxmoxmcp_core::firewall::{
    FirewallAction, FirewallOptionFields, FirewallRuleFields, ObservedFirewall,
};
use rust_proxmoxmcp_core::protect::Override;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;

/// Arguments for planning a firewall change.
///
/// The firewall is not written here. Apply sends the action this plan records,
/// after a second principal approves it.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PlanFirewallArgs {
    /// Inventory name of the cluster.
    pub cluster: String,
    /// `cluster`, `node` or `guest`.
    pub scope: String,
    /// `rule`, `options`, `group`, `group_rule`, `ipset`, `ipset_entry` or `alias`.
    pub object: String,
    /// `create`, `update` or `delete`. Defaults to `create`.
    #[serde(default = "default_firewall_op")]
    pub op: String,
    /// Node name. Required for node scope, and only then. A guest's node is
    /// resolved by the server.
    #[serde(default)]
    pub node: Option<String>,
    /// Guest id. Required for guest scope, and only then.
    #[serde(default)]
    pub vmid: Option<u32>,
    /// Security group, IPSet or alias name.
    #[serde(default)]
    pub name: Option<String>,
    /// Rule position. Required to update or delete a rule.
    #[serde(default)]
    pub pos: Option<u32>,
    /// Alias address, or the address of an IPSet entry.
    #[serde(default)]
    pub cidr: Option<String>,
    /// Free-text comment. Shown redacted in the preview.
    #[serde(default)]
    pub comment: Option<String>,
    /// Whether a rule is enabled.
    #[serde(default)]
    pub enable: Option<bool>,
    /// IPSet entry `nomatch` flag.
    #[serde(default)]
    pub nomatch: Option<bool>,
    /// Fields for a rule or a security-group rule.
    #[serde(default)]
    pub rule: Option<FirewallRuleArgs>,
    /// Fields for an options update: enable flag, default policy, and guest
    /// filter flags.
    #[serde(default)]
    pub options: Option<FirewallOptionArgs>,
}

fn default_firewall_op() -> String {
    "create".to_owned()
}

/// Fields a firewall rule create or update may set.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallRuleArgs {
    /// `ACCEPT`, `DROP`, `REJECT`, or a security-group name when `rule_type` is `group`.
    #[serde(default)]
    pub action: Option<String>,
    /// `in`, `out`, `forward` or `group`.
    #[serde(default)]
    pub rule_type: Option<String>,
    /// Destination address, alias or IPSet reference.
    #[serde(default)]
    pub dest: Option<String>,
    /// Destination port or range.
    #[serde(default)]
    pub dport: Option<String>,
    /// IP protocol.
    #[serde(default)]
    pub proto: Option<String>,
    /// Source address, alias or IPSet reference.
    #[serde(default)]
    pub source: Option<String>,
    /// Source port or range.
    #[serde(default)]
    pub sport: Option<String>,
    /// Interface name.
    #[serde(default)]
    pub iface: Option<String>,
    /// Firewall macro name.
    #[serde(default)]
    pub fw_macro: Option<String>,
    /// Log level.
    #[serde(default)]
    pub log: Option<String>,
    /// ICMP type name.
    #[serde(default)]
    pub icmp_type: Option<String>,
}

/// Fields an options update may set.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallOptionArgs {
    /// Whether the firewall is enabled.
    #[serde(default)]
    pub enable: Option<bool>,
    /// Default inbound policy.
    #[serde(default)]
    pub policy_in: Option<String>,
    /// Default outbound policy.
    #[serde(default)]
    pub policy_out: Option<String>,
    /// Default forward policy.
    #[serde(default)]
    pub policy_forward: Option<String>,
    /// Honour DHCP. Guest scope only.
    #[serde(default)]
    pub dhcp: Option<bool>,
    /// Restrict the guest to its configured addresses. Guest scope only.
    #[serde(default)]
    pub ipfilter: Option<bool>,
    /// Restrict the guest to its configured MAC. Guest scope only.
    #[serde(default)]
    pub macfilter: Option<bool>,
    /// Allow NDP. Guest scope only.
    #[serde(default)]
    pub ndp: Option<bool>,
    /// Allow router advertisements. Guest scope only.
    #[serde(default)]
    pub radv: Option<bool>,
    /// Inbound log level.
    #[serde(default)]
    pub log_level_in: Option<String>,
    /// Outbound log level.
    #[serde(default)]
    pub log_level_out: Option<String>,
    /// Forward log level.
    #[serde(default)]
    pub log_level_forward: Option<String>,
}

/// Arguments identifying a firewall change set.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FirewallChangeSetArgs {
    /// Change set identifier.
    pub change_set_id: String,
    /// Inventory name of the cluster.
    pub cluster: String,
    /// `cluster`, `node` or `guest`.
    pub scope: String,
    /// Firewall object family. See [`PlanFirewallArgs::object`].
    pub object: String,
    /// Node name, for node scope.
    #[serde(default)]
    pub node: Option<String>,
    /// Guest id, for guest scope.
    #[serde(default)]
    pub vmid: Option<u32>,
    /// Security group, IPSet or alias name.
    #[serde(default)]
    pub name: Option<String>,
}

/// A plan that has been validated and fingerprinted, ready to record.
pub(crate) struct PreparedFirewallPlan {
    /// Action the change set will store.
    pub action: FirewallAction,
    /// Fingerprint of the object as it was read.
    pub fingerprint: String,
    /// Preview text stored for the approver.
    pub preview: String,
    /// Device key the coordinator tracks this object under.
    pub device: String,
    /// Planner's token name.
    pub owner: String,
    /// Whether lab mode should approve this plan without a second principal.
    pub waive_for_lab_mode: bool,
}

/// Refusal for an IPSet entry whose address cannot be one path segment.
const PREFIXED_ENTRY: &str = "deleting or updating an IPSet entry requires an address that is a \
     single path segment. A prefixed address can be added with create, or the IPSet can be \
     deleted and recreated through its own change set.";

const LOG_LEVELS: &[&str] = &[
    "emerg", "alert", "crit", "err", "warning", "notice", "info", "debug", "nolog",
];

const PROTOS: &[&str] = &[
    "tcp", "udp", "icmp", "icmpv6", "igmp", "ah", "esp", "gre", "sctp",
];

/// Build and validate the action a plan will record.
///
/// The digest and guest type are filled in after the cluster is read. They
/// are not taken from the caller.
///
/// # Errors
///
/// Returns a caller-facing message when the arguments cannot name one
/// firewall write.
pub(crate) fn build_firewall_action(args: &PlanFirewallArgs) -> Result<FirewallAction, String> {
    let action = FirewallAction {
        op: args.op.clone(),
        object: args.object.clone(),
        scope: args.scope.clone(),
        cluster: args.cluster.clone(),
        node: args.node.clone(),
        vmid: args.vmid,
        guest_type: None,
        name: args.name.clone(),
        pos: args.pos,
        cidr: args.cidr.clone(),
        comment: args.comment.clone(),
        enable: args.enable,
        nomatch: args.nomatch,
        digest: None,
        rule: args.rule.as_ref().map(rule_from_args),
        options: args.options.as_ref().map(options_from_args),
    };
    validate_firewall_action(&action, false)?;
    Ok(action)
}

/// Re-check a stored action before it is applied.
///
/// # Errors
///
/// Returns a caller-facing message when the stored action is not a complete
/// firewall write.
pub(crate) fn revalidate_firewall_action(action: &FirewallAction) -> Result<(), String> {
    validate_firewall_action(action, true)
}

/// The concrete tool name a firewall operation authorises against.
#[must_use]
pub(crate) fn tool_for_firewall_op(object: &str, op: &str) -> Option<&'static str> {
    match (object, op) {
        ("rule", "create") => Some("create_firewall_rule"),
        ("rule", "update") => Some("update_firewall_rule"),
        ("rule", "delete") => Some("delete_firewall_rule"),
        ("group", "create") => Some("create_firewall_group"),
        ("group", "delete") => Some("delete_firewall_group"),
        ("group_rule", "create") => Some("create_firewall_group_rule"),
        ("group_rule", "update") => Some("update_firewall_group_rule"),
        ("group_rule", "delete") => Some("delete_firewall_group_rule"),
        ("ipset", "create") => Some("create_firewall_ipset"),
        ("ipset", "delete") => Some("delete_firewall_ipset"),
        ("ipset_entry", "create") => Some("create_firewall_ipset_entry"),
        ("ipset_entry", "update") => Some("update_firewall_ipset_entry"),
        ("ipset_entry", "delete") => Some("delete_firewall_ipset_entry"),
        ("alias", "create") => Some("create_firewall_alias"),
        ("alias", "update") => Some("update_firewall_alias"),
        ("alias", "delete") => Some("delete_firewall_alias"),
        ("options", "update") => Some("update_firewall_options"),
        _ => None,
    }
}

/// Waiver `op` string for a guest firewall change.
#[must_use]
pub(crate) fn firewall_waiver_op(action: &FirewallAction) -> String {
    format!("firewall_{}_{}", action.object, action.op)
}

/// Device key for one firewall object.
///
/// The key locks the whole ruleset, IPSet or security group, not one rule
/// position. A guest key uses the vmid, not the node the guest is on.
///
/// # Errors
///
/// Returns a message when the identity cannot form a key.
pub(crate) fn firewall_device(action: &FirewallAction) -> Result<String, String> {
    let (family, named) = match action.object.as_str() {
        "rule" => ("rules", None),
        "options" => ("options", None),
        "alias" => ("aliases", None),
        "group" | "group_rule" => ("group", action.name.as_deref()),
        "ipset" | "ipset_entry" => ("ipset", action.name.as_deref()),
        other => return Err(format!("unknown firewall object '{other}'")),
    };
    let cluster = &action.cluster;
    match action.scope.as_str() {
        "cluster" => match named {
            None => Ok(format!("{cluster}/fw:cluster:{family}")),
            Some(name) => Ok(format!("{cluster}/fw:cluster:{family}:{name}")),
        },
        "node" => {
            let node = action
                .node
                .as_deref()
                .ok_or_else(|| "node firewall change has no node".to_owned())?;
            match named {
                None => Ok(format!("{cluster}/fw:node:{node}:{family}")),
                Some(name) => Ok(format!("{cluster}/fw:node:{node}:{family}:{name}")),
            }
        }
        "guest" => {
            let vmid = action
                .vmid
                .ok_or_else(|| "guest firewall change has no vmid".to_owned())?;
            match named {
                None => Ok(format!("{cluster}/fw:guest:{vmid}:{family}")),
                Some(name) => Ok(format!("{cluster}/fw:guest:{vmid}:{family}:{name}")),
            }
        }
        other => Err(format!("unknown firewall scope '{other}'")),
    }
}

/// Device key for a get, approve or apply call.
///
/// # Errors
///
/// Returns a message when the identity is not a firewall object this server
/// tracks.
pub(crate) fn device_for_lookup(args: &FirewallChangeSetArgs) -> Result<String, String> {
    validate_lookup_identity(args)?;
    firewall_device(&lookup_action(args))
}

/// Whether a stored action is the object this call named.
#[must_use]
pub(crate) fn action_matches_lookup(action: &FirewallAction, args: &FirewallChangeSetArgs) -> bool {
    action.cluster == args.cluster
        && action.scope == args.scope
        && action.object == args.object
        && action.node == args.node
        && action.vmid == args.vmid
        && action.name == args.name
}

/// Refuse a plan the live object cannot satisfy.
#[must_use]
pub(crate) fn existence_error(
    action: &FirewallAction,
    observed: &ObservedFirewall,
) -> Option<String> {
    let present = observed.item_present;
    match (action.object.as_str(), action.op.as_str(), present) {
        ("rule" | "group_rule", "create", _) | ("options", _, _) => None,
        ("rule" | "group_rule", "update" | "delete", false) => Some(format!(
            "firewall rule position {} does not exist; nothing to {}",
            action
                .pos
                .map(|pos| pos.to_string())
                .unwrap_or_else(|| "?".to_owned()),
            action.op
        )),
        (_, "create", true) => Some(format!(
            "firewall {} '{}' already exists",
            action.object,
            object_label(action)
        )),
        (_, "update" | "delete", false) => Some(format!(
            "firewall {} '{}' does not exist; nothing to {}",
            action.object,
            object_label(action),
            action.op
        )),
        _ => None,
    }
}

/// Fingerprint of the live object an action addresses.
#[must_use]
pub(crate) fn fingerprint_firewall(
    action: &FirewallAction,
    live_node: Option<&str>,
    live_kind: Option<&str>,
    body: Option<&Value>,
) -> String {
    let (node, kind) = match action.scope.as_str() {
        "guest" => (live_node, live_kind),
        "node" => (action.node.as_deref(), None),
        _ => (None, None),
    };
    let name = match action.object.as_str() {
        "group" | "group_rule" | "ipset" | "ipset_entry" | "alias" => action.name.as_deref(),
        _ => None,
    };
    rust_proxmoxmcp_core::fingerprint::firewall_fingerprint(
        &rust_proxmoxmcp_core::fingerprint::FirewallFingerprint {
            cluster: &action.cluster,
            scope: &action.scope,
            object: &action.object,
            node,
            vmid: action.vmid,
            guest_kind: kind,
            name,
            body,
        },
    )
}

/// Preview lines for protection and a waiver.
///
/// Cluster and node firewall objects have no guest, so both lines say so.
#[must_use]
pub(crate) fn firewall_protection_lines(
    scope: &str,
    protected: bool,
    summary: &str,
    override_: &Override,
) -> (String, String) {
    if scope != "guest" {
        return (
            "  protected  n/a".to_owned(),
            "  waiver     none".to_owned(),
        );
    }
    let protected_line = if protected {
        format!("  protected  yes — {summary}")
    } else {
        "  protected  no".to_owned()
    };
    let waiver_line = match override_ {
        Override::None => "  waiver     none".to_owned(),
        Override::Waiver { reason, ticket, .. } => match ticket {
            Some(ticket) => format!("  waiver     {ticket} — {reason}"),
            None => format!("  waiver     {reason}"),
        },
        Override::LabMode => "  waiver     lab-mode".to_owned(),
    };
    (protected_line, waiver_line)
}

/// Render the preview an approver reviews.
#[must_use]
pub(crate) fn render_firewall_preview(
    action: &FirewallAction,
    observed: &ObservedFirewall,
    protected_line: &str,
    waiver_line: &str,
) -> String {
    let verb = match action.op.as_str() {
        "create" => "CREATE",
        "update" => "UPDATE",
        "delete" => "DELETE",
        other => other,
    };
    let place = match action.scope.as_str() {
        "guest" => format!(
            "guest {} ({}) of cluster {}",
            action
                .vmid
                .map(|vmid| vmid.to_string())
                .unwrap_or_else(|| "?".to_owned()),
            action.guest_type.as_deref().unwrap_or("guest"),
            action.cluster
        ),
        "node" => format!(
            "node {} of cluster {}",
            action.node.as_deref().unwrap_or("?"),
            action.cluster
        ),
        _ => format!("cluster {}", action.cluster),
    };
    let mut lines = vec![format!("{verb} firewall {} on {place}", action.object)];
    push_proposed(&mut lines, action);
    lines.push(current_summary(action, observed));
    lines.push(protected_line.to_owned());
    lines.push(waiver_line.to_owned());
    lines.join("\n")
}

fn validate_firewall_action(
    action: &FirewallAction,
    require_guest_type: bool,
) -> Result<(), String> {
    validate_identity(action)?;
    validate_guest_type(action, require_guest_type)?;
    validate_digest_field(action)?;
    match action.object.as_str() {
        "rule" | "group_rule" => validate_rule_action(action),
        "options" => validate_options_action(action),
        "group" | "ipset" => validate_named_container(action),
        "ipset_entry" => validate_ipset_entry(action),
        "alias" => validate_alias(action),
        other => Err(format!("unknown firewall object '{other}'")),
    }
}

fn validate_identity(action: &FirewallAction) -> Result<(), String> {
    if action.cluster.is_empty()
        || action.cluster.len() > 128
        || action
            .cluster
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == ':')
    {
        return Err("cluster name is not usable".to_owned());
    }
    match action.scope.as_str() {
        "cluster" | "node" | "guest" => {}
        other => return Err(format!("unknown firewall scope '{other}'")),
    }
    match action.object.as_str() {
        "rule" | "options" | "group" | "group_rule" | "ipset" | "ipset_entry" | "alias" => {}
        other => return Err(format!("unknown firewall object '{other}'")),
    }
    if !scope_supports(&action.scope, &action.object) {
        return Err(format!(
            "firewall {} is not available at {} scope",
            action.object, action.scope
        ));
    }
    if !op_supported(&action.object, &action.op) {
        return Err(format!(
            "firewall {} does not support '{}'",
            action.object, action.op
        ));
    }
    match (action.scope.as_str(), action.node.as_deref()) {
        ("node", Some(node)) => validate_node_name(node)?,
        ("node", None) => return Err("node firewall change requires node".to_owned()),
        (_, Some(_)) => return Err("node is only valid for node firewall scope".to_owned()),
        _ => {}
    }
    match (action.scope.as_str(), action.vmid) {
        ("guest", Some(_)) => {}
        ("guest", None) => return Err("guest firewall change requires vmid".to_owned()),
        (_, Some(_)) => return Err("vmid is only valid for guest firewall scope".to_owned()),
        _ => {}
    }
    let needs_name = matches!(
        action.object.as_str(),
        "group" | "group_rule" | "ipset" | "ipset_entry" | "alias"
    );
    match (needs_name, action.name.as_deref()) {
        (true, Some(name)) => validate_firewall_name(name, "name")?,
        (true, None) => return Err("this firewall object requires name".to_owned()),
        (false, Some(_)) => return Err("this firewall object does not take name".to_owned()),
        (false, None) => {}
    }
    let rule_object = matches!(action.object.as_str(), "rule" | "group_rule");
    match (rule_object, action.pos, action.op.as_str()) {
        (false, Some(_), _) => return Err("pos is only valid on a firewall rule".to_owned()),
        (true, None, "update" | "delete") => {
            return Err(format!("{} requires pos", action.op));
        }
        _ => {}
    }
    Ok(())
}

fn validate_lookup_identity(args: &FirewallChangeSetArgs) -> Result<(), String> {
    let action = lookup_action(args);
    if action.cluster.is_empty()
        || action
            .cluster
            .chars()
            .any(|c| c.is_whitespace() || c == '/' || c == ':')
    {
        return Err("cluster name is not usable".to_owned());
    }
    match action.scope.as_str() {
        "cluster" | "node" | "guest" => {}
        other => return Err(format!("unknown firewall scope '{other}'")),
    }
    match action.object.as_str() {
        "rule" | "options" | "group" | "group_rule" | "ipset" | "ipset_entry" | "alias" => {}
        other => return Err(format!("unknown firewall object '{other}'")),
    }
    if !scope_supports(&action.scope, &action.object) {
        return Err(format!(
            "firewall {} is not available at {} scope",
            action.object, action.scope
        ));
    }
    match (action.scope.as_str(), action.node.as_deref()) {
        ("node", Some(node)) => validate_node_name(node)?,
        ("node", None) => return Err("node firewall change requires node".to_owned()),
        (_, Some(_)) => return Err("node is only valid for node firewall scope".to_owned()),
        _ => {}
    }
    match (action.scope.as_str(), action.vmid) {
        ("guest", Some(_)) => {}
        ("guest", None) => return Err("guest firewall change requires vmid".to_owned()),
        (_, Some(_)) => return Err("vmid is only valid for guest firewall scope".to_owned()),
        _ => {}
    }
    let needs_name = matches!(
        action.object.as_str(),
        "group" | "group_rule" | "ipset" | "ipset_entry" | "alias"
    );
    match (needs_name, action.name.as_deref()) {
        (true, Some(name)) => validate_firewall_name(name, "name")?,
        (true, None) => return Err("this firewall object requires name".to_owned()),
        (false, Some(_)) => return Err("this firewall object does not take name".to_owned()),
        _ => {}
    }
    Ok(())
}

fn validate_guest_type(action: &FirewallAction, require_guest_type: bool) -> Result<(), String> {
    match (
        action.scope.as_str(),
        action.guest_type.as_deref(),
        require_guest_type,
    ) {
        ("guest", Some("qemu" | "lxc"), _) | ("guest", None, false) => Ok(()),
        ("guest", None, true) => Err("guest firewall change has no guest type".to_owned()),
        ("guest", Some(other), _) => Err(format!("unknown guest type '{other}'")),
        (_, Some(_), _) => Err("guest type is only valid for a guest firewall change".to_owned()),
        _ => Ok(()),
    }
}

fn validate_digest_field(action: &FirewallAction) -> Result<(), String> {
    if let Some(digest) = action.digest.as_deref()
        && (digest.is_empty()
            || digest.len() > 128
            || !digest.chars().all(|c| c.is_ascii_alphanumeric()))
    {
        return Err("firewall digest is not usable".to_owned());
    }
    Ok(())
}

fn validate_rule_action(action: &FirewallAction) -> Result<(), String> {
    require_absent(action.cidr.is_some(), "cidr", &action.op)?;
    require_absent(action.nomatch.is_some(), "nomatch", &action.op)?;
    require_absent(action.options.is_some(), "options", &action.op)?;
    match action.op.as_str() {
        "create" => {
            validate_optional_comment(action)?;
            validate_rule_fields(action.rule.as_ref(), true)?;
            Ok(())
        }
        "update" => {
            validate_optional_comment(action)?;
            validate_rule_fields(action.rule.as_ref(), false)?;
            if !rule_changes_something(action) {
                return Err("update changes nothing".to_owned());
            }
            Ok(())
        }
        "delete" => {
            require_absent(action.comment.is_some(), "comment", "delete")?;
            require_absent(action.enable.is_some(), "enable", "delete")?;
            require_absent(action.rule.is_some(), "rule", "delete")?;
            Ok(())
        }
        other => Err(format!("firewall rule does not support '{other}'")),
    }
}

fn validate_options_action(action: &FirewallAction) -> Result<(), String> {
    require_absent(action.comment.is_some(), "comment", &action.op)?;
    require_absent(action.enable.is_some(), "enable", &action.op)?;
    require_absent(action.nomatch.is_some(), "nomatch", &action.op)?;
    require_absent(action.cidr.is_some(), "cidr", &action.op)?;
    require_absent(action.rule.is_some(), "rule", &action.op)?;
    let Some(options) = action.options.as_ref() else {
        return Err("options update requires options".to_owned());
    };
    if options.is_empty() {
        return Err("options update changes nothing".to_owned());
    }
    if action.scope != "guest"
        && (options.dhcp.is_some()
            || options.ipfilter.is_some()
            || options.macfilter.is_some()
            || options.ndp.is_some()
            || options.radv.is_some())
    {
        return Err(
            "dhcp, ipfilter, macfilter, ndp and radv are guest firewall options".to_owned(),
        );
    }
    if let Some(policy) = options.policy_in.as_deref() {
        validate_policy(policy, "policy_in")?;
    }
    if let Some(policy) = options.policy_out.as_deref() {
        validate_policy(policy, "policy_out")?;
    }
    if let Some(policy) = options.policy_forward.as_deref() {
        validate_policy(policy, "policy_forward")?;
    }
    if let Some(level) = options.log_level_in.as_deref() {
        validate_log_level(level, "log_level_in")?;
    }
    if let Some(level) = options.log_level_out.as_deref() {
        validate_log_level(level, "log_level_out")?;
    }
    if let Some(level) = options.log_level_forward.as_deref() {
        validate_log_level(level, "log_level_forward")?;
    }
    Ok(())
}

fn validate_named_container(action: &FirewallAction) -> Result<(), String> {
    require_absent(action.cidr.is_some(), "cidr", &action.op)?;
    require_absent(action.enable.is_some(), "enable", &action.op)?;
    require_absent(action.nomatch.is_some(), "nomatch", &action.op)?;
    require_absent(action.rule.is_some(), "rule", &action.op)?;
    require_absent(action.options.is_some(), "options", &action.op)?;
    match action.op.as_str() {
        "create" => validate_optional_comment(action),
        "delete" => require_absent(action.comment.is_some(), "comment", "delete"),
        other => Err(format!(
            "firewall {} does not support '{other}'",
            action.object
        )),
    }
}

fn validate_ipset_entry(action: &FirewallAction) -> Result<(), String> {
    require_absent(action.enable.is_some(), "enable", &action.op)?;
    require_absent(action.rule.is_some(), "rule", &action.op)?;
    require_absent(action.options.is_some(), "options", &action.op)?;
    let cidr = action
        .cidr
        .as_deref()
        .ok_or_else(|| "IPSet entry requires an address".to_owned())?;
    validate_cidr(cidr)?;
    match action.op.as_str() {
        "create" => validate_optional_comment(action),
        "update" => {
            if !is_single_path_segment(cidr) {
                return Err(PREFIXED_ENTRY.to_owned());
            }
            validate_optional_comment(action)?;
            if action.comment.is_none() && action.nomatch.is_none() {
                return Err("update changes nothing".to_owned());
            }
            Ok(())
        }
        "delete" => {
            if !is_single_path_segment(cidr) {
                return Err(PREFIXED_ENTRY.to_owned());
            }
            require_absent(action.comment.is_some(), "comment", "delete")?;
            require_absent(action.nomatch.is_some(), "nomatch", "delete")?;
            Ok(())
        }
        other => Err(format!("firewall ipset_entry does not support '{other}'")),
    }
}

fn validate_alias(action: &FirewallAction) -> Result<(), String> {
    require_absent(action.enable.is_some(), "enable", &action.op)?;
    require_absent(action.nomatch.is_some(), "nomatch", &action.op)?;
    require_absent(action.rule.is_some(), "rule", &action.op)?;
    require_absent(action.options.is_some(), "options", &action.op)?;
    match action.op.as_str() {
        "create" => {
            let cidr = action
                .cidr
                .as_deref()
                .ok_or_else(|| "alias create requires an address".to_owned())?;
            validate_cidr(cidr)?;
            validate_optional_comment(action)
        }
        "update" => {
            if let Some(cidr) = action.cidr.as_deref() {
                validate_cidr(cidr)?;
            }
            validate_optional_comment(action)?;
            if action.cidr.is_none() && action.comment.is_none() {
                return Err("update changes nothing".to_owned());
            }
            Ok(())
        }
        "delete" => {
            require_absent(action.cidr.is_some(), "cidr", "delete")?;
            require_absent(action.comment.is_some(), "comment", "delete")
        }
        other => Err(format!("firewall alias does not support '{other}'")),
    }
}

fn validate_rule_fields(rule: Option<&FirewallRuleFields>, create: bool) -> Result<(), String> {
    let Some(rule) = rule else {
        if create {
            return Err("rule create requires rule".to_owned());
        }
        return Ok(());
    };
    match (create, rule.rule_type.as_deref(), rule.action.as_deref()) {
        (true, None, _) | (true, _, None) => {
            return Err("rule create requires type and action".to_owned());
        }
        (_, Some(rule_type), action) => {
            validate_rule_type(rule_type, action)?;
        }
        (_, None, Some(_)) => {
            return Err("rule action requires type".to_owned());
        }
        (_, None, None) => {}
    }
    if let Some(proto) = rule.proto.as_deref() {
        validate_proto(proto)?;
    }
    if let Some(port) = rule.dport.as_deref() {
        validate_port(port, "dport")?;
    }
    if let Some(port) = rule.sport.as_deref() {
        validate_port(port, "sport")?;
    }
    if let Some(level) = rule.log.as_deref() {
        validate_log_level(level, "log")?;
    }
    if let Some(iface) = rule.iface.as_deref() {
        validate_iface(iface)?;
    }
    if let Some(name) = rule.fw_macro.as_deref() {
        validate_firewall_name(name, "macro")?;
    }
    if let Some(icmp) = rule.icmp_type.as_deref() {
        validate_token(icmp, "icmp_type")?;
    }
    if let Some(source) = rule.source.as_deref() {
        validate_address_ref(source, "source")?;
    }
    if let Some(dest) = rule.dest.as_deref() {
        validate_address_ref(dest, "dest")?;
    }
    Ok(())
}

fn validate_rule_type(rule_type: &str, action: Option<&str>) -> Result<(), String> {
    match rule_type {
        "in" | "out" | "forward" => {
            if let Some(action) = action {
                validate_policy(action, "action")?;
            }
            Ok(())
        }
        "group" => {
            if let Some(action) = action {
                validate_firewall_name(action, "action")?;
            }
            Ok(())
        }
        other => Err(format!(
            "rule type '{other}' is not in, out, forward or group"
        )),
    }
}

fn validate_optional_comment(action: &FirewallAction) -> Result<(), String> {
    if let Some(comment) = action.comment.as_deref() {
        validate_comment(comment)?;
    }
    Ok(())
}

fn validate_comment(comment: &str) -> Result<(), String> {
    if comment.chars().count() > 512 {
        return Err("comment is longer than 512 characters".to_owned());
    }
    if comment.chars().any(char::is_control) {
        return Err("comment contains a control character".to_owned());
    }
    Ok(())
}

fn validate_firewall_name(name: &str, field: &str) -> Result<(), String> {
    let ok = (1..=64).contains(&name.len())
        && name.starts_with(|c: char| c.is_ascii_alphabetic())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        return Err(format!(
            "{field} must start with a letter and contain only letters, digits, '_' and '-'"
        ));
    }
    rust_proxmoxmcp_core::guests::validate_path_segment(name, field)
        .map_err(|error| error.to_string())
}

fn validate_node_name(node: &str) -> Result<(), String> {
    let ok = (1..=64).contains(&node.len())
        && node.starts_with(|c: char| c.is_ascii_alphanumeric())
        && node
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-');
    if !ok {
        return Err("node name is not usable".to_owned());
    }
    rust_proxmoxmcp_core::guests::validate_path_segment(node, "node")
        .map_err(|error| error.to_string())
}

fn validate_cidr(value: &str) -> Result<(), String> {
    if value.matches('/').count() > 1 {
        return Err("address is not a single prefix".to_owned());
    }
    let (addr, prefix) = match value.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix)),
        None => (value, None),
    };
    if addr.parse::<std::net::Ipv4Addr>().is_ok() {
        return check_prefix(prefix, 32);
    }
    if addr.parse::<std::net::Ipv6Addr>().is_ok() {
        return check_prefix(prefix, 128);
    }
    Err("address is not an IPv4 or IPv6 address".to_owned())
}

fn check_prefix(prefix: Option<&str>, max: u8) -> Result<(), String> {
    let Some(prefix) = prefix else {
        return Ok(());
    };
    let n: u8 = prefix
        .parse()
        .map_err(|_| "prefix is not a number".to_owned())?;
    if n > max {
        return Err(format!("prefix is larger than {max}"));
    }
    Ok(())
}

fn is_single_path_segment(cidr: &str) -> bool {
    !cidr.contains('/') && rust_proxmoxmcp_core::guests::validate_path_segment(cidr, "cidr").is_ok()
}

fn validate_policy(value: &str, field: &str) -> Result<(), String> {
    match value {
        "ACCEPT" | "DROP" | "REJECT" => Ok(()),
        _ => Err(format!("{field} must be ACCEPT, DROP or REJECT")),
    }
}

fn validate_log_level(value: &str, field: &str) -> Result<(), String> {
    if LOG_LEVELS.contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} is not a firewall log level"))
    }
}

fn validate_proto(value: &str) -> Result<(), String> {
    if PROTOS.contains(&value) {
        return Ok(());
    }
    match value.parse::<u16>() {
        Ok(number) if number <= 255 => Ok(()),
        _ => Err("proto is not a supported protocol".to_owned()),
    }
}

fn validate_port(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 {
        return Err(format!("{field} is empty or too long"));
    }
    for part in value.split(',') {
        let mut sides = part.split(':');
        let Some(start) = sides.next() else {
            return Err(format!("{field} is not a port"));
        };
        let end = sides.next();
        if sides.next().is_some() || start.parse::<u16>().is_err() {
            return Err(format!("{field} is not a port"));
        }
        if let Some(end) = end
            && end.parse::<u16>().is_err()
        {
            return Err(format!("{field} is not a port"));
        }
    }
    Ok(())
}

fn validate_iface(value: &str) -> Result<(), String> {
    let ok = (1..=32).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' || c == ':');
    if ok {
        Ok(())
    } else {
        Err("iface is not usable".to_owned())
    }
}

fn validate_token(value: &str, field: &str) -> Result<(), String> {
    let ok = (1..=32).contains(&value.len())
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if ok {
        Ok(())
    } else {
        Err(format!("{field} is not usable"))
    }
}

fn validate_address_ref(value: &str, field: &str) -> Result<(), String> {
    if value == "guest" {
        return Ok(());
    }
    if let Some(name) = value.strip_prefix('+') {
        return validate_firewall_name(name, field);
    }
    if value.contains('/')
        || value.parse::<std::net::Ipv4Addr>().is_ok()
        || value.parse::<std::net::Ipv6Addr>().is_ok()
    {
        return validate_cidr(value);
    }
    validate_firewall_name(value, field)
}

fn scope_supports(scope: &str, object: &str) -> bool {
    matches!(
        (scope, object),
        (
            "cluster",
            "rule" | "options" | "group" | "group_rule" | "ipset" | "ipset_entry" | "alias"
        ) | ("node", "rule" | "options")
            | (
                "guest",
                "rule" | "options" | "ipset" | "ipset_entry" | "alias"
            )
    )
}

fn op_supported(object: &str, op: &str) -> bool {
    matches!(
        (object, op),
        ("options", "update")
            | ("group" | "ipset", "create" | "delete")
            | (
                "rule" | "group_rule" | "ipset_entry" | "alias",
                "create" | "update" | "delete"
            )
    )
}

fn require_absent(present: bool, field: &str, op: &str) -> Result<(), String> {
    if present {
        Err(format!("{op} does not take {field}"))
    } else {
        Ok(())
    }
}

fn rule_changes_something(action: &FirewallAction) -> bool {
    action.comment.is_some()
        || action.enable.is_some()
        || action.rule.as_ref().is_some_and(|rule| !rule.is_empty())
}

fn object_label(action: &FirewallAction) -> String {
    if action.object == "ipset_entry" {
        action.cidr.clone().unwrap_or_default()
    } else {
        action.name.clone().unwrap_or_default()
    }
}

fn lookup_action(args: &FirewallChangeSetArgs) -> FirewallAction {
    FirewallAction {
        op: "update".to_owned(),
        object: args.object.clone(),
        scope: args.scope.clone(),
        cluster: args.cluster.clone(),
        node: args.node.clone(),
        vmid: args.vmid,
        guest_type: None,
        name: args.name.clone(),
        pos: None,
        cidr: None,
        comment: None,
        enable: None,
        nomatch: None,
        digest: None,
        rule: None,
        options: None,
    }
}

fn rule_from_args(args: &FirewallRuleArgs) -> FirewallRuleFields {
    FirewallRuleFields {
        action: args.action.clone(),
        rule_type: args.rule_type.clone(),
        dest: args.dest.clone(),
        dport: args.dport.clone(),
        proto: args.proto.clone(),
        source: args.source.clone(),
        sport: args.sport.clone(),
        iface: args.iface.clone(),
        fw_macro: args.fw_macro.clone(),
        log: args.log.clone(),
        icmp_type: args.icmp_type.clone(),
    }
}

fn options_from_args(args: &FirewallOptionArgs) -> FirewallOptionFields {
    FirewallOptionFields {
        enable: args.enable,
        policy_in: args.policy_in.clone(),
        policy_out: args.policy_out.clone(),
        policy_forward: args.policy_forward.clone(),
        dhcp: args.dhcp,
        ipfilter: args.ipfilter,
        macfilter: args.macfilter,
        ndp: args.ndp,
        radv: args.radv,
        log_level_in: args.log_level_in.clone(),
        log_level_out: args.log_level_out.clone(),
        log_level_forward: args.log_level_forward.clone(),
    }
}

fn push_proposed(lines: &mut Vec<String>, action: &FirewallAction) {
    if let Some(name) = action.name.as_deref() {
        lines.push(format!("  name    {name}"));
    }
    if let Some(cidr) = action.cidr.as_deref() {
        lines.push(format!("  address {cidr}"));
    }
    if let Some(pos) = action.pos {
        lines.push(format!("  pos     {pos}"));
    }
    if let Some(rule) = action.rule.as_ref() {
        push_field(lines, "type", rule.rule_type.as_deref());
        push_field(lines, "action", rule.action.as_deref());
        push_field(lines, "proto", rule.proto.as_deref());
        push_field(lines, "source", rule.source.as_deref());
        push_field(lines, "dest", rule.dest.as_deref());
        push_field(lines, "sport", rule.sport.as_deref());
        push_field(lines, "dport", rule.dport.as_deref());
        push_field(lines, "iface", rule.iface.as_deref());
        push_field(lines, "macro", rule.fw_macro.as_deref());
        push_field(lines, "log", rule.log.as_deref());
        push_field(lines, "icmp", rule.icmp_type.as_deref());
    }
    if let Some(options) = action.options.as_ref() {
        if let Some(enable) = options.enable {
            lines.push(format!("  enable  {enable}"));
        }
        push_field(lines, "policy_in", options.policy_in.as_deref());
        push_field(lines, "policy_out", options.policy_out.as_deref());
        push_field(lines, "policy_forward", options.policy_forward.as_deref());
        push_flag(lines, "dhcp", options.dhcp);
        push_flag(lines, "ipfilter", options.ipfilter);
        push_flag(lines, "macfilter", options.macfilter);
        push_flag(lines, "ndp", options.ndp);
        push_flag(lines, "radv", options.radv);
        push_field(lines, "log_level_in", options.log_level_in.as_deref());
        push_field(lines, "log_level_out", options.log_level_out.as_deref());
        push_field(
            lines,
            "log_level_forward",
            options.log_level_forward.as_deref(),
        );
    }
    if let Some(enable) = action.enable {
        lines.push(format!("  enable  {enable}"));
    }
    if let Some(nomatch) = action.nomatch {
        lines.push(format!("  nomatch {nomatch}"));
    }
    if let Some(comment) = action.comment.as_deref() {
        let redacted = mecmcp_redact::redact_text(comment);
        lines.push(format!("  comment {redacted}"));
    }
    if let Some(digest) = action.digest.as_deref() {
        lines.push(format!("  digest  {digest}"));
    }
}

fn push_field(lines: &mut Vec<String>, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        lines.push(format!("  {label:<7} {value}"));
    }
}

fn push_flag(lines: &mut Vec<String>, label: &str, value: Option<bool>) {
    if let Some(value) = value {
        lines.push(format!("  {label:<7} {value}"));
    }
}

fn current_summary(action: &FirewallAction, observed: &ObservedFirewall) -> String {
    match action.object.as_str() {
        "rule" | "group_rule" => {
            let count = array_len(observed.body.as_ref());
            match addressed_rule(action, observed) {
                Some(item) => format!(
                    "  current  ruleset entries: {count}; addressed {}",
                    redact_json(&item)
                ),
                None => format!("  current  ruleset entries: {count}; addressed rule: none"),
            }
        }
        "ipset_entry" => {
            let count = array_len(observed.body.as_ref());
            match addressed_entry(action, observed) {
                Some(item) => format!(
                    "  current  entries: {count}; addressed {}",
                    redact_json(&item)
                ),
                None => format!("  current  entries: {count}; addressed entry: none"),
            }
        }
        "options" => format!(
            "  current  {}",
            redact_json(observed.body.as_ref().unwrap_or(&Value::Null))
        ),
        _ => match &observed.body {
            Some(item) => format!("  current  {}", redact_json(item)),
            None => "  current  absent".to_owned(),
        },
    }
}

fn array_len(body: Option<&Value>) -> usize {
    body.and_then(Value::as_array).map(Vec::len).unwrap_or(0)
}

fn addressed_rule(action: &FirewallAction, observed: &ObservedFirewall) -> Option<Value> {
    let pos = action.pos?;
    observed
        .body
        .as_ref()?
        .as_array()?
        .iter()
        .find(|rule| rule.get("pos").and_then(Value::as_u64) == Some(u64::from(pos)))
        .cloned()
}

fn addressed_entry(action: &FirewallAction, observed: &ObservedFirewall) -> Option<Value> {
    let cidr = action.cidr.as_deref()?;
    observed
        .body
        .as_ref()?
        .as_array()?
        .iter()
        .find(|entry| entry.get("cidr").and_then(Value::as_str) == Some(cidr))
        .cloned()
}

fn redact_json(value: &Value) -> String {
    let mut copy = value.clone();
    super::redact_free_text_fields(&mut copy);
    serde_json::to_string(&copy).unwrap_or_else(|_| "<unreadable>".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_proxmoxmcp_core::firewall::{FirewallAction, FirewallRuleFields, ObservedFirewall};
    use rust_proxmoxmcp_core::protect::Override;

    fn rule_action(op: &str) -> FirewallAction {
        FirewallAction {
            op: op.to_owned(),
            object: "rule".to_owned(),
            scope: "cluster".to_owned(),
            cluster: "pve3".to_owned(),
            node: None,
            vmid: None,
            guest_type: None,
            name: None,
            pos: None,
            cidr: None,
            comment: None,
            enable: None,
            nomatch: None,
            digest: None,
            rule: Some(FirewallRuleFields {
                action: Some("ACCEPT".to_owned()),
                rule_type: Some("in".to_owned()),
                proto: Some("tcp".to_owned()),
                dport: Some("22".to_owned()),
                ..FirewallRuleFields::default()
            }),
            options: None,
        }
    }

    #[test]
    fn device_keys_lock_the_ruleset_group_or_ipset() {
        let mut rules = rule_action("create");
        assert_eq!(
            firewall_device(&rules).expect("device"),
            "pve3/fw:cluster:rules"
        );
        rules.scope = "node".to_owned();
        rules.node = Some("pve2".to_owned());
        assert_eq!(
            firewall_device(&rules).expect("device"),
            "pve3/fw:node:pve2:rules"
        );
        rules.scope = "guest".to_owned();
        rules.node = None;
        rules.vmid = Some(617);
        assert_eq!(
            firewall_device(&rules).expect("device"),
            "pve3/fw:guest:617:rules"
        );

        let group = FirewallAction {
            object: "group_rule".to_owned(),
            name: Some("web".to_owned()),
            scope: "cluster".to_owned(),
            ..rules
        };
        assert_eq!(
            firewall_device(&group).expect("device"),
            "pve3/fw:cluster:group:web"
        );

        let ipset = FirewallAction {
            object: "ipset_entry".to_owned(),
            scope: "guest".to_owned(),
            vmid: Some(617),
            name: Some("block".to_owned()),
            ..group
        };
        assert_eq!(
            firewall_device(&ipset).expect("device"),
            "pve3/fw:guest:617:ipset:block"
        );
    }

    #[test]
    fn a_prefixed_ipset_entry_cannot_be_updated_or_deleted() {
        let mut action = FirewallAction {
            op: "delete".to_owned(),
            object: "ipset_entry".to_owned(),
            scope: "cluster".to_owned(),
            cluster: "pve3".to_owned(),
            name: Some("block".to_owned()),
            cidr: Some("192.0.2.0/24".to_owned()),
            ..rule_action("delete")
        };
        action.rule = None;
        action.pos = None;
        let error = validate_firewall_action(&action, false).expect_err("prefix refused");
        assert!(error.contains("single path segment"), "{error}");

        action.op = "create".to_owned();
        validate_firewall_action(&action, false).expect("create may carry a prefix");
    }

    #[test]
    fn node_scope_has_no_alias() {
        let action = FirewallAction {
            op: "create".to_owned(),
            object: "alias".to_owned(),
            scope: "node".to_owned(),
            cluster: "pve3".to_owned(),
            node: Some("pve2".to_owned()),
            name: Some("web".to_owned()),
            cidr: Some("192.0.2.1".to_owned()),
            ..rule_action("create")
        };
        let error = validate_firewall_action(&action, false).expect_err("node alias");
        assert!(error.contains("not available"), "{error}");
    }

    #[test]
    fn preview_redacts_a_comment_and_names_the_change() {
        let mut action = rule_action("create");
        action.comment = Some(
            "re-provisioned 2026-09-27 (ticket OPS-4110); backup admin password: \
             FAKE-api-token-9f8e7d6c5b4a3210"
                .to_owned(),
        );
        let observed = ObservedFirewall {
            body: Some(serde_json::json!([])),
            digest: None,
            item_present: false,
        };
        let (protected, waiver) =
            firewall_protection_lines("cluster", false, "unprotected", &Override::None);
        let preview = render_firewall_preview(&action, &observed, &protected, &waiver);
        assert!(preview.contains("CREATE"), "{preview}");
        assert!(preview.contains("ACCEPT"), "{preview}");
        assert!(
            !preview.contains("FAKE-api-token-9f8e7d6c5b4a3210"),
            "{preview}"
        );
        assert!(preview.contains("protected  n/a"), "{preview}");
    }
}
