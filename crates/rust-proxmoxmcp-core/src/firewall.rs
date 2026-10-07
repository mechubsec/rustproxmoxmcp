//! Proxmox firewall reads and writes used by the change-set flow.
//!
//! Nothing here decides whether a write may run. The server plans, approves
//! and applies; these functions only read the current object and, once that
//! flow has claimed an approved change set, send the already-validated body.

use crate::client::ProxmoxClient;
use crate::error::ProxmoxError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Where a firewall object lives.
///
/// Node firewall has rules and options only. Aliases, IPSets and security
/// groups exist at cluster scope and, except for security groups, on a guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallScope {
    /// `/cluster/firewall`.
    Cluster,
    /// `/nodes/{node}/firewall`.
    Node,
    /// `/nodes/{node}/{kind}/{vmid}/firewall`.
    Guest,
}

impl FirewallScope {
    /// Parse the scope name recorded on a change set.
    ///
    /// # Errors
    ///
    /// Returns [`ProxmoxError::Malformed`] for anything other than `cluster`,
    /// `node` or `guest`.
    pub fn parse(value: &str) -> Result<Self, ProxmoxError> {
        match value {
            "cluster" => Ok(Self::Cluster),
            "node" => Ok(Self::Node),
            "guest" => Ok(Self::Guest),
            other => Err(ProxmoxError::Malformed(format!(
                "unknown firewall scope '{other}'"
            ))),
        }
    }
}

/// The firewall object a change addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallObject {
    /// A rule in a cluster, node, guest or security-group ruleset.
    Rule,
    /// The options object. It is updated, never created or deleted.
    Options,
    /// A cluster security group.
    Group,
    /// A rule inside a cluster security group.
    GroupRule,
    /// An IPSet (cluster or guest).
    Ipset,
    /// One CIDR entry in an IPSet.
    IpsetEntry,
    /// An address alias (cluster or guest).
    Alias,
}

impl FirewallObject {
    /// Parse the object name recorded on a change set.
    ///
    /// # Errors
    ///
    /// Returns [`ProxmoxError::Malformed`] for an unknown object.
    pub fn parse(value: &str) -> Result<Self, ProxmoxError> {
        match value {
            "rule" => Ok(Self::Rule),
            "options" => Ok(Self::Options),
            "group" => Ok(Self::Group),
            "group_rule" => Ok(Self::GroupRule),
            "ipset" => Ok(Self::Ipset),
            "ipset_entry" => Ok(Self::IpsetEntry),
            "alias" => Ok(Self::Alias),
            other => Err(ProxmoxError::Malformed(format!(
                "unknown firewall object '{other}'"
            ))),
        }
    }

    /// The wire name stored on a change-set action.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Options => "options",
            Self::Group => "group",
            Self::GroupRule => "group_rule",
            Self::Ipset => "ipset",
            Self::IpsetEntry => "ipset_entry",
            Self::Alias => "alias",
        }
    }
}

/// Fields a firewall rule create or update may set.
///
/// Every member is optional because an update names only what it changes.
/// `rule_type` is Proxmox's `type` (`in`, `out`, `forward`, `group`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallRuleFields {
    /// `ACCEPT`, `DROP`, `REJECT`, or a security-group name when `rule_type` is `group`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// Proxmox rule type: `in`, `out`, `forward` or `group`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_type: Option<String>,
    /// Destination address, alias or IPSet reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest: Option<String>,
    /// Destination port or range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dport: Option<String>,
    /// IP protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proto: Option<String>,
    /// Source address, alias or IPSet reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Source port or range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sport: Option<String>,
    /// Interface name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    /// Proxmox firewall macro name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fw_macro: Option<String>,
    /// Log level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    /// ICMP type name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<String>,
}

impl FirewallRuleFields {
    /// Whether every field is unset.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.action.is_none()
            && self.rule_type.is_none()
            && self.dest.is_none()
            && self.dport.is_none()
            && self.proto.is_none()
            && self.source.is_none()
            && self.sport.is_none()
            && self.iface.is_none()
            && self.fw_macro.is_none()
            && self.log.is_none()
            && self.icmp_type.is_none()
    }
}

/// Fields an options update may set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallOptionFields {
    /// Whether the firewall is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    /// Default inbound policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_in: Option<String>,
    /// Default outbound policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_out: Option<String>,
    /// Default forward policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_forward: Option<String>,
    /// Honour DHCP on a guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dhcp: Option<bool>,
    /// Restrict the guest to its configured addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipfilter: Option<bool>,
    /// Restrict the guest to its configured MAC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macfilter: Option<bool>,
    /// Allow NDP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ndp: Option<bool>,
    /// Allow router advertisements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub radv: Option<bool>,
    /// Inbound log level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level_in: Option<String>,
    /// Outbound log level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level_out: Option<String>,
    /// Forward log level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level_forward: Option<String>,
}

impl FirewallOptionFields {
    /// Whether every field is unset.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.enable.is_none()
            && self.policy_in.is_none()
            && self.policy_out.is_none()
            && self.policy_forward.is_none()
            && self.dhcp.is_none()
            && self.ipfilter.is_none()
            && self.macfilter.is_none()
            && self.ndp.is_none()
            && self.radv.is_none()
            && self.log_level_in.is_none()
            && self.log_level_out.is_none()
            && self.log_level_forward.is_none()
    }
}

/// One firewall change, as stored on the change set.
///
/// The digest covers this value. Apply dispatches on it, not on a second copy
/// of the caller's arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallAction {
    /// `create`, `update` or `delete`.
    pub op: String,
    /// Object family. See [`FirewallObject::as_str`].
    pub object: String,
    /// `cluster`, `node` or `guest`.
    pub scope: String,
    /// Inventory cluster name.
    pub cluster: String,
    /// Node name, for node scope only. A guest's node is resolved at plan and
    /// again at apply and is not stored here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    /// Guest id, for guest scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vmid: Option<u32>,
    /// `qemu` or `lxc`, recorded at plan so the digest names which API the
    /// apply will call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_type: Option<String>,
    /// Group, IPSet or alias name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Rule position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pos: Option<u32>,
    /// Alias or IPSet-entry address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Free-text comment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Whether a rule is enabled. Options use [`FirewallOptionFields::enable`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    /// IPSet entry `nomatch` flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nomatch: Option<bool>,
    /// Proxmox optimistic-concurrency token, copied from the live object at
    /// plan time. Never taken from the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// Rule fields, for `rule` and `group_rule`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<FirewallRuleFields>,
    /// Options fields, for `options`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<FirewallOptionFields>,
}

/// What a read of the current firewall object found.
#[derive(Debug, Clone, PartialEq)]
pub struct ObservedFirewall {
    /// The body a fingerprint covers. `None` when a named object is absent.
    pub body: Option<Value>,
    /// Digest of the specific item an update or delete will name, if Proxmox sent one.
    pub digest: Option<String>,
    /// Whether the addressed item (rule position, alias, IPSet, group, entry) exists.
    pub item_present: bool,
}

/// The node and guest type resolved for this call.
///
/// Guest scope needs both. Cluster scope uses neither. Node scope uses the
/// node stored on the action.
#[derive(Debug, Clone, Copy, Default)]
pub struct LiveFirewall<'a> {
    /// Node the guest is on right now.
    pub node: Option<&'a str>,
    /// `qemu` or `lxc`.
    pub guest_kind: Option<&'a str>,
}

/// Read the firewall object an action addresses.
///
/// # Errors
///
/// Propagates client errors. A missing security group or IPSet, when the
/// action needs that parent, is [`ProxmoxError::NotFound`]. A response that is
/// not the array or object the endpoint documents is [`ProxmoxError::Malformed`].
pub async fn observe(
    client: &ProxmoxClient,
    action: &FirewallAction,
    live: LiveFirewall<'_>,
) -> Result<ObservedFirewall, ProxmoxError> {
    let scope = FirewallScope::parse(&action.scope)?;
    let object = FirewallObject::parse(&action.object)?;
    let located = Located::resolve(scope, action, live)?;

    match object {
        FirewallObject::Rule => observe_rules(client, &located, action.pos, false).await,
        FirewallObject::GroupRule => {
            let name = require_name(action)?;
            confirm_named(client, &located, "group", name).await?;
            observe_rules(client, &located, action.pos, true).await
        }
        FirewallObject::Options => {
            let body = read_object(client, &located.options_path()).await?;
            let digest = digest_of(&body);
            Ok(ObservedFirewall {
                body: Some(body),
                digest,
                item_present: true,
            })
        }
        FirewallObject::Group => observe_named(client, &located, "group", "group").await,
        FirewallObject::Ipset => observe_named(client, &located, "ipset", "name").await,
        FirewallObject::Alias => observe_named(client, &located, "alias", "name").await,
        FirewallObject::IpsetEntry => {
            let name = require_name(action)?;
            confirm_named(client, &located, "ipset", name).await?;
            let entries = read_array(client, &located.ipset_entries_path(name)).await?;
            let cidr = action.cidr.as_deref().unwrap_or("");
            let found = entries
                .iter()
                .find(|entry| entry.get("cidr").and_then(Value::as_str) == Some(cidr));
            Ok(ObservedFirewall {
                digest: found.and_then(digest_of),
                item_present: found.is_some(),
                body: Some(Value::Array(entries)),
            })
        }
    }
}

/// Send one already-validated firewall write.
///
/// # Errors
///
/// Propagates client errors, including the cluster refusing the write.
pub async fn execute(
    client: &ProxmoxClient,
    action: &FirewallAction,
    live: LiveFirewall<'_>,
) -> Result<(), ProxmoxError> {
    let scope = FirewallScope::parse(&action.scope)?;
    let object = FirewallObject::parse(&action.object)?;
    let located = Located::resolve(scope, action, live)?;
    let digest = action.digest.as_deref();

    match (object, action.op.as_str()) {
        (FirewallObject::Rule, "create") => {
            let path = located.rules_collection(false);
            let form = rule_form(action, true);
            post_form(client, &path, &form).await?;
        }
        (FirewallObject::Rule, "update") => {
            let pos = require_pos(action)?;
            let path = located.rules_item(false, pos);
            let form = rule_form(action, false);
            put_form(client, &path, &form).await?;
        }
        (FirewallObject::Rule, "delete") => {
            let pos = require_pos(action)?;
            let path = located.rules_item(false, pos);
            delete_with_digest(client, &path, digest).await?;
        }
        (FirewallObject::GroupRule, "create") => {
            let path = located.rules_collection(true);
            let form = rule_form(action, true);
            post_form(client, &path, &form).await?;
        }
        (FirewallObject::GroupRule, "update") => {
            let pos = require_pos(action)?;
            let path = located.rules_item(true, pos);
            let form = rule_form(action, false);
            put_form(client, &path, &form).await?;
        }
        (FirewallObject::GroupRule, "delete") => {
            let pos = require_pos(action)?;
            let path = located.rules_item(true, pos);
            delete_with_digest(client, &path, digest).await?;
        }
        (FirewallObject::Options, "update") => {
            let path = located.options_path();
            let form = options_form(action);
            put_form(client, &path, &form).await?;
        }
        (FirewallObject::Group, "create") => {
            let name = require_name(action)?;
            let mut form = FormBuf::new();
            form.add("group", name);
            if let Some(comment) = action.comment.as_deref() {
                form.add("comment", comment);
            }
            let path = PathBuf::cluster("/api2/json/cluster/firewall/groups");
            post_form(client, &path, &form).await?;
        }
        (FirewallObject::Group, "delete") => {
            let name = require_name(action)?;
            let path = PathBuf::cluster_name("/api2/json/cluster/firewall/groups/{name}", name);
            delete_with_digest(client, &path, digest).await?;
        }
        (FirewallObject::Ipset, "create") => {
            let name = require_name(action)?;
            let mut form = FormBuf::new();
            form.add("name", name);
            if let Some(comment) = action.comment.as_deref() {
                form.add("comment", comment);
            }
            let path = located.ipset_collection();
            post_form(client, &path, &form).await?;
        }
        (FirewallObject::Ipset, "delete") => {
            let name = require_name(action)?;
            let path = located.ipset_item(name);
            delete_with_digest(client, &path, digest).await?;
        }
        (FirewallObject::IpsetEntry, "create") => {
            let name = require_name(action)?;
            let cidr = require_cidr(action)?;
            let mut form = FormBuf::new();
            form.add("cidr", cidr);
            push_comment_nomatch(&mut form, action);
            let path = located.ipset_entries_path(name);
            post_form(client, &path, &form).await?;
        }
        (FirewallObject::IpsetEntry, "update") => {
            let name = require_name(action)?;
            let cidr = require_cidr(action)?;
            let mut form = FormBuf::new();
            push_comment_nomatch(&mut form, action);
            if let Some(digest) = digest {
                form.add("digest", digest);
            }
            let path = located.ipset_entry_item(name, cidr);
            put_form(client, &path, &form).await?;
        }
        (FirewallObject::IpsetEntry, "delete") => {
            let name = require_name(action)?;
            let cidr = require_cidr(action)?;
            let path = located.ipset_entry_item(name, cidr);
            delete_with_digest(client, &path, digest).await?;
        }
        (FirewallObject::Alias, "create") => {
            let name = require_name(action)?;
            let cidr = require_cidr(action)?;
            let mut form = FormBuf::new();
            form.add("name", name);
            form.add("cidr", cidr);
            if let Some(comment) = action.comment.as_deref() {
                form.add("comment", comment);
            }
            let path = located.alias_collection();
            post_form(client, &path, &form).await?;
        }
        (FirewallObject::Alias, "update") => {
            let name = require_name(action)?;
            let mut form = FormBuf::new();
            if let Some(cidr) = action.cidr.as_deref() {
                form.add("cidr", cidr);
            }
            if let Some(comment) = action.comment.as_deref() {
                form.add("comment", comment);
            }
            if let Some(digest) = digest {
                form.add("digest", digest);
            }
            let path = located.alias_item(name);
            put_form(client, &path, &form).await?;
        }
        (FirewallObject::Alias, "delete") => {
            let name = require_name(action)?;
            let path = located.alias_item(name);
            delete_with_digest(client, &path, digest).await?;
        }
        (object, op) => {
            return Err(ProxmoxError::Malformed(format!(
                "firewall {} does not support '{op}'",
                object.as_str()
            )));
        }
    }
    Ok(())
}

struct Located {
    scope: FirewallScope,
    node: Option<String>,
    kind: Option<String>,
    vmid: Option<String>,
    group: Option<String>,
}

impl Located {
    fn resolve(
        scope: FirewallScope,
        action: &FirewallAction,
        live: LiveFirewall<'_>,
    ) -> Result<Self, ProxmoxError> {
        let (node, kind, vmid) = match scope {
            FirewallScope::Cluster => (None, None, None),
            FirewallScope::Node => {
                let node = action.node.as_deref().ok_or_else(|| {
                    ProxmoxError::Malformed("node firewall change has no node".into())
                })?;
                (Some(node.to_owned()), None, None)
            }
            FirewallScope::Guest => {
                let node = live.node.ok_or_else(|| {
                    ProxmoxError::Malformed("guest firewall change has no resolved node".into())
                })?;
                let kind = live.guest_kind.ok_or_else(|| {
                    ProxmoxError::Malformed("guest firewall change has no guest type".into())
                })?;
                let vmid = action.vmid.ok_or_else(|| {
                    ProxmoxError::Malformed("guest firewall change has no vmid".into())
                })?;
                (
                    Some(node.to_owned()),
                    Some(kind.to_owned()),
                    Some(vmid.to_string()),
                )
            }
        };
        Ok(Self {
            scope,
            node,
            kind,
            vmid,
            group: action.name.clone(),
        })
    }

    fn rules_collection(&self, group_rule: bool) -> PathBuf {
        if group_rule {
            return self.group_path(false);
        }
        self.under("rules", None)
    }

    fn rules_item(&self, group_rule: bool, pos: u32) -> PathBuf {
        if group_rule {
            return self.group_path_pos(pos);
        }
        self.under("rules", Some(("pos", pos.to_string(), "{pos}")))
    }

    fn options_path(&self) -> PathBuf {
        self.under("options", None)
    }

    fn ipset_collection(&self) -> PathBuf {
        self.under("ipset", None)
    }

    fn ipset_item(&self, name: &str) -> PathBuf {
        self.under("ipset", Some(("name", name.to_owned(), "{name}")))
    }

    fn ipset_entries_path(&self, name: &str) -> PathBuf {
        self.ipset_item(name)
    }

    fn ipset_entry_item(&self, name: &str, cidr: &str) -> PathBuf {
        let mut path = self.under("ipset", Some(("name", name.to_owned(), "{name}")));
        path.template_owned = match self.scope {
            FirewallScope::Cluster => "/api2/json/cluster/firewall/ipset/{name}/{cidr}".to_owned(),
            FirewallScope::Guest => {
                "/api2/json/nodes/{node}/{kind}/{vmid}/firewall/ipset/{name}/{cidr}".to_owned()
            }
            FirewallScope::Node => {
                "/api2/json/nodes/{node}/firewall/ipset/{name}/{cidr}".to_owned()
            }
        };
        path.cidr = Some(cidr.to_owned());
        path
    }

    fn alias_collection(&self) -> PathBuf {
        self.under("aliases", None)
    }

    fn alias_item(&self, name: &str) -> PathBuf {
        self.under("aliases", Some(("name", name.to_owned(), "{name}")))
    }

    fn list_path(&self, family: &str) -> PathBuf {
        match family {
            "group" => PathBuf::cluster("/api2/json/cluster/firewall/groups"),
            "ipset" => self.ipset_collection(),
            "alias" => self.alias_collection(),
            _ => self.under(family, None),
        }
    }

    fn group_path(&self, _item: bool) -> PathBuf {
        let name = self.group.clone().unwrap_or_default();
        PathBuf::cluster_name("/api2/json/cluster/firewall/groups/{name}", &name)
    }

    fn group_path_pos(&self, pos: u32) -> PathBuf {
        let mut path = self.group_path(true);
        path.template_owned = "/api2/json/cluster/firewall/groups/{name}/{pos}".to_owned();
        path.pos = Some(pos.to_string());
        path
    }

    fn under(&self, leaf: &str, extra: Option<(&str, String, &str)>) -> PathBuf {
        let suffix = match extra {
            Some((_, _, placeholder)) => format!("/{leaf}/{placeholder}"),
            None => format!("/{leaf}"),
        };
        let template = match self.scope {
            FirewallScope::Cluster => format!("/api2/json/cluster/firewall{suffix}"),
            FirewallScope::Node => format!("/api2/json/nodes/{{node}}/firewall{suffix}"),
            FirewallScope::Guest => {
                format!("/api2/json/nodes/{{node}}/{{kind}}/{{vmid}}/firewall{suffix}")
            }
        };
        let mut path = PathBuf {
            template_owned: template,
            node: self.node.clone(),
            kind: self.kind.clone(),
            vmid: self.vmid.clone(),
            name: None,
            pos: None,
            cidr: None,
        };
        if let Some((key, value, _)) = extra {
            match key {
                "name" => path.name = Some(value),
                "pos" => path.pos = Some(value),
                _ => {}
            }
        }
        path
    }
}

struct PathBuf {
    template_owned: String,
    node: Option<String>,
    kind: Option<String>,
    vmid: Option<String>,
    name: Option<String>,
    pos: Option<String>,
    cidr: Option<String>,
}

impl PathBuf {
    fn cluster(template: &str) -> Self {
        Self {
            template_owned: template.to_owned(),
            node: None,
            kind: None,
            vmid: None,
            name: None,
            pos: None,
            cidr: None,
        }
    }

    fn cluster_name(template: &str, name: &str) -> Self {
        let mut path = Self::cluster(template);
        path.name = Some(name.to_owned());
        path
    }

    fn template(&self) -> &str {
        &self.template_owned
    }

    fn params(&self) -> Vec<(&str, &str)> {
        let mut params = Vec::new();
        if let Some(node) = &self.node {
            params.push(("node", node.as_str()));
        }
        if let Some(kind) = &self.kind {
            params.push(("kind", kind.as_str()));
        }
        if let Some(vmid) = &self.vmid {
            params.push(("vmid", vmid.as_str()));
        }
        if let Some(name) = &self.name {
            params.push(("name", name.as_str()));
        }
        if let Some(pos) = &self.pos {
            params.push(("pos", pos.as_str()));
        }
        if let Some(cidr) = &self.cidr {
            params.push(("cidr", cidr.as_str()));
        }
        params
    }
}

async fn observe_rules(
    client: &ProxmoxClient,
    located: &Located,
    pos: Option<u32>,
    group_rule: bool,
) -> Result<ObservedFirewall, ProxmoxError> {
    let path = located.rules_collection(group_rule);
    let rules = read_array(client, &path).await?;
    let found = pos.and_then(|pos| rule_at(&rules, pos));
    Ok(ObservedFirewall {
        digest: found.and_then(digest_of),
        item_present: found.is_some(),
        body: Some(Value::Array(rules)),
    })
}

async fn observe_named(
    client: &ProxmoxClient,
    located: &Located,
    family: &str,
    key: &str,
) -> Result<ObservedFirewall, ProxmoxError> {
    // `located.group` holds the action's name for every named object.
    let name = located
        .group
        .as_deref()
        .ok_or_else(|| ProxmoxError::Malformed(format!("firewall {family} change has no name")))?;
    let path = located.list_path(family);
    let items = read_array(client, &path).await?;
    let found = items
        .iter()
        .find(|item| item.get(key).and_then(Value::as_str) == Some(name))
        .cloned();
    Ok(ObservedFirewall {
        digest: found.as_ref().and_then(digest_of),
        item_present: found.is_some(),
        body: found,
    })
}

async fn confirm_named(
    client: &ProxmoxClient,
    located: &Located,
    family: &str,
    name: &str,
) -> Result<(), ProxmoxError> {
    let key = if family == "group" { "group" } else { "name" };
    let path = located.list_path(family);
    let items = read_array(client, &path).await?;
    if items
        .iter()
        .any(|item| item.get(key).and_then(Value::as_str) == Some(name))
    {
        Ok(())
    } else {
        Err(ProxmoxError::NotFound {
            what: format!("firewall {family} '{name}'"),
        })
    }
}

async fn read_array(client: &ProxmoxClient, path: &PathBuf) -> Result<Vec<Value>, ProxmoxError> {
    let params = path.params();
    let data = client.get_json(path.template(), &params, &[]).await?;
    match data {
        Value::Array(items) => Ok(items),
        _ => Err(ProxmoxError::Malformed(
            "firewall list response is not an array".into(),
        )),
    }
}

async fn read_object(client: &ProxmoxClient, path: &PathBuf) -> Result<Value, ProxmoxError> {
    let params = path.params();
    let data = client.get_json(path.template(), &params, &[]).await?;
    match data {
        Value::Object(_) => Ok(data),
        Value::Null => Ok(Value::Object(serde_json::Map::new())),
        _ => Err(ProxmoxError::Malformed(
            "firewall options response is not an object".into(),
        )),
    }
}

async fn delete_with_digest(
    client: &ProxmoxClient,
    path: &PathBuf,
    digest: Option<&str>,
) -> Result<(), ProxmoxError> {
    let params = path.params();
    if let Some(digest) = digest {
        let query = [("digest", digest)];
        client.delete_json(path.template(), &params, &query).await?;
    } else {
        client.delete_json(path.template(), &params, &[]).await?;
    }
    Ok(())
}

fn rule_at(rules: &[Value], pos: u32) -> Option<&Value> {
    rules
        .iter()
        .find(|rule| rule.get("pos").and_then(Value::as_u64) == Some(u64::from(pos)))
}

fn digest_of(value: &Value) -> Option<String> {
    value
        .get("digest")
        .and_then(Value::as_str)
        .filter(|digest| !digest.is_empty())
        .map(ToOwned::to_owned)
}

fn require_name(action: &FirewallAction) -> Result<&str, ProxmoxError> {
    action
        .name
        .as_deref()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ProxmoxError::Malformed("firewall change has no name".into()))
}

fn require_cidr(action: &FirewallAction) -> Result<&str, ProxmoxError> {
    action
        .cidr
        .as_deref()
        .filter(|cidr| !cidr.is_empty())
        .ok_or_else(|| ProxmoxError::Malformed("firewall change has no address".into()))
}

fn require_pos(action: &FirewallAction) -> Result<u32, ProxmoxError> {
    action
        .pos
        .ok_or_else(|| ProxmoxError::Malformed("firewall rule change has no position".into()))
}

async fn post_form(
    client: &ProxmoxClient,
    path: &PathBuf,
    form: &FormBuf,
) -> Result<(), ProxmoxError> {
    let params = path.params();
    let body = form.refs();
    client.post_form(path.template(), &params, &body).await?;
    Ok(())
}

async fn put_form(
    client: &ProxmoxClient,
    path: &PathBuf,
    form: &FormBuf,
) -> Result<(), ProxmoxError> {
    let params = path.params();
    let body = form.refs();
    client.put_form(path.template(), &params, &body).await?;
    Ok(())
}

struct FormBuf {
    pairs: Vec<(String, String)>,
}

impl FormBuf {
    fn new() -> Self {
        Self { pairs: Vec::new() }
    }

    fn add(&mut self, key: &str, value: &str) {
        self.pairs.push((key.to_owned(), value.to_owned()));
    }

    fn refs(&self) -> Vec<(&str, &str)> {
        self.pairs
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect()
    }
}

fn push_bool(form: &mut FormBuf, key: &str, value: Option<bool>) {
    if let Some(value) = value {
        form.add(key, if value { "1" } else { "0" });
    }
}

fn push_comment_nomatch(form: &mut FormBuf, action: &FirewallAction) {
    if let Some(comment) = action.comment.as_deref() {
        form.add("comment", comment);
    }
    push_bool(form, "nomatch", action.nomatch);
}

fn rule_form(action: &FirewallAction, include_pos: bool) -> FormBuf {
    let mut form = FormBuf::new();
    let rule = action.rule.as_ref();
    if let Some(rule_type) = rule.and_then(|rule| rule.rule_type.as_deref()) {
        form.add("type", rule_type);
    }
    if let Some(action_value) = rule.and_then(|rule| rule.action.as_deref()) {
        form.add("action", action_value);
    }
    if let Some(rule) = rule {
        push_opt(&mut form, "dest", rule.dest.as_deref());
        push_opt(&mut form, "dport", rule.dport.as_deref());
        push_opt(&mut form, "proto", rule.proto.as_deref());
        push_opt(&mut form, "source", rule.source.as_deref());
        push_opt(&mut form, "sport", rule.sport.as_deref());
        push_opt(&mut form, "iface", rule.iface.as_deref());
        push_opt(&mut form, "macro", rule.fw_macro.as_deref());
        push_opt(&mut form, "log", rule.log.as_deref());
        push_opt(&mut form, "icmp-type", rule.icmp_type.as_deref());
    }
    push_bool(&mut form, "enable", action.enable);
    if let Some(comment) = action.comment.as_deref() {
        form.add("comment", comment);
    }
    if include_pos && let Some(pos) = action.pos {
        form.add("pos", &pos.to_string());
    }
    if let Some(digest) = action.digest.as_deref() {
        form.add("digest", digest);
    }
    form
}

fn options_form(action: &FirewallAction) -> FormBuf {
    let mut form = FormBuf::new();
    let options = action.options.as_ref();
    if let Some(options) = options {
        push_bool(&mut form, "enable", options.enable);
        push_opt(&mut form, "policy_in", options.policy_in.as_deref());
        push_opt(&mut form, "policy_out", options.policy_out.as_deref());
        push_opt(
            &mut form,
            "policy_forward",
            options.policy_forward.as_deref(),
        );
        push_bool(&mut form, "dhcp", options.dhcp);
        push_bool(&mut form, "ipfilter", options.ipfilter);
        push_bool(&mut form, "macfilter", options.macfilter);
        push_bool(&mut form, "ndp", options.ndp);
        push_bool(&mut form, "radv", options.radv);
        push_opt(&mut form, "log_level_in", options.log_level_in.as_deref());
        push_opt(&mut form, "log_level_out", options.log_level_out.as_deref());
        push_opt(
            &mut form,
            "log_level_forward",
            options.log_level_forward.as_deref(),
        );
    }
    if let Some(digest) = action.digest.as_deref() {
        form.add("digest", digest);
    }
    form
}

fn push_opt(form: &mut FormBuf, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        form.add(key, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ruleset_digest_is_taken_from_the_addressed_position() {
        let rules = vec![
            serde_json::json!({"pos": 0, "digest": "aaa", "action": "ACCEPT"}),
            serde_json::json!({"pos": 2, "digest": "bbb", "action": "DROP"}),
        ];
        let found = rule_at(&rules, 2).and_then(digest_of);
        assert_eq!(found.as_deref(), Some("bbb"));
        assert!(rule_at(&rules, 1).is_none());
    }
}
