//! The read surface, declared as data.
//!
//! Proxmox's read API is large and uniform, so a read tool is a catalog entry
//! rather than a function: name, HTTP method, path template, and whether it
//! addresses a specific guest. One generic executor in `crate::client` serves
//! all of them, expanding the template through `mecmcp-openapi`, which rejects
//! a parameter that would break a segment rather than sanitising it.
//!
//! Mutating tools are deliberately *not* here. Each needs preconditions a
//! catalog entry cannot express, so each is written as code that takes an
//! [`crate::AuthorizedGuest`].

use crate::selector::GuestType;
use mecmcp_http::Method;

/// One read tool.
#[derive(Debug, Clone, Copy)]
pub struct ReadTool {
    /// MCP tool name.
    pub name: &'static str,
    /// HTTP method.
    pub method: Method,
    /// Path template with `{node}` and `{vmid}` placeholders.
    pub path: &'static str,
    /// Whether the tool addresses one guest and therefore needs resolution.
    pub needs_guest: bool,
    /// One-line MCP description.
    pub description: &'static str,
    /// Guest type filter for tools that query `/cluster/resources`.
    ///
    /// Task 11's executor filters the response to guests of this type when set.
    pub type_filter: Option<GuestType>,
    /// Query parameters to append to the request.
    ///
    /// Task 11's executor appends these as `?key=value` pairs to the request.
    pub query: &'static [(&'static str, &'static str)],
    /// Whether this entry lists guests (reads `/cluster/resources` or an
    /// equivalent multi-guest endpoint) and therefore must be filtered by
    /// the caller's guest scope in `serve_read`.
    ///
    /// Kept separate from `type_filter` so a future catalog entry that lists
    /// guests without a type filter cannot silently skip the scope filter --
    /// see the catalog test that checks every `/cluster/resources` entry
    /// sets this to `true`.
    pub guest_listing: bool,
}

/// The complete 0.1 read surface.
pub const READ_TOOLS: &[ReadTool] = &[
    ReadTool {
        name: "get_cluster_status",
        method: Method::Get,
        path: "/api2/json/cluster/status",
        needs_guest: false,
        description: "Cluster quorum and node membership.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_nodes",
        method: Method::Get,
        path: "/api2/json/nodes",
        needs_guest: false,
        description: "All nodes in the cluster with status and resource totals.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_node_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/status",
        needs_guest: false,
        description: "Detailed status for one node.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_node_updates",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/apt/update",
        needs_guest: false,
        description: "Pending apt package updates on one node.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_vms",
        method: Method::Get,
        path: "/api2/json/cluster/resources",
        needs_guest: false,
        description: "All QEMU guests across the cluster, with node, status and tags.",
        type_filter: Some(GuestType::Qemu),
        guest_listing: true,
        query: &[],
    },
    ReadTool {
        name: "get_containers",
        method: Method::Get,
        path: "/api2/json/cluster/resources",
        needs_guest: false,
        description: "All LXC guests across the cluster, with node, status and tags.",
        type_filter: Some(GuestType::Lxc),
        guest_listing: true,
        query: &[],
    },
    ReadTool {
        name: "get_vm_config",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/qemu/{vmid}/config",
        needs_guest: true,
        description: "Configuration of one QEMU guest, including its Proxmox digest. \
                      `description`/`cicustom`/`args` content redacted on a best-effort \
                      basis (do not store secrets there); sshkeys and network \
                      config preserved.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_container_config",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/lxc/{vmid}/config",
        needs_guest: true,
        description: "Configuration of one LXC guest, including its Proxmox digest. \
                      `description`/`cicustom`/`args` content redacted on a best-effort \
                      basis (do not store secrets there); sshkeys and network \
                      config preserved.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    // LXC-only: the path hardcodes 'lxc'. Task 11's executor must refuse a QEMU
    // target for this tool rather than issuing a request that can only fail.
    ReadTool {
        name: "get_container_ip",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/lxc/{vmid}/interfaces",
        needs_guest: true,
        description: "Network interfaces and addresses of one LXC guest.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_guest_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/status/current",
        needs_guest: true,
        description: "Current runtime status of one guest.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "list_snapshots",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/snapshot",
        needs_guest: true,
        description: "Snapshots of one guest.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_storage",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage",
        needs_guest: false,
        description: "Storage backends visible to one node, with usage.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "list_backups",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "Backup archives on one storage backend.",
        type_filter: None,
        guest_listing: false,
        query: &[("content", "backup")],
    },
    ReadTool {
        name: "list_isos",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "ISO images on one storage backend.",
        type_filter: None,
        guest_listing: false,
        query: &[("content", "iso")],
    },
    ReadTool {
        name: "list_templates",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/storage/{storage}/content",
        needs_guest: false,
        description: "Container templates on one storage backend.",
        type_filter: None,
        guest_listing: false,
        query: &[("content", "vztmpl")],
    },
    ReadTool {
        name: "list_tasks",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/tasks",
        needs_guest: false,
        description: "Recent tasks on one node.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_task_status",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/tasks/{upid}/status",
        needs_guest: false,
        description: "Status of one task by UPID.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_cluster_firewall_rules",
        method: Method::Get,
        path: "/api2/json/cluster/firewall/rules",
        needs_guest: false,
        description: "Cluster-wide firewall rules.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_cluster_firewall_options",
        method: Method::Get,
        path: "/api2/json/cluster/firewall/options",
        needs_guest: false,
        description: "Cluster-wide firewall options (enable flag, default in/out policy).",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "list_firewall_security_groups",
        method: Method::Get,
        path: "/api2/json/cluster/firewall/groups",
        needs_guest: false,
        description: "Firewall security groups defined on the cluster.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_firewall_security_group_rules",
        method: Method::Get,
        path: "/api2/json/cluster/firewall/groups/{group}",
        needs_guest: false,
        description: "Rules contained in one firewall security group.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "list_firewall_ipsets",
        method: Method::Get,
        path: "/api2/json/cluster/firewall/ipset",
        needs_guest: false,
        description: "Cluster-wide IPSets.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_firewall_ipset_entries",
        method: Method::Get,
        path: "/api2/json/cluster/firewall/ipset/{name}",
        needs_guest: false,
        description: "CIDR entries in one cluster-wide IPSet.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "list_firewall_aliases",
        method: Method::Get,
        path: "/api2/json/cluster/firewall/aliases",
        needs_guest: false,
        description: "Cluster-wide firewall address aliases.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_node_firewall_rules",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/firewall/rules",
        needs_guest: false,
        description: "Firewall rules on one node.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_node_firewall_options",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/firewall/options",
        needs_guest: false,
        description: "Firewall options on one node.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_guest_firewall_rules",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/firewall/rules",
        needs_guest: true,
        description: "Firewall rules of one guest.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_guest_firewall_options",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/firewall/options",
        needs_guest: true,
        description: "Firewall options of one guest.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "list_guest_firewall_aliases",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/firewall/aliases",
        needs_guest: true,
        description: "Firewall address aliases of one guest.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "list_guest_firewall_ipsets",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/firewall/ipset",
        needs_guest: true,
        description: "IPSets defined on one guest.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_guest_firewall_ipset_entries",
        method: Method::Get,
        path: "/api2/json/nodes/{node}/{kind}/{vmid}/firewall/ipset/{name}",
        needs_guest: true,
        description: "CIDR entries in one IPSet of one guest.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "list_ha_rules",
        method: Method::Get,
        path: "/api2/json/cluster/ha/rules",
        needs_guest: false,
        description: "All HA rules (node-affinity and resource-affinity) in the cluster. \
                       Not the deprecated HA groups mechanism.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
    ReadTool {
        name: "get_ha_rule",
        method: Method::Get,
        path: "/api2/json/cluster/ha/rules/{rule}",
        needs_guest: false,
        description: "One HA rule by id.",
        type_filter: None,
        guest_listing: false,
        query: &[],
    },
];

/// Look up a read tool by MCP name.
#[must_use]
pub fn read_tool(name: &str) -> Option<&'static ReadTool> {
    READ_TOOLS.iter().find(|tool| tool.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for tool in READ_TOOLS {
            assert!(seen.insert(tool.name), "duplicate tool {}", tool.name);
        }
    }

    #[test]
    fn guest_scoped_tools_template_both_node_and_vmid() {
        for tool in READ_TOOLS.iter().filter(|tool| tool.needs_guest) {
            assert!(tool.path.contains("{node}"), "{} lacks node", tool.name);
            assert!(tool.path.contains("{vmid}"), "{} lacks vmid", tool.name);
        }
    }

    #[test]
    fn no_path_is_absolute_against_a_different_api_root() {
        for tool in READ_TOOLS {
            assert!(
                tool.path.starts_with("/api2/json/"),
                "{} path {}",
                tool.name,
                tool.path
            );
        }
    }

    #[test]
    fn get_node_updates_reads_the_node_apt_update_list() {
        let tool = read_tool("get_node_updates").expect("registered");
        assert_eq!(tool.path, "/api2/json/nodes/{node}/apt/update");
        assert!(!tool.needs_guest);
    }

    #[test]
    fn looks_up_by_name() {
        assert!(read_tool("get_vms").is_some());
        assert!(read_tool("not_a_tool").is_none());
    }

    #[test]
    fn the_two_guest_list_tools_are_distinguished_by_type_filter() {
        // Both hit /cluster/resources; without the filter one of them would lie.
        let vms = read_tool("get_vms").expect("get_vms");
        let containers = read_tool("get_containers").expect("get_containers");
        assert_eq!(
            vms.path, containers.path,
            "tools should share the same path"
        );
        assert_eq!(
            vms.type_filter,
            Some(GuestType::Qemu),
            "get_vms should filter to QEMU"
        );
        assert_eq!(
            containers.type_filter,
            Some(GuestType::Lxc),
            "get_containers should filter to LXC"
        );
    }

    #[test]
    fn every_cluster_resources_entry_is_marked_a_guest_listing() {
        // `serve_read` filters a listing by the caller's guest scope only when
        // `guest_listing` is set. Any tool reading `/cluster/resources` that
        // is not marked would silently skip that filter and hand a narrowed
        // token every guest in the cluster.
        for tool in READ_TOOLS
            .iter()
            .filter(|tool| tool.path == "/api2/json/cluster/resources")
        {
            assert!(
                tool.guest_listing,
                "{} reads /cluster/resources and must set guest_listing: true",
                tool.name
            );
        }
    }

    #[test]
    fn the_three_storage_tools_are_distinguished_by_content_query() {
        let backups = read_tool("list_backups").expect("list_backups");
        let isos = read_tool("list_isos").expect("list_isos");
        let templates = read_tool("list_templates").expect("list_templates");
        assert_eq!(
            backups.path, isos.path,
            "backups and isos should share the same path"
        );
        assert_eq!(
            isos.path, templates.path,
            "isos and templates should share the same path"
        );
        assert_eq!(
            backups.query,
            &[("content", "backup")],
            "list_backups should filter by backup content"
        );
        assert_eq!(
            isos.query,
            &[("content", "iso")],
            "list_isos should filter by iso content"
        );
        assert_eq!(
            templates.query,
            &[("content", "vztmpl")],
            "list_templates should filter by vztmpl content"
        );
    }

    #[test]
    fn tools_sharing_a_path_always_carry_a_discriminator() {
        // Guards the general defect the two rulings above fixed: if a future entry
        // reuses a path with neither a type filter nor a query, two tools become
        // indistinguishable and at least one of their descriptions is false.
        for (index, tool) in READ_TOOLS.iter().enumerate() {
            for other in READ_TOOLS.iter().skip(index + 1) {
                if tool.path != other.path {
                    continue;
                }
                let distinguished =
                    tool.type_filter != other.type_filter || tool.query != other.query;
                assert!(
                    distinguished,
                    "{} and {} share a path with no discriminator",
                    tool.name, other.name
                );
            }
        }
    }
}
