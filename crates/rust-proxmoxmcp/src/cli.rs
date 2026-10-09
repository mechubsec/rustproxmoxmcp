//! Command-line surface.
//!
//! `mecmcp_runtime::cli::Cli` is flattened rather than reimplemented, so every
//! shared flag — transport, bind, TLS, allowed hosts, audit — behaves exactly as
//! it does on the sibling servers.
//!
//! Release 0.3 adds `--lab-mode` and `--waivers-file` for the two-person control
//! override system (spec §4.2). These flags are spelled identically on every
//! mecmcp server.
//!
//! Token management is intercepted before parsing to prevent grant flags
//! (`--guests`, `--actions`) from appearing in the server's help. See
//! [`TokenCli`] and the dispatch logic in `main.rs`.

use clap::{Parser, Subcommand};
use mecmcp_secret::naming::{ServerNaming, known};
use std::path::PathBuf;

/// Layout for this server. `known::PROXMOX` is the deployed short name, so
/// the directories stay `/etc/proxmoxmcp` and `/var/lib/proxmoxmcp`.
#[must_use]
pub fn server_naming() -> ServerNaming {
    ServerNaming::derive(known::PROXMOX)
}

/// Default cluster inventory. Derived from [`server_naming`].
#[must_use]
pub fn default_clusters_file() -> PathBuf {
    server_naming().config_dir.join("clusters.json")
}

/// Default waiver file. Derived from [`server_naming`].
#[must_use]
pub fn default_waivers_file() -> PathBuf {
    server_naming().config_dir.join("waivers.json")
}

/// `rust-proxmoxmcp` command line.
#[derive(Debug, Parser)]
#[command(name = "rust-proxmoxmcp", version)]
pub struct ProxmoxCli {
    /// Flags shared with the rest of the mechub MCP family.
    #[command(flatten)]
    pub common: mecmcp_runtime::cli::Cli,

    /// Cluster inventory. Must be mode 0600 and owned by the service user.
    #[arg(long, default_value_os_t = default_clusters_file())]
    pub clusters_file: PathBuf,

    /// Run without two-person control for destructive operations.
    ///
    /// For a single-operator lab. No approver is invented: a waived change set
    /// records `approver: null` with a lab-mode waiver, so it stays
    /// distinguishable from one a second person reviewed.
    ///
    /// Spelled identically on every mecmcp server.
    #[arg(long = "lab-mode")]
    pub lab_mode: bool,

    /// Allow direct-commit tools that mutate a guest in one call with no
    /// change-set approval.
    ///
    /// The interrupting lifecycle verbs (`stop_vm`, `shutdown_vm`, `reset_vm`,
    /// `stop_container`, `restart_container`), `clone_vm`, `create_vm`,
    /// `create_container`, `resize_disk`, and `create_backup` act on Proxmox
    /// immediately -- there is no change-set flow to route an operational
    /// command like "stop this guest" through. By default this server refuses
    /// those calls rather than let a model commit a guest mutation alone.
    ///
    /// This applies identically over stdio and HTTP: stdio carries no caller
    /// context at all, so it is refused on exactly the same terms as an
    /// authenticated HTTP session.
    ///
    /// **Residual risk**: an operator can set this flag. Doing so is logged
    /// loudly at startup and every direct-commit call is recorded in the audit
    /// trail (`direct_commit_allowed=true`), but no second-principal review
    /// happens.
    ///
    /// Defaults to false (refuse). Spelled identically on every mecmcp server.
    #[arg(long = "allow-direct-commit")]
    pub allow_direct_commit: bool,

    /// Absolute path to the change-set and operation state file.
    ///
    /// Spelled `--state-file` on every mecmcp server, per
    /// `mecmcp/docs/PACKAGING.md`. **Without it the coordinator keeps change
    /// sets in memory only**: every approval, preview and in-flight apply is
    /// lost on restart, and `recover_in_flight` has nothing to scan. This
    /// server shipped without the flag, so that is what 0.3 did.
    ///
    /// Left optional rather than defaulted so an existing deployment does not
    /// silently start writing a file its unit never provisioned; the packaged
    /// unit passes `$STATE_DIRECTORY/changeset-state.json`, and startup warns
    /// loudly when it is unset.
    #[arg(long = "state-file")]
    pub state_file: Option<PathBuf>,

    /// Time-boxed operator waivers (spec §4.2). Mode 0600, service-owned.
    #[arg(long = "waivers-file", default_value_os_t = default_waivers_file())]
    pub waivers_file: PathBuf,

    /// Enable the `/metrics` (Prometheus) endpoint (streamable-http only). OFF
    /// by default: this repo pins `mecmcp-transport` v0.23.0, whose `/metrics`
    /// handler is not restricted to loopback callers — it is reachable, without
    /// a bearer token, by anything that can satisfy the Host/Origin allowlist
    /// (which always accepts `127.0.0.1`/`localhost`, trivially spoofable via
    /// the `Host` header). Flip this on only once the transport pin is
    /// `>= 0.24.0`, whose `metrics_access_middleware` enforces loopback-only
    /// access by peer IP (see MEC-449).
    #[arg(long = "enable-metrics")]
    pub enable_metrics: bool,

    /// HTTP resource limits (streamable-http only). Defaults match
    /// `mecmcp_transport::LimitsConfig::default()` so an upgrade with no flags
    /// passed behaves exactly as before.
    #[command(flatten)]
    pub limits: LimitsArgs,
}

/// CLI-configurable mirror of `mecmcp_transport::LimitsConfig`.
///
/// Flattened into [`ProxmoxCli`] rather than left hardcoded so an operator can
/// tune per-deployment resource limits without a fork. Every default below is
/// copied from `LimitsConfig::default()` — changing one here without changing
/// the other silently drifts a documented default out of sync with the
/// enforced one.
#[derive(Debug, clap::Args)]
pub struct LimitsArgs {
    /// Max request body bytes before HTTP 413. 0 = unlimited.
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    pub max_request_body_bytes: usize,

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_inflight_requests_per_token: usize,

    /// Max requests per second per source IP address. 0 = disabled (with burst 0).
    #[arg(long, default_value_t = 50)]
    pub max_requests_per_second_per_ip: u64,

    /// Max immediate request burst per source IP address. 0 = disabled (with rate 0).
    #[arg(long, default_value_t = 100)]
    pub max_request_burst_per_ip: u64,

    /// Max requests per second per bearer token. 0 = disabled (with burst 0).
    #[arg(long, default_value_t = 20)]
    pub max_requests_per_second_per_token: u64,

    /// Max immediate request burst per bearer token. 0 = disabled (with rate 0).
    #[arg(long, default_value_t = 40)]
    pub max_request_burst_per_token: u64,

    /// Max concurrent in-flight requests per target cluster. 0 = unlimited.
    #[arg(long, default_value_t = 4)]
    pub max_inflight_requests_per_cluster: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, default_value_t = 128)]
    pub max_sessions: usize,

    /// Max concurrent MCP sessions per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_sessions_per_token: usize,

    /// Session idle timeout in seconds. 0 = disabled.
    #[arg(long, default_value_t = 300)]
    pub session_idle_timeout_secs: u64,

    /// Session max lifetime in seconds. 0 = disabled.
    #[arg(long, default_value_t = 3600)]
    pub session_max_lifetime_secs: u64,
}

impl LimitsArgs {
    /// Build the transport's `LimitsConfig` from the parsed flags.
    #[must_use]
    pub fn to_limits_config(&self) -> mecmcp_transport::LimitsConfig {
        mecmcp_transport::LimitsConfig {
            max_request_body_bytes: self.max_request_body_bytes,
            max_inflight_requests: self.max_inflight_requests,
            max_inflight_requests_per_token: self.max_inflight_requests_per_token,
            max_requests_per_second_per_ip: self.max_requests_per_second_per_ip,
            max_request_burst_per_ip: self.max_request_burst_per_ip,
            max_requests_per_second_per_token: self.max_requests_per_second_per_token,
            max_request_burst_per_token: self.max_request_burst_per_token,
            max_inflight_requests_per_device: self.max_inflight_requests_per_cluster,
            max_sessions: self.max_sessions,
            max_sessions_per_token: self.max_sessions_per_token,
            session_idle_timeout_secs: self.session_idle_timeout_secs,
            session_max_lifetime_secs: self.session_max_lifetime_secs,
            // No CLI flag wires this up yet, so no proxy is trusted and
            // per-IP rate limiting keys on the peer address, same as before
            // this field existed.
            trusted_proxies: Vec::new(),
        }
    }
}

/// Token management CLI, parsed only when argv starts with `token`.
///
/// This is dispatched before `ProxmoxCli` to keep grant-specific flags
/// (`--guests`, `--actions`) off the server's help text. They apply only to
/// token operations, not the server, so showing them as top-level flags would
/// violate the principle that "a flag that is present but ignored is worse than
/// one that is absent."
#[derive(Debug, Parser)]
#[command(name = "rust-proxmoxmcp", version)]
pub struct TokenCli {
    /// Token subcommand (add, revoke, list, rotate).
    #[command(subcommand)]
    pub command: TokenCommand,
}

/// Token subcommands.
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Mint a new token and append to the file.
    Add {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Stable audit name for the token.
        #[arg(long)]
        name: String,
        /// Comma-separated device names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        devices: Vec<String>,
        /// Comma-separated tool names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Guest selectors for token grant (comma-separated).
        ///
        /// A token carrying no guest grant cannot call guest-addressed tools.
        /// Use '*' for all guests, or selectors like 'vmid:600-699', 'tag:ci',
        /// 'pool:lab'.
        #[arg(long, value_delimiter = ',')]
        guests: Vec<String>,
        /// Actions this token may invoke (comma-separated).
        ///
        /// Valid actions: read, low, destructive. Default: read.
        #[arg(long, value_delimiter = ',', default_value = "read")]
        actions: Vec<String>,
        /// Provider name (e.g., "anthropic", "ollama"). Optional.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Required if provider is set.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Optional.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Optional.
        #[arg(long)]
        actor_type: Option<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Revoke a token by name.
    Revoke {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token name to revoke.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List all tokens in the store.
    List {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Rotate a token's secret, preserving its grant.
    Rotate {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token name to rotate.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Change an existing token's scopes without reissuing its secret.
    ///
    /// The alternatives all mint a new secret: `rotate` preserves scopes and
    /// changes the secret — the exact inverse of what is wanted — and
    /// `revoke`+`add` does the same. Hand-editing `tokens.json` keeps the
    /// secret but skips every validation this path performs.
    ///
    /// Note that `--tools '*'` does not reach a mutating tool: `WRITE_TOOLS`
    /// is deliberately excluded from the tool wildcard, so `start_vm` and its
    /// peers must be named explicitly or the preflight refuses the call with
    /// `403 insufficient_scope`.
    SetScopes {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Replacement device scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Replacement tool scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// Replacement guest selectors ('*', 'vmid:600-699', 'tag:ci', ...).
        ///
        /// Replaced wholesale, not merged: naming one selector drops the
        /// others. Merging would make it impossible to *remove* a selector
        /// through this command, and a guest grant is a scope where "I meant
        /// to replace it" must not silently mean "I added to it".
        ///
        /// Omit both this and --actions to leave the grant unchanged.
        #[arg(long, value_delimiter = ',')]
        guests: Option<Vec<String>>,
        /// Replacement actions (read, low, destructive). Replaced wholesale.
        ///
        /// Only meaningful together with --guests, because a grant carries
        /// both; passing --actions alone is refused rather than silently
        /// inventing a guest selector.
        #[arg(long, value_delimiter = ',')]
        actions: Option<Vec<String>>,
        /// Apply a widening without the interactive confirmation.
        #[arg(long)]
        yes: bool,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lab_mode_flag_is_observable_when_passed() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp", "--lab-mode"]);
        assert!(
            cli.lab_mode,
            "a flag that parses but never converts is the defect that took a sibling server down"
        );
    }

    #[test]
    fn lab_mode_defaults_to_false() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp"]);
        assert!(!cli.lab_mode, "the default must be false");
    }

    #[test]
    fn allow_direct_commit_flag_is_observable_when_passed() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp", "--allow-direct-commit"]);
        assert!(
            cli.allow_direct_commit,
            "a flag that parses but never converts is the defect that took a sibling server down"
        );
    }

    #[test]
    fn allow_direct_commit_defaults_to_false() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp"]);
        assert!(!cli.allow_direct_commit, "the default must be false");
    }

    #[test]
    fn metrics_are_disabled_by_default() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp"]);
        assert!(
            !cli.enable_metrics,
            "metrics must stay off by default until the mecmcp-transport pin is >= 0.24.0 (MEC-449)"
        );
    }

    #[test]
    fn enable_metrics_flag_is_observable_when_passed() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp", "--enable-metrics"]);
        assert!(cli.enable_metrics);
    }

    /// Every default must match `LimitsConfig::default()` byte for byte: a
    /// mismatch here means an upgrade with no flags passed silently changes
    /// enforced limits, exactly the drift the flatten struct's doc comment
    /// warns about.
    #[test]
    fn limits_defaults_match_transport_defaults() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp"]);
        let got = cli.limits.to_limits_config();
        let want = mecmcp_transport::LimitsConfig::default();
        assert_eq!(got.max_request_body_bytes, want.max_request_body_bytes);
        assert_eq!(got.max_inflight_requests, want.max_inflight_requests);
        assert_eq!(
            got.max_inflight_requests_per_token,
            want.max_inflight_requests_per_token
        );
        assert_eq!(
            got.max_requests_per_second_per_ip,
            want.max_requests_per_second_per_ip
        );
        assert_eq!(got.max_request_burst_per_ip, want.max_request_burst_per_ip);
        assert_eq!(
            got.max_requests_per_second_per_token,
            want.max_requests_per_second_per_token
        );
        assert_eq!(
            got.max_request_burst_per_token,
            want.max_request_burst_per_token
        );
        assert_eq!(
            got.max_inflight_requests_per_device,
            want.max_inflight_requests_per_device
        );
        assert_eq!(got.max_sessions, want.max_sessions);
        assert_eq!(got.max_sessions_per_token, want.max_sessions_per_token);
        assert_eq!(
            got.session_idle_timeout_secs,
            want.session_idle_timeout_secs
        );
        assert_eq!(
            got.session_max_lifetime_secs,
            want.session_max_lifetime_secs
        );
    }

    #[test]
    fn limits_flags_override_defaults() {
        let cli = ProxmoxCli::parse_from([
            "rust-proxmoxmcp",
            "--max-requests-per-second-per-ip",
            "10",
            "--max-request-burst-per-ip",
            "20",
            "--max-sessions",
            "5",
        ]);
        let limits = cli.limits.to_limits_config();
        assert_eq!(limits.max_requests_per_second_per_ip, 10);
        assert_eq!(limits.max_request_burst_per_ip, 20);
        assert_eq!(limits.max_sessions, 5);
    }

    #[test]
    fn set_scopes_leaves_omitted_scopes_unchanged() {
        let cli = TokenCli::parse_from([
            "token",
            "set-scopes",
            "--tokens-file",
            "/etc/proxmoxmcp/tokens.json",
            "--name",
            "claude-proxmox",
            "--tools",
            "get_nodes,get_vms",
        ]);
        let TokenCommand::SetScopes {
            devices,
            tools,
            guests,
            actions,
            yes,
            ..
        } = cli.command
        else {
            panic!("expected SetScopes");
        };
        assert_eq!(devices, None, "an omitted scope must stay unchanged");
        assert_eq!(
            tools,
            Some(vec!["get_nodes".to_owned(), "get_vms".to_owned()])
        );
        assert_eq!(guests, None);
        assert_eq!(actions, None);
        assert!(!yes, "a widening is confirmed unless --yes is passed");
    }

    #[test]
    fn set_scopes_parses_the_grant_halves() {
        let cli = TokenCli::parse_from([
            "token",
            "set-scopes",
            "--tokens-file",
            "/etc/proxmoxmcp/tokens.json",
            "--name",
            "claude-proxmox",
            "--guests",
            "vmid:600-699,tag:ci",
            "--actions",
            "read,low",
            "--yes",
        ]);
        let TokenCommand::SetScopes {
            guests,
            actions,
            yes,
            ..
        } = cli.command
        else {
            panic!("expected SetScopes");
        };
        assert_eq!(
            guests,
            Some(vec!["vmid:600-699".to_owned(), "tag:ci".to_owned()])
        );
        assert_eq!(actions, Some(vec!["read".to_owned(), "low".to_owned()]));
        assert!(yes);
    }

    /// The shipped paths come from the shared layout and stay the directories
    /// already on disk.
    #[test]
    fn defaults_follow_the_proxmox_layout() {
        let naming = server_naming();
        let clusters = default_clusters_file();
        let waivers = default_waivers_file();
        let tokens = naming.state_dir.join("tokens.json");

        assert_eq!(clusters, PathBuf::from("/etc/proxmoxmcp/clusters.json"));
        assert_eq!(waivers, PathBuf::from("/etc/proxmoxmcp/waivers.json"));
        assert_eq!(tokens, PathBuf::from("/var/lib/proxmoxmcp/tokens.json"));
        assert_eq!(
            naming.config_dir.join("tokens.json"),
            PathBuf::from("/etc/proxmoxmcp/tokens.json")
        );
        assert_eq!(naming.service_user, "proxmoxmcp");

        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp"]);
        assert_eq!(cli.clusters_file, clusters);
        assert_eq!(cli.waivers_file, waivers);
    }
}
