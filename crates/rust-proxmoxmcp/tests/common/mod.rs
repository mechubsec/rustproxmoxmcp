//! Test harness for end-to-end tests through the assembled router.
//!
//! Provides `TestServer` which starts:
//! - A TLS mock Proxmox serving canned routes
//! - A token store with a minted token carrying specified scopes
//! - The same HTTP router that `main.rs` uses (via `build_http_router`)
//!
//! The harness exposes the base URL, the plaintext token, and the mock's
//! request count to prove preflight rejection happens before any Proxmox request.

#![allow(dead_code)]

pub use rust_proxmoxmcp_core::testing::Route;

use mecmcp_auth::{KnownNames, ScopeSet, TokenStoreFile};
use mecmcp_transport::LimitsConfig;
use mecmcp_transport::test_harness::{ServedPlan, serve_on_loopback};
use rust_proxmoxmcp::http_transport::build_http_router;
use rust_proxmoxmcp::server::ProxmoxServer;
use rust_proxmoxmcp_core::testing::TlsMockServer;
use rust_proxmoxmcp_core::{
    ProxmoxAction, ProxmoxGrant,
    client::ProxmoxClient,
    inventory::{Cluster, ClusterInventory},
    resolve::GuestIndex,
};
use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Token specification for test scenarios.
pub struct TokenSpec {
    /// Allowed clusters.
    pub clusters: Vec<String>,
    /// Allowed tools.
    pub tools: Vec<String>,
    /// Guest selectors (e.g., `["*"]`, `["vmid:600-699"]`).
    pub guests: Vec<String>,
}

impl TokenSpec {
    /// A token with full wildcard access.
    pub fn full() -> Self {
        Self {
            clusters: vec!["*".to_owned()],
            tools: vec!["*".to_owned()],
            guests: vec!["*".to_owned()],
        }
    }
}

/// The assembled test server with a mock Proxmox behind it.
pub struct TestServer {
    /// Base URL for the MCP server (e.g., `http://127.0.0.1:xxxxx`).
    pub url: String,
    /// Plaintext bearer token for authentication (first principal).
    pub token: String,
    /// Second bearer token for two-principal workflows. Carries
    /// `actor_type: Human`.
    pub second_token: String,
    /// A third bearer token carrying `actor_type: Agent`, for tests that
    /// prove an agent cannot stand in as the human approver.
    pub agent_token: String,
    /// A fourth token with the same clusters/tools as `token`, but scoped to
    /// vmid 1 only -- outside any guest a fixture test actually uses. For
    /// proving a guest-scope check is repeated at apply time rather than
    /// only at plan time: plan and approve with `token`, then apply with
    /// this one, and the apply must refuse it even though it carries every
    /// tool scope `token` does.
    pub narrow_token: String,
    /// A fifth token with the same clusters/tools/guests as `token`, but
    /// minted with only the `Read` and `Low` action tiers -- no
    /// `Destructive`. For proving a destructive-tier gate refuses a token
    /// that would otherwise pass every scope check, distinct from
    /// `narrow_token`, which instead narrows the guest scope.
    pub low_tier_token: String,
    /// A sixth token with every action tier and the same clusters/tools as
    /// `token`, but scoped to `vmid:600-699` only. See the field's
    /// definition site for why this range (not `narrow_token`'s `vmid:1-1`)
    /// is needed.
    pub mid_range_token: String,
    /// The mock Proxmox server.
    mock: TlsMockServer,
    /// Guest index for cache invalidation in tests.
    index: Arc<GuestIndex>,
    /// Temp directory holding clusters.json and tokens.json.
    _temp_dir: tempfile::TempDir,
    /// The server's change-set coordinator, for tests that need to build a
    /// store state the tool surface cannot produce.
    coordinator: Arc<mecmcp_changeset::ChangesetCoordinator>,
    /// Cancelled by [`Self::shutdown`] to stop the background serve task.
    shutdown: tokio_util::sync::CancellationToken,
    /// The background serve task, plus where it's bound. Held so
    /// [`Self::shutdown`] can await the task exiting before a caller reuses
    /// the same state path.
    served: ServedPlan,
    /// The `/readyz` cluster-reachability pollers. Held so they keep running
    /// for the server's lifetime instead of aborting as soon as this
    /// function returns.
    _readiness_handles: Vec<tokio_util::task::AbortOnDropHandle<()>>,
}

impl TestServer {
    /// Start the test server with a token carrying the given scopes and custom routes.
    ///
    /// Sets up:
    /// - TLS mock Proxmox with the provided routes
    /// - clusters.json and tokens.json
    /// - The same HTTP router that `main` uses
    ///
    /// The server listens on `127.0.0.1:0` and is served over plain HTTP
    /// (the HTTPS requirement is for the outbound leg to Proxmox).
    pub async fn start_with_routes(spec: TokenSpec, routes: Vec<Route>) -> Self {
        Self::start_with_config(
            spec,
            routes,
            Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
            false,
        )
        .await
    }

    /// As [`Self::start_with_routes`], with the primary/second/agent
    /// tokens' action tier caller-supplied instead of every tier. See
    /// [`Self::start_with_full_config`].
    pub async fn start_with_routes_and_actions(
        spec: TokenSpec,
        routes: Vec<Route>,
        actions: Vec<ProxmoxAction>,
    ) -> Self {
        Self::start_with_full_config(
            spec,
            routes,
            Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
            false,
            None,
            LimitsConfig::default(),
            mecmcp_audit::DirectCommitPolicy::new(false),
            actions,
        )
        .await
    }

    /// Start the test server with custom waivers and lab-mode setting.
    ///
    /// This is used for testing the two-person control override system.
    pub async fn start_with_config(
        spec: TokenSpec,
        routes: Vec<Route>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
    ) -> Self {
        Self::start_with_config_on_state(spec, routes, waivers, lab_mode, None).await
    }

    /// As [`Self::start_with_config`], but backing the change-set coordinator
    /// with a caller-supplied state file instead of keeping state in memory.
    ///
    /// Lets a test hand-write a state file -- the only way to reach guards
    /// that exist for records an older binary persisted, since the current
    /// coordinator will not create those states itself.
    pub async fn start_with_config_on_state(
        spec: TokenSpec,
        routes: Vec<Route>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
        state_path: Option<std::path::PathBuf>,
    ) -> Self {
        Self::start_with_config_on_state_and_limits(
            spec,
            routes,
            waivers,
            lab_mode,
            state_path,
            LimitsConfig::default(),
        )
        .await
    }

    /// Start the test server with the production default request limits
    /// replaced by `limits`.
    ///
    /// For a test that legitimately drives many calls back-to-back on one
    /// token -- a catalog sweep, say -- rather than one that probes rate
    /// limiting itself, which should keep the production default.
    pub async fn start_with_limits(
        spec: TokenSpec,
        routes: Vec<Route>,
        limits: LimitsConfig,
    ) -> Self {
        Self::start_with_config_on_state_and_limits(
            spec,
            routes,
            Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
            false,
            None,
            limits,
        )
        .await
    }

    /// As [`Self::start_with_routes`], with `--allow-direct-commit` set
    /// according to `allow_direct_commit` rather than left off.
    ///
    /// For the direct-commit gate tests, which need to prove both that the
    /// gate refuses by default and that it steps aside when the operator has
    /// explicitly accepted the risk.
    pub async fn start_with_direct_commit(
        spec: TokenSpec,
        routes: Vec<Route>,
        allow_direct_commit: bool,
    ) -> Self {
        Self::start_with_config_on_state_and_limits_and_direct_commit(
            spec,
            routes,
            Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
            false,
            None,
            LimitsConfig::default(),
            mecmcp_audit::DirectCommitPolicy::new(allow_direct_commit),
        )
        .await
    }

    /// As [`Self::start_with_config_on_state`], with the request limits also
    /// caller-supplied instead of hardcoded to [`LimitsConfig::default`].
    pub async fn start_with_config_on_state_and_limits(
        spec: TokenSpec,
        routes: Vec<Route>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
        state_path: Option<std::path::PathBuf>,
        limits: LimitsConfig,
    ) -> Self {
        Self::start_with_config_on_state_and_limits_and_direct_commit(
            spec,
            routes,
            waivers,
            lab_mode,
            state_path,
            limits,
            mecmcp_audit::DirectCommitPolicy::new(false),
        )
        .await
    }

    /// As [`Self::start_with_config_on_state_and_limits`], with
    /// `--allow-direct-commit` also caller-supplied instead of hardcoded off.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_config_on_state_and_limits_and_direct_commit(
        spec: TokenSpec,
        routes: Vec<Route>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
        state_path: Option<std::path::PathBuf>,
        limits: LimitsConfig,
        direct_commit: mecmcp_audit::DirectCommitPolicy,
    ) -> Self {
        Self::start_with_full_config(
            spec,
            routes,
            waivers,
            lab_mode,
            state_path,
            limits,
            direct_commit,
            vec![
                ProxmoxAction::Read,
                ProxmoxAction::Low,
                ProxmoxAction::Destructive,
            ],
        )
        .await
    }

    /// A token carrying every scope `spec` names, minted with `actions` as
    /// its action tier instead of every tier. For a test that must prove a
    /// gate refuses a token missing a specific tier (`destructive`, say)
    /// even though every other scope it could check is wide open -- there
    /// is no other way to mint such a token through this harness, since
    /// every other constructor hardcodes the full tier set.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_full_config(
        spec: TokenSpec,
        routes: Vec<Route>,
        waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
        lab_mode: bool,
        state_path: Option<std::path::PathBuf>,
        limits: LimitsConfig,
        direct_commit: mecmcp_audit::DirectCommitPolicy,
        actions: Vec<ProxmoxAction>,
    ) -> Self {
        // Install crypto provider once for the test binary.
        ensure_crypto_provider();

        // Start the TLS mock Proxmox with custom routes.
        let mock = TlsMockServer::start(routes).await;

        // Create a temp directory for clusters.json and tokens.json.
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let clusters_path = temp_dir.path().join("clusters.json");
        let tokens_path = temp_dir.path().join("tokens.json");

        // Write clusters.json.
        let cluster = Cluster {
            endpoint: mock.uri().to_owned(),
            token_id: "root@pam!mcp".to_owned(),
            token_secret_env: None,
            token_secret_file: Some(create_secret_file("mock-secret")),
            ca_pem_path: Some(mock.ca_pem_path().to_owned()),
            protected_vmids: vec![905],
            protected_tags: vec!["protected".to_owned()],
        };

        let mut clusters_map = BTreeMap::new();
        clusters_map.insert("pve3".to_owned(), cluster);

        let inventory_json = serde_json::json!({
            "version": 1,
            "devices": clusters_map,
            "policy": {
                "resource_cache_ttl_secs": 300
            }
        });

        let mut clusters_file =
            std::fs::File::create(&clusters_path).expect("create clusters.json");
        clusters_file
            .write_all(
                serde_json::to_string_pretty(&inventory_json)
                    .expect("serialize")
                    .as_bytes(),
            )
            .expect("write clusters.json");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&clusters_path, std::fs::Permissions::from_mode(0o600))
                .expect("set clusters.json permissions");
        }

        // Mint a token and write tokens.json.
        let grant = ProxmoxGrant {
            guests: spec.guests.clone(),
            actions: actions.clone(),
        };

        let tool_refs: Vec<&str> = spec.tools.iter().map(|s| s.as_str()).collect();
        let known = KnownNames {
            devices: Some(&spec.clusters),
            tools: &tool_refs,
        };

        let plaintext = TokenStoreFile::<ProxmoxGrant>::add_with_options(
            &tokens_path,
            "test-token",
            parse_scope(&spec.clusters),
            parse_scope(&spec.tools),
            None,
            Some(grant.clone()),
            None,
            None,
            None,
            None,
            None,
            &known,
        )
        .expect("mint token");

        // Mint a second token for two-principal workflows. Carries
        // `actor_type: Human`: mecmcp's `approve_change_set` (MEC-449) refuses
        // an approval from anything but a human principal, so the approver
        // this harness hands to every two-principal test must be one.
        let second_plaintext = TokenStoreFile::<ProxmoxGrant>::add_with_options(
            &tokens_path,
            "test-token-2",
            parse_scope(&spec.clusters),
            parse_scope(&spec.tools),
            None,
            Some(grant.clone()),
            None,
            None,
            None,
            Some(mecmcp_auth::ActorType::Human),
            None,
            &known,
        )
        .expect("mint second token");

        // A third token whose entry declares `actor_type: Agent`, for tests
        // that prove an agent cannot stand in as the human approver.
        let agent_plaintext = TokenStoreFile::<ProxmoxGrant>::add_with_options(
            &tokens_path,
            "test-token-agent",
            parse_scope(&spec.clusters),
            parse_scope(&spec.tools),
            None,
            Some(grant),
            None,
            None,
            None,
            Some(mecmcp_auth::ActorType::Agent),
            None,
            &known,
        )
        .expect("mint agent-actor-type token");

        // A fourth token, same clusters/tools as `token` but scoped to a
        // guest no fixture test targets. See the `narrow_token` field doc.
        let narrow_grant = ProxmoxGrant {
            guests: vec!["vmid:1-1".to_owned()],
            actions: vec![
                ProxmoxAction::Read,
                ProxmoxAction::Low,
                ProxmoxAction::Destructive,
            ],
        };
        let narrow_plaintext = TokenStoreFile::<ProxmoxGrant>::add_with_options(
            &tokens_path,
            "test-token-narrow",
            parse_scope(&spec.clusters),
            parse_scope(&spec.tools),
            None,
            Some(narrow_grant),
            None,
            None,
            None,
            // Human, not the default: tests that approve a change set with
            // this token must be refused for the guest-scope mismatch this
            // token exists to prove, not for an unrelated non-human actor
            // type that would mask it.
            Some(mecmcp_auth::ActorType::Human),
            None,
            &known,
        )
        .expect("mint narrow-scoped token");

        // A fifth token, same clusters/tools/guests as `token` but missing
        // the `destructive` action tier. See the `low_tier_token` field doc.
        let low_tier_grant = ProxmoxGrant {
            guests: spec.guests.clone(),
            actions: vec![ProxmoxAction::Read, ProxmoxAction::Low],
        };
        let low_tier_plaintext = TokenStoreFile::<ProxmoxGrant>::add_with_options(
            &tokens_path,
            "test-token-low-tier",
            parse_scope(&spec.clusters),
            parse_scope(&spec.tools),
            None,
            Some(low_tier_grant),
            None,
            None,
            None,
            // Human, for the same reason as `narrow_token` above.
            Some(mecmcp_auth::ActorType::Human),
            None,
            &known,
        )
        .expect("mint low-tier token");

        // A sixth token, same clusters/tools as `token`, carrying every
        // action tier, but scoped to `vmid:600-699` -- wide enough to cover
        // a restore target in that range (e.g. 650) while excluding the
        // fixture's other guests (617, 905, 618). For proving an
        // owner-guest authority check (scope or protection) is re-run
        // against the *approver's* own grant, distinct from `narrow_token`
        // (which excludes every fixture guest, including the target) and
        // `second_token` (which, like `token`, is scoped to every guest).
        let mid_range_grant = ProxmoxGrant {
            guests: vec!["vmid:600-699".to_owned()],
            actions: actions.clone(),
        };
        let mid_range_plaintext = TokenStoreFile::<ProxmoxGrant>::add_with_options(
            &tokens_path,
            "test-token-mid-range",
            parse_scope(&spec.clusters),
            parse_scope(&spec.tools),
            None,
            Some(mid_range_grant),
            None,
            None,
            None,
            // Human: this token stands in for a second, distinct approver in
            // the tests that use it.
            Some(mecmcp_auth::ActorType::Human),
            None,
            &known,
        )
        .expect("mint mid-range token");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tokens_path, std::fs::Permissions::from_mode(0o600))
                .expect("set tokens.json permissions");
        }

        // Load the inventory and build clients.
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
        let clients = Arc::new(clients);
        let (readiness_checks, readiness_handles) =
            rust_proxmoxmcp::readiness::spawn_cluster_readiness(&clients);

        let index = Arc::new(GuestIndex::new(Duration::from_secs(
            clusters.policy().resource_cache_ttl_secs,
        )));

        // Build the HTTP router using the same function `main` uses.
        let handler = ProxmoxServer::new_with_default_coordinator(
            clusters,
            clients,
            Arc::clone(&index),
            waivers,
            lab_mode,
            None,
            direct_commit,
            state_path.as_deref(),
            None,
        )
        .expect("build server");
        let coordinator = Arc::clone(handler.coordinator());
        let token_store_arc =
            Arc::new(TokenStoreFile::<ProxmoxGrant>::load(&tokens_path).expect("load tokens.json"));
        let shutdown = tokio_util::sync::CancellationToken::new();

        let plan = build_http_router(
            handler,
            Some(token_store_arc),
            vec![],
            vec![],
            limits,
            false,
            false,
            shutdown.clone(),
            readiness_checks,
        )
        .expect("build HTTP router");

        // Serve on an OS-assigned loopback port to avoid test collisions.
        let served = serve_on_loopback(plan).await;

        Self {
            url: format!("http://{}", served.address),
            token: plaintext.expose_secret().to_owned(),
            second_token: second_plaintext.expose_secret().to_owned(),
            agent_token: agent_plaintext.expose_secret().to_owned(),
            narrow_token: narrow_plaintext.expose_secret().to_owned(),
            low_tier_token: low_tier_plaintext.expose_secret().to_owned(),
            mid_range_token: mid_range_plaintext.expose_secret().to_owned(),
            mock,
            index,
            _temp_dir: temp_dir,
            coordinator,
            shutdown,
            served,
            _readiness_handles: readiness_handles,
        }
    }

    /// The server's change-set coordinator.
    pub fn coordinator(&self) -> &Arc<mecmcp_changeset::ChangesetCoordinator> {
        &self.coordinator
    }

    /// Stop the background serve task and wait for the coordinator's
    /// process-lifetime lock on its state path to release, so a caller can
    /// start a second server against the same `state_path`.
    ///
    /// mecmcp 0.25.0's `ChangesetCoordinator` holds an exclusive lock on the
    /// state file for as long as it is alive (`_owner_lock` in
    /// `mecmcp_changeset::coordinator`), which only drops once every
    /// `Arc` clone of the coordinator does. Cancelling `shutdown` and
    /// awaiting the serve task drops the router's own clone, but each MCP
    /// session a test opened (`call`/`call_with_token`) holds a separate
    /// clone that is *not* dropped by cancellation or by the client
    /// disconnecting -- mecmcp-transport's streamable-HTTP sessions are
    /// designed to outlive the connection that created them, and
    /// `cancellation_token` in `streamable_http_server_config` only cuts the
    /// SSE stream a session opened, not a session created solely to answer
    /// one `tools/call` POST. The only thing that drops that clone is
    /// mecmcp-transport's own idle-timeout reaper, which sweeps on a fixed,
    /// non-configurable 30-second period and only reaps a session once it
    /// has been idle past `session_idle_timeout_secs`.
    ///
    /// A caller that needs this to converge within the test's lifetime must
    /// build the server with a short `session_idle_timeout_secs` (see
    /// [`Self::start_with_limits`]) -- the production default (300s) would
    /// need the better part of five minutes. Even with a 1-second idle
    /// timeout, the first reap cannot happen before the reaper's first
    /// 30-second tick, so this is slow by construction, not by a bug here.
    ///
    /// # Panics
    ///
    /// Panics if other references to the coordinator remain 40 seconds after
    /// shutdown (one reaper period plus margin), since that means either the
    /// idle timeout was left at the production default or something new is
    /// holding a long-lived clone of the coordinator.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.served.serving.await;

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(40);
        while Arc::strong_count(&self.coordinator) > 1 {
            assert!(
                std::time::Instant::now() < deadline,
                "coordinator still has {} references 40s after shutdown; build the server \
                 with a short session_idle_timeout_secs (see start_with_limits) so \
                 mecmcp-transport's 30-second session reaper can release its session's \
                 clone within this deadline",
                Arc::strong_count(&self.coordinator)
            );
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Drop the stored preview from a change set, reproducing the state a
    /// failed preview write leaves behind. The tool surface cannot produce
    /// this, which is precisely why the guards against it need a test.
    ///
    /// Only valid before an approval exists. Once a change set is approved,
    /// mecmcp binds the preview to the approval digest and the coordinator
    /// refuses the write; use [`Self::try_strip_preview`] to assert that.
    pub async fn strip_preview(&self, change_set_id: &str) {
        self.try_strip_preview(change_set_id)
            .await
            .expect("store the previewless record");
    }

    /// Attempt to drop the stored preview, returning the coordinator's own
    /// error instead of panicking. Lets a test assert that an approved
    /// change set will not let its preview be taken away.
    pub async fn try_strip_preview(
        &self,
        change_set_id: &str,
    ) -> Result<(), mecmcp_changeset::CoordinatorError> {
        let mut record = self
            .coordinator
            .change_sets()
            .await
            .into_iter()
            .find(|record| record.id == change_set_id)
            .expect("the change set exists");
        record.preview = None;
        self.coordinator.update_change_set(record).await
    }

    /// Start the test server with default routes.
    pub async fn start(spec: TokenSpec) -> Self {
        let routes = vec![
            Route {
                path: "/api2/json/nodes",
                status: 200,
                body: br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
            },
            Route {
                path: "/api2/json/cluster/resources",
                status: 200,
                body: br#"{"data":[
                  {"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},
                  {"id":"lxc/606","type":"lxc","vmid":606,"name":"rustsdcmcp-606","node":"pve3","status":"running","tags":"disposable"}
                ]}"#,
            },
            Route {
                path: "/api2/json/nodes/pve2/qemu/905/config",
                status: 200,
                body: br#"{"data":{"vmid":905,"name":"vsrx-prod","cores":2,"memory":2048}}"#,
            },
        ];
        Self::start_with_routes(spec, routes).await
    }

    /// Number of requests the mock Proxmox has received.
    ///
    /// Used to prove that preflight rejection happens before any outbound request.
    pub fn proxmox_request_count(&self) -> usize {
        self.mock.request_count()
    }

    /// Script a task to complete with the given UPID and exit status.
    ///
    /// This sets up the mock to respond to task polling requests with the
    /// specified exit status. The first poll returns "running", and subsequent
    /// polls return "stopped" with the given exitstatus.
    pub fn script_task_completion(&self, upid: &str, exitstatus: &str) {
        // Parse the UPID to extract the node.
        let parts: Vec<&str> = upid.split(':').collect();
        let node = parts.get(1).expect("valid UPID with node");

        // Encode UPID for the path.
        let encoded_upid = upid.replace(':', "%3A");

        // First poll: running.
        let running_path = format!("/api2/json/nodes/{node}/tasks/{encoded_upid}/status");
        self.mock.replace_route(Route {
            path: Box::leak(running_path.into_boxed_str()),
            status: 200,
            body: Box::leak(
                format!(r#"{{"data":{{"status":"stopped","exitstatus":"{exitstatus}"}}}}"#)
                    .into_boxed_str(),
            )
            .as_bytes(),
        });
    }

    /// All requests the mock Proxmox has received.
    ///
    /// Used to assert that specific requests were issued (e.g., the DELETE).
    pub fn requests(&self) -> Vec<rust_proxmoxmcp_core::testing::RecordedRequest> {
        self.mock.requests()
    }

    /// Replace (or add) one route on the mock Proxmox.
    ///
    /// A thin passthrough for tests that simulate state changing out from
    /// under a change set for a resource with no dedicated helper -- an HA
    /// rule, unlike a guest, has neither `set_guest_config` nor
    /// `move_guest_to_node` to reach for.
    pub fn replace_route(&self, route: Route) {
        self.mock.replace_route(route);
    }
}

/// Parse a scope specification into a `ScopeSet`.
fn parse_scope(items: &[String]) -> ScopeSet {
    if items.len() == 1 && items[0] == "*" {
        ScopeSet::Wildcard
    } else {
        ScopeSet::Allowlist(items.to_vec())
    }
}

/// Create a secret file with mode 0600 and return its path.
fn create_secret_file(value: &str) -> PathBuf {
    let mut file = tempfile::NamedTempFile::new().expect("create secret file");
    file.write_all(value.as_bytes())
        .expect("write secret value");
    file.flush().expect("flush secret file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
            .expect("set secret file permissions");
    }

    file.into_temp_path().keep().expect("keep secret file")
}

/// Install a crypto provider once for the whole test binary.
///
/// `mecmcp-http` deliberately does not pick a provider, so tests stand in for
/// the consumer binary. `install_default` is process-global and one-shot.
fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// The routes `handler_with_guest` serves, exposed so a test can reuse them
/// with a different token scope.
///
/// # Parameters
/// - `_vmid`: kept for symmetry with `handler_with_guest`; the fixture guest is 617
/// - `protected`: whether the fixture guest carries the `protected` tag
#[must_use]
pub fn default_guest_routes(_vmid: u32, protected: bool) -> Vec<Route> {
    vec![
        Route {
            path: "/api2/json/nodes",
            status: 200,
            body:
                br#"{"data":[{"node":"pve2","status":"online"},{"node":"pve3","status":"online"}]}"#,
        },
        Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: if protected {
                br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},{"id":"lxc/617","type":"lxc","vmid":617,"name":"test-guest-617","node":"pve2","status":"stopped","tags":"protected"}]}"#
            } else {
                br#"{"data":[{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"},{"id":"lxc/617","type":"lxc","vmid":617,"name":"test-guest-617","node":"pve2","status":"stopped","tags":"test"}]}"#
            },
        },
        // A read that resolves through GuestIndex, so a test can deliberately
        // warm the snapshot the plan path reads. Carries a `digest` and a
        // disk: the plan/apply fingerprint reads both from this endpoint, and
        // an absent field would make the whole fixture untestable for drift.
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/config",
            status: 200,
            body: br#"{"data":{"hostname":"test-guest-617","cores":1,"memory":512,"digest":"aabbccddeeff00112233445566778899aabbccdd","rootfs":"local-lvm:vm-617-disk-0,size=8G"}}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:"}"#,
        },
        Route {
            path: "/api2/json/nodes/pve2/lxc/617/migrate",
            status: 200,
            body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzmigrate:617:root@pam:"}"#,
        },
    ]
}

/// Create a test handler configured with a specific guest.
///
/// # Parameters
/// - `_vmid`: The guest VMID to configure
/// - `protected`: Whether the guest should be protected
pub async fn handler_with_guest(_vmid: u32, protected: bool) -> TestServer {
    handler_with_guest_on_state(_vmid, protected, None).await
}

/// As [`handler_with_guest`], but persisting change-set state to `state_path`
/// so a test can inspect or hand-write the stored records.
pub async fn handler_with_guest_on_state(
    _vmid: u32,
    protected: bool,
    state_path: Option<std::path::PathBuf>,
) -> TestServer {
    let _tags = if protected { "protected" } else { "test" };
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
            // The operation's own tool, not just the generic handlers. These
            // tests planned a guest destroy while holding no `delete_vm`
            // scope, which the per-operation check now refuses — correctly:
            // that was the bypass it exists to close.
            "delete_vm".to_owned(),
            // The fixture guest is an LXC, and a guest destroy authorises
            // against its own type: delete_container, not delete_vm.
            "delete_container".to_owned(),
            // Migration: the fixture guest is an LXC, so migrate_container,
            // not migrate_vm.
            "migrate_container".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };

    let routes = default_guest_routes(_vmid, protected);

    TestServer::start_with_config_on_state(
        spec,
        routes,
        Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
        false,
        state_path,
    )
    .await
}

/// As [`handler_with_guest_on_state`], with the request limits also
/// caller-supplied instead of hardcoded to [`LimitsConfig::default`].
///
/// For a test that calls [`TestServer::shutdown`] on the returned server and
/// needs the session reaper to actually run within the test's lifetime: see
/// [`TestServer::shutdown`] for why a short `session_idle_timeout_secs` is
/// required for that to converge at all.
pub async fn handler_with_guest_on_state_and_limits(
    _vmid: u32,
    protected: bool,
    state_path: Option<std::path::PathBuf>,
    limits: LimitsConfig,
) -> TestServer {
    let spec = TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_proxmox_destroy".to_owned(),
            "get_proxmox_change_set".to_owned(),
            "approve_proxmox_change_set".to_owned(),
            "apply_proxmox_change_set".to_owned(),
            "delete_vm".to_owned(),
            "delete_container".to_owned(),
            "migrate_container".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    };

    let routes = default_guest_routes(_vmid, protected);

    TestServer::start_with_config_on_state_and_limits(
        spec,
        routes,
        Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
        false,
        state_path,
        limits,
    )
    .await
}

/// Make an MCP tool call.
///
/// Uses McpClient with proper initialize handshake. McpClient is synchronous,
/// so we spawn_blocking to avoid deadlocking against the server on the same runtime.
///
/// # Errors
///
/// Returns an error if the tool call fails.
pub async fn call(
    server: &TestServer,
    tool: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    call_with_token(server, &server.token, tool, args).await
}

/// Make an MCP tool call with a specific token.
///
/// # Errors
///
/// Returns an error if the tool call fails.
pub async fn call_with_token(
    server: &TestServer,
    token: &str,
    tool: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    use mecmcp_transport::test_client::McpClient;

    let url = server.url.clone();
    let token = token.to_owned();
    let tool = tool.to_owned();

    tokio::task::spawn_blocking(move || {
        let client = McpClient::new(&url)
            .map_err(|e| format!("create client: {e}"))?
            .with_bearer(&token);
        let session_id = client
            .initialize()
            .map_err(|e| format!("initialize: {e}"))?;
        call_on_session(&client, &session_id, &tool, args)
    })
    .await
    .map_err(|e| format!("spawn_blocking: {e}"))?
}

/// Parse one `tools/call` response into the same `Ok(json)` / `Err(message)`
/// shape [`call_with_token`] returns, without opening a new client or
/// session. Extracted so a caller that needs to make many calls -- a
/// catalog sweep, say -- can `initialize()` once and reuse the session,
/// instead of paying a fresh MCP handshake per call.
fn call_on_session(
    client: &mecmcp_transport::test_client::McpClient,
    session_id: &str,
    tool: &str,
    args: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let result = client
        .tools_call(session_id, tool, args)
        .map_err(|e| format!("call: {e}"))?;

    eprintln!(
        "Full MCP result: {}",
        serde_json::to_string_pretty(&result).unwrap_or_else(|_| format!("{result:?}"))
    );

    let is_error = result
        .get("isError")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let text = result
        .get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
        .ok_or_else(|| format!("no result text, response: {result}"))?;

    if is_error {
        Err(text.to_owned())
    } else {
        serde_json::from_str(text).map_err(|e| format!("json parse: {e}"))
    }
}

/// Make many `tools/call` requests over a single MCP session (one
/// `initialize()`, not one per call). Each element of `calls` is
/// `(tool, args)`; results come back in the same order, each as `Ok(json)`
/// on success or `Err(message)` on an MCP-level or transport-level error --
/// a caller that wants to fail on transport errors rather than treat them as
/// "no leak found" should check the error text itself.
///
/// # Errors
///
/// Returns an error only if the session itself cannot be established
/// (client construction or `initialize()`); a failure of one call in
/// `calls` is reported in that call's own `Result`, not here.
pub async fn call_many_on_one_session(
    server: &TestServer,
    token: &str,
    calls: Vec<(&'static str, serde_json::Value)>,
) -> Result<Vec<Result<serde_json::Value, String>>, String> {
    use mecmcp_transport::test_client::McpClient;

    let url = server.url.clone();
    let token = token.to_owned();

    tokio::task::spawn_blocking(move || {
        let client = McpClient::new(&url)
            .map_err(|e| format!("create client: {e}"))?
            .with_bearer(&token);
        let session_id = client
            .initialize()
            .map_err(|e| format!("initialize: {e}"))?;

        Ok(calls
            .into_iter()
            .map(|(tool, args)| call_on_session(&client, &session_id, tool, args))
            .collect())
    })
    .await
    .map_err(|e| format!("spawn_blocking: {e}"))?
}

/// Approve a change set as a second principal.
pub async fn approve_as_second_principal(server: &TestServer, change_set_id: &str) {
    approve_as_second_principal_for(server, change_set_id, "pve3", 617).await;
}

/// Approve a change set as a second principal for a specific cluster and vmid.
pub async fn approve_as_second_principal_for(
    server: &TestServer,
    change_set_id: &str,
    cluster: &str,
    vmid: u32,
) {
    call_with_token(
        server,
        &server.second_token,
        "approve_proxmox_change_set",
        serde_json::json!({
            "change_set_id": change_set_id,
            "cluster": cluster,
            "vmid": vmid
        }),
    )
    .await
    .expect("second principal approval should succeed");
}

impl TestServer {
    /// Replace a guest's own `/config` response, e.g. to simulate the guest's
    /// config or a disk changing between plan and apply.
    ///
    /// Unlike `/cluster/resources`, nothing caches this endpoint: the
    /// plan/apply fingerprint fetches it fresh on every call, so no index
    /// invalidation is needed here the way `move_guest_to_node` needs one.
    pub fn set_guest_config(&self, node: &str, kind: &str, vmid: u32, body: &'static [u8]) {
        self.mock.replace_route(Route {
            path: Box::leak(
                format!("/api2/json/nodes/{node}/{kind}/{vmid}/config").into_boxed_str(),
            ),
            status: 200,
            body,
        });
    }

    /// Simulate moving a guest to a different node (changes fingerprint).
    ///
    /// Updates the mock Proxmox's `/api2/json/cluster/resources` response to
    /// show the guest on a different node, which causes the fingerprint to change.
    /// Also invalidates the guest index cache so the next resolve sees the change.
    pub fn move_guest_to_node(&self, vmid: u32, new_node: &str) {
        // Replace the cluster/resources route with updated guest data.
        // The hardcoded guest 617 is moved to the specified node.
        let body = format!(
            r#"{{"data":[{{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"}},{{"id":"lxc/{}","type":"lxc","vmid":{},"name":"test-guest-{}","node":"{}","status":"stopped","tags":"test"}}]}}"#,
            vmid, vmid, vmid, new_node
        );

        self.mock.replace_route(Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: Box::leak(body.into_boxed_str()).as_bytes(),
        });

        // The re-fetched fingerprint reads the guest's config from its
        // (now-current) node, so the mock needs a route there too, or the
        // apply fails on the fetch itself rather than on the fingerprint
        // mismatch the test means to exercise. `replace_route` adds a route
        // that does not already exist, which this one does not.
        self.mock.replace_route(Route {
            path: Box::leak(format!("/api2/json/nodes/{new_node}/lxc/{vmid}/config").into_boxed_str()),
            status: 200,
            body: br#"{"data":{"hostname":"test-guest-moved","cores":1,"memory":512,"digest":"aabbccddeeff00112233445566778899aabbccdd","rootfs":"local-lvm:vm-617-disk-0,size=8G"}}"#,
        });

        // Invalidate the cache so the next resolve fetches the updated data.
        self.index.invalidate();
    }

    /// Move a guest **without** invalidating the index.
    ///
    /// This is what production looks like: Proxmox changes underneath a cached
    /// `/cluster/resources` snapshot and nothing tells the server. A handler
    /// that relies on the cache expiring cannot notice within the TTL, so any
    /// guarantee resting on a re-resolve has to drop the cache itself.
    pub fn move_guest_to_node_leaving_cache_stale(&self, vmid: u32, new_node: &str) {
        let body = format!(
            r#"{{"data":[{{"id":"qemu/905","type":"qemu","vmid":905,"name":"vsrx-prod","node":"pve2","status":"running","tags":"protected"}},{{"id":"lxc/{}","type":"lxc","vmid":{},"name":"test-guest-{}","node":"{}","status":"stopped","tags":"test"}}]}}"#,
            vmid, vmid, vmid, new_node
        );

        self.mock.replace_route(Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: Box::leak(body.into_boxed_str()).as_bytes(),
        });

        // Same reasoning as `move_guest_to_node`: whichever node the next
        // resolve reports, its config endpoint must exist for the fingerprint
        // re-check to reach its own comparison rather than failing the fetch.
        self.mock.replace_route(Route {
            path: Box::leak(format!("/api2/json/nodes/{new_node}/lxc/{vmid}/config").into_boxed_str()),
            status: 200,
            body: br#"{"data":{"hostname":"test-guest-moved","cores":1,"memory":512,"digest":"aabbccddeeff00112233445566778899aabbccdd","rootfs":"local-lvm:vm-617-disk-0,size=8G"}}"#,
        });
    }
}
