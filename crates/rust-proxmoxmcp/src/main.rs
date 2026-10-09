//! One MCP server for many Proxmox VE clusters.

mod cli;
mod http_transport;
mod readiness;
mod server;

use anyhow::{Context as _, Result};
use cli::{ProxmoxCli, TokenCli, TokenCommand, server_naming};
use http_transport::build_http_router;
use mecmcp_auth::TokenStoreFile;
use mecmcp_runtime::cli::{Command, TokenAction, Transport};
use mecmcp_secret::validate::{CredentialFileRole, CredentialFileSpec, validate_credential_files};
use mecmcp_transport::{LimitsConfig, serve_router};
use rmcp::ServiceExt as _;
use rust_proxmoxmcp_core::{
    ProxmoxAction, ProxmoxGrant, client::ProxmoxClient, inventory::ClusterInventory,
    resolve::GuestIndex, selector::Selector,
};
use server::ProxmoxServer;
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

/// Canonical token store and the legacy `/etc` location an unmigrated
/// install may still be using.
fn token_store_paths() -> (PathBuf, PathBuf) {
    let naming = server_naming();
    (
        naming.state_dir.join("tokens.json"),
        naming.config_dir.join("tokens.json"),
    )
}

/// Resolve the token file path, applying the legacy fallback ONLY when the
/// configured path is the canonical `/var/lib/proxmoxmcp/tokens.json`.
///
/// Any other configured path is used verbatim and fails if absent — that is the
/// honest outcome. This prevents a typo or deliberately deleted custom store from
/// silently reactivating unrelated or revoked credentials at the legacy path.
fn resolve_tokens(configured: &Path) -> Result<mecmcp_auth::ResolvedTokenPath> {
    let (canonical, legacy) = token_store_paths();
    resolve_tokens_with(configured, &canonical, &legacy)
}

/// The rule behind [`resolve_tokens`], with the two well-known paths injected so
/// it can be exercised against real files in a test rather than against absolute
/// paths that never exist there.
fn resolve_tokens_with(
    configured: &Path,
    canonical: &Path,
    legacy: &Path,
) -> Result<mecmcp_auth::ResolvedTokenPath> {
    // Byte-exact, not `Path` equality. `Path` comparison normalizes away trailing
    // separators and `.` components, so `/var/lib/<svc>/tokens.json/` compares
    // EQUAL to the canonical path — while `metadata()` on that spelling returns
    // NotFound when the file is absent, indistinguishable from the plain form.
    // A typo would therefore pass this gate and activate the legacy store, which
    // is exactly the fail-closed behaviour this check exists to provide.
    if configured.as_os_str() != canonical.as_os_str() {
        return Ok(mecmcp_auth::ResolvedTokenPath {
            path: configured.to_path_buf(),
            used_fallback: false,
            fallback_from: None,
        });
    }

    mecmcp_auth::resolve_token_path(configured, legacy).context("resolving token file path")
}

/// Token store the HTTP listener will load.
///
/// Stdio does not consult `--tokens-file`. The container entrypoint bakes
/// that flag in, and a stdio start must not fail because the bearer store
/// is absent.
fn listener_tokens(args: &ProxmoxCli) -> Result<Option<mecmcp_auth::ResolvedTokenPath>> {
    match args.common.transport {
        Transport::Stdio => Ok(None),
        Transport::StreamableHttp => match args.common.tokens_file.as_deref() {
            Some(path) => Ok(Some(resolve_tokens(path)?)),
            None => Ok(None),
        },
    }
}

/// API token paths named by `clusters.json`.
///
/// Discovery follows the three shapes `mecmcp-inventory` loads: a `devices`
/// object, a `devices` array, or a flat map whose keys do not start with
/// `_`. This only discovers the paths. Mode is enforced later, with every
/// other file, by [`validate_startup_credentials`]. A missing or unreadable
/// inventory yields an empty list; the mode pass still reports the inventory
/// itself. `ca_pem_path` is not collected: a cluster CA bundle is public
/// trust material, loaded with a plain read that accepts mode `0644`.
fn cluster_token_secret_files(clusters_file: &Path) -> Vec<PathBuf> {
    let limit = mecmcp_secret::FileLimits::default().max_bytes;
    let bytes = match std::fs::metadata(clusters_file) {
        Ok(metadata) if metadata.len() > u64::try_from(limit).unwrap_or(u64::MAX) => {
            return Vec::new();
        }
        Ok(_) => match std::fs::read(clusters_file) {
            Ok(bytes) if bytes.len() <= limit => bytes,
            _ => return Vec::new(),
        },
        Err(_) => return Vec::new(),
    };
    let value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let mut paths = Vec::new();
    for device in inventory_device_values(&value) {
        let Some(path) = device
            .get("token_secret_file")
            .and_then(|entry| entry.as_str())
        else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        paths.push(PathBuf::from(path));
    }
    paths.sort();
    paths.dedup();
    paths
}

/// Device objects from any inventory shape the loader accepts.
///
/// A `devices` object contributes its values. A `devices` array contributes
/// its elements. With no `devices` key, the top-level values are the devices,
/// except keys that start with `_` (`_blocklist_defaults` is policy, not a
/// cluster). A `devices` value that is neither object nor array is ignored:
/// the loader rejects that document, and this pass still checks the inventory
/// file itself.
fn inventory_device_values(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    let Some(root) = value.as_object() else {
        return Vec::new();
    };
    match root.get("devices") {
        Some(serde_json::Value::Object(devices)) => devices.values().collect(),
        Some(serde_json::Value::Array(devices)) => devices.iter().collect(),
        Some(_) => Vec::new(),
        None => root
            .iter()
            .filter(|(key, _)| !key.starts_with('_'))
            .map(|(_, device)| device)
            .collect(),
    }
}

/// Files whose mode is checked together, before any of them is loaded.
///
/// A startup that checks one file and exits reports the next bad mode only
/// on the next restart. [`validate_startup_credentials`] asks `mecmcp-secret`
/// to report every offender in this list at once.
struct StartupCredentialFiles<'a> {
    /// `clusters.json`. Required. The document holds no credential, but the
    /// inventory loader is `read_hardened_file`, which rejects group and
    /// other bits, so the required mode stays `0600`.
    clusters: &'a Path,
    /// Waiver file. Checked when the path is configured. An absent file is
    /// an empty waiver list, so a missing file is not a failure.
    waivers: Option<&'a Path>,
    /// Bearer-token store this process will load. Required when set.
    tokens: Option<&'a Path>,
    /// Audit HMAC key. Required when set; the caller creates a missing key first.
    audit_hmac_key: Option<&'a Path>,
    /// Approval digest key from `--approval-digest-key-file`. Required when set.
    approval_digest_key: Option<&'a Path>,
}

/// Check every credential-adjacent file in one pass.
///
/// On-disk paths are unchanged. The inventory path is whatever
/// `--clusters-file` names, each API token path is the one that inventory
/// names, and the bearer-store path is the one [`resolve_tokens`] already
/// selected, including the legacy `/etc` store when that fallback is in
/// effect. A cluster CA bundle is not in this list.
fn validate_startup_credentials(files: &StartupCredentialFiles<'_>) -> Result<()> {
    let token_files = cluster_token_secret_files(files.clusters);
    let mut specs = Vec::with_capacity(5 + token_files.len());
    specs.push(CredentialFileSpec {
        path: files.clusters,
        role: CredentialFileRole::Secret,
        description: "cluster inventory",
        required: true,
    });
    for path in &token_files {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "cluster API token",
            required: false,
        });
    }
    if let Some(path) = files.waivers {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "operator waivers",
            required: false,
        });
    }
    if let Some(path) = files.tokens {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "bearer token store",
            required: true,
        });
    }
    if let Some(path) = files.audit_hmac_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "audit HMAC key",
            required: true,
        });
    }
    if let Some(path) = files.approval_digest_key {
        specs.push(CredentialFileSpec {
            path,
            role: CredentialFileRole::Secret,
            description: "approval digest key",
            required: true,
        });
    }

    validate_credential_files(&specs)?;
    Ok(())
}

/// Build a vendor grant from TokenCommand::Add fields.
///
/// Returns `None` when no guest selectors are given, allowing cluster-scoped
/// tokens. Validates selectors at mint time and prints a note when omitted.
fn build_token_grant_from_add(
    guests: &[String],
    actions: &[String],
) -> Result<Option<ProxmoxGrant>> {
    // No grant fields given: token will work for cluster-scoped tools only.
    if guests.is_empty() {
        eprintln!(
            "Note: This token cannot use guest-addressed tools. \
             Use --guests '*' or a selector (vmid:X, tag:Y, pool:Z) to grant guest access."
        );
        return Ok(None);
    }

    // Validate each selector at mint time. A selector that cannot parse produces
    // a token that silently admits nothing, which an operator cannot diagnose.
    for term in guests {
        Selector::parse(term)
            .map_err(|error| anyhow::anyhow!("invalid --guests selector '{term}': {error}"))?;
    }

    // Parse action names.
    let parsed_actions: Result<Vec<ProxmoxAction>> = actions
        .iter()
        .map(|name| match name.as_str() {
            "read" => Ok(ProxmoxAction::Read),
            "low" => Ok(ProxmoxAction::Low),
            "destructive" => Ok(ProxmoxAction::Destructive),
            other => Err(anyhow::anyhow!(
                "invalid --actions value '{other}': must be read, low, or destructive"
            )),
        })
        .collect();

    Ok(Some(ProxmoxGrant {
        guests: guests.to_vec(),
        actions: parsed_actions?,
    }))
}

/// Build a replacement vendor grant for `TokenCommand::SetScopes`.
///
/// Returns `None` when neither `--guests` nor `--actions` is given, which
/// leaves the existing grant untouched. `--actions` alone is refused: a grant
/// carries both halves, and inventing a guest selector to satisfy the other
/// half would grant reach the operator never named.
fn build_token_grant_from_set_scopes(
    guests: Option<&Vec<String>>,
    actions: Option<&Vec<String>>,
) -> Result<Option<ProxmoxGrant>> {
    match (guests, actions) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(anyhow::anyhow!(
            "--actions requires --guests: a grant carries both, and this command \
             replaces it wholesale rather than merging"
        )),
        (Some(guests), actions) => {
            // Default to read when actions are omitted, matching `add`. An
            // omitted action list must not silently preserve a destructive
            // grant the operator is replacing.
            let actions = actions.cloned().unwrap_or_else(|| vec!["read".to_owned()]);
            build_token_grant_from_add(guests, &actions)
        }
    }
}

/// Convert `TokenCommand` to `TokenAction` and extract grant for Add.
fn token_command_to_action(command: TokenCommand) -> Result<(TokenAction, Option<ProxmoxGrant>)> {
    match command {
        TokenCommand::Add {
            tokens_file,
            name,
            devices,
            tools,
            guests,
            actions,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            server_pid,
        } => {
            let grant = build_token_grant_from_add(&guests, &actions)?;
            let action = TokenAction::Add {
                tokens_file,
                name,
                devices,
                tools,
                provider,
                provider_tier,
                on_behalf_of,
                actor_type,
                server_pid,
            };
            Ok((action, grant))
        }
        TokenCommand::Revoke {
            tokens_file,
            name,
            server_pid,
        } => Ok((
            TokenAction::Revoke {
                tokens_file,
                name,
                server_pid,
            },
            None,
        )),
        TokenCommand::List { tokens_file } => Ok((TokenAction::List { tokens_file }, None)),
        TokenCommand::SetScopes {
            tokens_file,
            name,
            devices,
            tools,
            guests,
            actions,
            yes,
            server_pid,
        } => {
            let grant = build_token_grant_from_set_scopes(guests.as_ref(), actions.as_ref())?;
            Ok((
                TokenAction::SetScopes {
                    tokens_file,
                    name,
                    devices,
                    tools,
                    yes,
                    server_pid,
                },
                grant,
            ))
        }
        TokenCommand::Rotate {
            tokens_file,
            name,
            server_pid,
        } => Ok((
            TokenAction::Rotate {
                tokens_file,
                name,
                server_pid,
            },
            None,
        )),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // mecmcp decision D4: the consumer installs the process-global rustls crypto
    // provider, and it must be installed before ANYTHING builds a TLS-capable
    // client. The binary installs it, once, before any client is constructed.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider was already installed"))?;

    // Dispatch token commands before parsing ProxmoxCli.
    //
    // This keeps grant-specific flags (--guests, --actions) off the server's help
    // and allows them to appear after the subcommand where they belong. The
    // flattened Cli still declares its own `token` subcommand, but TokenCli owns
    // the complete token surface including --help when argv names `token`.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("token") {
        use clap::Parser;
        // Build args for TokenCli: [program_name, add/revoke/list/rotate, ...]
        // Skip "token" at index 1 since TokenCli expects the subcommand directly.
        let token_args = std::iter::once(args[0].clone())
            .chain(args.iter().skip(2).cloned())
            .collect::<Vec<_>>();
        let token_cli = TokenCli::parse_from(token_args);

        // Install a subscriber before dispatching. `run_with_grant` emits the
        // scope change as a `target: "audit"` event, and this path returns
        // long before the server's `init_audit`, so without one every token
        // mutation — a mint, a revoke, a privilege widening — is written to
        // disk having left no record that it happened.
        //
        // Deliberately minimal: the token CLI carries no audit flags, so there
        // is no log file, journald sink, or redaction policy to honour. The
        // operator running the command is the audience, and stderr is where
        // they are looking.
        init_token_audit();

        let (action, grant) = token_command_to_action(token_cli.command)?;
        return mecmcp_runtime::token_cmd::run_with_grant::<ProxmoxGrant>(
            action,
            &[],
            server::KNOWN_TOOLS,
            grant,
        )
        .map_err(|error| anyhow::anyhow!("{error}"));
    }

    let parsed = mecmcp_runtime::cli::parse_with_provenance::<ProxmoxCli>(
        "rust-proxmoxmcp",
        env!("CARGO_PKG_VERSION"),
    );
    let mut args = parsed.cli;

    mecmcp_runtime::cli_validate::validate(&args.common)
        .map_err(|refusal| anyhow::anyhow!("{refusal}"))?;

    let audit_sink = init_audit(&args.common)?;

    if let Some(Command::Token { .. }) = args.common.command.take() {
        // This path fires when a server flag precedes the subcommand
        // (e.g., `--clusters-file X token add ...`). The early dispatch at argv[1]
        // does not intercept it, so TokenCli's grant-specific flags (--guests,
        // --actions) are unavailable. Refuse rather than silently minting a
        // grantless token.
        return Err(anyhow::anyhow!(
            "token subcommand must appear before server flags; use: \
             rust-proxmoxmcp token add [options]"
        ));
    }

    // Resolve before the mode pass so a legacy `/etc` store is the file that
    // gets checked, not the canonical path that is not there yet. `init_audit`
    // already created a missing HMAC key, so the mode pass sees the file it
    // will actually use.
    let tokens_resolved = listener_tokens(&args)?;
    validate_startup_credentials(&StartupCredentialFiles {
        clusters: &args.clusters_file,
        waivers: Some(&args.waivers_file),
        tokens: tokens_resolved
            .as_ref()
            .map(|resolved| resolved.path.as_path()),
        audit_hmac_key: args.common.audit_hmac_key_file.as_deref(),
        approval_digest_key: args.common.approval_digest_key_file.as_deref(),
    })
    .context("credential file validation")?;

    let approval_digest_key =
        load_approval_digest_key(args.common.approval_digest_key_file.as_deref())?;

    let clusters = Arc::new(
        ClusterInventory::load(&args.clusters_file)
            .with_context(|| format!("loading {}", args.clusters_file.display()))?,
    );

    let mut clients = BTreeMap::new();
    for name in clusters.names() {
        let cluster = clusters.get(&name)?;
        clients.insert(
            name.clone(),
            ProxmoxClient::new(cluster).with_context(|| format!("build client for {name}"))?,
        );
    }
    let clients = Arc::new(clients);

    let index = Arc::new(GuestIndex::new(Duration::from_secs(
        clusters.policy().resource_cache_ttl_secs,
    )));

    let waivers = Arc::new(
        rust_proxmoxmcp_core::waiver::WaiverFile::load(&args.waivers_file)
            .with_context(|| format!("loading {}", args.waivers_file.display()))?,
    );

    // Built before serving because the coordinator takes the recorder, and
    // started eagerly so a misconfiguration stops the server here rather than
    // at the first change.
    let evidence = match args.common.evidence.into_config() {
        Ok(Some(config)) => {
            tracing::info!(
                server_id = %config.server_id,
                run_id = %config.run_id,
                "SSDF evidence pipeline enabled"
            );
            // aws-lc-rs, not ring: this server's rustls is built with that
            // provider (workspace Cargo.toml), and the fleet is genuinely split.
            // Taking the provider as a parameter rather than hardcoding one in
            // mecmcp-audit is what lets both halves use the same transport.
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let transport = Arc::new(
                mecmcp_transport::evidence_transport::EvidenceHttpTransport::new(
                    args.common.evidence.ca_file(),
                    provider,
                )
                .context("building the SSDF evidence transport")?,
            );
            Some(
                mecmcp_audit::EvidenceService::start_with_transport(config, transport)
                    .context("starting the SSDF evidence pipeline")?,
            )
        }
        Ok(None) => None,
        Err(error) => anyhow::bail!("SSDF evidence configuration: {error}"),
    };
    let recorder = evidence
        .as_ref()
        .map(mecmcp_audit::EvidenceService::recorder);

    // Direct-commit tools (the interrupting lifecycle verbs, `stop_task`,
    // `update_container_resources`, `clone_vm`, `create_vm`,
    // `create_container`, `resize_disk`, and `create_backup`) mutate a guest
    // in one call with no change-set approval. Refused by default; logging
    // here mirrors the lab-mode banner above.
    let direct_commit = mecmcp_audit::DirectCommitPolicy::new(args.allow_direct_commit);
    direct_commit.log_startup("rust-proxmoxmcp");
    if !args.allow_direct_commit {
        tracing::info!(
            "direct-commit tools disabled: stop_vm, shutdown_vm, reset_vm, stop_container, \
             restart_container, stop_task, update_container_resources, clone_vm, create_vm, \
             create_container, resize_disk and create_backup are refused on stdio and HTTP \
             alike. Use --allow-direct-commit to enable them."
        );
    }

    let served = match args.common.transport {
        Transport::Stdio => {
            // SIGHUP reopens the audit log and reloads the inventory in
            // place. Stdio has no token store.
            install_sighup_reload(
                Arc::clone(&clusters),
                Arc::clone(&index),
                None,
                audit_sink.clone(),
            )?;
            serve_stdio(
                clusters,
                clients,
                index,
                waivers,
                args.lab_mode,
                recorder,
                direct_commit,
                args.state_file.clone(),
                approval_digest_key.clone(),
            )
            .await
        }
        Transport::StreamableHttp => {
            let token_store = load_http_token_store(tokens_resolved, args.common.allow_no_auth)?;

            // Check for stale secrets (superseded token files, old TLS keys) in both
            // the state dir and the config dir. Warn, never refuse.
            let naming = server_naming();
            let live_files = ["tokens.json"];
            for dir in [&naming.state_dir, &naming.config_dir] {
                let stale = mecmcp_auth::find_stale_secrets(dir, &live_files);
                for secret in stale {
                    tracing::warn!(
                        path = %secret.path.display(),
                        reason = ?secret.reason,
                        "Stale secret file detected. Consider removing after verifying it is no longer referenced."
                    );
                }
            }

            // Install SIGHUP handler that reopens the audit log and reloads
            // both inventory and token store.
            install_sighup_reload(
                Arc::clone(&clusters),
                Arc::clone(&index),
                token_store.clone(),
                audit_sink.clone(),
            )?;

            let tls = load_listener_tls(&args.common)?;
            let host = args
                .common
                .host
                .parse::<std::net::IpAddr>()
                .context("invalid --host IP address")?;
            let address = SocketAddr::new(host, args.common.port);
            let shutdown = tokio_util::sync::CancellationToken::new();

            // Install signal handlers
            let signal_shutdown = shutdown.clone();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm =
                    signal(SignalKind::terminate()).context("installing SIGTERM handler")?;
                let mut sigint =
                    signal(SignalKind::interrupt()).context("installing SIGINT handler")?;
                tokio::spawn(async move {
                    tokio::select! {
                        _ = sigterm.recv() => {
                            tracing::info!("SIGTERM received");
                        }
                        _ = sigint.recv() => {
                            tracing::info!("SIGINT received");
                        }
                    }
                    signal_shutdown.cancel();
                });
            }
            #[cfg(not(unix))]
            {
                tokio::spawn(async move {
                    tokio::signal::ctrl_c().await.ok();
                    tracing::info!("Ctrl+C received");
                    signal_shutdown.cancel();
                });
            }

            let shutdown_timeout = Duration::from_secs(10);
            serve_http(
                clusters,
                clients,
                index,
                address,
                token_store,
                args.common.allowed_host,
                args.common.allowed_origin,
                args.limits.to_limits_config(),
                args.enable_metrics,
                args.common.allow_insecure_bind,
                tls,
                shutdown,
                shutdown_timeout,
                waivers,
                args.lab_mode,
                recorder,
                direct_commit,
                args.state_file.clone(),
                approval_digest_key,
            )
            .await
        }
    };

    // Deliver what is still spooled, whichever way serving ended. Bound rather
    // than returned directly so the flush runs on the error path too -- which
    // is exactly when an unshipped trail matters most.
    if let Some(service) = evidence
        && let Err(error) = service.shutdown()
    {
        tracing::error!(%error, "the SSDF evidence pipeline did not flush cleanly");
    }

    served
}

/// Install a stderr subscriber for the standalone token command path.
///
/// Separate from [`init_audit`] because the token CLI has no audit flags to
/// read: there is no log file, journald sink, or redaction policy on this
/// path, only an operator at a terminal. Failure is ignored because a
/// subscriber already installed is not an error worth refusing a token
/// operation over.
fn init_token_audit() {
    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;
    use tracing_subscriber::{EnvFilter, filter::filter_fn, fmt};

    // Two layers, each with its own filter, because the audit record must not
    // be reachable by RUST_LOG at all.
    //
    // Adding `audit=info` to the env filter is not enough: `EnvFilter` picks
    // the most specific matching directive, so a field-specific value such as
    // `audit[{tool}]=off` still wins over a target-only one. Measured — the
    // widening applied and stderr stayed empty:
    //
    //     RUST_LOG=audit=off            audit lines: 1
    //     RUST_LOG=audit[{tool}]=off    audit lines: 0   <- silent widening
    //
    // So the audit layer carries a plain predicate instead, which no
    // environment variable participates in.
    let audit_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(filter_fn(|metadata| metadata.target() == "audit"));

    // Everything else follows RUST_LOG as usual, minus the audit target so a
    // permissive filter cannot print the record twice.
    let general_layer = fmt::layer()
        .with_writer(std::io::stderr)
        .with_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_filter(filter_fn(|metadata| metadata.target() != "audit"));

    // `try_init`, not `init`: a subscriber already installed is not a reason
    // to refuse a token operation.
    let _ = tracing_subscriber::registry()
        .with(audit_layer)
        .with(general_layer)
        .try_init();
}

/// Pre-provision the audit HMAC key file at `path` if it is absent or empty,
/// mirroring `packaging/lxc/install.sh`'s own key-generation step so every
/// entry point -- LXC install, systemd start, or a container's first run --
/// converges on the same keyed-audit posture instead of only the LXC path
/// doing it (mecmcp#376 / MEC-978). `--audit-redact` still defaults to empty
/// (redaction stays opt-in), so this alone does not turn redaction on; it
/// just means the key is already there the moment an operator flips
/// `--audit-redact ...=hmac` on, instead of failing on that first restart.
///
/// A zero-byte key file is indistinguishable from "never generated" and
/// would make every HMAC output constant, so rewriting it here is a repair,
/// not data loss. A non-empty file is never rotated -- that would silently
/// break verification of every audit record signed under the old key.
fn ensure_audit_hmac_key(path: &std::path::Path) -> Result<()> {
    if std::fs::metadata(path)
        .map(|m| m.len() > 0)
        .unwrap_or(false)
    {
        return Ok(());
    }

    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|e| {
        anyhow::anyhow!("generating audit HMAC key: OS entropy source unavailable: {e}")
    })?;
    let hex_key: String = key.iter().map(|b| format!("{b:02x}")).collect();

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating audit HMAC key file {}", path.display()))?;
        use std::io::Write as _;
        file.write_all(hex_key.as_bytes())
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &hex_key)
            .with_context(|| format!("writing audit HMAC key file {}", path.display()))?;
    }

    Ok(())
}

fn init_audit(args: &mecmcp_runtime::cli::Cli) -> Result<Option<mecmcp_audit::AuditFileSink>> {
    if let Some(key_path) = args.audit_hmac_key_file.as_deref() {
        ensure_audit_hmac_key(key_path).context("pre-provisioning audit HMAC key file")?;
    }

    let redaction = if args.audit_redact.trim().is_empty() {
        None
    } else {
        Some(
            mecmcp_audit::AuditRedaction::parse(
                &args.audit_redact,
                args.audit_hmac_key_file.as_deref(),
            )
            .map_err(|error| anyhow::anyhow!("invalid --audit-redact: {error}"))?,
        )
    };
    // This binary does not build mecmcp-audit's `otel` feature, so refuse to
    // start when telemetry export is requested in a build that can't export
    // it.
    if args.otel_endpoint.is_some() {
        anyhow::bail!(
            "--otel-endpoint requires a build of rust-proxmoxmcp with mecmcp-audit's `otel` \
             feature, which this binary does not enable"
        );
    }
    let sink = mecmcp_audit::init_tracing(&mecmcp_audit::AuditConfig {
        format: mecmcp_audit::AuditFormat::parse(&args.audit_format),
        audit_log_file: args.audit_log_file.clone(),
        redaction,
        journald: args.audit_journald,
        otel: None,
    })
    .context("initializing audit tracing")?;
    mecmcp_audit::install_duration_metric_name("rust_proxmoxmcp_tool_duration_seconds");
    Ok(sink)
}

/// Load `--approval-digest-key-file`, if set.
///
/// `None` keeps the change-set coordinator on today's default digest mode.
/// A load failure must stop startup rather than continue without the key,
/// since this flag controls an approval security control.
fn load_approval_digest_key(
    path: Option<&std::path::Path>,
) -> Result<Option<mecmcp_changeset::ApprovalDigestKey>> {
    path.map(|path| {
        mecmcp_changeset::ApprovalDigestKey::load_from_file(path)
            .with_context(|| format!("loading --approval-digest-key-file {}", path.display()))
    })
    .transpose()
}

#[allow(clippy::too_many_arguments)]
async fn serve_stdio(
    clusters: Arc<ClusterInventory>,
    clients: Arc<BTreeMap<String, ProxmoxClient>>,
    index: Arc<GuestIndex>,
    waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    direct_commit: mecmcp_audit::DirectCommitPolicy,
    state_file: Option<PathBuf>,
    approval_digest_key: Option<mecmcp_changeset::ApprovalDigestKey>,
) -> Result<()> {
    let handler = ProxmoxServer::new_with_default_coordinator(
        clusters,
        clients,
        index,
        waivers,
        lab_mode,
        evidence,
        direct_commit,
        state_file.as_deref(),
        approval_digest_key,
    )
    .context("build server")?;

    // Before serving: settle any apply that was in flight when this process
    // last stopped. Proxmox kept running it, so the answer exists and only has
    // to be asked for. Doing it before the first request means a caller never
    // sees a change set stuck in `Applying` that this server could have
    // resolved.
    if state_file.is_none() {
        tracing::warn!(
            target: "audit",
            "no --state-file: change sets live in memory only, so every approval, \
             preview and in-flight apply is lost on restart and crash recovery \
             cannot run. Pass --state-file to persist them."
        );
    }
    handler.recover_in_flight().await;

    if lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets for protected guests are approved on creation \
             with no second principal. Records carry approval_waiver=lab-mode. \
             Do not run this against production devices."
        );
    }

    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .context("starting MCP stdio service")?;
    service
        .waiting()
        .await
        .map(|_| ())
        .context("MCP stdio service exited with error")
}

fn load_http_token_store(
    resolved: Option<mecmcp_auth::ResolvedTokenPath>,
    allow_no_auth: bool,
) -> Result<Option<Arc<TokenStoreFile<ProxmoxGrant>>>> {
    match (resolved, allow_no_auth) {
        (Some(resolved), false) => {
            // The CONFIGURED path is the primary; /etc is the legacy fallback, so an
            // upgrade whose tokens have not been moved yet still starts.
            //
            // Apply the legacy /etc fallback ONLY when the configured path is the
            // canonical state-dir store. A typo or deliberately deleted custom
            // store must fail, not silently reactivate credentials from /etc.
            // [`resolve_tokens`] enforces that restriction, and the mode pass
            // already checked the path this function loads.
            if let (true, Some(fallback_from)) = (resolved.used_fallback, &resolved.fallback_from) {
                let (canonical, _) = token_store_paths();
                tracing::warn!(
                    path = %resolved.path.display(),
                    fallback_from = %fallback_from.display(),
                    "Using fallback token file (primary does not exist). \
                     Token operations (add, revoke, rotate) will fail under ProtectSystem=strict. \
                     Move to {canonical} to restore write capability.",
                    canonical = canonical.display()
                );
            }

            let store = Arc::new(
                TokenStoreFile::<ProxmoxGrant>::load(&resolved.path)
                    .with_context(|| format!("loading {}", resolved.path.display()))?,
            );
            tracing::info!(
                path = %resolved.path.display(),
                tokens = store.store().len(),
                "token store loaded"
            );
            Ok(Some(store))
        }
        (None, true) => {
            tracing::warn!(
                "--allow-no-auth: Streamable HTTP accepts ordinary read requests \
                 without authentication on loopback; write tools remain denied"
            );
            Ok(None)
        }
        (Some(_), true) => Err(anyhow::anyhow!(
            "contradictory flags: both --tokens-file and --allow-no-auth were given"
        )),
        (None, false) => Err(anyhow::anyhow!(
            "Streamable HTTP requires either --tokens-file or --allow-no-auth"
        )),
    }
}

fn load_listener_tls(args: &mecmcp_runtime::cli::Cli) -> Result<Option<Arc<rustls::ServerConfig>>> {
    let (Some(cert), Some(key)) = (&args.tls_cert, &args.tls_key) else {
        return Ok(None);
    };
    // The process-global provider is installed in `main`; do not install again —
    // `install_default` returns Err when one is already set, and treating that
    // as fatal would break every TLS start.
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    mecmcp_transport::load_tls(cert, key, Arc::new(provider))
        .context("loading listener TLS")
        .map(Some)
}

fn install_sighup_reload(
    clusters: Arc<ClusterInventory>,
    index: Arc<GuestIndex>,
    token_store: Option<Arc<TokenStoreFile<ProxmoxGrant>>>,
    audit_sink: Option<mecmcp_audit::AuditFileSink>,
) -> std::io::Result<()> {
    mecmcp_runtime::signals::install_hup_handler(move || {
        // Reopen the audit log first: this is the lossless half of log
        // rotation (rename the file, signal the process), and a failure here
        // must not block the reloads below.
        if let Some(sink) = &audit_sink {
            match sink.reopen() {
                Ok(()) => {
                    tracing::info!(path = %sink.path().display(), "audit log reopened");
                }
                Err(error) => {
                    tracing::warn!(%error, path = %sink.path().display(), "audit log reopen failed; keeping previous sink");
                }
            }
        }

        // Reload cluster inventory.
        match clusters.reload() {
            Ok(count) => {
                index.invalidate();
                tracing::info!(clusters = count, "cluster inventory reloaded");
            }
            Err(error) => {
                tracing::error!(%error, "cluster inventory reload failed; retaining previous snapshot");
            }
        }

        // Reload token store if present (HTTP mode only).
        if let Some(ref store) = token_store {
            match store.reload() {
                Ok(()) => {
                    let count = store.store().len();
                    tracing::info!(tokens = count, "token store reloaded");
                }
                Err(error) => {
                    tracing::error!(%error, "token store reload failed; retaining previous snapshot");
                }
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn serve_http(
    clusters: Arc<ClusterInventory>,
    clients: Arc<BTreeMap<String, ProxmoxClient>>,
    index: Arc<GuestIndex>,
    address: SocketAddr,
    token_store: Option<Arc<TokenStoreFile<ProxmoxGrant>>>,
    allowed_hosts: Vec<String>,
    allowed_origins: Vec<String>,
    limits: LimitsConfig,
    enable_metrics: bool,
    allow_insecure_bind: bool,
    tls: Option<Arc<rustls::ServerConfig>>,
    shutdown: tokio_util::sync::CancellationToken,
    shutdown_timeout: Duration,
    waivers: Arc<rust_proxmoxmcp_core::waiver::WaiverFile>,
    lab_mode: bool,
    evidence: Option<Arc<mecmcp_audit::recorder::EvidenceRecorder>>,
    direct_commit: mecmcp_audit::DirectCommitPolicy,
    state_file: Option<PathBuf>,
    approval_digest_key: Option<mecmcp_changeset::ApprovalDigestKey>,
) -> Result<()> {
    let (readiness_checks, _readiness_handles) = readiness::spawn_cluster_readiness(&clients);

    let handler = ProxmoxServer::new_with_default_coordinator(
        clusters,
        clients,
        index,
        waivers,
        lab_mode,
        evidence,
        direct_commit,
        state_file.as_deref(),
        approval_digest_key,
    )
    .context("build server")?;

    // Before serving: settle any apply that was in flight when this process
    // last stopped. Proxmox kept running it, so the answer exists and only has
    // to be asked for. Doing it before the first request means a caller never
    // sees a change set stuck in `Applying` that this server could have
    // resolved.
    if state_file.is_none() {
        tracing::warn!(
            target: "audit",
            "no --state-file: change sets live in memory only, so every approval, \
             preview and in-flight apply is lost on restart and crash recovery \
             cannot run. Pass --state-file to persist them."
        );
    }
    handler.recover_in_flight().await;

    if lab_mode {
        tracing::warn!(
            target: "audit",
            "lab mode enabled: change sets for protected guests are approved on creation \
             with no second principal. Records carry approval_waiver=lab-mode. \
             Do not run this against production devices."
        );
    }

    let plan = build_http_router(
        handler,
        token_store,
        allowed_hosts,
        allowed_origins,
        limits,
        enable_metrics,
        allow_insecure_bind,
        shutdown,
        readiness_checks,
    )
    .map_err(|error| anyhow::anyhow!("building HTTP router: {error}"))?;

    serve_router(plan, address, tls, shutdown_timeout)
        .await
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod token_path_tests {
    use super::resolve_tokens_with;

    /// The canonical path is absent and the legacy store exists: the fallback
    /// must fire, so an upgrade that has not migrated yet still starts.
    #[test]
    fn canonical_path_falls_back_to_an_existing_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let resolved = resolve_tokens_with(&canonical, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, legacy,
            "the legacy store should have been used"
        );
        assert!(resolved.used_fallback);
    }

    /// The same legacy store exists, but the operator configured a DIFFERENT
    /// path. Falling back here would silently reactivate credentials they did
    /// not ask for — a typo or a deleted store must fail, not resurrect tokens.
    #[test]
    fn a_custom_path_never_falls_back_to_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();
        let custom = dir.path().join("operator-chosen.json");

        let resolved = resolve_tokens_with(&custom, &canonical, &legacy).unwrap();
        assert_eq!(
            resolved.path, custom,
            "an operator-supplied path must be used verbatim"
        );
        assert!(
            !resolved.used_fallback,
            "a custom path must never resolve to the legacy /etc store"
        );
    }

    /// A malformed spelling of the canonical path must NOT reach the fallback.
    ///
    /// `Path` equality normalizes away a trailing separator, so
    /// `.../tokens.json/` compares equal to the canonical path; and when the
    /// file is absent `metadata()` returns NotFound for that spelling too,
    /// indistinguishable from the plain form. A typo would therefore activate
    /// the legacy store — the opposite of fail-closed. The comparison is
    /// byte-exact for this reason.
    #[test]
    fn a_trailing_slash_spelling_does_not_reach_the_legacy_store() {
        let dir = tempfile::tempdir().unwrap();
        let canonical = dir.path().join("var-lib-tokens.json");
        let legacy = dir.path().join("etc-tokens.json");
        std::fs::write(&legacy, "{}").unwrap();

        let mut malformed = canonical.clone().into_os_string();
        malformed.push("/");
        let malformed = std::path::PathBuf::from(malformed);

        let resolved = resolve_tokens_with(&malformed, &canonical, &legacy).unwrap();
        assert!(
            !resolved.used_fallback,
            "a trailing-slash spelling must not activate the legacy store"
        );
        assert_eq!(
            resolved.path, malformed,
            "the given path must be used verbatim"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod set_scopes_grant_tests {
    use super::build_token_grant_from_set_scopes;
    use rust_proxmoxmcp_core::ProxmoxAction;

    /// Neither half given: the existing grant is left alone. `set-scopes` is
    /// for changing what an operator names, not for clearing what they did not.
    #[test]
    fn neither_half_leaves_the_grant_unchanged() {
        let grant = build_token_grant_from_set_scopes(None, None).unwrap();
        assert!(grant.is_none(), "an untouched grant must be None");
    }

    /// A grant carries guests *and* actions. Accepting actions alone would
    /// force this code to invent a guest selector, granting reach the operator
    /// never named.
    #[test]
    fn actions_without_guests_is_refused() {
        let error = build_token_grant_from_set_scopes(None, Some(&vec!["destructive".to_owned()]))
            .expect_err("--actions alone must be refused");
        assert!(
            error.to_string().contains("--actions requires --guests"),
            "the refusal must name the missing flag, got: {error}"
        );
    }

    /// Omitting actions defaults to read, matching `add`. It must not preserve
    /// whatever the token held before: the grant is replaced wholesale, so a
    /// silent carry-over would keep a destructive action through a call the
    /// operator believed was narrowing.
    #[test]
    fn guests_without_actions_defaults_to_read() {
        let grant = build_token_grant_from_set_scopes(Some(&vec!["*".to_owned()]), None)
            .unwrap()
            .expect("naming guests builds a grant");
        assert_eq!(grant.actions, vec![ProxmoxAction::Read]);
        assert_eq!(grant.guests, vec!["*".to_owned()]);
    }

    /// An unparseable selector is caught at the CLI, not left to produce a
    /// token that silently admits nothing.
    #[test]
    fn an_invalid_selector_is_refused() {
        let error = build_token_grant_from_set_scopes(Some(&vec!["nonsense:zzz".to_owned()]), None)
            .expect_err("an invalid selector must be refused");
        assert!(
            error.to_string().contains("invalid --guests selector"),
            "got: {error}"
        );
    }

    /// Every action name round-trips, including the one that matters most.
    #[test]
    fn destructive_is_accepted_when_named() {
        let grant = build_token_grant_from_set_scopes(
            Some(&vec!["*".to_owned()]),
            Some(&vec![
                "read".to_owned(),
                "low".to_owned(),
                "destructive".to_owned(),
            ]),
        )
        .unwrap()
        .expect("grant");
        assert_eq!(
            grant.actions,
            vec![
                ProxmoxAction::Read,
                ProxmoxAction::Low,
                ProxmoxAction::Destructive
            ]
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod shared_cli_security_option_tests {
    use super::{init_audit, load_approval_digest_key};
    use crate::cli::ProxmoxCli;
    use clap::Parser as _;
    use std::os::unix::fs::PermissionsExt;

    /// No `--approval-digest-key-file` keeps the coordinator unkeyed, same as
    /// today.
    #[test]
    fn no_approval_digest_key_file_is_fine() {
        assert!(
            load_approval_digest_key(None)
                .expect("no path is not an error")
                .is_none()
        );
    }

    /// A valid key file must be loaded and used.
    #[test]
    fn a_valid_approval_digest_key_file_is_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"a-sufficiently-long-test-key-value").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let key = load_approval_digest_key(Some(&path))
            .expect("a valid key file must load")
            .expect("Some(path) must produce Some(key)");
        assert_eq!(&*key, b"a-sufficiently-long-test-key-value");
    }

    /// A key file that fails `mecmcp-changeset`'s checks (here: too short)
    /// must fail startup.
    #[test]
    fn a_too_short_approval_digest_key_file_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        std::fs::write(&path, b"short").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let error = load_approval_digest_key(Some(&path))
            .expect_err("a too-short key file must be refused, not silently skipped");
        assert!(
            error.to_string().contains("approval-digest-key-file"),
            "{error}"
        );
    }

    /// A missing key file must fail startup -- the operator asked for a
    /// keyed digest and typo'd the path.
    #[test]
    fn a_missing_approval_digest_key_file_fails_closed() {
        let error = load_approval_digest_key(Some(std::path::Path::new(
            "/nonexistent/does-not-exist/key",
        )))
        .expect_err("a missing key file must be refused, not silently skipped");
        assert!(
            error.to_string().contains("approval-digest-key-file"),
            "{error}"
        );
    }

    /// Requesting telemetry export must refuse startup in a build that
    /// cannot send it.
    #[test]
    fn otel_endpoint_set_refuses_to_start() {
        let mut cli = ProxmoxCli::parse_from(["rust-proxmoxmcp"]);
        cli.common.otel_endpoint = Some("http://127.0.0.1:4318".to_owned());

        let error = init_audit(&cli.common).expect_err("--otel-endpoint must be refused");
        assert!(error.to_string().contains("--otel-endpoint"), "{error}");
    }

    /// No `--otel-endpoint` keeps today's behaviour: audit initializes with
    /// `otel: None`.
    #[test]
    fn no_otel_endpoint_starts_normally() {
        let cli = ProxmoxCli::parse_from(["rust-proxmoxmcp"]);
        init_audit(&cli.common).expect("no --otel-endpoint must not be refused");
    }
}

#[cfg(all(test, unix))]
#[allow(clippy::unwrap_used)]
mod startup_credential_tests {
    use super::{
        StartupCredentialFiles, listener_tokens, token_store_paths, validate_startup_credentials,
    };
    use crate::cli::ProxmoxCli;
    use clap::Parser as _;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn write_file(dir: &std::path::Path, name: &str, body: &[u8], mode: u32) -> PathBuf {
        let path = dir.join(name);
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    fn inventory(token_file: &std::path::Path, ca_file: &std::path::Path) -> String {
        format!(
            r#"{{"version":1,"devices":{{"pve3":{{"endpoint":"https://pve3.example.org:8006","token_id":"root@pam!mcp","token_secret_file":"{}","ca_pem_path":"{}"}}}}}}"#,
            token_file.display(),
            ca_file.display()
        )
    }

    /// Two loose modes must come back together. The failure this guards is a
    /// startup that names the first file, exits, and only names the second
    /// after that restart. The CA bundle is mode 0644 and must not be named:
    /// that file is public trust material and is not part of this pass.
    #[test]
    fn one_pass_reports_every_bad_mode() {
        let dir = tempfile::tempdir().unwrap();
        let token = write_file(dir.path(), "pve3.token", b"secret\n", 0o640);
        let ca = write_file(dir.path(), "ca.pem", b"trust-anchor\n", 0o644);
        let body = inventory(&token, &ca);
        let clusters = write_file(dir.path(), "clusters.json", body.as_bytes(), 0o644);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            clusters: &clusters,
            waivers: None,
            tokens: None,
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("both files are looser than their role allows");

        let message = error.to_string();
        assert!(
            message.contains("2 credential file"),
            "expected both failures in one error, got {message}"
        );
        assert!(message.contains("clusters.json"), "{message}");
        assert!(message.contains("pve3.token"), "{message}");
        assert!(message.contains("0644"), "{message}");
        assert!(message.contains("0640"), "{message}");
        assert!(
            !message.contains("ca.pem"),
            "a world-readable CA bundle must stay out of this pass, got {message}"
        );
    }

    /// `0600` is the mode the hardened loaders accept. A missing waiver file
    /// is an empty list. A `0644` CA bundle named by the inventory is not a
    /// credential file.
    #[test]
    fn acceptable_modes_pass_and_a_world_readable_ca_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let token = write_file(dir.path(), "pve3.token", b"secret\n", 0o600);
        let ca = write_file(dir.path(), "ca.pem", b"trust-anchor\n", 0o644);
        let body = inventory(&token, &ca);
        let clusters = write_file(dir.path(), "clusters.json", body.as_bytes(), 0o600);
        let hmac = write_file(dir.path(), "audit-hmac.key", b"abcd", 0o600);
        let missing_waivers = dir.path().join("waivers.json");

        validate_startup_credentials(&StartupCredentialFiles {
            clusters: &clusters,
            waivers: Some(&missing_waivers),
            tokens: None,
            audit_hmac_key: Some(&hmac),
            approval_digest_key: None,
        })
        .expect("0600 secrets, an absent waiver file, and a 0644 CA bundle must pass");
    }

    /// A waiver file that exists is part of the same pass. An acceptable
    /// inventory next to it must not be named.
    #[test]
    fn a_present_waivers_file_joins_the_same_pass() {
        let dir = tempfile::tempdir().unwrap();
        let token = write_file(dir.path(), "pve3.token", b"secret\n", 0o600);
        let ca = write_file(dir.path(), "ca.pem", b"trust-anchor\n", 0o644);
        let body = inventory(&token, &ca);
        let clusters = write_file(dir.path(), "clusters.json", body.as_bytes(), 0o600);
        let waivers = write_file(dir.path(), "waivers.json", b"{}\n", 0o644);
        let tokens = write_file(dir.path(), "tokens.json", b"{}\n", 0o640);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            clusters: &clusters,
            waivers: Some(&waivers),
            tokens: Some(&tokens),
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("a loose waiver file and a loose token store must both fail");

        let message = error.to_string();
        assert!(
            message.contains("2 credential file"),
            "expected both failures in one error, got {message}"
        );
        assert!(message.contains("waivers.json"), "{message}");
        assert!(message.contains("tokens.json"), "{message}");
        assert!(
            !message.contains("clusters.json"),
            "an acceptable inventory must not be named, got {message}"
        );
        assert!(
            !message.contains("ca.pem"),
            "a world-readable CA bundle must stay out of this pass, got {message}"
        );
    }

    fn assert_loose_token_and_waivers_are_both_named(body: &str) {
        let dir = tempfile::tempdir().unwrap();
        let token = write_file(dir.path(), "pve3.token", b"secret\n", 0o640);
        let clusters_body = body.replace("{token}", &token.display().to_string());
        let clusters = write_file(dir.path(), "clusters.json", clusters_body.as_bytes(), 0o600);
        let waivers = write_file(dir.path(), "waivers.json", b"{}\n", 0o644);

        let error = validate_startup_credentials(&StartupCredentialFiles {
            clusters: &clusters,
            waivers: Some(&waivers),
            tokens: None,
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect_err("the loose token file and the loose waiver file must both fail");

        let message = error.to_string();
        assert!(
            message.contains("2 credential file"),
            "expected both failures in one error, got {message}"
        );
        assert!(message.contains("pve3.token"), "{message}");
        assert!(message.contains("waivers.json"), "{message}");
        assert!(message.contains("0640"), "{message}");
        assert!(message.contains("0644"), "{message}");
        assert!(
            !message.contains("clusters.json"),
            "an acceptable inventory must not be named, got {message}"
        );
    }

    /// A legacy flat map has no `devices` key. The token file it names is
    /// still part of the one pass, next to a loose waiver file.
    #[test]
    fn a_flat_map_inventory_names_its_token_file() {
        assert_loose_token_and_waivers_are_both_named(
            r#"{"pve3":{"endpoint":"https://pve3.example.org:8006","token_id":"root@pam!mcp","token_secret_file":"{token}"},"_blocklist_defaults":{"resource_cache_ttl_secs":10}}"#,
        );
    }

    /// A legacy `devices` array names token files the same way an object does.
    #[test]
    fn a_devices_array_inventory_names_its_token_file() {
        assert_loose_token_and_waivers_are_both_named(
            r#"{"version":1,"devices":[{"name":"pve3","endpoint":"https://pve3.example.org:8006","token_id":"root@pam!mcp","token_secret_file":"{token}"}]}"#,
        );
    }

    /// A token path the inventory names, and that is not on disk yet, is not
    /// a mode failure. The loader reports the absence when it builds the client.
    #[test]
    fn a_missing_token_file_is_not_a_mode_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("pve3.token");
        let ca = write_file(dir.path(), "ca.pem", b"trust-anchor\n", 0o644);
        let body = inventory(&missing, &ca);
        let clusters = write_file(dir.path(), "clusters.json", body.as_bytes(), 0o600);

        validate_startup_credentials(&StartupCredentialFiles {
            clusters: &clusters,
            waivers: None,
            tokens: None,
            audit_hmac_key: None,
            approval_digest_key: None,
        })
        .expect("a missing token file is outside this pass");
    }

    #[test]
    fn deployed_token_paths_come_from_the_shared_layout() {
        let (canonical, legacy) = token_store_paths();
        assert_eq!(canonical, PathBuf::from("/var/lib/proxmoxmcp/tokens.json"));
        assert_eq!(legacy, PathBuf::from("/etc/proxmoxmcp/tokens.json"));
    }

    #[test]
    fn stdio_does_not_require_the_token_store() {
        let cli = ProxmoxCli::try_parse_from([
            "rust-proxmoxmcp",
            "--transport",
            "stdio",
            "--tokens-file",
            "/var/lib/proxmoxmcp/tokens.json",
        ])
        .unwrap();
        assert!(listener_tokens(&cli).unwrap().is_none());
    }

    #[test]
    fn http_checks_the_configured_token_path() {
        let cli = ProxmoxCli::try_parse_from([
            "rust-proxmoxmcp",
            "--transport",
            "streamable-http",
            "--tokens-file",
            "/srv/custom-tokens.json",
        ])
        .unwrap();
        let resolved = listener_tokens(&cli).unwrap().unwrap();
        assert_eq!(resolved.path, PathBuf::from("/srv/custom-tokens.json"));
        assert!(!resolved.used_fallback);
    }
}
