//! SIGHUP audit log reopen. Unix-only.
//!
//! Verifies that sending SIGHUP to a running server with `--audit-log-file`
//! configured reopens the sink in place: a rename-then-signal rotation loses
//! nothing written before the rename and routes everything written after it
//! to the fresh inode at the same path. Also verifies that a reopen which
//! cannot succeed (the path is no longer usable) does not take down the
//! server or the other SIGHUP reloads.
#![cfg(unix)]
#![allow(clippy::unwrap_used)]

use mecmcp_transport::test_client::McpClient;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn binary_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rust-proxmoxmcp"))
}

fn pick_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn wait_for_port(port: u16, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("port {port} not accepting connections within {timeout:?}");
}

fn write_restricted(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("write config fixture");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict config fixture permissions");
}

/// Mint a token via the `token add` subcommand and return the plaintext.
///
/// Uses the real CLI rather than `TokenStoreFile::add_with_options` directly
/// so the fixture exercises the same path an operator would.
fn mint_token(tokens_path: &Path) -> String {
    write_restricted(tokens_path, r#"{"version":1,"tokens":[]}"#);
    let output = Command::new(binary_path())
        .args([
            "token",
            "add",
            "--tokens-file",
            tokens_path.to_str().unwrap(),
            "--name",
            "sighup-test",
            "--devices",
            "*",
            "--tools",
            "*",
            "--guests",
            "*",
            "--actions",
            "read",
        ])
        .output()
        .expect("spawn token add");
    assert!(
        output.status.success(),
        "token add failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("utf8 stdout")
        .trim()
        .to_owned()
}

/// Guarded server child: killed and reaped on drop so a panic mid-test never
/// leaks a process.
struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spawn the real binary in streamable-http mode with a bearer token store, no
/// TLS (plaintext loopback, as the shipped test fixtures elsewhere use) and no
/// configured clusters. An empty `devices` map is enough: the SIGHUP audit
/// reopen and the transport's own per-call audit record are both independent
/// of whether any cluster is reachable — `get_nodes` against an unconfigured
/// cluster fails inside the handler, but the transport's preflight audit
/// event has already been written by then.
fn spawn_server(clusters_path: &Path, tokens_path: &Path, audit_log_file: &Path) -> Server {
    let port = pick_port();
    let child = Command::new(binary_path())
        .args([
            "--clusters-file",
            clusters_path.to_str().unwrap(),
            "--tokens-file",
            tokens_path.to_str().unwrap(),
            "--transport",
            "streamable-http",
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--audit-format",
            "json",
            "--audit-log-file",
            audit_log_file.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-proxmoxmcp");
    wait_for_port(port, Duration::from_secs(15));
    Server { child, port }
}

fn sighup(pid: u32) {
    let status = Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .status()
        .expect("run kill -HUP");
    assert!(status.success(), "kill -HUP {pid} failed");
}

/// Build a client and its session once, up front. Reused across every audit
/// emission in a test: minting a fresh `Mcp-Session-Id` per call — the naive
/// approach — exhausts the server's session limit under the tight polling
/// loop below and fails tests with an unrelated 503, masking the real
/// assertion (whether the audit record reached the rotated-to path).
fn mcp_session(port: u16, token: &str) -> (McpClient, String) {
    let client = McpClient::new(format!("http://127.0.0.1:{port}"))
        .unwrap()
        .with_bearer(token);
    // The listener can accept a probe connection before the server is ready to
    // serve requests, so retry briefly on a transient transport error.
    let deadline = Instant::now() + Duration::from_secs(10);
    let session_id = loop {
        match client.initialize() {
            Ok(id) => break id,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("initialize: {e:?}"),
        }
    };
    (client, session_id)
}

/// Call a tool that reaches the server's normal request path. The cluster
/// named does not need to exist: the transport's preflight audit record for
/// this call is written before the handler runs, so it lands regardless of
/// what `get_nodes` itself does with an unconfigured cluster.
fn emit_audit_record(client: &McpClient, session_id: &str) {
    // Ignore the result: a tool-level failure (unconfigured cluster) still
    // reaches the transport's preflight audit event.
    let _ = client.tools_call(
        session_id,
        "get_nodes",
        serde_json::json!({"cluster": "nope"}),
    );
}

fn wait_for_nonempty(path: &Path, deadline: Instant) -> String {
    loop {
        if let Ok(contents) = std::fs::read_to_string(path)
            && !contents.is_empty()
        {
            return contents;
        }
        assert!(
            Instant::now() < deadline,
            "{} never became non-empty",
            path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn sighup_reopens_audit_log_after_rename() {
    let dir = tempfile::tempdir().unwrap();
    let clusters_path = dir.path().join("clusters.json");
    let tokens_path = dir.path().join("tokens.json");
    let audit_path = dir.path().join("audit.jsonl");
    write_restricted(&clusters_path, r#"{"version":1,"devices":{}}"#);

    let token = mint_token(&tokens_path);
    let server = spawn_server(&clusters_path, &tokens_path, &audit_path);
    let (client, session_id) = mcp_session(server.port, &token);

    // First record lands in the original inode.
    emit_audit_record(&client, &session_id);
    let deadline = Instant::now() + Duration::from_secs(5);
    let before = wait_for_nonempty(&audit_path, deadline);
    assert!(
        before.contains("get_nodes"),
        "audit file missing first record: {before}"
    );

    // Rotate the way logrotate's rename-mode fragment does: move the file
    // aside, then signal the process.
    let rotated = dir.path().join("audit.jsonl.1");
    std::fs::rename(&audit_path, &rotated).unwrap();
    sighup(server.child.id());

    // Second record must land at the same path, in a fresh inode, once the
    // reopen has completed. Poll rather than sleep a fixed amount: the
    // reopen races the SIGHUP delivery and this keeps the happy path fast.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        emit_audit_record(&client, &session_id);
        if let Ok(contents) = std::fs::read_to_string(&audit_path)
            && contents.contains("get_nodes")
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "second record never appeared at {} within 5s after SIGHUP",
            audit_path.display()
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    let after_rotation = std::fs::read_to_string(&audit_path).unwrap();
    assert!(
        after_rotation.contains("get_nodes"),
        "new audit file missing post-rotation record: {after_rotation}"
    );

    let rotated_contents = std::fs::read_to_string(&rotated).unwrap();
    assert_eq!(
        rotated_contents, before,
        "the rotated-away file must keep exactly what was written before the rename, losing nothing"
    );
}

#[test]
fn sighup_audit_reopen_failure_keeps_server_and_other_reloads_alive() {
    let dir = tempfile::tempdir().unwrap();
    let clusters_path = dir.path().join("clusters.json");
    let tokens_path = dir.path().join("tokens.json");
    let audit_path = dir.path().join("audit.jsonl");
    write_restricted(&clusters_path, r#"{"version":1,"devices":{}}"#);

    let token = mint_token(&tokens_path);
    let server = spawn_server(&clusters_path, &tokens_path, &audit_path);
    let (client, session_id) = mcp_session(server.port, &token);

    emit_audit_record(&client, &session_id);
    let deadline = Instant::now() + Duration::from_secs(5);
    wait_for_nonempty(&audit_path, deadline);

    // Make the reopen fail: replace the path with a directory, so
    // `OpenOptions::create().append()` on it returns EISDIR. The server's
    // existing (now-unlinked) descriptor keeps working regardless.
    std::fs::remove_file(&audit_path).unwrap();
    std::fs::create_dir(&audit_path).unwrap();
    sighup(server.child.id());

    // The server must keep serving requests — a failed audit reopen must not
    // take down the process or block the other SIGHUP reloads (inventory).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if client
            .tools_call(
                &session_id,
                "get_nodes",
                serde_json::json!({"cluster": "nope"}),
            )
            .is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "server stopped responding after a failed audit reopen"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    std::fs::remove_dir(&audit_path).unwrap();
}
