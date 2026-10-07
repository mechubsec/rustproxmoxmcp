//! A container's `ENTRYPOINT` bakes in a fixed `--tokens-file` path so a
//! manually-run HTTP server always stays protected. stdio must still start
//! when that path has nothing mounted there -- the file protects a bearer
//! listener stdio never opens, so a missing tokens file must not block the
//! MCP handshake (MEC-2121).

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Server {
    child: Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn send(stdin: &mut impl Write, msg: &Value) {
    let line = serde_json::to_string(msg).expect("serialize request");
    writeln!(stdin, "{line}").expect("write to stdin");
    stdin.flush().expect("flush stdin");
}

/// Reads stdout lines until one parses as a JSON-RPC response with the given
/// `id`, or the deadline passes.
fn read_response(stdout: &mut BufReader<std::process::ChildStdout>, id: i64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert!(
            Instant::now() < deadline,
            "no response with id={id} within 15s"
        );
        let mut line = String::new();
        let read = stdout.read_line(&mut line).expect("read stdout");
        assert_ne!(read, 0, "server closed stdout before responding");
        let Ok(value) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        if value.get("id") == Some(&json!(id)) {
            return value;
        }
    }
}

fn initialize(server: &mut Server) {
    send(
        &mut server.stdin,
        &json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "stdio-no-tokens-test", "version": "1"}
            }
        }),
    );
    let response = read_response(&mut server.stdout, 1);
    assert!(
        response.get("error").is_none(),
        "initialize failed: {response:?}"
    );
    send(
        &mut server.stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
}

/// Write a minimal, hardened-loader-compliant `clusters.json` with one
/// cluster whose token secret comes from an env var (`token_secret_env`),
/// never argv or the inventory file itself.
fn write_clusters_file(path: &std::path::Path) {
    std::fs::write(
        path,
        r#"{"version":1,"devices":{"pve3":{"endpoint":"https://pve3.example.test:8006","token_id":"root@pam!mcp","token_secret_env":"PROXMOX_STDIO_TEST_TOKEN","protected_vmids":[],"protected_tags":[]}}}"#,
    )
    .expect("write clusters.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("set clusters.json permissions");
    }
}

#[test]
fn stdio_starts_when_tokens_file_flag_points_to_a_missing_path() {
    let directory = tempfile::tempdir().expect("temp dir");
    let clusters_path = directory.path().join("clusters.json");
    write_clusters_file(&clusters_path);

    let missing_tokens_path = directory.path().join("tokens.json");
    assert!(
        !missing_tokens_path.exists(),
        "tokens path must not exist for this test"
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_rust-proxmoxmcp"))
        .args([
            "--clusters-file",
            clusters_path.to_str().expect("clusters path is UTF-8"),
            "--transport",
            "stdio",
            "--tokens-file",
            missing_tokens_path.to_str().expect("tokens path is UTF-8"),
        ])
        .env("PROXMOX_STDIO_TEST_TOKEN", "not-a-live-token")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn rust-proxmoxmcp");

    let stdin = child.stdin.take().expect("stdin was piped");
    let stdout = BufReader::new(child.stdout.take().expect("stdout was piped"));
    let mut server = Server {
        child,
        stdin,
        stdout,
    };

    initialize(&mut server);

    // `tools/list` is answered by the MCP framework itself with no outbound
    // call to Proxmox, so this proves the stdio handshake reached full
    // readiness without depending on cluster reachability.
    send(
        &mut server.stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    );
    let response = read_response(&mut server.stdout, 2);
    let tools = response
        .pointer("/result/tools")
        .and_then(Value::as_array)
        .expect("tools/list returned no tools array");
    assert!(
        tools
            .iter()
            .any(|tool| tool.get("name") == Some(&json!("get_nodes"))),
        "expected get_nodes in the tool catalog, got: {tools:?}"
    );

    assert!(
        !missing_tokens_path.exists(),
        "stdio must not create a bearer-token store"
    );
}
