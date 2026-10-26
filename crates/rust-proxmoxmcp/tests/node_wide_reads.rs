//! `get_node_status` and `get_storage` name no guest -- they report on a
//! node as a whole -- so a guest-scoped selector has nothing to narrow.
//!
//! L2 regression: before this fix both were served to a narrowed token
//! anyway, with `requires_unrestricted_guest_scope: false`. `get_storage` in
//! particular reports node-wide storage usage/capacity that every guest on
//! the node shares. Both now require an unrestricted ('*') scope, the same
//! way `download_iso` and the firewall/task reads do for the identical
//! reason.

mod common;

use serde_json::json;

fn routes() -> Vec<common::Route> {
    vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/status",
            status: 200,
            body: br#"{"data":{"cpu":0.1,"memory":{"used":1000,"total":4000}}}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/storage",
            status: 200,
            body: br#"{"data":[{"storage":"local","type":"dir","total":100,"used":50}]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/apt/update",
            status: 200,
            body: br#"{"data":[{"Package":"pve-manager","OldVersion":"9.2.0","Version":"9.2.1","Priority":"optional","Origin":"Proxmox"}]}"#,
        },
    ]
}

fn spec(tool: &str, guests: &[&str]) -> common::TokenSpec {
    common::TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![tool.to_owned()],
        guests: guests.iter().map(|g| (*g).to_owned()).collect(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrestricted_token_reaches_get_node_status() {
    let h = common::TestServer::start_with_routes(spec("get_node_status", &["*"]), routes()).await;

    common::call(
        &h,
        "get_node_status",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect("unrestricted token reaches get_node_status");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_cannot_reach_get_node_status() {
    let h =
        common::TestServer::start_with_routes(spec("get_node_status", &["vmid:600-699"]), routes())
            .await;

    let err = common::call(
        &h,
        "get_node_status",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect_err("a narrowed guest scope must not reach get_node_status");
    assert!(err.contains('*'), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrestricted_token_reaches_get_storage() {
    let h = common::TestServer::start_with_routes(spec("get_storage", &["*"]), routes()).await;

    common::call(
        &h,
        "get_storage",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect("unrestricted token reaches get_storage");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_cannot_reach_get_storage() {
    let h = common::TestServer::start_with_routes(spec("get_storage", &["vmid:600-699"]), routes())
        .await;

    let err = common::call(
        &h,
        "get_storage",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect_err("a narrowed guest scope must not reach get_storage");
    assert!(err.contains('*'), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrestricted_token_reaches_get_node_updates() {
    let h = common::TestServer::start_with_routes(spec("get_node_updates", &["*"]), routes()).await;

    let rendered = common::call(
        &h,
        "get_node_updates",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect("unrestricted token reaches get_node_updates");
    assert!(rendered.to_string().contains("pve-manager"), "{rendered}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_token_cannot_reach_get_node_updates() {
    let h = common::TestServer::start_with_routes(
        spec("get_node_updates", &["vmid:600-699"]),
        routes(),
    )
    .await;

    let err = common::call(
        &h,
        "get_node_updates",
        json!({"cluster": "pve3", "node": "pve2"}),
    )
    .await
    .expect_err("a narrowed guest scope must not reach get_node_updates");
    assert!(err.contains('*'), "{err}");
}
