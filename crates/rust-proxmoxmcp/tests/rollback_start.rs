//! `rollback_snapshot` with `start`, end to end.
//!
//! The fixture guest (617, LXC, stopped) lives on `pve2`.

mod common;

use common::{
    TestServer, TokenSpec, approve_as_second_principal, call, call_with_token,
    default_guest_routes, handler_with_guest,
};
use rust_proxmoxmcp_core::grant::ProxmoxAction;
use rust_proxmoxmcp_core::testing::Route;
use serde_json::json;

const UPID: &str = "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzrollback:617:root@pam:";

fn routes_with_rollback() -> Vec<Route> {
    let mut routes = default_guest_routes(617, false);
    routes.push(Route {
        path: "/api2/json/nodes/pve2/lxc/617/snapshot/pre-upgrade/rollback",
        status: 200,
        body: br#"{"data":"UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzrollback:617:root@pam:"}"#,
    });
    routes
}

/// A token for the change-set handlers plus the named op tools.
fn spec_with(op_tools: &[&str]) -> TokenSpec {
    let handlers = [
        "plan_proxmox_destroy",
        "approve_proxmox_change_set",
        "apply_proxmox_change_set",
    ];
    TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: handlers
            .iter()
            .chain(op_tools)
            .map(|tool| (*tool).to_owned())
            .collect(),
        guests: vec!["*".to_owned()],
    }
}

fn plan_args(start: Option<bool>) -> serde_json::Value {
    let mut args =
        json!({"cluster":"pve3","vmid":617,"op":"rollback_snapshot","snapname":"pre-upgrade"});
    if let Some(start) = start {
        args["start"] = json!(start);
    }
    args
}

/// Plan, approve and apply a rollback; returns the preview and the rollback
/// POST's form body.
async fn apply_rollback(start: Option<bool>) -> (String, String) {
    let spec = spec_with(&["rollback_snapshot", "start_container"]);
    let h = TestServer::start_with_routes(spec, routes_with_rollback()).await;
    let planned = call(&h, "plan_proxmox_destroy", plan_args(start))
        .await
        .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    let preview = planned["preview"].as_str().expect("preview").to_owned();
    approve_as_second_principal(&h, id).await;
    h.script_task_completion(UPID, "OK");
    call(
        &h,
        "apply_proxmox_change_set",
        json!({"change_set_id": id, "cluster":"pve3","vmid":617}),
    )
    .await
    .expect("apply");
    let reqs = h.requests();
    let post = reqs
        .iter()
        .find(|r| r.method == "POST" && r.path.ends_with("/snapshot/pre-upgrade/rollback"))
        .expect("the rollback POST must be issued");
    (preview, post.body.clone())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_true_is_previewed_and_sent_as_start_1() {
    let (preview, body) = apply_rollback(Some(true)).await;
    assert!(preview.contains("STARTED"), "{preview}");
    assert!(body.contains("start=1"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_start_nothing_is_previewed_or_sent() {
    let (preview, body) = apply_rollback(None).await;
    assert!(!preview.contains("STARTED"), "{preview}");
    assert!(!body.contains("start"), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_is_refused_on_any_other_op() {
    let h = handler_with_guest(617, false).await;
    let error = call(
        &h,
        "plan_proxmox_destroy",
        json!({"cluster":"pve3","vmid":617,"op":"delete_snapshot","snapname":"pre-upgrade","start":true}),
    )
    .await
    .expect_err("start is only valid for rollback_snapshot");
    assert!(
        error.contains("only valid for rollback_snapshot"),
        "{error}"
    );
}

/// Proxmox checks no power privilege for `start`, so a token scoped for the
/// rollback but not the start tool must not boot the guest through it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_requires_the_start_tool_scope() {
    let spec = spec_with(&["rollback_snapshot"]);
    let h = TestServer::start_with_routes(spec, routes_with_rollback()).await;

    let error = call_with_token(&h, &h.token, "plan_proxmox_destroy", plan_args(Some(true)))
        .await
        .expect_err("rollback scope alone must not authorise a start");
    assert!(
        error.contains("not authorized for tool 'start_container'"),
        "{error}"
    );
    call_with_token(&h, &h.token, "plan_proxmox_destroy", plan_args(None))
        .await
        .expect("the same token may still roll back without starting");
}

/// The start is a `low`-tier action even though the rollback is destructive.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn start_requires_the_low_action_tier() {
    let h = TestServer::start_with_routes_and_actions(
        spec_with(&["rollback_snapshot", "start_container"]),
        routes_with_rollback(),
        vec![ProxmoxAction::Read, ProxmoxAction::Destructive],
    )
    .await;
    let error = call(&h, "plan_proxmox_destroy", plan_args(Some(true)))
        .await
        .expect_err("a destructive-only grant must not start the guest");
    assert!(error.contains("'low' action tier"), "{error}");
}
