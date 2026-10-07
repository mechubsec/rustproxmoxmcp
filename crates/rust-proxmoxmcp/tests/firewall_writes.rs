//! Firewall writes go through plan, approve and apply.
//!
//! A write without an approved change set is refused. An approved one is
//! sent. Lab-mode and two-person approval follow the same rules as the other
//! governed writes.

mod common;

use common::{TestServer, TokenSpec, call_with_token};
use rust_proxmoxmcp_core::testing::Route;
use serde_json::json;
use std::sync::Arc;

const SECRET: &str = "FAKE-api-token-9f8e7d6c5b4a3210";

fn firewall_spec(extra: &[&str]) -> TokenSpec {
    let mut tools = vec![
        "plan_firewall_change".to_owned(),
        "get_firewall_change_set".to_owned(),
        "approve_firewall_change".to_owned(),
        "apply_firewall_change".to_owned(),
    ];
    tools.extend(extra.iter().map(|tool| (*tool).to_owned()));
    TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools,
        guests: vec!["*".to_owned()],
    }
}

fn rules_route(body: &'static [u8]) -> Route {
    Route {
        path: "/api2/json/cluster/firewall/rules",
        status: 200,
        body,
    }
}

fn empty_rules() -> Vec<Route> {
    vec![rules_route(br#"{"data":[]}"#)]
}

fn guest_routes(vmid: u32, protected: bool) -> Vec<Route> {
    let tags = if protected { "protected" } else { "test" };
    let resources = Box::leak(
        format!(
            r#"{{"data":[{{"id":"lxc/{vmid}","type":"lxc","vmid":{vmid},"name":"web","node":"pve2","status":"running","tags":"{tags}"}}]}}"#
        )
        .into_boxed_str(),
    )
    .as_bytes();
    let rules =
        Box::leak(format!("/api2/json/nodes/pve2/lxc/{vmid}/firewall/rules").into_boxed_str());
    vec![
        Route {
            path: "/api2/json/cluster/resources",
            status: 200,
            body: resources,
        },
        Route {
            path: rules,
            status: 200,
            body: br#"{"data":[]}"#,
        },
    ]
}

fn plan_args(object: &str) -> serde_json::Value {
    json!({
        "cluster": "pve3",
        "scope": "cluster",
        "object": object,
        "op": "create",
        "rule": {"rule_type": "in", "action": "ACCEPT", "proto": "tcp", "dport": "22"},
        "comment": format!(
            "re-provisioned 2026-09-27 (ticket OPS-4110); backup admin password: {SECRET}"
        )
    })
}

async fn approve_firewall(server: &TestServer, id: &str, object: &str) {
    call_with_token(
        server,
        &server.second_token,
        "approve_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": object
        }),
    )
    .await
    .expect("second principal approval");
}

fn posted(server: &TestServer) -> bool {
    server
        .requests()
        .iter()
        .any(|request| request.method == "POST")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unapproved_firewall_write_is_refused_and_sends_nothing() {
    let server =
        TestServer::start_with_routes(firewall_spec(&["create_firewall_rule"]), empty_rules())
            .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect("plan");
    assert_eq!(planned["state"], "Planned");
    let preview = planned["preview"].as_str().expect("preview");
    assert!(preview.contains("CREATE"), "{preview}");
    assert!(preview.contains("ACCEPT"), "{preview}");
    assert!(!preview.contains(SECRET), "{preview}");
    let before = server.requests().len();
    let id = planned["change_set_id"].as_str().expect("id");
    let error = call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "rule"
        }),
    )
    .await
    .expect_err("unapproved apply");
    assert!(error.to_lowercase().contains("approv"), "{error}");
    assert_eq!(
        server.requests().len(),
        before,
        "apply must not call the cluster"
    );
    assert!(!posted(&server));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_rule_create_posts_the_rule() {
    let server =
        TestServer::start_with_routes(firewall_spec(&["create_firewall_rule"]), empty_rules())
            .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    approve_firewall(&server, id, "rule").await;
    let applied = call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "rule"
        }),
    )
    .await
    .expect("apply");
    assert_eq!(applied["outcome"], "ok");
    let request = server
        .requests()
        .into_iter()
        .find(|request| request.method == "POST")
        .expect("POST");
    assert_eq!(request.path, "/api2/json/cluster/firewall/rules");
    assert!(request.body.contains("type=in"), "{}", request.body);
    assert!(request.body.contains("action=ACCEPT"), "{}", request.body);
    assert!(request.body.contains("proto=tcp"), "{}", request.body);
    assert!(request.body.contains("dport=22"), "{}", request.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_planner_cannot_approve_their_own_firewall_change() {
    let server =
        TestServer::start_with_routes(firewall_spec(&["create_firewall_rule"]), empty_rules())
            .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    let error = call_with_token(
        &server,
        &server.token,
        "approve_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "rule"
        }),
    )
    .await
    .expect_err("self-approval");
    assert!(error.to_lowercase().contains("self"), "{error}");
    assert!(!posted(&server));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_cannot_approve_a_firewall_change() {
    let server =
        TestServer::start_with_routes(firewall_spec(&["create_firewall_rule"]), empty_rules())
            .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    let error = call_with_token(
        &server,
        &server.agent_token,
        "approve_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "rule"
        }),
    )
    .await
    .expect_err("agent approval");
    assert!(error.to_lowercase().contains("human"), "{error}");
    let apply_error = call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "rule"
        }),
    )
    .await
    .expect_err("still unapproved");
    assert!(
        apply_error.to_lowercase().contains("approv"),
        "{apply_error}"
    );
    assert!(!posted(&server));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lab_mode_approves_a_protected_guest_firewall_change() {
    let server = TestServer::start_with_config(
        firewall_spec(&["create_firewall_rule"]),
        guest_routes(617, true),
        Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
        true,
    )
    .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        json!({
            "cluster": "pve3",
            "scope": "guest",
            "object": "rule",
            "op": "create",
            "vmid": 617,
            "rule": {"rule_type": "in", "action": "ACCEPT"}
        }),
    )
    .await
    .expect("plan");
    assert_eq!(planned["state"], "Approved", "{planned}");
    assert!(
        planned["preview"]
            .as_str()
            .unwrap_or("")
            .contains("lab-mode"),
        "{planned}"
    );
    let id = planned["change_set_id"].as_str().expect("id");
    let applied = call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "guest",
            "object": "rule",
            "vmid": 617
        }),
    )
    .await
    .expect("apply");
    assert_eq!(applied["outcome"], "ok");
    assert!(server.requests().iter().any(|request| {
        request.method == "POST" && request.path == "/api2/json/nodes/pve2/lxc/617/firewall/rules"
    }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lab_mode_still_requires_a_second_principal_for_an_ordinary_guest() {
    let server = TestServer::start_with_config(
        firewall_spec(&["create_firewall_rule"]),
        guest_routes(618, false),
        Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
        true,
    )
    .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        json!({
            "cluster": "pve3",
            "scope": "guest",
            "object": "rule",
            "op": "create",
            "vmid": 618,
            "rule": {"rule_type": "in", "action": "DROP"}
        }),
    )
    .await
    .expect("plan");
    assert_eq!(planned["state"], "Planned", "{planned}");
    let id = planned["change_set_id"].as_str().expect("id");
    let error = call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "guest",
            "object": "rule",
            "vmid": 618
        }),
    )
    .await
    .expect_err("ordinary guest still needs approval");
    assert!(error.to_lowercase().contains("approv"), "{error}");
    assert!(!posted(&server));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lab_mode_still_requires_a_second_principal_for_a_cluster_firewall() {
    let server = TestServer::start_with_config(
        firewall_spec(&["create_firewall_rule"]),
        empty_rules(),
        Arc::new(rust_proxmoxmcp_core::waiver::WaiverFile::empty()),
        true,
    )
    .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect("plan");
    assert_eq!(planned["state"], "Planned", "{planned}");
    let id = planned["change_set_id"].as_str().expect("id");
    let error = call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "rule"
        }),
    )
    .await
    .expect_err("cluster firewall still needs approval");
    assert!(error.to_lowercase().contains("approv"), "{error}");
    assert!(!posted(&server));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_protected_guest_without_an_override_is_refused_at_plan() {
    let server = TestServer::start_with_routes(
        firewall_spec(&["create_firewall_rule"]),
        guest_routes(617, true),
    )
    .await;
    let error = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        json!({
            "cluster": "pve3",
            "scope": "guest",
            "object": "rule",
            "op": "create",
            "vmid": 617,
            "rule": {"rule_type": "in", "action": "ACCEPT"}
        }),
    )
    .await
    .expect_err("protected guest");
    assert!(error.to_lowercase().contains("protected"), "{error}");
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request.path.contains("/firewall")),
        "{:?}",
        server.requests()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_changed_firewall_refuses_apply() {
    let server =
        TestServer::start_with_routes(firewall_spec(&["create_firewall_rule"]), empty_rules())
            .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();
    approve_firewall(&server, &id, "rule").await;
    server.replace_route(rules_route(
        br#"{"data":[{"pos":0,"type":"in","action":"DROP","digest":"abc"}]}"#,
    ));
    let error = call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "rule"
        }),
    )
    .await
    .expect_err("fingerprint drift");
    assert!(error.to_lowercase().contains("fingerprint"), "{error}");
    assert!(!posted(&server));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_caller_without_the_destructive_tier_is_refused_before_any_firewall_request() {
    let server = TestServer::start_with_routes_and_actions(
        firewall_spec(&["create_firewall_rule"]),
        empty_rules(),
        vec![
            rust_proxmoxmcp_core::ProxmoxAction::Read,
            rust_proxmoxmcp_core::ProxmoxAction::Low,
        ],
    )
    .await;
    let error = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect_err("missing destructive tier");
    assert!(error.contains("destructive"), "{error}");
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request.path.contains("/firewall")),
        "{:?}",
        server.requests()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_narrowed_guest_scope_cannot_plan_a_cluster_firewall_change() {
    let server =
        TestServer::start_with_routes(firewall_spec(&["create_firewall_rule"]), empty_rules())
            .await;
    let error = call_with_token(
        &server,
        &server.narrow_token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect_err("narrowed scope");
    assert!(error.contains('*'), "{error}");
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request.path.contains("/firewall")),
        "{:?}",
        server.requests()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_plan_without_the_operation_scope_is_refused() {
    let server = TestServer::start_with_routes(firewall_spec(&[]), empty_rules()).await;
    let error = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect_err("missing operation scope");
    assert!(
        error.contains("not authorized for tool 'create_firewall_rule'"),
        "{error}"
    );
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request.path.contains("/firewall")),
        "{:?}",
        server.requests()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wildcard_tool_scope_cannot_plan_a_firewall_change() {
    let server = TestServer::start_with_routes(TokenSpec::full(), empty_rules()).await;
    let error = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        plan_args("rule"),
    )
    .await
    .expect_err("wildcard");
    // A wildcard tool scope is refused by the same preflight as the other
    // write tools, before the handler runs.
    assert!(error.contains("403"), "{error}");
    assert!(
        !server
            .requests()
            .iter()
            .any(|request| request.path.contains("/firewall")),
        "{:?}",
        server.requests()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_options_update_puts_the_policy_and_digest() {
    let server = TestServer::start_with_routes(
        firewall_spec(&["update_firewall_options"]),
        vec![Route {
            path: "/api2/json/cluster/firewall/options",
            status: 200,
            body: br#"{"data":{"policy_in":"DROP","digest":"abc123"}}"#,
        }],
    )
    .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        json!({
            "cluster": "pve3",
            "scope": "cluster",
            "object": "options",
            "op": "update",
            "options": {"policy_in": "ACCEPT"}
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    approve_firewall(&server, id, "options").await;
    call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "options"
        }),
    )
    .await
    .expect("apply");
    let request = server
        .requests()
        .into_iter()
        .find(|request| request.method == "PUT")
        .expect("PUT");
    assert_eq!(request.path, "/api2/json/cluster/firewall/options");
    assert!(
        request.body.contains("policy_in=ACCEPT"),
        "{}",
        request.body
    );
    assert!(request.body.contains("digest=abc123"), "{}", request.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_prefixed_address_can_be_added_and_cannot_be_deleted_as_a_path_segment() {
    let server = TestServer::start_with_routes(
        firewall_spec(&["create_firewall_ipset_entry", "delete_firewall_ipset_entry"]),
        vec![
            Route {
                path: "/api2/json/cluster/firewall/ipset",
                status: 200,
                body: br#"{"data":[{"name":"block"}]}"#,
            },
            Route {
                path: "/api2/json/cluster/firewall/ipset/block",
                status: 200,
                body: br#"{"data":[]}"#,
            },
        ],
    )
    .await;
    let planned = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        json!({
            "cluster": "pve3",
            "scope": "cluster",
            "object": "ipset_entry",
            "op": "create",
            "name": "block",
            "cidr": "192.0.2.0/24"
        }),
    )
    .await
    .expect("plan create");
    let id = planned["change_set_id"].as_str().expect("id");
    call_with_token(
        &server,
        &server.second_token,
        "approve_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "ipset_entry",
            "name": "block"
        }),
    )
    .await
    .expect("approve named entry");
    call_with_token(
        &server,
        &server.token,
        "apply_firewall_change",
        json!({
            "change_set_id": id,
            "cluster": "pve3",
            "scope": "cluster",
            "object": "ipset_entry",
            "name": "block"
        }),
    )
    .await
    .expect("apply");
    let request = server
        .requests()
        .into_iter()
        .find(|request| request.method == "POST")
        .expect("POST");
    assert_eq!(request.path, "/api2/json/cluster/firewall/ipset/block");
    assert!(
        request.body.contains("cidr=192.0.2.0%2F24"),
        "{}",
        request.body
    );

    let before = server.requests().len();
    let error = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        json!({
            "cluster": "pve3",
            "scope": "cluster",
            "object": "ipset_entry",
            "op": "delete",
            "name": "block",
            "cidr": "192.0.2.0/24"
        }),
    )
    .await
    .expect_err("prefixed delete");
    assert!(error.contains("single path segment"), "{error}");
    assert_eq!(server.requests().len(), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_field_outside_the_allowlist_is_refused_before_any_request() {
    let server =
        TestServer::start_with_routes(firewall_spec(&["create_firewall_rule"]), empty_rules())
            .await;
    let error = call_with_token(
        &server,
        &server.token,
        "plan_firewall_change",
        json!({
            "cluster": "pve3",
            "scope": "cluster",
            "object": "rule",
            "op": "create",
            "rule": {"rule_type": "sideways", "action": "ACCEPT"}
        }),
    )
    .await
    .expect_err("bad rule type");
    assert!(error.contains("rule type"), "{error}");
    assert!(server.requests().is_empty(), "{:?}", server.requests());
}
