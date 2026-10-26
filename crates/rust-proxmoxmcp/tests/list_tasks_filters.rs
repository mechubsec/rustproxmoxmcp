//! `list_tasks` passes Proxmox's `/nodes/{node}/tasks` filters through
//! (`typefilter`, `vmid`, `since`, `until`, `limit`, `errors`, `statusfilter`)
//! and refuses malformed ones before any request is made. It stays a bare,
//! unpaginated array (MEC-871): there is no `start`/offset.

mod common;

use serde_json::{Value, json};

fn routes() -> Vec<common::Route> {
    vec![
        common::Route {
            path: "/api2/json/nodes",
            status: 200,
            body: br#"{"data":[{"node":"pve2","status":"online"}]}"#,
        },
        common::Route {
            path: "/api2/json/nodes/pve2/tasks",
            status: 200,
            body: br#"{"data":[]}"#,
        },
    ]
}

async fn server() -> common::TestServer {
    common::TestServer::start_with_routes(common::TokenSpec::full(), routes()).await
}

/// Targets of the `/tasks` requests that reached the mock Proxmox.
fn task_targets(server: &common::TestServer) -> Vec<String> {
    server
        .requests()
        .into_iter()
        .filter(|request| request.path.ends_with("/tasks"))
        .map(|request| request.target)
        .collect()
}

fn with_filters(filters: Value) -> Value {
    let mut args = json!({"cluster": "pve3", "node": "pve2"});
    args.as_object_mut()
        .expect("object")
        .extend(filters.as_object().expect("object").clone());
    args
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unfiltered_call_sends_no_query() {
    let h = server().await;
    common::call(&h, "list_tasks", with_filters(json!({})))
        .await
        .expect("unfiltered call succeeds");
    assert_eq!(task_targets(&h), ["/api2/json/nodes/pve2/tasks"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_filtered_call_carries_exactly_the_requested_query() {
    let h = server().await;
    common::call(
        &h,
        "list_tasks",
        with_filters(json!({
            "typefilter": "vzdump", "vmid": 100, "since": 1_700_000_000u64,
            "until": 1_700_086_400u64, "limit": 20, "errors": true,
            "statusfilter": "OK,Warning",
        })),
    )
    .await
    .expect("filtered call succeeds");
    assert_eq!(
        task_targets(&h),
        [
            "/api2/json/nodes/pve2/tasks?typefilter=vzdump&vmid=100&since=1700000000\
          &until=1700086400&limit=20&errors=1&statusfilter=ok%2Cwarning"
        ]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn errors_false_is_not_sent() {
    let h = server().await;
    common::call(&h, "list_tasks", with_filters(json!({"errors": false})))
        .await
        .expect("call succeeds");
    assert_eq!(task_targets(&h), ["/api2/json/nodes/pve2/tasks"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_filters_are_refused_before_any_request() {
    let long_typefilter = "a".repeat(65);
    let rejected = [
        json!({"typefilter": ""}),
        json!({"typefilter": long_typefilter}),
        json!({"typefilter": "vz dump"}),
        json!({"typefilter": "vzdump&limit=1"}),
        json!({"statusfilter": "ok,bogus"}),
        json!({"statusfilter": "ok,,error"}),
        json!({"statusfilter": ""}),
        json!({"limit": 0}),
        json!({"limit": 501}),
        json!({"vmid": 0}),
        json!({"since": 200, "until": 100}),
    ];
    let h = server().await;
    for filters in rejected {
        let error = common::call(&h, "list_tasks", with_filters(filters.clone()))
            .await
            .expect_err(&format!("{filters} must be refused"));
        assert!(!error.is_empty());
    }
    assert!(task_targets(&h).is_empty(), "no request may reach Proxmox");
}
