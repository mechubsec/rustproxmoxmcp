//! HA rule change-set end-to-end tests.

mod common;

use common::{TestServer, TokenSpec, call_with_token};
use rust_proxmoxmcp_core::testing::Route;
use serde_json::json;

fn ha_rule_spec() -> TokenSpec {
    TokenSpec {
        clusters: vec!["pve3".to_owned()],
        tools: vec![
            "plan_ha_rule_change".to_owned(),
            "get_ha_rule_change_set".to_owned(),
            "approve_ha_rule_change".to_owned(),
            "apply_ha_rule_change".to_owned(),
            "create_ha_rule".to_owned(),
            "update_ha_rule".to_owned(),
            "delete_ha_rule".to_owned(),
        ],
        guests: vec!["*".to_owned()],
    }
}

async fn approve_ha_rule_as_second_principal(server: &TestServer, change_set_id: &str, rule: &str) {
    call_with_token(
        server,
        &server.second_token,
        "approve_ha_rule_change",
        json!({"change_set_id": change_set_id, "cluster": "pve3", "rule": rule}),
    )
    .await
    .expect("second principal approval should succeed");
}

/// `/cluster/resources` with the two guests the fixture rules name. HA rule
/// writes are authorized against every guest a rule names, the same way a
/// destroy plan is authorized against its guest, so those guests must
/// resolve. `protected` tags vm:101.
fn guests_route(protected: bool) -> Route {
    Route {
        path: "/api2/json/cluster/resources",
        status: 200,
        body: if protected {
            br#"{"data":[{"id":"qemu/100","type":"qemu","vmid":100,"name":"ha-a","node":"pve2","status":"running","tags":"test"},{"id":"qemu/101","type":"qemu","vmid":101,"name":"ha-b","node":"pve3","status":"running","tags":"protected"}]}"#
        } else {
            br#"{"data":[{"id":"qemu/100","type":"qemu","vmid":100,"name":"ha-a","node":"pve2","status":"running","tags":"test"},{"id":"qemu/101","type":"qemu","vmid":101,"name":"ha-b","node":"pve3","status":"running","tags":"test"}]}"#
        },
    }
}

/// No rule named `keep-together` exists yet. PVE 9 answers a missing rule id
/// with HTTP 500 and a message naming it, not 404 -- `fetch_rule` must read
/// that shape as "does not exist" the same way it reads a 404. A `create`
/// plan is exactly this shape.
fn no_such_rule_routes() -> Vec<Route> {
    vec![
        guests_route(false),
        Route {
            path: "/api2/json/cluster/ha/rules/keep-together",
            status: 500,
            body: br#"{"data":null,"errors":{"rule":"no such HA rule 'keep-together'"}}"#,
        },
        Route {
            path: "/api2/json/cluster/ha/rules",
            status: 200,
            body: br#"{"data":null}"#,
        },
    ]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approved_create_issues_the_post_with_the_rule_body() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id");
    assert!(
        planned["preview"]
            .as_str()
            .expect("preview")
            .contains("CREATE"),
        "{planned:?}"
    );

    approve_ha_rule_as_second_principal(&h, id, "keep-together").await;

    let applied = call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect("apply");
    assert_eq!(applied["outcome"], "ok");

    let reqs = h.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "POST"
                && r.path == "/api2/json/cluster/ha/rules"
                && r.body.contains("rule=keep-together")
                && r.body.contains("type=resource-affinity")
                && r.body.contains("resources=vm%3A100%2Cvm%3A101")
                && r.body.contains("affinity=positive")
        }),
        "the create POST must actually be issued with the rule's fields: {reqs:?}"
    );
}

/// The deprecated `services` alias and pre-GA `location`/`colocation` type
/// names are still accepted as input, but the wire request must use the
/// current PVE 9 field and type names -- Percy's F1: keeping old names as
/// input aliases is fine, sending them is not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deprecated_aliases_are_accepted_but_not_sent_on_the_wire() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "colocation",
            "services": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect("plan accepts the deprecated alias names");
    let id = planned["change_set_id"].as_str().expect("id");

    approve_ha_rule_as_second_principal(&h, id, "keep-together").await;

    call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect("apply");

    let reqs = h.requests();
    assert!(
        reqs.iter().any(|r| {
            r.method == "POST"
                && r.path == "/api2/json/cluster/ha/rules"
                && r.body.contains("type=resource-affinity")
                && r.body.contains("resources=vm%3A100%2Cvm%3A101")
                && !r.body.contains("type=colocation")
                && !r.body.contains("services=")
        }),
        "the deprecated alias names must never reach the cluster: {reqs:?}"
    );
}

/// Giving both `resources` and its deprecated `services` alias is ambiguous
/// and must be refused rather than silently picking one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn giving_both_resources_and_the_services_alias_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100"],
            "services": ["vm:100"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("both resources and services must be refused");
    assert!(error.contains("only one"), "{error}");
}

/// The rejection case the acceptance criteria asks for on the HA side: a plan
/// against a rule that already exists must be refused before any approval is
/// spent on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn creating_a_rule_that_already_exists_is_refused_at_plan_time() {
    let h = TestServer::start_with_routes(
        ha_rule_spec(),
        vec![Route {
            path: "/api2/json/cluster/ha/rules/keep-together",
            status: 200,
            body: br#"{"data":{"rule":"keep-together","type":"resource-affinity","resources":"vm:100,vm:101","affinity":"positive","digest":"aabbcc"}}"#,
        }],
    )
    .await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a plan against an existing rule must be refused");
    assert!(error.contains("already exists"), "{error}");

    let reqs = h.requests();
    assert!(
        !reqs.iter().any(|r| r.method == "POST"),
        "nothing should have been written: {reqs:?}"
    );
}

/// A resource-affinity rule does not take `nodes` -- that is a
/// node-affinity-rule concept -- so a plan naming both must be refused
/// before it is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_resource_affinity_rule_with_nodes_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100"],
            "nodes": "pve2:100"
        }),
    )
    .await
    .expect_err("a resource-affinity rule must not take nodes");
    assert!(error.contains("does not take nodes"), "{error}");
}

/// A malformed resource id (not `vm:<n>` or `ct:<n>`) must be refused before
/// it is ever sent toward the cluster.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_resource_id_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100;rm -rf"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a malformed resource id must be refused");
    assert!(error.contains("vmid"), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_rule_that_does_not_exist_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({"cluster": "pve3", "rule": "keep-together", "op": "delete"}),
    )
    .await
    .expect_err("deleting a rule that does not exist must be refused");
    assert!(error.contains("does not exist"), "{error}");
}

/// The fingerprint drift guard: a rule that changed between plan and apply
/// (someone edited it out of band) must refuse the apply, the same as a
/// guest that moved between a destroy plan and its apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_that_changed_after_approval_refuses_the_apply() {
    let h = TestServer::start_with_routes(ha_rule_spec(), existing_rule_routes(false)).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "delete"
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    approve_ha_rule_as_second_principal(&h, &id, "keep-together").await;

    // The rule's comment changes underneath the plan -- same fingerprint
    // shape as `move_guest_to_node` for a guest.
    h.replace_route(Route {
        path: "/api2/json/cluster/ha/rules/keep-together",
        status: 200,
        body: br#"{"data":{"rule":"keep-together","type":"resource-affinity","resources":"vm:100,vm:101","affinity":"positive","comment":"changed out of band","digest":"ddeeff"}}"#,
    });

    let error = call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect_err("a rule that changed since the plan must refuse the apply");
    assert!(error.contains("fingerprint changed"), "{error}");
}

/// An existing `keep-together` resource-affinity rule over vm:100 and
/// vm:101, plus the guests it names.
fn existing_rule_routes(protected: bool) -> Vec<Route> {
    vec![
        guests_route(protected),
        Route {
            path: "/api2/json/cluster/ha/rules/keep-together",
            status: 200,
            body: br#"{"data":{"rule":"keep-together","type":"resource-affinity","resources":"vm:100,vm:101","affinity":"positive","digest":"aabbcc"}}"#,
        },
    ]
}

/// A rule naming a `protected` guest is refused at plan time: an HA rule
/// moves the guests it names, so it is gated like a destroy of each of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_naming_a_protected_guest_is_refused_at_plan_time() {
    let mut routes = no_such_rule_routes();
    routes[0] = guests_route(true);
    let h = TestServer::start_with_routes(ha_rule_spec(), routes).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a rule naming a protected guest must be refused");
    assert!(error.contains("protected"), "{error}");
}

/// Deleting an existing rule is gated on the guests the rule currently
/// names, not only on what the delete request names (nothing).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_rule_over_a_protected_guest_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), existing_rule_routes(true)).await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({"cluster": "pve3", "rule": "keep-together", "op": "delete"}),
    )
    .await
    .expect_err("a delete touching a protected guest must be refused");
    assert!(error.contains("protected"), "{error}");
}

/// A token whose guest scope does not cover the named guests cannot plan a
/// rule over them, even though it carries every HA tool scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rule_outside_the_token_guest_scope_is_refused() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let error = call_with_token(
        &h,
        &h.narrow_token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a rule outside the guest scope must be refused");
    assert!(error.contains("scope"), "{error}");
}

/// A narrowed token must not be able to tell an out-of-scope guest from an
/// absent one by planning a rule over each and comparing the refusal
/// wording -- the same existence-oracle guard `resolve.rs::authorize`
/// enforces for every other guest-addressed call, now also for
/// `plan_ha_rule_change`. Both plans name only the vmid in `resources`, not
/// an existing rule, so this exercises `authorize_ha_rule_guests`'s own
/// resolve match rather than the unrestricted-guest-scope gate on
/// `update`/`delete`.
///
/// The two errors necessarily differ in the vmid they echo back (the caller
/// already supplied it), so this asserts they share the unified suffix text
/// rather than asserting full equality.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_existing_out_of_scope_guest_and_an_absent_guest_read_identically_for_ha_rules() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let out_of_scope = call_with_token(
        &h,
        &h.narrow_token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("vm:100 exists but is outside the narrow token's guest scope");

    let absent = call_with_token(
        &h,
        &h.narrow_token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together-2",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:999"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("vm:999 does not exist in the fixture");

    let unified_suffix = "denied: guest is outside this caller's scope in cluster pve3 (an \
                          unknown vmid gets the same answer)";
    assert!(out_of_scope.contains(unified_suffix), "{out_of_scope}");
    assert!(absent.contains(unified_suffix), "{absent}");
    assert!(
        !absent.contains("which is outside this token's guest scope"),
        "the absent-guest arm must use the same wording as the out-of-scope arm, not the \
         old, distinct phrasing that let a narrowed token tell the two cases apart: {absent}"
    );
}

/// Planning an `update` or `delete` also authorizes the rule's *existing*
/// guests, which are not filtered by guest scope -- same reasoning as
/// `list_ha_rules`/`get_ha_rule`/`get_ha_rule_change_set`. Without this gate,
/// a narrowed token could learn a rule's membership from the refusal text
/// even though it can read none of those tools' output.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn updating_or_deleting_a_rule_requires_unrestricted_guest_scope() {
    let h = TestServer::start_with_routes(ha_rule_spec(), existing_rule_routes(false)).await;

    let delete_error = call_with_token(
        &h,
        &h.narrow_token,
        "plan_ha_rule_change",
        json!({"cluster": "pve3", "rule": "keep-together", "op": "delete"}),
    )
    .await
    .expect_err("a narrowed token must not plan a delete over a rule's existing membership");
    assert!(delete_error.contains("scope"), "{delete_error}");
    assert!(
        !delete_error.contains("100") && !delete_error.contains("101"),
        "the refusal must not name the rule's existing guests: {delete_error}"
    );

    let update_error = call_with_token(
        &h,
        &h.narrow_token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "update",
            "resources": ["vm:100"]
        }),
    )
    .await
    .expect_err("a narrowed token must not plan an update over a rule's existing membership");
    assert!(update_error.contains("scope"), "{update_error}");
}

/// The guest gate runs again at apply: a guest tagged `protected` after the
/// approval refuses the apply, and nothing is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_guest_protected_after_approval_refuses_the_apply() {
    let h = TestServer::start_with_routes(ha_rule_spec(), existing_rule_routes(false)).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({"cluster": "pve3", "rule": "keep-together", "op": "delete"}),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    approve_ha_rule_as_second_principal(&h, &id, "keep-together").await;

    h.replace_route(guests_route(true));

    let error = call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect_err("a guest protected since approval must refuse the apply");
    assert!(error.contains("protected"), "{error}");

    let reqs = h.requests();
    assert!(
        !reqs.iter().any(|r| r.method == "DELETE"),
        "nothing should have been deleted: {reqs:?}"
    );
}

/// F3: a token carrying every HA tool scope and `*` guests, but missing the
/// `destructive` action tier, must be refused -- and refused before any
/// request reaches the cluster on its behalf. Regression check for Percy's
/// finding that patching out the destructive-tier check left all of this
/// file's tests passing: none of them minted a token without the tier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_token_without_the_destructive_tier_is_refused_before_any_request() {
    let h = TestServer::start_with_routes_and_actions(
        ha_rule_spec(),
        no_such_rule_routes(),
        vec![
            rust_proxmoxmcp_core::ProxmoxAction::Read,
            rust_proxmoxmcp_core::ProxmoxAction::Low,
        ],
    )
    .await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a token without the destructive tier must be refused");
    assert!(error.contains("destructive"), "{error}");

    let reqs = h.requests();
    assert!(
        !reqs
            .iter()
            .any(|r| r.path.starts_with("/api2/json/cluster/ha/rules")),
        "no request should reach the cluster for a token missing the destructive tier: {reqs:?}"
    );
}

/// G1: a 500 whose body is an unrelated cluster fault that happens to
/// mention "rule" (a config file path, here) must not be read as "the
/// requested rule is absent" -- it must propagate as an error, and no POST
/// may go out on the strength of a false "does not exist".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unrelated_500_mentioning_rule_propagates_instead_of_meaning_absent() {
    let h = TestServer::start_with_routes(
        ha_rule_spec(),
        vec![
            guests_route(false),
            Route {
                path: "/api2/json/cluster/ha/rules/keep-together",
                status: 500,
                body: br#"{"data":null,"errors":{"x":"no such file or directory: /etc/pve/ha/rules.cfg"}}"#,
            },
        ],
    )
    .await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("an unrelated 500 must propagate rather than be read as absence");
    assert!(error.contains("reading current rule"), "{error}");

    let reqs = h.requests();
    assert!(
        !reqs.iter().any(|r| r.method == "POST"),
        "nothing should have been written on a false 'absent' read: {reqs:?}"
    );
}

/// G1: a 500 naming a *different* rule as missing must not be read as "the
/// requested rule is absent" either -- only a 500 naming the requested rule
/// itself counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_500_naming_a_different_rule_propagates() {
    let h = TestServer::start_with_routes(
        ha_rule_spec(),
        vec![
            guests_route(false),
            Route {
                path: "/api2/json/cluster/ha/rules/keep-together",
                status: 500,
                body: br#"{"data":null,"errors":{"rule":"no such HA rule 'other-rule'"}}"#,
            },
        ],
    )
    .await;

    let error = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect_err("a 500 naming a different rule must propagate");
    assert!(error.contains("reading current rule"), "{error}");

    let reqs = h.requests();
    assert!(
        !reqs.iter().any(|r| r.method == "POST"),
        "nothing should have been written on a false 'absent' read: {reqs:?}"
    );
}

/// G2: `apply_ha_rule_change`'s own early destructive-tier check, ahead of
/// `fetch_rule`, must refuse a token that lacks the `destructive` tier even
/// though it carries the same tool and guest scopes the plan/approve phase
/// used -- and must do so before any request past that phase reaches the
/// cluster. Regression check for the gap Percy found in #147's review: only
/// the plan-side check had a test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn apply_without_the_destructive_tier_is_refused_before_any_request() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    approve_ha_rule_as_second_principal(&h, &id, "keep-together").await;

    let before = h.requests().len();

    let error = call_with_token(
        &h,
        &h.low_tier_token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect_err("apply without the destructive tier must be refused");
    assert!(error.contains("destructive"), "{error}");

    let reqs = h.requests();
    assert_eq!(
        reqs.len(),
        before,
        "no request should reach the cluster once the plan/approve phase is done: {reqs:?}"
    );
}

/// F3: an override (a waiver, here) on a protected guest lets the plan pass,
/// but the change set still needs a second principal's approval before
/// apply -- an override only waives the guest check, never the
/// two-principal control.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_waiver_lets_the_plan_pass_but_apply_still_needs_second_principal_approval() {
    use rust_proxmoxmcp_core::waiver::{WaiverEntry, WaiverFile};
    use std::sync::Arc;

    let waiver = WaiverEntry::new(
        "pve3".to_owned(),
        101,
        4_102_444_800, // 2100-01-01 in Unix time
        "test waiver".to_owned(),
        Some("TEST-999".to_owned()),
        vec!["ha_rule_create".to_owned()],
        None,
    );
    let waivers = Arc::new(WaiverFile::with_entries(vec![waiver]));

    let mut routes = no_such_rule_routes();
    routes[0] = guests_route(true);
    let h = TestServer::start_with_config(ha_rule_spec(), routes, waivers, false).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect("plan should succeed with a matching waiver over the protected guest");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();
    let state = planned["state"].as_str().expect("state").to_owned();
    assert_ne!(
        state, "Approved",
        "an override waives the guest check, not the approval: {planned:?}"
    );

    let error = call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect_err("an unapproved change set must refuse the apply even with a waiver");
    assert!(error.to_lowercase().contains("approved"), "{error}");

    approve_ha_rule_as_second_principal(&h, &id, "keep-together").await;

    let applied = call_with_token(
        &h,
        &h.token,
        "apply_ha_rule_change",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect("apply should succeed once a second principal has approved");
    assert_eq!(applied["outcome"], "ok");
}

/// `get_ha_rule_change_set` must not hand its preview -- which names the
/// rule's guests -- to a token narrowed to a guest scope that does not cover
/// them, even though it did not create the change set and only knows its id.
/// Same reasoning as `list_ha_rules`/`get_ha_rule`, which already require an
/// unrestricted guest scope.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn get_ha_rule_change_set_requires_unrestricted_guest_scope() {
    let h = TestServer::start_with_routes(ha_rule_spec(), no_such_rule_routes()).await;

    let planned = call_with_token(
        &h,
        &h.token,
        "plan_ha_rule_change",
        json!({
            "cluster": "pve3",
            "rule": "keep-together",
            "op": "create",
            "rule_type": "resource-affinity",
            "resources": ["vm:100", "vm:101"],
            "affinity": "positive"
        }),
    )
    .await
    .expect("plan");
    let id = planned["change_set_id"].as_str().expect("id").to_owned();

    let error = call_with_token(
        &h,
        &h.narrow_token,
        "get_ha_rule_change_set",
        json!({"change_set_id": id, "cluster": "pve3", "rule": "keep-together"}),
    )
    .await
    .expect_err("a token narrowed away from '*' guest scope must not read the preview");
    assert!(error.contains("scope"), "{error}");
}
