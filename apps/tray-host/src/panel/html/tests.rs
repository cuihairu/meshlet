use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use super::{hub_status, mode_label, short_key, state_and_dot};
use crate::panel::snapshot::{age_text, now_secs};
use crate::panel::{
    config_value, read_url_file, remove_url_file, render, start, url, write_url_file, URL_FILE,
};

/// A `<base>/state` structure (isomorphic to `install.ps1`'s `%LOCALAPPDATA%\meshlet\{…,state}`).
fn temp_state_dir(tag: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "meshlet-panel-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let state = base.join("state");
    std::fs::create_dir_all(state.join("tray")).unwrap();
    state
}

/// A mock data source with all three blocks populated (no agent / server needed).
fn write_mock_data(state: &Path) {
    std::fs::write(
        state.parent().unwrap().join("agent.toml"),
        "server_url = \"https://meshlet.example.com\"\n\
             device_name = \"office-nas\"\n\
             state_dir = \"./state\"\n\
             [dataplane]\n\
             interface = \"wg-meshlet\"\n",
    )
    .unwrap();
    std::fs::write(
            state.join("tray").join("status.json"),
            r#"{"state":"Meshlet online","tooltip":"Meshlet「office-nas」 10.240.0.5：在线：控制通道正常，数据面与服务端期望一致（流量经 VPS 中继）","updated_at":"2026-11-06T12:00:00Z","version":"0.4.0","env":{"display":null,"wayland_display":null,"session_type":"tty","session_name":"Console","console_session":true}}"#,
        )
        .unwrap();
    std::fs::write(
            state.join("direct-peers.json"),
            r#"[{"name":"peer-b","virtual_ipv4":"10.240.0.3","public_key":"abc==","mode":"p2p_direct","rtt_ms":12,"rtt_source":"overlay","endpoint":"203.0.113.7:51820","last_handshake_at":1793980000},
               {"name":"","virtual_ipv4":"10.240.0.4","public_key":"def==","mode":"hub_relay","rtt_ms":null,"rtt_source":"unreachable","endpoint":"","last_handshake_at":null}]"#,
        )
        .unwrap();
    std::fs::write(
            state.join("applied.json"),
            r#"{"desired_config_hash":"abc","tunnel_address":"10.240.0.5","routes":["10.240.0.0/16"],"nat_rules":[],"nat_owners":[],"applied_at":"2026-11-06T11:59:00Z","local_public_key":"cWf8S0mVn1pQr7sT9uX2yZ4aB6dC8eF0gH1iJ3kL5=","last_good_plan":{"desired_revision":7,"tunnel":{"address":"10.240.0.5"},"routes":[{"destination":"10.240.0.0/16","interface":"wg-meshlet","gateway":null},{"destination":"192.168.8.0/24","interface":"wg-meshlet","gateway":"10.240.0.3"}],"nat_rules":[],"desired_config_hash":"abc"}}"#,
        )
        .unwrap();
}

#[test]
fn render_shows_all_three_sections_with_mock_data() {
    let state = temp_state_dir("render");
    write_mock_data(&state);
    let html = render(&state);

    // All three blocks present (screenshot/assertion vocabulary: node / direct / routes).
    for id in ["id=\"node\"", "id=\"direct\"", "id=\"routes\""] {
        assert!(html.contains(id), "missing section {id}");
    }
    for title in ["当前节点", "直连节点", "本地路由"] {
        assert!(html.contains(title), "missing section title {title}");
    }
    // ① Current node: name / state / version / EnvProbe.
    assert!(html.contains("office-nas"));
    assert!(html.contains("Meshlet online"));
    assert!(html.contains("已连接（控制通道正常）"));
    assert!(html.contains("10.240.0.5"));
    assert!(html.contains("agent 0.4.0"));
    assert!(html.contains("XDG_SESSION_TYPE"));
    assert!(html.contains("Console"));
    // ② Direct nodes: both entries in full (direct + relay candidate), including endpoint / mode / RTT.
    assert!(html.contains("peer-b"));
    assert!(html.contains("203.0.113.7:51820"));
    // The full public-key string (direct-peers.json full vocabulary; absent fields show —).
    assert!(html.contains("abc=="));
    assert!(html.contains("def=="));
    assert!(html.contains("直连"));
    assert!(html.contains("中继"));
    assert!(html.contains("12 ms"));
    // ③ Local routes: destination prefix / next hop / interface / source.
    assert!(html.contains("192.168.8.0/24"));
    assert!(html.contains("10.240.0.3"));
    assert!(html.contains("wg-meshlet"));
    assert!(html.contains("服务端计划 · applied.json"));
    // Console entry (listed separately, not a replacement for the local panel).
    assert!(html.contains("https://meshlet.example.com"));
    // Overlay IP copy buttons: the current node's virtual IP plus both direct-node IPs
    // each carry a button, and data-copy holds the correct value (the data written to
    // the clipboard on click).
    assert_eq!(
        html.matches("class=\"copy\"").count(),
        3,
        "three copy buttons"
    );
    assert!(
        html.contains("data-copy=\"10.240.0.5\""),
        "node virtual ip copy value"
    );
    assert!(
        html.contains("data-copy=\"10.240.0.3\""),
        "peer ip copy value"
    );
    assert!(
        html.contains("data-copy=\"10.240.0.4\""),
        "relay peer ip copy value"
    );
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// Copy-button security discipline: `data-copy` values come from local state
/// files and must be escaped — a hostile value must not break out of the
/// attribute into markup (the same escaping discipline as the panel's other
/// dynamic text).
#[test]
fn copy_button_escapes_hostile_ip_values() {
    let state = temp_state_dir("copy-escape");
    std::fs::write(
        state.join("applied.json"),
        r#"{"tunnel_address":"\"><script>alert(1)</script>"}"#,
    )
    .unwrap();
    let html = render(&state);
    // The attribute value is escaped as a whole: quotes become &quot;, angle brackets become entities.
    assert!(html.contains("data-copy=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
    // The raw quote/angle-bracket combination must not appear outside any data-copy attribute boundary.
    assert!(!html.contains("\"><script>alert(1)"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// No copy button without a virtual IP (ledger missing) — there is nothing to copy.
#[test]
fn no_copy_button_without_a_real_overlay_ip() {
    let state = temp_state_dir("copy-absent");
    let html = render(&state);
    assert!(!html.contains("data-copy="), "no copy button without data");
    // With direct nodes missing too, not a single button appears.
    assert!(!html.contains("class=\"copy\""));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// A direct-node row with a missing IP (shape mismatch → "—" placeholder) gets no copy button.
#[test]
fn placeholder_peer_ip_gets_no_copy_button() {
    let state = temp_state_dir("copy-placeholder");
    std::fs::write(state.join("direct-peers.json"), r#"[{"name":"peer-x"}]"#).unwrap();
    let html = render(&state);
    assert!(html.contains(">—<"), "placeholder ip renders");
    assert!(
        !html.contains("data-copy=\"—\""),
        "placeholder must not be copyable"
    );
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn render_degrades_gracefully_without_any_data_files() {
    let state = temp_state_dir("empty");
    let html = render(&state);
    for id in ["id=\"node\"", "id=\"direct\"", "id=\"routes\""] {
        assert!(html.contains(id), "sections must render even with no data");
    }
    // Data unavailable ≠ data empty: all three places state "unavailable" and never infer agent behavior.
    assert!(html.contains("直连节点数据不可用"));
    assert!(html.contains("本地账本不可用"));
    assert!(html.contains("未知（状态不可用）"));
    assert!(html.contains("状态说明不可用"));
    assert!(!html.contains("没有路由记录"));
    assert!(!html.contains("agent 尚未"));
    // No public-key fingerprint ≠ no applied plan: the wording must not mislead.
    assert!(html.contains("—（agent 未记录公钥指纹）"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn render_falls_back_to_ledger_route_prefixes() {
    let state = temp_state_dir("ledger-routes");
    std::fs::write(
        state.join("applied.json"),
        r#"{"applied_at":"2026-11-06T11:59:00Z","routes":["10.240.0.0/16","198.51.100.0/24"]}"#,
    )
    .unwrap();
    let html = render(&state);
    assert!(html.contains("10.240.0.0/16"));
    assert!(html.contains("198.51.100.0/24"));
    assert!(html.contains("本地账本 · applied.json"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// Real-machine imac shape: the plan **is applied** but `routes` is empty (a
/// pure leaf node). The panel must say "the plan delivered no routes" and must
/// not call an applied plan "not yet applied".
#[test]
fn applied_plan_without_routes_says_so_instead_of_claiming_no_plan() {
    let state = temp_state_dir("empty-plan-routes");
    std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":[],"last_good_plan":{"desired_revision":31,"routes":[]}}"#,
        )
        .unwrap();
    let html = render(&state);
    assert!(html.contains("计划未下发任何路由项"));
    assert!(html.contains("计划修订 rev31"));
    assert!(!html.contains("agent 尚未应用任何计划"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// `last_good_plan: null` is a legal shape of `AgentState::Option`
/// serialization: it must take the ledger branch, must not be treated as "the
/// plan was applied but has no routes", and must not hide the ledger's routes.
#[test]
fn null_last_good_plan_falls_back_to_ledger_routes() {
    let state = temp_state_dir("null-plan");
    std::fs::write(
        state.join("applied.json"),
        r#"{"applied_at":"2026-11-05T08:24:17Z","routes":["10.240.0.0/16"],"last_good_plan":null}"#,
    )
    .unwrap();
    let html = render(&state);
    assert!(html.contains("10.240.0.0/16"), "ledger route must show");
    assert!(html.contains("本地账本 · applied.json"));
    assert!(!html.contains("计划未下发任何路由项"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// The plan member is an object without `routes` (incomplete shape): it must
/// not say "the plan delivered no routes" — that would hide the ledger's
/// routes; fall back to the ledger branch.
#[test]
fn plan_without_routes_array_falls_back_to_ledger() {
    let state = temp_state_dir("plan-no-routes");
    std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":["10.240.0.0/16"],"last_good_plan":{"desired_revision":31}}"#,
        )
        .unwrap();
    let html = render(&state);
    assert!(html.contains("10.240.0.0/16"), "ledger route must show");
    assert!(!html.contains("计划未下发任何路由项"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// An empty array (the file exists, there just are no records) and unavailable data must be stated separately.
#[test]
fn empty_peer_array_says_no_records_while_missing_file_says_unavailable() {
    let state = temp_state_dir("peer-empty");
    std::fs::write(state.join("direct-peers.json"), "[]").unwrap();
    assert!(render(&state).contains("没有节点记录"));
    std::fs::remove_file(state.join("direct-peers.json")).unwrap();
    assert!(render(&state).contains("直连节点数据不可用"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// The ledger is readable but the `routes` field has the wrong shape: it must not say "no route records".
#[test]
fn malformed_ledger_routes_are_reported_as_unavailable() {
    let state = temp_state_dir("ledger-routes-invalid");
    std::fs::write(
        state.join("applied.json"),
        r#"{"applied_at":"2026-11-05T08:24:17Z","routes":"oops"}"#,
    )
    .unwrap();
    let html = render(&state);
    assert!(html.contains("本地账本路由数据不可用"));
    assert!(!html.contains("没有路由记录"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// "Direct" is reserved for an explicit `null` gateway; a missing field shows `—` and is not guessed as a direct route.
#[test]
fn next_hop_reserves_direct_label_for_explicit_null_gateway() {
    let state = temp_state_dir("gateway-shapes");
    std::fs::write(
            state.join("applied.json"),
            r#"{"applied_at":"2026-11-05T08:24:17Z","routes":[],"last_good_plan":{"desired_revision":3,"routes":[{"destination":"10.0.0.0/8","interface":"wg0","gateway":null},{"destination":"10.1.0.0/16","interface":"wg0"},{"destination":"10.2.0.0/16","interface":"wg0","gateway":"10.9.9.9"}]}}"#,
        )
        .unwrap();
    let html = render(&state);
    assert!(html.contains("直连（wg0）"), "explicit null = direct route");
    // The entry with the missing gateway: the destination prefix must be followed by `—`, and it must not be labeled direct too.
    let missing = html
        .split("10.1.0.0/16")
        .nth(1)
        .expect("route with missing gateway renders");
    assert!(
        missing.contains("<span data-f=\"routes.1.next\">—</span>"),
        "missing gateway must show —"
    );
    assert!(html.contains("10.9.9.9"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// With the ledger missing, an unevidenced application event such as "applied at —" must not appear.
#[test]
fn missing_ledger_never_claims_an_application_time() {
    let state = temp_state_dir("no-ledger");
    let html = render(&state);
    assert!(!html.contains("应用于 —"));
    assert!(html.contains("本地账本不可用"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// Legacy ledger: the plan member is null and the ledger has no routes — state only what the ledger says, without inferring whether a plan was applied.
#[test]
fn empty_legacy_ledger_states_the_ledger_fact_only() {
    let state = temp_state_dir("empty-ledger");
    std::fs::write(
        state.join("applied.json"),
        r#"{"applied_at":"2026-11-05T08:24:17Z","routes":[],"last_good_plan":null}"#,
    )
    .unwrap();
    let html = render(&state);
    assert!(html.contains("本地账本没有路由记录"));
    assert!(!html.contains("尚未应用任何计划"));
    assert!(!html.contains("计划未下发任何路由项"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn render_escapes_hostile_text() {
    let state = temp_state_dir("escape");
    std::fs::write(
        state.join("tray").join("status.json"),
        r#"{"state":"Meshlet online","tooltip":"<script>alert(1)</script>"}"#,
    )
    .unwrap();
    let html = render(&state);
    assert!(!html.contains("<script>alert(1)</script>"));
    assert!(html.contains("&lt;script&gt;"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn config_value_reads_top_level_keys_only() {
    let state = temp_state_dir("config");
    std::fs::write(
        state.parent().unwrap().join("agent.toml"),
        "server_url = \"https://hub.example\"\n\
             device_name = \"nas\"\n\
             [dataplane]\n\
             interface = \"wg-meshlet\"\n",
    )
    .unwrap();
    assert_eq!(
        config_value(&state, "server_url").as_deref(),
        Some("https://hub.example")
    );
    assert_eq!(config_value(&state, "device_name").as_deref(), Some("nas"));
    // Keys inside a section do not count as top level → None (interface must not be read out as config).
    assert_eq!(config_value(&state, "interface"), None);
    assert_eq!(config_value(&state, "nope"), None);
    // Older deployments fall back to config.toml.
    std::fs::remove_file(state.parent().unwrap().join("agent.toml")).unwrap();
    std::fs::write(
        state.parent().unwrap().join("config.toml"),
        "server_url = \"http://old.example:8080\"\n",
    )
    .unwrap();
    assert_eq!(
        config_value(&state, "server_url").as_deref(),
        Some("http://old.example:8080")
    );
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn state_and_hub_status_map_the_four_tray_states() {
    assert_eq!(
        state_and_dot(Some("Meshlet online")),
        ("在线".into(), "#c97b2e")
    );
    assert_eq!(
        hub_status(Some("Meshlet tunnel only")),
        "仅隧道（控制通道失效，agent 上报过期）"
    );
    // The drift state says nothing about the control channel (derive checks drift first) → honestly mark it unknown, without falsely claiming disconnected.
    assert_eq!(
        hub_status(Some("Meshlet tunnel drift")),
        "未知（隧道异常优先判定，控制通道状态未单独上报）"
    );
    assert_eq!(
        hub_status(Some("Meshlet offline")),
        "已断开（无新鲜的控制通道或隧道证据）"
    );
    assert_eq!(hub_status(None), "未知（状态不可用）");
}

#[test]
fn mode_label_maps_known_modes_and_keeps_unknowns() {
    assert_eq!(mode_label("p2p_direct"), "直连");
    assert_eq!(mode_label("direct_pending"), "拨号中");
    assert_eq!(mode_label("hub_relay"), "中继");
    assert_eq!(mode_label("something_new"), "something_new");
}

/// End to end: actually start a loopback service and use a raw TCP client to
/// verify 200 + the three blocks + read-only semantics (POST 405, unknown path
/// 404, HEAD without a body).
#[test]
fn server_answers_200_with_three_sections_and_rejects_writes() {
    let state = temp_state_dir("serve");
    write_mock_data(&state);
    let port = start(state.clone()).expect("bind loopback");
    let base = url(port);

    let get = |target: &str, method: &str| -> String {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let mut stream = stream;
        write!(
            stream,
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut stream, &mut out).unwrap();
        out
    };

    assert!(base.starts_with("http://127.0.0.1:"), "url = {base}");
    let body = get("/", "GET");
    assert!(
        body.starts_with("HTTP/1.1 200 OK"),
        "status line: {}",
        &body[..40]
    );
    assert!(body.contains("Cache-Control: no-store"));
    for id in ["id=\"node\"", "id=\"direct\"", "id=\"routes\""] {
        assert!(body.contains(id), "response missing {id}");
    }
    assert!(body.contains("office-nas"));
    assert!(body.contains("192.168.8.0/24"));

    // HEAD: headers present, no body.
    let head = get("/", "HEAD");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head.ends_with("\r\n\r\n"), "HEAD must not carry a body");

    // Read-only panel: anything but GET/HEAD is refused.
    let post = get("/", "POST");
    assert!(post.starts_with("HTTP/1.1 405"));
    // Only the root path and state.json are endpoints.
    let missing = get("/etc/passwd", "GET");
    assert!(missing.starts_with("HTTP/1.1 404"));

    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// The partial-update data source: `GET /state.json` 200 + the three JSON
/// blocks (the same data source as the page); write methods 405, unknown paths
/// 404, HEAD without a body (the read-only discipline is unchanged).
#[test]
fn state_json_route_serves_three_sections_and_stays_read_only() {
    let state = temp_state_dir("state-json");
    write_mock_data(&state);
    let port = start(state.clone()).expect("bind loopback");

    let get = |target: &str, method: &str| -> String {
        let stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let mut stream = stream;
        write!(
            stream,
            "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut out = String::new();
        std::io::Read::read_to_string(&mut stream, &mut out).unwrap();
        out
    };

    let response = get("/state.json", "GET");
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .expect("response splits into headers and body");
    assert!(
        headers.starts_with("HTTP/1.1 200 OK"),
        "status line: {}",
        &headers[..40]
    );
    assert!(
        headers.contains("Content-Type: application/json"),
        "state.json must be served as JSON: {headers}"
    );
    assert!(headers.contains("Cache-Control: no-store"));

    // All three blocks present: node / peers / routes (the same snapshot function as render).
    let json: serde_json::Value = serde_json::from_str(body).expect("valid JSON body");
    let node = json.get("node").expect("node block");
    assert_eq!(node.get("dot").and_then(|v| v.as_str()), Some("#c97b2e"));
    assert!(
        node.get("state_display")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("Meshlet online"),
        "state_display carries the raw agent state"
    );
    let fields = node.get("fields").and_then(|v| v.as_array()).unwrap();
    assert!(
        fields.iter().any(|f| f.as_array().unwrap()[0] == "设备名"),
        "node fields carry (label, value) pairs"
    );
    let peers = json
        .get("peers")
        .and_then(|p| p.get("rows"))
        .and_then(|v| v.as_array())
        .expect("peers rows");
    assert_eq!(peers.len(), 2, "both mock peers present");
    assert_eq!(peers[0].get("rtt").and_then(|v| v.as_str()), Some("12 ms"));
    assert_eq!(
        peers[0].get("rtt_title").and_then(|v| v.as_str()),
        Some("来源：overlay 实测（对端 overlay VIP 直测）"),
        "rtt source tooltip rides the row"
    );
    assert_eq!(
        peers[1].get("rtt_title").and_then(|v| v.as_str()),
        Some("来源：不可测（overlay 与 endpoint 均无响应，以「最近握手」为活性证据）"),
    );
    let routes = json
        .get("routes")
        .and_then(|r| r.get("rows"))
        .and_then(|v| v.as_array())
        .expect("routes rows");
    assert_eq!(routes.len(), 2, "both plan routes present");

    // Read-only discipline: /state.json likewise admits only GET/HEAD.
    let post = get("/state.json", "POST");
    assert!(post.starts_with("HTTP/1.1 405"));
    let head = get("/state.json", "HEAD");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head.ends_with("\r\n\r\n"), "HEAD must not carry a body");
    let missing = get("/state.json.bak", "GET");
    assert!(missing.starts_with("HTTP/1.1 404"));

    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// Gate: the page no longer does a full-page reload (no meta refresh, no
/// reload call) but instead uses fetch /state.json + cell-level diff (scroll
/// / focus / copy-button state are not lost).
#[test]
fn page_polls_state_json_and_never_full_page_reloads() {
    let state = temp_state_dir("no-refresh");
    write_mock_data(&state);
    let html = render(&state);

    assert!(
        !html.contains("http-equiv=\"refresh\""),
        "meta refresh must be gone (it caused the visible flicker)"
    );
    assert!(
        !html.contains("location.reload("),
        "full page reload is forbidden in the panel script"
    );
    assert!(
        html.contains("fetch('/state.json'"),
        "page must poll /state.json for partial updates"
    );
    assert!(html.contains("setInterval(poll"), "poll loop present");
    // The initial snapshot is inlined (the three blocks show even without JS — server-side pre-rendering is still there).
    assert!(html.contains("id=\"panel-state\""));
    assert!(html.contains("id=\"peers-body\""));
    // Cell diff keys: node fields, direct-node rows, and route rows all have data-f.
    assert!(html.contains("data-f=\"node."), "node field diff keys");
    assert!(html.contains("data-f=\"peer.0.rtt\""), "peer rtt diff key");
    assert!(html.contains("data-f=\"routes-caption\""));
    // The page's own caption no longer claims the "auto refresh" full-page semantics.
    assert!(html.contains("局部更新（不整页刷新）"));

    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// RTT source labels: the four truthful states (new agent) plus the historical
/// values persisted by old agents (no source field) each get their matching
/// tooltip; the "last handshake" column stays (the primary liveness evidence).
#[test]
fn rtt_column_labels_its_source() {
    let state = temp_state_dir("rtt-source");
    std::fs::write(
            state.join("direct-peers.json"),
            r#"[{"name":"a","virtual_ipv4":"10.240.0.3","mode":"p2p_direct","rtt_ms":12,"rtt_source":"probe_ok","endpoint":"203.0.113.7:51820"},
               {"name":"b","virtual_ipv4":"10.240.0.4","mode":"p2p_direct","rtt_ms":null,"rtt_source":"handshake_fresh"},
               {"name":"c","virtual_ipv4":"10.240.0.5","mode":"p2p_direct","rtt_ms":null,"rtt_source":"probe_failed"},
               {"name":"d","virtual_ipv4":"10.240.0.6","mode":"p2p_direct","rtt_ms":9},
               {"name":"e","virtual_ipv4":"10.240.0.7","mode":"p2p_direct","rtt_ms":null,"rtt_source":"unreachable"},
               {"name":"f","virtual_ipv4":"10.240.0.8","mode":"p2p_direct","rtt_ms":5,"rtt_source":"overlay"}]"#,
        )
        .unwrap();
    let html = render(&state);
    assert!(html.contains("来源：直连路径实测（overlay/endpoint ping 成功）"));
    assert!(html.contains("来源：握手新鲜（对端不答 ICMP，最近握手即链路活性证据）"));
    assert!(html.contains("来源：不可测（overlay 与 endpoint 均无响应，以「最近握手」为活性证据）"));
    assert!(html.contains("来源：未测（对端无直连路径或探测尚未完成）"));
    // Historical values from old agents stay readable (rolling-upgrade compatibility).
    assert!(html.contains("来源：overlay 实测（对端 overlay VIP 直测）"));
    // Values render as usual; unmeasurable ones show the placeholder.
    assert!(html.contains("12 ms"));
    assert!(html.contains(">—</span>"));
    // The last-handshake header stays (the primary liveness evidence).
    assert!(html.contains("最近握手"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// The handoff file: write → read → remove (both the CI gate and ops rely on it
/// to pick up the port; the write is atomic).
#[test]
fn url_file_round_trips_and_is_removed() {
    let state = temp_state_dir("url-file");
    assert!(read_url_file(&state).is_none());
    write_url_file(&state, "http://127.0.0.1:58132/").expect("write url file");
    assert_eq!(
        read_url_file(&state).as_deref(),
        Some("http://127.0.0.1:58132/")
    );
    // Overwrite (the second write must replace the old file, not fail or append).
    write_url_file(&state, "http://127.0.0.1:44444/").expect("overwrite url file");
    assert_eq!(
        read_url_file(&state).as_deref(),
        Some("http://127.0.0.1:44444/")
    );
    // Atomic publish: no .tmp residue left behind.
    assert!(!state.join(format!("{URL_FILE}.tmp")).exists());
    remove_url_file(&state);
    assert!(read_url_file(&state).is_none());
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

#[test]
fn short_key_and_age_helpers_are_human_readable() {
    assert_eq!(short_key("abc"), "abc");
    let long = "012345678901234567890123";
    assert_eq!(short_key(long), "01234567890123456789…");
    // A future timestamp never shows a negative age.
    assert_eq!(age_text(now_secs() + 10_000), "—");
    // Three tiers: just-now / minutes / hours.
    assert_eq!(age_text(now_secs() - 5), "5 秒前");
    assert_eq!(age_text(now_secs() - 300), "5 分钟前");
    assert_eq!(age_text(now_secs() - 7_200), "2 小时前");
}
