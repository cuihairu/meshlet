use std::io::Write;
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use super::{hub_status, mode_label, short_key, state_and_dot};
use crate::panel::snapshot::{age_text, now_secs};
use crate::panel::{
    config_value, read_url_file, remove_url_file, render, start, url, write_url_file, URL_FILE,
};

/// `<base>/state` 结构（与 `install.ps1` 的 `%LOCALAPPDATA%\meshlet\{…,state}` 同形）。
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

/// 三块数据齐全的 mock 数据源（不依赖 agent / server）。
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

    // 三块齐全（截图/断言口径：node / direct / routes）。
    for id in ["id=\"node\"", "id=\"direct\"", "id=\"routes\""] {
        assert!(html.contains(id), "missing section {id}");
    }
    for title in ["当前节点", "直连节点", "本地路由"] {
        assert!(html.contains(title), "missing section title {title}");
    }
    // ① 当前节点：名称 / 状态 / 版本 / EnvProbe。
    assert!(html.contains("office-nas"));
    assert!(html.contains("Meshlet online"));
    assert!(html.contains("已连接（控制通道正常）"));
    assert!(html.contains("10.240.0.5"));
    assert!(html.contains("agent 0.4.0"));
    assert!(html.contains("XDG_SESSION_TYPE"));
    assert!(html.contains("Console"));
    // ② 直连节点：全量两条（直连 + 中继候选），含 endpoint / 模式 / RTT。
    assert!(html.contains("peer-b"));
    assert!(html.contains("203.0.113.7:51820"));
    // 公钥整串（direct-peers.json 全量口径，缺省字段显示 —）。
    assert!(html.contains("abc=="));
    assert!(html.contains("def=="));
    assert!(html.contains("直连"));
    assert!(html.contains("中继"));
    assert!(html.contains("12 ms"));
    // ③ 本地路由：目标网段 / 下一跳 / 接口 / 来源。
    assert!(html.contains("192.168.8.0/24"));
    assert!(html.contains("10.240.0.3"));
    assert!(html.contains("wg-meshlet"));
    assert!(html.contains("服务端计划 · applied.json"));
    // 控制台入口（另列，不是本地面板的替代）。
    assert!(html.contains("https://meshlet.example.com"));
    // Overlay IP 复制按钮：当前节点的虚拟 IP + 直连节点两条 IP 都有按钮，
    // 且 data-copy 携带正确值（点击写剪贴板的数据源）。
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

/// 复制按钮的安全纪律：`data-copy` 值来自本机状态文件，必须转义——
/// 恶意值不得逃出属性变成标记（面板其余动态文本的既有转义口径）。
#[test]
fn copy_button_escapes_hostile_ip_values() {
    let state = temp_state_dir("copy-escape");
    std::fs::write(
        state.join("applied.json"),
        r#"{"tunnel_address":"\"><script>alert(1)</script>"}"#,
    )
    .unwrap();
    let html = render(&state);
    // 属性值整体被转义：引号变 &quot;、尖括号变实体。
    assert!(html.contains("data-copy=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\""));
    // 原始的引号/尖括号组合不得出现在任何 data-copy 属性边界外。
    assert!(!html.contains("\"><script>alert(1)"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// 没有虚拟 IP（账本缺失）时不出复制按钮——没有可复制的东西。
#[test]
fn no_copy_button_without_a_real_overlay_ip() {
    let state = temp_state_dir("copy-absent");
    let html = render(&state);
    assert!(!html.contains("data-copy="), "no copy button without data");
    // 直连节点也缺失时一条按钮都没有。
    assert!(!html.contains("class=\"copy\""));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// 直连节点 IP 缺失（形状不符 → 「—」占位）时该行不出复制按钮。
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
    // 数据不可用 ≠ 数据为空：三处都按「不可用」陈述，不推断 agent 行为。
    assert!(html.contains("直连节点数据不可用"));
    assert!(html.contains("本地账本不可用"));
    assert!(html.contains("未知（状态不可用）"));
    assert!(html.contains("状态说明不可用"));
    assert!(!html.contains("没有路由记录"));
    assert!(!html.contains("agent 尚未"));
    // 没有公钥指纹 ≠ 没有应用计划：措辞不得误导。
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

/// 真机 imac 形态：计划**已应用**但 `routes` 为空（纯叶子节点）。面板必须
/// 说「计划没下发路由」，不能把已应用的计划说成「尚未应用」。
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

/// `last_good_plan: null` 是 `AgentState::Option` 序列化的合法形状：必须走
/// 账本分支，不能当成「计划已应用但没路由」，更不能把账本里的路由藏掉。
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

/// 计划段是对象但没有 `routes`（形状不完整）：不能说「计划没下发路由」——
/// 那会把账本里的路由藏掉；回落账本分支。
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

/// 空数组（文件在、就是没记录）与数据不可用必须分开说。
#[test]
fn empty_peer_array_says_no_records_while_missing_file_says_unavailable() {
    let state = temp_state_dir("peer-empty");
    std::fs::write(state.join("direct-peers.json"), "[]").unwrap();
    assert!(render(&state).contains("没有节点记录"));
    std::fs::remove_file(state.join("direct-peers.json")).unwrap();
    assert!(render(&state).contains("直连节点数据不可用"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// 账本可读但 `routes` 字段形状不对：不能说「没有路由记录」。
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

/// 「直连」只留给显式 `null` gateway；字段缺失显示 `—`，不猜成直连路由。
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
    // 缺失 gateway 的那条：目标网段后必须是 `—`，不能也被标成直连。
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

/// 账本缺失时不得出现「应用于 —」这类没有证据的应用事件。
#[test]
fn missing_ledger_never_claims_an_application_time() {
    let state = temp_state_dir("no-ledger");
    let html = render(&state);
    assert!(!html.contains("应用于 —"));
    assert!(html.contains("本地账本不可用"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// 旧账本：计划段为 null 且账本无路由 —— 只陈述账本事实，不反推有没有应用计划。
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
    // section 内的键不算顶层 → None（不把 interface 当配置读出来）。
    assert_eq!(config_value(&state, "interface"), None);
    assert_eq!(config_value(&state, "nope"), None);
    // 旧部署 config.toml 兜底。
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
    // 漂移态推不出控制通道（derive 先判 drift）→ 如实标未知，不谎称断开。
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

/// 端到端：真起一个 loopback 服务，用裸 TCP 客户端验证 200 + 三块内容 +
/// 只读语义（POST 405、未知路径 404、HEAD 无 body）。
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

    // HEAD：头齐全、无 body。
    let head = get("/", "HEAD");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head.ends_with("\r\n\r\n"), "HEAD must not carry a body");

    // 只读面板：非 GET/HEAD 一律拒绝。
    let post = get("/", "POST");
    assert!(post.starts_with("HTTP/1.1 405"));
    // 只有根路径与 state.json 是端点。
    let missing = get("/etc/passwd", "GET");
    assert!(missing.starts_with("HTTP/1.1 404"));

    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// 局部更新数据源：`GET /state.json` 200 + 三块 JSON（与页面同一数据源）；
/// 写方法 405、未知路径 404、HEAD 无 body（只读纪律不变）。
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

    // 三块齐全：node / peers / routes（与 render 同一快照函数）。
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

    // 只读纪律：/state.json 同样只放行 GET/HEAD。
    let post = get("/state.json", "POST");
    assert!(post.starts_with("HTTP/1.1 405"));
    let head = get("/state.json", "HEAD");
    assert!(head.starts_with("HTTP/1.1 200 OK"));
    assert!(head.ends_with("\r\n\r\n"), "HEAD must not carry a body");
    let missing = get("/state.json.bak", "GET");
    assert!(missing.starts_with("HTTP/1.1 404"));

    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// 门禁：页面不再整页刷新（无 meta refresh、无 reload 调用），改用
/// fetch /state.json + 单元格 diff（滚动/焦点/复制钮状态不丢）。
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
    // 初始快照内联（无 JS 也见三块——服务端预渲染仍在）。
    assert!(html.contains("id=\"panel-state\""));
    assert!(html.contains("id=\"peers-body\""));
    // 单元格 diff 键：节点字段、直连节点行、路由行都有 data-f。
    assert!(html.contains("data-f=\"node."), "node field diff keys");
    assert!(html.contains("data-f=\"peer.0.rtt\""), "peer rtt diff key");
    assert!(html.contains("data-f=\"routes-caption\""));
    // 页面自身说明不再宣称「自动刷新」整页语义。
    assert!(html.contains("局部更新（不整页刷新）"));

    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// RTT 来源标注：如实四态（新 agent）+ 旧 agent 落盘的历史值（无来源字段）
/// 各得对应的 tooltip；「最近握手」列保留（活性主证据）。
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
    // 旧 agent 历史值仍可读（滚动升级兼容）。
    assert!(html.contains("来源：overlay 实测（对端 overlay VIP 直测）"));
    // 数值照常显示；不可测显示占位符。
    assert!(html.contains("12 ms"));
    assert!(html.contains(">—</span>"));
    // 最近握手表头仍在（活性主证据）。
    assert!(html.contains("最近握手"));
    let _ = std::fs::remove_dir_all(state.parent().unwrap());
}

/// 交接文件：写→读→删（CI 门禁与运维都靠它拿端口；写入是原子的）。
#[test]
fn url_file_round_trips_and_is_removed() {
    let state = temp_state_dir("url-file");
    assert!(read_url_file(&state).is_none());
    write_url_file(&state, "http://127.0.0.1:58132/").expect("write url file");
    assert_eq!(
        read_url_file(&state).as_deref(),
        Some("http://127.0.0.1:58132/")
    );
    // 覆盖写（第二次写必须替换旧文件，不是失败/追加）。
    write_url_file(&state, "http://127.0.0.1:44444/").expect("overwrite url file");
    assert_eq!(
        read_url_file(&state).as_deref(),
        Some("http://127.0.0.1:44444/")
    );
    // 原子发布：不留 .tmp 残骸。
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
    // 未来时间戳不显示负数。
    assert_eq!(age_text(now_secs() + 10_000), "—");
    // 刚刚 / 分钟 / 小时三档。
    assert_eq!(age_text(now_secs() - 5), "5 秒前");
    assert_eq!(age_text(now_secs() - 300), "5 分钟前");
    assert_eq!(age_text(now_secs() - 7_200), "2 小时前");
}
