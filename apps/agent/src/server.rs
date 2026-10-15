//! server 交互（agent API，Bearer 凭证；§16.4 无命令下发）。
//!
//! 两个端点，都只读/只写**类型化对象**：
//! - `GET /api/v1/agent/device/desired` → [`DevicePlan`]（隧道/路由/NAT +
//!   `desired_config_hash`；`private_key` 恒为 `null`）；
//! - `POST /api/v1/agent/heartbeat` → 上报本地时间 + 可选握手时间 + 数据面
//!   实测证据（内核读数 + 大包探测，§7.5/§12.4）。
//!
//! 认证边界（§13.5）：agent API 用 Bearer 凭证，与管理 API 的 Cookie + CSRF
//! 完全分离；凭证缺失/失效一律 401，**不得**回退到任何其他认证方式。
//! 服务端数据面未开启时返回 503（`dataplane_not_configured`）——agent 视为
//! 「计划暂不可用」重试，绝不把空计划当成「已生效」。

use meshlet_domain::DataplaneEvidence;
use meshlet_network::DevicePlan;

/// 拉取本设备的期望数据面计划。
pub fn fetch_plan(server_url: &str, token: &str) -> Result<DevicePlan, String> {
    let url = format!(
        "{}/api/v1/agent/device/desired",
        server_url.trim_end_matches('/')
    );
    let req = ureq::get(&url).set("authorization", &format!("Bearer {token}"));
    let body = read(req.call())?;
    // 服务端契约：结构化配置对象。解析失败必须显式报错——绝不吞掉、也绝不
    // 用「空计划」顶替（空计划会抹掉现有隧道配置）。
    serde_json::from_str(&body).map_err(|e| format!("parse the desired plan: {e}"))
}

/// 心跳上报：返回服务端在线判定回执（仅用于日志/排查）。
///
/// 失败一律以 `Err` 报出（含 401/503 等分类），由调用方决定是否重试。
pub fn heartbeat(
    server_url: &str,
    token: &str,
    last_handshake_at: Option<String>,
    dataplane: Option<DataplaneEvidence>,
) -> Result<String, String> {
    let url = format!(
        "{}/api/v1/agent/heartbeat",
        server_url.trim_end_matches('/')
    );
    let payload = serde_json::json!({
        "last_handshake_at": last_handshake_at,
        "dataplane": dataplane,
    })
    .to_string();
    let req = ureq::post(&url)
        .set("authorization", &format!("Bearer {token}"))
        .set("content-type", "application/json")
        .send(payload.as_bytes());
    read(req)
}

/// 读取响应体（非 2xx → 分类错误）。
fn read(res: Result<ureq::Response, ureq::Error>) -> Result<String, String> {
    let resp = res.map_err(describe)?;
    resp.into_string()
        .map_err(|e| format!("read response body: {e}"))
}

/// 错误分类：HTTP 非 2xx 一律带状态码与响应体片段报出（§12.2 失败可见——
/// agent 侧日志能一眼看出是 401 凭证问题还是 503 服务端数据面未开启）。
fn describe(e: ureq::Error) -> String {
    match e {
        ureq::Error::Status(code, resp) => {
            let detail = resp.into_string().unwrap_or_default();
            format!("server returned {code}: {}", truncate(&detail, 200))
        }
        ureq::Error::Transport(t) => format!("transport failure: {t}"),
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_plan_rejects_malformed_json() {
        // 契约解析失败必须可见：不得返回空计划伪装成“已生效”。
        let body = "{\"tunnel\": {}}";
        assert!(serde_json::from_str::<DevicePlan>(body).is_err());
    }

    #[test]
    fn fetch_plan_requires_private_key_to_be_absent() {
        // 服务端下发时 private_key 必须是 null（ADR-010）；若意外带值说明
        // 契约被破坏——agent 应当发现（此单测锁定“null 可解析、有值也解析
        // 但不入账本”这条边界，最终以 netns 集成测试断言执行侧不写盘私钥）。
        let plan: DevicePlan = serde_json::from_str(
            r#"{"tunnel":{"name":"wg0","address":"10.240.0.7","address_prefix":16,
            "listen_port":null,"peers":[],"mtu":null,"private_key":null},
            "routes":[],"nat_rules":[],"desired_config_hash":"abc"}"#,
        )
        .expect("plan parses");
        assert_eq!(plan.tunnel.private_key, None);
        assert_eq!(plan.tunnel.address.to_string(), "10.240.0.7");
        assert_eq!(plan.desired_config_hash, "abc");
    }

    #[test]
    fn truncate_keeps_short_bodies_intact() {
        assert_eq!(truncate("short", 10), "short");
        let long = "x".repeat(30);
        assert_eq!(truncate(&long, 10).chars().count(), 11); // 10 + ellipsis
    }
}
