//! 运行指标（[存档 §17.2](../../docs/review/chatgpt-2026-10-13.md)）。
//!
//! 第一版八项指标，**按数据来源分两类**（§17.2 明令「不要依赖单个指标判断
//! 端到端网络健康」）：
//!
//! - **控制面事件计数器**（进程内累加，随请求推进）：HTTP 请求/响应字节、
//!   配置应用成败、回滚成败、路由冲突拒绝、agent 心跳；
//! - **数据面证据量规**（抓取时从 `MeshState` 现算）：在线设备数、活跃 Peer
//!   数、最近握手时间、近期握手设备数（接口证据）、Alias 应用状态。
//!
//! 组合判读规则写死在 [`render`](Metrics::render) 的 HELP 文本与
//! `docs/architecture/observability.md`：控制面「在线」与数据面「握手」必须
//! 交叉看——单看任一指标都会把「控制面在册但隧道已断」或「隧道在但控制面
//! 未登记」误判为健康。
//!
//! 输出为 Prometheus 文本格式（`GET /api/v1/system/metrics`，管理面认证）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use crate::auth::{AuthenticatedUser, SharedAppState};
use crate::service;

/// 指标注册表（进程内；Clone 共享同一底层计数）。
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// key = `method|route|status_class`（route 是 axum 路由模板，基数有界）。
    http_requests: Mutex<BTreeMap<String, u64>>,
    http_response_bytes: AtomicU64,
    config_apply_applied: AtomicU64,
    config_apply_failed: AtomicU64,
    config_rollback_rolled_back: AtomicU64,
    config_rollback_unconfirmed: AtomicU64,
    route_conflicts: AtomicU64,
    agent_heartbeats: AtomicU64,
}

/// 抓取时从控制面状态现算的数据面证据量规。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GaugeSnapshot {
    /// 在线设备数（presence 判定 `online`）。
    pub devices_online: u64,
    /// 活跃 Peer 数（设备状态 `Active`）。
    pub devices_active: u64,
    /// 近期握手设备数（握手在窗口内——数据面隧道证据）。
    pub devices_with_recent_handshake: u64,
    /// 最近一次握手时刻（Unix 秒；0 = 从未观测到）。
    pub last_handshake_timestamp_seconds: i64,
    /// 接口状态（1 = 至少一台设备有近期握手证据；0 = 无数据面证据）。
    pub interface_up: u8,
    /// Alias 应用状态（Phase 4 未落地：恒 0 = 无 Alias 映射可应用）。
    pub alias_apply_status: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner::default()),
        }
    }

    /// HTTP 请求计数（中间件对每个已路由请求调用一次）。
    pub fn record_http(&self, method: &str, route: &str, status: StatusCode) {
        let class = match status.as_u16() {
            100..=199 => "1xx",
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            _ => "5xx",
        };
        let key = format!("{method}|{route}|{class}");
        let mut map = self.inner.http_requests.lock().unwrap();
        *map.entry(key).or_insert(0) += 1;
    }

    pub fn add_response_bytes(&self, bytes: u64) {
        self.inner
            .http_response_bytes
            .fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn record_config_apply(&self, applied: bool) {
        let counter = if applied {
            &self.inner.config_apply_applied
        } else {
            &self.inner.config_apply_failed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_config_rollback(&self, rolled_back: bool) {
        let counter = if rolled_back {
            &self.inner.config_rollback_rolled_back
        } else {
            &self.inner.config_rollback_unconfirmed
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_route_conflict(&self) {
        self.inner.route_conflicts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_agent_heartbeat(&self) {
        self.inner.agent_heartbeats.fetch_add(1, Ordering::Relaxed);
    }

    /// 渲染 Prometheus 文本格式（含 HELP/TYPE；量规来自 `gauges` 快照）。
    pub fn render(&self, gauges: &GaugeSnapshot) -> String {
        let applied = self.inner.config_apply_applied.load(Ordering::Relaxed);
        let failed = self.inner.config_apply_failed.load(Ordering::Relaxed);
        let rolled_back = self
            .inner
            .config_rollback_rolled_back
            .load(Ordering::Relaxed);
        let unconfirmed = self
            .inner
            .config_rollback_unconfirmed
            .load(Ordering::Relaxed);
        let conflicts = self.inner.route_conflicts.load(Ordering::Relaxed);
        let heartbeats = self.inner.agent_heartbeats.load(Ordering::Relaxed);
        let bytes = self.inner.http_response_bytes.load(Ordering::Relaxed);

        let mut out = String::new();
        out.push_str(
            "# HELP meshlet_http_requests_total Control-plane HTTP requests by route and status class.\n",
        );
        out.push_str("# TYPE meshlet_http_requests_total counter\n");
        {
            let map = self.inner.http_requests.lock().unwrap();
            for (key, count) in map.iter() {
                let mut parts = key.splitn(3, '|');
                let method = parts.next().unwrap_or("");
                let route = parts.next().unwrap_or("");
                let class = parts.next().unwrap_or("");
                out.push_str(&format!(
                    "meshlet_http_requests_total{{method=\"{}\",route=\"{}\",status_class=\"{}\"}} {count}\n",
                    escape_label(method),
                    escape_label(route),
                    escape_label(class),
                ));
            }
        }
        out.push_str("# HELP meshlet_http_response_bytes_total Control-plane response bytes (Content-Length sum).\n");
        out.push_str("# TYPE meshlet_http_response_bytes_total counter\n");
        out.push_str(&format!("meshlet_http_response_bytes_total {bytes}\n"));

        out.push_str(
            "# HELP meshlet_config_apply_total Config apply attempts by result (ADR-009).\n",
        );
        out.push_str("# TYPE meshlet_config_apply_total counter\n");
        out.push_str(&format!(
            "meshlet_config_apply_total{{result=\"applied\"}} {applied}\n"
        ));
        out.push_str(&format!(
            "meshlet_config_apply_total{{result=\"failed\"}} {failed}\n"
        ));
        // 成功率：仅在有样本时给出（无样本时省略，避免把「没数据」读成 100%）。
        if applied + failed > 0 {
            let ratio = applied as f64 / (applied + failed) as f64;
            out.push_str("# HELP meshlet_config_apply_success_ratio applied / (applied + failed); absent until the first apply.\n");
            out.push_str("# TYPE meshlet_config_apply_success_ratio gauge\n");
            out.push_str(&format!("meshlet_config_apply_success_ratio {ratio:.4}\n"));
        }
        out.push_str("# HELP meshlet_config_rollback_total Config rollback attempts by result.\n");
        out.push_str("# TYPE meshlet_config_rollback_total counter\n");
        out.push_str(&format!(
            "meshlet_config_rollback_total{{result=\"rolled_back\"}} {rolled_back}\n"
        ));
        out.push_str(&format!(
            "meshlet_config_rollback_total{{result=\"unconfirmed\"}} {unconfirmed}\n"
        ));
        out.push_str("# HELP meshlet_route_conflicts_total LAN route publications rejected as conflicting (ADR-004).\n");
        out.push_str("# TYPE meshlet_route_conflicts_total counter\n");
        out.push_str(&format!("meshlet_route_conflicts_total {conflicts}\n"));
        out.push_str("# HELP meshlet_agent_heartbeats_total Agent heartbeat reports accepted.\n");
        out.push_str("# TYPE meshlet_agent_heartbeats_total counter\n");
        out.push_str(&format!("meshlet_agent_heartbeats_total {heartbeats}\n"));

        out.push_str("# HELP meshlet_devices_online Devices judged online by the presence engine (control-plane view).\n");
        out.push_str("# TYPE meshlet_devices_online gauge\n");
        out.push_str(&format!(
            "meshlet_devices_online {}\n",
            gauges.devices_online
        ));
        out.push_str("# HELP meshlet_devices_active Devices in Active state (enrolled peers).\n");
        out.push_str("# TYPE meshlet_devices_active gauge\n");
        out.push_str(&format!(
            "meshlet_devices_active {}\n",
            gauges.devices_active
        ));
        out.push_str("# HELP meshlet_devices_with_recent_handshake Devices with a handshake inside the window (data-plane evidence; read together with meshlet_devices_online, never alone).\n");
        out.push_str("# TYPE meshlet_devices_with_recent_handshake gauge\n");
        out.push_str(&format!(
            "meshlet_devices_with_recent_handshake {}\n",
            gauges.devices_with_recent_handshake
        ));
        out.push_str("# HELP meshlet_last_handshake_timestamp_seconds Unix time of the newest observed handshake (0 = never observed).\n");
        out.push_str("# TYPE meshlet_last_handshake_timestamp_seconds gauge\n");
        out.push_str(&format!(
            "meshlet_last_handshake_timestamp_seconds {}\n",
            gauges.last_handshake_timestamp_seconds
        ));
        out.push_str("# HELP meshlet_interface_up 1 when at least one device shows recent handshake evidence, else 0 (agent-sourced; host-side interface lands with the data-plane backend).\n");
        out.push_str("# TYPE meshlet_interface_up gauge\n");
        out.push_str(&format!("meshlet_interface_up {}\n", gauges.interface_up));
        out.push_str("# HELP meshlet_alias_apply_status Alias apply state (§17.2). Phase 4 not landed: no alias mappings exist, so 0 means \"nothing to apply\", not \"healthy\".\n");
        out.push_str("# TYPE meshlet_alias_apply_status gauge\n");
        out.push_str(&format!(
            "meshlet_alias_apply_status {}\n",
            gauges.alias_apply_status
        ));
        out
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Prometheus 标签值转义（`\`、`"`、换行）。
fn escape_label(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            other => out.push(other),
        }
    }
    out
}

/// `GET /api/v1/system/metrics`：Prometheus 文本格式（管理面认证：会话或读
/// scope 的 API Token——外部监控以读 Token 抓取，见 `docs/guide/external-caller.md`）。
pub async fn metrics_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
) -> Response {
    let gauges = {
        let guard = state.mesh.lock().unwrap();
        service::gauge_snapshot(&guard)
    };
    let body = state.metrics.render(&gauges);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        body,
    )
        .into_response()
}

pub fn routes() -> Router<SharedAppState> {
    Router::new().route("/api/v1/system/metrics", get(metrics_handler))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_render_with_help_and_type_lines() {
        let m = Metrics::new();
        m.record_http("POST", "/api/v1/networks", StatusCode::CREATED);
        m.record_http("POST", "/api/v1/networks", StatusCode::CONFLICT);
        m.record_http("POST", "/api/v1/networks", StatusCode::CREATED);
        m.record_config_apply(false);
        m.record_config_rollback(false);
        m.record_route_conflict();
        m.record_agent_heartbeat();
        m.add_response_bytes(512);

        let text = m.render(&GaugeSnapshot::default());
        assert!(text.contains("# TYPE meshlet_http_requests_total counter"));
        assert!(text.contains(
            "meshlet_http_requests_total{method=\"POST\",route=\"/api/v1/networks\",status_class=\"2xx\"} 2"
        ));
        assert!(text.contains(
            "meshlet_http_requests_total{method=\"POST\",route=\"/api/v1/networks\",status_class=\"4xx\"} 1"
        ));
        assert!(text.contains("meshlet_http_response_bytes_total 512"));
        assert!(text.contains("meshlet_config_apply_total{result=\"applied\"} 0"));
        assert!(text.contains("meshlet_config_apply_total{result=\"failed\"} 1"));
        assert!(text.contains("meshlet_config_rollback_total{result=\"unconfirmed\"} 1"));
        assert!(text.contains("meshlet_route_conflicts_total 1"));
        assert!(text.contains("meshlet_agent_heartbeats_total 1"));
    }

    #[test]
    fn success_ratio_is_absent_until_the_first_apply() {
        // 无样本 ≠ 100% 健康：没有应用记录时不输出比率。
        let m = Metrics::new();
        let text = m.render(&GaugeSnapshot::default());
        assert!(!text.contains("meshlet_config_apply_success_ratio"));

        m.record_config_apply(true);
        m.record_config_apply(false);
        let text = m.render(&GaugeSnapshot::default());
        assert!(text.contains("meshlet_config_apply_success_ratio 0.5000"));
    }

    #[test]
    fn gauges_come_from_the_snapshot_not_from_statics() {
        let m = Metrics::new();
        let gauges = GaugeSnapshot {
            devices_online: 3,
            devices_active: 5,
            devices_with_recent_handshake: 2,
            last_handshake_timestamp_seconds: 1_760_000_000,
            interface_up: 1,
            alias_apply_status: 0,
        };
        let text = m.render(&gauges);
        assert!(text.contains("meshlet_devices_online 3"));
        assert!(text.contains("meshlet_devices_active 5"));
        assert!(text.contains("meshlet_devices_with_recent_handshake 2"));
        assert!(text.contains("meshlet_last_handshake_timestamp_seconds 1760000000"));
        assert!(text.contains("meshlet_interface_up 1"));
        assert!(text.contains("meshlet_alias_apply_status 0"));
        // 组合判读写进 HELP：不依赖单一指标（§17.2）。
        assert!(text.contains("never alone"));
    }

    #[test]
    fn label_values_are_escaped() {
        let m = Metrics::new();
        m.record_http("GET", "/weird\"\\\nroute", StatusCode::OK);
        let text = m.render(&GaugeSnapshot::default());
        assert!(text.contains("route=\"/weird\\\"\\\\\\nroute\""));
    }

    #[test]
    fn status_classes_are_bucketed() {
        let m = Metrics::new();
        for (status, class) in [
            (StatusCode::OK, "2xx"),
            (StatusCode::MOVED_PERMANENTLY, "3xx"),
            (StatusCode::NOT_FOUND, "4xx"),
            (StatusCode::INTERNAL_SERVER_ERROR, "5xx"),
        ] {
            m.record_http("GET", "/x", status);
            assert!(m
                .render(&GaugeSnapshot::default())
                .contains(&format!("status_class=\"{class}\"}} 1")));
        }
    }
}
