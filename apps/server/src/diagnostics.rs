//! 网络诊断（[存档 §12.7](../../docs/review/chatgpt-2026-10-13.md)）：13 项
//! 检查，按故障层归类（隧道/路由/转发/Alias + 控制面），第一版只诊断不修复。
//!
//! 判读纪律（§17.2 组合判读 + 本单硬要求）：
//! - **不假绿**：控制面观测不到的本机状态（WireGuard 接口、内核路由、IP
//!   forwarding、防火墙、NAT 规则）如实报 `unavailable`——它不是「健康」，
//!   并给出一句话可在目标机器上执行的检查命令；
//! - **控制面在册 ≠ 隧道正常**：Peer 注册（`server_peer_configured`）与握手
//!   新鲜（`recent_handshake`）是两项独立检查，前者 detail 必须点名这一点
//!   （§12.4：握手只证明隧道连通，agent 上报才证明设备功能正常）；
//! - 每一项 `fail`/`warning`/`unavailable` 都带可执行建议（`suggestion`）。
//!
//! 结果持久化（migration 006）：`POST` 计算并落一行快照，`GET` 返回最近
//! 一次运行的报告；未运行过 → 404（[ServiceError::DiagnosticsNotRun]）。

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use meshlet_domain::{
    AliasMapping, ApplyStatus, ConfigRevision, DataplaneEvidence, DesiredStateStatus, Device,
    LanRoute, PresenceState, RouteMode,
};
use serde::{Deserialize, Serialize};

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::{self, ServiceError};

// ---------------------------------------------------------------------------
// 报告结构
// ---------------------------------------------------------------------------

/// 故障层（§12.7 验收：能区分隧道/路由/转发/Alias 故障层）。
pub mod layer {
    pub const CONTROL_PLANE: &str = "control_plane";
    pub const TUNNEL: &str = "tunnel";
    pub const ROUTING: &str = "routing";
    pub const FORWARDING: &str = "forwarding";
    pub const ALIAS: &str = "alias";
}

/// 单项检查结果（id/name/layer/status 是封闭词表，存 `String` 便于快照
/// 反序列化；词表由下方构造函数与 `layer` 常量钉住）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    /// 稳定标识（契约字段，控制台据此排序/对位 §12.7 检查项）。
    pub id: String,
    pub name: String,
    /// `control_plane` / `tunnel` / `routing` / `forwarding` / `alias`。
    pub layer: String,
    /// `pass` / `fail` / `warning` / `unavailable` / `not_applicable`。
    pub status: String,
    /// 观测到的事实（含「为什么拿不到」——unavailable 的原因）。
    pub detail: String,
    /// 可执行建议；`pass` 为空串。
    pub suggestion: String,
}

/// 一次诊断运行的完整报告（`POST` 计算落库、`GET` 反序列化返回）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub network_id: String,
    pub checked_at: String,
    pub checks: Vec<DiagnosticCheck>,
}

/// `unavailable` 的统一语义：控制面**观测不到**（本机状态需要本地特权读数），
/// 不是「健康」。detail 说明缺什么，suggestion 给出目标机器上的检查命令。
fn unavailable(
    id: &'static str,
    name: &'static str,
    layer: &'static str,
    detail: String,
    suggestion: String,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        name: name.into(),
        layer: layer.into(),
        status: "unavailable".into(),
        detail,
        suggestion,
    }
}

/// `not_applicable`：本网络没有该检查的对象（如实区分于 pass）。
fn not_applicable(
    id: &'static str,
    name: &'static str,
    layer: &'static str,
    detail: String,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        name: name.into(),
        layer: layer.into(),
        status: "not_applicable".into(),
        detail,
        suggestion: String::new(),
    }
}

/// 构造一个任意状态的检查项（各 check_* 函数共用）。
fn check(
    id: &'static str,
    name: &'static str,
    layer: &'static str,
    status: &'static str,
    detail: String,
    suggestion: String,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        name: name.into(),
        layer: layer.into(),
        status: status.into(),
        detail,
        suggestion,
    }
}

// ---------------------------------------------------------------------------
// 13 项检查（§12.7 顺序）
// ---------------------------------------------------------------------------

/// 计算一个网络的 13 项检查。`now` 注入便于确定性测试；`aliases` 来自
/// `alias_mappings` 表（§12.6 服务写路径产生；正常数据创建时已过同一套
/// 冲突检查，此处兜底防脏库/手改库）；`tunnel_mtu` 来自 server 配置
/// （§7.5，⑬ 的输入）。
pub fn run_checks(
    mesh: &service::MeshState,
    network_id: &str,
    aliases: &[AliasMapping],
    tunnel_mtu: Option<u32>,
    now: &str,
) -> DiagnosticsReport {
    let overlay = mesh
        .network_row(network_id)
        .expect("caller checked network exists")
        .overlay_cidr;
    let active: Vec<&Device> = mesh
        .registry
        .devices()
        .iter()
        .filter(|d| d.network_id.to_string() == network_id && d.is_active())
        .collect();
    let routes: Vec<&LanRoute> = mesh
        .lan_routes
        .get(network_id)
        .map(|rs| rs.iter().collect())
        .unwrap_or_default();
    let latest = mesh
        .ledger
        .current(&meshlet_domain::NetworkId(network_id.to_string()))
        .cloned();
    let thresholds = &mesh.presence_thresholds;

    DiagnosticsReport {
        network_id: network_id.to_string(),
        checked_at: now.to_string(),
        checks: vec![
            check_api_reachable(now),
            check_wg_interface(),
            check_server_peer(&active),
            check_recent_handshake(&active, now, thresholds.handshake_window),
            check_overlay_route(&overlay.to_string()),
            check_ip_forwarding(),
            check_firewall_forwarding(),
            check_gateway_online(&routes, mesh, now),
            check_route_published(&routes, latest.as_ref()),
            check_alias_conflict(aliases, &routes, &overlay),
            check_nat_rules(&routes, mesh),
            check_revision_consistent(latest.as_ref()),
            check_mtu_planned(tunnel_mtu, &active),
        ],
    }
}

/// ① API 可达（控制面）：能读到本报告即证明诊断时刻管理 API 在服务。
fn check_api_reachable(now: &str) -> DiagnosticCheck {
    check(
        "api_reachable",
        "API reachable",
        layer::CONTROL_PLANE,
        "pass",
        format!(
            "this run was produced by the management API at {now} — the control plane answered the request"
        ),
        String::new(),
    )
}

/// ② WireGuard 接口存在（隧道）：本机状态，控制面不可观测。
fn check_wg_interface() -> DiagnosticCheck {
    unavailable(
        "wg_interface_exists",
        "WireGuard interface exists",
        layer::TUNNEL,
        "the control plane cannot read a device's local WireGuard interface; it requires a local `wg show` on each device".into(),
        "on each device run `wg show mesh0` (or the configured interface) — a missing interface means the agent has not brought the tunnel up; check the agent service (`systemctl status meshlet-agent`) and its logs".into(),
    )
}

/// ③ 服务端 Peer 已配置（隧道）：注册表里有公钥即已配置——但这只证明
/// 「控制面在册」，不证明隧道可用（那是 ④ 的职责）。
fn check_server_peer(active: &[&Device]) -> DiagnosticCheck {
    if active.is_empty() {
        return not_applicable(
            "server_peer_configured",
            "Server peer configured",
            layer::TUNNEL,
            "no devices registered in this network".into(),
        );
    }
    let names: Vec<String> = active.iter().map(|d| d.name.clone()).collect();
    check(
        "server_peer_configured",
        "Server peer configured",
        layer::TUNNEL,
        "pass",
        format!(
            "{} device(s) registered with a WireGuard public key on the server: {} — control-plane registration only; it does not prove the tunnel carries traffic (see the handshake check)",
            active.len(),
            names.join(", ")
        ),
        String::new(),
    )
}

/// ④ 最近握手正常（隧道）：握手是唯一隧道层证据（§12.4）；新鲜窗口与
/// presence 一致（`handshake_window`，默认 120s）。
fn check_recent_handshake(
    active: &[&Device],
    now: &str,
    window: std::time::Duration,
) -> DiagnosticCheck {
    if active.is_empty() {
        return not_applicable(
            "recent_handshake",
            "Recent handshake",
            layer::TUNNEL,
            "no devices registered in this network".into(),
        );
    }
    let mut parts: Vec<String> = Vec::new();
    let mut fresh_count = 0usize;
    for d in active {
        match d.last_handshake_at.as_deref() {
            Some(ts) if meshlet_domain::presence::fresh(ts, now, window) => {
                fresh_count += 1;
                parts.push(format!(
                    "{}: fresh handshake ({} ago)",
                    d.name,
                    ago(ts, now)
                ));
            }
            Some(ts) => parts.push(format!(
                "{}: stale handshake (last {} ago, window {}s)",
                d.name,
                ago(ts, now),
                window.as_secs()
            )),
            None => parts.push(format!(
                "{}: no handshake ever observed (device registered, tunnel never confirmed)",
                d.name
            )),
        }
    }
    let all_fresh = fresh_count == active.len();
    check(
        "recent_handshake",
        "Recent handshake",
        layer::TUNNEL,
        if all_fresh { "pass" } else { "fail" },
        format!(
            "{fresh_count}/{} device(s) with a handshake inside the {}s window: {}",
            active.len(),
            window.as_secs(),
            parts.join("; ")
        ),
        if all_fresh {
            String::new()
        } else {
            "a fresh handshake is the only tunnel-level evidence the control plane has (§12.4): run `wg show mesh0` on the devices to read latest-handshake directly; a stale or missing handshake usually means the interface is down, the peer endpoint is unreachable, or keys were rotated on one side".into()
        },
    )
}

/// ⑤ Overlay IP 路由存在（路由）：内核路由表，控制面不可观测。
fn check_overlay_route(overlay: &str) -> DiagnosticCheck {
    unavailable(
        "overlay_route_present",
        "Overlay route present",
        layer::ROUTING,
        format!(
            "the control plane cannot read a device's kernel routing table; the overlay to look for is {overlay}"
        ),
        format!(
            "on each device run `ip route show to {overlay}` — expect a route via the mesh interface; if missing, the agent has not installed the overlay route (check the agent's apply output)"
        ),
    )
}

/// ⑥ IP Forwarding 开启（转发）：网关机 sysctl，控制面不可观测。
fn check_ip_forwarding() -> DiagnosticCheck {
    unavailable(
        "ip_forwarding_enabled",
        "IP forwarding enabled",
        layer::FORWARDING,
        "the control plane cannot read the gateway's `net.ipv4.ip_forward` sysctl".into(),
        "on the LAN gateway run `sysctl net.ipv4.ip_forward` — expect 1; enable with `sysctl -w net.ipv4.ip_forward=1` and persist under /etc/sysctl.d/. ip_forward=0 silently drops all forwarded LAN traffic while the tunnel itself can still look healthy".into(),
    )
}

/// ⑦ 防火墙允许必要转发（转发）：网关机防火墙规则，控制面不可观测。
fn check_firewall_forwarding() -> DiagnosticCheck {
    unavailable(
        "firewall_allows_forwarding",
        "Firewall allows forwarding",
        layer::FORWARDING,
        "the control plane cannot read the gateway's firewall rules (FORWARD chain / ufw)".into(),
        "on the LAN gateway run `iptables -L FORWARD -n -v` and `iptables -t nat -L -n -v` (or `ufw status verbose`) — expect FORWARD to accept traffic from the mesh interface; a REJECT/DROP policy here silently breaks LAN reachability while handshakes keep succeeding".into(),
    )
}

/// ⑧ LAN 网关 Agent 在线（路由）：网关的 agent 必须有**新鲜 agent 上报**
/// （§12.4：仅握手新鲜 = tunnel_only，不能视为设备功能正常）。
fn check_gateway_online(
    routes: &[&LanRoute],
    mesh: &service::MeshState,
    now: &str,
) -> DiagnosticCheck {
    if routes.is_empty() {
        return not_applicable(
            "lan_gateway_agent_online",
            "LAN gateway agent online",
            layer::ROUTING,
            "no LAN routes in this network".into(),
        );
    }
    let mut parts: Vec<String> = Vec::new();
    let mut online = 0usize;
    let mut tunnel_only = 0usize;
    let mut broken = 0usize;
    for r in routes {
        let Some(device) = mesh.registry.find_by_id(&r.gateway_device_id) else {
            broken += 1;
            parts.push(format!(
                "route {}: gateway {} not registered (revoked or never enrolled) — the route has no live gateway",
                r.id, r.gateway_device_id
            ));
            continue;
        };
        if !device.is_active() {
            broken += 1;
            parts.push(format!(
                "route {} → gateway {}: device revoked — the route has no live gateway",
                r.id, device.name
            ));
            continue;
        }
        let presence =
            service::evaluate_presence(device, &now.to_string(), &mesh.presence_thresholds);
        match presence.state {
            PresenceState::Online => {
                online += 1;
                parts.push(format!(
                    "route {} → gateway {}: agent online (last report {} ago)",
                    r.id,
                    device.name,
                    ago(
                        device
                            .last_report_at
                            .as_deref()
                            .unwrap_or(&device.created_at),
                        now
                    )
                ));
            }
            PresenceState::TunnelOnly => {
                tunnel_only += 1;
                parts.push(format!(
                    "route {} → gateway {}: tunnel only (fresh handshake but no fresh agent report) — the agent process may be down",
                    r.id, device.name
                ));
            }
            PresenceState::Offline => {
                broken += 1;
                parts.push(format!(
                    "route {} → gateway {}: agent offline (no fresh evidence since {})",
                    r.id,
                    device.name,
                    ago(
                        device.last_seen_at.as_deref().unwrap_or(&device.created_at),
                        now
                    )
                ));
            }
        }
    }
    let (status, suggestion) = if broken > 0 {
        (
            "fail",
            "the gateway agent must report fresh agent evidence for its LAN routes to be considered live: check `systemctl status meshlet-agent` on the gateway, its reachability to the server, and the last heartbeat in the devices panel".to_string(),
        )
    } else if tunnel_only > 0 {
        (
            "warning",
            "a gateway with only fresh handshake evidence (tunnel_only) has a working tunnel but an unverifiable agent process — verify the agent is running and reporting".to_string(),
        )
    } else {
        ("pass", String::new())
    };
    DiagnosticCheck {
        id: "lan_gateway_agent_online".into(),
        name: "LAN gateway agent online".into(),
        layer: layer::ROUTING.into(),
        status: status.into(),
        detail: format!(
            "{online} online, {tunnel_only} tunnel-only, {broken} offline/unregistered across {} route(s): {}",
            routes.len(),
            parts.join("; ")
        ),
        suggestion,
    }
}

/// ⑨ LAN Route 已发布（路由）：控制面口径 = 路由已记录 + 覆盖它的最新修订
/// 已应用；**不**证明网关内核装了路由（那是 ⑤⑦ 的本机读数）。
fn check_route_published(routes: &[&LanRoute], latest: Option<&ConfigRevision>) -> DiagnosticCheck {
    if routes.is_empty() {
        return not_applicable(
            "lan_route_published",
            "LAN route published",
            layer::ROUTING,
            "no LAN routes in this network".into(),
        );
    }
    let items: Vec<String> = routes
        .iter()
        .map(|r| {
            format!(
                "{} → {} via {} ({})",
                r.id,
                r.destination_cidr,
                r.gateway_device_id,
                desired_status(r.status)
            )
        })
        .collect();
    let Some(rev) = latest else {
        return check(
            "lan_route_published",
            "LAN route published",
            layer::ROUTING,
            "fail",
            format!(
                "{} route(s) recorded ({}), but no config revision exists — desired state was never applied",
                routes.len(),
                items.join("; ")
            ),
            "record and apply a config revision covering these routes".into(),
        );
    };
    let (status, suggestion) = match rev.apply_status {
        ApplyStatus::Applied => ("pass", String::new()),
        ApplyStatus::Failed => (
            "fail",
            "the routes were recorded but the apply failed — nothing was published to any backend: roll back the failed revision or record a new one after fixing the backend".into(),
        ),
        _ => (
            "warning",
            "the revision covering these routes is not confirmed applied yet — apply it from the config-revisions panel".into(),
        ),
    };
    let state_note = match rev.apply_status {
        ApplyStatus::Applied => "applied",
        ApplyStatus::Failed => "failed",
        other => other.as_str(),
    };
    DiagnosticCheck {
        id: "lan_route_published".into(),
        name: "LAN route published".into(),
        layer: layer::ROUTING.into(),
        status: status.into(),
        detail: format!(
            "{} route(s) recorded ({}); latest revision #{} is {state_note} — control-plane publication only; whether the gateway's kernel actually has the route is a local-machine fact (see overlay route / firewall checks)",
            routes.len(),
            items.join("; "),
            rev.revision
        ),
        suggestion,
    }
}

/// ⑩ Alias 前缀冲突（Alias）：对已存在的映射跑域层冲突检测
/// （overlay 重叠 / alias 互叠 / 绑定路由网段不一致）。
fn check_alias_conflict(
    aliases: &[AliasMapping],
    routes: &[&LanRoute],
    overlay: &meshlet_domain::Ipv4Cidr,
) -> DiagnosticCheck {
    if aliases.is_empty() {
        return not_applicable(
            "alias_prefix_conflict",
            "Alias prefix conflict",
            layer::ALIAS,
            "no alias mappings in this network (equal-prefix virtual mapping, ADR-006) — nothing to conflict-check".into(),
        );
    }
    let mut conflicts: Vec<String> =
        meshlet_domain::conflict::overlay_alias_overlap(*overlay, aliases)
            .into_iter()
            .map(|c| c.detail)
            .collect();
    conflicts.extend(
        meshlet_domain::conflict::alias_alias_overlap(aliases)
            .into_iter()
            .map(|c| c.detail),
    );
    for alias in aliases {
        if let Some(route) = routes.iter().find(|r| r.id == alias.lan_route_id) {
            conflicts.extend(
                meshlet_domain::conflict::alias_target_mismatch(alias, route)
                    .into_iter()
                    .map(|c| c.detail),
            );
        }
    }
    check(
        "alias_prefix_conflict",
        "Alias prefix conflict",
        layer::ALIAS,
        if conflicts.is_empty() { "pass" } else { "fail" },
        if conflicts.is_empty() {
            format!(
                "{} alias mapping(s) checked against the overlay, each other, and their bound routes — no conflicts",
                aliases.len()
            )
        } else {
            format!("{} conflict(s): {}", conflicts.len(), conflicts.join("; "))
        },
        if conflicts.is_empty() {
            String::new()
        } else {
            "conflicting aliases make the equal-prefix translation ambiguous: remove or re-prefix the offending mapping (ADR-006) and record a new revision".into()
        },
    )
}

/// ⑪ NAT 规则生效（Alias）：网关 agent 心跳回传的内核扫描（按所有权注释，
/// §12.6）。没有任何网关上报证据时控制面如实「不可观测」——那部分不假装。
fn check_nat_rules(routes: &[&LanRoute], mesh: &service::MeshState) -> DiagnosticCheck {
    let alias_routes: Vec<&LanRoute> = routes
        .iter()
        .copied()
        .filter(|r| r.route_mode == RouteMode::Alias && r.status == DesiredStateStatus::Applied)
        .collect();
    // 只评判「上报了证据」的网关：证据缺失（agent 未运行 / 旧版本）不等于
    // 规则不存在，也不等于存在（§12.2 判读纪律）。
    let mut reporting: Vec<(String, bool, Option<bool>)> = Vec::new();
    for route in &alias_routes {
        let Some(gateway) = mesh.registry.find_by_id(&route.gateway_device_id) else {
            continue;
        };
        let Some(evidence) = gateway.dataplane_evidence.as_ref() else {
            continue;
        };
        let Some(present) = evidence.nat_rules_present else {
            continue;
        };
        reporting.push((
            gateway.name.clone(),
            present,
            evidence.nat_snat_rules_present,
        ));
    }
    if reporting.is_empty() {
        return unavailable(
            "nat_rules_effective",
            "NAT rules effective",
            layer::ALIAS,
            if alias_routes.is_empty() {
                "the control plane cannot read the gateway's NAT rules or their traffic counters; no gateway agent has reported kernel evidence yet".to_string()
            } else {
                format!(
                    "the control plane cannot read the gateway's NAT rules; {} alias route(s) registered but no gateway agent has reported kernel evidence yet (agent not running or an older agent without evidence reporting)",
                    alias_routes.len()
                )
            },
            "on the LAN gateway run `iptables -t nat -L -n -v` — for each alias mapping check the DNAT/SNAT rules exist and their packet counters grow with traffic; zero counters on an active mapping means the rule exists but no traffic matches (wrong prefix or interface). An up-to-date agent reports this reading via its heartbeat (§12.4)".into(),
        );
    }
    let broken: Vec<String> = reporting
        .iter()
        .filter(|(_, present, _)| !present)
        .map(|(name, _, _)| name.clone())
        .collect();
    if !broken.is_empty() {
        return check(
            "nat_rules_effective",
            "NAT rules effective",
            layer::ALIAS,
            "fail",
            format!(
                "at their last heartbeat, gateway(s) {} reported no meshlet NAT rules in the kernel — the rules do not survive reboots and the alias path is broken until the agent re-applies them",
                broken.join(", ")
            ),
            "check the gateway agent is running (`systemctl status meshlet-agent`) and can reach the server; a healthy agent detects the missing rules and replays them on its next reconcile (§12.6)".into(),
        );
    }
    let names: Vec<String> = reporting.iter().map(|(name, _, _)| name.clone()).collect();
    // SNAT 读数按内核实测分开表述：`dnat_only` 映射本就不下发 SNAT 规则
    // （ADR-005 模式 A），规则在场 ≠ SNAT 在场，不混为一谈。
    let snat_confirmed: Vec<String> = reporting
        .iter()
        .filter(|(_, _, snat)| *snat == Some(true))
        .map(|(name, _, _)| name.clone())
        .collect();
    let snat_absent: Vec<String> = reporting
        .iter()
        .filter(|(_, present, snat)| *present && *snat != Some(true))
        .map(|(name, _, _)| name.clone())
        .collect();
    let snat_note = if snat_absent.is_empty() {
        format!(
            "controlled SNAT kernel-confirmed by {}",
            snat_confirmed.join(", ")
        )
    } else if snat_confirmed.is_empty() {
        format!(
            "no meshlet SNAT rule observed on {} (dnat_only mappings keep original sources, ADR-005)",
            snat_absent.join(", ")
        )
    } else {
        format!(
            "controlled SNAT kernel-confirmed by {}; no meshlet SNAT rule observed on {} (dnat_only mappings keep original sources, ADR-005)",
            snat_confirmed.join(", "),
            snat_absent.join(", ")
        )
    };
    check(
        "nat_rules_effective",
        "NAT rules effective",
        layer::ALIAS,
        "pass",
        format!(
            "gateway(s) {} report the ownership-commented NAT rules present in their kernel ({})",
            names.join(", "),
            snat_note
        ),
        String::new(),
    )
}

/// ⑫ 配置版本一致（控制面）：最新未回滚修订的状态 = 期望配置与实际环境的
/// 一致性结论（§10.1：DB 写入 ≠ 生效）。
fn check_revision_consistent(latest: Option<&ConfigRevision>) -> DiagnosticCheck {
    let Some(rev) = latest else {
        return not_applicable(
            "config_revision_consistent",
            "Config revision consistent",
            layer::CONTROL_PLANE,
            "no config revisions recorded yet — nothing to apply".into(),
        );
    };
    let (status, suggestion) = match rev.apply_status {
        ApplyStatus::Applied => ("pass", String::new()),
        ApplyStatus::Failed => (
            "fail",
            "the actual network environment does not match the desired config: roll back the failed revision (config-revisions panel) or fix the backend and record a new revision".into(),
        ),
        _ => (
            "warning",
            "the desired config is not confirmed applied yet — apply the revision from the config-revisions panel; until then new devices may receive config no gateway actually has".into(),
        ),
    };
    let state_note = match rev.apply_status {
        ApplyStatus::Applied => format!("applied at {}", rev.applied_at.as_deref().unwrap_or("?")),
        ApplyStatus::Failed => format!(
            "failed: {}",
            rev.error_summary.as_deref().unwrap_or("no error summary")
        ),
        other => other.as_str().to_string(),
    };
    check(
        "config_revision_consistent",
        "Config revision consistent",
        layer::CONTROL_PLANE,
        status,
        format!("latest revision #{} is {state_note}", rev.revision),
        suggestion,
    )
}

/// ⑬ 隧道 MTU（隧道）：计划值 + 设备侧实测证据（§7.5）。计划值来自 server
/// 配置（未显式配置时按 WireGuard 默认 1420 解释黑洞风险）；实测来自 agent
/// 心跳回传的接口 MTU 读数与大包探测（`ping -M do`）。没有设备上报证据时
/// 只评计划——内核里是什么、路径是否承载，控制面不假装知道。
fn check_mtu_planned(tunnel_mtu: Option<u32>, active: &[&Device]) -> DiagnosticCheck {
    if active.is_empty() {
        return not_applicable(
            "mtu_planned",
            "Tunnel MTU planned",
            layer::TUNNEL,
            "no active devices in this network — no tunnel to size".into(),
        );
    }
    let planned = tunnel_mtu.unwrap_or(meshlet_network::DEFAULT_TUNNEL_MTU);
    let planned_note = match tunnel_mtu {
        Some(mtu) => format!("tunnel_mtu = {mtu} is explicitly configured"),
        None => format!(
            "tunnel_mtu is not configured — devices fall back to the WireGuard default {planned}, which blackholes large packets on PPPoE/4G underlays unless the path is verified"
        ),
    };
    let evidence: Vec<(&Device, &DataplaneEvidence)> = active
        .iter()
        .filter_map(|d| d.dataplane_evidence.as_ref().map(|e| (*d, e)))
        .collect();
    if evidence.is_empty() {
        return match tunnel_mtu {
            Some(_) => check(
                "mtu_planned",
                "Tunnel MTU planned",
                layer::TUNNEL,
                "pass",
                format!(
                    "{planned_note} (planned value; WireGuard adds ~80B overhead per packet, keep mtu + overhead <= underlay MTU)"
                ),
                String::new(),
            ),
            None => check(
                "mtu_planned",
                "Tunnel MTU planned",
                layer::TUNNEL,
                "warning",
                planned_note,
                "set tunnel_mtu in the server config for a deliberate value, or verify the path from a device: `ping -M do -s 1392 <overlay-peer-ip>` (1420-28) — failures mean the effective MTU is smaller and packets fragment or vanish (§7.5)".into(),
            ),
        };
    }
    // 设备读数与计划不符 → fail（点名设备与读数；agent 会对漂移重放纠回）。
    let mismatched: Vec<String> = evidence
        .iter()
        .filter(|(_, e)| e.tunnel_mtu.is_some() && e.tunnel_mtu != Some(planned))
        .map(|(d, e)| format!("{} reports interface mtu {}", d.name, e.tunnel_mtu.unwrap()))
        .collect();
    if !mismatched.is_empty() {
        return check(
            "mtu_planned",
            "Tunnel MTU planned",
            layer::TUNNEL,
            "fail",
            format!(
                "{planned_note}, but device readings disagree: {}",
                mismatched.join("; ")
            ),
            "the agent replays the planned MTU on drift — if a reading stays off, check that device's agent is running and reconciling; alternatively adjust tunnel_mtu in the server config and record a new revision".into(),
        );
    }
    // 读数一致但大包探测未证实（失败与未探测同形）→ warning，给出实测命令。
    let unverified: Vec<&str> = evidence
        .iter()
        .filter(|(_, e)| e.mtu_probe_payload.is_none())
        .map(|(d, _)| d.name.as_str())
        .collect();
    if !unverified.is_empty() {
        return check(
            "mtu_planned",
            "Tunnel MTU planned",
            layer::TUNNEL,
            "warning",
            format!(
                "{planned_note}; interface readings match the plan, but no successful large-packet probe was reported by {} — the path may not carry the planned MTU (probe failed) or the probe peer was unreachable",
                unverified.join(", ")
            ),
            format!(
                "verify from a device: `ping -M do -s {} <overlay-peer-ip>` ({planned}-28) — failures mean the effective MTU is smaller and packets fragment or vanish (§7.5)",
                planned - 28
            ),
        );
    }
    let readings: Vec<String> = evidence
        .iter()
        .map(|(d, e)| {
            format!(
                "{} reading {} probe {}",
                d.name,
                e.tunnel_mtu
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into()),
                e.mtu_probe_payload
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into())
            )
        })
        .collect();
    check(
        "mtu_planned",
        "Tunnel MTU planned",
        layer::TUNNEL,
        "pass",
        format!(
            "{planned_note}; device evidence confirms the plan: {} (probe = largest payload carried end-to-end)",
            readings.join("; ")
        ),
        String::new(),
    )
}

fn desired_status(s: DesiredStateStatus) -> &'static str {
    match s {
        DesiredStateStatus::Pending => "pending",
        DesiredStateStatus::Applied => "applied",
        DesiredStateStatus::Failed => "failed",
    }
}

/// 「多久之前」的人类可读时长（用于 detail；解析失败按 unknown，不猜）。
fn ago(ts: &str, now: &str) -> String {
    match (
        chrono::DateTime::parse_from_rfc3339(ts),
        chrono::DateTime::parse_from_rfc3339(now),
    ) {
        (Ok(ts), Ok(now)) => {
            let secs = now.signed_duration_since(ts).num_seconds().max(0);
            if secs < 60 {
                format!("{secs}s")
            } else if secs < 3600 {
                format!("{}m{}s", secs / 60, secs % 60)
            } else {
                format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
            }
        }
        _ => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// 端点
// ---------------------------------------------------------------------------

/// 诊断路由（管理 API：GET 读快照，POST 触发新运行——写请求挂写权限 + CSRF）。
pub fn routes() -> Router<SharedAppState> {
    Router::new().route(
        "/api/v1/networks/{network_id}/diagnostics",
        get(get_diagnostics_handler).post(run_diagnostics_handler),
    )
}

/// `POST /api/v1/networks/{network_id}/diagnostics`：计算 13 项检查，落一行
/// 快照并返回。留审计事件（显式操作者动作，便于事后追溯「谁在何时诊断过」）。
pub async fn run_diagnostics_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
) -> Result<Json<DiagnosticsReport>, ServiceError> {
    let _persist = state.persist.lock().await;
    let now = service::now();
    // alias 行（§12.7 第 10 项的输入）来自 DB（§12.6 服务写路径产生）。
    let aliases = crate::persist::alias_rows(state.auth.pool(), &network_id)
        .await
        .map_err(crate::persist::internal)?;
    let report = {
        let guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        run_checks(&guard, &network_id, &aliases, state.tunnel_mtu, &now)
    };
    let json = serde_json::to_string(&report)
        .map_err(|e| ServiceError::Internal(format!("serialize diagnostics report: {e}")))?;
    crate::persist::insert_diagnostics_run(state.auth.pool(), &network_id, &now, &json)
        .await
        .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "diagnostics.run",
        "network",
        Some(&network_id),
        Some(serde_json::json!({
            "checks": report.checks.len(),
            "fail": report.checks.iter().filter(|c| c.status == "fail").count(),
            "unavailable": report.checks.iter().filter(|c| c.status == "unavailable").count(),
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "run_diagnostics",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(Json(report))
}

/// `GET /api/v1/networks/{network_id}/diagnostics`：最近一次诊断运行。
/// 从未运行过 → 404（消息点名 POST 触发方式）。
pub async fn get_diagnostics_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<DiagnosticsReport>, ServiceError> {
    {
        let guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
    }
    match crate::persist::latest_diagnostics_run(state.auth.pool(), &network_id)
        .await
        .map_err(crate::persist::internal)?
    {
        Some(json) => {
            let report: DiagnosticsReport = serde_json::from_str(&json)
                .map_err(|e| ServiceError::Internal(format!("stored diagnostics report: {e}")))?;
            Ok(Json(report))
        }
        None => Err(ServiceError::DiagnosticsNotRun(format!(
            "no diagnostics run recorded for network {network_id} — trigger one with POST /api/v1/networks/{network_id}/diagnostics"
        ))),
    }
}
