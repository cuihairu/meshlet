//! Heartbeat and publish reporting.

use meshlet_domain::{DataplaneEvidence, DirectEndpointReport, DirectLinkStatus};
use meshlet_network::DevicePlan;

use crate::agent::direct_report::direct_report_from;
use crate::agent::evidence::probe_decision;
use crate::server;

impl super::Agent {
    /// 心跳上报并返回是否送达（失败只记日志，不让数据面循环退避）。
    pub(super) fn report_heartbeat(&self, plan: Option<&DevicePlan>) -> bool {
        match self.heartbeat(plan) {
            Ok(()) => true,
            Err(e) => {
                // 上报失败不影响数据面：计划已按期望对账完毕。
                tracing::warn!(error = %e, "heartbeat not delivered");
                false
            }
        }
    }

    /// 心跳上报（§12.4/§14.1）：带本地读到的最近握手时间 + 数据面实测证据
    /// （§7.5：内核读数 + 计划 MTU 大包探测）+ P2P 直连候选端点（§12）。
    pub fn heartbeat(&self, plan: Option<&DevicePlan>) -> Result<(), String> {
        let evidence = self.collect_evidence(plan);
        let direct = self.direct_report();
        // §12.3：随心跳上报各对端直连链路状态（P2P/中继），供控制台展示。
        // 状态是最近一次 30s 探测的结果——心跳比探测密，上报的是最后已知态。
        let direct_links = self.direct.link_statuses();
        // R-DIAG：随心跳上报本地网络诊断三快照（路由表/接口/wg 读数）。采集
        // 失败按 `None` 上报（服务端与控制台显示"无快照"，证据缺失可见），
        // 绝不吞掉心跳本身。
        let diagnostics = self.backend.diagnostics_sync().ok();
        server::heartbeat(
            &self.server_url,
            &self.token,
            self.last_handshake(),
            Some(evidence),
            direct,
            direct_links,
            diagnostics,
            crate::ssh_sync::local_hostname(),
        )
        .map(|_| ())
        .map_err(|e| format!("heartbeat failed: {e}"))
    }

    /// §12 P2P：本机直连候选端点（WireGuard 监听端口 + RFC1918 局域网地址）。
    /// 未开启直连时返回 `None`（上报省略，服务端按未上报处理）；LAN 枚举
    /// 失败只记空候选，不吞掉心跳本身。
    pub fn direct_report(&self) -> Option<DirectEndpointReport> {
        direct_report_from(
            &self.dataplane.direct_connect,
            self.backend.lan_addresses_sync().unwrap_or_default(),
        )
    }

    /// §12.3：本设备当前各对端直连链路状态（供心跳上报与诊断导出）。
    /// 空 = 全中继（无直连链路）。状态是最近一次 30s 探测的结果。
    pub fn direct_link_statuses(&self) -> Vec<DirectLinkStatus> {
        self.direct.link_statuses()
    }

    /// 数据面实测证据（§7.5）：内核读数 + 大包探测。读数失败按 `None` 上报
    /// （证据缺失可见），绝不臆测默认值——探测失败与未探测在服务端同形，
    /// 都按「未证实」处理。
    pub fn collect_evidence(&self, plan: Option<&DevicePlan>) -> DataplaneEvidence {
        let snapshot = self.backend.inspect_sync().ok();
        DataplaneEvidence {
            tunnel_mtu: snapshot.as_ref().and_then(|s| s.tunnel_mtu),
            // 证据口径不变（布尔），但从规则指纹集合推导：指纹里出现受控 SNAT
            // 动作即「SNAT 规则在场」，比单独枚举 POSTROUTING 链更贴近语义。
            nat_rules_present: snapshot.as_ref().map(|s| !s.nat_rules.is_empty()),
            nat_snat_rules_present: snapshot.as_ref().map(|s| {
                s.nat_rules
                    .iter()
                    .any(|signature| signature.contains("|snat_to_gateway_lan|"))
            }),
            mtu_probe_payload: plan.and_then(|p| {
                // 底层 MTU 只读一次（lane/dataplane-speed）：默认路由接口的
                // MTU 让未钉计划时的探测载荷自适应 jumbo/PPPoE 底层；读不到
                // 回退默认尺寸，不臆测。
                let underlay = self.backend.underlay_path_mtu_sync();
                let (target, payload) = probe_decision(p, underlay)?;
                self.backend
                    .mtu_probe_sync(target, payload)
                    .then_some(payload)
            }),
        }
    }

    /// `wg show <if> latest-handshakes` → 最近握手时刻（ISO-8601）；取不到则
    /// 省略（服务端按「未取到」处理，不虚构在线证据）。
    pub(super) fn last_handshake(&self) -> Option<String> {
        let out = std::process::Command::new("wg")
            .args(["show", &self.dataplane.interface, "latest-handshakes"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let ts: i64 = text
            .split_whitespace()
            .filter_map(|t| t.parse().ok())
            .filter(|t| *t > 0)
            .max()?;
        chrono::DateTime::from_timestamp(ts, 0).map(|d| d.to_rfc3339())
    }
}
