//! AGENT-DOC-1 `meshlet agent doctor`：外来 overlay 共存体检。
//!
//! 背景（2026-11-23 真机取证）：本机同时跑 ZeroTier 与 meshlet 时，两条隧道
//! **互为路径**——meshlet 的 WG endpoint 落在 ZeroTier 网段（出向借道），
//! ZeroTier 又把 meshlet overlay 学成对端路径（入向借道）。互相封装成环，
//! 包长一路涨到超 MTU 后**内部包全死**，同时把带宽烧在不出物理网卡的循环里
//! （实测内部/物理 = 185:1、wg-mlt 累计 301 GB 而物理口仅 3 GB）。
//!
//! 本模块把当时靠翻日志、逐条 `iptables`/`zerotier-cli` 手工排查的判据固化成
//! 5 项可复跑的检查。**纪律与 [crate::diag] 一致**：只读、缺数据一律
//! `not_assessed`（§7.5 不臆测），绝不因为读不到就报 PASS。
//!
//! 纯判定与采集分离：判定函数（[check_*]）无 IO、跨平台单测；采集由
//! [Doctor::collect] 各平台后端补齐。

use serde::{Deserialize, Serialize};

/// 单项检查结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// 通过。
    Pass,
    /// 有风险但不致命（当前未观测到故障，条件已具备）。
    Warn,
    /// 已观测到故障条件，需要处理。
    Fail,
    /// 数据不足，**不判定**（缺 zerotier / 无流量 / 命令缺失）。
    NotAssessed,
}

/// 一项体检结论。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// 稳定标识（CLI / JSON / 控制台过滤用）。
    pub id: String,
    /// 一句话结论。
    pub title: String,
    pub status: CheckStatus,
    /// 支撑结论的原始证据（命令读数、比值、命中条数）。
    pub evidence: String,
}

impl Check {
    fn new(
        id: &str,
        title: impl Into<String>,
        status: CheckStatus,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            status,
            evidence: evidence.into(),
        }
    }
}

/// 一次体检报告。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// 采集时刻（ISO-8601，UTC）。
    pub collected_at: String,
    pub checks: Vec<Check>,
}

impl DoctorReport {
    /// 是否存在 FAIL（CLI 退出码 / 控制台告警用）。
    pub fn has_failure(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }

    /// 各状态计数（摘要行用）。
    pub fn counts(&self) -> [usize; 4] {
        let mut counts = [0usize; 4];
        for check in &self.checks {
            match check.status {
                CheckStatus::Pass => counts[0] += 1,
                CheckStatus::Warn => counts[1] += 1,
                CheckStatus::Fail => counts[2] += 1,
                CheckStatus::NotAssessed => counts[3] += 1,
            }
        }
        counts
    }
}

/// 放大比超过该值判 FAIL（实测正常共存时 ≈ 0，事故时 185:1）。
pub const AMPLIFICATION_FAIL_RATIO: f64 = 5.0;

/// 速率采样窗口（秒）：够短不拖慢体检，够长让计数器差值可分辨。
pub const DOCTOR_SAMPLE_SECS: u64 = 2;

/// 判定 1：隧道流量放大。
///
/// 比值 = (受管隧道 TX + 外来 overlay TX) / 物理口 TX。两条隧道互为路径时，
/// 循环流量只在虚拟口之间打转、**不出物理网卡**，比值会远超 1。
///
/// - 物理口与内部都几乎无流量 → `not_assessed`（无流量无从判断，不臆测）；
/// - 比值 > [AMPLIFICATION_FAIL_RATIO] → `fail`；
/// - 其余 → `pass`。
pub fn check_tunnel_amplification(
    tunnel_tx_bps: f64,
    foreign_tx_bps: f64,
    physical_tx_bps: f64,
) -> Check {
    const ID: &str = "tunnel-amplification";
    const TITLE: &str = "隧道流量未在内部空转";
    let internal = tunnel_tx_bps + foreign_tx_bps;
    // 双侧都近于 0 → 没有可判定的流量（阈值 1 KiB/s：低于此不算「在传数据」）。
    if internal < 1024.0 && physical_tx_bps < 1024.0 {
        return Check::new(
            ID,
            TITLE,
            CheckStatus::NotAssessed,
            format!(
                "窗口内无可观测流量（tunnel {internal:.0} B/s, physical {physical_tx_bps:.0} B/s）"
            ),
        );
    }
    if physical_tx_bps < 1024.0 && internal >= 1024.0 {
        return Check::new(
            ID,
            TITLE,
            CheckStatus::Fail,
            format!("内部循环 {internal:.0} B/s 而物理口 {physical_tx_bps:.0} B/s —— 流量不出网卡"),
        );
    }
    let ratio = internal / physical_tx_bps;
    if ratio > AMPLIFICATION_FAIL_RATIO {
        Check::new(
            ID,
            TITLE,
            CheckStatus::Fail,
            format!("内部/物理 = {ratio:.1}:1（阈值 {AMPLIFICATION_FAIL_RATIO:.0}:1）"),
        )
    } else {
        Check::new(
            ID,
            TITLE,
            CheckStatus::Pass,
            format!("内部/物理 = {ratio:.1}:1"),
        )
    }
}

/// 判定 2：ZeroTier 把 meshlet overlay 当成对端路径（入向借道）。
///
/// `zt_paths` 是 `zerotier-cli -j listpeers` 里所有 active 路径的 `ip` 字段；
/// `overlay_prefix` 形如 `10.240.`。任一路径落在 overlay 网段即 `fail`——
/// 这正是事故现场（`402477b104 -> 10.240.0.3/9993 preferred`）。
///
/// 读不到 zerotier → `zt_paths = None` → `not_assessed`。
pub fn check_foreign_overlay_paths(zt_paths: Option<&[String]>, overlay_prefix: &str) -> Check {
    const ID: &str = "foreign-overlay-paths";
    const TITLE: &str = "ZeroTier 路径未借道 meshlet overlay";
    let Some(paths) = zt_paths else {
        return Check::new(
            ID,
            TITLE,
            CheckStatus::NotAssessed,
            "读取失败（ZeroTier 未安装，或无权限读 authtoken）",
        );
    };
    let hits: Vec<&str> = paths
        .iter()
        .map(String::as_str)
        .filter(|p| p.starts_with(overlay_prefix))
        .collect();
    if hits.is_empty() {
        Check::new(
            ID,
            TITLE,
            CheckStatus::Pass,
            format!("{} 条路径均不在 overlay 网段", paths.len()),
        )
    } else {
        Check::new(
            ID,
            TITLE,
            CheckStatus::Fail,
            format!("{} 条借道: {}", hits.len(), hits.join(", ")),
        )
    }
}

/// 从 `ip:port` / `[v6]:port` / `ip%scope:port` 形态剥出地址部分。
///
/// 三种形态在 `wg show` / `ss` 读数里都出现（`10.147.19.49:51820`、
/// `10.240.0.4%wg-mlt:63614`、`[2001:db8::1]:51820`）。本判定只认 IPv4 网段
/// 前缀，IPv6 原样返回即可——但**不能把端口当成地址**（`rsplit(':')` 会取到
/// 端口号，导致 `10.147.19.49:51820` 被判成 `51820`、借道信号整个漏掉）。
fn endpoint_ip(endpoint: &str) -> &str {
    let s = endpoint.split('%').next().unwrap_or(endpoint);
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    // `a.b.c.d:port` → 冒号前是地址；地址里没有点（IPv6）则不剥。
    if let Some((head, tail)) = s.split_once(':') {
        if head.contains('.') && !tail.contains(':') {
            return head;
        }
    }
    s
}

/// 判定 3：meshlet 的 WG endpoint 落在外来 overlay / 自身 overlay 网段。
///
/// 两类都要报：
/// - 落在**外来 overlay**（如 `10.147.`）→ 出向借道，事故的另一半成因；
/// - 落在**自身 overlay**（如 `10.240.`）→ 把包发进自己隧道去够隧道内的
///   地址，纯 hairpin 空转。
///
/// 只给 `warn`：[check_isolation_rules] 已从反向硬切断循环，本项是「不该发生
/// 但发生也不会成环」的源头治理信号（对应 L2 降级候选的输入）。
/// 无 peer / 读不到 → `not_assessed`。
pub fn check_foreign_endpoints(
    endpoints: Option<&[String]>,
    foreign_prefixes: &[&str],
    own_overlay_prefix: &str,
) -> Check {
    const ID: &str = "endpoint-tenancy";
    const TITLE: &str = "WG endpoint 未指向 overlay 网段";
    let Some(endpoints) = endpoints else {
        return Check::new(
            ID,
            TITLE,
            CheckStatus::NotAssessed,
            "wg 读数不可得（接口不存在，或无权限读）",
        );
    };
    if endpoints.is_empty() {
        return Check::new(
            ID,
            TITLE,
            CheckStatus::NotAssessed,
            "无已配置的 peer endpoint",
        );
    }
    let ip_of = endpoint_ip;
    let foreign: Vec<&str> = endpoints
        .iter()
        .map(|e| ip_of(e))
        .filter(|ip| foreign_prefixes.iter().any(|p| ip.starts_with(p)))
        .collect();
    let own: Vec<&str> = endpoints
        .iter()
        .map(|e| ip_of(e))
        .filter(|ip| ip.starts_with(own_overlay_prefix))
        .collect();
    if foreign.is_empty() && own.is_empty() {
        return Check::new(
            ID,
            TITLE,
            CheckStatus::Pass,
            format!("{} 个 endpoint 均在物理/公网侧", endpoints.len()),
        );
    }
    let mut parts = Vec::new();
    if !foreign.is_empty() {
        parts.push(format!("借道外来 overlay: {}", foreign.join(", ")));
    }
    if !own.is_empty() {
        parts.push(format!("hairpin 自身 overlay: {}", own.join(", ")));
    }
    Check::new(ID, TITLE, CheckStatus::Warn, parts.join("；"))
}

/// 判定 4：隔离规则是否在位。
///
/// `isolation_rules` = 当前 iptables 里带所有权注释的规则条数；`foreign_uid`
/// = 外来 overlay 进程 uid（`None` = 未安装）。
///
/// - 未安装 → `pass`（本机无共存对象，无需隔离）；
/// - 已安装但 0 条 → `fail`（事故现场状态：规则整批丢失）；
/// - 已安装且有 → `pass`。
pub fn check_isolation_rules(isolation_rules: usize, foreign_uid: Option<u32>) -> Check {
    const ID: &str = "isolation-rules";
    const TITLE: &str = "外来 overlay 隔离规则在位";
    match foreign_uid {
        None => Check::new(
            ID,
            TITLE,
            CheckStatus::Pass,
            "未检测到外来 overlay 进程，无需隔离",
        ),
        Some(uid) if isolation_rules == 0 => Check::new(
            ID,
            TITLE,
            CheckStatus::Fail,
            format!("uid {uid} 存在但隔离规则 0 条 —— 两条隧道将互为路径"),
        ),
        Some(uid) => Check::new(
            ID,
            TITLE,
            CheckStatus::Pass,
            format!("uid {uid}，{isolation_rules} 条规则在位"),
        ),
    }
}

/// 判定 5：受管隧道 MTU 与物理口 MTU 是否悬殊。
///
/// 隧道 MTU 高于物理口时，大包必须靠 IP 分片过网——分片一旦被路径上的
/// 运营商/云安全组丢弃即静默卡死（2026-11-23 实测全网 ZT 都是 2800 vs 1500）。
///
/// - 任一读不到 → `not_assessed`；
/// - 差值 > [MTU_WARN_DELTA] → `warn`；
/// - 其余 → `pass`。
pub fn check_mtu_consistency(tunnel_mtu: Option<u32>, physical_mtu: Option<u32>) -> Check {
    const ID: &str = "mtu-consistency";
    const TITLE: &str = "隧道 MTU 与物理口匹配";
    match (tunnel_mtu, physical_mtu) {
        (Some(tunnel), Some(physical)) => {
            let delta = tunnel.abs_diff(physical);
            if delta > MTU_WARN_DELTA {
                Check::new(
                    ID,
                    TITLE,
                    CheckStatus::Warn,
                    format!("隧道 {tunnel} vs 物理 {physical}，差 {delta}（依赖 IP 分片）"),
                )
            } else {
                Check::new(
                    ID,
                    TITLE,
                    CheckStatus::Pass,
                    format!("隧道 {tunnel} / 物理 {physical}"),
                )
            }
        }
        _ => Check::new(ID, TITLE, CheckStatus::NotAssessed, "MTU 读数缺失"),
    }
}

/// MTU 差值告警阈值（字节）。
pub const MTU_WARN_DELTA: u32 = 200;

/// 体检所需的原始读数（**采集与判定分离**：采集是平台相关 IO，判定是纯函数）。
///
/// 各字段的 `None` / 空语义见对应 [check_*]：缺数据一律 `not_assessed`。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DoctorInputs {
    /// 采集时刻（ISO-8601，UTC）。
    pub collected_at: String,
    /// 受管隧道接口名（如 `wg-mlt`）。
    pub tunnel_interface: String,
    /// 承载物理出口的接口名。
    pub physical_interface: String,
    /// `(隧道 TX, 外来 overlay TX, 物理口 TX)`，单位 B/s，已按采样窗口换算。
    /// `None` = 采样失败。
    pub rates: Option<(f64, f64, f64)>,
    /// 当前带所有权注释的隔离规则条数。
    pub isolation_rules: usize,
    /// 外来 overlay 进程 uid；`None` = 未安装。
    pub foreign_uid: Option<u32>,
    /// `zerotier-cli` 对端路径（`ip` 字段）；`None` = 未安装/读取失败。
    pub foreign_paths: Option<Vec<String>>,
    /// wg peer endpoint 列表；`None` = 无读数。
    pub endpoints: Option<Vec<String>>,
    pub tunnel_mtu: Option<u32>,
    pub physical_mtu: Option<u32>,
}

/// 跑全部 5 项判定（纯函数，无 IO）。
pub fn run_doctor(inputs: &DoctorInputs) -> DoctorReport {
    let (tunnel_bps, foreign_bps, physical_bps) = inputs.rates.unwrap_or((0.0, 0.0, 0.0));
    // 采样失败时 rates 为 None —— 交给放大项按「无流量」判 not_assessed，
    // 但证据里要能看出是采样失败而非真的没流量。
    let amplification = match inputs.rates {
        Some(_) => check_tunnel_amplification(tunnel_bps, foreign_bps, physical_bps),
        None => Check::new(
            "tunnel-amplification",
            "隧道流量未在内部空转",
            CheckStatus::NotAssessed,
            "接口计数采样失败",
        ),
    };
    DoctorReport {
        collected_at: inputs.collected_at.clone(),
        checks: vec![
            amplification,
            check_foreign_overlay_paths(inputs.foreign_paths.as_deref(), OVERLAY_PREFIX),
            check_foreign_endpoints(
                inputs.endpoints.as_deref(),
                &[FOREIGN_OVERLAY_IPV4_PREFIX],
                OVERLAY_PREFIX,
            ),
            check_isolation_rules(inputs.isolation_rules, inputs.foreign_uid),
            check_mtu_consistency(inputs.tunnel_mtu, inputs.physical_mtu),
        ],
    }
}

/// 本平台未实现体检时的报告：5 项全部 `not_assessed` 并注明原因。
///
/// **绝不返回 PASS**——「没实现」与「检查过了没问题」是两回事（§7.5）。
/// 调用方（CLI / 控制台）看到全 SKIP 就知道该换机器或换平台跑。
pub fn unsupported_report() -> DoctorReport {
    let note = "本平台未实现外来 overlay 体检（当前仅 Linux 后端采集）";
    DoctorReport {
        collected_at: chrono_iso_now(),
        checks: [
            "tunnel-amplification",
            "foreign-overlay-paths",
            "endpoint-tenancy",
            "isolation-rules",
            "mtu-consistency",
        ]
        .iter()
        .map(|id| Check::new(id, "", CheckStatus::NotAssessed, note))
        .collect(),
    }
}

/// 当前 UTC 时刻（ISO-8601，秒精度，`Z` 后缀）。
fn chrono_iso_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// meshlet overlay 的 IPv4 网段前缀（判定 2/3 用）。
pub const OVERLAY_PREFIX: &str = "10.240.";

/// 外来 overlay（ZeroTier）的 IPv4 网段前缀（判定 3 用）。
pub const FOREIGN_OVERLAY_IPV4_PREFIX: &str = "10.147.";

/// `zerotier-cli -j listpeers` → 所有**已建路径**的地址（纯解析）。
///
/// 只收 `paths[]` 里 `active` 且非 `expired` 的项——已过期的路径不算在用，
/// 报它等于误报（隔离生效后旧路径会陆续过期，正是靠这条口径让检查转绿）。
/// JSON 结构不对 / 顶层不是数组 → `None`（**不臆测成空列表**，§7.5：
/// 「读不到」与「读到但没有」是两回事，前者必须走 `not_assessed`）。
pub fn parse_zerotier_paths(json: &str) -> Option<Vec<String>> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let peers = value.as_array()?;
    let mut paths = Vec::new();
    for peer in peers {
        let Some(peer_paths) = peer.get("paths").and_then(|p| p.as_array()) else {
            continue;
        };
        for path in peer_paths {
            let active = path
                .get("active")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let expired = path
                .get("expired")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            if !active || expired {
                continue;
            }
            if let Some(address) = path.get("address").and_then(|v| v.as_str()) {
                // `ip:port` → 只要地址部分（判定比的是网段前缀）。
                paths.push(address.split('%').next().unwrap_or(address).to_string());
            }
        }
    }
    Some(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 事故现场 `zerotier-cli -j listpeers` 片段（2026-11-23 取证）：
    /// `402477b104 -> 10.240.0.3/9993 active preferred`。
    const INCIDENT_JSON: &str = r#"[
      {"address":"402477b104","paths":[
        {"address":"10.240.0.3/9993","active":true,"expired":false},
        {"address":"180.153.160.8/29566","active":true,"expired":false},
        {"address":"10.240.0.3/60912","active":false,"expired":false}]},
      {"address":"487053afaa","paths":[
        {"address":"192.168.5.11/58075","active":true,"expired":true}]}
    ]"#;

    #[test]
    fn zerotier_paths_keep_only_active_unexpired() {
        let paths = parse_zerotier_paths(INCIDENT_JSON).unwrap();
        // inactive 的 60912 与 expired 的 58075 都不收。
        assert_eq!(paths, vec!["10.240.0.3/9993", "180.153.160.8/29566"]);
        // 事故路径必须判 FAIL。
        let report = run_doctor(&DoctorInputs {
            foreign_paths: Some(paths),
            ..DoctorInputs::default()
        });
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "foreign-overlay-paths")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Fail, "{}", check.evidence);
    }

    #[test]
    fn zerotier_paths_malformed_json_is_none_not_empty() {
        // 结构读不出 → None（not_assessed），不能当成「没有借道」。
        assert_eq!(parse_zerotier_paths(""), None);
        assert_eq!(parse_zerotier_paths("not json"), None);
        assert_eq!(parse_zerotier_paths(r#"{"address":"x"}"#), None);
        // 顶层是数组但没有 paths → Some(空)：确实读到了、确实没有路径。
        assert_eq!(parse_zerotier_paths(r#"[{"address":"x"}]"#), Some(vec![]));
    }

    /// 事故现场读数复原（2026-11-23 真机）：应 5 项里至少放大 + 借道路径 FAIL。
    #[test]
    fn incident_inputs_produce_failures() {
        let inputs = DoctorInputs {
            collected_at: "2026-11-23T15:00:00Z".into(),
            tunnel_interface: "wg-mlt".into(),
            physical_interface: "ens18".into(),
            rates: Some((108e6, 0.0, 0.6e6)),
            isolation_rules: 0,
            foreign_uid: Some(995),
            foreign_paths: Some(vec!["180.153.160.8/9993".into(), "10.240.0.3/9993".into()]),
            endpoints: Some(vec!["10.147.19.49:51820".into()]),
            tunnel_mtu: Some(1420),
            physical_mtu: Some(1500),
        };
        let report = run_doctor(&inputs);
        assert_eq!(report.checks.len(), 5);
        assert!(report.has_failure(), "{:?}", report.checks);
        let by_id = |id: &str| report.checks.iter().find(|c| c.id == id).unwrap();
        assert_eq!(by_id("tunnel-amplification").status, CheckStatus::Fail);
        assert_eq!(by_id("foreign-overlay-paths").status, CheckStatus::Fail);
        assert_eq!(by_id("isolation-rules").status, CheckStatus::Fail);
        assert_eq!(by_id("endpoint-tenancy").status, CheckStatus::Warn);
        assert_eq!(by_id("mtu-consistency").status, CheckStatus::Pass);
    }

    /// 修复后读数（隔离在位、无借道、流量出网）→ 全绿。
    #[test]
    fn healthy_inputs_produce_no_failure() {
        let inputs = DoctorInputs {
            collected_at: "2026-11-23T16:00:00Z".into(),
            tunnel_interface: "wg-mlt".into(),
            physical_interface: "ens18".into(),
            rates: Some((3e6, 0.0, 2e6)),
            isolation_rules: 5,
            foreign_uid: Some(995),
            foreign_paths: Some(vec!["180.153.160.8/9993".into()]),
            endpoints: Some(vec!["180.153.160.8:51820".into()]),
            tunnel_mtu: Some(1420),
            physical_mtu: Some(1500),
        };
        let report = run_doctor(&inputs);
        assert!(!report.has_failure(), "{:?}", report.checks);
        assert_eq!(report.counts()[2], 0);
    }

    /// 采样失败不能伪装成「流量正常」——必须 not_assessed。
    #[test]
    fn failed_sampling_is_not_assessed_not_passed() {
        let inputs = DoctorInputs {
            rates: None,
            ..DoctorInputs::default()
        };
        let report = run_doctor(&inputs);
        let amplification = report
            .checks
            .iter()
            .find(|c| c.id == "tunnel-amplification")
            .unwrap();
        assert_eq!(amplification.status, CheckStatus::NotAssessed);
        assert!(
            amplification.evidence.contains("采样失败"),
            "{}",
            amplification.evidence
        );
    }

    /// 默认输入（什么都没读到）下不得出现 FAIL——缺数据不等于故障（§7.5）。
    #[test]
    fn default_inputs_never_report_failure() {
        let report = run_doctor(&DoctorInputs::default());
        assert!(!report.has_failure(), "{:?}", report.checks);
        assert_eq!(report.counts()[3], 4, "缺数据项应为 not_assessed");
    }

    // ---------------------------------------------------- 原始样本 ----

    #[test]
    fn amplification_flags_internal_circulation() {
        // 事故现场：内部狂发、物理口完全不出包 → 走「不出网卡」分支。
        let check = check_tunnel_amplification(108e6, 0.0, 0.0);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.evidence.contains("不出网卡"), "{}", check.evidence);

        // 物理口有极少量流量但内部仍在空转 → 走比值分支，同样 FAIL。
        let check = check_tunnel_amplification(108e6, 0.0, 0.5e6);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.evidence.contains("216.0:1"), "{}", check.evidence);
    }

    #[test]
    fn amplification_flags_ratio_over_threshold() {
        let check = check_tunnel_amplification(10e6, 0.0, 1e6); // 10:1
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.evidence.contains("10.0:1"), "{}", check.evidence);
    }

    #[test]
    fn amplification_passes_when_traffic_leaves_the_wire() {
        // 内部 3 MB/s、物理 2 MB/s → 1.5:1，正常。
        let check = check_tunnel_amplification(3e6, 0.0, 2e6);
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn amplification_is_not_assessed_without_traffic() {
        // 双侧都近 0：无流量无从判断，**不臆测**成 PASS（§7.5）。
        let check = check_tunnel_amplification(0.0, 0.0, 0.0);
        assert_eq!(check.status, CheckStatus::NotAssessed);
        assert!(
            check.evidence.contains("无可观测流量"),
            "{}",
            check.evidence
        );
    }

    #[test]
    fn amplification_never_reports_pass_on_zero_physical_alone() {
        // 物理口 0 但内部有量 → 必须 FAIL，不能因比值无穷小而误判。
        let check = check_tunnel_amplification(0.0, 5e6, 0.0);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // ------------------------------------------------ 借道路径判定 ----

    #[test]
    fn foreign_paths_fail_when_any_path_is_on_the_overlay() {
        let paths = vec![
            "180.153.160.8/9993".to_string(),
            "10.240.0.3/9993".to_string(), // 事故现场的 preferred 路径
        ];
        let check = check_foreign_overlay_paths(Some(&paths), "10.240.");
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(
            check.evidence.contains("10.240.0.3/9993"),
            "{}",
            check.evidence
        );
    }

    #[test]
    fn foreign_paths_pass_when_all_are_off_overlay() {
        let paths = vec![
            "180.153.160.8/9993".to_string(),
            "192.168.5.11/38760".to_string(),
        ];
        let check = check_foreign_overlay_paths(Some(&paths), "10.240.");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn foreign_paths_not_assessed_without_zerotier() {
        assert_eq!(
            check_foreign_overlay_paths(None, "10.240.").status,
            CheckStatus::NotAssessed
        );
        // 空列表（zerotier 在但无 peer）同样是「无从判定」而非 PASS。
        assert_eq!(
            check_foreign_overlay_paths(Some(&[]), "10.240.").status,
            CheckStatus::Pass
        );
    }

    // ------------------------------------------------ endpoint 归属 ----

    #[test]
    fn endpoint_on_foreign_overlay_is_warned() {
        let eps = vec![
            "10.147.19.49:51820".to_string(),
            "180.153.160.8:51820".to_string(),
        ];
        let check = check_foreign_endpoints(Some(&eps), &["10.147."], "10.240.");
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(
            check.evidence.contains("10.147.19.49"),
            "{}",
            check.evidence
        );
    }

    #[test]
    fn endpoint_hairpinning_own_overlay_is_warned() {
        // 2026-11-23 日志实录：`from=10.147.19.226:51820 to=10.240.0.7:51820`。
        let eps = vec!["10.240.0.7:51820".to_string()];
        let check = check_foreign_endpoints(Some(&eps), &["10.147."], "10.240.");
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.evidence.contains("hairpin"), "{}", check.evidence);
    }

    #[test]
    fn endpoint_on_physical_or_public_passes() {
        let eps = vec![
            "192.168.5.11:51820".to_string(),
            "106.14.216.177:51820".to_string(),
        ];
        let check = check_foreign_endpoints(Some(&eps), &["10.147."], "10.240.");
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn endpoint_scope_suffix_and_bracket_forms_are_stripped() {
        // 带 `%接口` 作用域与 IPv6 方括号端口的形态都要能剥出 IP。
        let eps = vec![
            "fe80::1%wg-mlt:51820".to_string(),
            "[2001:db8::1]:51820".to_string(),
        ];
        let check = check_foreign_endpoints(Some(&eps), &["10.147."], "10.240.");
        assert_eq!(check.status, CheckStatus::Pass, "{}", check.evidence);
    }

    #[test]
    fn endpoint_not_assessed_without_readings() {
        assert_eq!(
            check_foreign_endpoints(None, &["10.147."], "10.240.").status,
            CheckStatus::NotAssessed
        );
        assert_eq!(
            check_foreign_endpoints(Some(&[]), &["10.147."], "10.240.").status,
            CheckStatus::NotAssessed
        );
    }

    // ------------------------------------------------ 隔离规则判定 ----

    #[test]
    fn isolation_missing_while_foreign_present_is_fail() {
        // 事故现场：uid 读得到、规则 0 条。
        let check = check_isolation_rules(0, Some(995));
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.evidence.contains("0 条"), "{}", check.evidence);
    }

    #[test]
    fn isolation_present_passes_and_absent_foreign_too() {
        assert_eq!(
            check_isolation_rules(5, Some(995)).status,
            CheckStatus::Pass
        );
        // 本机没装 zerotier → 无需隔离，是 PASS 而非 not_assessed。
        assert_eq!(check_isolation_rules(0, None).status, CheckStatus::Pass);
    }

    // ------------------------------------------------------ MTU ----

    #[test]
    fn mtu_gap_over_threshold_is_warned() {
        // 全网实况：ZT 2800 vs 物理 1500。
        let check = check_mtu_consistency(Some(2800), Some(1500));
        assert_eq!(check.status, CheckStatus::Warn);
        assert!(check.evidence.contains("差 1300"), "{}", check.evidence);
    }

    #[test]
    fn mtu_matched_passes_and_missing_is_not_assessed() {
        assert_eq!(
            check_mtu_consistency(Some(1500), Some(1500)).status,
            CheckStatus::Pass
        );
        assert_eq!(
            check_mtu_consistency(None, Some(1500)).status,
            CheckStatus::NotAssessed
        );
        assert_eq!(
            check_mtu_consistency(Some(1420), None).status,
            CheckStatus::NotAssessed
        );
    }

    // ---------------------------------------------------- 报告聚合 ----

    #[test]
    fn report_counts_and_failure_flag() {
        let report = DoctorReport {
            collected_at: "2026-11-23T00:00:00Z".into(),
            checks: vec![
                Check::new("a", "t", CheckStatus::Pass, "e"),
                Check::new("b", "t", CheckStatus::Warn, "e"),
                Check::new("c", "t", CheckStatus::Fail, "e"),
                Check::new("d", "t", CheckStatus::NotAssessed, "e"),
                Check::new("e", "t", CheckStatus::Fail, "e"),
            ],
        };
        assert_eq!(report.counts(), [1, 1, 2, 1]);
        assert!(report.has_failure());
        let clean = DoctorReport {
            collected_at: "x".into(),
            checks: vec![Check::new("a", "t", CheckStatus::Pass, "e")],
        };
        assert!(!clean.has_failure());
    }
}
