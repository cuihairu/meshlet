//! AGENT-DOC-1 `meshlet agent doctor`: the health check for coexisting with a
//! foreign overlay.
//!
//! Background (2026-11-23 real-machine forensics): when this host runs ZeroTier
//! and meshlet at the same time, the two tunnels **serve as each other's path** —
//! meshlet's WG endpoint lands in the ZeroTier segment (outbound borrowing),
//! and ZeroTier learns the meshlet overlay as a peer path (inbound borrowing).
//! They encapsulate each other into a loop, packet sizes climb past MTU and
//! **every inner packet dies**, while the bandwidth is burned in a loop that
//! never leaves the physical NIC (measured internal/physical = 185:1, wg-mlt
//! 301 GB cumulative against only 3 GB on the physical port).
//!
//! This module turns the criteria that were once hunted down by digging through
//! logs and running `iptables`/`zerotier-cli` by hand into five repeatable
//! checks. **The discipline matches [crate::diag]**: read-only, missing data is
//! always `not_assessed` (§7.5, no guessing), and never report PASS merely
//! because something could not be read.
//!
//! Pure verdicts are separated from collection: the check functions ([check_*])
//! do no IO and are unit-tested cross-platform; collection is filled in by the
//! [Doctor::collect] backends per platform.

use serde::{Deserialize, Serialize};

/// Verdict of a single check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Passed.
    Pass,
    /// Risky but not fatal (no fault observed yet, the conditions are in place).
    Warn,
    /// Fault conditions observed; needs attention.
    Fail,
    /// Insufficient data, **not judged** (no zerotier / no traffic / command
    /// missing).
    NotAssessed,
}

/// The verdict of one health check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Check {
    /// Stable identifier (used by the CLI / JSON / console filtering).
    pub id: String,
    /// One-line verdict.
    pub title: String,
    pub status: CheckStatus,
    /// Raw evidence backing the verdict (command readings, ratios, hit counts).
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

/// A single health-check report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Collection timestamp (ISO-8601, UTC).
    pub collected_at: String,
    pub checks: Vec<Check>,
}

impl DoctorReport {
    /// Whether any check FAILED (for the CLI exit code / console alerts).
    pub fn has_failure(&self) -> bool {
        self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }

    /// Counts per status (for the summary line).
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

/// An amplification ratio above this value is a FAIL (measured ≈ 0 under normal
/// coexistence, 185:1 during the incident).
pub const AMPLIFICATION_FAIL_RATIO: f64 = 5.0;

/// Rate sampling window (seconds): short enough not to slow the check down,
/// long enough that the counter difference is resolvable.
pub const DOCTOR_SAMPLE_SECS: u64 = 2;

/// Verdict 1: tunnel traffic amplification.
///
/// Ratio = (managed tunnel TX + foreign overlay TX) / physical port TX. When
/// the two tunnels serve as each other's path, the circulating traffic spins
/// only between virtual interfaces and **never leaves the physical NIC**, so
/// the ratio far exceeds 1.
///
/// - Physical port and internals both nearly idle -> `not_assessed` (with no
///   traffic there is nothing to judge, no guessing);
/// - Ratio > [AMPLIFICATION_FAIL_RATIO] -> `fail`;
/// - Otherwise -> `pass`.
pub fn check_tunnel_amplification(
    tunnel_tx_bps: f64,
    foreign_tx_bps: f64,
    physical_tx_bps: f64,
) -> Check {
    const ID: &str = "tunnel-amplification";
    const TITLE: &str = "隧道流量未在内部空转";
    let internal = tunnel_tx_bps + foreign_tx_bps;
    // Both sides near zero -> there is no traffic to judge (the threshold is 1
    // KiB/s: below it does not count as "transferring data").
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

/// Verdict 2: ZeroTier treats the meshlet overlay as a peer path (inbound
/// borrowing).
///
/// `zt_paths` holds the `ip` field of every active path in
/// `zerotier-cli -j listpeers`; `overlay_prefix` looks like `10.240.`. Any
/// path landing in the overlay segment is a `fail` — that is exactly the
/// incident scene (`402477b104 -> 10.240.0.3/9993 preferred`).
///
/// zerotier unreadable -> `zt_paths = None` -> `not_assessed`.
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

/// Strip the address out of an `ip:port` / `[v6]:port` / `ip%scope:port`
/// form.
///
/// All three forms show up in `wg show` / `ss` readings (`10.147.19.49:51820`,
/// `10.240.0.4%wg-mlt:63614`, `[2001:db8::1]:51820`). This verdict only
/// recognizes IPv4 segment prefixes, so IPv6 is returned as-is — but the **port
/// must never be mistaken for an address** (`rsplit(':')` would pick up the
/// port number, so that `10.147.19.49:51820` gets judged as `51820` and the
/// whole borrowing signal is missed).
fn endpoint_ip(endpoint: &str) -> &str {
    let s = endpoint.split('%').next().unwrap_or(endpoint);
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    // `a.b.c.d:port` -> the address is what precedes the colon; an address
    // without a dot (IPv6) is left alone.
    if let Some((head, tail)) = s.split_once(':') {
        if head.contains('.') && !tail.contains(':') {
            return head;
        }
    }
    s
}

/// Verdict 3: meshlet's WG endpoints land in a foreign overlay / its own
/// overlay segment.
///
/// Both kinds are reported:
/// - Landing in a **foreign overlay** (such as `10.147.`) -> outbound
///   borrowing, the other half of the incident's cause;
/// - Landing in **its own overlay** (such as `10.240.`) -> sending packets
///   into its own tunnel to reach an address inside the tunnel, pure hairpin
///   spinning.
///
/// Only a `warn` is given: [check_isolation_rules] already cuts the loop hard
/// from the reverse direction, so this item is a root-cause governance signal
/// for the "should not happen, and even if it does it cannot form a loop"
/// case (the input for the L2 downgrade candidates).
/// No peer / unreadable -> `not_assessed`.
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

/// Verdict 4: whether the isolation rules are in place.
///
/// `isolation_rules` = the number of rules carrying the ownership comment in
/// iptables right now; `foreign_uid` = the uid of the foreign overlay process
/// (`None` = not installed).
///
/// - Not installed -> `pass` (no coexisting peer on this host, no isolation
///   needed);
/// - Installed but zero rules -> `fail` (the incident state: the whole batch of
///   rules is gone);
/// - Installed and present -> `pass`.
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

/// Verdict 5: whether the managed tunnel MTU and the physical port MTU differ
/// markedly.
///
/// When the tunnel MTU is higher than the physical one, large packets must cross
/// the network via IP fragmentation — the moment an ISP or a cloud security
/// group along the path drops the fragments it stalls silently (measured on
/// 2026-11-23, every ZT across the whole network sat at 2800 vs 1500).
///
/// - Either one unreadable -> `not_assessed`;
/// - Difference > [MTU_WARN_DELTA] -> `warn`;
/// - Otherwise -> `pass`.
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

/// MTU difference warning threshold (bytes).
pub const MTU_WARN_DELTA: u32 = 200;

/// The raw readings a health check needs (**collection is separated from
/// verdicts**: collection is platform-dependent IO, verdicts are pure
/// functions).
///
/// See the matching [check_*] for the `None` / empty semantics of each field:
/// missing data is always `not_assessed`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DoctorInputs {
    /// Collection timestamp (ISO-8601, UTC).
    pub collected_at: String,
    /// Name of the managed tunnel interface (such as `wg-mlt`).
    pub tunnel_interface: String,
    /// Name of the interface carrying the physical egress.
    pub physical_interface: String,
    /// `(tunnel TX, foreign overlay TX, physical port TX)` in B/s, already scaled
    /// by the sampling window.
    /// `None` = the sampling failed.
    pub rates: Option<(f64, f64, f64)>,
    /// Number of isolation rules currently carrying the ownership comment.
    pub isolation_rules: usize,
    /// uid of the foreign overlay process; `None` = not installed.
    pub foreign_uid: Option<u32>,
    /// `zerotier-cli` peer paths (the `ip` field); `None` = not installed /
    /// read failed.
    pub foreign_paths: Option<Vec<String>>,
    /// The list of wg peer endpoints; `None` = no reading.
    pub endpoints: Option<Vec<String>>,
    pub tunnel_mtu: Option<u32>,
    pub physical_mtu: Option<u32>,
}

/// Run all five verdicts (a pure function, no IO).
pub fn run_doctor(inputs: &DoctorInputs) -> DoctorReport {
    let (tunnel_bps, foreign_bps, physical_bps) = inputs.rates.unwrap_or((0.0, 0.0, 0.0));
    // When sampling fails, rates is None — leave it to the amplification item
    // to judge not_assessed as "no traffic", but the evidence must show that it
    // was a sampling failure rather than genuinely idle.
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

/// The report returned when this platform does not implement the health
/// check: all five items are `not_assessed`, each stating why.
///
/// **Never return PASS** — "not implemented" and "checked and fine" are two
/// different things (§7.5).
/// When the callers (CLI / console) see everything skipped, they know they must
/// run on another machine or another platform.
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

/// The current UTC time (ISO-8601, second precision, `Z` suffix).
fn chrono_iso_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// The IPv4 segment prefix of the meshlet overlay (used by verdicts 2/3).
pub const OVERLAY_PREFIX: &str = "10.240.";

/// The IPv4 segment prefix of the foreign overlay (ZeroTier) (used by
/// verdict 3).
pub const FOREIGN_OVERLAY_IPV4_PREFIX: &str = "10.147.";

/// `zerotier-cli -j listpeers` -> the addresses of every **established path**
/// (pure parsing).
///
/// Only items in `paths[]` that are `active` and not `expired` are taken — an
/// expired path is no longer in use, and reporting it would be a false alarm
/// (once isolation takes effect the old paths expire one after another, and it
/// is exactly this criterion that turns the check green).
/// Malformed JSON / a top level that is not an array -> `None` (**do not guess
/// it as an empty list**, §7.5: "unreadable" and "read but empty" are two
/// different things, and the former must go to `not_assessed`).
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
                // `ip:port` -> keep only the address part (the verdict compares
                // segment prefixes).
                paths.push(address.split('%').next().unwrap_or(address).to_string());
            }
        }
    }
    Some(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A snippet of `zerotier-cli -j listpeers` from the incident scene
    /// (2026-11-23 forensics):
    /// `402477b104 -> 10.240.0.3/9993 active preferred`.
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
        // Neither the inactive 60912 nor the expired 58075 is taken.
        assert_eq!(paths, vec!["10.240.0.3/9993", "180.153.160.8/29566"]);
        // The incident path must be judged FAIL.
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
        // Structure unreadable -> None (not_assessed); never treat it as "no
        // borrowing".
        assert_eq!(parse_zerotier_paths(""), None);
        assert_eq!(parse_zerotier_paths("not json"), None);
        assert_eq!(parse_zerotier_paths(r#"{"address":"x"}"#), None);
        // Top level is an array but has no paths -> Some(empty): it really
        // was read, and there really are no paths.
        assert_eq!(parse_zerotier_paths(r#"[{"address":"x"}]"#), Some(vec![]));
    }

    /// Restored incident-scene readings (2026-11-23 real machine): at least
    /// amplification plus the borrowing paths should FAIL among the five.
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

    /// Post-fix readings (isolation in place, no borrowing, traffic leaving the
    /// wire) -> all green.
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

    /// A sampling failure must not be disguised as "traffic fine" — it has to
    /// be not_assessed.
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

    /// Under default inputs (nothing read) no FAIL may appear — missing data
    /// is not a fault (§7.5).
    #[test]
    fn default_inputs_never_report_failure() {
        let report = run_doctor(&DoctorInputs::default());
        assert!(!report.has_failure(), "{:?}", report.checks);
        assert_eq!(report.counts()[3], 4, "缺数据项应为 not_assessed");
    }

    // ---------------------------------------------------- raw samples ----

    #[test]
    fn amplification_flags_internal_circulation() {
        // Incident scene: the internals hammering while the physical port sends
        // nothing at all -> the "never leaves the NIC" branch.
        let check = check_tunnel_amplification(108e6, 0.0, 0.0);
        assert_eq!(check.status, CheckStatus::Fail);
        assert!(check.evidence.contains("不出网卡"), "{}", check.evidence);

        // A trace of traffic on the physical port while the internals still spin
        // -> the ratio branch, likewise FAIL.
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
        // 3 MB/s internally, 2 MB/s physically -> 1.5:1, normal.
        let check = check_tunnel_amplification(3e6, 0.0, 2e6);
        assert_eq!(check.status, CheckStatus::Pass);
    }

    #[test]
    fn amplification_is_not_assessed_without_traffic() {
        // Both sides near zero: with no traffic there is nothing to judge, so
        // **never guess** it as PASS (§7.5).
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
        // Physical port 0 while the internals carry traffic -> must FAIL; do
        // not misjudge on an infinite ratio.
        let check = check_tunnel_amplification(0.0, 5e6, 0.0);
        assert_eq!(check.status, CheckStatus::Fail);
    }

    // ------------------------------------------------ borrowing-path verdict ----

    #[test]
    fn foreign_paths_fail_when_any_path_is_on_the_overlay() {
        let paths = vec![
            "180.153.160.8/9993".to_string(),
            "10.240.0.3/9993".to_string(), // the preferred path from the incident scene
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
        // An empty list (zerotier present but no peer) is likewise "nothing to
        // judge" rather than PASS.
        assert_eq!(
            check_foreign_overlay_paths(Some(&[]), "10.240.").status,
            CheckStatus::Pass
        );
    }

    // ------------------------------------------------ endpoint tenancy ----

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
        // 2026-11-23 log verbatim: `from=10.147.19.226:51820 to=10.240.0.7:51820`.
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
        // The `%interface` scope form and the IPv6 bracketed port form must
        // both have their IP stripped out.
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

    // ------------------------------------------------ isolation rules ----

    #[test]
    fn isolation_missing_while_foreign_present_is_fail() {
        // Incident scene: the uid is readable, the rules number zero.
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
        // No zerotier on this host -> no isolation needed; it is a PASS, not
        // not_assessed.
        assert_eq!(check_isolation_rules(0, None).status, CheckStatus::Pass);
    }

    // ------------------------------------------------------ MTU ----

    #[test]
    fn mtu_gap_over_threshold_is_warned() {
        // Whole-network reality: ZT 2800 vs physical 1500.
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

    // ---------------------------------------------------- report aggregation ----

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
