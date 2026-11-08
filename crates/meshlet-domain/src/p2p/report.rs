//! hub 侧上报与分发（纯逻辑）：把「心跳观测源地址 + agent 上报」合并成候选
//! endpoint 列表，并为 `GET .../peers/endpoints` 聚合同网络其他 Active 设备
//! 的直连信息。公网地址由 hub 观测 HTTP 源地址得出，agent 不自报
//! （NAT 后自报不可信）。

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::cidr::Ipv4Cidr;
use crate::entities::{Device, DeviceId};
use crate::p2p::endpoint::{is_private_ip, EndpointCandidate};
use crate::p2p::link::DirectLinkStatus;

/// agent 心跳携带的本地直连入口上报：本机 wg 的 UDP 监听端口 + RFC1918
/// 局域网地址列表。公网地址由 hub 观测 HTTP 源地址得出，agent 不自报
/// （NAT 后自报不可信）。
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DirectEndpointReport {
    /// 本机 wg 接口的 UDP 监听端口（直连对端向它发包）。
    pub listen_port: u16,
    /// 本机各接口的 RFC1918 地址（不含端口；端口统一取 `listen_port`）。
    pub lan_addrs: Vec<Ipv4Addr>,
}

/// hub 记录的单设备直连状态：最近一次观测到的 agent 源地址 + 最近一次
/// 上报。二者任一缺失则该设备暂无可用候选。
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeviceDirectState {
    /// 心跳 HTTP 请求的源地址（hub 观测；`None` = 尚未见过心跳）。
    pub observed_ip: Option<Ipv4Addr>,
    /// 最近一次 [DirectEndpointReport]（`None` = 该 agent 版本未上报）。
    pub report: Option<DirectEndpointReport>,
    /// §12.3 链路状态上报：本设备对各对端的直连链路（空 = 全中继/未上报）。
    pub links: Vec<DirectLinkStatus>,
}

impl DeviceDirectState {
    /// hub 观测 endpoint（P2P-⑤）：`observed_ip:listen_port`，即观测源地址 +
    /// agent 上报的 wg 监听端口。二者任一缺失则 `None`。**不做**私网过滤——
    /// 这是原始观测；公网判定见 [DeviceDirectState::public_endpoint]。
    pub fn observed_endpoint(&self) -> Option<(Ipv4Addr, u16)> {
        let report = self.report.as_ref()?;
        Some((self.observed_ip?, report.listen_port))
    }

    /// 公网 endpoint：观测地址非私网时才有（与 agent 拨号候选同源，
    /// [public_candidate] 同一口径）。`None` = 无观测、未上报或观测地址非公网。
    pub fn public_endpoint(&self) -> Option<EndpointCandidate> {
        let report = self.report.as_ref()?;
        public_candidate(self.observed_ip, report.listen_port)
    }
}

/// 公网候选：hub 观测源地址**非私网**时才与 wg 监听端口合成（hub 与 agent
/// 同内网时观测地址就是 LAN 地址，再标成 public 只会误导打洞）。`None` =
/// 无观测或观测地址非公网。
pub fn public_candidate(
    observed_ip: Option<Ipv4Addr>,
    listen_port: u16,
) -> Option<EndpointCandidate> {
    let ip = observed_ip?;
    if !is_private_ip(ip) && !ip.is_loopback() && !ip.is_unspecified() {
        Some(EndpointCandidate::public(ip, listen_port))
    } else {
        None
    }
}

/// 把「hub 观测源地址 + agent 上报」合并成候选 endpoint 列表（纯函数）：
/// - LAN 候选 = 上报地址中 RFC1918 的每一个（端口统一 `listen_port`），
///   丢弃未指定 / 回环 / 非私网地址；
/// - 公网候选 = [public_candidate]（观测源地址非私网时才构造）；
/// - 结果按 (ip, port) 确定性排序去重。
pub fn endpoint_candidates(
    observed_ip: Option<Ipv4Addr>,
    report: &DirectEndpointReport,
) -> Vec<EndpointCandidate> {
    let mut lan: Vec<_> = report
        .lan_addrs
        .iter()
        .copied()
        .filter(|ip| is_private_ip(*ip) && !ip.is_loopback() && !ip.is_unspecified())
        .map(|ip| EndpointCandidate::lan(ip, report.listen_port))
        .collect();
    lan.sort_by_key(|c| (c.ip, c.port));
    lan.dedup();
    let mut out = lan;
    if let Some(c) = public_candidate(observed_ip, report.listen_port) {
        out.push(c);
    }
    out
}

/// hub 下发给 agent 的单节点直连信息（`GET .../peers/endpoints` 列表项）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerEndpoints {
    pub device_id: DeviceId,
    /// 对端 wg 公钥（agent 据此 `wg set peer`）。
    pub public_key: String,
    /// 对端 overlay 地址（AllowedIPs `/32` 的来源）。
    pub virtual_ipv4: Ipv4Addr,
    /// 对端设备名（控制台/CLI 直连 peers 展示用；旧服务端缺省为空）。
    #[serde(default)]
    pub name: String,
    /// 候选 endpoint 列表（公网 + 局域网）。
    pub endpoints: Vec<EndpointCandidate>,
}

/// hub 侧聚合（纯函数）：为 `self_id` 视角汇总同网络内其他 Active 设备的
/// 直连候选。调用方传入已按网络过滤的设备列表；本函数只做：
/// - 排除非自身、非 Active、无上报、虚拟 IP 越出路由范围（scope）的设备；
/// - 无候选（未上报 / 观测缺失）的设备不进列表（不可能直连，避免死载荷）；
/// - 输出按 device_id 确定性排序。
///
/// `scope_cidr` = 该设备可路由的网段（单段网络为整个 overlay；分段网络为
/// 所属段前缀，与 peer AllowedIPs 推导同一口径）。
pub fn peer_endpoints_for(
    scope_cidr: Ipv4Cidr,
    self_id: &DeviceId,
    devices: &[Device],
    direct: &BTreeMap<DeviceId, DeviceDirectState>,
) -> Vec<PeerEndpoints> {
    let mut out = Vec::new();
    for device in devices {
        if &device.id == self_id || !device.is_active() {
            continue;
        }
        let Some(state) = direct.get(&device.id) else {
            continue;
        };
        let Some(report) = state.report.as_ref() else {
            continue;
        };
        if !scope_cidr.contains(device.virtual_ipv4) {
            continue;
        }
        let endpoints = endpoint_candidates(state.observed_ip, report);
        if endpoints.is_empty() {
            continue;
        }
        out.push(PeerEndpoints {
            device_id: device.id.clone(),
            public_key: device.public_key.clone(),
            virtual_ipv4: device.virtual_ipv4,
            name: device.name.clone(),
            endpoints,
        });
    }
    out.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    out
}

#[cfg(test)]
mod tests {
    use super::{
        endpoint_candidates, peer_endpoints_for, DeviceDirectState, DirectEndpointReport,
        PeerEndpoints,
    };
    use crate::entities::{Device, DeviceId, DeviceStatus, NetworkId, Platform, SegmentId};
    use crate::p2p::test_support::{cidr, lan, public, OVERLAY};
    use std::collections::BTreeMap;

    fn device(id: &str, ip: &str, status: DeviceStatus) -> Device {
        Device {
            id: DeviceId(id.into()),
            network_id: NetworkId("net-1".into()),
            name: id.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: format!("pub-{id}"),
            platform: Platform::Linux,
            status,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: "2026-10-31T00:00:00Z".into(),
            approved_at: None,
            revoked_at: None,
            segment_id: SegmentId("seg-net-1".into()),
            labels: BTreeMap::new(),
        }
    }

    fn report(port: u16, addrs: &[&str]) -> DirectEndpointReport {
        DirectEndpointReport {
            listen_port: port,
            lan_addrs: addrs.iter().map(|a| a.parse().unwrap()).collect(),
        }
    }

    // ------------------------------------------------- 候选合并（hub）----

    #[test]
    fn candidates_merge_lan_report_and_public_observation() {
        let cands = endpoint_candidates(
            Some("203.0.113.7".parse().unwrap()),
            &report(51821, &["192.168.1.10", "10.8.0.5"]),
        );
        assert_eq!(
            cands,
            vec![
                lan("10.8.0.5", 51821),
                lan("192.168.1.10", 51821),
                public("203.0.113.7", 51821),
            ]
        );
    }

    #[test]
    fn same_lan_observation_yields_no_public_candidate() {
        // hub 与 agent 同内网：观测源地址是私网地址，不能标成 public。
        let cands = endpoint_candidates(
            Some("192.168.1.10".parse().unwrap()),
            &report(51821, &["192.168.1.10"]),
        );
        assert_eq!(cands, vec![lan("192.168.1.10", 51821)]);
    }

    #[test]
    fn candidates_drop_loopback_unspecified_and_non_private_lan_addrs() {
        let cands = endpoint_candidates(
            None,
            &report(51820, &["127.0.0.1", "0.0.0.0", "8.8.8.8", "192.168.1.10"]),
        );
        assert_eq!(cands, vec![lan("192.168.1.10", 51820)]);
    }

    #[test]
    fn candidates_dedup_and_sort_deterministically() {
        let cands = endpoint_candidates(
            None,
            &report(51820, &["192.168.1.20", "192.168.1.10", "192.168.1.20"]),
        );
        assert_eq!(
            cands,
            vec![lan("192.168.1.10", 51820), lan("192.168.1.20", 51820)]
        );
    }

    #[test]
    fn observed_endpoint_pairs_observed_ip_with_wg_listen_port() {
        let state = DeviceDirectState {
            observed_ip: Some("203.0.113.7".parse().unwrap()),
            report: Some(report(51821, &["192.168.1.10"])),
            links: Vec::new(),
        };
        assert_eq!(
            state.observed_endpoint(),
            Some(("203.0.113.7".parse().unwrap(), 51821))
        );
        assert_eq!(state.public_endpoint(), Some(public("203.0.113.7", 51821)));
    }

    #[test]
    fn observed_endpoint_requires_both_observation_and_report() {
        let no_report = DeviceDirectState {
            observed_ip: Some("203.0.113.7".parse().unwrap()),
            report: None,
            links: Vec::new(),
        };
        assert_eq!(no_report.observed_endpoint(), None);
        assert_eq!(no_report.public_endpoint(), None);
        let no_observation = DeviceDirectState {
            observed_ip: None,
            report: Some(report(51821, &["192.168.1.10"])),
            links: Vec::new(),
        };
        assert_eq!(no_observation.observed_endpoint(), None);
        assert_eq!(no_observation.public_endpoint(), None);
    }

    #[test]
    fn private_observation_has_no_public_endpoint_but_keeps_observed() {
        // hub 与 agent 同内网：观测地址私网 → 观测端点仍在（原始观测），
        // 公网端点缺（与 endpoint_candidates 同一口径，标 public 会误导）。
        let state = DeviceDirectState {
            observed_ip: Some("192.168.1.10".parse().unwrap()),
            report: Some(report(51821, &["192.168.1.10"])),
            links: Vec::new(),
        };
        assert_eq!(
            state.observed_endpoint(),
            Some(("192.168.1.10".parse().unwrap(), 51821))
        );
        assert_eq!(state.public_endpoint(), None);
    }

    // --------------------------------------------- 分发聚合（hub）--------

    #[test]
    fn peer_endpoints_lists_active_peers_with_reports_sorted_by_id() {
        let devices = vec![
            device("dev-a", "10.240.0.2", DeviceStatus::Active),
            device("dev-b", "10.240.0.3", DeviceStatus::Active),
            device("dev-c", "10.240.0.4", DeviceStatus::Pending),
        ];
        let mut direct = BTreeMap::new();
        direct.insert(
            DeviceId("dev-a".into()),
            DeviceDirectState {
                observed_ip: Some("203.0.113.1".parse().unwrap()),
                report: Some(report(51820, &["192.168.1.2"])),
                links: Vec::new(),
            },
        );
        direct.insert(
            DeviceId("dev-c".into()),
            DeviceDirectState {
                observed_ip: Some("203.0.113.3".parse().unwrap()),
                report: Some(report(51820, &[])),
                links: Vec::new(),
            },
        );

        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-b".into()), &devices, &direct);

        // dev-a 在列（Active + 有上报）；dev-c 是 Pending 被排除；dev-b 是自己。
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].device_id, DeviceId("dev-a".into()));
        assert_eq!(list[0].public_key, "pub-dev-a");
        assert_eq!(
            list[0].virtual_ipv4,
            "10.240.0.2".parse::<std::net::Ipv4Addr>().unwrap()
        );
        assert_eq!(list[0].endpoints.len(), 2);
    }

    #[test]
    fn peer_endpoints_excludes_self_out_of_scope_and_reportless() {
        let devices = vec![
            device("dev-a", "10.240.0.2", DeviceStatus::Active),
            device("dev-out", "10.250.0.9", DeviceStatus::Active), // 越出 scope
            device("dev-x", "10.240.0.5", DeviceStatus::Revoked),
        ];
        let mut direct = BTreeMap::new();
        direct.insert(
            DeviceId("dev-a".into()),
            DeviceDirectState {
                observed_ip: None,
                report: Some(report(51820, &["192.168.1.2"])),
                links: Vec::new(),
            },
        );
        direct.insert(
            DeviceId("dev-out".into()),
            DeviceDirectState {
                observed_ip: None,
                report: Some(report(51820, &["192.168.1.9"])),
                links: Vec::new(),
            },
        );

        // 自己（dev-a）被排除；越界与撤销的被排除。
        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-a".into()), &devices, &direct);
        assert!(list.is_empty());
    }

    #[test]
    fn peer_endpoints_skips_devices_without_usable_candidates() {
        let devices = vec![device("dev-a", "10.240.0.2", DeviceStatus::Active)];
        let mut direct = BTreeMap::new();
        // 观测缺失：LAN 候选仍在 → 在列。
        direct.insert(
            DeviceId("dev-a".into()),
            DeviceDirectState {
                observed_ip: None,
                report: Some(report(51820, &["192.168.1.2"])),
                links: Vec::new(),
            },
        );
        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-b".into()), &devices, &direct);
        assert_eq!(list.len(), 1);

        // 完全无上报 → 不进列表。
        let mut direct = BTreeMap::new();
        direct.insert(DeviceId("dev-a".into()), DeviceDirectState::default());
        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-b".into()), &devices, &direct);
        assert!(list.is_empty());
    }

    #[test]
    fn peer_endpoints_round_trips_as_json() {
        let list = vec![PeerEndpoints {
            device_id: DeviceId("dev-a".into()),
            public_key: "pub-a".into(),
            virtual_ipv4: "10.240.0.2".parse().unwrap(),
            name: "edge-a".into(),
            endpoints: vec![lan("192.168.1.2", 51821), public("203.0.113.1", 51821)],
        }];
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(
            serde_json::from_str::<Vec<PeerEndpoints>>(&json).unwrap(),
            list
        );
        assert!(json.contains(r#""kind":"lan""#));
        assert!(json.contains(r#""kind":"public""#));
    }
}
