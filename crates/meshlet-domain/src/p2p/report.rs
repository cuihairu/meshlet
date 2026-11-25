//! Hub-side reporting and distribution (pure logic): merges "heartbeat-observed source
//! address + agent report" into a candidate endpoint list, and aggregates direct-connect
//! info of the other Active devices on the network for `GET .../peers/endpoints`. The
//! public address comes from the hub observing the HTTP source address; the agent never self-reports it (self-reports behind NAT are untrustworthy).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::cidr::Ipv4Cidr;
use crate::entities::{Device, DeviceId};
use crate::p2p::endpoint::{is_private_ip, EndpointCandidate};
use crate::p2p::link::DirectLinkStatus;

/// Local direct-connect entry points reported in the agent heartbeat: this host's wg UDP
/// listen port plus a list of RFC1918 LAN addresses. The public address comes from the
/// hub observing the HTTP source address; the agent never self-reports it (self-reports behind NAT are untrustworthy).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DirectEndpointReport {
    /// UDP listen port of this host's wg interface (direct peers send packets to it).
    pub listen_port: u16,
    /// RFC1918 addresses of this host's interfaces (no port; the port is always `listen_port`).
    pub lan_addrs: Vec<Ipv4Addr>,
}

/// Per-device direct-connect state recorded by the hub: the most recently observed agent
/// source address plus the most recent report. If either is missing, the device has no usable candidates for now.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DeviceDirectState {
    /// Source address of the heartbeat HTTP request (observed by the hub; `None` = no heartbeat seen yet).
    pub observed_ip: Option<Ipv4Addr>,
    /// Most recent [DirectEndpointReport] (`None` = this agent version does not report).
    pub report: Option<DirectEndpointReport>,
    /// §12.3 link status report: this device's direct links to each peer (empty = all relay / not reported).
    pub links: Vec<DirectLinkStatus>,
}

impl DeviceDirectState {
    /// Hub-observed endpoint (P2P-⑤): `observed_ip:listen_port`, i.e. the observed source
    /// address plus the wg listen port reported by the agent. `None` if either is missing.
    /// **No** private-range filtering - this is the raw observation; see [DeviceDirectState::public_endpoint] for the public check.
    pub fn observed_endpoint(&self) -> Option<(Ipv4Addr, u16)> {
        let report = self.report.as_ref()?;
        Some((self.observed_ip?, report.listen_port))
    }

    /// Public endpoint: exists only when the observed address is not private (same source as
    /// the agent's dial candidates, same rule as [public_candidate]). `None` = no observation, no report, or the observed address is not public.
    pub fn public_endpoint(&self) -> Option<EndpointCandidate> {
        let report = self.report.as_ref()?;
        public_candidate(self.observed_ip, report.listen_port)
    }
}

/// Public candidate: combined with the wg listen port only when the hub-observed source
/// address is **not private** (when hub and agent share a LAN, the observed address is a LAN
/// address, and labelling it public would only mislead hole punching). `None` = no observation or the observed address is not public.
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

/// Merge "hub-observed source address + agent report" into a candidate endpoint list (pure function):
/// - LAN candidates = every RFC1918 address in the report (port always `listen_port`),
///   dropping unspecified / loopback / non-private addresses;
/// - public candidate = [public_candidate] (built only when the observed source address is not private);
/// - the result is sorted and deduplicated deterministically by (ip, port).
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

/// Per-node direct-connect info the hub sends to the agent (item of `GET .../peers/endpoints`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerEndpoints {
    pub device_id: DeviceId,
    /// Peer wg public key (the agent runs `wg set peer` with it).
    pub public_key: String,
    /// Peer overlay address (the source of the AllowedIPs `/32`).
    pub virtual_ipv4: Ipv4Addr,
    /// Peer device name (for console/CLI direct-connect peers display; empty by default on older servers).
    #[serde(default)]
    pub name: String,
    /// Candidate endpoint list (public + LAN).
    pub endpoints: Vec<EndpointCandidate>,
}

/// Hub-side aggregation (pure function): collects direct-connect candidates of the other Active devices
/// on the same network from `self_id`'s perspective. The caller passes a device list already
/// filtered by network; this function only:
/// - excludes devices that are not self, not Active, without a report, or whose virtual IP falls outside the routable range (scope);
/// - drops candidate-less devices (no report / missing observation), then sorts the output deterministically by device_id.
///
/// `scope_cidr` = the routable range for the device (the whole overlay on a single-segment
/// network; the owning segment prefix on a segmented one, same rule as peer AllowedIPs derivation).
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

    // ------------------------------------------------- candidate merge (hub) ----

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
        // Hub and agent share a LAN: the observed source address is private, so it must not be labelled public.
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
        // Hub and agent share a LAN: observed address is private -> the observed endpoint
        // still exists (raw observation), the public endpoint is absent (same rule as endpoint_candidates; labelling it public would mislead).
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

    // --------------------------------------------- distribution (hub) --------

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

        // dev-a is listed (Active + has a report); dev-c is Pending and excluded; dev-b is self.
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
            device("dev-out", "10.250.0.9", DeviceStatus::Active), // out of scope
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

        // Self (dev-a) is excluded; out-of-scope and revoked devices are excluded too.
        let list = peer_endpoints_for(cidr(OVERLAY), &DeviceId("dev-a".into()), &devices, &direct);
        assert!(list.is_empty());
    }

    #[test]
    fn peer_endpoints_skips_devices_without_usable_candidates() {
        let devices = vec![device("dev-a", "10.240.0.2", DeviceStatus::Active)];
        let mut direct = BTreeMap::new();
        // Observation missing: the LAN candidate still stands -> listed.
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

        // No report at all -> not in the list.
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
