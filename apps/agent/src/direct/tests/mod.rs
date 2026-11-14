//! `direct` 单测：共享夹具（常量 + cidr/direct_peer/peer/lan）挂本模块，
//! 用例按被测对象分档——纯函数系列见 [plan]，Manager 系列见 [manager]。

use super::*;
use meshlet_domain::EndpointCandidate;

mod manager;
mod plan;

const OVERLAY: &str = "10.240.0.0/16";
const HOME: &str = "192.168.1.0/24";

fn cidr(s: &str) -> Ipv4Cidr {
    s.parse().unwrap()
}

fn direct_peer(key: &str, vip: &str, state: PeerLinkState) -> DirectPeer {
    DirectPeer {
        virtual_ipv4: vip.parse().unwrap(),
        state,
        last_handshake_age_secs: None,
        peer_name: format!("{key}-name"),
        endpoint: String::new(),
        rtt_ms: None,
        rtt_source: None,
        last_handshake_at: None,
        rx_bytes: 0,
        tx_bytes: 0,
        candidates: vec![],
        last_direct: None,
    }
}

fn peer(key: &str, vip: &str, endpoints: &[EndpointCandidate]) -> PeerEndpoints {
    PeerEndpoints {
        device_id: meshlet_domain::DeviceId(key.into()),
        public_key: key.into(),
        virtual_ipv4: vip.parse().unwrap(),
        name: format!("{key}-name"),
        endpoints: endpoints.to_vec(),
    }
}

fn lan(ip: &str, port: u16) -> EndpointCandidate {
    EndpointCandidate::lan(ip.parse().unwrap(), port)
}

fn public(ip: &str, port: u16) -> EndpointCandidate {
    EndpointCandidate::public(ip.parse().unwrap(), port)
}
