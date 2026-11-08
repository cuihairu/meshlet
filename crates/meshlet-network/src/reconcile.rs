//! 纯解析与对账（从 lib.rs 拆出）：wg 输出解析、握手年龄表，以及计划与内核
//! 快照的逐项对账（无 IO，双平台共享，Linux 本机可测）。

use crate::{DevicePlan, NetworkSnapshot};

/// 解析 `wg show <if> latest-handshakes` 输出（每行 `公钥 握手unix时间 距今秒`）：
/// 公钥 → 距今秒数。第三列优先（WireGuard 自己算好的年龄）；缺第三列时按
/// `now - 握手时间` 兜底。握手时间为 0（从未握手）的 peer 不在输出里——
/// 调用方按「无读数」处理（§12 `classify_probe` 的 Unknown/Unhealthy 之别）。
///
/// 由 crate 根 re-export（实现见本模块，而非 [crate::linux] 模块）：双平台共享的**纯解析逻辑**，
/// Windows 执行层（`windows` 模块，`#[cfg(windows)]`）与 Linux 执行层各取
/// 所需——解析本身不依赖平台，二进制格式两侧一致。
pub(crate) fn parse_handshake_ages(
    text: &str,
    now_secs: u64,
) -> std::collections::BTreeMap<String, u64> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next()?;
            // 公钥 44 字符 base64 且以 `=` 结尾（与 dump 行解析同一判据）。
            if key.len() != 44 || !key.ends_with('=') {
                return None;
            }
            let ts: u64 = fields.next()?.parse().ok()?;
            if ts == 0 {
                return None;
            }
            let age = fields
                .next()
                .and_then(|ago| ago.parse::<u64>().ok())
                .unwrap_or_else(|| now_secs.saturating_sub(ts));
            Some((key.to_string(), age))
        })
        .collect()
}

/// 解析 `wg show <if> dump` 接口行的本机公钥指纹（字段 1；字段 0 是私钥，
/// 绝不外传）。Linux `wg` 与 Windows `wg.exe` 同一 dump 格式，共享本解析。
/// 公钥按身份校验（44 字符 base64、`=` 结尾）——残行/占位文本不臆造指纹。
pub fn parse_wg_dump_local_public_key(dump: &str) -> Option<String> {
    let header = dump.lines().next()?;
    let public_key = header.split_whitespace().nth(1)?;
    if public_key.len() != 44 || !public_key.ends_with('=') {
        return None;
    }
    Some(public_key.to_string())
}

/// 解析 `wg show <if> dump` 接口行的实际监听端口（字段 2）。Linux `wg` 与
/// Windows `wg.exe` 同一 dump 格式，共享本解析；解析不出（空/残行）→
/// `None`（调用方按证据缺失处理，不判漂移）。
pub fn parse_wg_dump_listen_port(dump: &str) -> Option<u16> {
    dump.lines().next()?.split_whitespace().nth(2)?.parse().ok()
}

/// 计划与内核快照逐项对账（纯函数，无 IO，Linux 本机可测）。
///
/// 供 Windows 后端 `device_plan_matches_sync` 使用（Linux 有内联的更强实现）；
/// 把「隧道在但配置已漂移」从「误判一致」中分辨出来：
/// ① 每个计划 peer 公钥必须存在于快照 peers（子集方向）；
/// ①a. 每个计划 peer 的 `allowed_ips` 必须与快照读回的 allowed-ips 精确一致
///    （顺序无关；与 Linux 同职责实现的身份级判定对齐）；
/// ② 快照里每个 peer 必须是计划 peer 或 `extra_peer_keys`（无未受管漂移；
///    `extra_peer_keys` 是直连保留等允许存在的额外 peer）；
/// ③ 每个计划路由 `destination` 必须在 `installed_routes`（CIDR 精确匹配）；
/// ④ 计划显式指定 MTU 则须与快照 `tunnel_mtu` 一致；
/// ⑤ 隧道不存在（`tunnel_exists=false`）→ 不匹配；
/// ⑥ 适配器实际地址读数存在且与计划地址不同 → 不匹配（手动换址的隧道）。
///
/// 调用方是 `#[cfg(windows)]` 的 `WindowsNetworkBackend`，故非 Windows 目标
/// 上本函数保持可编译（含单测）但无调用方——按仓内惯例以 cfg_attr 豁免
/// dead_code，让 Linux 本机能跑这些对账单测。
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn device_plan_matches(
    plan: &DevicePlan,
    extra_peer_keys: &std::collections::BTreeSet<String>,
    snapshot: &NetworkSnapshot,
) -> bool {
    if !snapshot.tunnel_exists {
        return false;
    }
    for peer in &plan.tunnel.peers {
        if !snapshot.peers.iter().any(|p| {
            p.public_key == peer.public_key
                // 集合语义：wg dump 读回的 CIDR 顺序不稳定，按集合比较。
                && p.allowed_ips.len() == peer.allowed_ips.len()
                && peer
                    .allowed_ips
                    .iter()
                    .all(|cidr| p.allowed_ips.contains(cidr))
        }) {
            return false;
        }
    }
    for p in &snapshot.peers {
        if plan
            .tunnel
            .peers
            .iter()
            .any(|pp| pp.public_key == p.public_key)
        {
            continue;
        }
        if extra_peer_keys.contains(&p.public_key) {
            continue;
        }
        return false;
    }
    for route in &plan.routes {
        if !snapshot.installed_routes.contains(&route.destination) {
            return false;
        }
    }
    if let Some(mtu) = plan.tunnel.mtu {
        if snapshot.tunnel_mtu != Some(mtu) {
            return false;
        }
    }
    // ⑥ 适配器实际地址：读数存在且与计划不符 → 手动换址，必须判不匹配。
    //    读数缺失（None）不判——证据缺失不假装一致，也不进重放死循环。
    if let Some(actual) = snapshot.tunnel_address {
        if actual != plan.tunnel.address {
            return false;
        }
    }
    // ⑦ 实际监听端口：直连钉住的固定端口与内核读数不符（手动 `wg set
    //    listen-port` / 半应用状态）→ 判不匹配，重放纠回。读数缺失不判。
    if let Some(port) = plan.tunnel.listen_port {
        if let Some(actual) = snapshot.tunnel_listen_port {
            if actual != port {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod device_plan_matches_tests {
    use super::*;
    use crate::{PeerConfig, PeerObserved, RouteConfig, TunnelConfig};
    use std::collections::BTreeSet;

    fn peer(key: &str) -> PeerConfig {
        PeerConfig {
            public_key: key.into(),
            allowed_ips: vec!["10.240.0.5/32".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        }
    }

    fn plan(peers: &[&str], routes: &[&str], mtu: Option<u32>) -> DevicePlan {
        DevicePlan {
            desired_revision: 1,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "Meshlet".into(),
                address: "10.240.0.1".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: peers.iter().map(|p| peer(p)).collect(),
                mtu,
                private_key: None,
            },
            routes: routes
                .iter()
                .map(|r| RouteConfig {
                    destination: r.parse().unwrap(),
                    interface: "Meshlet".into(),
                    gateway: None,
                })
                .collect(),
            nat_rules: Vec::new(),
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: "h".into(),
        }
    }

    fn snapshot(
        tunnel_exists: bool,
        peers: &[&str],
        routes: &[&str],
        mtu: Option<u32>,
    ) -> NetworkSnapshot {
        NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled: None,
            peers: peers
                .iter()
                .map(|k| PeerObserved {
                    public_key: (*k).into(),
                    allowed_ips: vec!["10.240.0.5/32".parse().unwrap()],
                })
                .collect(),
            installed_routes: routes.iter().map(|r| r.parse().unwrap()).collect(),
            nat_rules: Vec::new(),
            tunnel_mtu: mtu,
            local_public_key: None,
            tunnel_address: None,
            tunnel_listen_port: None,
        }
    }

    fn empty_extra() -> BTreeSet<String> {
        BTreeSet::new()
    }

    #[test]
    fn adapter_address_mismatch_reads_as_not_matching() {
        // 手动把隧道地址改了（peer/路由/MTU 全一致）→ 必须判不匹配；
        // 读数缺失（None）不判。
        let p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        let mut moved = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        moved.tunnel_address = Some("10.240.0.99".parse().unwrap());
        assert!(!device_plan_matches(&p, &empty_extra(), &moved));
        let mut matching = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        matching.tunnel_address = Some(p.tunnel.address);
        assert!(device_plan_matches(&p, &empty_extra(), &matching));
    }

    #[test]
    fn all_match_true() {
        let p = plan(&["pk-a", "pk-b"], &["10.240.0.0/24"], Some(1420));
        let s = snapshot(true, &["pk-a", "pk-b"], &["10.240.0.0/24"], Some(1420));
        assert!(device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn pinned_listen_port_mismatch_reads_as_not_matching() {
        // 直连钉住的固定端口与内核读数不符（手动 wg set listen-port /
        // 半应用）→ 必须判不匹配，重放纠回；读数缺失（None）不判。
        let mut p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        p.tunnel.listen_port = Some(51820);
        let mut drifted = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        drifted.tunnel_listen_port = Some(60736);
        assert!(!device_plan_matches(&p, &empty_extra(), &drifted));
        let mut matching = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        matching.tunnel_listen_port = Some(51820);
        assert!(device_plan_matches(&p, &empty_extra(), &matching));
        // 证据缺失不判（不进重放死循环）。
        let mut unreadable = snapshot(true, &["pk-a"], &["10.240.0.0/24"], None);
        unreadable.tunnel_listen_port = None;
        assert!(device_plan_matches(&p, &empty_extra(), &unreadable));
    }

    #[test]
    fn wg_dump_listen_port_parses_interface_line() {
        // 接口行形状：私钥 本机公钥 监听端口 …
        let dump = format!("{} {} 51820\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&dump), Some(51820));
        let no_port = format!("{} {}\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&no_port), None);
        assert_eq!(crate::parse_wg_dump_listen_port(""), None);
        let junk = format!("{} {} not-a-port\n", "x".repeat(32), "A".repeat(43) + "=");
        assert_eq!(crate::parse_wg_dump_listen_port(&junk), None);
    }

    #[test]
    fn missing_plan_peer_false() {
        // 计划有 pk-c，快照缺 → 漂移。
        let p = plan(&["pk-a", "pk-c"], &[], None);
        let s = snapshot(true, &["pk-a"], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn drifted_peer_false_but_extra_allowed_true() {
        // 快照多出 pk-x：不在计划也不在 extra → 未受管漂移。
        let p = plan(&["pk-a"], &[], None);
        let s = snapshot(true, &["pk-a", "pk-x"], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
        // extra_peer_keys 放行 pk-x → 一致。
        let mut extra = empty_extra();
        extra.insert("pk-x".into());
        assert!(device_plan_matches(&p, &extra, &s));
    }

    #[test]
    fn drifted_peer_allowed_ips_false() {
        // 计划 peer 存在但内核 allowed-ips 已漂移（如被外部 wg set 改过）
        // → 必须判定不匹配以触发重放纠回。
        let p = plan(&["pk-a"], &[], None);
        let mut s = snapshot(true, &["pk-a"], &[], None);
        s.peers[0].allowed_ips = vec!["10.240.0.6/32".parse().unwrap()];
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn missing_route_false() {
        // 计划路由 10.240.0.0/24 未安装 → 漂移。
        let p = plan(&[], &["10.240.0.0/24"], None);
        let s = snapshot(true, &[], &["192.168.1.0/24"], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn mtu_drift_false() {
        // 计划显式 1420，内核读数 1300 → 漂移。
        let p = plan(&[], &[], Some(1420));
        let s = snapshot(true, &[], &[], Some(1300));
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn tunnel_not_exists_false() {
        let p = plan(&["pk-a"], &["10.240.0.0/24"], Some(1420));
        let s = snapshot(false, &[], &[], None);
        assert!(!device_plan_matches(&p, &empty_extra(), &s));
    }

    #[test]
    fn no_planned_mtu_skips_mtu_check() {
        // 计划未指定 MTU → 不比对，仅其余项判定。
        let p = plan(&["pk-a"], &["10.240.0.0/24"], None);
        let s = snapshot(true, &["pk-a"], &["10.240.0.0/24"], Some(1300));
        assert!(device_plan_matches(&p, &empty_extra(), &s));
    }
    /// 本机公钥指纹解析（BUG② 修复的读数端）：接口行字段 1；私钥（字段 0）
    /// 绝不返回；残行 / 占位文本 / 空表 → None。
    #[test]
    fn wg_dump_local_public_key_reads_field_one_and_validates_shape() {
        let key = format!("{}=", "K".repeat(43));
        let dump = format!("some-private-key\t{key}\t51820\t0\n");
        assert_eq!(parse_wg_dump_local_public_key(&dump), Some(key.clone()));
        // 接口行在前、peer 行在后：只看首行。
        let with_peer =
            format!("{dump}PEER-KEY-PLACEHOLDER\t\tendpoint\t10.240.0.2/32\t0\t0\t0\t0\n");
        assert_eq!(parse_wg_dump_local_public_key(&with_peer), Some(key));
        // 空表 / 残行 / 非法形状。
        assert_eq!(parse_wg_dump_local_public_key(""), None);
        assert_eq!(parse_wg_dump_local_public_key("only-private-key\n"), None);
        assert_eq!(
            parse_wg_dump_local_public_key("priv\tPLACEHOLDER\t51820\t0\n"),
            None
        );
    }
}
