#[cfg(test)]
mod tests {
    use std::path::Path;

    use meshlet_config::{AgentConfig, DataplaneConfig, TrayConfig};
    use meshlet_domain::PeerLinkState;
    use std::net::Ipv4Addr;

    use crate::agent::direct_report::direct_report_from;
    use crate::direct_rtt::RttProbe;
    use meshlet_config::DirectConnectConfig;
    use meshlet_domain::{DirectLinkStatus, Ipv4Cidr};
    use meshlet_network::NetworkDiagnostics;
    use meshlet_network::{DevicePlan, SystemBackend};

    use crate::agent::endpoint::parse_endpoint_candidate;
    use crate::agent::evidence::probe_decision;
    use crate::agent::handshake::dump_handshake_ages;
    use crate::agent::paths::read_private_key;
    use crate::agent::plan_adapter::{enforce_hub_keepalive, plan_with_hub_endpoint};
    use crate::agent::rtt_source::honest_rtt_source;
    use crate::agent::scope::direct_scope;
    use crate::agent::verdict::dial_verdict;
    use crate::agent::views::direct_peer_views;
    use crate::Agent;

    fn config(state_dir: &str) -> AgentConfig {
        AgentConfig {
            server_url: "http://127.0.0.1:1".into(),
            state_dir: state_dir.into(),
            device_token: Some("tok".into()),
            bootstrap_token: None,
            device_name: None,
            tray: TrayConfig::OFF,
            upgrade: meshlet_config::UpgradeConfig::default(),
            dataplane: DataplaneConfig {
                enabled: true,
                ..DataplaneConfig::default()
            },
            ssh_config_sync: meshlet_config::SshConfigSyncConfig::OFF,
        }
    }

    #[test]
    fn private_key_is_read_trimmed_and_absent_is_ok() {
        // 未配置私钥：None（保留接口现有私钥，幂等重放）。
        assert_eq!(read_private_key(&DataplaneConfig::default()).unwrap(), None);

        let dir = std::env::temp_dir().join("meshlet-agent-key-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dev.key");
        std::fs::write(&path, "key-material\n").unwrap();
        let dp = DataplaneConfig {
            private_key_file: Some(path.to_string_lossy().to_string()),
            ..DataplaneConfig::default()
        };
        assert_eq!(
            read_private_key(&dp).unwrap().as_deref(),
            Some("key-material")
        );

        // 空文件：明确报错，不当“没配”处理（首装必然握手失败）。
        std::fs::write(&path, "\n").unwrap();
        assert!(read_private_key(&dp).is_err());

        // 缺失文件：路径写错必须可见。
        let missing = DataplaneConfig {
            private_key_file: Some("/nonexistent/meshlet/dev.key".into()),
            ..DataplaneConfig::default()
        };
        assert!(read_private_key(&missing).is_err());

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn state_path_lives_under_the_configured_state_dir() {
        let agent = Agent::new(config("/var/lib/meshlet"), None);
        assert_eq!(
            agent.state_path(),
            Path::new("/var/lib/meshlet/applied.json")
        );
    }

    #[test]
    fn heartbeat_against_a_dead_server_fails_visibly() {
        // 拉不到服务端时报错（可见），而不是静默「成功」——tick 据此退避重试。
        let agent = Agent::new(config("/tmp/meshlet-agent-dead"), None);
        let err = agent.heartbeat(None).expect_err("dead server");
        assert!(!err.is_empty(), "failure must be reported: {err}");
    }

    fn probe_plan(mtu: Option<u32>, hub: Option<&str>, own: &str) -> DevicePlan {
        DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: meshlet_network::TunnelConfig {
                name: "wg0".into(),
                address: own.parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![],
                mtu,
                private_key: None,
            },
            routes: vec![],
            nat_rules: vec![],
            hub_address: hub.map(|h| h.parse().unwrap()),
            publish: None,
            ssh_config: None,
            desired_config_hash: "hash".into(),
        }
    }

    #[test]
    fn hub_endpoint_fills_a_plan_without_one() {
        // 服务端计划不携带 endpoint（§16.4：服务端不知道 agent 的网络位置）。
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        p.tunnel.peers.push(meshlet_network::PeerConfig {
            public_key: "hub-pub".into(),
            allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        });

        // 本地兜底填充 → 设备可主动发起握手。
        let filled = plan_with_hub_endpoint(&p, Some("10.98.0.10:51820"));
        assert_eq!(
            filled.tunnel.peers[0].endpoint.as_deref(),
            Some("10.98.0.10:51820")
        );
        // 哈希不被本地兜底改写：账本与漂移判定仍以服务端期望为准。
        assert_eq!(filled.desired_config_hash, p.desired_config_hash);

        // 服务端已带值（未来通告 advertise endpoint）→ 尊重服务端，不覆盖。
        let mut explicit = p.clone();
        explicit.tunnel.peers[0].endpoint = Some("10.98.0.99:51820".into());
        assert_eq!(
            plan_with_hub_endpoint(&explicit, Some("10.98.0.10:51820"))
                .tunnel
                .peers[0]
                .endpoint,
            explicit.tunnel.peers[0].endpoint
        );

        // 未配置兜底 → 原样返回；空 peer 计划不越界。
        assert_eq!(
            plan_with_hub_endpoint(&p, None).tunnel.peers[0].endpoint,
            None
        );
        let empty = probe_plan(None, None, "10.240.0.7");
        assert_eq!(
            plan_with_hub_endpoint(&empty, Some("10.98.0.10:51820"))
                .tunnel
                .peers
                .len(),
            0
        );
    }

    #[test]
    fn probe_decision_targets_the_hub_with_the_planned_payload() {
        let p = probe_plan(Some(1380), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, None),
            Some(("10.240.0.1".parse().unwrap(), 1352))
        );

        // 计划未配置 MTU：按默认 1420 探测（1420 − 28 = 1392）。
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, None),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );

        // hub 未知 / hub 就是自己（自 ping 不经过隧道）/ 载荷为 0：不探测。
        let p = probe_plan(Some(1380), None, "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
        let p = probe_plan(Some(1380), Some("10.240.0.7"), "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
        let p = probe_plan(Some(28), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
    }

    /// rtt_source 如实四态：实测成功 probe_ok；不可测但握手新鲜 handshake_fresh
    /// （「不可测」不再谎报链路结论）；握手不新鲜 probe_failed；没轮到 unprobed。
    #[test]
    fn rtt_source_is_honest_about_handshake_evidence() {
        let now = 1_800_000_000u64;
        // 实测成功：无论握手状态，来源都是 probe_ok。
        assert_eq!(
            honest_rtt_source(
                &RttProbe {
                    rtt_ms: Some(12),
                    source: crate::direct_rtt::RttSource::Overlay
                },
                None,
                now
            ),
            Some("probe_ok")
        );
        // 不可测（两路 ping 全静默）+ 握手新鲜 → handshake_fresh（链路活着）。
        assert_eq!(
            honest_rtt_source(
                &RttProbe {
                    rtt_ms: None,
                    source: crate::direct_rtt::RttSource::Unreachable
                },
                Some(now - meshlet_domain::DIRECT_PROMOTE_FRESH_SECS),
                now
            ),
            Some("handshake_fresh")
        );
        // 不可测 + 握手超过晋升阈值 → 如实 probe_failed（不再谎报「不可测=活着」）。
        assert_eq!(
            honest_rtt_source(
                &RttProbe {
                    rtt_ms: None,
                    source: crate::direct_rtt::RttSource::Unreachable
                },
                Some(now - meshlet_domain::DIRECT_PROMOTE_FRESH_SECS - 1),
                now
            ),
            Some("probe_failed")
        );
        // 没轮到（探测在途）+ 无握手 → unprobed（不是结论）。
        assert_eq!(
            honest_rtt_source(&RttProbe::unknown(), None, now),
            Some("unprobed")
        );
        // 从未握手（ts=0）不算新鲜证据。
        assert_eq!(
            honest_rtt_source(&RttProbe::unknown(), Some(0), now),
            Some("unprobed")
        );
    }

    /// 诊断 dump → 握手年龄：从未握手 / 时钟回拨的行丢弃，其余翻译成距今秒。
    #[test]
    fn dump_handshake_ages_skips_never_handshaked_and_future_timestamps() {
        let now = 1_800_000_000u64;
        let net = NetworkDiagnostics {
            collected_at: None,
            route_table: vec![],
            interfaces: vec![],
            wg: vec![
                meshlet_network::WgPeerDiagnostic {
                    public_key: "fresh".into(),
                    last_handshake: now - 42,
                    ..Default::default()
                },
                meshlet_network::WgPeerDiagnostic {
                    public_key: "never".into(),
                    last_handshake: 0,
                    ..Default::default()
                },
                meshlet_network::WgPeerDiagnostic {
                    public_key: "clock-skew".into(),
                    last_handshake: now + 10,
                    ..Default::default()
                },
            ],
        };
        let ages = dump_handshake_ages(Some(&net), now);
        assert_eq!(ages.len(), 1);
        assert_eq!(ages.get("fresh"), Some(&42));
        // 无快照 → 空（证据缺失不臆造）。
        assert!(dump_handshake_ages(None, now).is_empty());
    }

    #[test]
    fn probe_payload_adapts_to_the_underlay_when_plan_leaves_mtu_unset() {
        // 计划钉 MTU：计划优先，底层读数不影响探测载荷。
        let p = probe_plan(Some(1380), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, Some(9000)),
            Some(("10.240.0.1".parse().unwrap(), 1352))
        );

        // 计划未配置：按底层 MTU 推导。1500 以太网推导回 1420（默认行为
        // 不变）；jumbo 9000 → 8920 − 28；PPPoE 1492 → 1412 − 28。
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, Some(1500)),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );
        assert_eq!(
            probe_decision(&p, Some(9000)),
            Some(("10.240.0.1".parse().unwrap(), 8892))
        );
        assert_eq!(
            probe_decision(&p, Some(1492)),
            Some(("10.240.0.1".parse().unwrap(), 1384))
        );

        // 底层读数不可得：回退 WireGuard 默认（行为与旧版一致）。
        assert_eq!(
            probe_decision(&p, None),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );
    }

    #[test]
    fn direct_scope_is_the_allowed_cidr_that_contains_own_address() {
        let hub = |allowed: &[&str]| meshlet_network::PeerConfig {
            public_key: "hub-pub".into(),
            allowed_ips: allowed.iter().map(|s| s.parse().unwrap()).collect(),
            endpoint: None,
            persistent_keepalive_secs: None,
        };

        // 单段：唯一 AllowedIPs 即 scope。
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.0.2");
        p.tunnel.peers.push(hub(&["10.240.0.0/16"]));
        assert_eq!(
            direct_scope(&p),
            Some("10.240.0.0/16".parse::<Ipv4Cidr>().unwrap())
        );

        // 分段路由：AllowedIPs 多条且排序不保证——包含自身地址的那条才是 scope
        //（不是 `allowed_ips[0]`）。
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.1.2");
        p.tunnel
            .peers
            .push(hub(&["10.240.0.0/16", "10.240.1.0/24"]));
        assert_eq!(
            direct_scope(&p),
            Some("10.240.1.0/24".parse::<Ipv4Cidr>().unwrap())
        );

        // 无 hub peer / 自身地址越出所有段：None（保持 hub 中继，不猜）。
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.2");
        assert_eq!(direct_scope(&p), None);
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.250.0.2");
        p.tunnel.peers.push(hub(&["10.240.0.0/16"]));
        assert_eq!(direct_scope(&p), None);
    }

    #[test]
    fn direct_report_gates_on_enabled_and_carries_port() {
        let on = DirectConnectConfig {
            enabled: true,
            listen_port: 51820,
        };
        let report =
            direct_report_from(&on, vec!["192.168.1.50".parse().unwrap()]).expect("enabled");
        assert_eq!(report.listen_port, 51820);
        assert_eq!(
            report.lan_addrs,
            vec!["192.168.1.50".parse::<Ipv4Addr>().unwrap()]
        );

        // 空候选仍合法（对端可尝试公网观测地址）。
        let report = direct_report_from(&on, vec![]).expect("empty candidates");
        assert!(report.lan_addrs.is_empty());

        // 未开启直连：上报省略（None），不伪造端点。
        let off = DirectConnectConfig {
            enabled: false,
            listen_port: 51820,
        };
        assert_eq!(direct_report_from(&off, vec![]), None);
    }

    #[test]
    fn pending_receipt_queue_is_bounded_at_sixteen() {
        let root = std::env::temp_dir().join(format!(
            "meshlet-agent-receipt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut agent =
            Agent::with_backend(config(root.to_str().unwrap()), None, SystemBackend::new());
        let plan = DevicePlan {
            desired_revision: 1,
            hub_port: None,
            tunnel: meshlet_network::TunnelConfig {
                name: "wg0".into(),
                address: "127.0.0.1".parse().unwrap(),
                address_prefix: 32,
                listen_port: None,
                peers: Vec::new(),
                mtu: None,
                private_key: Some("private".into()),
            },
            routes: Vec::new(),
            nat_rules: Vec::new(),
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: "hash".into(),
        };
        for index in 0..17 {
            agent.enqueue_receipt(plan.clone(), Some(format!("error {index}")));
        }
        assert_eq!(agent.pending_receipts.len(), 16);
        assert_eq!(
            agent
                .pending_receipts
                .front()
                .and_then(|receipt| receipt.error.as_deref()),
            Some("error 1")
        );
        assert_eq!(
            agent
                .pending_receipts
                .back()
                .and_then(|receipt| receipt.error.as_deref()),
            Some("error 16")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// `peer dial` 结果判定：Direct/Pending = 成功；Relay/不在管 = 失败（绝不
    /// 假装成功）。
    #[test]
    fn dial_verdict_maps_state_to_success_or_failure() {
        use crate::direct::DirectPeer;
        let peer = |state| DirectPeer {
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            state,
            last_handshake_age_secs: None,
            peer_name: String::new(),
            endpoint: String::new(),
            rtt_ms: None,
            rtt_source: None,
            last_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
            candidates: vec![],
        };
        let (ok, mode, _) = dial_verdict(Some(&peer(PeerLinkState::Direct)));
        assert!(ok);
        assert_eq!(mode, "p2p_direct");
        let (ok, mode, _) = dial_verdict(Some(&peer(PeerLinkState::DirectPending { attempts: 1 })));
        assert!(ok);
        assert_eq!(mode, "direct_pending");
        let (ok, mode, _) = dial_verdict(Some(&peer(PeerLinkState::Relay)));
        assert!(!ok);
        assert_eq!(mode, "hub_relay");
        let (ok, mode, _) = dial_verdict(None);
        assert!(!ok);
        assert_eq!(mode, "hub_relay");
    }

    /// 直连对端视图合并：候选已直连/待握手取链路状态；候选无路径标
    /// `hub_relay`（可拨号）；候选集外但链路在管的对端不进视图（候选集为
    /// 服务端下发的可直连集合，视图只反映它）。
    #[test]
    fn direct_peer_views_merges_candidates_with_link_status() {
        use meshlet_domain::EndpointCandidate;
        let wanted = vec![
            meshlet_domain::PeerEndpoints {
                device_id: meshlet_domain::DeviceId("a".into()),
                public_key: "key-a".into(),
                virtual_ipv4: "10.240.0.3".parse().unwrap(),
                name: "peer-a".into(),
                endpoints: vec![EndpointCandidate::lan(
                    "192.168.1.50".parse().unwrap(),
                    51821,
                )],
            },
            meshlet_domain::PeerEndpoints {
                device_id: meshlet_domain::DeviceId("b".into()),
                public_key: "key-b".into(),
                virtual_ipv4: "10.240.0.4".parse().unwrap(),
                name: "peer-b".into(),
                endpoints: vec![EndpointCandidate::lan(
                    "192.168.1.60".parse().unwrap(),
                    51821,
                )],
            },
        ];
        let links = vec![DirectLinkStatus {
            public_key: "key-a".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            link_state: "direct".into(),
            last_handshake_age_secs: Some(7),
            peer_name: "peer-a".into(),
            connection_mode: "p2p_direct".into(),
            endpoint: "192.168.1.50:51821".into(),
            rtt_ms: Some(5),
            rtt_source: Some("overlay".into()),
            last_handshake_at: Some(1_700_000_000),
            rx_bytes: 0,
            tx_bytes: 0,
            candidates: vec![],
        }];
        let views = direct_peer_views(&wanted, &links);
        assert_eq!(views.len(), 2);
        // 已直连：取链路状态（mode/rtt/endpoint）。
        let a = views.iter().find(|v| v.public_key == "key-a").unwrap();
        assert_eq!(a.mode, "p2p_direct");
        assert_eq!(a.rtt_ms, Some(5));
        assert_eq!(a.endpoint, "192.168.1.50:51821");
        // 候选无路径：标 hub_relay（可拨号目标）。
        let b = views.iter().find(|v| v.public_key == "key-b").unwrap();
        assert_eq!(b.mode, "hub_relay");
        assert_eq!(b.rtt_ms, None);
        assert_eq!(b.endpoint, "");
    }

    #[test]
    fn parse_endpoint_candidate_reads_ip_port_and_kind() {
        use meshlet_domain::EndpointKind;
        // 私网 → Lan；畸形/空 → None。
        let lan = parse_endpoint_candidate("192.168.1.50:51821").expect("lan parses");
        assert_eq!(lan.ip, "192.168.1.50".parse::<Ipv4Addr>().unwrap());
        assert_eq!(lan.port, 51821);
        assert_eq!(lan.kind, EndpointKind::Lan);
        let public = parse_endpoint_candidate("203.0.113.10:51820").expect("public parses");
        assert_eq!(public.kind, EndpointKind::Public);
        assert!(parse_endpoint_candidate("").is_none());
        assert!(parse_endpoint_candidate("192.168.1.50").is_none());
        assert!(parse_endpoint_candidate("not-an-ip:51821").is_none());
        assert!(parse_endpoint_candidate("192.168.1.50:99999").is_none());
    }

    #[test]
    fn enforce_hub_keepalive_raises_none_or_low_to_floor() {
        use meshlet_network::PeerConfig;
        use meshlet_network::TunnelConfig;
        let mk = |ka: Option<u32>| DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "wg0".into(),
                address: "10.240.0.7".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![PeerConfig {
                    public_key: "hub-pub".into(),
                    allowed_ips: vec![],
                    endpoint: None,
                    persistent_keepalive_secs: ka,
                }],
                mtu: None,
                private_key: None,
            },
            routes: vec![],
            nat_rules: vec![],
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: "h".into(),
        };
        // 旧版计划缺省 None → 抬到 floor。
        let mut plan = mk(None);
        enforce_hub_keepalive(&mut plan);
        assert_eq!(
            plan.tunnel.peers[0].persistent_keepalive_secs,
            Some(meshlet_network::HUB_KEEPALIVE_SECS)
        );
        // 计划给低于 floor 的值 → 抬到 floor。
        let mut plan = mk(Some(5));
        enforce_hub_keepalive(&mut plan);
        assert_eq!(
            plan.tunnel.peers[0].persistent_keepalive_secs,
            Some(meshlet_network::HUB_KEEPALIVE_SECS)
        );
        // 计划给更高值 → 尊重（永不掉）。
        let mut plan = mk(Some(30));
        enforce_hub_keepalive(&mut plan);
        assert_eq!(plan.tunnel.peers[0].persistent_keepalive_secs, Some(30));
        // 空 peer 列表 → no-op。
        let mut plan = mk(None);
        plan.tunnel.peers.clear();
        enforce_hub_keepalive(&mut plan);
        assert!(plan.tunnel.peers.is_empty());
    }
}
