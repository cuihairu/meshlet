#[cfg(test)]
// This file is included via `mod tests;`; naming the inner module tests again would
// trigger module_inception - a test-organization convention, not a flaw, so allow it locally.
#[allow(clippy::module_inception)]
mod tests {
    use std::path::Path;

    use meshlet_config::{AgentConfig, DataplaneConfig, TrayConfig};
    use meshlet_domain::PeerLinkState;
    use std::net::Ipv4Addr;

    use crate::agent::direct_report::direct_report_from;
    use crate::direct_rtt::RttProbe;
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
            mcp: meshlet_config::McpConfig::OFF,
        }
    }

    #[test]
    fn private_key_is_read_trimmed_and_absent_is_ok() {
        // No private key configured: None (keep the interface's existing key; idempotent replay).
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

        // Empty file: an explicit error, not treated as "unconfigured" (first install would otherwise fail the handshake).
        std::fs::write(&path, "\n").unwrap();
        assert!(read_private_key(&dp).is_err());

        // Missing file: a wrong path must be visible.
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
        let agent = Agent::new(config("/var/lib/meshlet"), None).expect("test agent builds");
        assert_eq!(
            agent.state_path(),
            Path::new("/var/lib/meshlet/applied.json")
        );
    }

    #[test]
    fn heartbeat_against_a_dead_server_fails_visibly() {
        // Reaching a dead server errors (visibly) instead of silently "succeeding" - the tick backs off and retries on it.
        let agent = Agent::new(config("/tmp/meshlet-agent-dead"), None).expect("test agent builds");
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
        // The server plan carries no endpoint (§16.4: the server does not know the agent's network location).
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        p.tunnel.peers.push(meshlet_network::PeerConfig {
            public_key: "hub-pub".into(),
            allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        });

        // Local fallback fill -> the device can initiate the handshake itself.
        let filled = plan_with_hub_endpoint(&p, Some("10.98.0.10:51820"));
        assert_eq!(
            filled.tunnel.peers[0].endpoint.as_deref(),
            Some("10.98.0.10:51820")
        );
        // The hash is not rewritten by the local fallback: the ledger and drift verdict still follow the server's expectation.
        assert_eq!(filled.desired_config_hash, p.desired_config_hash);

        // The server already carries a value (a future advertised endpoint) -> respect the server, no overwrite.
        let mut explicit = p.clone();
        explicit.tunnel.peers[0].endpoint = Some("10.98.0.99:51820".into());
        assert_eq!(
            plan_with_hub_endpoint(&explicit, Some("10.98.0.10:51820"))
                .tunnel
                .peers[0]
                .endpoint,
            explicit.tunnel.peers[0].endpoint
        );

        // No fallback configured -> returned unchanged; an empty-peer plan never goes out of bounds.
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

        // Plan without an MTU: probe with the default 1420 (1420 - 28 = 1392).
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, None),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );

        // Unknown hub / the hub is this machine (a self-ping does not traverse the tunnel) / zero payload: no probe.
        let p = probe_plan(Some(1380), None, "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
        let p = probe_plan(Some(1380), Some("10.240.0.7"), "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
        let p = probe_plan(Some(28), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
    }

    /// The four honest rtt_source states: a successful measurement is probe_ok; unmeasurable with a fresh handshake is
    /// handshake_fresh ("unmeasurable" no longer lies about the link); a stale handshake is probe_failed; not yet probed is unprobed.
    #[test]
    fn rtt_source_is_honest_about_handshake_evidence() {
        let now = 1_800_000_000u64;
        // Successful measurement: the source is probe_ok regardless of handshake state.
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
        // Unmeasurable (both ping paths silent) + a fresh handshake -> handshake_fresh (the link is alive).
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
        // Unmeasurable + the handshake past the promote threshold -> honestly probe_failed (no more "unmeasurable = alive" lies).
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
        // Not yet probed (probe in flight) + no handshake -> unprobed (not a verdict).
        assert_eq!(
            honest_rtt_source(&RttProbe::unknown(), None, now),
            Some("unprobed")
        );
        // Never handshaked (ts=0) does not count as fresh evidence.
        assert_eq!(
            honest_rtt_source(&RttProbe::unknown(), Some(0), now),
            Some("unprobed")
        );
    }

    /// Diagnostics dump -> handshake ages: never-handshaked / clock-skewed rows are dropped, the rest translated to age-in-seconds.
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
        // No snapshot -> empty (missing evidence is never fabricated).
        assert!(dump_handshake_ages(None, now).is_empty());
    }

    #[test]
    fn probe_payload_adapts_to_the_underlay_when_plan_leaves_mtu_unset() {
        // Plan pins the MTU: the plan wins, the underlay reading does not affect the probe payload.
        let p = probe_plan(Some(1380), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, Some(9000)),
            Some(("10.240.0.1".parse().unwrap(), 1352))
        );

        // Plan unconfigured: derived from the underlay MTU. 1500 Ethernet derives back to 1420 (default
        // behavior unchanged); jumbo 9000 -> 8920 - 28; PPPoE 1492 -> 1412 - 28.
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

        // Underlay reading unavailable: fall back to the WireGuard default (behavior matches the old version).
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

        // Single segment: the sole AllowedIPs entry is the scope.
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.0.2");
        p.tunnel.peers.push(hub(&["10.240.0.0/16"]));
        assert_eq!(
            direct_scope(&p),
            Some("10.240.0.0/16".parse::<Ipv4Cidr>().unwrap())
        );

        // Segmented routing: multiple AllowedIPs entries in no guaranteed order - the one containing this
        // machine's address is the scope (not `allowed_ips[0]`).
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.1.2");
        p.tunnel
            .peers
            .push(hub(&["10.240.0.0/16", "10.240.1.0/24"]));
        assert_eq!(
            direct_scope(&p),
            Some("10.240.1.0/24".parse::<Ipv4Cidr>().unwrap())
        );

        // No hub peer / this machine's address outside every segment: None (stay on hub relay, no guessing).
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.2");
        assert_eq!(direct_scope(&p), None);
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.250.0.2");
        p.tunnel.peers.push(hub(&["10.240.0.0/16"]));
        assert_eq!(direct_scope(&p), None);
    }

    #[test]
    fn direct_report_gates_on_resolved_port_and_carries_it() {
        let report = direct_report_from(Some(51820), vec!["192.168.1.50".parse().unwrap()])
            .expect("resolved");
        assert_eq!(report.listen_port, 51820);
        assert_eq!(
            report.lan_addrs,
            vec!["192.168.1.50".parse::<Ipv4Addr>().unwrap()]
        );

        // Empty candidates are still valid (the peer may try the publicly observed address).
        let report = direct_report_from(Some(51820), vec![]).expect("empty candidates");
        assert!(report.lan_addrs.is_empty());

        // Effective port missing (disabled / unresolved / all candidates blocked shut by WIN-PORT-1 B2):
        // the report is omitted (None), no endpoint fabricated - reporting a port this machine cannot bind just points the peer at a dead port.
        assert_eq!(direct_report_from(None, vec![]), None);
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

    /// `peer dial` verdict: Direct/Pending = success; Relay/unmanaged = failure (never
    /// pretend to succeed).
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
            last_direct: None,
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

    /// Direct-peer view merge: candidates already direct/pending take the link status; a candidate with no
    /// path is marked `hub_relay` (dialable); peers outside the candidate set but with a managed link do not
    /// enter the view (the candidate set is the server-delivered direct-connect set, and the view only reflects it).
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
        // Already direct: take the link status (mode/rtt/endpoint).
        let a = views.iter().find(|v| v.public_key == "key-a").unwrap();
        assert_eq!(a.mode, "p2p_direct");
        assert_eq!(a.rtt_ms, Some(5));
        assert_eq!(a.endpoint, "192.168.1.50:51821");
        // Candidate with no path: marked hub_relay (a dialable target).
        let b = views.iter().find(|v| v.public_key == "key-b").unwrap();
        assert_eq!(b.mode, "hub_relay");
        assert_eq!(b.rtt_ms, None);
        assert_eq!(b.endpoint, "");
    }

    #[test]
    fn parse_endpoint_candidate_reads_ip_port_and_kind() {
        use meshlet_domain::EndpointKind;
        // Private network -> Lan; malformed/empty -> None.
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
        // Old-version plan defaulting to None -> raised to the floor.
        let mut plan = mk(None);
        enforce_hub_keepalive(&mut plan);
        assert_eq!(
            plan.tunnel.peers[0].persistent_keepalive_secs,
            Some(meshlet_network::HUB_KEEPALIVE_SECS)
        );
        // Plan value below the floor -> raised to the floor.
        let mut plan = mk(Some(5));
        enforce_hub_keepalive(&mut plan);
        assert_eq!(
            plan.tunnel.peers[0].persistent_keepalive_secs,
            Some(meshlet_network::HUB_KEEPALIVE_SECS)
        );
        // Plan value higher -> respected (never dropped).
        let mut plan = mk(Some(30));
        enforce_hub_keepalive(&mut plan);
        assert_eq!(plan.tunnel.peers[0].persistent_keepalive_secs, Some(30));
        // Empty peer list -> no-op.
        let mut plan = mk(None);
        plan.tunnel.peers.clear();
        enforce_hub_keepalive(&mut plan);
        assert!(plan.tunnel.peers.is_empty());
    }
}
