use super::*;
use crate::{parse_handshake_ages, NetworkBackend, NetworkError, TunnelConfig, DEFAULT_TUNNEL_MTU};
use meshlet_domain::Ipv4Cidr;
use std::net::Ipv4Addr;

// The file itself is pulled in via `mod tests;`, and calling the inner module
// `tests` again would trigger module_inception;
// that is a test-organization convention rather than a defect, allowed locally.
#[allow(clippy::module_inception)]
mod tests {
    use super::*;
    use crate::nat::{NatAction, NatChain, NatRule};

    #[test]
    fn ip_octet_subnets_mask_interface_host_bits_into_the_lan_subnet() {
        // The addresses of `ip -4 -o addr show` carry host bits (an interface
        // address is not a network address) —
        // regression: parsing as a normalized CIDR once failed the whole line,
        // the LAN enumeration was always empty, and direct connect never
        // fired (caught by the netns real-machine test).
        let output = "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                      2: wg0    inet 10.240.0.2/24 scope global wg0\\\n\
                      18623: eth0    inet 10.98.0.20/24 brd 10.98.0.255 scope global eth0\\\n";
        let subnets = parse_ip_octet_subnets(output);
        assert_eq!(subnets.len(), 3, "every addr line parses, host bits masked");
        assert_eq!(subnets[0].1.to_string(), "127.0.0.0/8");
        assert_eq!(subnets[1].1.to_string(), "10.240.0.0/24");
        assert_eq!(subnets[2].0, "eth0");
        assert_eq!(subnets[2].1.to_string(), "10.98.0.0/24");

        // Filtering under the same convention as lan_subnets_sync: lo/the
        // managed tunnel are out, non-private is out
        // -> only eth0's segment is left.
        let lan: Vec<String> = subnets
            .iter()
            .filter(|(ifname, _)| is_lan_interface(ifname, "wg0"))
            .map(|(_, subnet)| subnet)
            .filter(|subnet| meshlet_domain::is_private_ip(subnet.network()))
            .map(|subnet| subnet.to_string())
            .collect();
        assert_eq!(lan, vec!["10.98.0.0/24"]);

        // Lines with an out-of-range prefix or a non-address are skipped
        // without panicking.
        assert!(parse_ip_octet_subnets("3: eth1 inet 1.2.3.4/99 x\n").is_empty());
        assert!(parse_ip_octet_subnets("3: eth1 inet junk/24 x\n").is_empty());
    }

    #[test]
    fn handshake_ages_parses_peer_lines_and_skips_never_handshaked() {
        // The standard three columns: public key, handshake time, seconds ago.
        let pk_a = "A".repeat(43) + "=";
        let pk_b = "B".repeat(43) + "=";
        // A peer that never handshaked: its handshake timestamp is 0 (WireGuard
        // semantics), not "0 seconds ago".
        let text = format!("{pk_a} 1750000000 12\n{pk_b} 0 0\nnot-a-key 1750000000 5\n");
        let ages = parse_handshake_ages(&text, 1750000060);
        assert_eq!(ages.len(), 1, "zero-handshake and junk lines are skipped");
        assert_eq!(ages.get(&pk_a), Some(&12));

        // Missing third column: fall back to now - handshake time.
        let two_col = format!("{pk_b} 1750000000\n");
        let ages = parse_handshake_ages(&two_col, 1750000060);
        assert_eq!(ages.get(&pk_b), Some(&60));
    }

    #[test]
    fn mtu_readback_enforces_the_default_like_an_explicit_value() {
        let link_at = |mtu: u32| {
            format!(
                "523: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu {mtu} qdisc noqueue state UNKNOWN"
            )
        };
        // Unset plan means the default 1420: an interface left higher by an old
        // plan must read as drifted (regression: the check used to be skipped
        // entirely for unset plans, so 1480 never converged back).
        assert!(!mtu_matches_planned(&link_at(1480), None));
        assert!(mtu_matches_planned(&link_at(1420), None));
        assert!(mtu_matches_planned(&link_at(1420), Some(1420)));
        // An explicit plan value must match exactly, higher or lower.
        assert!(!mtu_matches_planned(&link_at(1420), Some(1380)));
        assert!(mtu_matches_planned(&link_at(1380), Some(1380)));
        // A missing/unparseable mtu field never counts as a match.
        assert!(!mtu_matches_planned(
            "523: wg0: <POINTOPOINT,NOARP,UP> qdisc noqueue state UNKNOWN",
            None
        ));
        assert_eq!(enforced_tunnel_mtu(None), DEFAULT_TUNNEL_MTU);
        assert_eq!(enforced_tunnel_mtu(Some(1380)), 1380);
    }

    #[test]
    fn route_source_uses_kernel_selection_and_rejects_unsafe_egress() {
        assert_eq!(
            route_source("192.168.1.5 dev eth0 src 192.168.1.1 uid 0\n cache", "wg0"),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(
            route_source(
                "192.168.2.5 via 192.168.1.2 dev eth0 src 192.168.1.9",
                "wg0"
            ),
            Some("192.168.1.9".parse().unwrap())
        );
        for output in [
            "192.168.1.5 dev wg0 src 10.240.0.2",
            "local 192.168.1.1 dev lo src 192.168.1.1",
            "broadcast 192.168.1.255 dev eth0 src 192.168.1.1",
            "unreachable 192.168.1.5",
            "blackhole 192.168.1.5",
            "192.168.1.5 dev eth0",
            "192.168.1.5 src 192.168.1.1",
            "192.168.1.5 dev eth0 src bad",
            "",
        ] {
            assert_eq!(route_source(output, "wg0"), None, "{output}");
        }
    }

    #[test]
    fn parses_ip_octet_addr_output_and_filters_non_lan() {
        let out = "\
1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.0.0.5/16 scope global eth0\\       valid_lft forever preferred_lft forever
3: wg0    inet 10.240.0.2/32 scope global wg0\\       valid_lft forever preferred_lft forever
4: docker0    inet 172.17.0.1/16 scope global docker0\\       valid_lft forever preferred_lft forever
5: br-1234    inet 172.18.0.1/16 scope global br-1234\\       valid_lft forever preferred_lft forever
";
        let parsed = parse_ip_octet_addrs(out);
        let addrs: Vec<Ipv4Addr> = parsed
            .iter()
            .filter(|(ifname, _)| is_lan_interface(ifname, "wg0"))
            .map(|(_, addr)| *addr)
            .collect();
        // eth0's two RFC1918 addresses are kept; lo/wg0/docker0/br-* are all
        // excluded.
        assert_eq!(
            addrs,
            vec![
                "192.168.1.50".parse::<Ipv4Addr>().unwrap(),
                "10.0.0.5".parse().unwrap()
            ]
        );
        assert!(!is_lan_interface("lo", "wg0"));
        assert!(!is_lan_interface("wg0", "wg0"));
        assert!(!is_lan_interface("wg9", "wg0")); // other wg interfaces are
                                                  // excluded the same way
                                                  // A foreign overlay (ZeroTier's `zt*` interfaces) is out too: keeping it
                                                  // would treat its segment as this host's LAN, the peer's ZT address would
                                                  // be judged same-segment direct connect -> the WG endpoint would ride the
                                                  // other tunnel into a loop.
        assert!(!is_lan_interface("ztksetoehl", "wg0"));
        assert!(!is_lan_interface("ztabc123def", "wg0"));
        assert!(is_lan_interface("eth0", "wg0"));
        assert!(is_lan_interface("enp2s0", "wg0"));
        assert!(is_lan_interface("ens18", "wg0"));
    }

    #[test]
    fn split_iptables_line_keeps_quoted_comment_as_one_token() {
        let line = "-A PREROUTING -d 10.241.1.0/24 -j NETMAP --to 192.168.1.0/24 \
            -m comment --comment \"meshlet alias al-1\"";
        let tokens = LinuxNetworkBackend::split_iptables_line(line);
        assert_eq!(tokens[0], "-A");
        assert_eq!(tokens[1], "PREROUTING");
        let idx = tokens.iter().position(|t| t == "--comment").unwrap();
        assert_eq!(tokens[idx + 1], "meshlet alias al-1");
    }

    #[test]
    fn meshlet_rule_deletion_matches_ownership_comment() {
        let line = "-A POSTROUTING -d 192.168.1.0/24 -j SNAT --to-source 192.168.1.1 \
            -m comment --comment \"meshlet alias al-1\"";
        let del = LinuxNetworkBackend::meshlet_rule_deletion(line, None).unwrap();
        assert_eq!(del[0], "-D");
        assert_eq!(del[1], "POSTROUTING");
        assert_eq!(del[2], "-d");

        // Exact owner matching: al-1's rule is not hit by al-2's cleanup.
        assert!(
            LinuxNetworkBackend::meshlet_rule_deletion(line, Some("meshlet alias al-2")).is_none()
        );
        assert!(
            LinuxNetworkBackend::meshlet_rule_deletion(line, Some("meshlet alias al-1")).is_some()
        );

        // Non-Meshlet rules (no comment / a user comment) are not hit.
        assert!(LinuxNetworkBackend::meshlet_rule_deletion(
            "-A PREROUTING -d 203.0.113.0/24 -j ACCEPT -m comment --comment \"user rule\"",
            None
        )
        .is_none());
        assert!(LinuxNetworkBackend::meshlet_rule_deletion(
            "-A PREROUTING -d 10.241.1.0/24 -j NETMAP --to 192.168.1.0/24",
            None
        )
        .is_none());
        // Non-rule lines (comment headers / chain declarations) are not hit.
        assert!(
            LinuxNetworkBackend::meshlet_rule_deletion(":PREROUTING ACCEPT [0:0]", None).is_none()
        );
    }

    #[test]
    fn parse_default_route_interface_reads_the_dev_token() {
        assert_eq!(
            parse_default_route_interface(
                "default via 192.168.1.1 dev ens18 proto dhcp metric 100\n"
            ),
            Some("ens18".to_string())
        );
        assert_eq!(
            parse_default_route_interface("default dev wg0 scope link\n"),
            Some("wg0".to_string())
        );
        assert_eq!(parse_default_route_interface(""), None);
        assert_eq!(parse_default_route_interface("unreachable default\n"), None);
    }

    #[test]
    fn parse_link_mtu_reads_the_first_mtu_field() {
        let link_show = "7: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1380 \
            qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\n\
            \x20   link/none";
        assert_eq!(parse_link_mtu(link_show), Some(1380));

        // When a reading is unavailable (a missing field / non-numeric), it is
        // treated as None rather than guessing a default.
        assert_eq!(
            parse_link_mtu("7: wg0: <...> state UNKNOWN\n link/none"),
            None
        );
        assert_eq!(parse_link_mtu("7: wg0: mtu junk qdisc"), None);
    }

    #[test]
    fn parse_ping_rtt_ms_reads_normal_and_sub_millisecond_values() {
        assert_eq!(
            super::parse_ping_rtt_ms("64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time=12.3 ms"),
            Some(12)
        );
        assert_eq!(
            super::parse_ping_rtt_ms("64 bytes from 10.0.0.2: icmp_seq=1 ttl=64 time<1.0 ms"),
            Some(1)
        );
        assert_eq!(
            super::parse_ping_rtt_ms("ping: sendmsg: Destination host unreachable"),
            None
        );
    }

    #[test]
    fn parse_wg_dump_diag_line_reads_peer_readings() {
        // A peer line of Linux `wg show dump`: pubkey preshared endpoint
        // allowed-ips latest-handshake rx tx keepalive.
        let line = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= (preshared) 198.51.100.10:51820 \
            10.240.0.1/32,10.241.0.0/24 1234567 1024 2048 25";
        let diag = super::parse_wg_dump_diag_line(line).expect("valid line");
        assert_eq!(
            diag.public_key,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
        assert_eq!(diag.endpoint, "198.51.100.10:51820");
        assert_eq!(diag.allowed_ips, "10.240.0.1/32,10.241.0.0/24");
        assert_eq!(diag.last_handshake, 1234567);
        assert_eq!(diag.rx_bytes, 1024);
        assert_eq!(diag.tx_bytes, 2048);

        // A missing column / an empty line / a non-public-key line -> None (never
        // inventing a peer).
        assert!(super::parse_wg_dump_diag_line("").is_none());
        assert!(super::parse_wg_dump_diag_line("short-row").is_none());
        assert!(super::parse_wg_dump_diag_line("bad-key not-a-peer").is_none());
    }

    #[test]
    fn wg_dump_diag_defaults_missing_numeric_columns_to_zero() {
        // When the endpoint/traffic columns are missing, default to 0/empty
        // strings (the unavailable reading stays visible, the line is not
        // swallowed).
        let diag =
            super::parse_wg_dump_diag_line("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= x y")
                .expect("row");
        assert_eq!(diag.endpoint, "y");
        assert_eq!(diag.last_handshake, 0);
        assert_eq!(diag.rx_bytes, 0);
        assert_eq!(diag.tx_bytes, 0);
    }

    #[test]
    fn nat_apply_probes_with_the_same_rule_shape() {
        // apply_nat_sync assembles `iptables -t nat <args>`; the -C probe and the
        // -A application differ only in the flag position (index 3), keeping the
        // probe and the real rule in the same shape.
        let rule = NatRule {
            source_cidr: None,
            incoming_interface: None,
            chain: NatChain::Prerouting,
            match_dest: "10.241.1.0/24".parse().unwrap(),
            action: NatAction::NetMap {
                to: "192.168.1.0/24".parse().unwrap(),
            },
            owner: "meshlet alias al-1".into(),
        };
        let mut args = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
        args.extend(rule.iptables_args(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(args[3], "-A");
        let probe: Vec<&str> = args
            .iter()
            .enumerate()
            .map(|(i, s)| if i == 3 { "-C" } else { s.as_str() })
            .collect();
        assert_eq!(probe[3], "-C");
        assert_eq!(probe[..3], args[..3]);
        assert_eq!(probe[4..], args[4..]);
    }

    #[tokio::test]
    async fn foreign_tunnel_name_is_rejected() {
        // The backend only manages its own interface: another tunnel name is
        // refused (protecting against clobbering a system interface).
        let backend = LinuxNetworkBackend::new();
        let config = TunnelConfig {
            name: "wg-user".into(),
            address: Ipv4Addr::new(10, 240, 0, 1),
            address_prefix: 24,
            listen_port: None,
            peers: vec![],
            mtu: None,
            private_key: None,
        };
        let result = backend.apply_tunnel(config).await;
        assert!(matches!(result, Err(NetworkError::ApplyRejected(_))));
    }

    #[test]
    fn snat_target_cidr_picks_only_the_controlled_snat_rule() {
        use crate::nat::{alias_nat_rules, NatChain};
        use meshlet_domain::{AliasMappingId, LanRouteId, NetworkId, TranslationMode};

        let mapping = meshlet_domain::AliasMapping::new(
            AliasMappingId("al-9".into()),
            NetworkId("net-1".into()),
            LanRouteId("rt-9".into()),
            "10.241.9.0/24".parse().unwrap(),
            "192.168.9.0/24".parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap();
        let rules = alias_nat_rules(&mapping);
        // The plan holds two rules: DNAT matches the alias, SNAT the target (the
        // real LAN segment).
        assert_eq!(
            LinuxNetworkBackend::snat_target_cidr(&rules),
            Some("192.168.9.0/24".parse().unwrap())
        );

        // A dnat_only plan has no SNAT rule — the gateway LAN address does not
        // apply (§9.5).
        let dnat_only: Vec<NatRule> = rules
            .iter()
            .filter(|r| r.chain == NatChain::Prerouting)
            .cloned()
            .collect();
        assert!(LinuxNetworkBackend::snat_target_cidr(&dnat_only).is_none());
    }

    #[test]
    fn foreign_route_line_flags_routes_on_other_paths() {
        // Marked routes on the managed interface remain Meshlet-owned even
        // when their proto appears in exact output; other-interface paths are
        // conflicts and are named verbatim.
        let via = "10.244.0.0/24 via 10.99.0.1 dev eth0";
        assert_eq!(foreign_route_line(via, "wg0").as_deref(), Some(via));
        assert_eq!(
            foreign_route_line("10.244.0.0/24 dev eth0", "wg0").as_deref(),
            Some("10.244.0.0/24 dev eth0")
        );

        // Through the managed interface: a Meshlet-owned object, and an idempotent
        // rewrite is not a conflict.
        assert!(foreign_route_line("10.241.1.0/24 via 10.240.0.4 dev wg0", "wg0").is_none());
    }

    #[test]
    fn foreign_route_line_fails_closed_without_a_dev_field() {
        // blackhole / a changed output format: failing to parse a dev field is
        // treated as a conflict, never letting an unknown object through (fail
        // closed).
        assert_eq!(
            foreign_route_line("blackhole 10.244.0.0/24", "wg0").as_deref(),
            Some("blackhole 10.244.0.0/24")
        );
        assert!(foreign_route_line("10.244.0.0/24", "wg0").is_some());
    }

    #[test]
    fn connected_route_line_is_not_a_conflict_on_its_own_interface() {
        // A connected route (proto kernel, the address is self-carried): the dev
        // field still appears in the exact output, and going through the managed
        // interface is not a conflict.
        let line = "10.240.0.0/24 proto kernel scope link src 10.240.0.1 dev wg0";
        assert!(foreign_route_line(line, "wg0").is_none());
    }

    #[test]
    fn peer_dump_line_yields_identity_not_a_count() {
        // The dump column order: pubkey presharedkey endpoint allowed-ips ... (an
        // endpoint of none and an empty allowed-ips string are the normal state of
        // an unhandshaked peer). allowed-ips are comma-joined with **no spaces**
        // (the field-tested `wg show dump` output).
        let key = "B".repeat(43) + "=";
        let peer = LinuxNetworkBackend::parse_peer_dump_line(&format!(
            "{key} (none) 10.240.0.3:16190 10.240.0.3/32,10.241.1.0/24 0 0 0 0"
        ))
        .unwrap();
        assert_eq!(peer.public_key, key);
        assert_eq!(
            peer.allowed_ips,
            vec![
                "10.240.0.3/32".parse::<Ipv4Cidr>().unwrap(),
                "10.241.1.0/24".parse::<Ipv4Cidr>().unwrap(),
            ]
        );

        // A peer that has not handshaked and allows no prefix: an empty
        // allowed-ips is a legal state, not "a peer is missing".
        let none = LinuxNetworkBackend::parse_peer_dump_line(&format!(
            "{key} (none) (none) (none) 0 0 0 0"
        ))
        .unwrap();
        assert!(none.allowed_ips.is_empty());

        // A mangled line missing the 44-character public key yields no peer
        // (never inventing an identity).
        assert!(LinuxNetworkBackend::parse_peer_dump_line("(none) 10.240.0.3/32 0 0 0").is_none());
        assert!(LinuxNetworkBackend::parse_peer_dump_line("tooshort").is_none());
    }

    #[test]
    fn nat_signature_round_trips_through_kernel_rendering() {
        // The plan-side fingerprint must be readable back to the same value from
        // the iptables arguments rendered by the kernel — both sides compare
        // exactly as sets on it, and a shape mismatch would mean drift is
        // invisible. The field order of `-S` (`-s` before `-d`, `-m comment`
        // before `-j`) is used rather than the order of `iptables_args`,
        // proving the parsing is independent of the field order.
        let rules = [
            NatRule {
                source_cidr: Some("10.240.0.0/16".parse().unwrap()),
                incoming_interface: Some("wg0".into()),
                chain: NatChain::Prerouting,
                match_dest: "10.241.1.0/24".parse().unwrap(),
                action: NatAction::NetMap {
                    to: "192.168.1.0/24".parse().unwrap(),
                },
                owner: "meshlet alias al-2".into(),
            },
            // POSTROUTING does not render `-i`: `incoming_interface` is inert
            // metadata for it, and both sides must align on `none` (an SNAT rule
            // already inside the table was once misjudged as surplus this
            // way).
            NatRule {
                source_cidr: Some("10.240.0.0/16".parse().unwrap()),
                incoming_interface: Some("wg0".into()),
                chain: NatChain::Postrouting,
                match_dest: "192.168.1.0/24".parse().unwrap(),
                action: NatAction::SnatToGatewayLan,
                owner: "meshlet alias al-2".into(),
            },
        ];
        for rule in &rules {
            let rendered = rule.iptables_args("192.168.1.1".parse().unwrap());
            let kernel: Vec<String> = rendered
                .iter()
                .map(|arg| {
                    if arg == "-A" {
                        "-D".to_string()
                    } else {
                        arg.clone()
                    }
                })
                .collect();
            let [_, chain, rest @ ..] = kernel.as_slice() else {
                panic!("malformed rendering: {rendered:?}")
            };
            let signature = LinuxNetworkBackend::nat_rule_signature_from_iptables(chain, rest)
                .unwrap_or_else(|| panic!("unparsable rendering: {rendered:?}"));
            assert_eq!(signature, rule.signature(), "plan vs kernel fingerprint");
        }
    }

    #[test]
    fn nat_signature_rejects_shapes_the_renderer_never_emits() {
        // Claims Meshlet ownership but with a shape beyond what this gateway's
        // renderer emits -> no fingerprint is produced:
        // neither pretending to be a planned rule nor being mis-deleted by the
        // set-difference cleanup (left to the whole-unit cleanup path).
        let unparsable = [
            (
                "POSTROUTING",
                vec![
                    "-d".to_string(),
                    "203.0.113.0/24".into(),
                    "-j".into(),
                    "MASQUERADE".into(),
                    "-m".into(),
                    "comment".into(),
                    "--comment".into(),
                    "meshlet alias al-9".into(),
                ],
            ),
            (
                "POSTROUTING",
                vec![
                    "-d".to_string(),
                    "203.0.113.0/24".into(),
                    "-j".into(),
                    "SNAT".into(),
                    "--to-source".into(),
                    "192.168.1.1".into(),
                ],
            ),
            (
                "PREROUTING",
                vec![
                    "-j".to_string(),
                    "NETMAP".into(),
                    "--to".into(),
                    "192.168.1.0/24".into(),
                    "--comment".into(),
                    "meshlet alias al-9".into(),
                ],
            ),
        ];
        for (chain, args) in unparsable {
            assert!(
                LinuxNetworkBackend::nat_rule_signature_from_iptables(chain, &args).is_none(),
                "{chain} {args:?}"
            );
        }

        // A non-Meshlet-comment rule brings its own comment with it: its
        // fingerprint can never collide with any plan-side fingerprint, so the
        // set-difference cleanup never reaches it.
        let foreign = vec![
            "-d".to_string(),
            "10.0.0.0/24".into(),
            "-j".into(),
            "SNAT".into(),
            "--to-source".into(),
            "192.168.1.1".into(),
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            "user rule".into(),
        ];
        let signature =
            LinuxNetworkBackend::nat_rule_signature_from_iptables("POSTROUTING", &foreign).unwrap();
        assert!(signature.contains("|user rule|"));
    }

    #[test]
    fn host_firewall_plan_is_idempotent_and_manager_gated() {
        // No manager active -> no action (whether an allowance rule exists or not
        // does not matter).
        assert!(host_firewall_allow_actions(false, false, false, false, "wg0").is_empty());
        assert!(host_firewall_allow_actions(false, true, false, true, "wg0").is_empty());

        // ufw active and the interface already allowed -> supplement only the
        // firewalld side (if any).
        assert_eq!(
            host_firewall_allow_actions(true, true, false, false, "wg0"),
            vec![]
        );
        assert_eq!(
            host_firewall_allow_actions(true, false, false, false, "wg0"),
            vec![HostFirewallAction::UfwAllowInOn {
                interface: "wg0".into()
            }]
        );

        // firewalld active and the interface not in trusted -> supplement the
        // trusted interface.
        assert_eq!(
            host_firewall_allow_actions(false, false, true, false, "wg0"),
            vec![HostFirewallAction::FirewalldTrustedInterface {
                interface: "wg0".into()
            }]
        );

        // Both managers active and both not allowed -> two actions, in a fixed
        // order (ufw first).
        assert_eq!(
            host_firewall_allow_actions(true, false, true, false, "wg0"),
            vec![
                HostFirewallAction::UfwAllowInOn {
                    interface: "wg0".into()
                },
                HostFirewallAction::FirewalldTrustedInterface {
                    interface: "wg0".into()
                },
            ]
        );
    }

    #[test]
    fn direct_udp_firewall_plan_is_idempotent_and_manager_gated() {
        // Manager not active -> no action; already allowed -> no action
        // (idempotent).
        assert!(direct_udp_firewall_allow_actions(false, false, false, false, 51820).is_empty());
        assert!(direct_udp_firewall_allow_actions(true, true, false, false, 51820).is_empty());
        assert!(direct_udp_firewall_allow_actions(false, false, true, true, 51820).is_empty());

        // ufw active and the port not allowed -> open by port.
        assert_eq!(
            direct_udp_firewall_allow_actions(true, false, false, false, 51820),
            vec![HostFirewallAction::UfwAllowPort { port: 51820 }]
        );

        // firewalld active and the port not allowed -> open as a trusted
        // port.
        assert_eq!(
            direct_udp_firewall_allow_actions(false, false, true, false, 51820),
            vec![HostFirewallAction::FirewalldAllowPort { port: 51820 }]
        );

        // Both managers active and both not allowed -> two actions, in a fixed
        // order (ufw first).
        assert_eq!(
            direct_udp_firewall_allow_actions(true, false, true, false, 20000),
            vec![
                HostFirewallAction::UfwAllowPort { port: 20000 },
                HostFirewallAction::FirewalldAllowPort { port: 20000 },
            ]
        );
    }

    // -------------------------------------- AGENT-ISO-1 foreign overlay isolation ----

    /// A full identity -> all rules present: the outbound owner block + the
    /// inbound port blocks (per local port) + the inbound well-known source port
    /// block. Fixed order (OUTPUT first, ports ascending).
    #[test]
    fn overlay_isolation_plan_covers_both_directions() {
        let foreign = ForeignOverlay {
            uid: Some(995),
            local_ports: vec![28162, 9993],
            wellknown_port: 9993,
        };
        let rules = overlay_isolation_rules("wg-mlt", &foreign);
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].chain, "OUTPUT");
        assert!(rules[0].spec.contains(&"--uid-owner".to_string()));
        assert!(rules[0].spec.contains(&"995".to_string()));
        assert!(rules[0].spec.contains(&"wg-mlt".to_string()));
        assert_eq!(rules[1].chain, "INPUT");
        assert!(rules[1].spec.contains(&"--dport".to_string()));
        assert!(rules[1].spec.contains(&"28162".to_string()));
        assert!(rules[2].spec.contains(&"9993".to_string()));
        assert_eq!(rules[3].chain, "INPUT");
        assert!(rules[3].spec.contains(&"--sport".to_string()));
    }

    /// Identity unreadable (both uid and ports absent) -> an empty plan, never
    /// inventing a uid (§7.5).
    #[test]
    fn overlay_isolation_plan_absent_without_identity() {
        let foreign = ForeignOverlay::default();
        assert!(overlay_isolation_rules("wg-mlt", &foreign).is_empty());
    }

    /// An empty interface name -> an empty plan (the rules must bind to the
    /// managed tunnel, never the host's whole interface set).
    #[test]
    fn overlay_isolation_plan_requires_a_managed_interface() {
        let foreign = ForeignOverlay {
            uid: Some(995),
            local_ports: vec![9993],
            wellknown_port: 9993,
        };
        assert!(overlay_isolation_rules("", &foreign).is_empty());
    }

    /// A uid absent but ports read -> the port rules are still emitted (partial
    /// identity must also be blocked, block one rule at a time).
    #[test]
    fn overlay_isolation_plan_keeps_port_rules_when_uid_is_unknown() {
        let foreign = ForeignOverlay {
            uid: None,
            local_ports: vec![9993],
            wellknown_port: 9993,
        };
        let rules = overlay_isolation_rules("wg-mlt", &foreign);
        assert_eq!(rules.len(), 2);
        assert!(rules.iter().all(|r| r.chain == "INPUT"));
    }

    /// `wellknown_port = 0` (no well-known port on the peer side) -> no sport
    /// rule is emitted.
    #[test]
    fn overlay_isolation_plan_skips_sport_rule_without_wellknown_port() {
        let foreign = ForeignOverlay {
            uid: Some(995),
            local_ports: vec![],
            wellknown_port: 0,
        };
        let rules = overlay_isolation_rules("wg-mlt", &foreign);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].chain, "OUTPUT");
    }

    /// Every rule carries the ownership comment — rollback/cleanup locates the
    /// target precisely by the comment (§10.3), the same discipline as
    /// `meshlet tunnel` / `meshlet alias`.
    #[test]
    fn overlay_isolation_rules_carry_ownership_comment() {
        let foreign = ForeignOverlay {
            uid: Some(995),
            local_ports: vec![9993],
            wellknown_port: 9993,
        };
        let rules = overlay_isolation_rules("wg-mlt", &foreign);
        for rule in &rules {
            assert!(
                rule.spec
                    .windows(2)
                    .any(|w| w[0] == "--comment" && w[1] == MESHLET_ISOLATION_COMMENT),
                "rule {:?} 缺所有权注释",
                rule.spec
            );
            assert_eq!(rule.spec.last().map(String::as_str), Some("DROP"));
        }
    }

    /// `ss -H -ulnp` -> port parsing: filter by process name, take the local
    /// address/port (including the `%interface` scope suffix), dedupe and sort
    /// ascending, never bleeding into another process.
    #[test]
    fn ss_udp_listen_ports_parse_dedupes_and_sorts() {
        let out = "UNCONN 0 0 10.147.19.130%ztksetoehl:9993 0.0.0.0:* users:((\"zerotier-one\",pid=1579,fd=25))\n\
                   UNCONN 0 0 0.0.0.0:28162 0.0.0.0:* users:((\"zerotier-one\",pid=1579,fd=5))\n\
                   UNCONN 0 0 10.240.0.4%wg-mlt:63614 0.0.0.0:* users:((\"zerotier-one\",pid=1579,fd=24))\n\
                   UNCONN 0 0 10.240.0.4%wg-mlt:63614 0.0.0.0:* users:((\"zerotier-one\",pid=1579,fd=23))\n\
                   UNCONN 0 0 10.240.0.4%wg-mlt:51820 0.0.0.0:* users:((\"wg-mlt\",pid=9,fd=4))\n\
                   UNCONN 0 0 127.0.0.1:631 0.0.0.0:* users:((\"cupsd\",pid=10,fd=6))\n";
        let ports = parse_ss_udp_listen_ports(out, "zerotier-one");
        assert_eq!(
            ports,
            vec![9993, 28162, 63614],
            "deduped and ascending, the `%interface` suffix stripped, never bleeding into another process"
        );
        assert!(parse_ss_udp_listen_ports(out, "no-such-user").is_empty());
        assert!(parse_ss_udp_listen_ports("", "zerotier-one").is_empty());
    }

    #[test]
    fn ufw_status_port_line_detects_direct_udp_allow() {
        // The `ufw status` port line is `51820/udp ALLOW IN Anywhere`; once
        // allowed, contains("{port}/udp") hits, and the plan adds no rule
        // (idempotent).
        let allowed = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n51820/udp                 ALLOW IN    Anywhere\n";
        assert!(allowed.to_lowercase().contains("51820/udp"));
        let not_allowed = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n";
        assert!(!not_allowed.to_lowercase().contains("51820/udp"));
    }
}
