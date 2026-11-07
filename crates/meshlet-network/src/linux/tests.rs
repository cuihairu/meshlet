use super::*;
use crate::{parse_handshake_ages, NetworkBackend, NetworkError, TunnelConfig, DEFAULT_TUNNEL_MTU};
use meshlet_domain::Ipv4Cidr;
use std::net::Ipv4Addr;

mod tests {
    use super::*;
    use crate::nat::{NatAction, NatChain, NatRule};

    #[test]
    fn ip_octet_subnets_mask_interface_host_bits_into_the_lan_subnet() {
        // `ip -4 -o addr show` 的地址带主机位（接口地址不是网络地址）——
        // 回归：按规范化 CIDR 解析曾整行失败，LAN 枚举恒为空，直连永不
        // 触发（netns 真机测试抓到）。
        let output = "1: lo    inet 127.0.0.1/8 scope host lo\\\n\
                      2: wg0    inet 10.240.0.2/24 scope global wg0\\\n\
                      18623: eth0    inet 10.98.0.20/24 brd 10.98.0.255 scope global eth0\\\n";
        let subnets = parse_ip_octet_subnets(output);
        assert_eq!(subnets.len(), 3, "every addr line parses, host bits masked");
        assert_eq!(subnets[0].1.to_string(), "127.0.0.0/8");
        assert_eq!(subnets[1].1.to_string(), "10.240.0.0/24");
        assert_eq!(subnets[2].0, "eth0");
        assert_eq!(subnets[2].1.to_string(), "10.98.0.0/24");

        // 与 lan_subnets_sync 同一口径的过滤：lo/受管隧道出局、非私网出局
        // → 只剩 eth0 的网段。
        let lan: Vec<String> = subnets
            .iter()
            .filter(|(ifname, _)| is_lan_interface(ifname, "wg0"))
            .map(|(_, subnet)| subnet)
            .filter(|subnet| meshlet_domain::is_private_ip(subnet.network()))
            .map(|subnet| subnet.to_string())
            .collect();
        assert_eq!(lan, vec!["10.98.0.0/24"]);

        // 前缀越界/非地址的行被跳过，不 panic。
        assert!(parse_ip_octet_subnets("3: eth1 inet 1.2.3.4/99 x\n").is_empty());
        assert!(parse_ip_octet_subnets("3: eth1 inet junk/24 x\n").is_empty());
    }

    #[test]
    fn handshake_ages_parses_peer_lines_and_skips_never_handshaked() {
        // 标准三列：公钥 握手时间 距今秒。
        let pk_a = "A".repeat(43) + "=";
        let pk_b = "B".repeat(43) + "=";
        // 从未握手的 peer：握手时间戳为 0（WireGuard 语义），非「距今 0 秒」。
        let text = format!("{pk_a} 1750000000 12\n{pk_b} 0 0\nnot-a-key 1750000000 5\n");
        let ages = parse_handshake_ages(&text, 1750000060);
        assert_eq!(ages.len(), 1, "zero-handshake and junk lines are skipped");
        assert_eq!(ages.get(&pk_a), Some(&12));

        // 缺第三列：按 now - 握手时间兜底。
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
        // eth0 两条 RFC1918 保留；lo/wg0/docker0/br-* 全部排除。
        assert_eq!(
            addrs,
            vec![
                "192.168.1.50".parse::<Ipv4Addr>().unwrap(),
                "10.0.0.5".parse().unwrap()
            ]
        );
        assert!(!is_lan_interface("lo", "wg0"));
        assert!(!is_lan_interface("wg0", "wg0"));
        assert!(!is_lan_interface("wg9", "wg0")); // 其它 wg 接口同样排除
        assert!(is_lan_interface("eth0", "wg0"));
        assert!(is_lan_interface("enp2s0", "wg0"));
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

        // 精确 owner 匹配：al-1 的规则不被 al-2 的清理命中。
        assert!(
            LinuxNetworkBackend::meshlet_rule_deletion(line, Some("meshlet alias al-2")).is_none()
        );
        assert!(
            LinuxNetworkBackend::meshlet_rule_deletion(line, Some("meshlet alias al-1")).is_some()
        );

        // 非 Meshlet 规则（无注释 / 用户注释）不命中。
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
        // 非规则行（注释头 / 链声明）不命中。
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

        // 读数不可得（缺字段 / 非数字）时按 None 处理，不臆测默认值。
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
        // Linux `wg show dump` 的 peer 行：pubkey preshared endpoint
        // allowed-ips latest-handshake rx tx keepalive。
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

        // 缺列 / 空行 / 非公钥行 → None（不臆造 peer）。
        assert!(super::parse_wg_dump_diag_line("").is_none());
        assert!(super::parse_wg_dump_diag_line("short-row").is_none());
        assert!(super::parse_wg_dump_diag_line("bad-key not-a-peer").is_none());
    }

    #[test]
    fn wg_dump_diag_defaults_missing_numeric_columns_to_zero() {
        // 端点/流量列缺失时按 0/空串处理（读数不可得可见，不吞行）。
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
        // apply_nat_sync 组装 `iptables -t nat <args>`；-C 探测与 -A 下发只差
        // flag 位（index 3），保证探测与实际规则形状一致。
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
        // 后端只受管自己的接口：拒绝别的隧道名（防误操作系统接口）。
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
        // 计划含两条：DNAT 匹配 alias，SNAT 匹配 target（真实 LAN 段）。
        assert_eq!(
            LinuxNetworkBackend::snat_target_cidr(&rules),
            Some("192.168.9.0/24".parse().unwrap())
        );

        // dnat_only 计划无 SNAT 规则——网关 LAN 地址不适用（§9.5）。
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

        // 经受管接口：Meshlet 自有对象，幂等改写不冲突。
        assert!(foreign_route_line("10.241.1.0/24 via 10.240.0.4 dev wg0", "wg0").is_none());
    }

    #[test]
    fn foreign_route_line_fails_closed_without_a_dev_field() {
        // blackhole / 输出格式变化：解析不出 dev 即按冲突处理，不放过
        // 未知对象（fail closed）。
        assert_eq!(
            foreign_route_line("blackhole 10.244.0.0/24", "wg0").as_deref(),
            Some("blackhole 10.244.0.0/24")
        );
        assert!(foreign_route_line("10.244.0.0/24", "wg0").is_some());
    }

    #[test]
    fn connected_route_line_is_not_a_conflict_on_its_own_interface() {
        // connected 路由（proto kernel，地址自带）：dev 字段在 exact 输出
        // 里照常出现，经受管接口则不算冲突。
        let line = "10.240.0.0/24 proto kernel scope link src 10.240.0.1 dev wg0";
        assert!(foreign_route_line(line, "wg0").is_none());
    }

    #[test]
    fn peer_dump_line_yields_identity_not_a_count() {
        // dump 行序：pubkey presharedkey endpoint allowed-ips …（endpoint
        // none、allowed-ips 空串是未握手 peer 的常态）。allowed-ips 用逗号
        // 连接且**不带空格**（`wg show dump` 的实测输出）。
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

        // 未握手 / 未放行任何前缀的 peer：allowed-ips 为空是合法状态，
        // 不等于「少了一条 peer」。
        let none = LinuxNetworkBackend::parse_peer_dump_line(&format!(
            "{key} (none) (none) (none) 0 0 0 0"
        ))
        .unwrap();
        assert!(none.allowed_ips.is_empty());

        // 缺 44 字符公钥的残行不产 peer（不臆造身份）。
        assert!(LinuxNetworkBackend::parse_peer_dump_line("(none) 10.240.0.3/32 0 0 0").is_none());
        assert!(LinuxNetworkBackend::parse_peer_dump_line("tooshort").is_none());
    }

    #[test]
    fn nat_signature_round_trips_through_kernel_rendering() {
        // 计划侧指纹必须能从内核渲染出的 iptables 参数读回同值——两侧据此
        // 做集合精确比对，形状不一致就等于看不见漂移。用 `-S` 的字段顺序
        // （`-s` 在 `-d` 前、`-m comment` 在 `-j` 前）而非 `iptables_args`
        // 的顺序，证明解析与字段顺序无关。
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
            // POSTROUTING 不渲染 `-i`：`incoming_interface` 对它是惰性元数据，
            // 两侧都必须按 `none` 对齐（曾因此把在表内的 SNAT 规则误判为多余）。
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
        // 认了 Meshlet 所有权、形状却超出本网关渲染器产出的范围 → 不产指纹：
        // 既不冒充计划内规则，也不会被差集清理误删（交由整单元清理路径处置）。
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

        // 非 Meshlet 注释的规则带进来的也是它自己的注释：指纹永远撞不上计划
        // 侧的任何指纹，所以差集清理碰不到它。
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
        // 管理器都未活跃 → 不动作（放行规则存不存在都不影响）。
        assert!(host_firewall_allow_actions(false, false, false, false, "wg0").is_empty());
        assert!(host_firewall_allow_actions(false, true, false, true, "wg0").is_empty());

        // ufw 活跃且接口已放行 → 只补 firewalld 侧（若有）。
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

        // firewalld 活跃且接口未入 trusted → 补 trusted 接口。
        assert_eq!(
            host_firewall_allow_actions(false, false, true, false, "wg0"),
            vec![HostFirewallAction::FirewalldTrustedInterface {
                interface: "wg0".into()
            }]
        );

        // 双管理器都活跃且都未放行 → 两条动作，顺序确定（ufw 在前）。
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
        // 管理器未活跃 → 不动作；已放行 → 不动作（幂等）。
        assert!(direct_udp_firewall_allow_actions(false, false, false, false, 51820).is_empty());
        assert!(direct_udp_firewall_allow_actions(true, true, false, false, 51820).is_empty());
        assert!(direct_udp_firewall_allow_actions(false, false, true, true, 51820).is_empty());

        // ufw 活跃且端口未放行 → 按端口开。
        assert_eq!(
            direct_udp_firewall_allow_actions(true, false, false, false, 51820),
            vec![HostFirewallAction::UfwAllowPort { port: 51820 }]
        );

        // firewalld 活跃且端口未放行 → trusted 端口开。
        assert_eq!(
            direct_udp_firewall_allow_actions(false, false, true, false, 51820),
            vec![HostFirewallAction::FirewalldAllowPort { port: 51820 }]
        );

        // 双管理器都活跃且都未放行 → 两条，顺序确定（ufw 在前）。
        assert_eq!(
            direct_udp_firewall_allow_actions(true, false, true, false, 20000),
            vec![
                HostFirewallAction::UfwAllowPort { port: 20000 },
                HostFirewallAction::FirewalldAllowPort { port: 20000 },
            ]
        );
    }

    #[test]
    fn ufw_status_port_line_detects_direct_udp_allow() {
        // `ufw status` 的端口行是 `51820/udp ALLOW IN Anywhere`；放行后
        // contains("{port}/udp") 命中，plan 不再补规则（幂等）。
        let allowed = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n51820/udp                 ALLOW IN    Anywhere\n";
        assert!(allowed.to_lowercase().contains("51820/udp"));
        let not_allowed = "Status: active\n\nTo                         Action      From\n--                         ------      ----\n22/tcp                     ALLOW IN    Anywhere\n";
        assert!(!not_allowed.to_lowercase().contains("51820/udp"));
    }
}
