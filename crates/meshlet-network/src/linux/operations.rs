use super::{
    chrono_now_iso, direct_udp_firewall_allow_actions, enforced_tunnel_mtu, foreign_route_line,
    host_firewall_allow_actions, is_lan_interface, mtu_matches_planned,
    parse_default_route_interface, parse_ip_octet_addrs, parse_ip_octet_subnets, parse_link_mtu,
    parse_ping_rtt_ms, parse_wg_dump_diag_line, route_source, HostFirewallAction,
    MESHLET_FILTER_COMMENT, MESHLET_ROUTE_PROTO,
};
use crate::nat::{NatAction, NatRule};
use crate::{
    ApplyResult, ConfigRevisionRef, DevicePlan, NetworkBackend, NetworkDiagnostics, NetworkError,
    NetworkSnapshot, RouteConfig, TunnelConfig,
};
use meshlet_domain::Ipv4Cidr;
use std::collections::BTreeSet;
use std::net::Ipv4Addr;

use super::LinuxNetworkBackend;

impl LinuxNetworkBackend {
    /// 同步检查快照（inspect 的命令核心；服务端同步 backend 直接调用）。
    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
        let link = self.run(&["ip", "link", "show", &self.interface]).ok();
        let tunnel_exists = link.is_some();
        let tunnel_mtu = link
            .as_ref()
            .and_then(|out| parse_link_mtu(&String::from_utf8_lossy(&out.stdout)));
        let forwarding_enabled = self
            .run(&["sysctl", "-n", "net.ipv4.ip_forward"])
            .ok()
            .and_then(|out| match String::from_utf8_lossy(&out.stdout).trim() {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            });
        let peers = if tunnel_exists {
            self.peers_on_interface()?
        } else {
            Vec::new()
        };
        let installed_routes = if tunnel_exists {
            self.routes_on_interface()?
        } else {
            Vec::new()
        };
        let nat_rules = self.meshlet_nat_signatures_sync()?;
        // 本机身份读数（BUG② 修复的漂移判定输入）：dump 读不到 → None（证据
        // 缺失不判）；适配器地址从 `ip -4 addr show dev <if>` 读实际地址。
        let local_public_key = if tunnel_exists {
            let dump = self.wg_dump_on_interface()?;
            crate::parse_wg_dump_local_public_key(&dump)
        } else {
            None
        };
        let tunnel_address = if tunnel_exists {
            self.interface_address()
        } else {
            None
        };
        let tunnel_listen_port = if tunnel_exists {
            self.wg_dump_on_interface()
                .ok()
                .and_then(|dump| crate::parse_wg_dump_listen_port(&dump))
        } else {
            None
        };
        Ok(NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled,
            peers,
            installed_routes,
            nat_rules,
            tunnel_mtu,
            local_public_key,
            tunnel_address,
            tunnel_listen_port,
        })
    }

    /// `wg show <if> dump` 原文（接口行 + peer 行；`wg` 缺失/接口未起 → 错误，
    /// 由调用方按证据缺失处理）。
    fn wg_dump_on_interface(&self) -> Result<String, NetworkError> {
        let dump = self.run(&["wg", "show", &self.interface, "dump"])?;
        Ok(String::from_utf8_lossy(&dump.stdout).into_owned())
    }

    /// 受管接口的实际 IPv4 地址（`ip -4 -o addr show dev <if>` 单行格式，复用
    /// [`parse_ip_octet_addrs`] 的行解析）。读不到 → None。
    fn interface_address(&self) -> Option<Ipv4Addr> {
        let out = self
            .run(&["ip", "-4", "-o", "addr", "show", "dev", &self.interface])
            .ok()?;
        parse_ip_octet_addrs(&String::from_utf8_lossy(&out.stdout))
            .into_iter()
            .find(|(ifname, _)| ifname == &self.interface)
            .map(|(_, addr)| addr)
    }

    /// 枚举本机 RFC1918 局域网地址（§12 P2P 直连候选上报）：`ip -4 -o addr
    /// show` 里过滤回环、受管隧道与容器/虚拟接口。命令失败返回错误，由调用方
    /// 决定是否仍上报（候选为空）。
    pub fn lan_addresses_sync(&self) -> Result<Vec<Ipv4Addr>, NetworkError> {
        let out = self.run(&["ip", "-4", "-o", "addr", "show"])?;
        let mut addrs: Vec<Ipv4Addr> = parse_ip_octet_addrs(&String::from_utf8_lossy(&out.stdout))
            .into_iter()
            .filter(|(ifname, _)| is_lan_interface(ifname, &self.interface))
            .map(|(_, addr)| addr)
            .filter(|addr| meshlet_domain::is_private_ip(*addr))
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        Ok(addrs)
    }

    /// 枚举本机 RFC1918 局域网**子网**（§12 P2P 同网段判定）：与
    /// [`lan_addresses_sync`] 同一来源，但保留前缀长度——「对端 LAN 候选是否
    /// 落在本机子网内」需要网段而不是单个地址。
    pub fn lan_subnets_sync(&self) -> Result<Vec<meshlet_domain::Ipv4Cidr>, NetworkError> {
        let out = self.run(&["ip", "-4", "-o", "addr", "show"])?;
        let mut subnets: Vec<meshlet_domain::Ipv4Cidr> =
            parse_ip_octet_subnets(&String::from_utf8_lossy(&out.stdout))
                .into_iter()
                .filter(|(ifname, _)| is_lan_interface(ifname, &self.interface))
                .map(|(_, subnet)| subnet)
                .filter(|subnet| meshlet_domain::is_private_ip(subnet.network()))
                .collect();
        subnets.sort();
        subnets.dedup();
        Ok(subnets)
    }

    /// R-DIAG 网络诊断信息面采集（2026-11-01 用户令）：三类快照。
    ///
    /// - 路由表：`ip route show table all` 原文（全表，含多表）；命令失败按
    ///   空表上报（诊断展示「未取到」，绝不臆测）；
    /// - 接口清单：`ip -o link show` + `ip -4 -o addr show` + `ip -o link show`
    ///   的 MTU 字段，按接口名聚合（IPv4 地址/前缀 + 状态 + MTU）；
    /// - wg-mlt 读数：`wg show <if> dump` 解析（复用既有 peer dump 解析器
    ///   的形状，但保留 endpoint / 握手 / 流量列，[WgPeerDiagnostic]）。
    ///
    /// 采集只读、不写内核；单项失败按空/缺上报，不吞掉整体。
    pub fn diagnostics_sync(&self) -> Result<NetworkDiagnostics, NetworkError> {
        use crate::{InterfaceDiagnostic, NetworkDiagnostics};

        let route_table = self
            .run(&["ip", "route", "show", "table", "all"])
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        // 接口清单：`ip -o link show`（名称 + UP flag + MTU）与
        // `ip -4 -o addr show`（地址/前缀）按接口名聚合。
        let mut interfaces: Vec<InterfaceDiagnostic> = Vec::new();
        let link_show = self.run(&["ip", "-o", "link", "show"]).ok();
        let addr_show = self.run(&["ip", "-4", "-o", "addr", "show"]).ok();
        if let Some(out) = &link_show {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // `1: lo: <LOOPBACK,UP,...> mtu 65536 ...`
                if fields.len() < 3 {
                    continue;
                }
                let name = fields[1].trim_end_matches(':').to_string();
                if name.is_empty() {
                    continue;
                }
                let flags = fields[2].trim_start_matches('<').trim_end_matches('>');
                let state = if flags.split(',').any(|f| f == "UP") {
                    "up".to_string()
                } else {
                    "down".to_string()
                };
                let mtu = fields
                    .iter()
                    .position(|t| *t == "mtu")
                    .and_then(|i| fields.get(i + 1))
                    .and_then(|v| v.parse::<u32>().ok());
                interfaces.push(InterfaceDiagnostic {
                    name,
                    ipv4: String::new(),
                    prefix: None,
                    state,
                    mtu,
                });
            }
        }
        if let Some(out) = &addr_show {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                // `2: eth0    inet 192.168.1.50/24 ...`
                if fields.len() < 4 || fields[2] != "inet" {
                    continue;
                }
                let name = fields[1].trim_end_matches(':').to_string();
                let Some((addr, prefix)) = fields[3].split_once('/') else {
                    continue;
                };
                let Some(prefix) = prefix.parse::<u8>().ok() else {
                    continue;
                };
                if let Some(iface) = interfaces.iter_mut().find(|i| i.name == name) {
                    if iface.ipv4.is_empty() {
                        iface.ipv4 = addr.to_string();
                        iface.prefix = Some(prefix);
                    }
                }
            }
        }

        // wg-mlt 读数：`wg show <if> dump`（第一行接口，其后每行一个 peer）。
        let wg = self
            .run(&["wg", "show", &self.interface, "dump"])
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .skip(1)
                    .filter_map(parse_wg_dump_diag_line)
                    .collect()
            })
            .unwrap_or_default();

        Ok(NetworkDiagnostics {
            collected_at: Some(chrono_now_iso()),
            route_table,
            interfaces,
            wg,
        })
    }

    /// 以 `ping -c 1` 实测直连路径 RTT（毫秒）。返回原始输出中首个
    /// `time=…` / `time<…` 数值；失败按 `None`（诊断面显示不可得）。
    pub fn ping_rtt_ms(&self, target: Ipv4Addr) -> Option<u128> {
        let out = self
            .run(&["ping", "-c", "1", "-W", "2", &target.to_string()])
            .ok()?;
        parse_ping_rtt_ms(&String::from_utf8_lossy(&out.stdout))
    }

    /// Remove only this hub interface and its isolation rules; gateways own NAT.
    pub fn clear_hub_sync(&self) -> Result<(), NetworkError> {
        let chain = format!("MLT_{}", self.interface);
        for table_chain in ["INPUT", "FORWARD"] {
            let out = self.run(&["iptables", "-S", table_chain])?;
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let tokens = Self::split_iptables_line(line);
                if tokens.first().map(String::as_str) != Some("-A") {
                    continue;
                }
                let owned = tokens
                    .windows(2)
                    .any(|p| (p[0] == "-j" || p[0] == "--comment") && p[1] == chain)
                    || (tokens
                        .windows(2)
                        .any(|p| (p[0] == "-i" || p[0] == "-o") && p[1] == self.interface)
                        && tokens
                            .windows(2)
                            .any(|p| p[0] == "--comment" && p[1] == MESHLET_FILTER_COMMENT));
                if owned {
                    let mut argv = vec!["iptables", "-D"];
                    argv.extend(tokens[1..].iter().map(String::as_str));
                    self.run(&argv)?;
                }
            }
        }
        if self.run(&["iptables", "-S", &chain]).is_ok() {
            self.run(&["iptables", "-F", &chain])?;
            self.run(&["iptables", "-X", &chain])?;
        }
        if self.run(&["ip", "link", "show", &self.interface]).is_ok() {
            self.run(&["ip", "link", "del", &self.interface])?;
        }
        Ok(())
    }

    /// Hub traffic can only be forwarded between peers of this network.
    pub fn isolate_hub_sync(&self, address: Ipv4Addr) -> Result<(), NetworkError> {
        let chain = format!("MLT_{}", self.interface);
        if self.run(&["iptables", "-S", &chain]).is_err() {
            self.run(&["iptables", "-N", &chain])?;
        }
        let out = self.run(&["iptables", "-S", &chain])?;
        let text = String::from_utf8_lossy(&out.stdout);
        let actual: Vec<_> = text
            .lines()
            .filter(|line| line.starts_with("-A "))
            .collect();
        let accept = format!(
            "-A {chain} -i {} -o {} -j ACCEPT",
            self.interface, self.interface
        );
        let drop = format!("-A {chain} -j DROP");
        if actual != [accept.as_str(), drop.as_str()] {
            // Install a fail-closed pair before discarding a drifted rule set.
            self.run(&["iptables", "-I", &chain, "1", "-j", "DROP"])?;
            self.run(&[
                "iptables",
                "-I",
                &chain,
                "1",
                "-i",
                &self.interface,
                "-o",
                &self.interface,
                "-j",
                "ACCEPT",
            ])?;
            for _ in actual {
                self.run(&["iptables", "-D", &chain, "3"])?;
            }
        }
        for dir in ["-i", "-o"] {
            let mut args = vec![
                "iptables",
                "-C",
                "FORWARD",
                dir,
                &self.interface,
                "-j",
                &chain,
            ];
            if self.run(&args).is_err() {
                args[1] = "-I";
                self.run(&args)?;
            }
        }
        let address = address.to_string();
        let mut args = vec![
            "iptables",
            "-C",
            "INPUT",
            "-i",
            &self.interface,
            "!",
            "-d",
            &address,
            "-m",
            "comment",
            "--comment",
            &chain,
            "-j",
            "DROP",
        ];
        if self.run(&args).is_err() {
            args[1] = "-I";
            self.run(&args)?;
        }
        Ok(())
    }

    /// Read back each planned object; counts alone do not prove convergence.
    ///
    /// `extra_peer_keys` 是 P2P 直连对端公钥集（§12）：它们由 agent 直连管理
    /// 器单独增删，**不属于**服务端计划——读回时按「额外允许的 peer」容忍
    /// （只认存在、不严格核其 allowed-ips，直连态由管理器自己收敛），绝不让
    /// 直连 peer 的存在被判成「计划未收敛」而反复重放。
    pub fn device_plan_matches_sync(
        &self,
        plan: &DevicePlan,
        extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        let addresses = self.run(&["ip", "-4", "-o", "addr", "show", "dev", &self.interface])?;
        let expected = format!("{}/{}", plan.tunnel.address, plan.tunnel.address_prefix);
        if !String::from_utf8_lossy(&addresses.stdout)
            .split_whitespace()
            .any(|v| v == expected)
        {
            return Ok(false);
        }
        let link = self.run(&["ip", "link", "show", &self.interface])?;
        let link_text = String::from_utf8_lossy(&link.stdout);
        if !link_text
            .split(['<', '>'])
            .nth(1)
            .is_some_and(|flags| flags.split(',').any(|f| f == "UP"))
        {
            return Ok(false);
        }
        if !mtu_matches_planned(&link_text, plan.tunnel.mtu) {
            return Ok(false);
        }
        let dump = self.run(&["wg", "show", &self.interface, "dump"])?;
        let body = String::from_utf8_lossy(&dump.stdout);
        let header: Vec<_> = body
            .lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if let Some(port) = plan.tunnel.listen_port {
            if header.get(2).and_then(|s| s.parse::<u16>().ok()) != Some(port) {
                return Ok(false);
            }
        }
        if let Some(key) = &plan.tunnel.private_key {
            if header.get(1).copied() != Some(self.public_key_from_private(key)?.as_str()) {
                return Ok(false);
            }
        }
        let peers: Vec<_> = body.lines().skip(1).collect();
        // 每个计划 peer 必须存在且 allowed-ips 精确匹配（身份级，非计数）。
        for peer in &plan.tunnel.peers {
            let Some(line) = peers
                .iter()
                .find(|line| line.split_whitespace().next() == Some(peer.public_key.as_str()))
            else {
                return Ok(false);
            };
            let fields: Vec<_> = line.split_whitespace().collect();
            let actual: std::collections::BTreeSet<_> =
                fields.get(3).unwrap_or(&"").split(',').collect();
            let wanted: Vec<_> = peer.allowed_ips.iter().map(ToString::to_string).collect();
            if actual != wanted.iter().map(String::as_str).collect() {
                return Ok(false);
            }
        }
        // 受管接口上不得有既非计划、也非直连保留的 peer（未受管对象 → 漂移）。
        for line in &peers {
            let key = line.split_whitespace().next().unwrap_or("");
            if plan.tunnel.peers.iter().any(|p| p.public_key == key) {
                continue;
            }
            if extra_peer_keys.contains(key) {
                continue;
            }
            return Ok(false);
        }
        for route in &plan.routes {
            let out = self.run(&[
                "ip",
                "-4",
                "route",
                "show",
                "exact",
                &route.destination.to_string(),
            ])?;
            let text = String::from_utf8_lossy(&out.stdout);
            let dev = format!("dev {}", route.interface);
            let via = route.gateway.map(|g| format!("via {g}"));
            if !text
                .lines()
                .any(|line| line.contains(&dev) && via.as_ref().is_none_or(|v| line.contains(v)))
            {
                return Ok(false);
            }
        }
        for dir in ["-i", "-o"] {
            if self
                .run(&[
                    "iptables",
                    "-C",
                    "FORWARD",
                    dir,
                    &self.interface,
                    "-m",
                    "comment",
                    "--comment",
                    MESHLET_FILTER_COMMENT,
                    "-j",
                    "ACCEPT",
                ])
                .is_err()
            {
                return Ok(false);
            }
        }
        for rule in &plan.nat_rules {
            let addr = match rule.action {
                NatAction::NetMap { .. } => Ipv4Addr::UNSPECIFIED,
                NatAction::SnatToGatewayLan => self.lan_source_for(rule.match_dest)?,
            };
            if !self.nat_rule_matches(rule, addr) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 大包探测（§7.5）：以 DF 位（`ping -M do`）向 `target` 发一个载荷
    /// `payload` 字节的 ICMP echo——成功即路径可承载「payload + 28B」（IP
    /// 头 20B + ICMP 头 8B）的数据报。只读诊断，不写任何内核状态；ping
    /// 不可用或无应答返回 `false`（证据按「未证实」处理，不臆测）。
    pub fn mtu_probe_sync(&self, target: std::net::Ipv4Addr, payload: u32) -> bool {
        match self.run(&[
            "ping",
            "-c",
            "1",
            "-W",
            "2",
            "-M",
            "do",
            "-s",
            &payload.to_string(),
            &target.to_string(),
        ]) {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// 默认路由底层接口的 MTU（lane/dataplane-speed：大包探测载荷的自适应
    /// 来源，配合 [`crate::derive_tunnel_mtu`]）。只读；默认路由、出接口或
    /// MTU 任一读数不可得都返回 `None`，调用方回退默认探测尺寸，不臆测。
    pub fn underlay_path_mtu_sync(&self) -> Option<u32> {
        let route = self.run(&["ip", "-4", "route", "show", "default"]).ok()?;
        let dev = parse_default_route_interface(&String::from_utf8_lossy(&route.stdout))?;
        let link = self.run(&["ip", "link", "show", &dev]).ok()?;
        parse_link_mtu(&String::from_utf8_lossy(&link.stdout))
    }

    /// 同步隧道应用（[NetworkBackend::apply_tunnel] 的命令核心）。
    ///
    /// `keep_keys`：P2P 直连对端公钥集（§12）——计划重放时保留它们，不冲掉。
    pub fn apply_tunnel_sync(
        &self,
        config: &TunnelConfig,
        keep_keys: &BTreeSet<String>,
    ) -> Result<ApplyResult, NetworkError> {
        let ifname = config.name.clone();
        if ifname.is_empty()
            || ifname.len() > 15
            || !ifname
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        {
            return Err(NetworkError::ApplyRejected("invalid interface name".into()));
        }
        if ifname != self.interface {
            return Err(NetworkError::ApplyRejected(format!(
                "tunnel name {ifname} is not the managed interface {}",
                self.interface
            )));
        }
        // 接口存在则复用，不存在则创建（幂等）。
        if self.run(&["ip", "link", "show", &ifname]).is_err() {
            self.run(&["ip", "link", "add", &ifname, "type", "wireguard"])?;
        }
        self.run(&[
            "ip",
            "address",
            "replace",
            &format!("{}/{}", config.address, config.address_prefix),
            "dev",
            &ifname,
        ])?;
        // 未配置的 MTU 也按默认值落盘（不是「不动」）：接口停在更高的 MTU
        // 时若不收敛回默认，下面 `device_plan_matches_sync` 的读回（同样按
        // 默认值比较）会一直判漂移，大包探测也持续失败。默认值与显式值
        // 一视同仁。
        let mtu = enforced_tunnel_mtu(config.mtu);
        self.run(&["ip", "link", "set", &ifname, "mtu", &mtu.to_string()])?;
        self.run(&["ip", "link", "set", &ifname, "up"])?;
        if let Some(key) = &config.private_key {
            // 本环境 wg 工具 fopen 普通路径与 /dev/stdin 均报 EPERM（同
            // setconf 坑位），仅 bash 进程替换的 /dev/fd 管道可读——经
            // `<(cat)` + 管道 stdin 下发，私钥不进 argv、不落盘。
            self.run_bash_stdin(
                &format!("wg set {ifname} private-key <(cat)"),
                &format!("{key}\n"),
            )?;
        }
        if let Some(port) = config.listen_port {
            self.run(&["wg", "set", &ifname, "listen-port", &port.to_string()])?;
        }
        // key 与 peer 分两次 set（合并调用会静默丢 peer，真机实测坑位）。
        self.reconcile_peers(config, keep_keys)?;
        Ok(ApplyResult::ok())
    }

    /// 同步路由/ip_forward/FORWARD 应用（[NetworkBackend::apply_routes] 核心）。
    pub fn apply_routes_sync(
        &mut self,
        routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        // §18.3 冲突预检：目标前缀已有指向其他接口的路由时显式拒绝——
        // `ip route replace` 会静默接管外来路由，这里改为点名冲突对象并
        // 拒绝，且拒绝发生在任何内核状态（sysctl/iptables）改动之前。
        for route in routes {
            if let Some(line) = self.foreign_route_conflict(&route.destination, &route.interface)? {
                return Err(NetworkError::ApplyRejected(format!(
                    "route {} already exists on another path ({}): meshlet does not take over foreign routes",
                    route.destination, line
                )));
            }
        }
        let forwarding = self.run(&["sysctl", "-n", "net.ipv4.ip_forward"])?;
        if String::from_utf8_lossy(&forwarding.stdout).trim() != "1" {
            self.run(&["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
        }
        // FORWARD 放行：进出受管隧道接口的流量（注释标记所有权，回滚可精确定位）。
        for dir in ["-i", "-o"] {
            let probe = vec![
                "iptables",
                "-C",
                "FORWARD",
                dir,
                self.interface.as_str(),
                "-m",
                "comment",
                "--comment",
                MESHLET_FILTER_COMMENT,
                "-j",
                "ACCEPT",
            ];
            if self.run(&probe).is_err() {
                let mut add = probe.clone();
                add[1] = "-A";
                self.run(&add)?;
            }
        }
        for existing in self.routes_on_interface()? {
            if !routes.iter().any(|r| r.destination == existing) {
                self.run(&[
                    "ip",
                    "route",
                    "del",
                    &existing.to_string(),
                    "dev",
                    &self.interface,
                    "proto",
                    MESHLET_ROUTE_PROTO,
                ])?;
            }
        }
        for route in routes {
            let mut args: Vec<String> = vec![
                "ip".into(),
                "route".into(),
                "replace".into(),
                route.destination.to_string(),
            ];
            if let Some(gw) = route.gateway {
                args.extend(["via".into(), gw.to_string()]);
            }
            args.extend(["dev".into(), route.interface.clone()]);
            args.extend(["proto".into(), MESHLET_ROUTE_PROTO.into()]);
            let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            self.run(&argv)?;
        }
        Ok(ApplyResult::ok())
    }

    /// §18.3 冲突预检：`ip route show exact <dst>` 有任何一行指向非受管
    /// 接口即冲突，返回该行原文供拒绝信息点名。无既有路由或全部经受管
    /// 接口（Meshlet 自有对象，幂等改写属正常计划变更）则返回 None。
    fn foreign_route_conflict(
        &self,
        destination: &Ipv4Cidr,
        interface: &str,
    ) -> Result<Option<String>, NetworkError> {
        let out = self.run(&["ip", "route", "show", "exact", &destination.to_string()])?;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(conflict) = foreign_route_line(line, interface) {
                return Ok(Some(conflict));
            }
        }
        Ok(None)
    }

    /// 同步 NAT 规则下发（[NetworkBackend::apply_nat] 的命令核心）。
    pub fn apply_nat_sync(
        &self,
        rules: &[NatRule],
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        for rule in rules {
            // nat.rs 渲染不含程序与前缀（`-t nat` 之外的部分），这里补全。
            let mut args = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
            args.extend(rule.iptables_args(gateway_lan_addr));
            // -C 探测（-A 换成 -C），已存在则跳过——幂等下发。
            let probe: Vec<&str> = args
                .iter()
                .enumerate()
                .map(|(i, s)| if i == 3 { "-C" } else { s.as_str() })
                .collect();
            if self.run(&probe).is_err() {
                let apply_args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
                self.run(&apply_args)?;
            }
        }
        Ok(ApplyResult::ok())
    }

    /// 同步按所有权注释移除 NAT 规则（[NetworkBackend::remove_nat] 核心）。
    pub fn remove_nat_sync(&self, owner: &str) -> Result<ApplyResult, NetworkError> {
        for del_args in self.meshlet_nat_rules(Some(owner))? {
            let mut full = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
            full.extend(del_args);
            let args: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
            self.run(&args)?;
        }
        Ok(ApplyResult::ok())
    }

    /// Enumerate NAT ownership units that currently exist in the kernel.
    pub fn meshlet_nat_owners_sync(&self) -> Result<Vec<String>, NetworkError> {
        let owners = self
            .meshlet_nat_rules(None)?
            .into_iter()
            .filter_map(|tokens| {
                let index = tokens.iter().position(|token| token == "--comment")? + 1;
                tokens.get(index).cloned()
            })
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        Ok(owners)
    }

    /// Meshlet 所有权注释下的 NAT 规则身份指纹集合（`NatRule::signature` 同一
    /// 形状，去重排序）。集合只含 Meshlet 自有规则——注释前缀过滤在前，非本
    /// meshlet 规则在此处即已被排除，因此该集合的集合比对绝不会把用户规则
    /// 误判为漂移。
    pub fn meshlet_nat_signatures_sync(&self) -> Result<Vec<String>, NetworkError> {
        let signatures = self
            .meshlet_nat_rules(None)?
            .into_iter()
            .filter_map(|tokens| {
                // 删除参数形如 `-D CHAIN -d … -j … --comment …`。
                let [_, chain, args @ ..] = tokens.as_slice() else {
                    return None;
                };
                Self::nat_rule_signature_from_iptables(chain, args)
            })
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect();
        Ok(signatures)
    }

    /// 按身份指纹移除「有 Meshlet 所有权注释、但不在计划里」的 NAT 规则
    /// （M2）：计划侧与内核侧产出同一指纹，集合差集即多余对象。非本 meshlet
    /// 规则（注释不符）进不了该枚举，永不被触碰。
    ///
    /// 认了所有权却认不出形状的规则在此不删——那是异常而非匹配失败，交给
    /// 整单元清理路径（`remove_nat_sync` 按所有权）处置。
    pub fn remove_stale_nat_rules_sync(
        &self,
        planned: &[String],
    ) -> Result<ApplyResult, NetworkError> {
        let keep: BTreeSet<&str> = planned.iter().map(String::as_str).collect();
        for del_args in self.meshlet_nat_rules(None)? {
            let [_, chain, args @ ..] = del_args.as_slice() else {
                continue;
            };
            let Some(signature) = Self::nat_rule_signature_from_iptables(chain, args) else {
                continue;
            };
            if keep.contains(signature.as_str()) {
                continue;
            }
            let mut full = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
            full.extend(del_args);
            let args: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
            self.run(&args)?;
        }
        Ok(ApplyResult::ok())
    }

    /// 单行 iptables 规则的删除参数 → 身份指纹。形状必须与
    /// [`NatRule::signature`] 逐字节一致（两侧据此做集合比对），且只接受
    /// 本网关渲染器会产出的两种动作：`NETMAP --to <cidr>` 与 `SNAT`。
    /// 无法识别的规则形状返回 `None`——按注释认领了却不认得，属异常而非匹配
    /// 失败，交由所有权清理路径处置（`remove_nat_sync` 按注释精确移除）。
    pub(super) fn nat_rule_signature_from_iptables(chain: &str, args: &[String]) -> Option<String> {
        let mut match_dest = String::new();
        let mut source = String::new();
        let mut interface = String::new();
        let mut action = String::new();
        let mut owner = String::new();
        let mut i = 0;
        while i < args.len() {
            let flag = args[i].as_str();
            let value = args.get(i + 1).map(String::as_str).unwrap_or("");
            match flag {
                "-d" => match_dest = value.to_string(),
                "-s" => source = value.to_string(),
                "-i" | "-o" => interface = value.to_string(),
                "-j" => {
                    let target = args.get(i + 1).cloned().unwrap_or_default();
                    // `-S` 输出里 `--to` / `--to-source` 的值是**下一个 token**
                    // （`split_iptables_line` 已按空白切开）：两个 token 都要
                    // 消费，否则 NETMAP 的网段会被漏读成空串。
                    let (to, extra) = if matches!(
                        args.get(i + 2).map(String::as_str),
                        Some("--to") | Some("--to-source")
                    ) {
                        (args.get(i + 3).cloned().unwrap_or_default(), 3)
                    } else {
                        (String::new(), 1)
                    };
                    action = if target == "NETMAP" {
                        format!("net_map:{to}")
                    } else if target == "SNAT" {
                        "snat_to_gateway_lan".to_string()
                    } else {
                        return None;
                    };
                    i += extra; // 循环末尾的 +1 再跳过剩余位置
                }
                "-m" | "--comment" if flag == "--comment" => {
                    owner = value.to_string();
                }
                _ => {}
            }
            i += 1;
        }
        if action.is_empty() || owner.is_empty() || match_dest.is_empty() {
            return None;
        }
        Some(format!(
            "{}|{}|{}|{}|{}|{}",
            chain,
            match_dest,
            action,
            owner,
            if source.is_empty() {
                "none".to_string()
            } else {
                source
            },
            if interface.is_empty() {
                "none".to_string()
            } else {
                interface
            },
        ))
    }

    /// Remove Meshlet-marked routes that are absent from the desired plan.
    ///
    /// The managed-interface route marker is deliberately narrow: connected,
    /// static and manually installed paths (including unmarked paths on the
    /// managed interface) are foreign and are never deleted.
    pub fn remove_stale_meshlet_routes_sync(
        &self,
        routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        if self.run(&["ip", "link", "show", &self.interface]).is_err() {
            return Ok(ApplyResult::ok());
        }
        let desired: BTreeSet<_> = routes.iter().map(|route| route.destination).collect();
        for existing in self.routes_on_interface()? {
            if desired.contains(&existing) {
                continue;
            }
            self.run(&[
                "ip",
                "route",
                "del",
                &existing.to_string(),
                "dev",
                &self.interface,
                "proto",
                MESHLET_ROUTE_PROTO,
            ])?;
        }
        Ok(ApplyResult::ok())
    }

    /// 私钥 → 公钥（`wg pubkey`，密钥走 stdin、不进 argv）。服务端据此填充
    /// 下发给设备的 hub peer 公钥，无需额外持久化公钥（ADR-010）。
    pub fn public_key_from_private(&self, private_key: &str) -> Result<String, NetworkError> {
        // `wg pubkey` 从 stdin 读私钥（不像 `wg set private-key` 那样走 argv）。
        let out = self.run_bash_stdin("wg pubkey", &format!("{private_key}\n"))?;
        let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if key.is_empty() {
            return Err(NetworkError::Io("wg pubkey returned an empty key".into()));
        }
        Ok(key)
    }

    /// Resolve the route-selected LAN source, including /32 targets and routed LANs.
    /// Reject missing routes, local destinations and routes back into our own tunnel.
    pub fn lan_source_for(&self, target: Ipv4Cidr) -> Result<Ipv4Addr, NetworkError> {
        let out = self.run(&["ip", "-4", "route", "get", &target.network().to_string()])?;
        let text = String::from_utf8_lossy(&out.stdout);
        route_source(&text, &self.interface).ok_or_else(|| {
            NetworkError::ApplyRejected(format!(
                "no usable LAN egress/source for {target}: route get={text:?}"
            ))
        })
    }

    fn nat_rule_matches(&self, rule: &NatRule, source: Ipv4Addr) -> bool {
        let mut args = rule.iptables_args(source);
        args[0] = "-C".into();
        let mut argv = vec!["iptables", "-t", "nat"];
        argv.extend(args.iter().map(String::as_str));
        self.run(&argv).is_ok()
    }

    /// 设备数据面计划的同步应用入口：agent（§16.4 结构化配置对象）与测试共
    /// 用同一条执行路径。失败即报错，绝不返回「已应用」。
    ///
    /// - `private_key` = 本设备本地私钥（服务端不携带）；
    /// - `gateway_lan_addr` = `Some` 显式给定 SNAT 源地址；`None` = 从本机
    ///   到每个目标的实际路由解析；显式地址也须与读回使用的内核选择一致。
    ///   没有 SNAT 规则时无需解析源地址。
    pub fn apply_device_plan_sync(
        &mut self,
        plan: &DevicePlan,
        private_key: Option<String>,
        gateway_lan_addr: Option<Ipv4Addr>,
        keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        let mut tunnel = plan.tunnel.clone();
        tunnel.private_key = private_key;
        let tunnel_result = self.apply_tunnel_sync(&tunnel, keep_keys)?;
        if !tunnel_result.applied {
            return Err(NetworkError::ApplyRejected(
                tunnel_result.error.unwrap_or_default(),
            ));
        }
        let routes_result = self.apply_routes_sync(&plan.routes)?;
        if !routes_result.applied {
            return Err(NetworkError::ApplyRejected(
                routes_result.error.unwrap_or_default(),
            ));
        }
        // AGENT-FW-2：宿主 ufw/firewalld 活跃时自动放行 mesh 接口流量（幂等；
        // 探测失败按「未活跃」处理，放行失败显式报错——不假装生效）。netns
        // 测试钩子不跑此步，避免污染宿主防火墙。
        self.ensure_host_firewall_sync()?;
        // §12.4 防火墙联动：直连开启（计划携带 listen_port——agent 只在
        // direct_connect.enabled 时改写）→ 自动放行直连 UDP 端口。直连 peer
        // 经 LAN/公网接口到达，接口级放行不覆盖，须按端口开。
        if let Some(port) = plan.tunnel.listen_port {
            self.ensure_direct_udp_firewall_sync(port)?;
        }
        if plan.nat_rules.is_empty() {
            return Ok(());
        }
        // Resolve all sources before adding any NAT, so an unreachable target does
        // not leave a partial NETMAP-only unit. Apply and readback share this lookup.
        let sources: Vec<_> = plan
            .nat_rules
            .iter()
            .map(|rule| match rule.action {
                NatAction::NetMap { .. } => Ok(Ipv4Addr::UNSPECIFIED),
                NatAction::SnatToGatewayLan => {
                    let source = self.lan_source_for(rule.match_dest)?;
                    if gateway_lan_addr.is_some_and(|explicit| explicit != source) {
                        return Err(NetworkError::ApplyRejected(format!(
                            "explicit gateway address does not match route source {source} for {}",
                            rule.match_dest
                        )));
                    }
                    Ok(source)
                }
            })
            .collect::<Result<_, NetworkError>>()?;
        // A changed egress source must replace the old owner's SNAT, not append a
        // shadowed rule that passes -C while packets still use the obsolete source.
        let mut reset_owners = std::collections::BTreeSet::new();
        for (rule, source) in plan.nat_rules.iter().zip(&sources) {
            if !self.nat_rule_matches(rule, *source) {
                reset_owners.insert(rule.owner.as_str());
            }
        }
        for owner in reset_owners {
            self.remove_nat_sync(owner)?;
        }
        for (rule, source) in plan.nat_rules.iter().zip(sources) {
            let result = self.apply_nat_sync(std::slice::from_ref(rule), source)?;
            if !result.applied {
                return Err(NetworkError::ApplyRejected(
                    result.error.unwrap_or_default(),
                ));
            }
        }
        // 计划外的 Meshlet 自有规则按身份指纹清理（M2）：`apply_nat_sync` 只增
        // 不删，改名前后的旧指纹、半途失败的中间态会永远留在表里；按指纹
        // 差集清掉，非本 meshlet 规则不在该枚举内、永不被触碰。
        let planned_signatures: Vec<String> =
            plan.nat_rules.iter().map(|rule| rule.signature()).collect();
        let stale = self.remove_stale_nat_rules_sync(&planned_signatures)?;
        if !stale.applied {
            return Err(NetworkError::ApplyRejected(stale.error.unwrap_or_default()));
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn snat_target_cidr(rules: &[NatRule]) -> Option<Ipv4Cidr> {
        rules.iter().find_map(|rule| match rule.action {
            NatAction::SnatToGatewayLan => Some(rule.match_dest),
            _ => None,
        })
    }

    /// 探测宿主防火墙管理器并产出放行计划（AGENT-FW-2）。
    ///
    /// 命令缺失/未活跃一律按「未活跃」处理（no-op）；探测失败不阻断数据面
    /// 应用——放行是增益而非前提。
    fn host_firewall_allow_plan(&self) -> Vec<HostFirewallAction> {
        let (ufw_active, ufw_allowed) = match self.run(&["ufw", "status"]) {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
                (
                    text.contains("status: active"),
                    text.contains(&format!("on {}", self.interface)),
                )
            }
            // `ufw` 未安装（spawn 失败）→ 不活跃。
            Err(_) => (false, false),
        };
        let firewalld_active = matches!(
            self.run(&["firewall-cmd", "--state"]),
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "running"
        );
        let firewalld_allowed = matches!(
            self.run(&[
                "firewall-cmd",
                "--zone=trusted",
                &format!("--query-interface={}", self.interface),
            ]),
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "yes"
        );
        host_firewall_allow_actions(
            ufw_active,
            ufw_allowed,
            firewalld_active,
            firewalld_allowed,
            &self.interface,
        )
    }

    /// 执行宿主防火墙放行（AGENT-FW-2）。测试 netns 钩子下跳过——探测经
    /// `ip netns exec` 仍能读到宿主 ufw 状态文件，若真放行会改宿主防火墙。
    fn ensure_host_firewall_sync(&self) -> Result<(), NetworkError> {
        if self.netns.is_some() {
            return Ok(());
        }
        for action in self.host_firewall_allow_plan() {
            match action {
                HostFirewallAction::UfwAllowInOn { interface } => {
                    self.run(&["ufw", "allow", "in", "on", &interface])?;
                }
                HostFirewallAction::FirewalldTrustedInterface { interface } => {
                    self.run(&[
                        "firewall-cmd",
                        "--zone=trusted",
                        &format!("--add-interface={interface}"),
                    ])?;
                }
                // 端口类动作走直连专用路径（§12.4），接口放行里不可能出现。
                HostFirewallAction::UfwAllowPort { .. }
                | HostFirewallAction::FirewalldAllowPort { .. } => {}
            }
        }
        Ok(())
    }

    /// 探测宿主防火墙管理器并产出直连 UDP 端口放行计划（§12.4）。
    ///
    /// 命令缺失/未活跃一律按「未活跃」处理（no-op）；探测失败不阻断数据面
    /// 应用——放行是增益而非前提（同 [host_firewall_allow_plan]）。
    fn host_direct_udp_allow_plan(&self, port: u16) -> Vec<HostFirewallAction> {
        let (ufw_active, ufw_port_allowed) = match self.run(&["ufw", "status"]) {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
                (
                    text.contains("status: active"),
                    text.contains(&format!("{port}/udp")),
                )
            }
            // `ufw` 未安装（spawn 失败）→ 不活跃。
            Err(_) => (false, false),
        };
        let firewalld_active = matches!(
            self.run(&["firewall-cmd", "--state"]),
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "running"
        );
        let firewalld_port_allowed = matches!(
            self.run(&["firewall-cmd", "--query-port", &format!("{port}/udp")]),
            Ok(out) if String::from_utf8_lossy(&out.stdout).trim() == "yes"
        );
        direct_udp_firewall_allow_actions(
            ufw_active,
            ufw_port_allowed,
            firewalld_active,
            firewalld_port_allowed,
            port,
        )
    }

    /// 执行直连 UDP 端口放行（§12.4）。netns 钩子下跳过（同
    /// [ensure_host_firewall_sync]）；直连关闭时端口规则保留无害（只开一个
    /// UDP 端口），幂等重复执行。失败显式报错——不假装生效。
    fn ensure_direct_udp_firewall_sync(&self, port: u16) -> Result<(), NetworkError> {
        if self.netns.is_some() {
            return Ok(());
        }
        for action in self.host_direct_udp_allow_plan(port) {
            match action {
                HostFirewallAction::UfwAllowPort { port } => {
                    // `ufw allow 51820/udp`：规范形式（ufw status 同形展示）。
                    self.run(&["ufw", "allow", &format!("{port}/udp")])?;
                }
                HostFirewallAction::FirewalldAllowPort { port } => {
                    self.run(&[
                        "firewall-cmd",
                        "--zone=trusted",
                        "--add-port",
                        &format!("{port}/udp"),
                    ])?;
                }
                HostFirewallAction::UfwAllowInOn { .. }
                | HostFirewallAction::FirewalldTrustedInterface { .. } => {}
            }
        }
        Ok(())
    }

    /// 同步回滚（[NetworkBackend::rollback] 的命令核心）。
    pub fn rollback_sync(&self) -> Result<ApplyResult, NetworkError> {
        // §10.3：只删 Meshlet 自有对象——本后端拥有的隧道接口上的全部数据面
        // 对象（nat 规则 / FORWARD 放行 / 隧道路由 / peer），保留接口、地址与
        // 系统级 ip_forward（属系统状态，不动用户既有配置）。
        // Gateway NAT cleanup requires exact owner ids from its local ledger.
        // A hub rollback must never sweep the machine-wide NAT table.
        let out = self.run(&["iptables", "-S", "FORWARD"])?;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let tokens = Self::split_iptables_line(line);
            if tokens.len() < 2 || tokens[0] != "-A" {
                continue;
            }
            let owned = tokens
                .iter()
                .position(|t| t == "--comment")
                .and_then(|i| tokens.get(i + 1))
                .is_some_and(|c| *c == MESHLET_FILTER_COMMENT);
            if owned
                && tokens
                    .windows(2)
                    .any(|pair| (pair[0] == "-i" || pair[0] == "-o") && pair[1] == self.interface)
            {
                let mut del = vec!["iptables".to_string(), "-D".to_string(), tokens[1].clone()];
                del.extend(tokens[2..].iter().cloned());
                let args: Vec<&str> = del.iter().map(|s| s.as_str()).collect();
                self.run(&args)?;
            }
        }
        for cidr in self.routes_on_interface()? {
            self.run(&[
                "ip",
                "route",
                "del",
                &cidr.to_string(),
                "dev",
                &self.interface,
            ])?;
        }
        for key in self.existing_peers()? {
            self.run(&["wg", "set", &self.interface, "peer", &key, "remove"])?;
        }
        Ok(ApplyResult::ok())
    }
}

impl NetworkBackend for LinuxNetworkBackend {
    async fn inspect(&self) -> Result<NetworkSnapshot, NetworkError> {
        self.inspect_sync()
    }

    async fn apply_tunnel(&self, config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
        // trait 面无直连保留集语义（trait 是旧接口，直连只走 sync 面）。
        self.apply_tunnel_sync(&config, &BTreeSet::new())
    }

    async fn apply_routes(
        &mut self,
        routes: Vec<RouteConfig>,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_routes_sync(&routes)
    }

    async fn apply_nat(
        &self,
        rules: Vec<NatRule>,
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_nat_sync(&rules, gateway_lan_addr)
    }

    async fn remove_nat<'s>(&'s self, owner: &'s str) -> Result<ApplyResult, NetworkError> {
        self.remove_nat_sync(owner)
    }

    async fn rollback(&self, _revision: ConfigRevisionRef) -> Result<ApplyResult, NetworkError> {
        self.rollback_sync()
    }
}

impl Default for LinuxNetworkBackend {
    fn default() -> Self {
        Self::new()
    }
}
