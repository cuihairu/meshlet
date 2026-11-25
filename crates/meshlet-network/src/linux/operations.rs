use super::{
    chrono_now_iso, direct_udp_firewall_allow_actions, enforced_tunnel_mtu, foreign_route_line,
    host_firewall_allow_actions, is_lan_interface, mtu_matches_planned, overlay_isolation_rules,
    parse_default_route_interface, parse_ip_octet_addrs, parse_ip_octet_subnets, parse_link_mtu,
    parse_ping_rtt_ms, parse_ss_udp_listen_ports, parse_wg_dump_diag_line, route_source,
    ForeignOverlay, HostFirewallAction, FOREIGN_OVERLAY_USER, FOREIGN_OVERLAY_WELLKNOWN_PORT,
    MESHLET_FILTER_COMMENT, MESHLET_ISOLATION_COMMENT, MESHLET_ROUTE_PROTO,
};
use crate::doctor::{
    parse_zerotier_paths, run_doctor, DoctorInputs, DoctorReport, DOCTOR_SAMPLE_SECS,
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
    /// Synchronous inspection snapshot (the command core of inspect; the
    /// server-side sync backend calls it directly).
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
        // Local identity readings (input to the drift decision fixed by BUG
        // 2): dump unreadable -> None (missing evidence is not judged); the
        // adapter address is read from `ip -4 addr show dev <if>`.
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
            routes_from_peers: false,
        })
    }

    /// Raw `wg show <if> dump` output (the interface line plus the peer
    /// lines; a missing `wg` or a down interface -> an error, which the
    /// caller handles as missing evidence).
    fn wg_dump_on_interface(&self) -> Result<String, NetworkError> {
        let dump = self.run(&["wg", "show", &self.interface, "dump"])?;
        Ok(String::from_utf8_lossy(&dump.stdout).into_owned())
    }

    /// The managed interface's actual IPv4 address (the one-line format of
    /// `ip -4 -o addr show dev <if>`, reusing [`parse_ip_octet_addrs`] line
    /// parsing). Returns None when unreadable.
    fn interface_address(&self) -> Option<Ipv4Addr> {
        let out = self
            .run(&["ip", "-4", "-o", "addr", "show", "dev", &self.interface])
            .ok()?;
        parse_ip_octet_addrs(&String::from_utf8_lossy(&out.stdout))
            .into_iter()
            .find(|(ifname, _)| ifname == &self.interface)
            .map(|(_, addr)| addr)
    }

    /// Enumerate this host's RFC1918 LAN addresses (reported as §12 P2P
    /// direct-connect candidates): from `ip -4 -o addr show`, filtering out
    /// loopback, the managed tunnel, and container/virtual interfaces. A
    /// failed command returns an error; the caller decides whether to report
    /// anyway (with an empty candidate list).
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

    /// Enumerate this host's RFC1918 LAN **subnets** (the §12 P2P same-segment
    /// decision): same source as [`lan_addresses_sync`], but keeping the prefix
    /// length — "does a remote LAN candidate fall inside a local subnet" needs
    /// the segment, not a single address.
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

    /// R-DIAG network diagnostics information surface (2026-11-01 user
    /// directive): three snapshot families.
    ///
    /// - Route table: the raw `ip route show table all` output (all tables,
    ///   including multiple routing tables); a failed command reports an empty
    ///   table (diagnostics show "not obtained" — never guess);
    /// - Interface list: the MTU field of `ip -o link show` plus `ip -4 -o addr
    ///   show`, aggregated by interface name (IPv4 address/prefix + state + MTU);
    /// - wg-mlt readings: parsed `wg show <if> dump` (the shape of the existing
    ///   peer dump parser, but keeping the endpoint / handshake / transfer
    ///   columns, [WgPeerDiagnostic]).
    ///
    /// Collection is read-only and writes no kernel state; an individual
    /// failure reports empty/missing rather than swallowing the whole thing.
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

        // Interface list: aggregate `ip -o link show` (name + UP flag + MTU)
        // with `ip -4 -o addr show` (address/prefix) by interface name.
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

        // wg-mlt readings: `wg show <if> dump` (first line the interface,
        // then one peer per line).
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

    /// Measure the direct-connect path RTT (milliseconds) with `ping -c 1`.
    /// Returns the first `time=…` / `time<…` value in the raw output; a failure
    /// yields `None` (the diagnostics surface shows it as unavailable).
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
    /// `extra_peer_keys` is the set of P2P direct-connect peer public keys
    /// (§12): the agent's direct-connect manager adds and removes them on its
    /// own, so they are **not part of** the server plan — read-back tolerates
    /// them as "additionally allowed peers" (only their presence is checked,
    /// not their allowed-ips strictly; the direct-connect state converges on
    /// its own), so a direct-connect peer never reads as "the plan did not
    /// converge" and triggers repeated replays.
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
        // Every planned peer must exist with exactly matching allowed-ips
        // (identity level, not a count).
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
        // The managed interface must not carry peers that are neither planned
        // nor direct-connect-kept (an unmanaged object -> drift).
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

    /// Large-packet probe (§7.5): send an ICMP echo with a `payload`-byte
    /// payload to `target` with the DF bit set (`ping -M do`) — success means
    /// the path can carry a datagram of "payload + 28B" (20B IP header + 8B
    /// ICMP header). Read-only diagnostics, no kernel state is written; an
    /// unavailable ping or no reply returns `false` (the evidence is treated as
    /// "unproven", never guessed).
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

    /// MTU of the default route's underlay interface (lane/dataplane-speed:
    /// the adaptive source of the large-packet probe payload, working with
    /// [`crate::derive_tunnel_mtu`]). Read-only; when the default route, the
    /// egress interface, or the MTU cannot be read, `None` is returned and the
    /// caller falls back to the default probe size rather than guessing.
    pub fn underlay_path_mtu_sync(&self) -> Option<u32> {
        let route = self.run(&["ip", "-4", "route", "show", "default"]).ok()?;
        let dev = parse_default_route_interface(&String::from_utf8_lossy(&route.stdout))?;
        let link = self.run(&["ip", "link", "show", &dev]).ok()?;
        parse_link_mtu(&String::from_utf8_lossy(&link.stdout))
    }

    /// Synchronous tunnel application (the command core of
    /// [NetworkBackend::apply_tunnel]).
    ///
    /// `keep_keys`: the set of P2P direct-connect peer public keys (§12) —
    /// kept on a plan replay rather than wiped.
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
        // Reuse the interface when it exists, create it otherwise
        // (idempotent).
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
        // An unset MTU is also written as the default value (not "leave it
        // alone"): if an interface parked at a higher MTU were not converged
        // back to the default, the read-back below in
        // `device_plan_matches_sync` (which compares against the default too)
        // would keep judging drift and the large-packet probe would keep
        // failing. Defaults and explicit values are treated alike.
        let mtu = enforced_tunnel_mtu(config.mtu);
        self.run(&["ip", "link", "set", &ifname, "mtu", &mtu.to_string()])?;
        self.run(&["ip", "link", "set", &ifname, "up"])?;
        if let Some(key) = &config.private_key {
            // In this environment the wg tool's fopen on a plain path and on
            // /dev/stdin both report EPERM (the same trap as setconf); only the
            // bash process-substitution /dev/fd pipe is readable — feed the key
            // through `<(cat)` plus piped stdin so it never enters argv nor
            // lands on disk.
            self.run_bash_stdin(
                &format!("wg set {ifname} private-key <(cat)"),
                &format!("{key}\n"),
            )?;
        }
        if let Some(port) = config.listen_port {
            self.run(&["wg", "set", &ifname, "listen-port", &port.to_string()])?;
        }
        // Set key and peers in two separate calls (a merged call silently
        // drops peers — a trap measured on a real machine).
        self.reconcile_peers(config, keep_keys)?;
        Ok(ApplyResult::ok())
    }

    /// Synchronous application of routes/ip_forward/FORWARD (the core of
    /// [NetworkBackend::apply_routes]).
    pub fn apply_routes_sync(
        &mut self,
        routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        // §18.3 conflict pre-check: when the destination prefix already has a
        // route toward another interface, reject explicitly — `ip route
        // replace` would silently take over a foreign route, so this names the
        // conflicting object and refuses, and the refusal happens before any
        // kernel state (sysctl/iptables) is touched.
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
        // FORWARD allowance: traffic entering and leaving the managed tunnel
        // interface (the comment marks ownership so a rollback can pinpoint
        // it).
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

    /// §18.3 conflict pre-check: any line of `ip route show exact <dst>` that
    /// points to a non-managed interface is a conflict, and that line is
    /// returned verbatim so the rejection message can name it. Returns None
    /// when there is no existing route or every route goes through a managed
    /// interface (Meshlet's own objects; an idempotent rewrite is a normal plan
    /// change).
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

    /// Synchronous NAT rule application (the command core of
    /// [NetworkBackend::apply_nat]).
    pub fn apply_nat_sync(
        &self,
        rules: &[NatRule],
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        for rule in rules {
            // The nat.rs rendering carries neither the program nor the prefix
            // (everything besides `-t nat`); complete it here.
            let mut args = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
            args.extend(rule.iptables_args(gateway_lan_addr));
            // -C probe (swapping -A for -C); skip when it already exists —
            // idempotent application.
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

    /// Synchronously remove NAT rules by ownership comment (the core of
    /// [NetworkBackend::remove_nat]).
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

    /// The set of identity fingerprints of NAT rules under the Meshlet
    /// ownership comment (the same shape as `NatRule::signature`, deduplicated
    /// and sorted). The set holds Meshlet's own rules only — the comment-prefix
    /// filter runs first, so rules that do not belong to this meshlet are
    /// already excluded, and this set comparison can never mistake a user rule
    /// for drift.
    pub fn meshlet_nat_signatures_sync(&self) -> Result<Vec<String>, NetworkError> {
        let signatures = self
            .meshlet_nat_rules(None)?
            .into_iter()
            .filter_map(|tokens| {
                // Delete arguments look like `-D CHAIN -d … -j … --comment …`.
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

    /// Remove NAT rules that carry the Meshlet ownership comment but are not
    /// in the plan (M2), by identity fingerprint: the plan side and the kernel
    /// side produce the same fingerprint, and the set difference is the surplus.
    /// Rules not belonging to this meshlet (comment mismatch) cannot enter the
    /// enumeration and are never touched.
    ///
    /// A rule that claims ownership but whose shape cannot be recognized is not
    /// deleted here — that is an anomaly rather than a match failure, and it is
    /// left to the whole-unit cleanup path (`remove_nat_sync`, by ownership).
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

    /// Turn the delete arguments of one iptables rule line into an identity
    /// fingerprint. The shape must match [`NatRule::signature`] byte for byte
    /// (both sides use it for set comparison), and only the two actions this
    /// gateway renderer emits are accepted: `NETMAP --to <cidr>` and `SNAT`.
    /// An unrecognized rule shape returns `None` — claiming ownership by
    /// comment yet not being recognizable is an anomaly rather than a match
    /// failure, and it is left to the ownership cleanup path (`remove_nat_sync`
    /// removes exactly by comment).
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
                    // In `-S` output the value of `--to` / `--to-source` is
                    // the **next token** (`split_iptables_line` already split
                    // on whitespace): both tokens must be consumed, otherwise
                    // NETMAP's segment would be read as an empty string.
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
                    i += extra; // the +1 at the end of the loop skips the remaining positions
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

    /// Private key -> public key (`wg pubkey`, the key travels over stdin and
    /// never enters argv). The server fills in the hub peer public key it
    /// issues to devices from this, so no public key needs to be persisted
    /// separately (ADR-010).
    pub fn public_key_from_private(&self, private_key: &str) -> Result<String, NetworkError> {
        // `wg pubkey` reads the private key from stdin (unlike
        // `wg set private-key`, which goes through argv).
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

    /// Synchronous application entry point for the device data-plane plan:
    /// the agent (§16.4 structured configuration objects) and the tests share
    /// one execution path. A failure raises an error and never reports
    /// "applied".
    ///
    /// - `private_key` = this device's local private key (the server carries
    ///   none);
    /// - `gateway_lan_addr` = `Some` gives the SNAT source address explicitly;
    ///   `None` means resolving it from the actual route from this host to
    ///   each target; an explicit address must also agree with the kernel's
    ///   choice used for read-back. No source resolution is needed when there
    ///   are no SNAT rules.
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
        // AGENT-FW-2: automatically allow mesh interface traffic when the host
        // ufw/firewalld is active (idempotent; a probe failure is treated as
        // "inactive", and a failed allowance reports an explicit error —
        // never pretending it took effect). The netns test hook skips this
        // step to avoid polluting the host firewall.
        self.ensure_host_firewall_sync()?;
        // AGENT-ISO-1: a foreign overlay (ZeroTier-like) must not ride this
        // tunnel — with two tunnels serving as each other's path they wrap each
        // other into a loop (see overlay_isolation_rules). This runs **on every
        // reconcile**, not only at boot: the rules can be flushed externally,
        // and the timing of wg-mlt coming up races with zerotier starting
        // (measured 2026-11-23, ExecStartPost landed 0.7s before the
        // interface, and the isolation rules were lost as a batch -> recursive
        // encapsulation amplifying 185:1). Idempotent and self-healing.
        self.ensure_overlay_isolation_sync()?;
        // §12.4 firewall linkage: direct connect is enabled (the plan carries a
        // listen_port — the agent only rewrites it when
        // direct_connect.enabled) -> automatically allow the direct-connect
        // UDP port. A direct-connect peer arrives through a LAN/public
        // interface, which interface-level allowance does not cover, so it must
        // be opened by port.
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
        // Meshlet's own rules outside the plan are cleaned by identity
        // fingerprint (M2): `apply_nat_sync` only adds and never deletes, so
        // stale fingerprints from before and after a rename, or an intermediate
        // state from a halfway failure, would linger in the table forever;
        // clear them by fingerprint difference, and rules not belonging to this
        // meshlet are not in the enumeration and are never touched.
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

    /// Probe the host firewall manager and produce an allowance plan
    /// (AGENT-FW-2).
    ///
    /// A missing command or an inactive manager is always treated as
    /// "inactive" (no-op); a probe failure does not block data-plane
    /// application — allowance is a bonus, not a precondition.
    fn host_firewall_allow_plan(&self) -> Vec<HostFirewallAction> {
        let (ufw_active, ufw_allowed) = match self.run(&["ufw", "status"]) {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
                (
                    text.contains("status: active"),
                    text.contains(&format!("on {}", self.interface)),
                )
            }
            // `ufw` is not installed (spawn failed) -> inactive.
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

    /// Perform the host firewall allowance (AGENT-FW-2). Skipped under the
    /// test netns hook — the probe still reads the host's ufw state files
    /// through `ip netns exec`, so an actual allowance would modify the host
    /// firewall.
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
                // Port-based actions belong to the dedicated direct-connect
                // path (§12.4) and cannot appear in an interface allowance.
                HostFirewallAction::UfwAllowPort { .. }
                | HostFirewallAction::FirewalldAllowPort { .. } => {}
            }
        }
        Ok(())
    }

    /// Probe the host firewall manager and produce a direct-connect UDP port
    /// allowance plan (§12.4).
    ///
    /// A missing command or an inactive manager is always treated as
    /// "inactive" (no-op); a probe failure does not block data-plane
    /// application — allowance is a bonus, not a precondition (same as
    /// [host_firewall_allow_plan]).
    fn host_direct_udp_allow_plan(&self, port: u16) -> Vec<HostFirewallAction> {
        let (ufw_active, ufw_port_allowed) = match self.run(&["ufw", "status"]) {
            Ok(out) => {
                let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
                (
                    text.contains("status: active"),
                    text.contains(&format!("{port}/udp")),
                )
            }
            // `ufw` is not installed (spawn failed) -> inactive.
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

    /// Perform the direct-connect UDP port allowance (§12.4). Skipped under
    /// the netns hook (same as [ensure_host_firewall_sync]); leaving the port
    /// rule in place when direct connect is off is harmless (it opens only one
    /// UDP port), and the operation is idempotent under repetition. A failure
    /// reports an explicit error — never pretending it took effect.
    fn ensure_direct_udp_firewall_sync(&self, port: u16) -> Result<(), NetworkError> {
        if self.netns.is_some() {
            return Ok(());
        }
        for action in self.host_direct_udp_allow_plan(port) {
            match action {
                HostFirewallAction::UfwAllowPort { port } => {
                    // `ufw allow 51820/udp`: the canonical form (ufw status
                    // displays it the same way).
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

    /// Probe the identity of a foreign overlay (ZeroTier-like) (AGENT-ISO-1).
    ///
    /// A missing user or a missing command is always treated as "absent"
    /// (no-op) — **no guessing** of the uid or the ports (§7.5). Ports are read
    /// live (`ss`) rather than hardcoded: after a ZeroTier restart the primary
    /// socket port changes, so hardcoded rules would become stale.
    fn foreign_overlay_probe(&self) -> Option<ForeignOverlay> {
        // `id -u zerotier-one`: no such user -> a non-zero exit code, treated
        // as absent.
        let uid = self
            .run(&["id", "-u", FOREIGN_OVERLAY_USER])
            .ok()
            .and_then(|out| String::from_utf8_lossy(&out.stdout).trim().parse().ok());
        let local_ports = self
            .run(&["ss", "-H", "-ulnp"])
            .map(|out| {
                parse_ss_udp_listen_ports(
                    &String::from_utf8_lossy(&out.stdout),
                    FOREIGN_OVERLAY_USER,
                )
            })
            .unwrap_or_default();
        // Neither the uid nor any port can be read -> this host has no such
        // overlay, so produce no rules.
        if uid.is_none() && local_ports.is_empty() {
            return None;
        }
        Some(ForeignOverlay {
            uid,
            local_ports,
            wellknown_port: FOREIGN_OVERLAY_WELLKNOWN_PORT,
        })
    }

    /// Perform foreign overlay isolation (AGENT-ISO-1). Skipped under the
    /// netns hook (same as [ensure_host_firewall_sync]: inside a netns,
    /// `id`/`ss` read the host's state, so real rules would pollute the host
    /// firewall).
    ///
    /// Idempotent: `-C` found means skip, otherwise insert with `-I` (the
    /// same criterion as `meshlet-zt-separation.sh`). **A failure reports an
    /// explicit error** — isolation is a hard guarantee, never pretend it took
    /// effect.
    fn ensure_overlay_isolation_sync(&self) -> Result<(), NetworkError> {
        if self.netns.is_some() {
            return Ok(());
        }
        let Some(foreign) = self.foreign_overlay_probe() else {
            return Ok(());
        };
        for rule in overlay_isolation_rules(&self.interface, &foreign) {
            let mut check = vec!["iptables", "-C", &rule.chain];
            check.extend(rule.spec.iter().map(String::as_str));
            if self.run(&check).is_ok() {
                continue;
            }
            let mut insert = vec!["iptables", "-I", &rule.chain, "1"];
            insert.extend(rule.spec.iter().map(String::as_str));
            self.run(&insert)?;
        }
        Ok(())
    }

    /// Read the cumulative TX bytes of a single interface (sysfs, read-only).
    fn interface_tx_bytes(&self, ifname: &str) -> Option<u64> {
        std::fs::read_to_string(format!("/sys/class/net/{ifname}/statistics/tx_bytes"))
            .ok()?
            .trim()
            .parse()
            .ok()
    }

    /// TX rate (B/s) of each interface over the sampling window.
    ///
    /// Each of the three links is read twice, spaced [DOCTOR_SAMPLE_SECS]
    /// seconds apart: the amplification check looks at the **rate ratio**, not
    /// at cumulative values — cumulative values are diluted by historical
    /// traffic, so an incident window (hundreds of GB burned in a few minutes)
    /// would be invisible. Any interface that cannot be read -> `None` (the
    /// verdict layer reports not_assessed).
    fn sample_tx_rates(&self, interfaces: &[String]) -> Option<Vec<f64>> {
        let read_all = || -> Option<Vec<u64>> {
            interfaces
                .iter()
                .map(|name| self.interface_tx_bytes(name))
                .collect()
        };
        let first = read_all()?;
        std::thread::sleep(std::time::Duration::from_secs(DOCTOR_SAMPLE_SECS));
        let second = read_all()?;
        let secs = DOCTOR_SAMPLE_SECS as f64;
        Some(
            second
                .into_iter()
                .zip(first)
                .map(|(now, before)| now.saturating_sub(before) as f64 / secs)
                .collect(),
        )
    }

    /// AGENT-DOC-1: collect the health-check readings (the platform-side
    /// data gathering for [crate::doctor]).
    ///
    /// **It only gathers faithfully**: a segment that cannot be read stays
    /// `None` / 0 and is judged `not_assessed` by
    /// [crate::doctor::run_doctor] — the collection layer never guesses
    /// (§7.5), and the verdict layer never reports PASS for missing data.
    pub fn collect_doctor_inputs(&self) -> DoctorInputs {
        // The carrying physical egress: the output interface of the default
        // route (left empty if unreadable; the MTU/rate items degrade
        // themselves).
        let physical = self
            .run(&["ip", "route", "show", "default"])
            .ok()
            .and_then(|out| parse_default_route_interface(&String::from_utf8_lossy(&out.stdout)))
            .unwrap_or_default();
        // The foreign overlay interface: read from zerotier's own network
        // configuration (its portDeviceName is the authority; reverse-guessing
        // from a 10.147. prefix would misjudge once it renames the
        // interface).
        let foreign = self
            .run(&["zerotier-cli", "-j", "listnetworks"])
            .ok()
            .and_then(|out| {
                let value: serde_json::Value =
                    serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).ok()?;
                value
                    .as_array()?
                    .first()?
                    .get("portDeviceName")?
                    .as_str()
                    .map(str::to_string)
            });

        let mut interfaces = vec![self.interface.clone()];
        if !physical.is_empty() && physical != self.interface {
            interfaces.push(physical.clone());
        }
        if let Some(name) = &foreign {
            if name != &self.interface && name != &physical {
                interfaces.push(name.clone());
            }
        }
        // Expand into the fixed order (tunnel, foreign, physical); missing
        // entries are padded with 0, and the rate items are judged as usual.
        let rates = self.sample_tx_rates(&interfaces).map(|values| {
            let at = |name: &str| {
                interfaces
                    .iter()
                    .position(|i| i == name)
                    .and_then(|idx| values.get(idx).copied())
                    .unwrap_or(0.0)
            };
            (
                at(&self.interface),
                foreign.as_deref().map(at).unwrap_or(0.0),
                if physical.is_empty() {
                    0.0
                } else {
                    at(&physical)
                },
            )
        });

        let isolation_rules = self
            .run(&["iptables", "-S"])
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter(|line| line.contains(MESHLET_ISOLATION_COMMENT))
                    .count()
            })
            .unwrap_or(0);
        let foreign_uid = self
            .run(&["id", "-u", FOREIGN_OVERLAY_USER])
            .ok()
            .and_then(|out| String::from_utf8_lossy(&out.stdout).trim().parse().ok());
        let foreign_paths = self
            .run(&["zerotier-cli", "-j", "listpeers"])
            .ok()
            .and_then(|out| parse_zerotier_paths(&String::from_utf8_lossy(&out.stdout)));
        let endpoints = self
            .run(&["wg", "show", &self.interface, "dump"])
            .ok()
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(parse_wg_dump_diag_line)
                    .map(|peer| peer.endpoint)
                    .filter(|endpoint| {
                        !endpoint.is_empty() && endpoint != "(none)" && endpoint != "off"
                    })
                    .collect::<Vec<_>>()
            });
        let mtu_of = |name: &str| -> Option<u32> {
            std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
                .ok()?
                .trim()
                .parse()
                .ok()
        };
        let physical_mtu = if physical.is_empty() {
            None
        } else {
            mtu_of(&physical)
        };
        DoctorInputs {
            collected_at: chrono_now_iso(),
            tunnel_interface: self.interface.clone(),
            physical_interface: physical,
            rates,
            isolation_rules,
            foreign_uid,
            foreign_paths,
            endpoints,
            tunnel_mtu: mtu_of(&self.interface),
            physical_mtu,
        }
    }

    /// Synchronous rollback (the command core of [NetworkBackend::rollback]).
    pub fn rollback_sync(&self) -> Result<ApplyResult, NetworkError> {
        // §10.3: only remove Meshlet's own objects — every data-plane object on
        // the tunnel interface owned by this backend (nat rules / FORWARD
        // allowance / tunnel routes / peers) — while keeping the interface, its
        // addresses, and the system-level ip_forward (system state; the user's
        // existing configuration is left alone).
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
        // The trait surface has no direct-connect retention-set semantics
        // (the trait is the older interface; direct connect goes only through
        // the sync surface).
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

    /// AGENT-ISO-1: idempotently replenish the foreign overlay isolation rules
    /// on every reconcile round (see the trait documentation).
    fn ensure_overlay_isolation(&self) -> Result<(), NetworkError> {
        self.ensure_overlay_isolation_sync()
    }

    /// AGENT-DOC-1: real collection plus verdict (overriding the trait's
    /// "not implemented" default).
    fn doctor(&self) -> DoctorReport {
        run_doctor(&self.collect_doctor_inputs())
    }
}

impl Default for LinuxNetworkBackend {
    fn default() -> Self {
        Self::new()
    }
}
