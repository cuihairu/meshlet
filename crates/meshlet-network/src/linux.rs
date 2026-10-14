//! Linux 数据面实现（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）：
//! 受控执行 `ip` / `wg` / `iptables` 系统命令（ADR-007 的受控降级路径，
//! Netlink/nftables 化留待其重评估条件触发）。
//!
//! 所有命令都经 [LinuxNetworkBackend::run] 以参数数组执行（无 shell 拼接，
//! §4.3 禁止项）；每个可写操作都幂等（`replace`/`-C` 探测/`peer remove`
//! 对账），保证重复应用同一修订结果一致（§10.3）。
//!
//! 命令面坑位（netns 集成测试真机验证，见 `tests/wg_forwarding.rs` 头注）：
//! - `wg set` 的 private-key 与 peer 必须**分两次**调用（合并调用会静默丢 peer）；
//! - `wg setconf` 在本环境触发 fopen EPERM，只用 `wg set`；
//! - peer 的 endpoint 指向对端 **netns 侧** 地址（宿主侧 veth 地址会让握手
//!   对错端口）；
//! - 回滚只删 Meshlet 自有对象：所有权标记为 iptables 注释（`meshlet alias
//!   {id}` / `meshlet tunnel`）与「本后端的隧道接口上的对象」，绝不触碰
//!   系统路由与用户已有规则（§10.3、ADR-007）。
//!
//! `netns` / `sudo` 两个字段是测试钩子：生产以特权进程直连宿主网络栈
//! （`netns=None, sudo=false`）；集成测试在无特权 runner 上用 `sudo -n` 进
//! 入 netns 操作（`with_netns(..).with_sudo()`）。

use std::process::{Command, Output, Stdio};

use meshlet_domain::Ipv4Cidr;
use std::net::Ipv4Addr;
use std::str::FromStr;

use crate::nat::{NatChain, NatRule};
use crate::{
    ApplyResult, ConfigRevisionRef, NetworkBackend, NetworkError, NetworkSnapshot, RouteConfig,
    TunnelConfig,
};

/// iptables 所有权注释前缀：nat 规则带 `meshlet alias {id}`（§12.6），filter
/// 的 FORWARD 放行规则带 `meshlet tunnel`——回滚/清理只按注释精确定位。
pub const MESHLET_NAT_COMMENT_PREFIX: &str = "meshlet alias";
pub const MESHLET_FILTER_COMMENT: &str = "meshlet tunnel";

/// Linux 网络后端：命令执行器 + 对账式幂等应用。
pub struct LinuxNetworkBackend {
    /// 测试钩子：命令在此 netns 内执行（`ip netns exec <ns> ...`）。
    netns: Option<String>,
    /// 测试钩子：每条命令前缀 `sudo -n`（无特权集成测试用）。
    sudo: bool,
    /// 受管隧道接口名（默认 `wg0`）。
    interface: String,
}

impl LinuxNetworkBackend {
    pub fn new() -> Self {
        Self {
            netns: None,
            sudo: false,
            interface: "wg0".to_string(),
        }
    }

    /// 测试钩子：在指定网络命名空间内执行命令。
    pub fn with_netns(mut self, netns: impl Into<String>) -> Self {
        self.netns = Some(netns.into());
        self
    }

    /// 测试钩子：以 `sudo -n` 前缀执行每条命令。
    pub fn with_sudo(mut self) -> Self {
        self.sudo = true;
        self
    }

    /// 受管接口名（默认 `wg0`）。
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    /// 命令前缀（sudo / netns 测试钩子展开在这之后统一处理）。
    fn command_prefix(&self) -> Vec<&str> {
        let mut prefix: Vec<&str> = Vec::with_capacity(6);
        if self.sudo {
            prefix.extend(["sudo", "-n"]);
        }
        if let Some(ns) = &self.netns {
            prefix.extend(["ip", "netns", "exec", ns.as_str()]);
        }
        prefix
    }

    /// 执行一条命令。非零退出返回携带 stderr 的 [NetworkError::Io]
    /// （不静默、不假装成功）。
    fn run(&self, argv: &[&str]) -> Result<Output, NetworkError> {
        let mut full = self.command_prefix();
        full.extend_from_slice(argv);

        let out = Command::new(full[0])
            .args(&full[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .map_err(|e| NetworkError::Io(format!("spawn {}: {e}", full.join(" "))))?;
        Self::check(&out, &full)
    }

    /// `bash -c <script>` + 管道 stdin（私钥下发专用路径）。私钥经 stdin
    /// 传递，不进 argv/命令行（`ps` 不可见）。
    fn run_bash_stdin(&self, script: &str, input: &str) -> Result<Output, NetworkError> {
        use std::io::Write;
        let mut full = self.command_prefix();
        full.extend(["bash", "-c"]);
        let mut child = Command::new(full[0])
            .args(&full[1..])
            .arg(script)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| NetworkError::Io(format!("spawn {}: {e}", full.join(" "))))?;
        child
            .stdin
            .as_mut()
            .expect("piped stdin")
            .write_all(input.as_bytes())
            .map_err(|e| NetworkError::Io(format!("stdin write: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| NetworkError::Io(format!("wait: {e}")))?;
        Self::check(&out, &full)
    }

    fn check(out: &Output, full: &[&str]) -> Result<Output, NetworkError> {
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
            let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let detail = if err.is_empty() { stdout } else { err };
            return Err(NetworkError::Io(format!(
                "{} exited {}: {}",
                full.join(" "),
                out.status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                detail
            )));
        }
        Ok(out.clone())
    }

    /// `wg show <if> peers` 输出（每行一个公钥）。
    fn existing_peers(&self) -> Result<Vec<String>, NetworkError> {
        let out = self.run(&["wg", "show", &self.interface, "peers"])?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect())
    }

    /// 对账式 peer 下发：目标集之外的 peer 显式移除（撤销即失效，§11.5）。
    fn reconcile_peers(&self, config: &TunnelConfig) -> Result<(), NetworkError> {
        let existing = self.existing_peers()?;
        for peer in &config.peers {
            let allowed = peer
                .allowed_ips
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(",");
            let mut args: Vec<String> = vec![
                "wg".into(),
                "set".into(),
                self.interface.clone(),
                "peer".into(),
                peer.public_key.clone(),
                "allowed-ips".into(),
                allowed,
            ];
            if let Some(ep) = &peer.endpoint {
                args.extend(["endpoint".into(), ep.clone()]);
            }
            if let Some(ka) = peer.persistent_keepalive_secs {
                args.extend(["persistent-keepalive".into(), ka.to_string()]);
            }
            let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            self.run(&argv)?;
        }
        for key in existing {
            if !config.peers.iter().any(|p| p.public_key == key) {
                self.run(&["wg", "set", &self.interface, "peer", &key, "remove"])?;
            }
        }
        Ok(())
    }

    /// `ip -4 route show dev <if>` → 目的网段列表（回滚与 inspect 共用解析）。
    /// `default` 等非 CIDR 行跳过（不归 Meshlet 管，也不该在回滚里误删）。
    fn routes_on_interface(&self) -> Result<Vec<Ipv4Cidr>, NetworkError> {
        let out = self.run(&["ip", "-4", "route", "show", "dev", &self.interface])?;
        let mut dsts = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let dst = line.split_whitespace().next().unwrap_or("");
            if dst.is_empty() || dst == "default" {
                continue;
            }
            match Ipv4Cidr::from_str(dst) {
                Ok(cidr) => dsts.push(cidr),
                Err(_) => return Err(NetworkError::Io(format!("unparsable route line: {line}"))),
            }
        }
        Ok(dsts)
    }

    /// 带引号的 iptables `-S` 输出分词（注释含空格，需保留为单 token）。
    fn split_iptables_line(line: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        for ch in line.chars() {
            match ch {
                '"' => in_quotes = !in_quotes,
                ' ' if !in_quotes => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                _ => cur.push(ch),
            }
        }
        if !cur.is_empty() {
            tokens.push(cur);
        }
        tokens
    }

    /// nat 表 PREROUTING/POSTROUTING 中携带指定所有权注释的规则（回滚与
    /// remove_nat 共用定位逻辑）。`owner=None` = 全部 `meshlet alias` 前缀。
    /// 返回删除用参数（`-A` 已换成 `-D`）。
    fn meshlet_nat_rules(&self, owner: Option<&str>) -> Result<Vec<Vec<String>>, NetworkError> {
        let mut deletions = Vec::new();
        for chain in [NatChain::Prerouting, NatChain::Postrouting] {
            let out = self.run(&["iptables", "-t", "nat", "-S", chain.as_str()])?;
            for line in String::from_utf8_lossy(&out.stdout).lines() {
                let tokens = Self::split_iptables_line(line);
                if tokens.len() < 2 || tokens[0] != "-A" {
                    continue;
                }
                let comment = tokens
                    .iter()
                    .position(|t| t == "--comment")
                    .and_then(|i| tokens.get(i + 1));
                let matches = comment
                    .map(|c| match owner {
                        Some(o) => *c == o,
                        None => c.starts_with(MESHLET_NAT_COMMENT_PREFIX),
                    })
                    .unwrap_or(false);
                if matches {
                    let mut del = vec!["-D".to_string(), tokens[1].clone()];
                    del.extend(tokens[2..].iter().cloned());
                    deletions.push(del);
                }
            }
        }
        Ok(deletions)
    }
}

impl LinuxNetworkBackend {
    /// 同步检查快照（inspect 的命令核心；服务端同步 backend 直接调用）。
    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
        let tunnel_exists = self.run(&["ip", "link", "show", &self.interface]).is_ok();
        let forwarding_enabled = self
            .run(&["sysctl", "-n", "net.ipv4.ip_forward"])
            .ok()
            .and_then(|out| match String::from_utf8_lossy(&out.stdout).trim() {
                "1" => Some(true),
                "0" => Some(false),
                _ => None,
            });
        let peer_count = if tunnel_exists {
            self.existing_peers()?.len() as u32
        } else {
            0
        };
        let installed_routes = if tunnel_exists {
            self.routes_on_interface()?
        } else {
            Vec::new()
        };
        let nat_rules_present = !self.meshlet_nat_rules(None)?.is_empty();
        Ok(NetworkSnapshot {
            tunnel_exists,
            forwarding_enabled,
            peer_count,
            installed_routes,
            nat_rules_present,
        })
    }

    /// 同步隧道应用（[NetworkBackend::apply_tunnel] 的命令核心）。
    pub fn apply_tunnel_sync(&self, config: &TunnelConfig) -> Result<ApplyResult, NetworkError> {
        let ifname = config.name.clone();
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
        if let Some(mtu) = config.mtu {
            self.run(&["ip", "link", "set", &ifname, "mtu", &mtu.to_string()])?;
        }
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
        self.reconcile_peers(config)?;
        Ok(ApplyResult::ok())
    }

    /// 同步路由/ip_forward/FORWARD 应用（[NetworkBackend::apply_routes] 核心）。
    pub fn apply_routes_sync(&self, routes: &[RouteConfig]) -> Result<ApplyResult, NetworkError> {
        self.run(&["sysctl", "-w", "net.ipv4.ip_forward=1"])?;
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
            let argv: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            self.run(&argv)?;
        }
        Ok(ApplyResult::ok())
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

    /// 同步回滚（[NetworkBackend::rollback] 的命令核心）。
    pub fn rollback_sync(&self) -> Result<ApplyResult, NetworkError> {
        // §10.3：只删 Meshlet 自有对象——本后端拥有的隧道接口上的全部数据面
        // 对象（nat 规则 / FORWARD 放行 / 隧道路由 / peer），保留接口、地址与
        // 系统级 ip_forward（属系统状态，不动用户既有配置）。
        for del_args in self.meshlet_nat_rules(None)? {
            let mut full = vec!["iptables".to_string(), "-t".to_string(), "nat".to_string()];
            full.extend(del_args);
            let args: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
            self.run(&args)?;
        }
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
            if owned {
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
        self.apply_tunnel_sync(&config)
    }

    async fn apply_routes(&self, routes: Vec<RouteConfig>) -> Result<ApplyResult, NetworkError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::NatAction;

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
    fn nat_apply_probes_with_the_same_rule_shape() {
        // apply_nat_sync 组装 `iptables -t nat <args>`；-C 探测与 -A 下发只差
        // flag 位（index 3），保证探测与实际规则形状一致。
        let rule = NatRule {
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
}
