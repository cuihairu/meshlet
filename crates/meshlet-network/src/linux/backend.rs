use super::{MESHLET_NAT_COMMENT_PREFIX, MESHLET_ROUTE_PROTO};
use crate::nat::NatChain;
use crate::{parse_handshake_ages, NetworkError, PeerObserved, TunnelConfig};
use meshlet_domain::Ipv4Cidr;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddrV4;
use std::process::{Command, Output, Stdio};
use std::str::FromStr;

/// Linux 网络后端：命令执行器 + 对账式幂等应用。
#[derive(Clone)]
pub struct LinuxNetworkBackend {
    /// 测试钩子：命令在此 netns 内执行（`ip netns exec <ns> ...`）。
    pub(super) netns: Option<String>,
    /// 测试钩子：每条命令前缀 `sudo -n`（无特权集成测试用）。
    sudo: bool,
    /// 受管隧道接口名（默认 `wg0`）。
    pub(super) interface: String,
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
    pub(super) fn command_prefix(&self) -> Vec<&str> {
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
    pub(super) fn run(&self, argv: &[&str]) -> Result<Output, NetworkError> {
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
    pub(super) fn run_bash_stdin(&self, script: &str, input: &str) -> Result<Output, NetworkError> {
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
    pub(super) fn existing_peers(&self) -> Result<Vec<String>, NetworkError> {
        Ok(self
            .peers_on_interface()?
            .into_iter()
            .map(|peer| peer.public_key)
            .collect())
    }

    /// `wg show <if> dump` 的 peer 行 → 身份级读数（公钥 + allowed-ips）。
    /// 漂移判定按**身份集合**而非条数：多一个不该在的 peer、某 peer 的
    /// allowed-ips 被改宽，都与「少一个 peer」同样必须重放纠回。
    pub(super) fn peers_on_interface(&self) -> Result<Vec<PeerObserved>, NetworkError> {
        let dump = self.run(&["wg", "show", &self.interface, "dump"])?;
        let body = String::from_utf8_lossy(&dump.stdout);
        Ok(body
            .lines()
            .skip(1) // 首行是本机（private_key 起头），其后每行一个 peer。
            .filter_map(Self::parse_peer_dump_line)
            .collect())
    }

    /// 单行 peer dump 解析（`pubkey presharedkey endpoint allowed-ips …`，
    /// allowed-ips 逗号分隔、可为空）。纯函数，单测直接覆盖。
    pub(super) fn parse_peer_dump_line(line: &str) -> Option<PeerObserved> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // 公钥固定为 44 字符 base64（32 字节 curve25519）且以 `=` 结尾：
        // 空行 / 残行 / 占位串不臆造 peer。
        let public_key = fields.first()?;
        if public_key.len() != 44 || !public_key.ends_with('=') {
            return None;
        }
        let public_key = public_key.to_string();
        let allowed_ips = fields
            .get(3)
            .unwrap_or(&"")
            .split(',')
            .filter_map(|c| c.trim().parse().ok())
            .collect();
        Some(PeerObserved {
            public_key,
            allowed_ips,
        })
    }

    /// 对账式 peer 下发：目标集之外的 peer 显式移除（撤销即失效，§11.5）。
    ///
    /// `keep_keys` 是 P2P 直连对端（§12）：它们由 agent 的直连管理器单独
    /// 增删（`set_direct_peer_sync` / `remove_peer_sync`），不属于服务端计划。
    /// 计划重放时把它们当「保留集」，**只不删**、不重刷——避免与服务端期望
    /// 哈希无关的直连态在每次配置变更时被冲掉。
    pub(super) fn reconcile_peers(
        &self,
        config: &TunnelConfig,
        keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
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
            if config.peers.iter().any(|p| p.public_key == key) {
                continue;
            }
            if keep_keys.contains(&key) {
                continue;
            }
            self.run(&["wg", "set", &self.interface, "peer", &key, "remove"])?;
        }
        Ok(())
    }

    /// 各对端最近一次握手距今秒数（`wg show <if> latest-handshakes`）：
    /// 公钥 → 距今秒数。从未握手的 peer 不在输出里（WireGuard 输出 0，
    /// 这里按「无读数」跳过）。P2P 健康探测用（§12）。
    pub fn handshake_ages_sync(&self) -> Result<BTreeMap<String, u64>, NetworkError> {
        let out = self.run(&["wg", "show", &self.interface, "latest-handshakes"])?;
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(parse_handshake_ages(
            &String::from_utf8_lossy(&out.stdout),
            now_secs,
        ))
    }

    /// 直连 peer 下发（P2P，§12）：`allowed-ips` 只写对端 overlay `/32` +
    /// `endpoint`（直连地址）+ `persistent-keepalive`（既开 NAT 打洞的洞，
    /// 也是健康探测的心跳）。幂等：重复调用结果一致。
    ///
    /// `/32` 最长前缀匹配天然优先于 hub peer 的整段路由，故不触碰 hub 配置
    /// 也能把流量引到直连路径。
    pub fn set_direct_peer_sync(
        &self,
        public_key: &str,
        allowed_ips: &[Ipv4Cidr],
        endpoint: SocketAddrV4,
        persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        let allowed = allowed_ips
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let endpoint = endpoint.to_string();
        let keepalive = persistent_keepalive_secs.to_string();
        self.run(&[
            "wg",
            "set",
            &self.interface,
            "peer",
            public_key,
            "allowed-ips",
            &allowed,
            "endpoint",
            &endpoint,
            "persistent-keepalive",
            &keepalive,
        ])?;
        Ok(())
    }

    /// 移除直连 peer（回退 hub，§12）：`wg set <if> peer <key> remove`。
    /// 幂等：不存在也成功（WireGuard 对缺失 peer 的 remove 是 no-op）。
    pub fn remove_peer_sync(&self, public_key: &str) -> Result<(), NetworkError> {
        self.run(&["wg", "set", &self.interface, "peer", public_key, "remove"])?;
        Ok(())
    }

    /// SEL-002：直连 peer 的 endpoint 漫游更新（`wg set <if> peer <key> endpoint
    /// <ip:port>`）。WireGuard 在同一 peer 上改 endpoint 是**无缝**的（不
    /// 断开已有握手，只把后续包引向新地址），满足「漫游零断线」。幂等：
    /// 重复设置同一 endpoint 结果一致。
    pub fn set_direct_endpoint_sync(
        &self,
        public_key: &str,
        endpoint: SocketAddrV4,
    ) -> Result<(), NetworkError> {
        let endpoint = endpoint.to_string();
        self.run(&[
            "wg",
            "set",
            &self.interface,
            "peer",
            public_key,
            "endpoint",
            &endpoint,
        ])?;
        Ok(())
    }

    /// `ip -4 route show dev <if> proto <marker>` → successful Meshlet route
    /// destinations. The routing protocol marker is the route-side ownership
    /// tag: unlike `proto kernel` connected routes, these objects can be
    /// enumerated safely even after the local agent ledger is lost.
    pub(super) fn routes_on_interface(&self) -> Result<Vec<Ipv4Cidr>, NetworkError> {
        let out = self.run(&[
            "ip",
            "-4",
            "route",
            "show",
            "dev",
            &self.interface,
            "proto",
            MESHLET_ROUTE_PROTO,
        ])?;
        let mut dsts = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut fields = line.split_whitespace();
            let dst = fields.next().unwrap_or("");
            if dst.is_empty() || dst == "default" {
                continue;
            }
            let cidr = match dst.parse::<std::net::Ipv4Addr>() {
                Ok(addr) => {
                    let prefix = fields
                        .next()
                        .and_then(|spec| spec.strip_prefix('/'))
                        .and_then(|prefix| prefix.parse().ok())
                        .unwrap_or(32);
                    Ipv4Cidr::new(addr, prefix)
                }
                Err(_) => Ipv4Cidr::from_str(dst),
            };
            let cidr = match cidr {
                Ok(cidr) => cidr,
                Err(_) => return Err(NetworkError::Io(format!("unparsable route line: {line}"))),
            };
            dsts.push(cidr);
        }
        Ok(dsts)
    }

    /// 带引号的 iptables `-S` 输出分词（注释含空格，需保留为单 token）。
    pub(super) fn split_iptables_line(line: &str) -> Vec<String> {
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
    pub(super) fn meshlet_nat_rules(
        &self,
        owner: Option<&str>,
    ) -> Result<Vec<Vec<String>>, NetworkError> {
        let mut deletions = Vec::new();
        for chain in [NatChain::Prerouting, NatChain::Postrouting] {
            deletions.extend(self.meshlet_nat_rules_in(chain, owner)?);
        }
        Ok(deletions)
    }

    /// 单条链上的 Meshlet 所有权规则（[meshlet_nat_rules] 的链级拆分）。
    fn meshlet_nat_rules_in(
        &self,
        chain: NatChain,
        owner: Option<&str>,
    ) -> Result<Vec<Vec<String>>, NetworkError> {
        let out = self.run(&["iptables", "-t", "nat", "-S", chain.as_str()])?;
        let mut deletions = Vec::new();
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            if let Some(del) = Self::meshlet_rule_deletion(line, owner) {
                deletions.push(del);
            }
        }
        Ok(deletions)
    }

    /// 单行 `-A CHAIN ...` 若为匹配的 Meshlet 所有权规则，返回其删除参数
    /// （`-A` 换成 `-D`）；否则 `None`。纯函数，单测直接覆盖。
    pub(super) fn meshlet_rule_deletion(line: &str, owner: Option<&str>) -> Option<Vec<String>> {
        let tokens = Self::split_iptables_line(line);
        if tokens.len() < 2 || tokens[0] != "-A" {
            return None;
        }
        let comment = tokens
            .iter()
            .position(|t| t == "--comment")
            .and_then(|i| tokens.get(i + 1))?;
        let matches = match owner {
            Some(o) => *comment == o,
            None => comment.starts_with(MESHLET_NAT_COMMENT_PREFIX),
        };
        if !matches {
            return None;
        }
        let mut del = vec!["-D".to_string(), tokens[1].clone()];
        del.extend(tokens[2..].iter().cloned());
        Some(del)
    }
}
