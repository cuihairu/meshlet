use super::{MESHLET_NAT_COMMENT_PREFIX, MESHLET_ROUTE_PROTO};
use crate::nat::NatChain;
use crate::{parse_handshake_ages, NetworkError, PeerObserved, TunnelConfig};
use meshlet_domain::Ipv4Cidr;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddrV4;
use std::process::{Command, Output, Stdio};
use std::str::FromStr;

/// Linux network backend: command executor + reconcile-style idempotent apply.
#[derive(Clone)]
pub struct LinuxNetworkBackend {
    /// Test hook: run each command inside this netns (`ip netns exec <ns> ...`).
    pub(super) netns: Option<String>,
    /// Test hook: prefix each command with `sudo -n` (for integration tests run
    /// as an unprivileged user).
    sudo: bool,
    /// Managed tunnel interface name (default `wg0`).
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

    /// Test hook: run commands inside the given network namespace.
    pub fn with_netns(mut self, netns: impl Into<String>) -> Self {
        self.netns = Some(netns.into());
        self
    }

    /// Test hook: run each command with a `sudo -n` prefix.
    pub fn with_sudo(mut self) -> Self {
        self.sudo = true;
        self
    }

    /// Managed interface name (default `wg0`).
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    /// Command prefix (the sudo / netns test hooks are expanded uniformly here).
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

    /// Run a single command. A non-zero exit returns [NetworkError::Io]
    /// carrying stderr (never silent, never faked as success).
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

    /// `bash -c <script>` + piped stdin (the dedicated path for private-key
    /// delivery). The key travels over stdin and never enters argv/the command
    /// line (invisible to `ps`).
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

    /// Output of `wg show <if> peers` (one public key per line).
    pub(super) fn existing_peers(&self) -> Result<Vec<String>, NetworkError> {
        Ok(self
            .peers_on_interface()?
            .into_iter()
            .map(|peer| peer.public_key)
            .collect())
    }

    /// Peer lines of `wg show <if> dump` -> identity-level readings (public
    /// key and allowed-ips). Drift is judged on the **identity set**, not on
    /// the count: an extra peer that should not be there, or a peer whose
    /// allowed-ips was widened, just like a missing peer, must be repaired by
    /// a replay.
    pub(super) fn peers_on_interface(&self) -> Result<Vec<PeerObserved>, NetworkError> {
        let dump = self.run(&["wg", "show", &self.interface, "dump"])?;
        let body = String::from_utf8_lossy(&dump.stdout);
        Ok(body
            .lines()
            .skip(1) // The first line is this machine (starts with private_key); each line after it is one peer.
            .filter_map(Self::parse_peer_dump_line)
            .collect())
    }

    /// Parse one peer dump line (`pubkey presharedkey endpoint allowed-ips …`,
    /// allowed-ips comma separated and possibly empty). Pure function, covered
    /// directly by unit tests.
    pub(super) fn parse_peer_dump_line(line: &str) -> Option<PeerObserved> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // A public key is always a 44-character base64 string (32-byte curve25519)
        // ending in `=`: never invent a peer from blank, truncated or placeholder lines.
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

    /// Reconcile-style peer application: peers outside the target set are
    /// explicitly removed (revocation takes effect immediately, §11.5).
    ///
    /// `keep_keys` are P2P direct-connect peers (§12): the agent's direct
    /// manager adds and removes them on its own (`set_direct_peer_sync` /
    /// `remove_peer_sync`); they are not part of the server plan. During a
    /// plan replay they are treated as a "keep set" — **never deleted**, and
    /// not re-applied either — so that direct-connect state, which is
    /// unrelated to the server's expected hash, is not wiped out by every
    /// configuration change.
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

    /// Seconds since each peer's most recent handshake (`wg show <if>
    /// latest-handshakes`): public key -> age in seconds. A peer that has
    /// never handshaked is not in the output (WireGuard emits 0; it is skipped
    /// here as "no reading"). Used for P2P health probing (§12).
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

    /// Apply a direct peer (P2P, §12): `allowed-ips` only carries the peer's
    /// overlay `/32` + `endpoint` (the direct address) + `persistent-keepalive`
    /// (which both keeps the NAT hole open and doubles as the health-probe
    /// heartbeat). Idempotent: repeated calls produce the same result.
    ///
    /// Longest-prefix matching naturally prefers the `/32` over the hub peer's
    /// whole-range route, so traffic is steered onto the direct path without
    /// touching the hub configuration.
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

    /// Remove a direct peer (fall back to the hub, §12):
    /// `wg set <if> peer <key> remove`. Idempotent: a missing peer also
    /// succeeds (WireGuard treats removing an absent peer as a no-op).
    pub fn remove_peer_sync(&self, public_key: &str) -> Result<(), NetworkError> {
        self.run(&["wg", "set", &self.interface, "peer", public_key, "remove"])?;
        Ok(())
    }

    /// SEL-002: endpoint roaming update for a direct peer (`wg set <if> peer
    /// <key> endpoint <ip:port>`). WireGuard changes a peer's endpoint
    /// **seamlessly** (it does not tear down existing handshakes; it only
    /// steers subsequent packets to the new address), which satisfies "roam
    /// with zero disconnection". Idempotent: setting the same endpoint
    /// repeatedly yields the same result.
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

    /// Tokenize quoted iptables `-S` output (comments contain spaces and must
    /// stay a single token).
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

    /// Rules in the nat table's PREROUTING/POSTROUTING carrying the given
    /// ownership comment (the location logic shared by rollback and
    /// remove_nat). `owner=None` means every `meshlet alias` prefix. Returns
    /// deletion arguments (with `-A` already replaced by `-D`).
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

    /// Meshlet-owned rules on a single chain (the per-chain split of
    /// [meshlet_nat_rules]).
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

    /// For a single `-A CHAIN ...` line, return its deletion arguments
    /// (`-A` swapped for `-D`) if it is a matching Meshlet-owned rule, and
    /// `None` otherwise. Pure function, covered directly by unit tests.
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
