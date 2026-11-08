use std::path::PathBuf;

use crate::PeerObserved;

impl WindowsNetworkBackend {
    /// 隧道服务安装（重配正确性，BUG 修复）：已存在 → 停/卸载/装新 conf；
    /// 不存在 → 直接装。装完轮询 `sc query` 直到服务 RUNNING（读不到运行
    /// 证据即报错，绝不假装生效——apply_device_plan_sync 随后有内核回读，
    /// 此处只负责「服务确实起来了」）。
    pub(super) fn install_tunnel_reconfigured(
        &self,
        exe: &std::path::Path,
        conf_path: &std::path::Path,
    ) -> Result<(), NetworkError> {
        let existing = self.tunnel_service_exists(&self.interface);
        for command in crate::windows_tunnel::install_plan(existing, &self.interface, conf_path) {
            if matches!(
                command,
                crate::windows_tunnel::WireGuardCommand::UninstallService { .. }
            ) {
                run_wireguard_command(&command, Some(exe))?;
                // 卸载只是发停止信号：旧服务进程退出要时间，退出前仍持有
                // conf 文件。新服务立刻启动读同一份 conf 会报「The process
                // cannot access the file because it is being used by another
                // process」起不来（真机 imac 2026-11-07 事件日志：7045 安装 →
                // 7023 停止连环失败，隧道永远起不来）。等旧服务退干净再装。
                self.wait_tunnel_service_gone(&self.interface);
                continue;
            }
            run_wireguard_command(&command, Some(exe))?;
        }
        self.wait_tunnel_service_running(&self.interface)
    }

    /// 轮询直到旧隧道服务退干净（SCM 里不再 RUNNING / 已删除），最多约 4s；
    /// 超时也继续装（给一次机会，绝不为等退出卡死 apply）。
    fn wait_tunnel_service_gone(&self, tunnel_name: &str) {
        let service = crate::windows_tunnel::tunnel_service_query_name(tunnel_name);
        for _ in 0..16 {
            if self.sc_query_state_code(&service) != Some(4) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
    }

    /// 轮询 `sc query WireGuardTunnel$<name>` 直到 RUNNING（装服务后驱动
    /// 拉起隧道需要一点时间）；超时（约 5s）→ 显式失败。
    fn wait_tunnel_service_running(&self, tunnel_name: &str) -> Result<(), NetworkError> {
        let service = crate::windows_tunnel::tunnel_service_query_name(tunnel_name);
        for _ in 0..20 {
            if self.sc_query_state_code(&service) == Some(4) {
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        Err(NetworkError::ApplyRejected(format!(
            "tunnel service `{service}` did not reach RUNNING within 5s after install"
        )))
    }

    /// `sc query <service>` 的数字状态码（zh/en 双标签解析见
    /// [windows_tunnel::parse_sc_query_state_code]）；命令失败/解析不到 → None。
    fn sc_query_state_code(&self, service: &str) -> Option<u32> {
        let output = std::process::Command::new("sc")
            .args(["query", service])
            .output()
            .ok()?;
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        crate::windows_tunnel::parse_sc_query_state_code(&text)
    }

    fn read_tunnel_peers(&self, tunnel_name: &str) -> Vec<PeerObserved> {
        // 漂移探测：从 `wg.exe show <name> dump` 读回实际生效的 peer。读不到
        // （wg.exe 缺失 / 隧道未运行 / 输出异常）一律返回空——调用方据存在性
        // 判定为「与期望不符」宁可重装收敛，绝不因读数缺失假装一致。
        match self.read_tunnel_dump(tunnel_name) {
            Some(text) => crate::windows_tunnel::parse_wg_dump_peers(&text),
            None => Vec::new(),
        }
    }

    /// `wg.exe show <name> dump` 原文（接口行 + peer 行；解码走
    /// [windows_console] 的活动代码页兜底）。读不到 → None。
    fn read_tunnel_dump(&self, tunnel_name: &str) -> Option<String> {
        let exe = self.find_wg_exe()?;
        let out = std::process::Command::new(&exe)
            .args(["show", tunnel_name, "dump"])
            .output()
            .ok()?;
        Some(format!(
            "{}{}",
            crate::windows_console::decode_output(&out.stdout),
            crate::windows_console::decode_output(&out.stderr),
        ))
    }

    /// 受管接口适配器的实际 IPv4 地址（`netsh interface ipv4 show addresses
    /// name=<if>` 解析；漂移判定的适配器地址读数，BUG②）。读不到 → None。
    fn interface_address(&self) -> Option<std::net::Ipv4Addr> {
        let output = std::process::Command::new("netsh")
            .args(["interface", "ipv4", "show", "addresses", &self.interface])
            .output()
            .ok()?;
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        parse_netsh_interface_ipv4_address(&text)
    }

    /// `wg.exe` 路径解析（与 [Self::find_wireguard_exe] 同纪律：WireGuard for
    /// Windows 把 wg.exe 与 wireguard.exe 装在同一目录，故优先复用其目录）。
    pub(super) fn find_wg_exe(&self) -> Option<PathBuf> {
        if let Some(wireguard) = self.find_wireguard_exe() {
            if let Some(dir) = wireguard.parent() {
                let candidate = dir.join("wg.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                let candidate = dir.join("wg.exe");
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
        None
    }

    /// 私钥 → 公钥（`wg pubkey`，密钥走 stdin、不进 argv，与 Linux 后端同法；
    /// 服务端据此填充下发给设备的 hub peer 公钥，ADR-010）。
    pub fn public_key_from_private(&self, private_key: &str) -> Result<String, NetworkError> {
        let Some(exe) = self.find_wg_exe() else {
            return Err(NetworkError::Unsupported(
                "wg.exe not found; cannot derive public key".to_string(),
            ));
        };
        use std::io::Write;
        let mut child = std::process::Command::new(&exe)
            .arg("pubkey")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| NetworkError::Io(format!("spawn wg pubkey: {e}")))?;
        child
            .stdin
            .take()
            .ok_or_else(|| NetworkError::Io("wg pubkey stdin unavailable".into()))?
            .write_all(format!("{private_key}\n").as_bytes())
            .map_err(|e| NetworkError::Io(format!("write wg pubkey stdin: {e}")))?;
        let out = child
            .wait_with_output()
            .map_err(|e| NetworkError::Io(format!("wg pubkey wait: {e}")))?;
        let key = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if key.is_empty() {
            return Err(NetworkError::Io("wg pubkey returned an empty key".into()));
        }
        Ok(key)
    }

    /// P2P 直连执行层（§12）：`wg.exe show <if> latest-handshakes` →
    /// 公钥 → 秒龄。与 Linux 同一解析器（[crate::parse_handshake_ages]）。
    pub fn handshake_ages_sync(
        &self,
    ) -> Result<std::collections::BTreeMap<String, u64>, NetworkError> {
        let exe = self.find_wg_exe().ok_or_else(|| {
            NetworkError::Unsupported(
                "wg.exe not found. Install WireGuard for Windows.".to_string(),
            )
        })?;
        let out = std::process::Command::new(&exe)
            .args(["show", &self.interface, "latest-handshakes"])
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn wg.exe: {error}")))?;
        if !out.status.success() {
            return Err(NetworkError::ApplyRejected(format!(
                "wg show {} latest-handshakes: {}",
                self.interface,
                crate::windows_console::decode_output(&out.stderr)
            )));
        }
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Ok(crate::parse_handshake_ages(
            &crate::windows_console::decode_output(&out.stdout),
            now_secs,
        ))
    }

    /// P2P 直连 peer 下发（§12）：`wg.exe set <if> peer …`——与 Linux
    /// [`crate::linux::LinuxNetworkBackend::set_direct_peer_sync`] 同参数形状
    /// （allowed-ips 对端 overlay /32 + endpoint + persistent-keepalive）。
    /// WireGuardNT 适配器支持运行期 `wg set`（wireguard.exe 隧道服务创建的
    /// 适配器同样适用），无需重装隧道；写入要求提升权限（agent 以管理员运行）。
    /// 幂等：重复调用结果一致。
    ///
    /// 注意：隧道重装（apply）会重置运行期 peer——调用方（agent）按 tick 重推，
    /// 与 Linux 的 reconcile 语义一致。
    pub fn set_direct_peer_sync(
        &self,
        public_key: &str,
        allowed_ips: &[Ipv4Cidr],
        endpoint: std::net::SocketAddrV4,
        persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        let allowed = allowed_ips
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let endpoint = endpoint.to_string();
        let keepalive = persistent_keepalive_secs.to_string();
        self.run_wg_set(&[
            "peer",
            public_key,
            "allowed-ips",
            &allowed,
            "endpoint",
            &endpoint,
            "persistent-keepalive",
            &keepalive,
        ])
    }

    /// P2P 直连 peer 移除（回退 hub，§12）：`wg.exe set <if> peer <key> remove`。
    /// 幂等：不存在也成功（WireGuard 对缺失 peer 的 remove 是 no-op）。
    pub fn remove_peer_sync(&self, public_key: &str) -> Result<(), NetworkError> {
        self.run_wg_set(&["peer", public_key, "remove"])
    }

    /// SEL-002 直连 endpoint 漫游：`wg.exe set <if> peer <key> endpoint <ip:port>`。
    /// WireGuard 在同一 peer 上改 endpoint 是无缝的（不断开已有握手）。幂等。
    pub fn set_direct_endpoint_sync(
        &self,
        public_key: &str,
        endpoint: std::net::SocketAddrV4,
    ) -> Result<(), NetworkError> {
        let endpoint = endpoint.to_string();
        self.run_wg_set(&["peer", public_key, "endpoint", &endpoint])
    }

    /// `wg.exe set <if> <args>`：运行期变更受管适配器（成功静默；失败携带
    /// wg.exe stderr 文本——权限不足/适配器不存在都在其中可读）。
    fn run_wg_set(&self, args: &[&str]) -> Result<(), NetworkError> {
        let exe = self.find_wg_exe().ok_or_else(|| {
            NetworkError::Unsupported(
                "wg.exe not found. Install WireGuard for Windows.".to_string(),
            )
        })?;
        let out = std::process::Command::new(&exe)
            .arg("set")
            .arg(&self.interface)
            .args(args)
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn wg.exe: {error}")))?;
        if out.status.success() {
            return Ok(());
        }
        Err(NetworkError::ApplyRejected(format!(
            "wg set {}: {}",
            self.interface,
            crate::windows_console::decode_output(&out.stderr)
        )))
    }
}
