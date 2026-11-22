//! macOS boringtun 后端——命令计划层 + `cfg(target_os = "macos")` 执行器。
//!
//! 路径（见 [crate::macos_wireguard_bt] 模块文档，②-3 决策）：**PATH B——
//! spawn boringtun-cli + wg.sock UAPI**。boringtun-cli 起 utun 并挂
//! `/var/run/wireguard/*.sock`，meshlet 经 `wg` 工具配密钥/peer、本文件的
//! 命令计划配**哑 utun** 的 IP/路由/MTU。
//!
//! 三层纪律：
//!
//! - **命令计划（全平台纯函数）**：[bt_apply_commands] 把 [BtInterfacePlan]
//!   → `Vec<[BtCommand]>`（确定性顺序：地址 → MTU → 逐 peer 逐 allowed_ip
//!   路由）。mac 无 netns 等价物，测试钩子退化为**命令记录器 mock**——单测
//!   断言生成的命令序列，不真执行。
//! - **执行器（`cfg(target_os = "macos")`）**：`exec` 子模块的
//!   `MacNetworkBackend` 把命令计划逐条 spawn（对齐 [crate::linux::backend]
//!   执行器模型：前缀测试钩子、非零退出落 [NetworkError::Io] 携带 stderr）。
//!   宿主 CI 不跑 macOS 测试，本层经 `x86_64-apple-darwin` 交叉 check 编译
//!   验证。
//! - **接口名守门**：utun 名白名单对 `resolved_iface` 同样生效——执行层从
//!   `WG_TUN_NAME_FILE` 读到的内核分配名同样不可信（fail closed）。

use crate::macos_wireguard_bt::{bt_utun_name, BtInterfacePlan};
use crate::NetworkError;
use meshlet_domain::Ipv4Cidr;
use std::net::Ipv4Addr;

/// 单条已生成命令（哑设备的自管面：地址 / MTU / 路由）。
///
/// 变体即 macOS 命令方言的最小闭集——密钥/peer 配置面走 `wg`（UAPI），
/// 不在本枚举内。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BtCommand {
    /// `ifconfig <iface> inet <local> <dest> netmask <mask>`——utun 是
    /// 点对点设备，dest 取自身（wireguard-go / boringtun-cli 同款），转发
    /// 由下方逐条路由驱动。
    SetAddress {
        iface: String,
        local: Ipv4Addr,
        dest: Ipv4Addr,
        mask: Ipv4Addr,
    },
    /// `ifconfig <iface> mtu <mtu>`——MTU 经 ifconfig 设置（计划守门
    /// [crate::macos_wireguard_bt::BT_INTERFACE_MTU]）。
    SetMtu { iface: String, mtu: u32 },
    /// `route -n add -net <network> -netmask <mask> -interface <iface>`——
    /// allowed_ips 逐条落路由（peer 级 allowed-ips 即身份级路由）。
    AddRoute {
        iface: String,
        network: Ipv4Addr,
        mask: Ipv4Addr,
    },
}

impl BtCommand {
    /// 渲染为 argv（不执行）。测试断言序列与参数均走此形。
    pub fn argv(&self) -> Vec<String> {
        match self {
            Self::SetAddress {
                iface,
                local,
                dest,
                mask,
            } => vec![
                "ifconfig".into(),
                iface.clone(),
                "inet".into(),
                local.to_string(),
                dest.to_string(),
                "netmask".into(),
                mask.to_string(),
            ],
            Self::SetMtu { iface, mtu } => vec![
                "ifconfig".into(),
                iface.clone(),
                "mtu".into(),
                mtu.to_string(),
            ],
            Self::AddRoute {
                iface,
                network,
                mask,
            } => vec![
                "route".into(),
                "-n".into(),
                "add".into(),
                "-net".into(),
                network.to_string(),
                "-netmask".into(),
                mask.to_string(),
                "-interface".into(),
                iface.clone(),
            ],
        }
    }
}

/// 实际接口名解析（纯函数）：计划名是 `utun`（内核自选）时取 `kernel_assigned`
/// （执行层读 `WG_TUN_NAME_FILE` 得到）；计划名是 `utun<digits>` 显式指定时
/// 直接采用。解析结果同样过 [bt_utun_name] 守门——内核给的名字也不信。
pub fn bt_resolved_interface_name(
    plan: &BtInterfacePlan,
    kernel_assigned: &str,
) -> Result<String, crate::macos_wireguard_bt::BtPlanError> {
    if plan.interface_name == "utun" {
        bt_utun_name(kernel_assigned)
    } else {
        Ok(plan.interface_name.clone())
    }
}

/// 命令计划：[BtInterfacePlan] → `Vec<[BtCommand]>`（确定性顺序）。
///
/// - 第一条：接口地址（`inet <local> <dest> netmask <mask>`，dest=自身）；
/// - 第二条：MTU（计划 `mtu` 为 `None` 时省略，不静默补默认）；
/// - 其后：每 peer 的每条 allowed_ip 一条 `route add`（peer 序 →
///   allowed_ip 序，不排序、不合并——与 linux 路由平铺语义同构）。
///
/// `resolved_iface` 是实际 utun 名（[bt_resolved_interface_name] 解析后的），
/// 过守门拒绝非白名单名。
pub fn bt_apply_commands(
    plan: &BtInterfacePlan,
    resolved_iface: &str,
) -> Result<Vec<BtCommand>, NetworkError> {
    bt_utun_name(resolved_iface)?;
    let cidr = Ipv4Cidr::from_host_address(plan.address, plan.address_prefix).map_err(|error| {
        NetworkError::ApplyRejected(format!(
            "address {}/{}: {error}",
            plan.address, plan.address_prefix
        ))
    })?;
    let mut commands = Vec::new();
    commands.push(BtCommand::SetAddress {
        iface: resolved_iface.to_string(),
        local: plan.address,
        dest: plan.address,
        mask: cidr.mask(),
    });
    if let Some(mtu) = plan.mtu {
        commands.push(BtCommand::SetMtu {
            iface: resolved_iface.to_string(),
            mtu,
        });
    }
    for peer in &plan.peers {
        for allowed in &peer.allowed_ips {
            commands.push(BtCommand::AddRoute {
                iface: resolved_iface.to_string(),
                network: allowed.network(),
                mask: allowed.mask(),
            });
        }
    }
    Ok(commands)
}

#[cfg(target_os = "macos")]
mod exec {
    use super::BtCommand;
    use crate::NetworkError;
    use std::process::{Command, Output, Stdio};

    /// macOS 命令执行器（`cfg(target_os = "macos")`，宿主 CI 不跑 macOS
    /// 测试，仅经 `x86_64-apple-darwin` 交叉 check 编译验证）。
    pub struct MacNetworkBackend {
        /// 测试钩子：每条命令前缀 `sudo -n`（无特权验证用）。
        sudo: bool,
    }

    impl MacNetworkBackend {
        pub fn new() -> Self {
            Self { sudo: false }
        }

        /// 测试钩子：以 `sudo -n` 前缀执行每条命令。
        pub fn with_sudo(mut self) -> Self {
            self.sudo = true;
            self
        }

        /// 命令前缀（sudo 测试钩子）。
        fn command_prefix(&self) -> Vec<&'static str> {
            if self.sudo {
                vec!["sudo", "-n"]
            } else {
                Vec::new()
            }
        }

        /// `sudo -n` 失败是否因「需要密码/未配 NOPASSWD」。
        ///
        /// 只匹配 sudo 自身报错面，不匹配下游命令失败（那走 Io）。
        fn sudo_password_required(stderr: &str) -> bool {
            let lower = stderr.to_ascii_lowercase();
            lower.contains("password is required")
                || lower.contains("a password is required")
                || lower.contains("no password was provided")
                || lower.contains("may not run sudo")
        }

        /// 执行一条命令。非零退出返回携带 stderr 的 [NetworkError::Io]
        /// （不静默、不假装成功）。
        ///
        /// `sudo` 模式下先过 [crate::macos_privileges] 白名单：白名单外
        /// 拒绝提升（fail-closed）；`sudo -n` 因未配置 NOPASSWD / 需密码
        /// 失败时返回 [NetworkError::InsufficientPrivileges] 并点名
        /// `docs/macos-privileges.md`。
        pub fn run(&self, argv: &[&str]) -> Result<Output, NetworkError> {
            let owned: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
            if self.sudo {
                crate::macos_privileges::check_sudo_elevation(&owned)?;
            }
            let mut full = self.command_prefix();
            full.extend_from_slice(argv);
            let out = Command::new(full[0])
                .args(&full[1..])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .map_err(|e| NetworkError::Io(format!("spawn {}: {e}", full.join(" "))))?;
            if !out.status.success() {
                let stderr = String::from_utf8_lossy(&out.stderr);
                if self.sudo && Self::sudo_password_required(&stderr) {
                    return Err(NetworkError::InsufficientPrivileges(format!(
                        "sudo -n for `{}` needs a sudoers NOPASSWD entry \
                         (docs/macos-privileges.md): {}",
                        full.join(" "),
                        stderr.trim()
                    )));
                }
                return Err(NetworkError::Io(format!(
                    "{} failed ({}): {}",
                    full.join(" "),
                    out.status,
                    stderr.trim()
                )));
            }
            Ok(out)
        }

        /// 按序执行命令计划（第一条失败即停，后续不执行——fail closed）。
        pub fn apply(&self, commands: &[BtCommand]) -> Result<(), NetworkError> {
            for command in commands {
                let owned = command.argv();
                let argv: Vec<&str> = owned.iter().map(String::as_str).collect();
                self.run(&argv)?;
            }
            Ok(())
        }
    }

    impl Default for MacNetworkBackend {
        fn default() -> Self {
            Self::new()
        }
    }
}

#[cfg(target_os = "macos")]
pub use exec::MacNetworkBackend;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerConfig;
    use crate::TunnelConfig;

    fn tunnel() -> TunnelConfig {
        TunnelConfig {
            name: "net-a".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 16,
            listen_port: Some(51821),
            peers: vec![
                peer("pub-a", Some("100.64.0.2:51820"), &["10.240.0.8/32"]),
                peer(
                    "pub-b",
                    Some("100.64.0.3:51820"),
                    &["10.240.0.9/32", "10.99.0.0/24"],
                ),
            ],
            mtu: Some(1420),
            private_key: Some("secret-key-material".into()),
        }
    }

    fn peer(public_key: &str, endpoint: Option<&str>, allowed_ips: &[&str]) -> PeerConfig {
        PeerConfig {
            public_key: public_key.into(),
            allowed_ips: allowed_ips.iter().map(|ip| ip.parse().unwrap()).collect(),
            endpoint: endpoint.map(str::to_string),
            persistent_keepalive_secs: Some(25),
        }
    }

    fn plan() -> BtInterfacePlan {
        crate::macos_wireguard_bt::bt_interface_plan(&tunnel(), "utun5").unwrap()
    }

    /// ④ 钉：命令序列顺序与参数——地址 → MTU → 逐 peer 逐 allowed_ip 路由
    /// （peer 序、allowed_ip 序保持，不排序不合并）。
    #[test]
    fn command_sequence_is_deterministic_and_ordered() {
        let commands = bt_apply_commands(&plan(), "utun5").unwrap();
        let rendered: Vec<Vec<String>> = commands.iter().map(BtCommand::argv).collect();
        assert_eq!(
            rendered,
            vec![
                vec![
                    "ifconfig",
                    "utun5",
                    "inet",
                    "10.240.0.7",
                    "10.240.0.7",
                    "netmask",
                    "255.255.0.0",
                ],
                vec!["ifconfig", "utun5", "mtu", "1420"],
                vec![
                    "route",
                    "-n",
                    "add",
                    "-net",
                    "10.240.0.8",
                    "-netmask",
                    "255.255.255.255",
                    "-interface",
                    "utun5"
                ],
                vec![
                    "route",
                    "-n",
                    "add",
                    "-net",
                    "10.240.0.9",
                    "-netmask",
                    "255.255.255.255",
                    "-interface",
                    "utun5"
                ],
                vec![
                    "route",
                    "-n",
                    "add",
                    "-net",
                    "10.99.0.0",
                    "-netmask",
                    "255.255.255.0",
                    "-interface",
                    "utun5"
                ],
            ]
        );
    }

    /// ④ 钉：地址命令 dest=自身（点对点 utun，转发由路由驱动）。
    #[test]
    fn address_command_uses_self_as_point_to_point_dest() {
        let commands = bt_apply_commands(&plan(), "utun5").unwrap();
        assert_eq!(
            commands[0],
            BtCommand::SetAddress {
                iface: "utun5".into(),
                local: "10.240.0.7".parse().unwrap(),
                dest: "10.240.0.7".parse().unwrap(),
                mask: "255.255.0.0".parse().unwrap(),
            }
        );
    }

    /// ④ 钉：MTU 为 `None` 时不补命令（不静默套用 1420 假装满足）。
    #[test]
    fn mtu_none_omits_mtu_command() {
        let mut tunnel = tunnel();
        tunnel.mtu = None;
        let plan = crate::macos_wireguard_bt::bt_interface_plan(&tunnel, "utun5").unwrap();
        let commands = bt_apply_commands(&plan, "utun5").unwrap();
        assert_eq!(commands.len(), 4, "no MTU command when plan.mtu is None");
        assert!(commands
            .iter()
            .all(|c| !matches!(c, BtCommand::SetMtu { .. })));
    }

    /// ④ 钉：`resolved_iface` 同样过 utun 白名单（WG_TUN_NAME_FILE 读来的
    /// 内核名也不信，fail closed）。
    #[test]
    fn resolved_iface_is_validated() {
        assert_eq!(
            bt_apply_commands(&plan(), "wg0"),
            Err(NetworkError::ApplyRejected(
                crate::macos_wireguard_bt::BtPlanError::UtunNameInvalid { name: "wg0".into() }
                    .to_string()
            ))
        );
    }

    /// ④ 钉：显式名走计划名（内核给的名字被忽略）；`utun` 名走内核分配名。
    #[test]
    fn resolved_interface_name_prefers_explicit_and_falls_back_to_kernel() {
        let explicit = crate::macos_wireguard_bt::bt_interface_plan(&tunnel(), "utun5").unwrap();
        assert_eq!(
            bt_resolved_interface_name(&explicit, "utun7").unwrap(),
            "utun5",
            "explicit plan name wins over kernel assignment"
        );

        let bare = crate::macos_wireguard_bt::bt_interface_plan(&tunnel(), "utun").unwrap();
        assert_eq!(bt_resolved_interface_name(&bare, "utun7").unwrap(), "utun7");
        assert_eq!(
            bt_resolved_interface_name(&bare, "wg0"),
            Err(crate::macos_wireguard_bt::BtPlanError::UtunNameInvalid { name: "wg0".into() })
        );
    }

    /// ④ 钉：命令计划不碰私钥（密钥面在 `wg`/boringtun-cli UAPI 配置文件
    /// 里，命令序列与私钥字节无关——Debug 序列化含私钥的计划也一样）。
    #[test]
    fn command_plan_never_carries_private_key_bytes() {
        let commands = bt_apply_commands(&plan(), "utun5").unwrap();
        let rendered = format!("{commands:?}");
        assert!(!rendered.contains("secret-key-material"), "{rendered}");
        assert!(!rendered.contains("private_key"), "{rendered}");
    }
}
