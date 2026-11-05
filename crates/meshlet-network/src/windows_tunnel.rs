//! Windows 隧道计划层（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 选型依据（ADR-008 复审门）：本子系统采用 **WireGuardNT**（官方 WireGuard
//! for Windows 的 `wireguard.exe` + `wireguard-nt` 内核驱动，一条受管服务承载
//! 一个隧道，`WireGuardTunnel$<name>`），**不是** wintun。理由：wintun 只是
//! TUN 适配器（无驱动侧用户态隧道），必须再自研/自押一个用户态 WireGuard
//! 栈（wireguard-go / boringtun）才能完成隧道语义；而 WireGuardNT 的隧道
//! 服务模型与 Linux 侧 `wg set` + 系统服务自启同构，且驱动与用户态二进制由
//! 官方安装包管理，本仓无需引入第二套 WireGuard 实现。ADR-008 复审条件
//! （Windows 环境就绪后重审 wintun 取舍）保持有效。
//!
//! 本模块包含**纯规划**与 `#[cfg(windows)]` 执行层：WireGuard conf 渲染、
//! `wireguard.exe /installtunnelservice` 等命令参数构造、失败文本分类与
//! 受控执行。计划层函数在任意平台编译并单测（本仓 CI 的 Linux 侧即可跑
//! 绿）；执行层 `#[cfg(windows)]` 只调计划函数、经
//! [crate::windows_console] 解码本地化输出。
//!
//! 与 [windows_service](windows_service)、[windows_firewall](windows_firewall)
//! 同一纪律：
//!
//! - **受控命令**：只从类型化 [TunnelConfig] 渲染 conf 与
//!   `wireguard.exe` 子命令 argv，控制面不能注入任意文本；
//! - **私钥边界（ADR-010）**：conf 的 `PrivateKey` 行**只在
//!   [TunnelConfig::private_key] 为 `Some` 时渲染**——agent 本地注入私钥，
//!   服务端永不携带；`None` = 不写该行（服务沿用现存密钥，幂等重应用），
//!   与 Linux 侧 `apply_tunnel_sync` 的 `None` 契约同构；
//! - **幂等 re-apply 与已存在隧道的重配（BUG 修复）**：安装前先查隧道服务
//!   是否已存在（[`install_plan`]）——已存在时先停/卸载旧服务再装新 conf
//!   （`wireguard.exe` 无 setconf 等价 CLI，卸载重建即重配路径）；此前把
//!   "already installed" 失败文本判成幂等成功是**静默 no-op**（key/地址
//!   不更新，todo.md Windows 部署发现），已移除。卸载不存在隧道按
//!   [`NetworkError`] 分类放行——WireGuardNT 隧道由 Windows 服务承载，
//!   不存在时服务控制管理器返回 1060，复用 [windows_service] 已真机取证的
//!   `service_absent` 文案；
//! - **fail closed**：权限文案宽匹配映射为
//!   [`NetworkError::InsufficientPrivileges`]；未知失败统一
//!   [`NetworkError::ApplyRejected`] 并携带 wireguard.exe 原文首行。
//!
//! **执行层真机验证（仍缺，如实记录）**：WireGuardNT 驱动安装后的隧道全
//! 生命周期（install → start → stop → uninstall）、提权执行层真机报文、
//! 开机恢复重启验证，以及据此做出的 [crate::SystemBackend] 接线决策。本轮
//! 交付计划层与 `#[cfg(windows)]` 执行层原语；TODO #52 / R-05 保持未勾，
//! Windows 仍保持 [crate::unsupported] 的显式占位，不接
//! [crate::SystemBackend]。

use crate::{NetworkError, TunnelConfig, DEFAULT_TUNNEL_MTU};

/// 一条受控 `wireguard.exe` 命令（计划态；执行见 [exec]）。
///
/// 命令形状锁定官方 CLI（WireGuard for Windows）：
/// `wireguard.exe /installtunnelservice <conf>`、`/uninstalltunnelservice
/// <tunnel>`、`/starttunnelservice <tunnel>`、`/stoptunnelservice <tunnel>`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireGuardCommand {
    /// 安装隧道服务：`/installtunnelservice <conf_path>`。**必须**经
    /// [`install_plan`] 调用（服务已存在时先停/卸载再装，否则 wireguard.exe
    /// 报 "already installed" 拒绝且旧 conf 不更新）。
    InstallService {
        /// 隧道名（错误消息点名用；与 conf 的 `Name =` 一致）。
        name: String,
        /// 渲染好的 conf 文件路径（agent 本地受保护状态目录）。
        conf_path: std::path::PathBuf,
    },
    /// `wireguard.exe /starttunnelservice <name>`。
    StartService { name: String },
    /// `wireguard.exe /stoptunnelservice <name>`。
    StopService { name: String },
    /// `wireguard.exe /uninstalltunnelservice <name>`；隧道已不存在按幂等
    /// 成功（卸载可从半清理状态重入）。
    UninstallService { name: String },
}

impl WireGuardCommand {
    /// `wireguard.exe` 参数（不含可执行文件路径；计划与执行层共用同一构造，
    /// 避免参数漂移）。
    pub fn args(&self) -> Vec<String> {
        match self {
            WireGuardCommand::InstallService { conf_path, .. } => vec![
                "/installtunnelservice".into(),
                conf_path.display().to_string(),
            ],
            WireGuardCommand::StartService { name } => {
                vec!["/starttunnelservice".into(), name.clone()]
            }
            WireGuardCommand::StopService { name } => {
                vec!["/stoptunnelservice".into(), name.clone()]
            }
            WireGuardCommand::UninstallService { name } => {
                vec!["/uninstalltunnelservice".into(), name.clone()]
            }
        }
    }

    /// 操作名（错误消息点名用）。
    pub fn operation(&self) -> &'static str {
        match self {
            WireGuardCommand::InstallService { .. } => "tunnel service install",
            WireGuardCommand::StartService { .. } => "tunnel service start",
            WireGuardCommand::StopService { .. } => "tunnel service stop",
            WireGuardCommand::UninstallService { .. } => "tunnel service uninstall",
        }
    }

    /// 受管隧道名（错误消息点名用）。
    pub fn name(&self) -> &str {
        match self {
            WireGuardCommand::InstallService { name, .. }
            | WireGuardCommand::StartService { name }
            | WireGuardCommand::StopService { name }
            | WireGuardCommand::UninstallService { name } => name,
        }
    }
}

/// 隧道 conf 文件名（`<name>.conf`）：安装的输入路径，与 `Name =` 同源，
/// 使卸载按同名 `wireguard.exe /uninstalltunnelservice <name>` 对称。
pub fn conf_file_name(tunnel_name: &str) -> String {
    format!("{tunnel_name}.conf")
}

/// 安装策略（BUG 修复：已存在隧道必须重配，不允许静默 no-op）。
///
/// `wireguard.exe` 对**已存在**的隧道服务执行 `/installtunnelservice` 会以
/// "already installed" 失败退出、conf 不生效；此前该失败文本被判成幂等成功，
/// 导致 apply 对残留/手动隧道永不更新 key/地址（todo.md「Windows 部署发现」
/// 第一项：openclaw 残留隧道静默 no-op）。`wireguard.exe` 无 setconf 等价
/// CLI，**卸载重建即重配路径**：
///
/// - 服务不存在 → 直接 `[InstallService]`（首装）；
/// - 服务已存在 → `[StopService, UninstallService, InstallService]`——先停
///   （1062 按幂等成功，可从「建了服务但从未启动」的半状态重入）、再卸载
///   （1060 按幂等成功，可从半清理状态重入）、最后装新 conf。短暂断流是
///   重配的固有代价，换收敛正确性。
///
/// 纯函数（跨平台单测）：执行层只按序跑返回的命令，不掺策略。
pub fn install_plan(
    existing_service: bool,
    tunnel_name: &str,
    conf_path: &std::path::Path,
) -> Vec<WireGuardCommand> {
    let name = tunnel_name.to_string();
    let install = WireGuardCommand::InstallService {
        name: name.clone(),
        conf_path: conf_path.to_path_buf(),
    };
    if !existing_service {
        return vec![install];
    }
    vec![
        WireGuardCommand::StopService { name: name.clone() },
        WireGuardCommand::UninstallService { name },
        install,
    ]
}

/// 受管隧道服务的 SCM 查询名（`WireGuardTunnel$<tunnel>`，官方命名）。
pub fn tunnel_service_query_name(tunnel_name: &str) -> String {
    format!("WireGuardTunnel${tunnel_name}")
}

/// 解析 `sc query <service>` 输出的数字状态码（`STATE`/`状态` 行冒号后的
/// 首个整数；zh/en 双标签宽匹配）。解析不到 → `None`（fail closed）。
pub fn parse_sc_query_state_code(output: &str) -> Option<u32> {
    for line in output.lines() {
        // 状态行标签 en = `STATE`，zh-CN sc.exe 为 `状态`；双标签宽匹配。
        if !line.to_uppercase().contains("STATE") && !line.contains("状态") {
            continue;
        }
        // `        STATE              : 4    RUNNING` → 取冒号后的首个数字。
        if let Some(code) = line
            .split(':')
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|token| token.parse::<u32>().ok())
        {
            return Some(code);
        }
    }
    None
}

/// 解析 `sc query` 输出：数字状态码 `4 = RUNNING`。数字码系统语言无关
/// （比状态词更权威）；解析不到 → `false`（读不到运行证据不假装在运行）。
pub fn sc_query_reports_running(output: &str) -> bool {
    parse_sc_query_state_code(output) == Some(4)
}

/// `wireguard.exe` 可执行路径解析。
///
/// 优先级：显式覆盖 > `MESHLET_WIREGUARD_EXE` 环境变量（非默认安装位置 /
/// 测试指向桩实现）> `wireguard.exe`（依赖 PATH 或官方安装目录已入 PATH）。
pub fn wireguard_exe(override_path: Option<&std::path::Path>) -> std::path::PathBuf {
    if let Some(path) = override_path {
        return path.to_path_buf();
    }
    if let Ok(path) = std::env::var("MESHLET_WIREGUARD_EXE") {
        return std::path::PathBuf::from(path);
    }
    std::path::PathBuf::from("wireguard.exe")
}

/// 从 [TunnelConfig] 渲染 WireGuard conf 文本（LF 行尾；WireGuardNT 解析
/// 器兼容 LF/CRLF）。
///
/// 字段顺序固定（确定性）：`[Interface]` 的 `Name` / `Address` / 可选
/// `ListenPort` / `MTU` / 可选 `PrivateKey`，随后每个 peer 一节 `[Peer]` 的
/// `PublicKey` / `AllowedIPs` / 可选 `Endpoint` / 可选 `PersistentKeepalive`。
///
/// 幂等语义：`[TunnelConfig::private_key]` 为 `None` 时**不渲染** `PrivateKey`
/// 行——服务沿用现存密钥（agent 本地注入密钥由调用方在
/// [TunnelConfig::private_key] 置 `Some`，服务端配置恒为 `None`）。
pub fn render_wireguard_conf(config: &TunnelConfig) -> String {
    let mut out = String::new();
    out.push_str("[Interface]\n");
    // WireGuard Windows derives tunnel name from the .conf filename.
    out.push_str(&format!(
        "Address = {}/{}\n",
        config.address, config.address_prefix
    ));
    if let Some(port) = config.listen_port {
        out.push_str(&format!("ListenPort = {port}\n"));
    }
    out.push_str(&format!(
        "MTU = {}\n",
        config.mtu.unwrap_or(DEFAULT_TUNNEL_MTU)
    ));
    if let Some(key) = &config.private_key {
        out.push_str(&format!("PrivateKey = {key}\n"));
    }
    for peer in &config.peers {
        out.push('\n');
        out.push_str("[Peer]\n");
        out.push_str(&format!("PublicKey = {}\n", peer.public_key));
        out.push_str(&format!(
            "AllowedIPs = {}\n",
            render_allowed_ips(&peer.allowed_ips)
        ));
        if let Some(endpoint) = &peer.endpoint {
            out.push_str(&format!("Endpoint = {endpoint}\n"));
        }
        if let Some(keepalive) = peer.persistent_keepalive_secs {
            out.push_str(&format!("PersistentKeepalive = {keepalive}\n"));
        }
    }
    out
}

/// 多段 AllowedIPs 以 `, ` 连接成单行（WireGuard 语法）；渲染顺序保持计划
/// 输入顺序，不重排。
fn render_allowed_ips(allowed_ips: &[meshlet_domain::Ipv4Cidr]) -> String {
    allowed_ips
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// 解析 `netsh interface ipv4 show subinterfaces` 输出，取受管接口的 MTU。
///
/// 供 [`crate::NetworkSnapshot`] 的 `tunnel_mtu` 读数——漂移判定的第三项
/// （计划显式配置 MTU 而内核读数不符 → 漂移）在 Windows 上此前恒为
/// `None`，显式 MTU 的计划会永不收敛。只匹配行尾等接口名的数据行、首字段
/// 可解析为数值（跳过表头与分隔线）；匹配不到返回 `None`（不下断言）。
pub fn parse_netsh_subinterface_mtu(text: &str, interface: &str) -> Option<u32> {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 2 {
            continue;
        }
        if !fields
            .last()
            .map(|s| s.eq_ignore_ascii_case(interface))
            .unwrap_or(false)
        {
            continue;
        }
        if let Ok(mtu) = fields[0].parse::<u32>() {
            return Some(mtu);
        }
    }
    None
}

/// 解析 `wg.exe show <name> dump` 输出为受管隧道的 peer 观测集。
///
/// 官方 `dump` 格式为制表符分隔：首行是接口（private-key / public-key /
/// listen-port / fwmark），其后每行一个 peer（public-key / preshared-key /
/// endpoint / allowed-ips / latest-handshake / transfer-rx / transfer-tx /
/// keepalive）。只取 `public-key`（字段 0）与 `allowed-ips`（字段 3，逗号
/// 分隔 CIDR）——与 [`crate::PeerObserved`] 对应，供 [crate::NetworkSnapshot]
/// 的 peer 漂移判定使用。格式不符的行跳过（fail closed 于调用方的存在性
/// 判定：读不到即视为无 peer，宁重装不假装一致）。
pub fn parse_wg_dump_peers(dump: &str) -> Vec<crate::PeerObserved> {
    let mut peers = Vec::new();
    for (idx, line) in dump.lines().enumerate() {
        if idx == 0 {
            continue; // 接口行
        }
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 4 {
            continue;
        }
        let public_key = fields[0].trim();
        if public_key.is_empty() {
            continue;
        }
        let allowed_ips = fields[3]
            .split(',')
            .filter_map(|s| s.trim().parse::<meshlet_domain::Ipv4Cidr>().ok())
            .collect();
        peers.push(crate::PeerObserved {
            public_key: public_key.to_string(),
            allowed_ips,
        });
    }
    peers
}

/// 分类 `wireguard.exe` 失败：卸载/停止重入按幂等成功，提权失败明示，
/// 其余 fail closed。
///
/// WireGuardNT 隧道由 Windows 服务承载（`WireGuardTunnel$<name>`）：卸载
/// 不存在隧道、停止未运行隧道时由服务控制管理器返回 1060 / 1062，复用
/// [windows_service] 已真机取证的 `service_absent` / `service_not_active`
/// 文案与退出码双通道。**wireguard.exe 是否原样透传服务控制管理器文案，
/// 属仍缺的真机全生命周期验证**——本分类器只断言已真机取证的事实类别，
/// 不以任何 fixture 冒充。
///
/// 权限文案用子串宽匹配（大小写不敏感），覆盖 Windows 版本/语言包差异；
/// `InstallService` 一律不放行（含 "already installed"——那正是已存在隧道
/// 未被重配的证据，必须显式失败；重配走 [install_plan] 的停/卸载/装路径）。
pub fn classify_wireguard_failure(
    exit_code: i32,
    output: &str,
    operation: &str,
    name: &str,
) -> Result<(), NetworkError> {
    // 退出码 1060 = ERROR_SERVICE_DOES_NOT_EXIST，系统语言无关的权威信号；
    // service_absent 文本分类是同一事实的宽匹配双通道（zh-CN 文案见其注记）。
    let absent = exit_code == 1060 || crate::windows_service::service_absent(output);
    if operation == "tunnel service uninstall" && absent {
        return Ok(());
    }

    // Stop 的目标状态是「已停止」：服务未运行（1062）＝目标已达成，同归
    // 幂等成功——卸载可从「建了服务但从未启动」的半状态重入。
    if operation == "tunnel service stop"
        && (exit_code == 1062 || crate::windows_service::service_not_active(output))
    {
        return Ok(());
    }

    let lowered = output.to_lowercase();
    if lowered.contains("access is denied")
        || lowered.contains("requires elevation")
        || lowered.contains("elevation is required")
        || lowered.contains("not authorized")
        // zh-CN 标准本地化文案（「拒绝访问」= ERROR_ACCESS_DENIED；
        // 「需要提升」= ERROR_ELEVATION_REQUIRED）。宽匹配纪律不变。
        || output.contains("拒绝访问")
        || output.contains("需要提升")
    {
        return Err(NetworkError::InsufficientPrivileges(format!(
            "wireguard.exe {operation} for tunnel `{name}` requires administrator \
             privileges (run from an elevated shell); wireguard.exe said: {}",
            first_nonempty_line(output)
        )));
    }

    Err(NetworkError::ApplyRejected(format!(
        "wireguard.exe {operation} for tunnel `{name}` failed (exit {exit_code}): {}",
        first_nonempty_line(output)
    )))
}

/// 输出的首个非空行（错误消息携带 wireguard.exe 原文，便于诊断）。
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// 执行层（`#[cfg(windows)]`）：只负责把计划函数构造的参数交给
/// `wireguard.exe`、把输出交回计划层分类，没有其他逻辑。
///
/// 真机验证仍缺（如实记录）：WireGuardNT 驱动安装后隧道全生命周期、提权
/// 执行层真机报文、开机恢复重启验证。`#[cfg(windows)]` 下本模块经 CI
/// windows-latest 的 `cargo test --workspace` 编译与运行文件级集成测试
/// （[`crate`] 的 `tests/windows_tunnel.rs`，不触发真实隧道安装——CI 未装
/// WireGuardNT 驱动）。TODO #52 / R-05 保持未勾：接 [crate::SystemBackend]
/// 仍以完整验收为准。
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_wireguard_failure, WireGuardCommand};
    use crate::{ApplyResult, NetworkError};
    use std::path::Path;

    /// 把渲染好的隧道 conf 写入 agent 本地路径（私钥只落客户端磁盘，服务端
    /// 永不携带）。父目录不存在时创建；写入即整文件覆盖（幂等 re-apply）。
    ///
    /// conf 含私钥，调用方应置于 agent 的受保护状态目录（与私钥文件同一
    /// 信任边界）；**ACL 收紧（非管理员可读限制）属仍缺的真机验证项**，本
    /// 函数只保证原子性足够的整文件写入，不在此处冒充安全措施。
    pub fn write_tunnel_conf(path: &Path, conf: &str) -> Result<(), NetworkError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    NetworkError::Io(format!("create conf dir {}: {error}", parent.display()))
                })?;
            }
        }
        std::fs::write(path, conf)
            .map_err(|error| NetworkError::Io(format!("write conf {}: {error}", path.display())))
    }

    /// 执行一条受控 `wireguard.exe` 命令：成功/幂等成功/分类失败三态。
    ///
    /// `exe_override` 指向 `wireguard.exe` 的显式路径（非默认安装位置 /
    /// 测试桩）；`None` 走 [super::wireguard_exe] 的解析链。
    pub fn run_wireguard_command(
        command: &WireGuardCommand,
        exe_override: Option<&Path>,
    ) -> Result<ApplyResult, NetworkError> {
        let exe = super::wireguard_exe(exe_override);
        let output = std::process::Command::new(&exe)
            .args(command.args())
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn {}: {error}", exe.display())))?;
        // wireguard.exe 重定向输出按活动代码页编码（zh-CN 为 GBK），UTF-8
        // 优先 + CP_ACP 兑底解码，见 [crate::windows_console]。
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if output.status.success() {
            return Ok(ApplyResult::ok());
        }
        classify_wireguard_failure(
            output.status.code().unwrap_or(-1),
            &text,
            command.operation(),
            command.name(),
        )?;
        Ok(ApplyResult::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PeerConfig;
    use meshlet_domain::Ipv4Cidr;
    use std::path::PathBuf;

    fn hub_peer() -> PeerConfig {
        PeerConfig {
            public_key: "HUB-PUBLIC-KEY-BASE64==".into(),
            allowed_ips: vec![
                "10.240.0.1/32".parse::<Ipv4Cidr>().unwrap(),
                "10.241.0.0/24".parse::<Ipv4Cidr>().unwrap(),
            ],
            endpoint: Some("198.51.100.10:51820".into()),
            persistent_keepalive_secs: Some(25),
        }
    }

    fn tunnel() -> TunnelConfig {
        TunnelConfig {
            name: "meshlet-overlay".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 32,
            listen_port: Some(51820),
            peers: vec![hub_peer()],
            mtu: None,
            private_key: Some("CLIENT-PRIVATE-KEY-BASE64==".into()),
        }
    }

    #[test]
    fn conf_renders_interface_and_peer_sections() {
        assert_eq!(
            render_wireguard_conf(&tunnel()),
            "[Interface]\n\
             \
             Address = 10.240.0.7/32\n\
             ListenPort = 51820\n\
             MTU = 1420\n\
             PrivateKey = CLIENT-PRIVATE-KEY-BASE64==\n\
             \n\
             [Peer]\n\
             PublicKey = HUB-PUBLIC-KEY-BASE64==\n\
             AllowedIPs = 10.240.0.1/32, 10.241.0.0/24\n\
             Endpoint = 198.51.100.10:51820\n\
             PersistentKeepalive = 25\n"
        );
    }

    /// 私钥边界（ADR-010）：`None` 不渲染 PrivateKey 行——agent 本地注入，
    /// 服务端配置恒为 `None`，服务沿用现存密钥（幂等重应用）。
    #[test]
    fn conf_without_private_key_omits_the_line_for_idempotent_reapply() {
        let mut value = tunnel();
        value.private_key = None;
        let conf = render_wireguard_conf(&value);
        assert!(!conf.contains("PrivateKey"));
        assert!(!conf.contains("CLIENT-PRIVATE-KEY-BASE64=="));
        // 其余字段不受影响。
        // Name is derived from filename, not a conf key
        assert!(conf.contains("AllowedIPs = 10.240.0.1/32, 10.241.0.0/24"));
    }

    #[test]
    fn conf_omits_listen_port_when_unset() {
        let mut value = tunnel();
        value.listen_port = None;
        let conf = render_wireguard_conf(&value);
        assert!(!conf.contains("ListenPort"));
        // 无 ListenPort 行；端口串仍可在 peer Endpoint 出现，不断言其缺席。
        assert!(!conf.lines().any(|line| line.starts_with("ListenPort")));
    }

    #[test]
    fn conf_defaults_mtu_to_wireguard_default_when_unset() {
        let conf = render_wireguard_conf(&tunnel());
        assert!(conf.contains(&format!("MTU = {DEFAULT_TUNNEL_MTU}\n")));
    }

    #[test]
    fn conf_uses_explicit_mtu_when_set() {
        let mut value = tunnel();
        value.mtu = Some(1380);
        assert!(render_wireguard_conf(&value).contains("MTU = 1380\n"));
    }

    #[test]
    fn conf_renders_each_peer_section_with_optional_fields_omitted() {
        let bare = PeerConfig {
            public_key: "PEER2-PUBLIC-KEY-BASE64==".into(),
            allowed_ips: vec!["10.240.0.2/32".parse::<Ipv4Cidr>().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        };
        let mut value = tunnel();
        value.peers.push(bare);
        assert_eq!(
            render_wireguard_conf(&value),
            "[Interface]\n\
             \
             Address = 10.240.0.7/32\n\
             ListenPort = 51820\n\
             MTU = 1420\n\
             PrivateKey = CLIENT-PRIVATE-KEY-BASE64==\n\
             \n\
             [Peer]\n\
             PublicKey = HUB-PUBLIC-KEY-BASE64==\n\
             AllowedIPs = 10.240.0.1/32, 10.241.0.0/24\n\
             Endpoint = 198.51.100.10:51820\n\
             PersistentKeepalive = 25\n\
             \n\
             [Peer]\n\
             PublicKey = PEER2-PUBLIC-KEY-BASE64==\n\
             AllowedIPs = 10.240.0.2/32\n"
        );
    }

    /// `wg.exe show <name> dump` 官方格式解析：接口行跳过，peer 行取
    /// public-key 与 allowed-ips；格式不符的行跳过（不假装一致）。
    #[test]
    fn wg_dump_parses_peer_public_keys_and_allowed_ips() {
        let dump = "PRIVATE-KEY\tINTERFACE-PUBLIC-KEY\t51820\t0\n\
                    HUB-PUBLIC-KEY-BASE64==\t(preshared)\t198.51.100.10:51820\t10.240.0.1/32, 10.241.0.0/24\t1234567\t1024\t2048\t25\n\
                    PEER2-PUBLIC-KEY-BASE64==\t\t10.240.0.2:51820\t10.240.0.2/32\t0\t0\t0\t0\n";
        let peers = parse_wg_dump_peers(dump);
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].public_key, "HUB-PUBLIC-KEY-BASE64==");
        assert_eq!(
            peers[0].allowed_ips,
            vec![
                "10.240.0.1/32".parse::<Ipv4Cidr>().unwrap(),
                "10.241.0.0/24".parse::<Ipv4Cidr>().unwrap(),
            ]
        );
        assert_eq!(peers[1].public_key, "PEER2-PUBLIC-KEY-BASE64==");
        assert_eq!(peers[1].allowed_ips, vec!["10.240.0.2/32".parse().unwrap()]);
    }

    #[test]
    fn wg_dump_skips_interface_line_and_malformed_rows() {
        // 仅接口行 / 空行 / 缺字段行 → 无 peer；不会误报一个 peer。
        let dump = "PRIVATE-KEY\tPUBLIC-KEY\t51820\t0\n\n\t\t\t\nPARTIAL-ROW\n";
        assert!(parse_wg_dump_peers(dump).is_empty());
        assert!(parse_wg_dump_peers("").is_empty());
        assert!(parse_wg_dump_peers("only-one-line").is_empty());
    }

    #[test]
    fn netsh_subinterface_mtu_matches_interface_line_and_skips_header() {
        let text = "   MTU  MediaSenseState   Bytes In  Bytes Out  Interface\n\
                    ------  ---------------  ---------  ---------  -------------\n\
                      1420                1     1234567      123456  meshlet\n\
                      1500                1        1000         900  Ethernet\n";
        assert_eq!(parse_netsh_subinterface_mtu(text, "meshlet"), Some(1420));
        assert_eq!(parse_netsh_subinterface_mtu(text, "Ethernet"), Some(1500));
        // 未知接口 / 空 / 表头 → None（不误判）。
        assert_eq!(parse_netsh_subinterface_mtu(text, "wg0"), None);
        assert_eq!(parse_netsh_subinterface_mtu("", "meshlet"), None);
        assert_eq!(
            parse_netsh_subinterface_mtu("   MTU  Interface\n", "meshlet"),
            None
        );
    }

    #[test]
    fn wg_dump_ignores_unparseable_allowed_ips_but_keeps_the_peer() {
        let dump = "PRIVATE-KEY\tPUBLIC-KEY\t51820\t0\n\
                    PEER\t(preshared)\tendpoint\tnot-a-cidr, 10.240.0.9/32\t0\t0\t0\t0\n";
        let peers = parse_wg_dump_peers(dump);
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].public_key, "PEER");
        assert_eq!(peers[0].allowed_ips, vec!["10.240.0.9/32".parse().unwrap()]);
    }

    #[test]
    fn rendering_is_deterministic() {
        assert_eq!(
            render_wireguard_conf(&tunnel()),
            render_wireguard_conf(&tunnel())
        );
    }

    #[test]
    fn install_uninstall_start_stop_render_documented_cli_argv() {
        let install = WireGuardCommand::InstallService {
            name: "meshlet-overlay".into(),
            conf_path: PathBuf::from(r"C:\ProgramData\meshlet\meshlet-overlay.conf"),
        };
        assert_eq!(
            install.args(),
            vec![
                "/installtunnelservice".to_string(),
                r"C:\ProgramData\meshlet\meshlet-overlay.conf".to_string(),
            ]
        );
        assert_eq!(
            WireGuardCommand::UninstallService {
                name: "meshlet-overlay".into(),
            }
            .args(),
            vec![
                "/uninstalltunnelservice".to_string(),
                "meshlet-overlay".to_string(),
            ]
        );
        assert_eq!(
            WireGuardCommand::StartService {
                name: "meshlet-overlay".into(),
            }
            .args(),
            vec![
                "/starttunnelservice".to_string(),
                "meshlet-overlay".to_string(),
            ]
        );
        assert_eq!(
            WireGuardCommand::StopService {
                name: "meshlet-overlay".into(),
            }
            .args(),
            vec![
                "/stoptunnelservice".to_string(),
                "meshlet-overlay".to_string(),
            ]
        );
    }

    #[test]
    fn command_operation_and_name_are_reported() {
        let commands = [
            (
                WireGuardCommand::InstallService {
                    name: "meshlet-overlay".into(),
                    conf_path: PathBuf::from("meshlet-overlay.conf"),
                },
                "tunnel service install",
            ),
            (
                WireGuardCommand::StartService {
                    name: "meshlet-overlay".into(),
                },
                "tunnel service start",
            ),
            (
                WireGuardCommand::StopService {
                    name: "meshlet-overlay".into(),
                },
                "tunnel service stop",
            ),
            (
                WireGuardCommand::UninstallService {
                    name: "meshlet-overlay".into(),
                },
                "tunnel service uninstall",
            ),
        ];
        for (command, operation) in commands {
            assert_eq!(command.operation(), operation);
            assert_eq!(command.name(), "meshlet-overlay");
        }
    }

    #[test]
    fn conf_file_name_appends_extension() {
        assert_eq!(conf_file_name("meshlet-overlay"), "meshlet-overlay.conf");
        assert_eq!(conf_file_name("a b"), "a b.conf");
    }

    /// wireguard.exe 解析链：显式覆盖 > 环境变量 > PATH 缺省。单函数顺序
    /// 执行，避免并行测试互相污染 `MESHLET_WIREGUARD_EXE`。
    #[test]
    fn exe_resolution_override_wins_then_env_then_default() {
        assert_eq!(
            wireguard_exe(Some(std::path::Path::new(r"C:\stub\wg.exe"))),
            PathBuf::from(r"C:\stub\wg.exe")
        );
        std::env::set_var("MESHLET_WIREGUARD_EXE", r"C:\env\wg.exe");
        assert_eq!(wireguard_exe(None), PathBuf::from(r"C:\env\wg.exe"));
        std::env::remove_var("MESHLET_WIREGUARD_EXE");
        assert_eq!(wireguard_exe(None), PathBuf::from("wireguard.exe"));
    }

    /// 卸载不存在隧道 = 幂等成功（WireGuardNT 隧道是 Windows 服务，服务控制
    /// 管理器 1060 文案经 [windows_service] 已真机取证，双通道命中）。
    #[test]
    fn uninstall_absent_is_idempotent_only_for_uninstall() {
        for (exit_code, output) in [
            (1, "ERROR 1060: The specified service does not exist."),
            (
                1060,
                "[SC] OpenService 失败 1060:\r\n\r\n指定的服务未安装。\r\n",
            ),
        ] {
            assert!(
                classify_wireguard_failure(
                    exit_code,
                    output,
                    "tunnel service uninstall",
                    "meshlet-overlay"
                )
                .is_ok(),
                "exit {exit_code} absence must be idempotent for uninstall"
            );
        }
        // 安装不存在目标不是幂等成功：fail closed。
        assert!(matches!(
            classify_wireguard_failure(
                1060,
                "[SC] OpenService 失败 1060:\r\n\r\n指定的服务未安装。\r\n",
                "tunnel service install",
                "meshlet-overlay"
            ),
            Err(NetworkError::ApplyRejected(_))
        ));
    }

    /// 安装不存在目标不是幂等成功：fail closed（含 "already installed" 文本——
    /// BUG 回归：此前被误判为幂等成功，apply 对已存在隧道静默 no-op、
    /// key/地址永不更新；重配必须走 `install_plan` 的停/卸载/装路径）。
    #[test]
    fn install_failures_are_never_idempotent_success() {
        for (exit_code, output) in [
            (
                1060,
                "[SC] OpenService 失败 1060:\r\n\r\n指定的服务未安装。\r\n",
            ),
            (1, "\r\nAlready installed.\r\n"),
            (2, "WireGuard tunnel service is already installed."),
        ] {
            assert!(
                matches!(
                    classify_wireguard_failure(
                        exit_code,
                        output,
                        "tunnel service install",
                        "meshlet-overlay"
                    ),
                    Err(NetworkError::ApplyRejected(_))
                ),
                "install failure ({exit_code}, {output:?}) must fail closed"
            );
        }
    }

    /// 安装策略（BUG 回归）：服务已存在 + 换了 key 的新 plan → 必须
    /// [停, 卸, 装新 conf]，且装步骤携带**新** conf——「隧道实际更新」的
    /// 计划级模拟。首装则只装一步。
    #[test]
    fn install_plan_replaces_an_existing_tunnel_with_the_new_conf() {
        let name = "meshlet-overlay";
        let old_conf = PathBuf::from(r"C:\ProgramData\meshlet\meshlet-overlay.conf");
        let rotated_conf = PathBuf::from(r"C:\ProgramData\meshlet\meshlet-overlay.conf");

        // 首装：单步安装。
        assert_eq!(
            install_plan(false, name, &old_conf),
            vec![WireGuardCommand::InstallService {
                name: name.into(),
                conf_path: old_conf.clone(),
            }]
        );

        // 已存在 + 换 key：渲染两版 conf（仅私钥不同），断言计划装的是新版。
        let mut rotated = tunnel();
        rotated.private_key = Some("ROTATED-PRIVATE-KEY-BASE64==".into());
        let rotated_conf_text = render_wireguard_conf(&rotated);
        assert!(rotated_conf_text.contains("ROTATED-PRIVATE-KEY-BASE64=="));
        assert_ne!(rotated_conf_text, render_wireguard_conf(&tunnel()));

        let plan = install_plan(true, name, &rotated_conf);
        assert_eq!(
            plan,
            vec![
                WireGuardCommand::StopService { name: name.into() },
                WireGuardCommand::UninstallService { name: name.into() },
                WireGuardCommand::InstallService {
                    name: name.into(),
                    conf_path: rotated_conf,
                },
            ],
            "existing tunnel must be stopped, uninstalled, then reinstalled with the new conf"
        );
        // 顺序即语义：卸载必须先于安装（否则 wireguard.exe 报 already installed）。
        let uninstall_idx = plan
            .iter()
            .position(|c| matches!(c, WireGuardCommand::UninstallService { .. }))
            .unwrap();
        let install_idx = plan
            .iter()
            .position(|c| matches!(c, WireGuardCommand::InstallService { .. }))
            .unwrap();
        assert!(uninstall_idx < install_idx);
    }

    /// `sc query` 的 STATE 行解析：数字码 4 = RUNNING（系统语言无关）；
    /// 其余状态 / 缺 STATE 行 / 缺数字一律不算运行（fail closed）。
    #[test]
    fn sc_query_running_is_judged_by_the_numeric_state_code() {
        assert!(sc_query_reports_running(
            "\r\nSERVICE_NAME: WireGuardTunnel$meshlet\r\n        TYPE               : 10  WIN32_OWN_PROCESS \r\n        STATE              : 4  RUNNING \r\n"
        ));
        // zh-CN 文案同构（数字码在冒号后）。
        assert!(sc_query_reports_running(
            "        STATE              : 4    RUNNING\r\n"
        ));
        // zh-CN 文案同构（数字码在冒号后；zh sc.exe 状态行标签为「状态」）。
        assert!(sc_query_reports_running(
            "        状态              : 4    RUNNING\r\n"
        ));
        assert!(!sc_query_reports_running(
            "        状态              : 1    STOPPED\r\n"
        ));
        for output in [
            "        STATE              : 1    STOPPED\r\n",
            "        STATE              : 2    START_PENDING\r\n",
            "        STATE              : 3    STOP_PENDING\r\n",
            "        STATE              : (NO NUMERIC CODE)\r\n",
            "[SC] OpenService 失败 1060:\r\n指定的服务未安装。\r\n",
            "",
        ] {
            assert!(
                !sc_query_reports_running(output),
                "non-running output must not read as running: {output:?}"
            );
        }
    }

    #[test]
    fn tunnel_service_query_name_uses_the_official_prefix() {
        assert_eq!(
            tunnel_service_query_name("meshlet"),
            "WireGuardTunnel$meshlet"
        );
    }

    /// 停止未运行隧道 = 幂等成功（1062 双通道；Stop 目标状态「已停止」）。
    #[test]
    fn stop_not_active_is_idempotent_only_for_stop() {
        let output = "[SC] ControlService 失败 1062:\r\n\r\n服务尚未启动。\r\n";
        assert!(
            classify_wireguard_failure(1062, output, "tunnel service stop", "meshlet-overlay")
                .is_ok()
        );
        assert!(classify_wireguard_failure(
            1,
            "[SC] ControlService failed 1062:\r\n\r\nThe service has not been started.\r\n",
            "tunnel service stop",
            "meshlet-overlay"
        )
        .is_ok());
        // 1062 宽容只归 Stop。
        assert!(matches!(
            classify_wireguard_failure(1062, output, "tunnel service uninstall", "meshlet-overlay"),
            Err(NetworkError::ApplyRejected(_))
        ));
    }

    /// 权限文案（en + zh-CN 标准本地化）归权限类，错误消息点名隧道名。
    #[test]
    fn elevation_and_denied_output_map_to_privileges() {
        for output in [
            "Access is denied.",
            "The requested operation requires elevation.",
            "Elevation is required to perform this operation.",
            "This operation is not authorized.",
            "请求的操作需要提升(作为管理员运行)。",
            "拒绝访问。",
        ] {
            assert!(matches!(
                classify_wireguard_failure(1, output, "tunnel service install", "meshlet-overlay"),
                Err(NetworkError::InsufficientPrivileges(detail))
                    if detail.contains("`meshlet-overlay`")
            ));
        }
    }

    #[test]
    fn unknown_failure_fails_closed_with_original_text() {
        assert!(matches!(
            classify_wireguard_failure(
                2,
                "\nUnable to open configuration file.\n",
                "tunnel service install",
                "meshlet-overlay"
            ),
            Err(NetworkError::ApplyRejected(detail))
                if detail.contains("exit 2") && detail.contains("Unable to open configuration file.")
        ));
    }

    #[cfg(target_os = "windows")]
    mod exec_tests {
        use super::{classify_wireguard_failure, tunnel, WireGuardCommand};
        use crate::{ApplyResult, NetworkError};
        use std::path::Path;

        /// 编译期锁定 exec 入口：签名只接收计划命令与可执行覆盖、返回计划层
        /// 结果，测试不启动 wireguard.exe。
        #[test]
        fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
            fn assert_signature(
                _run: fn(&WireGuardCommand, Option<&Path>) -> Result<ApplyResult, NetworkError>,
            ) {
            }
            assert_signature(super::super::exec::run_wireguard_command);
        }

        /// exec 的 conf 写入回读：字节一致、覆盖写入（幂等 re-apply）一致，
        /// 私钥不被转码破坏。
        #[test]
        fn write_tunnel_conf_round_trips_bytes() {
            let dir = std::env::temp_dir().join(format!(
                "meshlet-tunnel-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let path = dir.join(super::super::conf_file_name("meshlet-overlay"));
            let conf = super::super::render_wireguard_conf(&tunnel());
            super::super::exec::write_tunnel_conf(&path, &conf).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), conf);
            // 重应用覆盖写：换一版 conf（密钥变更）再写，仍整文件一致。
            let mut value = tunnel();
            value.private_key = Some("ROTATED-PRIVATE-KEY-BASE64==".into());
            let rotated = super::super::render_wireguard_conf(&value);
            super::super::exec::write_tunnel_conf(&path, &rotated).unwrap();
            assert_eq!(std::fs::read_to_string(&path).unwrap(), rotated);
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// exec 的非零退出码交回计划层：权限类必须仍归权限错误。
        #[test]
        fn exec_failure_classification_preserves_privilege_mapping() {
            let command = WireGuardCommand::InstallService {
                name: "meshlet-overlay".into(),
                conf_path: std::path::PathBuf::from("meshlet-overlay.conf"),
            };
            assert!(matches!(
                classify_wireguard_failure(
                    1,
                    "Access is denied.",
                    command.operation(),
                    command.name()
                ),
                Err(NetworkError::InsufficientPrivileges(_))
            ));
        }
    }
}
