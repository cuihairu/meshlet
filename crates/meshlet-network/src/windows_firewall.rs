//! Windows 防火墙计划层（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 本模块包含**纯规划**与 `#[cfg(windows)]` 执行层：`netsh advfirewall
//! firewall add/delete rule` 的参数构造、失败文本分类与受控执行。计划层
//! 函数在任意平台编译并单测（本仓 CI 的 Linux 侧即可跑绿）；执行层真机
//! 验证（2026-10-26，中文 Windows Server）：add / show 读回 / delete /
//! 幂等 re-delete 全链路走通；完整验收前 Windows 仍保持 [crate::unsupported]
//! 的显式占位，不接 [crate::SystemBackend]。
//!
//! 与 [windows_routes](../../../crates/meshlet-network/src/windows_routes.rs)
//! 同一纪律：
//!
//! - **受控命令**：只构造 `name=` / `dir=` / `action=` / `protocol=` /
//!   `localport=` / `remoteport=` / `profile=` 等命名参数；`key=value` 对
//!   保持单个 argv 词元，含空格的规则名（如 `Meshlet WireGuard`）不拆词，
//!   也**不内嵌引号**（netsh 引号语义见 [windows_routes] 的实测注记）；
//! - **确定性**：Add 的字段顺序固定；profile 多值固定为
//!   `domain,private,public`，重复值去重，未显式提供时用 `any`；
//! - **fail closed**：权限文案宽匹配映射为
//!   [`NetworkError::InsufficientPrivileges`]；删除规则已不存在的文案按
//!   幂等成功；其他未知失败统一 [`NetworkError::ApplyRejected`] 并携带
//!   netsh 原文首行。

use crate::NetworkError;

/// 防火墙规则方向（netsh `dir=` 的受控取值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallDirection {
    Inbound,
    Outbound,
}

impl FirewallDirection {
    fn as_str(self) -> &'static str {
        match self {
            FirewallDirection::Inbound => "in",
            FirewallDirection::Outbound => "out",
        }
    }
}

/// 防火墙规则动作（netsh `action=` 的受控取值）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallAction {
    Allow,
    Block,
}

impl FirewallAction {
    fn as_str(self) -> &'static str {
        match self {
            FirewallAction::Allow => "allow",
            FirewallAction::Block => "block",
        }
    }
}

/// 受控协议；`Any` 是 netsh 的缺省语义，显式渲染避免参数形状漂移。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallProtocol {
    Any,
    Tcp,
    Udp,
    /// ICMPv4 回显（echo request，type 8 / any code）：mesh 邻居可达性探测
    /// 依赖它——Windows 把 wg 接口判为 Public 档后默认挡 ICMP（2026-10-30
    /// 实战 dev→win 不通，手工建 Meshlet-ICMPv4-In 才通）。netsh 用
    /// `protocol=icmpv4:8,any` 表达；ICMP 无端口，[FirewallRule] 的端口词元
    /// 对 [FirewallProtocol::IcmpV4] 省略。
    IcmpV4,
}

impl FirewallProtocol {
    fn as_str(self) -> &'static str {
        match self {
            FirewallProtocol::Any => "any",
            FirewallProtocol::Tcp => "tcp",
            FirewallProtocol::Udp => "udp",
            FirewallProtocol::IcmpV4 => "icmpv4:8,any",
        }
    }
}

/// 防火墙 profile；渲染顺序固定且与 netsh 常见写法一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirewallProfile {
    Domain,
    Private,
    Public,
}

impl FirewallProfile {
    fn as_str(self) -> &'static str {
        match self {
            FirewallProfile::Domain => "domain",
            FirewallProfile::Private => "private",
            FirewallProfile::Public => "public",
        }
    }
}

/// 受控规则描述。计划层从类型化字段渲染，控制面不能注入任意 argv。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub name: String,
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub protocol: FirewallProtocol,
    /// netsh 端口词元（如 `51820`、`5000-5010` 或 `any`）；保持字符串是
    /// 为了完整覆盖 Windows 的范围/列表语法，执行层仍以单个 argv 传递。
    pub local_port: String,
    pub remote_port: String,
    /// `None` 渲染为 `profile=any`；有值时固定 domain/private/public 顺序。
    pub profiles: Option<Vec<FirewallProfile>>,
    /// netsh `description=`；规则计划可空，省略该参数。
    pub description: Option<String>,
    /// netsh `localip=`；mesh 可达性规则用它把放行**限定到 wg 接口地址**
    /// （netsh 无按接口限定能力，`localip=<设备 overlay 地址>` 是等价且有
    /// 安全边界的做法：只有发往该 mesh 地址的包才匹配）。`None` = 省略。
    pub local_ip: Option<std::net::Ipv4Addr>,
}

/// 一条受控 netsh 防火墙命令（计划态；执行见 [exec]）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallRuleCommand {
    Add { rule: FirewallRule },
    Delete { name: String },
}

impl FirewallRuleCommand {
    /// netsh 参数（含 `advfirewall firewall add/delete rule` 前缀；计划与
    /// 未来执行层共用同一构造，避免参数漂移）。
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["advfirewall".into(), "firewall".into()];
        match self {
            FirewallRuleCommand::Add { rule } => {
                args.extend(["add".into(), "rule".into()]);
                args.push(named_value("name", &rule.name));
                args.push(format!("dir={}", rule.direction.as_str()));
                args.push(format!("action={}", rule.action.as_str()));
                args.push(format!("protocol={}", rule.protocol.as_str()));
                // ICMPv4 无端口概念：对 `icmpv4:8,any` 省略 localport/remoteport
                // （netsh 不接受 ICMP 协议带端口词元）。
                if !matches!(rule.protocol, FirewallProtocol::IcmpV4) {
                    args.push(named_value("localport", &rule.local_port));
                    args.push(named_value("remoteport", &rule.remote_port));
                }
                args.push(format!(
                    "profile={}",
                    render_profiles(rule.profiles.as_deref())
                ));
                if let Some(local_ip) = rule.local_ip {
                    args.push(format!("localip={local_ip}"));
                }
                if let Some(description) = &rule.description {
                    args.push(named_value("description", description));
                }
            }
            FirewallRuleCommand::Delete { name } => {
                args.extend(["delete".into(), "rule".into()]);
                args.push(named_value("name", name));
            }
        }
        args
    }

    /// 操作名（错误消息点名用）。
    pub fn operation(&self) -> &'static str {
        match self {
            FirewallRuleCommand::Add { .. } => "firewall rule add",
            FirewallRuleCommand::Delete { .. } => "firewall rule delete",
        }
    }

    /// 受管规则名（错误消息点名用）。
    pub fn name(&self) -> &str {
        match self {
            FirewallRuleCommand::Add { rule } => &rule.name,
            FirewallRuleCommand::Delete { name } => name,
        }
    }

    pub fn is_delete(&self) -> bool {
        matches!(self, FirewallRuleCommand::Delete { .. })
    }
}

/// mesh 可达性保障命令（AGENT-FW-1）。
///
/// 背景（2026-10-30 实战）：Windows 把 wg 接口判为 **Public** 档，其默认
/// 入站策略挡 ICMP——dev→win 的 wg 隧道握手正常但 ping 不通，手工建
/// `Meshlet-ICMPv4-In` 规则才通。根因修复 = 把接口连接档位设为 **Private**
/// （Private 档默认放行 ICMP）+ 显式入站 ICMPv4 放行规则作双保险。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshFirewallCommand {
    /// `Set-NetConnectionProfile -InterfaceAlias <if> -NetworkCategory Private`。
    ///
    /// 用 PowerShell 而非 netsh：NetworkCategory 是**连接档位**属性，netsh 无
    /// 对应子命令；set 语义天然幂等（已是 Private 再设仍成功）。
    SetNetworkCategoryPrivate { interface: String },
    /// `netsh advfirewall firewall add rule`：`Meshlet-ICMPv4-In` 入站 ICMP 放行，
    /// 限定设备 overlay 地址（见 [mesh_icmp_rule]）；幂等由调用方先探
    /// [firewall_rule_present] 再决定是否下发。
    AddIcmpRule { rule: FirewallRule },
    /// `netsh advfirewall firewall delete rule`：按名删除同名 ICMP 规则。
    /// 地址变更残留 / 被禁用的旧规则先删后建（审核发现 #1）；netsh delete
    /// 按名删全部同名规则，重建后恰一条。
    DeleteIcmpRule { name: String },
}

impl MeshFirewallCommand {
    /// 构造档位命令并校验接口名（拒绝引号/空白，防 `-Command` 注入）。
    pub fn set_network_category_private(interface: &str) -> Result<Self, NetworkError> {
        validate_tunnel_interface(interface)?;
        Ok(Self::SetNetworkCategoryPrivate {
            interface: interface.into(),
        })
    }

    /// argv（不含程序名）：档位命令走 `powershell`，ICMP 规则走 `netsh`。
    pub fn args(&self) -> Vec<String> {
        match self {
            Self::SetNetworkCategoryPrivate { interface } => vec![
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-Command".into(),
                format!(
                    "Set-NetConnectionProfile -InterfaceAlias '{interface}' \
                     -NetworkCategory Private"
                ),
            ],
            Self::AddIcmpRule { rule } => FirewallRuleCommand::Add { rule: rule.clone() }.args(),
            Self::DeleteIcmpRule { name } => {
                FirewallRuleCommand::Delete { name: name.clone() }.args()
            }
        }
    }

    pub fn operation(&self) -> &'static str {
        match self {
            Self::SetNetworkCategoryPrivate { .. } => "network category set private",
            Self::AddIcmpRule { .. } => "firewall rule add",
            Self::DeleteIcmpRule { .. } => "firewall rule delete",
        }
    }

    /// 该命令是否走 netsh（否则走 PowerShell）。
    pub fn uses_netsh(&self) -> bool {
        matches!(self, Self::AddIcmpRule { .. } | Self::DeleteIcmpRule { .. })
    }
}

/// 受管隧道接口名校验：Windows 隧道名（`wg-meshlet`）字符集，拒绝引号与
/// 空白——接口名会进入 PowerShell 单引号字符串，防注入。
fn validate_tunnel_interface(interface: &str) -> Result<(), NetworkError> {
    if interface.is_empty()
        || !interface
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_' || c == b'.')
    {
        return Err(NetworkError::ApplyRejected(
            "invalid tunnel interface name".into(),
        ));
    }
    Ok(())
}

/// 直连 UDP 放行规则名（批次④ Windows 接线）。固定名是幂等探测的一半：
/// `netsh advfirewall firewall show rule name=<此名>` + 端口双重核对。
pub const DIRECT_UDP_RULE_NAME: &str = "Meshlet-Direct-UDP-In";

/// 直连 UDP 端口入站放行规则（P2P §12 批次④ Windows 侧）：inbound / allow /
/// `protocol=udp` / `localport=<port>`，profile 不绑（any）——wg 适配器被
/// Windows 判为 Public 档，直连握手入站包在默认入站策略下会被丢弃。
/// 与 [mesh_icmp_rule] 同纪律：受控命名参数，调用方先探在场再 add。
pub fn direct_udp_rule(port: u16) -> FirewallRule {
    FirewallRule {
        name: DIRECT_UDP_RULE_NAME.into(),
        direction: FirewallDirection::Inbound,
        action: FirewallAction::Allow,
        protocol: FirewallProtocol::Udp,
        local_port: port.to_string(),
        remote_port: "any".into(),
        profiles: None,
        description: Some(
            "meshlet direct connect: inbound UDP on the data-plane listen port".into(),
        ),
        local_ip: None,
    }
}

/// `netsh … show rule` 输出里是否出现该端口的 `LocalPort` 词元。
/// 规则名固定而端口可变（配置改端口后旧规则在场但端口不符）：名字在场
/// **不**代表端口放行，需逐条核对 `LocalPort: <port>` 行。
///
/// 字段标签按 en / zh-CN 双语言匹配（`LocalPort` / `本地端口`），避免中文
/// 系统的本地化输出漏判、每次重放叠加同名规则（2026-11-09 审核发现 #2）。
pub fn rule_output_mentions_port(output: &str, port: u16) -> bool {
    rule_output_ports(output).contains(&port)
}

/// `netsh … show rule` 输出中出现的全部 `LocalPort` 值。
///
/// 同一固定规则名可含多条（配置改端口后旧端口规则残留，审核发现 #3）；
/// 调用方据此判断「名字在场但端口不符」并触发重建。
pub fn rule_output_ports(output: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in output.lines() {
        let Some((label, value)) = line.trim().split_once(':') else {
            continue;
        };
        if !is_local_port_label(label.trim()) {
            continue;
        }
        if let Ok(port) = value.trim().parse::<u16>() {
            ports.push(port);
        }
    }
    ports
}

/// `netsh advfirewall firewall show rule` 输出的 LocalPort 字段标签。
/// en `LocalPort`；zh-CN `本地端口`（本地化输出，审核发现 #2）。
fn is_local_port_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("localport") || label.to_ascii_lowercase().contains("本地端口")
}

/// LocalIP 字段标签：en `LocalIP`；zh-CN `本地IP` / `本地 IP`。
fn is_local_ip_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("localip")
        || label.to_ascii_lowercase().contains("本地ip")
        || label.to_ascii_lowercase().contains("本地 ip")
}

/// Enabled 字段标签：en `Enabled`；zh-CN `已启用`。
fn is_enabled_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("enabled") || label.to_ascii_lowercase().contains("已启用")
}

/// 布尔字段取值：en `Yes`；zh-CN `是`（兼容 `true` / `1`）。
fn is_yes_value(value: &str) -> bool {
    let v = value.trim();
    v.eq_ignore_ascii_case("yes") || v.eq_ignore_ascii_case("true") || v == "是" || v == "1"
}

/// 规则块头标签：en `Rule Name`；zh-CN `规则名称`。
fn is_rule_name_header(line: &str) -> bool {
    let t = line.trim();
    t.eq_ignore_ascii_case("rule name")
        || t.to_ascii_lowercase().starts_with("rule name:")
        || t.starts_with("规则名称")
}

/// `netsh … show rule name=<n>` 输出按规则块拆分。同名规则可能多条（地址变更
/// 残留 / 禁用副本，审核发现 #1）；无块头时整段视为单块。
fn rule_blocks(output: &str) -> Vec<String> {
    let lines: Vec<&str> = output.lines().collect();
    let mut headers: Vec<usize> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if is_rule_name_header(line) {
            headers.push(i);
        }
    }
    if headers.is_empty() {
        return if output.trim().is_empty() {
            Vec::new()
        } else {
            vec![output.to_string()]
        };
    }
    let mut blocks = Vec::new();
    for (k, &h) in headers.iter().enumerate() {
        let end = if k + 1 < headers.len() {
            headers[k + 1]
        } else {
            lines.len()
        };
        blocks.push(lines[h..end].join("\n"));
    }
    blocks
}

/// LocalIP 值与设备地址匹配：netsh show 把 localip 归一成 `ip/netmask` 形态
/// （`127.0.0.1/255.255.255.255`），多地址逗号分隔——取每个词元 `/` 前的
/// IP 部分做精确比较（真机取证见 windows_firewall_live，裸地址也兼容）。
fn local_ip_value_matches(value: &str, addr: std::net::Ipv4Addr) -> bool {
    value.split(',').any(|token| {
        let ip = token.trim().split('/').next().unwrap_or("").trim();
        ip.parse::<std::net::Ipv4Addr>() == Ok(addr)
    })
}

/// 同名 ICMP 规则中是否存在「已启用 且 localip 匹配当前设备地址」的规则。
///
/// 审核发现 #1：仅按名字判在场会在地址变更 / 规则被禁用后误报为已满足、跳过
/// 创建——需逐块核对启用态与地址绑定。
pub fn rule_output_has_satisfied_icmp_rule(output: &str, addr: std::net::Ipv4Addr) -> bool {
    for block in rule_blocks(output) {
        let mut enabled = false;
        let mut addr_match = false;
        for line in block.lines() {
            let Some((label, value)) = line.trim().split_once(':') else {
                continue;
            };
            let label = label.trim();
            if is_enabled_label(label) {
                enabled = is_yes_value(value);
            }
            if is_local_ip_label(label) && local_ip_value_matches(value, addr) {
                addr_match = true;
            }
        }
        if enabled && addr_match {
            return true;
        }
    }
    false
}

/// mesh 入站 ICMP 放行规则（`Meshlet-ICMPv4-In`）：inbound / allow /
/// `icmpv4:8,any`，`localip` 限定到设备 overlay 地址——netsh 无按接口限定，
/// `localip=<设备地址>` 等价且带安全边界（只匹配发往该 mesh 地址的包）。
pub fn mesh_icmp_rule(device_addr: std::net::Ipv4Addr) -> FirewallRule {
    FirewallRule {
        name: "Meshlet-ICMPv4-In".into(),
        direction: FirewallDirection::Inbound,
        action: FirewallAction::Allow,
        protocol: FirewallProtocol::IcmpV4,
        local_port: "any".into(),
        remote_port: "any".into(),
        profiles: None, // any：Private 档为主修复，本规则作双保险，不绑档位
        description: Some(
            "meshlet mesh reachability: inbound ICMP echo to the wg interface".into(),
        ),
        local_ip: Some(device_addr),
    }
}

/// 同名 ICMP 规则在场状态（探测 → 规划，AGENT-FW-1 审核发现 #1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpRuleState {
    /// 名为 `Meshlet-ICMPv4-In` 的规则不存在——直接添加。
    Absent,
    /// 存在、已启用、且 localip 与当前设备地址一致——已满足，不动。
    Satisfied,
    /// 同名规则在场但不满足（地址变更残留 / 被禁用）——先删后建，
    /// 否则仅按名判在场会跳过创建、当前地址的入站 ping 未获保障。
    Stale,
}

/// 纯规划（AGENT-FW-1，跨平台单测）：给定档位与规则现状，产出保障命令。
///
/// 调用方先探测 `category_is_private` 与 ICMP 规则在场状态
/// （[IcmpRuleState]），本函数只做决定论映射——全幂等（现状已满足 → 空计划）。
pub fn mesh_reachability_commands(
    interface: &str,
    device_addr: std::net::Ipv4Addr,
    category_is_private: bool,
    icmp_rule_state: IcmpRuleState,
) -> Result<Vec<MeshFirewallCommand>, NetworkError> {
    validate_tunnel_interface(interface)?;
    let mut commands = Vec::new();
    if !category_is_private {
        commands.push(MeshFirewallCommand::set_network_category_private(
            interface,
        )?);
    }
    match icmp_rule_state {
        IcmpRuleState::Satisfied => {}
        IcmpRuleState::Absent => commands.push(MeshFirewallCommand::AddIcmpRule {
            rule: mesh_icmp_rule(device_addr),
        }),
        IcmpRuleState::Stale => {
            commands.push(MeshFirewallCommand::DeleteIcmpRule {
                name: mesh_icmp_rule(device_addr).name,
            });
            commands.push(MeshFirewallCommand::AddIcmpRule {
                rule: mesh_icmp_rule(device_addr),
            });
        }
    }
    Ok(commands)
}

/// 判断 `netsh advfirewall firewall show rule name=<name>` 输出表示规则存在。
/// 缺失时报「没有与指定标准相匹配的规则。」（zh-CN 真机取证）/ 英文等价
/// 文案——复用 [firewall_rule_already_absent] 判定缺位。
pub fn firewall_rule_present(output: &str) -> bool {
    !output.trim().is_empty() && !firewall_rule_already_absent(output)
}

/// 判断 `Get-NetConnectionProfile` 输出表示连接档位已是 Private。
///
/// 只认 `NetworkCategory` 字段（PowerShell 字段名不随界面语言变化）或裸值
/// 输出（探测命令只取 `.NetworkCategory`）；绝不在整段输出里搜 `private`——
/// 否则连接名/别名含该词的 Public 档会被误判为 Private、跳过档位切换
/// （2026-11-09 审核发现 #4）。
pub fn net_category_is_private(output: &str) -> bool {
    let mut bare: Option<&str> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((label, value)) = trimmed.split_once(':') {
            let label = label.trim();
            if label.eq_ignore_ascii_case("networkcategory") {
                return value.trim().eq_ignore_ascii_case("private");
            }
            // 其他字段（Name / InterfaceAlias 等）忽略，防同名词误判。
        } else if bare.is_none() {
            bare = Some(trimmed);
        }
    }
    bare.is_some_and(|v| v.eq_ignore_ascii_case("private"))
}

/// `key=value` 形式的 netsh 命名参数，**整个键值对是单个 argv 词元**，不内嵌
/// 引号；命令行层引号由 std 进程生成器负责。
fn named_value(key: &str, value: &str) -> String {
    format!("{key}={value}")
}

/// 多 profile 固定顺序渲染；重复项只保留一次，`any` 不与具体 profile 混用。
fn render_profiles(profiles: Option<&[FirewallProfile]>) -> String {
    match profiles {
        None => "any".into(),
        Some(profiles) => {
            let mut ordered = [
                FirewallProfile::Domain,
                FirewallProfile::Private,
                FirewallProfile::Public,
            ]
            .into_iter()
            .filter(|profile| profiles.contains(profile))
            .collect::<Vec<_>>();
            ordered.dedup();
            if ordered.is_empty() {
                "any".into()
            } else {
                ordered
                    .iter()
                    .map(|profile| profile.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            }
        }
    }
}

/// 判断 netsh 删除输出是否表示「没有匹配规则」；按子串宽匹配覆盖 Windows
/// 各版本/语言路径下的幂等删除文案差异。
pub fn firewall_rule_already_absent(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("no rules match the specified criteria")
        || lowered.contains("rule does not exist")
        || lowered.contains("cannot find")
        // zh-CN 真机取证（2026-10-25，CP936 解码后）：netsh 防火墙删除不
        // 存在规则的完整报文为「没有与指定标准相匹配的规则。」。
        || output.contains("没有与指定标准相匹配的规则")
}

/// 分类 netsh 防火墙失败：幂等删除成功，权限失败明示提权，其余 fail closed。
///
/// `requires elevation` / `access is denied` 用子串宽匹配（大小写不敏感），
/// 覆盖 Windows 版本与重定向输出的文案差异；错误消息点名操作与规则名。
pub fn classify_netsh_firewall_failure(
    exit_code: i32,
    output: &str,
    operation: &str,
    name: &str,
) -> Result<(), NetworkError> {
    if operation == "firewall rule delete" && firewall_rule_already_absent(output) {
        return Ok(());
    }

    let lowered = output.to_lowercase();
    if lowered.contains("requires elevation")
        || lowered.contains("access is denied")
        // zh-CN 真机取证：「请求的操作需要提升(作为管理员运行)。」=
        // ERROR_ELEVATION_REQUIRED；「拒绝访问」= ERROR_ACCESS_DENIED
        // 的 zh-CN 标准文案。宽匹配纪律不变。
        || output.contains("需要提升")
        || output.contains("拒绝访问")
    {
        return Err(NetworkError::InsufficientPrivileges(format!(
            "netsh {operation} for rule `{name}` requires administrator \
             privileges (run from an elevated shell); netsh said: {}",
            first_nonempty_line(output)
        )));
    }

    Err(NetworkError::ApplyRejected(format!(
        "netsh {operation} for rule `{name}` failed (exit {exit_code}): {}",
        first_nonempty_line(output)
    )))
}

/// 输出的首个非空行（错误消息携带 netsh 原文，便于诊断）。
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// 执行层（`#[cfg(windows)]`）：只负责把计划函数构造的参数交给 netsh、
/// 把输出交回计划层分类，没有其他逻辑。
///
/// 真机实测（2026-10-26，中文 Windows Server）：add / show 读回 / delete /
/// 幂等 re-delete（「没有与指定标准相匹配的规则。」经
/// [crate::windows_console] 解码后分类）全链路走通。TODO #52 保持未勾：
/// 接 [crate::SystemBackend] 仍以完整验收为准。
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_netsh_firewall_failure, FirewallRuleCommand};
    use crate::{ApplyResult, NetworkError};

    /// 执行一条受控 netsh 防火墙命令：成功/幂等成功/分类失败三态。
    pub fn run_firewall_command(
        command: &FirewallRuleCommand,
    ) -> Result<ApplyResult, NetworkError> {
        let output = std::process::Command::new("netsh")
            .args(command.args())
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn netsh: {error}")))?;
        // netsh 重定向输出按活动代码页编码（zh-CN 真机取证为 GBK），
        // UTF-8 优先 + CP_ACP 兑底解码，见 [windows_console]。
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if output.status.success() {
            return Ok(ApplyResult::ok());
        }
        // 删除规则已不存在 = 幂等成功（清理路径清到空态不算失败）。
        if command.is_delete() && super::firewall_rule_already_absent(&text) {
            return Ok(ApplyResult::ok());
        }
        classify_netsh_firewall_failure(
            output.status.code().unwrap_or(-1),
            &text,
            command.operation(),
            command.name(),
        )?;
        Ok(ApplyResult::ok())
    }

    /// 执行一条 mesh 可达性命令（AGENT-FW-1）：按变体走 netsh 或 PowerShell，
    /// 成功/分类失败两态（档位 set 语义天然幂等，无需 absent 分支）。
    ///
    /// 真机验证随 #52 接线后的 apply 链路一并进行（R-05 门禁）；本函数只把
    /// 计划命令交给系统、把输出交回计划层分类。
    pub fn run_mesh_firewall_command(
        command: &super::MeshFirewallCommand,
    ) -> Result<ApplyResult, NetworkError> {
        let (program, args) = if command.uses_netsh() {
            ("netsh", command.args())
        } else {
            ("powershell", command.args())
        };
        let output = std::process::Command::new(program)
            .args(&args)
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn {program}: {error}")))?;
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if output.status.success() {
            return Ok(ApplyResult::ok());
        }
        classify_netsh_firewall_failure(
            output.status.code().unwrap_or(-1),
            &text,
            command.operation(),
            match command {
                super::MeshFirewallCommand::SetNetworkCategoryPrivate { interface } => {
                    interface.as_str()
                }
                super::MeshFirewallCommand::AddIcmpRule { rule } => rule.name.as_str(),
                super::MeshFirewallCommand::DeleteIcmpRule { name } => name.as_str(),
            },
        )?;
        Ok(ApplyResult::ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_udp_rule_renders_inbound_udp_allow_on_the_port() {
        let rule = direct_udp_rule(51820);
        assert_eq!(rule.name, DIRECT_UDP_RULE_NAME);
        assert_eq!(rule.direction, FirewallDirection::Inbound);
        assert_eq!(rule.action, FirewallAction::Allow);
        assert_eq!(rule.protocol, FirewallProtocol::Udp);
        assert_eq!(rule.local_port, "51820");
        let args = FirewallRuleCommand::Add { rule: rule.clone() }.args();
        let joined = args.join(" ");
        assert!(joined.contains("dir=in"), "{joined}");
        assert!(joined.contains("action=allow"), "{joined}");
        assert!(joined.contains("protocol=udp"), "{joined}");
        assert!(joined.contains("localport=51820"), "{joined}");
    }

    #[test]
    fn rule_output_mentions_port_matches_only_that_port() {
        let output = "规则名称: Meshlet-Direct-UDP-In\r\nLocalPort:\t20000\r\nRemotePort:\tany\r\n";
        assert!(rule_output_mentions_port(output, 20000));
        assert!(!rule_output_mentions_port(output, 51820));
        assert!(!rule_output_mentions_port("", 51820));
        // 无冒号/畸形行按不匹配处理，不 panic。
        assert!(!rule_output_mentions_port("LocalPort garbage", 51820));
    }

    #[test]
    fn rule_output_mentions_port_matches_zh_cn_label() {
        // 审核发现 #2：中文 Windows 的 netsh 输出用「本地端口」标签，英文标签
        // 匹配会漏判 → 每次重放叠加同名规则。zh 标签必须命中。
        let zh = "规则名称: Meshlet-Direct-UDP-In\r\n本地端口:\t51820\r\n";
        assert!(rule_output_mentions_port(zh, 51820));
        assert!(!rule_output_mentions_port(zh, 20000));
        assert_eq!(rule_output_ports(zh), vec![51820]);
    }

    #[test]
    fn rule_output_ports_enumerates_all_mentioned_ports() {
        // 审核发现 #3：同名规则可含多条（配置改端口后残留），端口全集需枚举。
        let both = "Rule Name: Meshlet-Direct-UDP-In\r\nLocalPort: 20000\r\n\
                    Rule Name: Meshlet-Direct-UDP-In\r\nLocalPort: 51820\r\n";
        assert_eq!(rule_output_ports(both), vec![20000, 51820]);
        assert!(rule_output_mentions_port(both, 51820));
        assert!(rule_output_mentions_port(both, 20000));
    }

    #[test]
    fn icmp_rule_satisfaction_checks_enabled_and_local_ip() {
        // 审核发现 #1：仅按名判在场会在地址变更 / 规则被禁用后误报。
        let addr = "10.240.0.7".parse().unwrap();
        let satisfied_en = format!(
            "Rule Name:        Meshlet-ICMPv4-In\r\nEnabled:          Yes\r\nLocalIP:         {addr}\r\n"
        );
        assert!(rule_output_has_satisfied_icmp_rule(&satisfied_en, addr));

        // 地址变更：规则在场但 localip 是旧地址 → 不满足。
        let stale_addr = "Rule Name:        Meshlet-ICMPv4-In\r\nEnabled:          Yes\r\nLocalIP:         10.240.0.9\r\n".to_string();
        assert!(!rule_output_has_satisfied_icmp_rule(&stale_addr, addr));

        // 同名规则被禁用（Enabled: No）→ 不满足。
        let disabled = format!(
            "Rule Name:        Meshlet-ICMPv4-In\r\nEnabled:          No\r\nLocalIP:         {addr}\r\n"
        );
        assert!(!rule_output_has_satisfied_icmp_rule(&disabled, addr));

        // zh-CN 字段（已启用: 是 / 本地 IP）→ 满足。
        let zh = format!(
            "规则名称:      Meshlet-ICMPv4-In\r\n已启用:        是\r\n本地 IP:        {addr}\r\n"
        );
        assert!(rule_output_has_satisfied_icmp_rule(&zh, addr));
    }

    /// netsh show 把 localip 归一为 `ip/netmask`（真机 windows_firewall_live
    /// 取证：`LocalIP: 127.0.0.1/255.255.255.255`），裸串等值比较会把已满足
    /// 误判 Stale、每轮 apply delete+add 永不幂等。
    #[test]
    fn icmp_rule_satisfaction_tolerates_netsh_ip_mask_suffix() {
        let addr = "127.0.0.1".parse().unwrap();
        // 真机形态：ip/netmask + 对齐宽空格。
        let real = "Rule Name:                            Meshlet-ICMPv4-In\r\n\
                    Enabled:                              Yes\r\n\
                    LocalIP:                              127.0.0.1/255.255.255.255\r\n";
        assert!(rule_output_has_satisfied_icmp_rule(real, addr));
        // CIDR 形态同样兼容。
        let cidr = "Enabled: Yes\r\nLocalIP: 127.0.0.1/32\r\n";
        assert!(rule_output_has_satisfied_icmp_rule(cidr, addr));
        // 多地址逗号分隔，含目标地址 → 满足。
        let multi =
            "Enabled: Yes\r\nLocalIP: 10.240.0.9/255.255.255.255,127.0.0.1/255.255.255.255\r\n";
        assert!(rule_output_has_satisfied_icmp_rule(multi, addr));
        // 形态合法但地址不同 → 不满足（前缀同段也不行）。
        let other = "Enabled: Yes\r\nLocalIP: 127.0.0.2/255.255.255.255\r\n";
        assert!(!rule_output_has_satisfied_icmp_rule(other, addr));
    }

    #[cfg(target_os = "windows")]
    mod exec_tests {
        use super::super::*;
        use super::rule;
        use crate::{ApplyResult, NetworkError};

        /// 编译期锁定 exec 入口：签名只接收计划命令、返回计划层结果，测试不
        /// 启动 netsh。
        #[test]
        fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
            fn assert_signature(
                _run: fn(&FirewallRuleCommand) -> Result<ApplyResult, NetworkError>,
            ) {
            }
            assert_signature(super::super::exec::run_firewall_command);
        }

        /// exec 的删除分支依赖计划层判定：不存在文案 = 幂等成功。
        #[test]
        fn exec_delete_absence_classifier_is_idempotent_success() {
            assert!(firewall_rule_already_absent(
                "No rules match the specified criteria."
            ));
            assert!(classify_netsh_firewall_failure(
                1,
                "No rules match the specified criteria.",
                FirewallRuleCommand::Delete {
                    name: "Meshlet WireGuard".into(),
                }
                .operation(),
                FirewallRuleCommand::Delete {
                    name: "Meshlet WireGuard".into(),
                }
                .name()
            )
            .is_ok());
        }

        /// exec 的非零退出码交回计划层：权限类必须仍归权限错误。
        #[test]
        fn exec_failure_classification_preserves_privilege_mapping() {
            let command = FirewallRuleCommand::Add { rule: rule() };
            assert!(matches!(
                classify_netsh_firewall_failure(
                    1,
                    "Access is denied.",
                    command.operation(),
                    command.name()
                ),
                Err(NetworkError::InsufficientPrivileges(_))
            ));
        }
    }

    fn rule() -> FirewallRule {
        FirewallRule {
            name: "Meshlet WireGuard".into(),
            direction: FirewallDirection::Inbound,
            action: FirewallAction::Allow,
            protocol: FirewallProtocol::Udp,
            local_port: "51820".into(),
            remote_port: "any".into(),
            profiles: Some(vec![
                FirewallProfile::Public,
                FirewallProfile::Domain,
                FirewallProfile::Public,
            ]),
            description: Some("Meshlet managed inbound tunnel".into()),
            local_ip: None,
        }
    }

    #[test]
    fn add_renders_all_parameters_in_deterministic_order() {
        let command = FirewallRuleCommand::Add { rule: rule() };
        assert_eq!(
            command.args(),
            vec![
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Meshlet WireGuard",
                "dir=in",
                "action=allow",
                "protocol=udp",
                "localport=51820",
                "remoteport=any",
                "profile=domain,public",
                "description=Meshlet managed inbound tunnel",
            ]
        );
    }

    #[test]
    fn delete_renders_only_the_controlled_rule_name() {
        let command = FirewallRuleCommand::Delete {
            name: "Meshlet WireGuard".into(),
        };
        assert_eq!(
            command.args(),
            vec![
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                "name=Meshlet WireGuard",
            ]
        );
    }

    #[test]
    fn planning_is_deterministic() {
        let command = FirewallRuleCommand::Add { rule: rule() };
        assert_eq!(command.args(), command.args());
    }

    #[test]
    fn rule_name_with_spaces_remains_one_named_argv_token() {
        let args = FirewallRuleCommand::Add { rule: rule() }.args();
        assert_eq!(args[4], "name=Meshlet WireGuard");
        assert!(!args[4].contains('"'));
    }

    #[test]
    fn absence_output_is_idempotent_success_for_delete() {
        assert!(classify_netsh_firewall_failure(
            1,
            "No rules match the specified criteria.",
            "firewall rule delete",
            "Meshlet WireGuard"
        )
        .is_ok());
    }

    #[test]
    fn absence_output_does_not_succeed_for_add() {
        assert!(matches!(
            classify_netsh_firewall_failure(
                1,
                "No rules match the specified criteria.",
                "firewall rule add",
                "Meshlet WireGuard"
            ),
            Err(NetworkError::ApplyRejected(detail)) if detail.contains("exit 1")
        ));
    }

    /// zh-CN 真机取证（2026-10-25）：中文缺失报文按原文命中幂等删除判定。
    #[test]
    fn localized_absence_output_is_idempotent_success_for_delete() {
        assert!(firewall_rule_already_absent("没有与指定标准相匹配的规则。"));
        assert!(classify_netsh_firewall_failure(
            1,
            "没有与指定标准相匹配的规则。",
            "firewall rule delete",
            "Meshlet WireGuard"
        )
        .is_ok());
    }

    /// zh-CN 真机取证：本地化提权文案归入权限类。
    #[test]
    fn localized_privilege_output_maps_to_privileges() {
        assert!(matches!(
            classify_netsh_firewall_failure(
                1,
                "请求的操作需要提升(作为管理员运行)。",
                "firewall rule add",
                "Meshlet WireGuard"
            ),
            Err(NetworkError::InsufficientPrivileges(_))
        ));
    }

    #[test]
    fn elevation_and_denied_output_map_to_privileges() {
        for output in [
            "The requested operation requires elevation.",
            "Access is denied.",
        ] {
            assert!(matches!(
                classify_netsh_firewall_failure(1, output, "firewall rule add", "Meshlet WireGuard"),
                Err(NetworkError::InsufficientPrivileges(detail))
                    if detail.contains("`Meshlet WireGuard`")
            ));
        }
    }

    #[test]
    fn unknown_failure_fails_closed_with_original_text() {
        assert!(matches!(
            classify_netsh_firewall_failure(
                2,
                "\n  The parameter is incorrect.\n",
                "firewall rule add",
                "Meshlet WireGuard"
            ),
            Err(NetworkError::ApplyRejected(detail))
                if detail.contains("exit 2") && detail.contains("The parameter is incorrect.")
        ));
    }

    #[test]
    fn missing_profiles_render_any() {
        let mut value = rule();
        value.profiles = None;
        let args = FirewallRuleCommand::Add { rule: value }.args();
        assert_eq!(args[10], "profile=any");
    }

    const DEVICE_ADDR: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 240, 0, 5);

    #[test]
    fn icmp_rule_renders_protocol_and_localip_without_ports() {
        // netsh 不接受 ICMP 协议带端口词元：localport/remoteport 必须省略；
        // localip 把放行限定到设备 overlay 地址（=「限定 wg 接口」的 netsh 等价）。
        let args = FirewallRuleCommand::Add {
            rule: mesh_icmp_rule(DEVICE_ADDR),
        }
        .args();
        assert_eq!(
            args,
            vec![
                "advfirewall",
                "firewall",
                "add",
                "rule",
                "name=Meshlet-ICMPv4-In",
                "dir=in",
                "action=allow",
                "protocol=icmpv4:8,any",
                "profile=any",
                "localip=10.240.0.5",
                "description=meshlet mesh reachability: inbound ICMP echo to the wg interface",
            ]
        );
    }

    #[test]
    fn set_network_category_renders_powershell_command() {
        let command = MeshFirewallCommand::set_network_category_private("wg-meshlet").unwrap();
        assert_eq!(
            command.args(),
            vec![
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Set-NetConnectionProfile -InterfaceAlias 'wg-meshlet' -NetworkCategory Private",
            ]
        );
        assert!(!command.uses_netsh());
        assert_eq!(command.operation(), "network category set private");
    }

    #[test]
    fn mesh_reachability_plan_covers_all_current_states() {
        use IcmpRuleState::*;
        // 全幂等：档位已 Private 且规则已满足 → 空计划；任一缺 → 只补缺的那条。
        let none = mesh_reachability_commands("wg-meshlet", DEVICE_ADDR, true, Satisfied).unwrap();
        assert!(none.is_empty());

        let only_category =
            mesh_reachability_commands("wg-meshlet", DEVICE_ADDR, false, Satisfied).unwrap();
        assert_eq!(only_category.len(), 1);
        assert!(matches!(
            only_category[0],
            MeshFirewallCommand::SetNetworkCategoryPrivate { .. }
        ));

        let only_rule =
            mesh_reachability_commands("wg-meshlet", DEVICE_ADDR, true, Absent).unwrap();
        assert_eq!(only_rule.len(), 1);
        assert_eq!(
            only_rule[0],
            MeshFirewallCommand::AddIcmpRule {
                rule: mesh_icmp_rule(DEVICE_ADDR)
            }
        );

        let both = mesh_reachability_commands("wg-meshlet", DEVICE_ADDR, false, Absent).unwrap();
        assert_eq!(both.len(), 2);
    }

    #[test]
    fn mesh_reachability_stale_icmp_rule_is_delete_then_add() {
        // 审核发现 #1：地址变更残留 / 被禁用的同名规则 → 先删后建，保证恰一条。
        let commands =
            mesh_reachability_commands("wg-meshlet", DEVICE_ADDR, true, IcmpRuleState::Stale)
                .unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0],
            MeshFirewallCommand::DeleteIcmpRule {
                name: mesh_icmp_rule(DEVICE_ADDR).name
            }
        );
        assert_eq!(
            commands[1],
            MeshFirewallCommand::AddIcmpRule {
                rule: mesh_icmp_rule(DEVICE_ADDR)
            }
        );
    }

    #[test]
    fn mesh_reachability_rejects_unsafe_interface_names() {
        // 接口名进入 PowerShell 单引号字符串：引号/空白必须拒绝（防注入）。
        for bad in ["", "wg meshlet", "wg'x", "wg\"x", "wg;x", "$(x)", "wg|x"] {
            assert!(
                mesh_reachability_commands(bad, DEVICE_ADDR, false, IcmpRuleState::Absent).is_err(),
                "interface {bad:?} must be rejected"
            );
            assert!(MeshFirewallCommand::set_network_category_private(bad).is_err());
        }
        // 合法隧道名（含 dot / 下划线）必须放行。
        for good in ["wg-meshlet", "wg0", "Meshlet.Tunnel_1"] {
            assert!(
                mesh_reachability_commands(good, DEVICE_ADDR, true, IcmpRuleState::Satisfied)
                    .is_ok()
            );
        }
    }

    #[test]
    fn firewall_rule_present_distinguishes_show_output() {
        // en-US / zh-CN 真机报文（CP936 解码后）。
        assert!(firewall_rule_present(
            "Rule Name:        Meshlet-ICMPv4-In\r\nEnabled:          Yes"
        ));
        assert!(firewall_rule_present(
            "规则名称:      Meshlet-ICMPv4-In\r\n已启用:        是"
        ));
        assert!(!firewall_rule_present(
            "No rules match the specified criteria."
        ));
        assert!(!firewall_rule_present("没有与指定标准相匹配的规则。"));
        assert!(!firewall_rule_present(""));
    }

    #[test]
    fn net_category_probe_matches_private_only() {
        assert!(net_category_is_private("NetworkCategory : Private"));
        assert!(!net_category_is_private("NetworkCategory : Public"));
        assert!(!net_category_is_private(
            "Get-NetConnectionProfile : No matching MSFT_NetConnectionProfile"
        ));
    }

    #[test]
    fn net_category_probe_ignores_name_collisions() {
        // 审核发现 #4：连接名/别名含 private 但档位为 Public → 必须判非 Private。
        assert!(!net_category_is_private(
            "Name       : Private LAN\nNetworkCategory : Public"
        ));
        assert!(net_category_is_private(
            "Name       : Private LAN\nNetworkCategory : Private"
        ));
        // 探测命令只取 `.NetworkCategory` 时的裸值输出。
        assert!(net_category_is_private("Private"));
        assert!(!net_category_is_private("Public"));
        assert!(!net_category_is_private("DomainAuthenticated"));
        assert!(!net_category_is_private(""));
    }
}
