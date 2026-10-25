//! Windows 完整卸载计划层（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 本模块只包含**纯规划**：把 Meshlet 自有卸载步骤渲染成既有模块已经定义、
//! 已经分类过的受控命令，不执行任何命令。计划层在任意平台编译并单测。
//! 执行层复用 routes/service/firewall 三个已真机验证的 exec 薄封装
//! （2026-10-26 中文 Windows Server：卸载链重入集成测试
//! `windows_cleanup_e2e` 闭环）；TODO #52 保持未勾：接
//! [crate::SystemBackend] 仍以完整验收为准，非 Linux 平台仍保持
//! [crate::unsupported] 的显式占位（§10.3、§12.2）。
//!
//! 与 [windows_service](windows_service)、[windows_routes](windows_routes)、
//! [windows_firewall](windows_firewall) 同一纪律：
//!
//! - **受控命令**：只复用既有 pub 命令构造器（`sc` 服务停止/删除、
//!   `netsh interface ipv4 delete route`、`netsh advfirewall firewall delete
//!   rule`），不拼接自由文本；含空格的服务/接口/规则名保持单个 argv 词元；
//! - **确定性顺序**：固定为 service stop → service delete → 已知前缀逐条
//!   route delete → Meshlet 受管规则名逐条 firewall delete；
//! - **失败可清理**：每一步的「目标已缺失 = 可重入跳过」判定只调用对应
//!   模块已有的 absent 分类函数，不在此重复实现分类逻辑；
//! - **所有权边界**：只接收显式列出的 Meshlet 服务、已知前缀和受管规则名，
//!   绝不扫描或清理机器全局服务/路由/防火墙表。

use std::path::PathBuf;

use meshlet_domain::Ipv4Cidr;

use crate::windows_firewall::{firewall_rule_already_absent, FirewallRuleCommand};
use crate::windows_routes::{route_already_absent, NetshRouteCommand};
use crate::windows_service::{service_absent, ServiceCommand};
use crate::NetworkError;

/// 完整卸载的输入计划（只描述 Meshlet 自有对象，不描述机器全局状态）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPlan {
    /// 受管服务名；先 Stop 再 Delete，缺失时对两步均按成功处理。
    pub service_name: String,
    /// 本设备 WireGuard 隧道接口；仅在 `route_prefixes` 非空时用于删除路由。
    pub route_interface: String,
    /// 已知由本接口承载、需要逐条删除的 on-link 前缀；空列表不产生路由步。
    pub route_prefixes: Vec<Ipv4Cidr>,
    /// Meshlet 受管防火墙规则名；按输入顺序逐条删除。
    pub firewall_rule_names: Vec<String>,
    /// Meshlet 写出的临时文件；按输入顺序逐个删除。
    pub temp_files: Vec<PathBuf>,
    /// Meshlet 私钥文件；按输入顺序逐个删除，绝不按目录扫描。
    pub key_material_files: Vec<PathBuf>,
}

impl CleanupPlan {
    /// 受控卸载命令序列；顺序和参数形状均可在任意平台确定性断言。
    pub fn commands(&self) -> Vec<CleanupCommand> {
        let mut commands = vec![
            CleanupCommand::Service(ServiceCommand::Stop {
                name: self.service_name.clone(),
            }),
            CleanupCommand::Service(ServiceCommand::Delete {
                name: self.service_name.clone(),
            }),
        ];

        for destination in &self.route_prefixes {
            commands.push(CleanupCommand::Route(NetshRouteCommand::Delete {
                destination: *destination,
                interface: self.route_interface.clone(),
                gateway: None,
            }));
        }

        commands.extend(self.firewall_rule_names.iter().map(|name| {
            CleanupCommand::Firewall(FirewallRuleCommand::Delete { name: name.clone() })
        }));

        commands.extend(self.temp_files.iter().cloned().map(|path| {
            CleanupCommand::File(CleanupFileCommand {
                path,
                kind: CleanupFileKind::Temporary,
            })
        }));
        commands.extend(self.key_material_files.iter().cloned().map(|path| {
            CleanupCommand::File(CleanupFileCommand {
                path,
                kind: CleanupFileKind::KeyMaterial,
            })
        }));

        commands
    }
}

/// 一条计划态卸载命令。
///
/// 本枚举只包装既有模块的计划命令，不新增命令语法；执行器可直接遍历本序列
/// 并按包装类型调用各模块的既有执行入口（本轮不实现执行层）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupCommand {
    /// `sc stop/delete <service>`；服务不存在时按幂等成功跳过。
    Service(ServiceCommand),
    /// `netsh interface ipv4 delete route ... store=active`；前缀不存在时跳过。
    Route(NetshRouteCommand),
    /// `netsh advfirewall firewall delete rule name=...`；规则不存在时跳过。
    Firewall(FirewallRuleCommand),
    /// 删除一个显式列出的临时文件或私钥文件。
    File(CleanupFileCommand),
}

/// 文件清理的对象类别；类别只决定审计语义，不扩大删除范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupFileKind {
    Temporary,
    KeyMaterial,
}

/// 一次受控文件删除；目标必须由卸载计划显式列出。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupFileCommand {
    pub path: PathBuf,
    pub kind: CleanupFileKind,
}

impl CleanupCommand {
    /// 进程参数（复用既有模块 `args()`；不含程序名，执行层决定）。
    pub fn args(&self) -> Vec<String> {
        match self {
            CleanupCommand::Service(command) => command.args(),
            CleanupCommand::Route(command) => command.args(),
            CleanupCommand::Firewall(command) => command.args(),
            CleanupCommand::File(command) => command.args(),
        }
    }

    /// 操作名（复用既有模块的操作名，错误消息不漂移）。
    pub fn operation(&self) -> &'static str {
        match self {
            CleanupCommand::Service(command) => command.operation(),
            CleanupCommand::Route(command) => command.operation(),
            CleanupCommand::Firewall(command) => command.operation(),
            CleanupCommand::File(command) => command.operation(),
        }
    }

    /// 目标对象已缺失时是否可重入跳过。
    ///
    /// 该函数本身不做文本分类：sc/netsh 的 absent 判据分别留在
    /// [windows_service] / [windows_routes] / [windows_firewall] 三个权威模块中。
    pub fn absent_is_skippable(&self, output: &str) -> bool {
        match self {
            CleanupCommand::Service(_) => service_absent(output),
            CleanupCommand::Route(_) => route_already_absent(output),
            CleanupCommand::Firewall(_) => firewall_rule_already_absent(output),
            CleanupCommand::File(_) => false,
        }
    }
}

impl CleanupFileCommand {
    /// 审计用操作名；文件清理没有外部进程参数。
    pub fn args(&self) -> Vec<String> {
        vec![self.path.display().to_string()]
    }

    /// 审计用操作名。
    pub fn operation(&self) -> &'static str {
        match self.kind {
            CleanupFileKind::Temporary => "cleanup temporary file",
            CleanupFileKind::KeyMaterial => "cleanup key material file",
        }
    }

    /// 删除显式列出的文件；缺失返回 `Ok(false)` 以支持卸载重入。
    pub fn remove(self) -> Result<bool, NetworkError> {
        let metadata = match std::fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(NetworkError::Io(format!(
                    "inspect {}: {error}",
                    self.path.display()
                )))
            }
        };

        if metadata.is_dir() {
            return Err(NetworkError::ApplyRejected(format!(
                "refusing to remove directory during cleanup: {}",
                self.path.display()
            )));
        }

        std::fs::remove_file(&self.path).map_err(|error| {
            NetworkError::Io(format!("remove {}: {error}", self.path.display()))
        })?;
        Ok(true)
    }
}

/// 执行层（`#[cfg(windows)]`）：服务/路由/防火墙复用既有薄封装；文件清理
/// 使用跨平台受控 std API，只删除计划中显式列出的路径。
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{CleanupCommand, CleanupFileCommand};
    use crate::windows_firewall::exec::run_firewall_command;
    use crate::windows_routes::exec::run_route_command;
    use crate::windows_service::exec::run_service_command;
    use crate::{ApplyResult, NetworkError};

    /// 执行一条完整卸载计划命令：成功/幂等成功/分类失败三态。
    pub fn run_cleanup_command(command: &CleanupCommand) -> Result<ApplyResult, NetworkError> {
        match command {
            CleanupCommand::Service(command) => run_service_command(command),
            CleanupCommand::Route(command) => run_route_command(command),
            CleanupCommand::Firewall(command) => run_firewall_command(command),
            CleanupCommand::File(command) => {
                CleanupFileCommand::clone(command).remove()?;
                Ok(ApplyResult::ok())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> CleanupPlan {
        CleanupPlan {
            service_name: "meshlet".into(),
            route_interface: "Meshlet Office".into(),
            route_prefixes: vec![
                "10.241.1.0/24".parse().unwrap(),
                "10.242.2.0/24".parse().unwrap(),
            ],
            firewall_rule_names: vec!["Meshlet WireGuard".into(), "Meshlet Admin".into()],
            temp_files: Vec::new(),
            key_material_files: Vec::new(),
        }
    }

    #[test]
    fn cleanup_sequence_keeps_service_route_firewall_order() {
        let commands = plan().commands();
        assert_eq!(
            commands
                .iter()
                .map(CleanupCommand::operation)
                .collect::<Vec<_>>(),
            vec![
                "service stop",
                "service delete",
                "route delete",
                "route delete",
                "firewall rule delete",
                "firewall rule delete",
            ]
        );
        assert_eq!(commands[2].args(), route_args("10.241.1.0/24"));
    }

    #[test]
    fn cleanup_reuses_existing_command_argv_shapes() {
        let commands = plan().commands();
        assert_eq!(commands[0].args(), vec!["stop", "meshlet"]);
        assert_eq!(commands[1].args(), vec!["delete", "meshlet"]);
        assert_eq!(commands[2].args(), route_args("10.241.1.0/24"));
        assert_eq!(
            commands[4].args(),
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
    fn interface_and_rule_names_with_spaces_are_single_unquoted_args() {
        let commands = plan().commands();
        let route_args = commands[2].args();
        let firewall_args = commands[4].args();
        assert!(route_args.contains(&"interface=Meshlet Office".to_string()));
        assert!(firewall_args.contains(&"name=Meshlet WireGuard".to_string()));
        assert!(!route_args.iter().any(|arg| arg.contains('"')));
        assert!(!firewall_args.iter().any(|arg| arg.contains('"')));
    }

    #[test]
    fn empty_route_prefix_list_omits_only_route_steps() {
        let mut cleanup_plan = plan();
        cleanup_plan.route_prefixes.clear();
        let commands = cleanup_plan.commands();
        assert_eq!(
            commands
                .iter()
                .map(CleanupCommand::operation)
                .collect::<Vec<_>>(),
            vec![
                "service stop",
                "service delete",
                "firewall rule delete",
                "firewall rule delete",
            ]
        );
    }

    #[test]
    fn absent_outputs_are_skippable_through_existing_classifiers() {
        let commands = plan().commands();
        assert!(
            commands[0].absent_is_skippable("ERROR 1060: The specified service does not exist.")
        );
        assert!(
            commands[1].absent_is_skippable("ERROR 1060: The specified service does not exist.")
        );
        assert!(commands[2].absent_is_skippable("Cannot find the interface in the table."));
        assert!(commands[4].absent_is_skippable("No rules match the specified criteria."));
    }

    #[test]
    fn explicit_files_and_key_material_are_removed_idempotently() {
        let directory = std::env::temp_dir().join(format!(
            "meshlet-windows-cleanup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let temp_file = directory.join("meshlet.tmp");
        let key_file = directory.join("device.key");
        std::fs::write(&temp_file, b"temporary").unwrap();
        std::fs::write(&key_file, b"private-key").unwrap();

        let mut cleanup_plan = plan();
        cleanup_plan.temp_files = vec![temp_file.clone()];
        cleanup_plan.key_material_files = vec![key_file.clone()];
        let removed: Vec<bool> = cleanup_plan
            .commands()
            .into_iter()
            .filter_map(|command| match command {
                CleanupCommand::File(command) => Some(command.remove().unwrap()),
                _ => None,
            })
            .collect();

        assert_eq!(removed, vec![true, true]);
        assert!(!temp_file.exists());
        assert!(!key_file.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn missing_cleanup_files_are_reentrant_and_directories_are_rejected() {
        let directory = std::env::temp_dir().join(format!(
            "meshlet-windows-cleanup-missing-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(directory.join("key")).unwrap();
        let file = CleanupFileCommand {
            path: directory.join("missing.tmp"),
            kind: CleanupFileKind::Temporary,
        };
        assert!(!file.clone().remove().unwrap());
        assert!(!file.remove().unwrap());

        let directory_command = CleanupFileCommand {
            path: directory.join("key"),
            kind: CleanupFileKind::KeyMaterial,
        };
        assert!(matches!(
            directory_command.remove(),
            Err(NetworkError::ApplyRejected(_))
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn route_args(prefix: &str) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv4".into(),
            "delete".into(),
            "route".into(),
            format!("prefix={prefix}"),
            "interface=Meshlet Office".into(),
            "store=active".into(),
        ]
    }
}
