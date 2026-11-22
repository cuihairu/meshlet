//! macOS DNS 面（③-B）：resolver 文件计划——纯函数层，全平台编译+单测。
//!
//! macOS 的按域解析器是**文件机制**（`/etc/resolver/<domain>`），不需要改
//! `scutil` 状态：写文件即可。本模块产出写文件计划（路径/内容/权限）并
//! 守门路径穿越；执行器经 [ResolverSink] 落盘（`cfg(macos)` 的真实现
//! 在 [crate::macos::backend]）。
//!
//! 只读诊断面是命令计划的 [crate::macos::backend::BtCommand::DumpDns]
//! （`scutil --dns`），不在本模块。

use crate::NetworkError;
use std::path::PathBuf;

/// 解析器根目录（`/etc/resolver/<domain>`，macOS 标准机制）。
pub const RESOLVER_ROOT: &str = "/etc/resolver";

/// resolver 文件计划的固定权限：普通文件、644（组/其他可读，属主可写）。
pub const RESOLVER_FILE_MODE: u32 = 0o644;

/// 一条写文件计划（`/etc/resolver/<domain>`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverFilePlan {
    /// 绝对路径（[RESOLVER_ROOT] 内，无穿越）。
    pub path: PathBuf,
    /// 文件内容（每行一条 `nameserver <ip>`）。
    pub content: String,
    /// 权限位（[RESOLVER_FILE_MODE]）。
    pub mode: u32,
}

/// resolver 计划错误（→ [NetworkError::ApplyRejected]）。
#[derive(Debug, thiserror::Error)]
pub enum DnsPlanError {
    #[error("invalid resolver domain {0:?}")]
    InvalidDomain(String),
    #[error("at least one nameserver is required")]
    NoNameservers,
}

impl From<DnsPlanError> for NetworkError {
    fn from(error: DnsPlanError) -> Self {
        NetworkError::ApplyRejected(error.to_string())
    }
}

/// 域计划：`domain` + nameserver 列表 → [ResolverFilePlan]（纯函数）。
///
/// - **路径守门**：domain 必须是单段 DNS 标签（或点分标签），拒绝分隔符、
///   空标签、`..`、绝对路径与空白——保证计划路径恒在 [RESOLVER_ROOT] 内，
///   绝不写出根目录。
/// - **内容**：每条 nameserver 一行 `nameserver <ip>`（无 nameserver 拒绝，
///   不写空文件）。
/// - **权限**：[RESOLVER_FILE_MODE]。
pub fn resolver_file_plan(
    domain: &str,
    nameservers: &[std::net::Ipv4Addr],
) -> Result<ResolverFilePlan, DnsPlanError> {
    if !is_valid_resolver_domain(domain) {
        return Err(DnsPlanError::InvalidDomain(domain.to_string()));
    }
    if nameservers.is_empty() {
        return Err(DnsPlanError::NoNameservers);
    }
    let mut content = String::new();
    for nameserver in nameservers {
        content.push_str(&format!("nameserver {nameserver}\n"));
    }
    let path = PathBuf::from(RESOLVER_ROOT).join(domain);
    // 双保险：路径必须落在 resolver 根目录内（穿越即拒，不依赖标签校验）。
    if !path.starts_with(RESOLVER_ROOT) {
        return Err(DnsPlanError::InvalidDomain(domain.to_string()));
    }
    Ok(ResolverFilePlan {
        path,
        content,
        mode: RESOLVER_FILE_MODE,
    })
}

/// 域是否可作为 resolver 文件名（单段或点分标签；无路径成分）。
pub fn is_valid_resolver_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain
        .chars()
        .any(|c| c.is_whitespace() || c == '/' || c == '\0' || c == '\n' || !c.is_ascii())
    {
        return false;
    }
    // 标签内：字母数字 + 连字符；标签间：单个点。
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// 解析器文件落盘端口：计划层产出计划，执行器经本 trait 落盘。
///
/// Linux 侧测试用 [RecordingResolverSink] 断言落盘调用序列（内存 mock，
/// 不真写盘）；`cfg(macos)` 真实现在 [crate::macos::backend]。
pub trait ResolverSink {
    fn write(&self, plan: &ResolverFilePlan) -> Result<(), NetworkError>;
}

/// 内存 mock 落盘端口（测试钩子）：记录写入序列，不真写盘。
#[cfg(test)]
#[derive(Debug, Default)]
pub struct RecordingResolverSink {
    written: std::cell::RefCell<Vec<ResolverFilePlan>>,
}

#[cfg(test)]
impl RecordingResolverSink {
    pub fn new() -> Self {
        Self::default()
    }

    /// 已记录的落盘计划序列（断言用）。
    pub fn written(&self) -> Vec<ResolverFilePlan> {
        self.written.borrow().clone()
    }
}

#[cfg(test)]
impl ResolverSink for RecordingResolverSink {
    fn write(&self, plan: &ResolverFilePlan) -> Result<(), NetworkError> {
        self.written.borrow_mut().push(plan.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::path::Path;

    #[test]
    fn resolver_plan_builds_nameserver_lines_and_mode() {
        let plan = resolver_file_plan(
            "example.com",
            &[Ipv4Addr::new(10, 240, 0, 1), Ipv4Addr::new(10, 240, 0, 2)],
        )
        .unwrap();
        assert_eq!(plan.path, PathBuf::from("/etc/resolver/example.com"));
        assert_eq!(
            plan.content,
            "nameserver 10.240.0.1\nnameserver 10.240.0.2\n"
        );
        assert_eq!(plan.mode, RESOLVER_FILE_MODE);
        assert_eq!(plan.mode, 0o644);
    }

    #[test]
    fn resolver_plan_rejects_path_traversal() {
        let cases = [
            "",
            "..",
            "a/../../etc/passwd",
            "/etc/passwd",
            "example.com/",
            "exa mple.com",
            "exa\nmple.com",
            ".com",
            "-foo",
            "foo-",
            "中文域名",
        ];
        for case in cases {
            assert!(
                resolver_file_plan(case, &[Ipv4Addr::new(10, 240, 0, 1)]).is_err(),
                "expected {case:?} rejected"
            );
            assert!(!is_valid_resolver_domain(case), "expected {case:?} invalid");
        }
    }

    #[test]
    fn resolver_plan_rejects_empty_nameservers() {
        assert!(matches!(
            resolver_file_plan("example.com", &[]),
            Err(DnsPlanError::NoNameservers)
        ));
    }

    #[test]
    fn resolver_plan_maps_to_apply_rejected() {
        let error: NetworkError =
            resolver_file_plan("../etc/passwd", &[Ipv4Addr::new(10, 240, 0, 1)])
                .unwrap_err()
                .into();
        assert!(matches!(error, NetworkError::ApplyRejected(_)));
    }

    #[test]
    fn recording_sink_records_the_write_sequence() {
        let sink = RecordingResolverSink::new();
        let plan = resolver_file_plan("a.b", &[Ipv4Addr::new(1, 1, 1, 1)]).unwrap();
        assert!(sink.write(&plan).is_ok());
        let written = sink.written();
        assert_eq!(written.len(), 1);
        assert_eq!(written[0].path, PathBuf::from("/etc/resolver/a.b"));
        assert_eq!(written[0].content, "nameserver 1.1.1.1\n");
        // 内存 mock 断言的是落盘计划序列，不真写盘。
    }

    #[test]
    fn resolver_root_is_the_expected_directory() {
        assert_eq!(RESOLVER_ROOT, "/etc/resolver");
        assert!(Path::new(RESOLVER_ROOT).is_absolute());
    }
}
