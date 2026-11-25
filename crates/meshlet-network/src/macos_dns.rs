//! macOS DNS surface (③-B): resolver file plan — a pure-function layer,
//! compiled and unit-tested on every platform.
//!
//! macOS per-domain resolvers are a **file mechanism**
//! (`/etc/resolver/<domain>`) and need no `scutil` state change: writing the
//! file is enough. This module produces write-file plans (path/content/
//! permissions) and guards against path traversal; the executor writes to
//! disk through [ResolverSink] (the real `cfg(macos)` implementation lives in
//! [crate::macos::backend]).
//!
//! The read-only diagnostics surface is the
//! [crate::macos::backend::BtCommand::DumpDns] command plan (`scutil --dns`),
//! which is not part of this module.

use crate::NetworkError;
use std::path::PathBuf;

/// Resolver root directory (`/etc/resolver/<domain>`, the standard macOS
/// mechanism).
pub const RESOLVER_ROOT: &str = "/etc/resolver";

/// Fixed permissions for a resolver file plan: a regular file, mode 644
/// (group/others readable, owner writable).
pub const RESOLVER_FILE_MODE: u32 = 0o644;

/// A single write-file plan (`/etc/resolver/<domain>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverFilePlan {
    /// Absolute path (inside [RESOLVER_ROOT], no traversal).
    pub path: PathBuf,
    /// File content (one `nameserver <ip>` line each).
    pub content: String,
    /// Permission bits ([RESOLVER_FILE_MODE]).
    pub mode: u32,
}

/// Resolver plan error (-> [NetworkError::ApplyRejected]).
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

/// Domain plan: `domain` + a list of nameservers -> [ResolverFilePlan] (pure
/// function).
///
/// - **Path gate**: the domain must be a single DNS label (or dot-separated
///   labels); separators, empty labels, `..`, absolute paths and whitespace are
///   rejected — this keeps the planned path always inside [RESOLVER_ROOT] and
///   never writes outside the root directory.
/// - **Content**: one `nameserver <ip>` line per nameserver (no nameservers is
///   refused, so no empty file is written).
/// - **Permissions**: [RESOLVER_FILE_MODE].
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
    // Belt and braces: the path must land inside the resolver root directory
    // (traversal is refused outright, not relying on the label validation).
    if !path.starts_with(RESOLVER_ROOT) {
        return Err(DnsPlanError::InvalidDomain(domain.to_string()));
    }
    Ok(ResolverFilePlan {
        path,
        content,
        mode: RESOLVER_FILE_MODE,
    })
}

/// Whether the domain can be used as a resolver file name (a single label or
/// dot-separated labels; no path components).
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
    // Within a label: alphanumerics plus hyphen; between labels: a single dot.
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// Sink port for resolver file writes: the plan layer produces the plan and
/// the executor writes to disk through this trait.
///
/// Linux-side tests use [RecordingResolverSink] to assert the write call
/// sequence (an in-memory mock, nothing is really written); the real
/// `cfg(macos)` implementation is in [crate::macos::backend].
pub trait ResolverSink {
    fn write(&self, plan: &ResolverFilePlan) -> Result<(), NetworkError>;
}

/// In-memory mock sink port (test hook): records the write sequence without
/// really writing to disk.
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

    /// The recorded write-plan sequence (for assertions).
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
    #[cfg(unix)]
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
        // The in-memory mock asserts the write-plan sequence, it does not
        // really write to disk.
    }

    /// Pin: the resolver root is the standard macOS path (cross-platform we
    /// only pin the string itself).
    #[test]
    fn resolver_root_is_the_expected_directory() {
        assert_eq!(RESOLVER_ROOT, "/etc/resolver");
    }

    /// Under Unix path semantics `/etc/resolver` is an absolute path. Windows'
    /// `Path::is_absolute` requires a drive letter or UNC prefix, so the same
    /// string does not qualify there — this module is a macOS mechanism and
    /// only pins the Unix side (Windows CI runs `cargo test --workspace`, where
    /// that assertion is false on Win32).
    #[cfg(unix)]
    #[test]
    fn resolver_root_is_absolute_on_unix() {
        assert!(Path::new(RESOLVER_ROOT).is_absolute());
    }
}
