//! Windows full uninstall planning layer
//! ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)).
//!
//! This module contains **pure planning only**: it renders Meshlet's own
//! uninstall steps into controlled commands already defined and already
//! classified by existing modules, and executes nothing. The plan layer
//! compiles and unit-tests on any platform. The execution layer reuses the
//! three real-machine-verified exec thin wrappers (routes/service/firewall;
//! 2026-10-26 Chinese Windows Server: the reentrant uninstall-chain
//! integration test `windows_cleanup_e2e` is closed loop); TODO #52 stays
//! unchecked: wiring up [crate::SystemBackend] still requires full acceptance,
//! and non-Linux platforms keep the explicit placeholder of
//! [crate::unsupported] (§10.3, §12.2).
//!
//! Same discipline as [windows_service](windows_service),
//! [windows_routes](windows_routes), [windows_firewall](windows_firewall):
//!
//! - **controlled commands**: only reuse existing pub command constructors
//!   (`sc` service stop/delete, `netsh interface ipv4 delete route`,
//!   `netsh advfirewall firewall delete rule`), never free-form text;
//!   service/interface/rule names containing spaces stay a single argv token;
//! - **deterministic order**: fixed as service stop → service delete → route
//!   delete one by one for the known prefixes → firewall delete one by one for
//!   the Meshlet managed rule names;
//! - **cleanable failures**: the per-step "target already absent = skippable
//!   on re-entry" verdict only calls the absent classification functions the
//!   corresponding module already has; the classification logic is not
//!   reimplemented here;
//! - **ownership boundary**: accepts only explicitly listed Meshlet services,
//!   known prefixes, and managed rule names — never scans or cleans the
//!   machine-global service/route/firewall tables.

use std::path::PathBuf;

use meshlet_domain::Ipv4Cidr;

use crate::windows_firewall::{firewall_rule_already_absent, FirewallRuleCommand};
use crate::windows_routes::{route_already_absent, NetshRouteCommand};
use crate::windows_service::{service_absent, ServiceCommand};
use crate::NetworkError;

/// Input plan for the full uninstall (describes only Meshlet-owned objects,
/// not machine-global state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupPlan {
    /// Managed service name; Stop first, then Delete. Missing counts as success
    /// for both steps.
    pub service_name: String,
    /// This device's WireGuard tunnel interface; used to delete routes only when
    /// `route_prefixes` is non-empty.
    pub route_interface: String,
    /// On-link prefixes known to be carried by this interface, deleted one by
    /// one; an empty list produces no route steps.
    pub route_prefixes: Vec<Ipv4Cidr>,
    /// Meshlet managed firewall rule names; deleted one by one in input order.
    pub firewall_rule_names: Vec<String>,
    /// Temporary files written by Meshlet; deleted one by one in input order.
    pub temp_files: Vec<PathBuf>,
    /// Meshlet private key files; deleted one by one in input order, never by
    /// directory scanning.
    pub key_material_files: Vec<PathBuf>,
}

impl CleanupPlan {
    /// Controlled uninstall command sequence; order and argument shapes can be
    /// asserted deterministically on any platform.
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

/// One planned uninstall command.
///
/// This enum only wraps the plan commands of existing modules and introduces no
/// new command syntax; an executor can walk this sequence directly and dispatch
/// by wrapped type to each module's existing execution entry points (the
/// execution layer is not implemented in this round).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CleanupCommand {
    /// `sc stop/delete <service>`; skipped as an idempotent success when the
    /// service does not exist.
    Service(ServiceCommand),
    /// `netsh interface ipv4 delete route ... store=active`; skipped when the
    /// prefix does not exist.
    Route(NetshRouteCommand),
    /// `netsh advfirewall firewall delete rule name=...`; skipped when the rule
    /// does not exist.
    Firewall(FirewallRuleCommand),
    /// Deletes one explicitly listed temporary or private key file.
    File(CleanupFileCommand),
}

/// Object category of a file cleanup; the category only affects audit
/// semantics and never widens the deletion scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupFileKind {
    Temporary,
    KeyMaterial,
}

/// One controlled file deletion; the target must be explicitly listed in the
/// uninstall plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupFileCommand {
    pub path: PathBuf,
    pub kind: CleanupFileKind,
}

impl CleanupCommand {
    /// Process arguments (reuses the existing modules' `args()`; no program
    /// name — the execution layer decides that).
    pub fn args(&self) -> Vec<String> {
        match self {
            CleanupCommand::Service(command) => command.args(),
            CleanupCommand::Route(command) => command.args(),
            CleanupCommand::Firewall(command) => command.args(),
            CleanupCommand::File(command) => command.args(),
        }
    }

    /// Operation name (reuses the existing modules' operation names so error
    /// messages do not drift).
    pub fn operation(&self) -> &'static str {
        match self {
            CleanupCommand::Service(command) => command.operation(),
            CleanupCommand::Route(command) => command.operation(),
            CleanupCommand::Firewall(command) => command.operation(),
            CleanupCommand::File(command) => command.operation(),
        }
    }

    /// Whether a missing target object is skippable on re-entry.
    ///
    /// This function does no text classification itself: the sc/netsh absent
    /// verdicts stay in the three authoritative modules [windows_service] /
    /// [windows_routes] / [windows_firewall].
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
    /// Operation name for auditing; file cleanup has no external process
    /// arguments.
    pub fn args(&self) -> Vec<String> {
        vec![self.path.display().to_string()]
    }

    /// Operation name for auditing.
    pub fn operation(&self) -> &'static str {
        match self.kind {
            CleanupFileKind::Temporary => "cleanup temporary file",
            CleanupFileKind::KeyMaterial => "cleanup key material file",
        }
    }

    /// Deletes the explicitly listed file; returns `Ok(false)` when missing so
    /// uninstall re-entry keeps working.
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

/// Execution layer (`#[cfg(windows)]`): service/route/firewall reuse the
/// existing thin wrappers; file cleanup uses controlled cross-platform std
/// APIs and deletes only paths explicitly listed in the plan.
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{CleanupCommand, CleanupFileCommand};
    use crate::windows_firewall::exec::run_firewall_command;
    use crate::windows_routes::exec::run_route_command;
    use crate::windows_service::exec::run_service_command;
    use crate::{ApplyResult, NetworkError};

    /// Runs one full-uninstall plan command: success / idempotent success /
    /// classified failure.
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
