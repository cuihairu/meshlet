//! meshlet CLI command catalog — **single source of truth** for the command
//! surface (R-TRAY-1).
//!
//! Both the CLI (`apps/cli` — help + dispatch) and the tray settings "commands"
//! zone (`apps/tray-app`) consume this table, so adding a command updates every
//! surface at once and `meshlet --help` can never drift from the catalog (the
//! help text is generated *from* this table).

use serde::Serialize;

/// One CLI command entry. `name` is the invocation without the binary prefix
/// (e.g. `agent diag`); `args` are extra tokens for a copyable command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CommandSpec {
    pub name: &'static str,
    /// Group: [`GROUP_CONNECTION`] | [`GROUP_DIAGNOSTICS`] | [`GROUP_CONFIG`]
    /// | [`GROUP_SERVICE`]. The tray "commands" zone groups by this key.
    pub group: &'static str,
    /// One-line purpose (shown in help and the tray commands zone).
    pub summary: &'static str,
    /// Extra argument tokens, e.g. `["--peers"]`; empty = bare command.
    pub args: &'static [&'static str],
}

pub const GROUP_CONNECTION: &str = "connection";
pub const GROUP_DIAGNOSTICS: &str = "diagnostics";
pub const GROUP_CONFIG: &str = "config";
pub const GROUP_SERVICE: &str = "service";

/// The full command surface. Keep in sync with `apps/cli/src/main.rs` dispatch;
/// the reconcile test in the CLI crate guards that (and the generated help).
pub const COMMANDS: &[CommandSpec] = &[
    CommandSpec {
        name: "info",
        group: GROUP_CONNECTION,
        summary: "Show device info (name, IP, status)",
        args: &[],
    },
    CommandSpec {
        name: "status",
        group: GROUP_CONNECTION,
        summary: "Show agent status",
        args: &[],
    },
    CommandSpec {
        name: "peers",
        group: GROUP_DIAGNOSTICS,
        summary: "List direct peers (IP/mode/RTT/endpoint/traffic)",
        args: &[],
    },
    CommandSpec {
        name: "peer dial",
        group: GROUP_CONNECTION,
        summary: "Force a direct connection to a node (by name or IP)",
        args: &[],
    },
    CommandSpec {
        name: "agent diag",
        group: GROUP_DIAGNOSTICS,
        summary: "Show network diagnostics snapshot (routes/interfaces/wg)",
        args: &[],
    },
    CommandSpec {
        name: "agent diag",
        group: GROUP_DIAGNOSTICS,
        summary: "Append direct peers table to the snapshot",
        args: &["--peers"],
    },
    CommandSpec {
        name: "networks",
        group: GROUP_CONFIG,
        summary: "List subnets/routes",
        args: &[],
    },
    CommandSpec {
        name: "config",
        group: GROUP_CONFIG,
        summary: "Show configuration",
        args: &[],
    },
    CommandSpec {
        name: "task assign",
        group: GROUP_CONFIG,
        summary: "Dispatch a task to a device (needs --network/--node/--cmd)",
        args: &[],
    },
    CommandSpec {
        name: "task ls",
        group: GROUP_CONFIG,
        summary: "List tasks in a network (--network)",
        args: &[],
    },
    CommandSpec {
        name: "task confirm",
        group: GROUP_CONFIG,
        summary: "Confirm a done task (user-side, --network <id>)",
        args: &[],
    },
    CommandSpec {
        name: "task retry",
        group: GROUP_CONFIG,
        summary: "Reject and rerun a task (--network <id>)",
        args: &[],
    },
    CommandSpec {
        name: "version",
        group: GROUP_SERVICE,
        summary: "Show version",
        args: &[],
    },
    CommandSpec {
        name: "help",
        group: GROUP_SERVICE,
        summary: "Show this help",
        args: &[],
    },
];

/// Render the `meshlet --help` body from the catalog. The CLI prints exactly
/// this string, so help and catalog are the same source by construction.
pub fn usage_text(version: &str) -> String {
    let mut out = format!("meshlet-cli {version}\n\nUsage: meshlet <command>\n\nCommands:\n");
    // Column width covers the longest name+args line ("agent diag --peers").
    let width = COMMANDS
        .iter()
        .map(|c| c.name.len() + c.args.iter().map(|a| a.len() + 1).sum::<usize>())
        .max()
        .unwrap_or(0);
    for c in COMMANDS {
        let mut line = c.name.to_string();
        for a in c.args {
            line.push(' ');
            line.push_str(a);
        }
        out.push_str(&format!("  {line:<width$}  {}\n", c.summary));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usage_includes_every_catalog_command() {
        let help = usage_text("0.1.0");
        assert!(help.contains("meshlet-cli 0.1.0"));
        for c in COMMANDS {
            assert!(help.contains(c.name), "{} missing from help", c.name);
            assert!(help.contains(c.summary), "{} summary missing", c.name);
        }
        // The --peers variant renders with its argument.
        assert!(help.contains("agent diag --peers"));
    }

    #[test]
    fn groups_are_stable_keys() {
        let groups: std::collections::BTreeSet<_> = COMMANDS.iter().map(|c| c.group).collect();
        for g in [
            GROUP_CONNECTION,
            GROUP_DIAGNOSTICS,
            GROUP_CONFIG,
            GROUP_SERVICE,
        ] {
            assert!(groups.contains(g), "missing group {g}");
        }
    }
}
