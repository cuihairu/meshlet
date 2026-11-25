//! The Windows route plan layer ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)).
//!
//! This module is **pure planning** (the same pattern as the
//! [nat](../../../crates/meshlet-network/src/nat.rs) module): the argument
//! construction for netsh route commands, the parsing of the `show route`
//! output, and the classification of failure texts — no command is ever run.
//! The plan-layer functions compile and unit-test on any platform (the Linux
//! side of this repo's CI already runs green).
//!
//! The execution layer is the [exec] submodule, which under `#[cfg(windows)]`
//! only calls this module's plan functions. Real-machine verification
//! (2026-10-16 CI runner en-US; 2026-10-26 a zh-CN Windows Server machine):
//! the whole chain of add / show read-back / delete / idempotent re-delete works,
//! and the localized output is decoded through
//! [windows_console](crate::windows_console) before classification closes the
//! loop.
//! TODO #52 stays unchecked: wiring up [crate::SystemBackend] is still gated on
//! full acceptance (the full wireguardnt tunnel lifecycle, see ADR-008);
//! non-Linux platforms keep the explicit placeholder of
//! [unsupported](../../../crates/meshlet-network/src/unsupported.rs) and never
//! pretend to have a data plane (§10.3, §12.2).
//!
//! ADR-008's tradeoffs land in this module as three things:
//!
//! - **Controlled commands**: only the named-argument form of
//!   `netsh interface ipv4 add/delete route` is constructed
//!   (`prefix=` / `interface=` / `nexthop=` / `store=active`); no free text is
//!   concatenated. An interface name containing spaces (WireGuard tunnel names
//!   allow spaces) stays a single argv token, and command-line quoting is left
//!   to the process builder (see the field-tested note on [named_value]);
//! - **Clear privilege messages**: `requires elevation` / `access is denied`
//!   texts map to [`NetworkError::InsufficientPrivileges`], with the message
//!   naming the operation and the interface;
//! - **Cleanable failures**: deleting a route that does not exist
//!   (`element not found` and the like) counts as an idempotent success;
//!   an unknown failure text fails closed as
//!   [`NetworkError::ApplyRejected`] carrying the raw netsh line.
//!
//! `store=active` (non-persistent) matches the agent reconciliation model: no
//! routes survive a reboot, and drift is corrected by the agent replay (see
//! ADR-009 for the reboot replay semantics).

use std::net::Ipv4Addr;

use meshlet_domain::Ipv4Cidr;

use crate::{NetworkError, RouteConfig};

/// One controlled netsh route command (plan state; execution in [exec]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetshRouteCommand {
    /// Add a route (`gateway = None` is an on-link route, without `nexthop=`).
    Add { route: RouteConfig },
    /// Delete a route; a missing target counts as an idempotent success
    /// (cleanable failure).
    Delete {
        destination: Ipv4Cidr,
        interface: String,
        gateway: Option<Ipv4Addr>,
    },
}

impl NetshRouteCommand {
    /// The netsh arguments (including the `interface ipv4 add/delete route`
    /// prefix; unit tests and the execution layer share the same construction,
    /// so the plan and the execution never drift — the same discipline as
    /// [nat::NatRule::iptables_args](../../../crates/meshlet-network/src/nat.rs)).
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["interface".into(), "ipv4".into()];
        let (verb, destination, interface, gateway) = match self {
            NetshRouteCommand::Add { route } => {
                ("add", route.destination, &route.interface, route.gateway)
            }
            NetshRouteCommand::Delete {
                destination,
                interface,
                gateway,
            } => ("delete", *destination, interface, *gateway),
        };
        args.push(verb.into());
        args.push("route".into());
        args.push(format!("prefix={destination}"));
        args.push(named_value("interface", interface));
        if let Some(gateway) = gateway {
            args.push(format!("nexthop={gateway}"));
        }
        // store=active: routes are not persistent across reboots (the agent
        // replay reconciles them back, ADR-009).
        args.push("store=active".into());
        args
    }

    /// The operation name (used to name it in error messages).
    pub fn operation(&self) -> &'static str {
        match self {
            NetshRouteCommand::Add { .. } => "route add",
            NetshRouteCommand::Delete { .. } => "route delete",
        }
    }

    /// The managed interface name (used to name it in error messages).
    pub fn interface(&self) -> &str {
        match self {
            NetshRouteCommand::Add { route } => &route.interface,
            NetshRouteCommand::Delete { interface, .. } => interface,
        }
    }

    pub fn is_delete(&self) -> bool {
        matches!(self, NetshRouteCommand::Delete { .. })
    }
}

/// A netsh named argument in `key=value` form; **the whole key-value pair is a
/// single argv token** (an interface name containing spaces is not split into
/// words: `interface=Meshlet Office` is one token).
///
/// Deliberately **no embedded quotes** (the 2026-10-16 CI runner field-test
/// message): netsh's own tokenizer does not understand `\"` escapes — embedded
/// quotes would shred `interface="…"`, landing `Loopback` on the
/// `siteprefixlength` slot (`Invalid siteprefixlength parameter (Loopback)`).
/// Quoting at the command-line level is the process builder's job: std
/// `Command::args` automatically quotes a token containing spaces as a whole,
/// and netsh accepts quotes wrapping the entire key-value pair.
fn named_value(key: &str, value: &str) -> String {
    format!("{key}={value}")
}

/// Modifying a route = **delete and rebuild** (the same idiom as the control
/// plane routes: no PATCH, modify = delete and rebuild). netsh has no
/// `set route`; semantically it is deleting the old prefix then creating the new
/// prefix, each step being one controlled call.
pub fn replace_route_commands(old: &RouteConfig, new: &RouteConfig) -> Vec<NetshRouteCommand> {
    vec![
        NetshRouteCommand::Delete {
            destination: old.destination,
            interface: old.interface.clone(),
            gateway: old.gateway,
        },
        NetshRouteCommand::Add { route: new.clone() },
    ]
}

/// Classify the netsh exit code and output into a backend error (a pure
/// function, unit-tested on any platform).
///
/// Privilege-class texts are **deliberately matched broadly**
/// (case-insensitive substrings): Windows versions disagree on the exact wording
/// for ERROR_ELEVATION_REQUIRED (740) and ERROR_ACCESS_DENIED (5). It is better
/// to put an ambiguous privilege failure under "insufficient privileges" (a
/// clear message) than to misreport a privilege problem as some other cause.
/// Any other failure fails closed as [`NetworkError::ApplyRejected`]
/// (unknown does not mean success, §8.3).
pub fn classify_netsh_route_failure(
    exit_code: i32,
    output: &str,
    operation: &str,
    interface: &str,
) -> NetworkError {
    let lowered = output.to_lowercase();
    if lowered.contains("requires elevation")
        || lowered.contains("access is denied")
        // The standard zh-CN localized texts (real-machine forensics: the
        // zh-CN wording of ERROR_ELEVATION_REQUIRED is "the requested operation
        // requires elevation (running as administrator)", and
        // ERROR_ACCESS_DENIED is "access denied"). The broad-match discipline
        // holds: better to land in the privilege class than to misreport.
        || output.contains("需要提升")
        || output.contains("拒绝访问")
    {
        return NetworkError::InsufficientPrivileges(format!(
            "netsh {operation} on interface `{interface}` requires administrator \
             privileges (run from an elevated shell); netsh said: {}",
            first_nonempty_line(output)
        ));
    }
    NetworkError::ApplyRejected(format!(
        "netsh {operation} on interface `{interface}` failed (exit {exit_code}): {}",
        first_nonempty_line(output)
    ))
}

/// A netsh delete reporting "the target does not exist" = an idempotent
/// success (a cleanup path reaching an empty state is not a failure; §10.3
/// cleanable failures). Also matched broadly by substring to cover wording
/// differences across versions.
pub fn route_already_absent(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("element not found")
        || lowered.contains("cannot find")
        // zh-CN real-machine forensics (2026-10-25, decoded from CP936): the
        // full netsh message for deleting a non-existent route is the zh-CN
        // localized "element not found" — matched as the localized original.
        || output.contains("找不到元素")
}

/// The first non-empty line of the output (error messages carry the raw netsh
/// text for diagnostics).
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// Parse the tabular output of `netsh interface ipv4 show route`, keeping the
/// IPv4 prefixes that **land on the given interface** (for reconciliation: the
/// reading source of the Windows-side `installed_routes`).
///
/// The judgment runs per line: the only token in the line parseable as
/// [Ipv4Cidr] is the prefix column, and the trailing token sequence equals the
/// interface-name token sequence (the interface name may contain spaces, such
/// as `Loopback Pseudo-Interface 1`). IPv6 lines (`::/0` etc.) fail to parse and
/// are skipped naturally; header/divider lines carry no CIDR token and are
/// skipped naturally.
pub fn route_prefixes_on_interface(output: &str, interface: &str) -> Vec<Ipv4Cidr> {
    let name: Vec<&str> = interface.split_whitespace().collect();
    output
        .lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let prefix = tokens.iter().find_map(|t| t.parse::<Ipv4Cidr>().ok())?;
            let trailing = tokens.len().saturating_sub(name.len());
            (tokens.get(trailing..)? == name.as_slice()).then_some(prefix)
        })
        .collect()
}

/// The execution layer (`#[cfg(windows)]`): it only hands the arguments built
/// by the plan functions to netsh and hands the output back to the plan layer
/// for classification; nothing else.
///
/// Real-machine tests: 2026-10-16 CI runner (en-US) and 2026-10-26 a zh-CN
/// Windows Server machine — the whole chain of add / show read-back / delete /
/// idempotent re-delete works, and the localized (zh-CN) output is decoded
/// through [crate::windows_console] before classification closes the loop.
/// TODO #52 stays unchecked: wiring up [crate::SystemBackend] is still gated on
/// full acceptance (the full wireguardnt tunnel lifecycle and the elevation
/// path, see ADR-008).
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_netsh_route_failure, route_already_absent, NetshRouteCommand};
    use crate::windows_console::NoWindowCommand;
    use crate::{ApplyResult, NetworkError};

    /// Run one controlled netsh route command: success / idempotent success /
    /// classified failure, three states.
    pub fn run_route_command(command: &NetshRouteCommand) -> Result<ApplyResult, NetworkError> {
        let output = std::process::Command::new("netsh")
            .args(command.args())
            .no_window()
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn netsh: {error}")))?;
        // netsh's redirected output is encoded in the active code page (a
        // zh-CN real machine yields GBK); decode as UTF-8 first with a CP_ACP
        // fallback, see [windows_console].
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if output.status.success() {
            return Ok(ApplyResult::ok());
        }
        // Deleting an already-absent target = an idempotent success (a cleanup
        // path reaching an empty state is not a failure).
        if command.is_delete() && route_already_absent(&text) {
            return Ok(ApplyResult::ok());
        }
        Err(classify_netsh_route_failure(
            output.status.code().unwrap_or(-1),
            &text,
            command.operation(),
            command.interface(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(interface: &str, gateway: Option<Ipv4Addr>) -> RouteConfig {
        RouteConfig {
            destination: "10.241.1.0/24".parse().unwrap(),
            interface: interface.into(),
            gateway,
        }
    }

    /// The named-argument form plus store=active; a route with a gateway carries
    /// nexthop=.
    #[test]
    fn add_route_renders_named_netsh_form_with_gateway() {
        let command = NetshRouteCommand::Add {
            route: route("meshlet", Some("10.240.0.4".parse().unwrap())),
        };
        assert_eq!(
            command.args(),
            vec![
                "interface",
                "ipv4",
                "add",
                "route",
                "prefix=10.241.1.0/24",
                "interface=meshlet",
                "nexthop=10.240.0.4",
                "store=active",
            ]
        );
    }

    /// An on-link route (no gateway) produces no nexthop= token.
    #[test]
    fn add_route_without_gateway_is_on_link() {
        let command = NetshRouteCommand::Add {
            route: route("meshlet", None),
        };
        let args = command.args();
        assert_eq!(
            args[..4],
            [
                "interface".to_string(),
                "ipv4".into(),
                "add".into(),
                "route".into()
            ]
        );
        assert!(!args.iter().any(|a| a.starts_with("nexthop=")));
        assert_eq!(args.last().unwrap(), "store=active");
    }

    /// Delete and add share the same named-argument form (only the verb
    /// differs).
    #[test]
    fn delete_route_renders_named_netsh_form() {
        let command = NetshRouteCommand::Delete {
            destination: "10.241.1.0/24".parse().unwrap(),
            interface: "meshlet".into(),
            gateway: Some("10.240.0.4".parse().unwrap()),
        };
        assert_eq!(
            command.args(),
            vec![
                "interface",
                "ipv4",
                "delete",
                "route",
                "prefix=10.241.1.0/24",
                "interface=meshlet",
                "nexthop=10.240.0.4",
                "store=active",
            ]
        );
        assert_eq!(command.operation(), "route delete");
        assert!(command.is_delete());
    }

    /// When the interface name contains spaces (allowed for WireGuard tunnel
    /// names), the **key-value pair stays a single token with no embedded
    /// quotes** — command-line quoting is added by the process builder; netsh's
    /// tokenizer does not understand `\"` escapes
    /// (see the named_value note for the runner field-test message).
    #[test]
    fn interface_names_with_spaces_stay_one_unquoted_arg() {
        let command = NetshRouteCommand::Add {
            route: route("Meshlet Office", None),
        };
        let args = command.args();
        assert!(args.contains(&"interface=Meshlet Office".to_string()));
        assert!(!args.iter().any(|a| a.contains('"')));
        let plain = NetshRouteCommand::Add {
            route: route("meshlet", None),
        };
        assert!(plain.args().contains(&"interface=meshlet".to_string()));
    }

    /// Modify = delete and rebuild, in a fixed order (delete the old prefix
    /// first, then create the new one).
    #[test]
    fn replace_is_delete_then_add_in_order() {
        let old = route("meshlet", Some("10.240.0.4".parse().unwrap()));
        let new = RouteConfig {
            destination: "10.242.1.0/24".parse().unwrap(),
            interface: "meshlet".into(),
            gateway: Some("10.240.0.5".parse().unwrap()),
        };
        assert_eq!(
            replace_route_commands(&old, &new),
            vec![
                NetshRouteCommand::Delete {
                    destination: old.destination,
                    interface: old.interface.clone(),
                    gateway: old.gateway,
                },
                NetshRouteCommand::Add { route: new.clone() },
            ]
        );
    }

    /// "Clear privilege messages": an elevation text -> InsufficientPrivileges,
    /// with the message naming the operation and the interface and carrying the
    /// raw netsh text (the administrator hint is actionable).
    #[test]
    fn elevation_failure_maps_to_insufficient_privileges_naming_operation_and_interface() {
        let error = classify_netsh_route_failure(
            1,
            "The requested operation requires elevation.",
            "route add",
            "meshlet",
        );
        match error {
            NetworkError::InsufficientPrivileges(detail) => {
                assert!(detail.contains("route add"), "{detail}");
                assert!(detail.contains("meshlet"), "{detail}");
                assert!(detail.contains("administrator"), "{detail}");
                assert!(detail.contains("requires elevation"), "{detail}");
            }
            other => panic!("elevation must map to InsufficientPrivileges, got {other:?}"),
        }
    }

    /// Access denied lands in the privilege class together with elevation
    /// (a case-insensitive broad substring match).
    #[test]
    fn access_denied_also_maps_to_insufficient_privileges() {
        let error = classify_netsh_route_failure(1, "Access is denied.", "route delete", "meshlet");
        assert!(matches!(error, NetworkError::InsufficientPrivileges(_)));
    }

    /// An unknown failure text fails closed as ApplyRejected: it carries the
    /// operation, the interface, the exit code, and the raw netsh line
    /// (unknown does not mean success, §8.3).
    #[test]
    fn unknown_failure_fails_closed_as_rejection_with_raw_line() {
        let error = classify_netsh_route_failure(
            1,
            "\r\nThe parameter is incorrect.\r\n",
            "route add",
            "meshlet",
        );
        match error {
            NetworkError::ApplyRejected(detail) => {
                assert!(detail.contains("route add"), "{detail}");
                assert!(detail.contains("meshlet"), "{detail}");
                assert!(detail.contains("exit 1"), "{detail}");
                assert!(detail.contains("The parameter is incorrect."), "{detail}");
            }
            other => panic!("unknown text must fail closed, got {other:?}"),
        }
    }

    /// "Cleanable failures": deleting a target that does not exist counts as an
    /// idempotent success — matched broadly across version wordings.
    #[test]
    fn absent_route_output_counts_as_idempotent_delete() {
        assert!(route_already_absent("Element not found."));
        assert!(route_already_absent(
            "The system cannot find the file specified."
        ));
        assert!(!route_already_absent("Ok."));
        assert!(!route_already_absent(""));
    }

    /// zh-CN real-machine forensics (2026-10-25): the zh-CN Windows absent
    /// message hits the idempotent judgment as its original text (the
    /// real-machine failure in the `windows_netsh` integration test went red
    /// exactly here).
    #[test]
    fn localized_absence_output_counts_as_idempotent_delete() {
        assert!(route_already_absent("找不到元素。"));
    }

    /// zh-CN real-machine forensics: localized privilege texts land in the
    /// privilege class and are never misreported as ApplyRejected.
    #[test]
    fn localized_privilege_text_maps_to_insufficient_privileges() {
        assert!(matches!(
            classify_netsh_route_failure(
                1,
                "请求的操作需要提升(作为管理员运行)。",
                "route add",
                "meshlet"
            ),
            NetworkError::InsufficientPrivileges(_)
        ));
        assert!(matches!(
            classify_netsh_route_failure(1, "拒绝访问。", "route add", "meshlet"),
            NetworkError::InsufficientPrivileges(_)
        ));
    }

    /// The `show route` tabular output filters prefixes by interface: header /
    /// divider lines and IPv6 lines are skipped naturally, and the interface name
    /// may contain spaces (a trailing token sequence match).
    #[test]
    fn show_route_output_scopes_prefixes_to_the_interface() {
        let output = "\
Publish  Type      Met   Prefix                    Idx  Gateway/Interface Name
-------  --------  ----  ------------------------  ---  ------------------------
No       System    256   127.0.0.0/8                1   Loopback Pseudo-Interface 1
No       System    0     ::/0                      17  meshlet
No       Manual    0     10.241.1.0/24             17  10.240.0.4 meshlet
No       Manual    0     10.242.1.0/24             12  10.240.0.9 Meshlet Office
";
        assert_eq!(
            route_prefixes_on_interface(output, "meshlet"),
            vec![
                "10.241.1.0/24".parse::<Ipv4Cidr>().unwrap(),
                // ::/0 cannot parse into an IPv4 CIDR and is skipped naturally.
            ]
        );
        assert_eq!(
            route_prefixes_on_interface(output, "Meshlet Office"),
            vec!["10.242.1.0/24".parse::<Ipv4Cidr>().unwrap()]
        );
        assert!(route_prefixes_on_interface(output, "unknown-if").is_empty());
    }
}
