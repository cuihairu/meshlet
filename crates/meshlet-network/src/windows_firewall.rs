//! Windows firewall plan layer ([ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)).
//!
//! This module contains **pure planning** plus a `#[cfg(windows)]` execution
//! layer: argument construction for `netsh advfirewall firewall add/delete
//! rule`, failure text classification, and controlled execution. Plan-layer
//! functions compile and unit-test on any platform (the Linux side of this
//! repo's CI runs green); the execution layer was verified on a real machine
//! (2026-10-26, Chinese Windows Server): add / show read-back / delete /
//! idempotent re-delete all ran end to end. Until full acceptance, Windows
//! still keeps the explicit [crate::unsupported] placeholder and is not wired
//! into [crate::SystemBackend].
//!
//! Same discipline as [windows_routes](../../../crates/meshlet-network/src/windows_routes.rs):
//!
//! - **Controlled commands**: only `name=` / `dir=` / `action=` / `protocol=` /
//!   `localport=` / `remoteport=` / `profile=`-style named arguments are
//!   constructed; a `key=value` pair stays a single argv token, so a rule
//!   name containing spaces (such as `Meshlet WireGuard`) is not split into
//!   words and carries **no embedded quotes** (see the measured notes on
//!   netsh quoting semantics in [windows_routes]);
//! - **Determinism**: Add field order is fixed; multi-value profile is fixed
//!   to `domain,private,public`, duplicate values are deduplicated, and `any`
//!   is used when nothing is supplied explicitly;
//! - **fail closed**: wide matching on permission text maps to
//!   [`NetworkError::InsufficientPrivileges`]; the text for deleting a rule
//!   that no longer exists counts as idempotent success; any other unknown
//!   failure becomes [`NetworkError::ApplyRejected`] carrying the first line
//!   of the original netsh output.

use crate::NetworkError;

/// Firewall rule direction (the controlled values for netsh `dir=`).
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

/// Firewall rule action (the controlled values for netsh `action=`).
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

/// Controlled protocols; `Any` is netsh's default semantics, rendered
/// explicitly to keep the argument shape from drifting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallProtocol {
    Any,
    Tcp,
    Udp,
    /// ICMPv4 echo (echo request, type 8 / any code): mesh neighbor
    /// reachability probing depends on it — once Windows classifies the wg
    /// interface as the Public category the default inbound policy blocks
    /// ICMP (2026-10-30 in practice: dev->win did not go through until a
    /// Meshlet-ICMPv4-In rule was created by hand). netsh expresses it as
    /// `protocol=icmpv4:8,any`; ICMP has no ports, so [FirewallRule]'s port
    /// tokens are omitted for [FirewallProtocol::IcmpV4].
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

/// Firewall profiles; render order is fixed and matches netsh's common
/// spelling.
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

/// Controlled rule description. The plan layer renders it from typed
/// fields; the control plane cannot inject arbitrary argv.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub name: String,
    pub direction: FirewallDirection,
    pub action: FirewallAction,
    pub protocol: FirewallProtocol,
    /// netsh port tokens (e.g. `51820`, `5000-5010`, or `any`); kept as
    /// strings to fully cover Windows's range/list syntax, and still passed
    /// as a single argv by the execution layer.
    pub local_port: String,
    pub remote_port: String,
    /// `None` renders as `profile=any`; with values the order is fixed
    /// domain/private/public.
    pub profiles: Option<Vec<FirewallProfile>>,
    /// netsh `description=`; optional in the rule plan, and the argument is
    /// omitted when so.
    pub description: Option<String>,
    /// netsh `localip=`; mesh reachability rules use it to **restrict the
    /// allowance to the wg interface address** (netsh cannot restrict per
    /// interface, and `localip=<device overlay address>` is the equivalent
    /// with a security boundary: only packets destined for that mesh address
    /// match). `None` = omit.
    pub local_ip: Option<std::net::Ipv4Addr>,
}

/// A controlled netsh firewall command (planned form; execution in [exec]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallRuleCommand {
    Add { rule: FirewallRule },
    Delete { name: String },
}

impl FirewallRuleCommand {
    /// netsh arguments (including the `advfirewall firewall add/delete rule`
    /// prefix; the plan and the future execution layer share the same
    /// construction to avoid argument drift).
    pub fn args(&self) -> Vec<String> {
        let mut args = vec!["advfirewall".into(), "firewall".into()];
        match self {
            FirewallRuleCommand::Add { rule } => {
                args.extend(["add".into(), "rule".into()]);
                args.push(named_value("name", &rule.name));
                args.push(format!("dir={}", rule.direction.as_str()));
                args.push(format!("action={}", rule.action.as_str()));
                args.push(format!("protocol={}", rule.protocol.as_str()));
                // ICMPv4 has no concept of ports: omit localport/remoteport
                // for `icmpv4:8,any` (netsh does not accept port tokens with
                // an ICMP protocol).
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

    /// Operation name (used to name things in error messages).
    pub fn operation(&self) -> &'static str {
        match self {
            FirewallRuleCommand::Add { .. } => "firewall rule add",
            FirewallRuleCommand::Delete { .. } => "firewall rule delete",
        }
    }

    /// Managed rule name (used to name things in error messages).
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

/// Mesh reachability safeguard commands (AGENT-FW-1).
///
/// Background (2026-10-30 in practice): Windows classifies the wg interface
/// as the **Public** category, whose default inbound policy blocks ICMP —
/// the dev->win wg tunnel handshake worked but ping did not, until a
/// `Meshlet-ICMPv4-In` rule was created by hand. Root-cause fix = set the
/// interface's network category to **Private** (the Private category allows
/// ICMP by default) plus an explicit inbound ICMPv4 allow rule as a second
/// line of defense.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshFirewallCommand {
    /// `Set-NetConnectionProfile -InterfaceAlias <if> -NetworkCategory Private`.
    ///
    /// PowerShell rather than netsh: NetworkCategory is a **network
    /// category** property and netsh has no matching subcommand; the set
    /// semantics are naturally idempotent (setting Private on an already
    /// Private connection still succeeds).
    SetNetworkCategoryPrivate { interface: String },
    /// `netsh advfirewall firewall add rule`: allow inbound ICMP for
    /// `Meshlet-ICMPv4-In`, restricted to the device overlay address (see
    /// [mesh_icmp_rule]); idempotency comes from the caller probing
    /// [firewall_rule_present] first and deciding whether to issue it.
    AddIcmpRule { rule: FirewallRule },
    /// `netsh advfirewall firewall delete rule`: delete the ICMP rule with
    /// this name. Leftovers from an address change or a disabled stale rule
    /// are deleted then recreated (audit finding #1); netsh delete removes
    /// every rule with that name, so exactly one remains after the rebuild.
    DeleteIcmpRule { name: String },
}

impl MeshFirewallCommand {
    /// Build the category command after validating the interface name
    /// (quotes and whitespace are rejected to prevent `-Command`
    /// injection).
    pub fn set_network_category_private(interface: &str) -> Result<Self, NetworkError> {
        validate_tunnel_interface(interface)?;
        Ok(Self::SetNetworkCategoryPrivate {
            interface: interface.into(),
        })
    }

    /// argv (without the program name): the category command goes through
    /// `powershell`, ICMP rules through `netsh`.
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

    /// Whether this command goes through netsh (otherwise PowerShell).
    pub fn uses_netsh(&self) -> bool {
        matches!(self, Self::AddIcmpRule { .. } | Self::DeleteIcmpRule { .. })
    }
}

/// Validate a managed tunnel interface name: the Windows tunnel name
/// character set (`wg-meshlet`), rejecting quotes and whitespace — the
/// interface name goes into a PowerShell single-quoted string, so this is
/// injection defense.
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

/// Name of the direct-connect UDP allow rule (batch 4 Windows wiring). The
/// fixed name is half of the idempotency probe:
/// `netsh advfirewall firewall show rule name=<this name>` plus a port
/// cross-check.
pub const DIRECT_UDP_RULE_NAME: &str = "Meshlet-Direct-UDP-In";

/// Inbound allow rule for the direct-connect UDP port (P2P §12, batch 4,
/// Windows side): inbound / allow / `protocol=udp` / `localport=<port>`,
/// with no profile binding (any) — the wg adapter is classified by Windows
/// as the Public category, so inbound packets of a direct-connect handshake
/// are dropped under the default inbound policy. Same discipline as
/// [mesh_icmp_rule]: controlled named arguments, and the caller probes for
/// presence before adding.
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

/// Whether the `netsh … show rule` output contains a `LocalPort` token for
/// that port. The rule name is fixed while the port is variable (after a
/// config port change the old rule is still present but the port does not
/// match): the name being present **does not** mean the port is allowed, so
/// each `LocalPort: <port>` line must be checked.
///
/// Field labels are matched in both en / zh-CN (`LocalPort`, plus the zh-CN localized label),
/// so localized output on a Chinese system is not missed, which would stack
/// another rule with the same name on every replay (2026-11-09 audit finding
/// #2).
pub fn rule_output_mentions_port(output: &str, port: u16) -> bool {
    rule_output_ports(output).contains(&port)
}

/// Every `LocalPort` value appearing in `netsh … show rule` output.
///
/// The same fixed rule name can cover several rules (a rule for the old port
/// lingers after a config port change, audit finding #3); the caller uses
/// this to detect "name present but port mismatched" and trigger a rebuild.
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

/// The LocalPort field label in `netsh advfirewall firewall show rule`
/// output. en `LocalPort`; the zh-CN localized label (localized output, audit
/// finding #2).
fn is_local_port_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("localport") || label.to_ascii_lowercase().contains("本地端口")
}

/// LocalIP field label: en `LocalIP`; the two zh-CN localized label spellings.
fn is_local_ip_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("localip")
        || label.to_ascii_lowercase().contains("本地ip")
        || label.to_ascii_lowercase().contains("本地 ip")
}

/// Enabled field label: en `Enabled`; the zh-CN localized label.
fn is_enabled_label(label: &str) -> bool {
    label.eq_ignore_ascii_case("enabled") || label.to_ascii_lowercase().contains("已启用")
}

/// Boolean field value: en `Yes`; the zh-CN localized value (`true` / `1` also accepted).
fn is_yes_value(value: &str) -> bool {
    let v = value.trim();
    v.eq_ignore_ascii_case("yes") || v.eq_ignore_ascii_case("true") || v == "是" || v == "1"
}

/// Rule block header label: en `Rule Name`; the zh-CN localized label.
fn is_rule_name_header(line: &str) -> bool {
    let t = line.trim();
    t.eq_ignore_ascii_case("rule name")
        || t.to_ascii_lowercase().starts_with("rule name:")
        || t.starts_with("规则名称")
}

/// Split `netsh … show rule name=<n>` output into rule blocks. Several rules
/// may share a name (leftover from an address change / a disabled copy, audit
/// finding #1); when no block header exists, the whole output is treated as
/// one block.
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

/// Match a LocalIP value against the device address: netsh show normalizes
/// localip into `ip/netmask` form (`127.0.0.1/255.255.255.255`), with
/// multiple addresses comma-separated — compare the IP part before `/` in
/// each token exactly (real-machine evidence in windows_firewall_live; a
/// bare address is tolerated too).
fn local_ip_value_matches(value: &str, addr: std::net::Ipv4Addr) -> bool {
    value.split(',').any(|token| {
        let ip = token.trim().split('/').next().unwrap_or("").trim();
        ip.parse::<std::net::Ipv4Addr>() == Ok(addr)
    })
}

/// Whether the ICMP rules with this name contain one that is **enabled and
/// whose localip matches the current device address**.
///
/// Audit finding #1: judging presence by name alone reports the rule as
/// satisfied after an address change or a disable, skipping creation — each
/// block must be checked for both its enabled state and its address binding.
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

/// Inbound mesh ICMP allow rule (`Meshlet-ICMPv4-In`): inbound / allow /
/// `icmpv4:8,any`, with `localip` restricted to the device overlay address —
/// netsh cannot restrict per interface, and
/// `localip=<device address>` is the equivalent with a security boundary
/// (only packets destined for that mesh address match).
pub fn mesh_icmp_rule(device_addr: std::net::Ipv4Addr) -> FirewallRule {
    FirewallRule {
        name: "Meshlet-ICMPv4-In".into(),
        direction: FirewallDirection::Inbound,
        action: FirewallAction::Allow,
        protocol: FirewallProtocol::IcmpV4,
        local_port: "any".into(),
        remote_port: "any".into(),
        profiles: None, // any: the Private category is the main fix, this rule is the second line of defense, no profile binding
        description: Some(
            "meshlet mesh reachability: inbound ICMP echo to the wg interface".into(),
        ),
        local_ip: Some(device_addr),
    }
}

/// Presence state of the ICMP rule with this name (probe -> plan,
/// AGENT-FW-1 audit finding #1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpRuleState {
    /// No rule named `Meshlet-ICMPv4-In` exists — add one directly.
    Absent,
    /// Present, enabled, and localip matches the current device address —
    /// satisfied, leave it alone.
    Satisfied,
    /// A rule with this name is present but unsatisfied (leftover from an
    /// address change / disabled) — delete then recreate; otherwise judging
    /// presence by name alone would skip creation and inbound ping to the
    /// current address would not be guaranteed.
    Stale,
}

/// Pure planning (AGENT-FW-1, unit-tested across platforms): given the
/// category and the rule state, produce the safeguard commands.
///
/// The caller probes `category_is_private` and the ICMP rule presence state
/// ([IcmpRuleState]) first; this function only performs a deterministic
/// mapping — fully idempotent (an already-satisfied state -> an empty
/// plan).
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

/// Decide whether `netsh advfirewall firewall show rule name=<name>` output
/// indicates the rule exists. Absence is reported with the zh-CN localized
/// "no rules match the specified criteria" message (evidenced on a real zh-CN machine) /
/// the English equivalent text — this
/// reuses [firewall_rule_already_absent] to detect absence.
pub fn firewall_rule_present(output: &str) -> bool {
    !output.trim().is_empty() && !firewall_rule_already_absent(output)
}

/// Decide whether `Get-NetConnectionProfile` output shows the network
/// category is already Private.
///
/// Trust only the `NetworkCategory` field (PowerShell field names do not
/// vary with UI language) or a bare-value output (the probe command only
/// takes `.NetworkCategory`); never search for `private` across the whole
/// output — a Public connection whose name/alias contains that word would
/// then be misjudged as Private and the category switch skipped
/// (2026-11-09 audit finding #4).
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
            // Other fields (Name / InterfaceAlias, etc.) are ignored to
            // avoid false hits on same-word collisions.
        } else if bare.is_none() {
            bare = Some(trimmed);
        }
    }
    bare.is_some_and(|v| v.eq_ignore_ascii_case("private"))
}

/// A netsh named argument in `key=value` form: **the whole pair is a single
/// argv token**, with no embedded quotes; command-line-level quoting is
/// handled by std's process builder.
fn named_value(key: &str, value: &str) -> String {
    format!("{key}={value}")
}

/// Render multiple profiles in a fixed order; duplicates are kept once, and
/// `any` is never mixed with concrete profiles.
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

/// Decide whether netsh delete output means "no matching rule"; wide
/// substring matching covers the differences in idempotent delete text
/// across Windows versions and languages.
pub fn firewall_rule_already_absent(output: &str) -> bool {
    let lowered = output.to_lowercase();
    lowered.contains("no rules match the specified criteria")
        || lowered.contains("rule does not exist")
        || lowered.contains("cannot find")
        // Evidenced on a real zh-CN machine (2026-10-25, after CP936
        // decoding): the full message from netsh firewall when deleting a
        // nonexistent rule is the zh-CN localized "no rules match the specified criteria".
        || output.contains("没有与指定标准相匹配的规则")
}

/// Classify netsh firewall failures: an idempotent successful delete, an
/// explicit elevation demand for privilege failures, and fail closed for
/// anything else.
///
/// `requires elevation` / `access is denied` use wide substring matching
/// (case-insensitive) to cover differences in Windows versions and
/// redirected output; the error message names the operation and the rule.
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
        // Evidenced on a real zh-CN machine: the standard zh-CN wording of
        // ERROR_ELEVATION_REQUIRED and ERROR_ACCESS_DENIED. The wide-match
        // discipline is unchanged.
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

/// The first non-empty line of the output (error messages carry the original
/// netsh text to ease diagnostics).
fn first_nonempty_line(output: &str) -> &str {
    output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("(no output)")
}

/// Execution layer (`#[cfg(windows)]`): it only hands the arguments built by
/// the plan functions to netsh and hands the output back to the plan layer
/// for classification — there is no other logic.
///
/// Verified on a real machine (2026-10-26, Chinese Windows Server): add /
/// show read-back / delete / idempotent re-delete (the zh-CN localized
/// absence text, classified after decoding through
/// [crate::windows_console]) all ran end to end. TODO #52 stays unchecked:
/// wiring into [crate::SystemBackend] still awaits full acceptance.
#[cfg(target_os = "windows")]
pub mod exec {
    use super::{classify_netsh_firewall_failure, FirewallRuleCommand};
    use crate::windows_console::NoWindowCommand;
    use crate::{ApplyResult, NetworkError};

    /// Execute one controlled netsh firewall command: success / idempotent
    /// success / classified failure.
    pub fn run_firewall_command(
        command: &FirewallRuleCommand,
    ) -> Result<ApplyResult, NetworkError> {
        let output = std::process::Command::new("netsh")
            .args(command.args())
            .no_window()
            .output()
            .map_err(|error| NetworkError::Io(format!("spawn netsh: {error}")))?;
        // netsh's redirected output is encoded in the active code page
        // (evidenced as GBK on a real zh-CN machine); prefer UTF-8 with a
        // CP_ACP fallback decode, see [windows_console].
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if output.status.success() {
            return Ok(ApplyResult::ok());
        }
        // Deleting an already-absent rule = idempotent success (driving the
        // cleanup path to an empty state is not a failure).
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

    /// Execute one mesh reachability command (AGENT-FW-1): per variant it
    /// goes through netsh or PowerShell, with success / classified failure
    /// states (the category set semantics are naturally idempotent, so no
    /// absent branch is needed).
    ///
    /// Real-machine verification runs together with the apply chain after
    /// #52 is wired (the R-05 gate); this function only hands the planned
    /// command to the system and hands the output back to the plan layer
    /// for classification.
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
            .no_window()
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
        // Lines without a colon / malformed lines are treated as
        // non-matching, without panicking.
        assert!(!rule_output_mentions_port("LocalPort garbage", 51820));
    }

    #[test]
    fn rule_output_mentions_port_matches_zh_cn_label() {
        // Audit finding #2: netsh output on a Chinese Windows uses the
        // zh-CN local-port label, so matching only the English label misses
        // it and every replay stacks another rule with the same name. The
        // zh label must hit.
        let zh = "规则名称: Meshlet-Direct-UDP-In\r\n本地端口:\t51820\r\n";
        assert!(rule_output_mentions_port(zh, 51820));
        assert!(!rule_output_mentions_port(zh, 20000));
        assert_eq!(rule_output_ports(zh), vec![51820]);
    }

    #[test]
    fn rule_output_ports_enumerates_all_mentioned_ports() {
        // Audit finding #3: a fixed rule name can cover several rules
        // (lingering after a config port change), so the full port set must
        // be enumerated.
        let both = "Rule Name: Meshlet-Direct-UDP-In\r\nLocalPort: 20000\r\n\
                    Rule Name: Meshlet-Direct-UDP-In\r\nLocalPort: 51820\r\n";
        assert_eq!(rule_output_ports(both), vec![20000, 51820]);
        assert!(rule_output_mentions_port(both, 51820));
        assert!(rule_output_mentions_port(both, 20000));
    }

    #[test]
    fn icmp_rule_satisfaction_checks_enabled_and_local_ip() {
        // Audit finding #1: judging presence by name alone gives false
        // positives after an address change or when the rule is disabled.
        let addr = "10.240.0.7".parse().unwrap();
        let satisfied_en = format!(
            "Rule Name:        Meshlet-ICMPv4-In\r\nEnabled:          Yes\r\nLocalIP:         {addr}\r\n"
        );
        assert!(rule_output_has_satisfied_icmp_rule(&satisfied_en, addr));

        // Address change: the rule is present but localip is the old
        // address -> unsatisfied.
        let stale_addr = "Rule Name:        Meshlet-ICMPv4-In\r\nEnabled:          Yes\r\nLocalIP:         10.240.0.9\r\n".to_string();
        assert!(!rule_output_has_satisfied_icmp_rule(&stale_addr, addr));

        // A rule with the same name is disabled (Enabled: No) ->
        // unsatisfied.
        let disabled = format!(
            "Rule Name:        Meshlet-ICMPv4-In\r\nEnabled:          No\r\nLocalIP:         {addr}\r\n"
        );
        assert!(!rule_output_has_satisfied_icmp_rule(&disabled, addr));

        // zh-CN fields (enabled: yes / local IP) -> satisfied.
        let zh = format!(
            "规则名称:      Meshlet-ICMPv4-In\r\n已启用:        是\r\n本地 IP:        {addr}\r\n"
        );
        assert!(rule_output_has_satisfied_icmp_rule(&zh, addr));
    }

    /// netsh show normalizes localip to `ip/netmask` (evidenced in the real-
    /// machine windows_firewall_live notes: `LocalIP: 127.0.0.1/255.255.255.255`),
    /// so a bare string equality comparison would misjudge a satisfied rule
    /// as Stale and delete+add on every apply, never idempotent.
    #[test]
    fn icmp_rule_satisfaction_tolerates_netsh_ip_mask_suffix() {
        let addr = "127.0.0.1".parse().unwrap();
        // Real-machine shape: ip/netmask plus wide alignment spaces.
        let real = "Rule Name:                            Meshlet-ICMPv4-In\r\n\
                    Enabled:                              Yes\r\n\
                    LocalIP:                              127.0.0.1/255.255.255.255\r\n";
        assert!(rule_output_has_satisfied_icmp_rule(real, addr));
        // The CIDR form is compatible too.
        let cidr = "Enabled: Yes\r\nLocalIP: 127.0.0.1/32\r\n";
        assert!(rule_output_has_satisfied_icmp_rule(cidr, addr));
        // Multiple comma-separated addresses including the target ->
        // satisfied.
        let multi =
            "Enabled: Yes\r\nLocalIP: 10.240.0.9/255.255.255.255,127.0.0.1/255.255.255.255\r\n";
        assert!(rule_output_has_satisfied_icmp_rule(multi, addr));
        // Well-formed but a different address -> unsatisfied (a shared
        // prefix is not enough either).
        let other = "Enabled: Yes\r\nLocalIP: 127.0.0.2/255.255.255.255\r\n";
        assert!(!rule_output_has_satisfied_icmp_rule(other, addr));
    }

    #[cfg(target_os = "windows")]
    mod exec_tests {
        use super::super::*;
        use super::rule;
        use crate::{ApplyResult, NetworkError};

        /// Compile-time lock on the exec entry point: the signature only
        /// accepts a planned command and returns a plan-layer result, so the
        /// test never launches netsh.
        #[test]
        fn exec_entrypoint_takes_planned_command_and_returns_planned_result() {
            fn assert_signature(
                _run: fn(&FirewallRuleCommand) -> Result<ApplyResult, NetworkError>,
            ) {
            }
            assert_signature(super::super::exec::run_firewall_command);
        }

        /// exec's delete branch depends on the plan-layer decision: the
        /// absence text = idempotent success.
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

        /// exec hands non-zero exit codes back to the plan layer: a
        /// privilege-class failure must still land as a privilege error.
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

    /// Evidenced on a real zh-CN machine (2026-10-25): the Chinese absence
    /// message, verbatim, hits the idempotent delete decision.
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

    /// Evidenced on a real zh-CN machine: the localized elevation text
    /// classifies as a privilege error.
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
        // netsh does not accept port tokens with an ICMP protocol:
        // localport/remoteport must be omitted; localip restricts the
        // allowance to the device overlay address (the netsh equivalent of
        // "restrict to the wg interface").
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
        // Fully idempotent: category already Private and the rule already
        // satisfied -> empty plan; missing either -> only fill that gap.
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
        // Audit finding #1: a lingering rule from an address change, or a
        // disabled rule with the same name -> delete then create, guaranteeing
        // exactly one.
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
        // The interface name goes into a PowerShell single-quoted string:
        // quotes/whitespace must be rejected (injection defense).
        for bad in ["", "wg meshlet", "wg'x", "wg\"x", "wg;x", "$(x)", "wg|x"] {
            assert!(
                mesh_reachability_commands(bad, DEVICE_ADDR, false, IcmpRuleState::Absent).is_err(),
                "interface {bad:?} must be rejected"
            );
            assert!(MeshFirewallCommand::set_network_category_private(bad).is_err());
        }
        // Legal tunnel names (with dot / underscore) must pass through.
        for good in ["wg-meshlet", "wg0", "Meshlet.Tunnel_1"] {
            assert!(
                mesh_reachability_commands(good, DEVICE_ADDR, true, IcmpRuleState::Satisfied)
                    .is_ok()
            );
        }
    }

    #[test]
    fn firewall_rule_present_distinguishes_show_output() {
        // en-US / zh-CN real-machine messages (after CP936 decoding).
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
        // Audit finding #4: a connection name/alias containing private but
        // the category is Public -> must judge non-Private.
        assert!(!net_category_is_private(
            "Name       : Private LAN\nNetworkCategory : Public"
        ));
        assert!(net_category_is_private(
            "Name       : Private LAN\nNetworkCategory : Private"
        ));
        // Bare-value output when the probe command takes only
        // `.NetworkCategory`.
        assert!(net_category_is_private("Private"));
        assert!(!net_category_is_private("Public"));
        assert!(!net_category_is_private("DomainAuthenticated"));
        assert!(!net_category_is_private(""));
    }
}
