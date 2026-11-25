//! Network diagnostics ([Archive §12.7](../../docs/review/chatgpt-2026-10-13.md)):
//! 13 checks, grouped by failure layer (tunnel/routing/forwarding/Alias +
//! control plane); the first version diagnoses but does not repair.
//!
//! Interpretation discipline (§17.2 combined interpretation + this spec's hard
//! requirements):
//! - **No fake green**: local-machine state the control plane cannot observe
//!   (WireGuard interface, kernel routes, IP forwarding, firewall, NAT rules)
//!   is reported honestly as `unavailable` — that is not "healthy" — together
//!   with a one-line check command that can run on the target machine;
//! - **Registered on the control plane ≠ tunnel working**: peer registration
//!   (`server_peer_configured`) and a fresh handshake (`recent_handshake`) are
//!   two independent checks, and the former's detail must call this out
//!   (§12.4: a handshake only proves the tunnel connects, an agent report is
//!   what proves the device works);
//! - Every `fail`/`warning`/`unavailable` carries an actionable suggestion
//!   (`suggestion`).
//!
//! Result persistence (migration 006): `POST` computes and stores one snapshot
//! row, `GET` returns the latest run's report; never run → 404
//! ([ServiceError::DiagnosticsNotRun]).

use axum::extract::{Path, State};
use axum::routing::get;
use axum::{Json, Router};
use meshlet_domain::{
    AliasMapping, ApplyStatus, ConfigRevision, DataplaneEvidence, DesiredStateStatus, Device,
    LanRoute, PresenceState, RouteMode,
};
use serde::{Deserialize, Serialize};

use crate::auth::{AuthenticatedUser, CsrfHeader, SharedAppState, WriteUser};
use crate::service::{self, ServiceError};

// ---------------------------------------------------------------------------
// Report structure
// ---------------------------------------------------------------------------

/// Failure layers (§12.7 acceptance: able to tell the tunnel/routing/
/// forwarding/Alias failure layers apart).
pub mod layer {
    pub const CONTROL_PLANE: &str = "control_plane";
    pub const TUNNEL: &str = "tunnel";
    pub const ROUTING: &str = "routing";
    pub const FORWARDING: &str = "forwarding";
    pub const ALIAS: &str = "alias";
}

/// One check's result (id/name/layer/status form closed vocabularies, stored as
/// `String` for convenient snapshot deserialization; the vocabularies are pinned
/// by the constructors below and the `layer` constants).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticCheck {
    /// Stable identifier (contract field; the console sorts/aligns the §12.7
    /// checks by it).
    pub id: String,
    pub name: String,
    /// `control_plane` / `tunnel` / `routing` / `forwarding` / `alias`.
    pub layer: String,
    /// `pass` / `fail` / `warning` / `unavailable` / `not_applicable`.
    pub status: String,
    /// Observed facts (including "why it could not be read" — the reason for
    /// unavailable).
    pub detail: String,
    /// Actionable suggestion; an empty string when `pass`.
    pub suggestion: String,
}

/// Full report of one diagnostics run (computed and stored by `POST`,
/// returned deserialized by `GET`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiagnosticsReport {
    pub network_id: String,
    pub checked_at: String,
    pub checks: Vec<DiagnosticCheck>,
}

/// The unified semantics of `unavailable`: the control plane **cannot observe**
/// it (local-machine state needs local privileged readings), which is not
/// "healthy". detail says what is missing, suggestion gives the check command
/// for the target machine.
fn unavailable(
    id: &'static str,
    name: &'static str,
    layer: &'static str,
    detail: String,
    suggestion: String,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        name: name.into(),
        layer: layer.into(),
        status: "unavailable".into(),
        detail,
        suggestion,
    }
}

/// `not_applicable`: this network has no object for the check (honestly
/// distinguished from pass).
fn not_applicable(
    id: &'static str,
    name: &'static str,
    layer: &'static str,
    detail: String,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        name: name.into(),
        layer: layer.into(),
        status: "not_applicable".into(),
        detail,
        suggestion: String::new(),
    }
}

/// Build a check with an arbitrary status (shared by the check_* functions).
fn check(
    id: &'static str,
    name: &'static str,
    layer: &'static str,
    status: &'static str,
    detail: String,
    suggestion: String,
) -> DiagnosticCheck {
    DiagnosticCheck {
        id: id.into(),
        name: name.into(),
        layer: layer.into(),
        status: status.into(),
        detail,
        suggestion,
    }
}

// ---------------------------------------------------------------------------
// The 13 checks (§12.7 order)
// ---------------------------------------------------------------------------

/// Compute a network's 13 checks. `now` is injected for deterministic testing;
/// `aliases` come from the `alias_mappings` table (produced by the §12.6
/// service write path; normal data creation already passes the same conflict
/// checks, so this is a backstop against a dirty/hand-edited database);
/// `tunnel_mtu` comes from the server config (§7.5, the input to ⑬).
pub fn run_checks(
    mesh: &service::MeshState,
    network_id: &str,
    aliases: &[AliasMapping],
    tunnel_mtu: Option<u32>,
    now: &str,
) -> DiagnosticsReport {
    let overlay = mesh
        .network_row(network_id)
        .expect("caller checked network exists")
        .overlay_cidr;
    let active: Vec<&Device> = mesh
        .registry
        .devices()
        .iter()
        .filter(|d| d.network_id.to_string() == network_id && d.is_active())
        .collect();
    let routes: Vec<&LanRoute> = mesh
        .lan_routes
        .get(network_id)
        .map(|rs| rs.iter().collect())
        .unwrap_or_default();
    let latest = mesh
        .ledger
        .current(&meshlet_domain::NetworkId(network_id.to_string()))
        .cloned();
    let thresholds = &mesh.presence_thresholds;

    DiagnosticsReport {
        network_id: network_id.to_string(),
        checked_at: now.to_string(),
        checks: vec![
            check_api_reachable(now),
            check_wg_interface(),
            check_server_peer(&active),
            check_recent_handshake(&active, now, thresholds.handshake_window),
            check_overlay_route(&overlay.to_string()),
            check_ip_forwarding(),
            check_firewall_forwarding(),
            check_gateway_online(&routes, mesh, now),
            check_route_published(&routes, latest.as_ref()),
            check_alias_conflict(aliases, &routes, &overlay),
            check_nat_rules(&routes, mesh),
            check_revision_consistent(latest.as_ref()),
            check_mtu_planned(tunnel_mtu, &active),
        ],
    }
}

/// ① API reachable (control plane): being able to read this report proves the
/// management API was serving at diagnosis time.
fn check_api_reachable(now: &str) -> DiagnosticCheck {
    check(
        "api_reachable",
        "API reachable",
        layer::CONTROL_PLANE,
        "pass",
        format!(
            "this run was produced by the management API at {now} — the control plane answered the request"
        ),
        String::new(),
    )
}

/// ② WireGuard interface exists (tunnel): local-machine state, unobservable
/// from the control plane.
fn check_wg_interface() -> DiagnosticCheck {
    unavailable(
        "wg_interface_exists",
        "WireGuard interface exists",
        layer::TUNNEL,
        "the control plane cannot read a device's local WireGuard interface; it requires a local `wg show` on each device".into(),
        "on each device run `wg show mesh0` (or the configured interface) — a missing interface means the agent has not brought the tunnel up; check the agent service (`systemctl status meshlet-agent`) and its logs".into(),
    )
}

/// ③ Server peer configured (tunnel): a public key in the registry means
/// configured — but that only proves "registered on the control plane", not
/// that the tunnel works (that is ④'s job).
fn check_server_peer(active: &[&Device]) -> DiagnosticCheck {
    if active.is_empty() {
        return not_applicable(
            "server_peer_configured",
            "Server peer configured",
            layer::TUNNEL,
            "no devices registered in this network".into(),
        );
    }
    let names: Vec<String> = active.iter().map(|d| d.name.clone()).collect();
    check(
        "server_peer_configured",
        "Server peer configured",
        layer::TUNNEL,
        "pass",
        format!(
            "{} device(s) registered with a WireGuard public key on the server: {} — control-plane registration only; it does not prove the tunnel carries traffic (see the handshake check)",
            active.len(),
            names.join(", ")
        ),
        String::new(),
    )
}

/// ④ Recent handshake healthy (tunnel): the handshake is the only tunnel-layer
/// evidence (§12.4); the freshness window matches presence
/// (`handshake_window`, default 120s).
fn check_recent_handshake(
    active: &[&Device],
    now: &str,
    window: std::time::Duration,
) -> DiagnosticCheck {
    if active.is_empty() {
        return not_applicable(
            "recent_handshake",
            "Recent handshake",
            layer::TUNNEL,
            "no devices registered in this network".into(),
        );
    }
    let mut parts: Vec<String> = Vec::new();
    let mut fresh_count = 0usize;
    for d in active {
        match d.last_handshake_at.as_deref() {
            Some(ts) if meshlet_domain::presence::fresh(ts, now, window) => {
                fresh_count += 1;
                parts.push(format!(
                    "{}: fresh handshake ({} ago)",
                    d.name,
                    ago(ts, now)
                ));
            }
            Some(ts) => parts.push(format!(
                "{}: stale handshake (last {} ago, window {}s)",
                d.name,
                ago(ts, now),
                window.as_secs()
            )),
            None => parts.push(format!(
                "{}: no handshake ever observed (device registered, tunnel never confirmed)",
                d.name
            )),
        }
    }
    let all_fresh = fresh_count == active.len();
    check(
        "recent_handshake",
        "Recent handshake",
        layer::TUNNEL,
        if all_fresh { "pass" } else { "fail" },
        format!(
            "{fresh_count}/{} device(s) with a handshake inside the {}s window: {}",
            active.len(),
            window.as_secs(),
            parts.join("; ")
        ),
        if all_fresh {
            String::new()
        } else {
            "a fresh handshake is the only tunnel-level evidence the control plane has (§12.4): run `wg show mesh0` on the devices to read latest-handshake directly; a stale or missing handshake usually means the interface is down, the peer endpoint is unreachable, or keys were rotated on one side".into()
        },
    )
}

/// ⑤ Overlay IP route present (routing): kernel routing table, unobservable
/// from the control plane.
fn check_overlay_route(overlay: &str) -> DiagnosticCheck {
    unavailable(
        "overlay_route_present",
        "Overlay route present",
        layer::ROUTING,
        format!(
            "the control plane cannot read a device's kernel routing table; the overlay to look for is {overlay}"
        ),
        format!(
            "on each device run `ip route show to {overlay}` — expect a route via the mesh interface; if missing, the agent has not installed the overlay route (check the agent's apply output)"
        ),
    )
}

/// ⑥ IP forwarding enabled (forwarding): gateway-machine sysctl, unobservable
/// from the control plane.
fn check_ip_forwarding() -> DiagnosticCheck {
    unavailable(
        "ip_forwarding_enabled",
        "IP forwarding enabled",
        layer::FORWARDING,
        "the control plane cannot read the gateway's `net.ipv4.ip_forward` sysctl".into(),
        "on the LAN gateway run `sysctl net.ipv4.ip_forward` — expect 1; enable with `sysctl -w net.ipv4.ip_forward=1` and persist under /etc/sysctl.d/. ip_forward=0 silently drops all forwarded LAN traffic while the tunnel itself can still look healthy".into(),
    )
}

/// ⑦ Firewall allows the necessary forwarding (forwarding): gateway-machine
/// firewall rules, unobservable from the control plane.
fn check_firewall_forwarding() -> DiagnosticCheck {
    unavailable(
        "firewall_allows_forwarding",
        "Firewall allows forwarding",
        layer::FORWARDING,
        "the control plane cannot read the gateway's firewall rules (FORWARD chain / ufw)".into(),
        "on the LAN gateway run `iptables -L FORWARD -n -v` and `iptables -t nat -L -n -v` (or `ufw status verbose`) — expect FORWARD to accept traffic from the mesh interface; a REJECT/DROP policy here silently breaks LAN reachability while handshakes keep succeeding".into(),
    )
}

/// ⑧ LAN gateway agent online (routing): the gateway's agent must have a
/// **fresh agent report**
/// (§12.4: handshake freshness alone = tunnel_only, which cannot be treated as
/// a working device).
fn check_gateway_online(
    routes: &[&LanRoute],
    mesh: &service::MeshState,
    now: &str,
) -> DiagnosticCheck {
    if routes.is_empty() {
        return not_applicable(
            "lan_gateway_agent_online",
            "LAN gateway agent online",
            layer::ROUTING,
            "no LAN routes in this network".into(),
        );
    }
    let mut parts: Vec<String> = Vec::new();
    let mut online = 0usize;
    let mut tunnel_only = 0usize;
    let mut broken = 0usize;
    for r in routes {
        let Some(device) = mesh.registry.find_by_id(&r.gateway_device_id) else {
            broken += 1;
            parts.push(format!(
                "route {}: gateway {} not registered (revoked or never enrolled) — the route has no live gateway",
                r.id, r.gateway_device_id
            ));
            continue;
        };
        if !device.is_active() {
            broken += 1;
            parts.push(format!(
                "route {} → gateway {}: device revoked — the route has no live gateway",
                r.id, device.name
            ));
            continue;
        }
        let presence =
            service::evaluate_presence(device, &now.to_string(), &mesh.presence_thresholds);
        match presence.state {
            PresenceState::Online => {
                online += 1;
                parts.push(format!(
                    "route {} → gateway {}: agent online (last report {} ago)",
                    r.id,
                    device.name,
                    ago(
                        device
                            .last_report_at
                            .as_deref()
                            .unwrap_or(&device.created_at),
                        now
                    )
                ));
            }
            PresenceState::TunnelOnly => {
                tunnel_only += 1;
                parts.push(format!(
                    "route {} → gateway {}: tunnel only (fresh handshake but no fresh agent report) — the agent process may be down",
                    r.id, device.name
                ));
            }
            PresenceState::Offline => {
                broken += 1;
                parts.push(format!(
                    "route {} → gateway {}: agent offline (no fresh evidence since {})",
                    r.id,
                    device.name,
                    ago(
                        device.last_seen_at.as_deref().unwrap_or(&device.created_at),
                        now
                    )
                ));
            }
        }
    }
    let (status, suggestion) = if broken > 0 {
        (
            "fail",
            "the gateway agent must report fresh agent evidence for its LAN routes to be considered live: check `systemctl status meshlet-agent` on the gateway, its reachability to the server, and the last heartbeat in the devices panel".to_string(),
        )
    } else if tunnel_only > 0 {
        (
            "warning",
            "a gateway with only fresh handshake evidence (tunnel_only) has a working tunnel but an unverifiable agent process — verify the agent is running and reporting".to_string(),
        )
    } else {
        ("pass", String::new())
    };
    DiagnosticCheck {
        id: "lan_gateway_agent_online".into(),
        name: "LAN gateway agent online".into(),
        layer: layer::ROUTING.into(),
        status: status.into(),
        detail: format!(
            "{online} online, {tunnel_only} tunnel-only, {broken} offline/unregistered across {} route(s): {}",
            routes.len(),
            parts.join("; ")
        ),
        suggestion,
    }
}

/// ⑨ LAN route published (routing): the control-plane criterion = the route is
/// recorded + the latest revision covering it is applied; it does **not** prove
/// the gateway's kernel has the route installed (that is the local-machine
/// reading of ⑤⑦).
fn check_route_published(routes: &[&LanRoute], latest: Option<&ConfigRevision>) -> DiagnosticCheck {
    if routes.is_empty() {
        return not_applicable(
            "lan_route_published",
            "LAN route published",
            layer::ROUTING,
            "no LAN routes in this network".into(),
        );
    }
    let items: Vec<String> = routes
        .iter()
        .map(|r| {
            format!(
                "{} → {} via {} ({})",
                r.id,
                r.destination_cidr,
                r.gateway_device_id,
                desired_status(r.status)
            )
        })
        .collect();
    let Some(rev) = latest else {
        return check(
            "lan_route_published",
            "LAN route published",
            layer::ROUTING,
            "fail",
            format!(
                "{} route(s) recorded ({}), but no config revision exists — desired state was never applied",
                routes.len(),
                items.join("; ")
            ),
            "record and apply a config revision covering these routes".into(),
        );
    };
    let (status, suggestion) = match rev.apply_status {
        ApplyStatus::Applied => ("pass", String::new()),
        ApplyStatus::Failed => (
            "fail",
            "the routes were recorded but the apply failed — nothing was published to any backend: roll back the failed revision or record a new one after fixing the backend".into(),
        ),
        _ => (
            "warning",
            "the revision covering these routes is not confirmed applied yet — apply it from the config-revisions panel".into(),
        ),
    };
    let state_note = match rev.apply_status {
        ApplyStatus::Applied => "applied",
        ApplyStatus::Failed => "failed",
        other => other.as_str(),
    };
    DiagnosticCheck {
        id: "lan_route_published".into(),
        name: "LAN route published".into(),
        layer: layer::ROUTING.into(),
        status: status.into(),
        detail: format!(
            "{} route(s) recorded ({}); latest revision #{} is {state_note} — control-plane publication only; whether the gateway's kernel actually has the route is a local-machine fact (see overlay route / firewall checks)",
            routes.len(),
            items.join("; "),
            rev.revision
        ),
        suggestion,
    }
}

/// ⑩ Alias prefix conflict (Alias): runs the domain-layer conflict detection
/// over the existing mappings
/// (overlay overlap / alias-alias overlap / bound-route CIDR mismatch).
fn check_alias_conflict(
    aliases: &[AliasMapping],
    routes: &[&LanRoute],
    overlay: &meshlet_domain::Ipv4Cidr,
) -> DiagnosticCheck {
    if aliases.is_empty() {
        return not_applicable(
            "alias_prefix_conflict",
            "Alias prefix conflict",
            layer::ALIAS,
            "no alias mappings in this network (equal-prefix virtual mapping, ADR-006) — nothing to conflict-check".into(),
        );
    }
    let mut conflicts: Vec<String> =
        meshlet_domain::conflict::overlay_alias_overlap(*overlay, aliases)
            .into_iter()
            .map(|c| c.detail)
            .collect();
    conflicts.extend(
        meshlet_domain::conflict::alias_alias_overlap(aliases)
            .into_iter()
            .map(|c| c.detail),
    );
    for alias in aliases {
        if let Some(route) = routes.iter().find(|r| r.id == alias.lan_route_id) {
            conflicts.extend(
                meshlet_domain::conflict::alias_target_mismatch(alias, route)
                    .into_iter()
                    .map(|c| c.detail),
            );
        }
    }
    check(
        "alias_prefix_conflict",
        "Alias prefix conflict",
        layer::ALIAS,
        if conflicts.is_empty() { "pass" } else { "fail" },
        if conflicts.is_empty() {
            format!(
                "{} alias mapping(s) checked against the overlay, each other, and their bound routes — no conflicts",
                aliases.len()
            )
        } else {
            format!("{} conflict(s): {}", conflicts.len(), conflicts.join("; "))
        },
        if conflicts.is_empty() {
            String::new()
        } else {
            "conflicting aliases make the equal-prefix translation ambiguous: remove or re-prefix the offending mapping (ADR-006) and record a new revision".into()
        },
    )
}

/// ⑪ NAT rules effective (Alias): kernel scan returned by the gateway agent's
/// heartbeat (ownership comment, §12.6). When no gateway has reported evidence
/// the control plane honestly reports "unobservable" — no pretending there.
fn check_nat_rules(routes: &[&LanRoute], mesh: &service::MeshState) -> DiagnosticCheck {
    let alias_routes: Vec<&LanRoute> = routes
        .iter()
        .copied()
        .filter(|r| r.route_mode == RouteMode::Alias && r.status == DesiredStateStatus::Applied)
        .collect();
    // Only judge gateways that "reported evidence": missing evidence (agent not
    // running / an old version) means neither that the rules are absent nor
    // that they exist (§12.2 interpretation discipline).
    let mut reporting: Vec<(String, bool, Option<bool>)> = Vec::new();
    for route in &alias_routes {
        let Some(gateway) = mesh.registry.find_by_id(&route.gateway_device_id) else {
            continue;
        };
        let Some(evidence) = gateway.dataplane_evidence.as_ref() else {
            continue;
        };
        let Some(present) = evidence.nat_rules_present else {
            continue;
        };
        reporting.push((
            gateway.name.clone(),
            present,
            evidence.nat_snat_rules_present,
        ));
    }
    if reporting.is_empty() {
        return unavailable(
            "nat_rules_effective",
            "NAT rules effective",
            layer::ALIAS,
            if alias_routes.is_empty() {
                "the control plane cannot read the gateway's NAT rules or their traffic counters; no gateway agent has reported kernel evidence yet".to_string()
            } else {
                format!(
                    "the control plane cannot read the gateway's NAT rules; {} alias route(s) registered but no gateway agent has reported kernel evidence yet (agent not running or an older agent without evidence reporting)",
                    alias_routes.len()
                )
            },
            "on the LAN gateway run `iptables -t nat -L -n -v` — for each alias mapping check the DNAT/SNAT rules exist and their packet counters grow with traffic; zero counters on an active mapping means the rule exists but no traffic matches (wrong prefix or interface). An up-to-date agent reports this reading via its heartbeat (§12.4)".into(),
        );
    }
    let broken: Vec<String> = reporting
        .iter()
        .filter(|(_, present, _)| !present)
        .map(|(name, _, _)| name.clone())
        .collect();
    if !broken.is_empty() {
        return check(
            "nat_rules_effective",
            "NAT rules effective",
            layer::ALIAS,
            "fail",
            format!(
                "at their last heartbeat, gateway(s) {} reported no meshlet NAT rules in the kernel — the rules do not survive reboots and the alias path is broken until the agent re-applies them",
                broken.join(", ")
            ),
            "check the gateway agent is running (`systemctl status meshlet-agent`) and can reach the server; a healthy agent detects the missing rules and replays them on its next reconcile (§12.6)".into(),
        );
    }
    let names: Vec<String> = reporting.iter().map(|(name, _, _)| name.clone()).collect();
    // SNAT readings are stated separately per what the kernel actually shows:
    // `dnat_only` mappings by design never receive SNAT rules
    // (ADR-005 mode A); rules being present ≠ SNAT being present, and the two
    // must not be conflated.
    let snat_confirmed: Vec<String> = reporting
        .iter()
        .filter(|(_, _, snat)| *snat == Some(true))
        .map(|(name, _, _)| name.clone())
        .collect();
    let snat_absent: Vec<String> = reporting
        .iter()
        .filter(|(_, present, snat)| *present && *snat != Some(true))
        .map(|(name, _, _)| name.clone())
        .collect();
    let snat_note = if snat_absent.is_empty() {
        format!(
            "controlled SNAT kernel-confirmed by {}",
            snat_confirmed.join(", ")
        )
    } else if snat_confirmed.is_empty() {
        format!(
            "no meshlet SNAT rule observed on {} (dnat_only mappings keep original sources, ADR-005)",
            snat_absent.join(", ")
        )
    } else {
        format!(
            "controlled SNAT kernel-confirmed by {}; no meshlet SNAT rule observed on {} (dnat_only mappings keep original sources, ADR-005)",
            snat_confirmed.join(", "),
            snat_absent.join(", ")
        )
    };
    check(
        "nat_rules_effective",
        "NAT rules effective",
        layer::ALIAS,
        "pass",
        format!(
            "gateway(s) {} report the ownership-commented NAT rules present in their kernel ({})",
            names.join(", "),
            snat_note
        ),
        String::new(),
    )
}

/// ⑫ Config revision consistent (control plane): the status of the latest
/// non-rolled-back revision = the verdict on whether the desired config matches
/// the actual environment (§10.1: a DB write is not the same as being in
/// effect).
fn check_revision_consistent(latest: Option<&ConfigRevision>) -> DiagnosticCheck {
    let Some(rev) = latest else {
        return not_applicable(
            "config_revision_consistent",
            "Config revision consistent",
            layer::CONTROL_PLANE,
            "no config revisions recorded yet — nothing to apply".into(),
        );
    };
    let (status, suggestion) = match rev.apply_status {
        ApplyStatus::Applied => ("pass", String::new()),
        ApplyStatus::Failed => (
            "fail",
            "the actual network environment does not match the desired config: roll back the failed revision (config-revisions panel) or fix the backend and record a new revision".into(),
        ),
        _ => (
            "warning",
            "the desired config is not confirmed applied yet — apply the revision from the config-revisions panel; until then new devices may receive config no gateway actually has".into(),
        ),
    };
    let state_note = match rev.apply_status {
        ApplyStatus::Applied => format!("applied at {}", rev.applied_at.as_deref().unwrap_or("?")),
        ApplyStatus::Failed => format!(
            "failed: {}",
            rev.error_summary.as_deref().unwrap_or("no error summary")
        ),
        other => other.as_str().to_string(),
    };
    check(
        "config_revision_consistent",
        "Config revision consistent",
        layer::CONTROL_PLANE,
        status,
        format!("latest revision #{} is {state_note}", rev.revision),
        suggestion,
    )
}

/// ⑬ Tunnel MTU (tunnel): the planned value + device-side measured evidence
/// (§7.5). The planned value comes from the server config (when not explicitly
/// configured, the blackhole risk is interpreted against the WireGuard default
/// of 1420); the measurements come from interface MTU readings and large-packet
/// probes (`ping -M do`) returned by the agent heartbeat. With no device
/// evidence only the plan is judged — what the kernel holds and whether the
/// path carries it, the control plane does not pretend to know.
fn check_mtu_planned(tunnel_mtu: Option<u32>, active: &[&Device]) -> DiagnosticCheck {
    if active.is_empty() {
        return not_applicable(
            "mtu_planned",
            "Tunnel MTU planned",
            layer::TUNNEL,
            "no active devices in this network — no tunnel to size".into(),
        );
    }
    let planned = tunnel_mtu.unwrap_or(meshlet_network::DEFAULT_TUNNEL_MTU);
    let planned_note = match tunnel_mtu {
        Some(mtu) => format!("tunnel_mtu = {mtu} is explicitly configured"),
        None => format!(
            "tunnel_mtu is not configured — devices fall back to the WireGuard default {planned}, which blackholes large packets on PPPoE/4G underlays unless the path is verified"
        ),
    };
    let evidence: Vec<(&Device, &DataplaneEvidence)> = active
        .iter()
        .filter_map(|d| d.dataplane_evidence.as_ref().map(|e| (*d, e)))
        .collect();
    if evidence.is_empty() {
        return match tunnel_mtu {
            Some(_) => check(
                "mtu_planned",
                "Tunnel MTU planned",
                layer::TUNNEL,
                "pass",
                format!(
                    "{planned_note} (planned value; WireGuard adds ~80B overhead per packet, keep mtu + overhead <= underlay MTU)"
                ),
                String::new(),
            ),
            None => check(
                "mtu_planned",
                "Tunnel MTU planned",
                layer::TUNNEL,
                "warning",
                planned_note,
                "set tunnel_mtu in the server config for a deliberate value, or verify the path from a device: `ping -M do -s 1392 <overlay-peer-ip>` (1420-28) — failures mean the effective MTU is smaller and packets fragment or vanish (§7.5)".into(),
            ),
        };
    }
    // A device reading that disagrees with the plan → fail (naming the device and
    // the reading; the agent replays drift back to plan).
    let mismatched: Vec<String> = evidence
        .iter()
        .filter(|(_, e)| e.tunnel_mtu.is_some() && e.tunnel_mtu != Some(planned))
        .map(|(d, e)| format!("{} reports interface mtu {}", d.name, e.tunnel_mtu.unwrap()))
        .collect();
    if !mismatched.is_empty() {
        return check(
            "mtu_planned",
            "Tunnel MTU planned",
            layer::TUNNEL,
            "fail",
            format!(
                "{planned_note}, but device readings disagree: {}",
                mismatched.join("; ")
            ),
            "the agent replays the planned MTU on drift — if a reading stays off, check that device's agent is running and reconciling; alternatively adjust tunnel_mtu in the server config and record a new revision".into(),
        );
    }
    // Readings match but the large-packet probe is unconfirmed (a failed probe and
    // a probe never sent look identical) → warning, with the measure command.
    let unverified: Vec<&str> = evidence
        .iter()
        .filter(|(_, e)| e.mtu_probe_payload.is_none())
        .map(|(d, _)| d.name.as_str())
        .collect();
    if !unverified.is_empty() {
        return check(
            "mtu_planned",
            "Tunnel MTU planned",
            layer::TUNNEL,
            "warning",
            format!(
                "{planned_note}; interface readings match the plan, but no successful large-packet probe was reported by {} — the path may not carry the planned MTU (probe failed) or the probe peer was unreachable",
                unverified.join(", ")
            ),
            format!(
                "verify from a device: `ping -M do -s {} <overlay-peer-ip>` ({planned}-28) — failures mean the effective MTU is smaller and packets fragment or vanish (§7.5)",
                planned - 28
            ),
        );
    }
    let readings: Vec<String> = evidence
        .iter()
        .map(|(d, e)| {
            format!(
                "{} reading {} probe {}",
                d.name,
                e.tunnel_mtu
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into()),
                e.mtu_probe_payload
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "?".into())
            )
        })
        .collect();
    check(
        "mtu_planned",
        "Tunnel MTU planned",
        layer::TUNNEL,
        "pass",
        format!(
            "{planned_note}; device evidence confirms the plan: {} (probe = largest payload carried end-to-end)",
            readings.join("; ")
        ),
        String::new(),
    )
}

fn desired_status(s: DesiredStateStatus) -> &'static str {
    match s {
        DesiredStateStatus::Pending => "pending",
        DesiredStateStatus::Applied => "applied",
        DesiredStateStatus::Failed => "failed",
    }
}

/// Human-readable "how long ago" duration (used in detail; a value that fails
/// to parse is reported as unknown, never guessed).
fn ago(ts: &str, now: &str) -> String {
    match (
        chrono::DateTime::parse_from_rfc3339(ts),
        chrono::DateTime::parse_from_rfc3339(now),
    ) {
        (Ok(ts), Ok(now)) => {
            let secs = now.signed_duration_since(ts).num_seconds().max(0);
            if secs < 60 {
                format!("{secs}s")
            } else if secs < 3600 {
                format!("{}m{}s", secs / 60, secs % 60)
            } else {
                format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
            }
        }
        _ => "unknown".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Endpoints
// ---------------------------------------------------------------------------

/// Diagnostics routes (management API: GET reads the snapshot, POST triggers a
/// new run — write requests require write permission + CSRF).
pub fn routes() -> Router<SharedAppState> {
    Router::new().route(
        "/api/v1/networks/{network_id}/diagnostics",
        get(get_diagnostics_handler).post(run_diagnostics_handler),
    )
}

/// `POST /api/v1/networks/{network_id}/diagnostics`: computes the 13 checks,
/// stores one snapshot row and returns it. Leaves an audit event (an explicit
/// operator action, so "who diagnosed what, when" can be traced afterwards).
pub async fn run_diagnostics_handler(
    State(state): State<SharedAppState>,
    WriteUser(user_id): WriteUser,
    CsrfHeader: CsrfHeader,
    Path(network_id): Path<String>,
) -> Result<Json<DiagnosticsReport>, ServiceError> {
    let _persist = state.persist.lock().await;
    let now = service::now();
    // alias rows (the input to item 10 of §12.7) come from the DB (produced by
    // the §12.6 service write path).
    let aliases = crate::persist::alias_rows(state.auth.pool(), &network_id)
        .await
        .map_err(crate::persist::internal)?;
    let report = {
        let guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
        run_checks(&guard, &network_id, &aliases, state.tunnel_mtu, &now)
    };
    let json = serde_json::to_string(&report)
        .map_err(|e| ServiceError::Internal(format!("serialize diagnostics report: {e}")))?;
    crate::persist::insert_diagnostics_run(state.auth.pool(), &network_id, &now, &json)
        .await
        .map_err(crate::persist::internal)?;
    crate::audit::record_or_fail(
        &state,
        Some(&user_id.0),
        "diagnostics.run",
        "network",
        Some(&network_id),
        Some(serde_json::json!({
            "checks": report.checks.len(),
            "fail": report.checks.iter().filter(|c| c.status == "fail").count(),
            "unavailable": report.checks.iter().filter(|c| c.status == "unavailable").count(),
        })),
    )
    .await?;
    crate::op_log!(
        info,
        "network",
        "run_diagnostics",
        &network_id,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::NOT_APPLICABLE,
        crate::telemetry::ErrorCategory::None.as_str(),
        crate::telemetry::RESULT_OK
    );
    Ok(Json(report))
}

/// `GET /api/v1/networks/{network_id}/diagnostics`: the latest diagnostics
/// run. Never run → 404 (the message names POST as the way to trigger one).
pub async fn get_diagnostics_handler(
    State(state): State<SharedAppState>,
    AuthenticatedUser(_user): AuthenticatedUser,
    Path(network_id): Path<String>,
) -> Result<Json<DiagnosticsReport>, ServiceError> {
    {
        let guard = state.mesh.lock().unwrap();
        service::require_network(&guard, &network_id)?;
    }
    match crate::persist::latest_diagnostics_run(state.auth.pool(), &network_id)
        .await
        .map_err(crate::persist::internal)?
    {
        Some(json) => {
            let report: DiagnosticsReport = serde_json::from_str(&json)
                .map_err(|e| ServiceError::Internal(format!("stored diagnostics report: {e}")))?;
            Ok(Json(report))
        }
        None => Err(ServiceError::DiagnosticsNotRun(format!(
            "no diagnostics run recorded for network {network_id} — trigger one with POST /api/v1/networks/{network_id}/diagnostics"
        ))),
    }
}
