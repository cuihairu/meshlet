//! Heartbeat and publish reporting.

use meshlet_domain::{DataplaneEvidence, DirectEndpointReport, DirectLinkStatus};
use meshlet_network::DevicePlan;

use crate::agent::direct_report::direct_report_from;
use crate::agent::evidence::probe_decision;
use crate::server;

impl super::Agent {
    /// Report the heartbeat and return whether it was delivered (a failure only logs; it must not make the dataplane loop back off).
    pub(super) fn report_heartbeat(&self, plan: Option<&DevicePlan>) -> bool {
        match self.heartbeat(plan) {
            Ok(()) => true,
            Err(e) => {
                // A report failure does not affect the dataplane: the plan has already been reconciled to expectation.
                tracing::warn!(error = %e, "heartbeat not delivered");
                false
            }
        }
    }

    /// Heartbeat report (§12.4/§14.1): carries the last handshake time read locally + dataplane measured
    /// evidence (§7.5: kernel readings + a planned-MTU large-packet probe) + the P2P direct candidate endpoints (§12).
    pub fn heartbeat(&self, plan: Option<&DevicePlan>) -> Result<(), String> {
        let evidence = self.collect_evidence(plan);
        let direct = self.direct_report();
        // §12.3: report each peer's direct link status (P2P/relay) with the heartbeat, for console display.
        // The status is the result of the most recent 30s probe - the heartbeat is denser than the probe, so what is reported is the last known state.
        let direct_links = self.direct.link_statuses();
        // R-DIAG: report the three local network diagnostics snapshots (routing table / interfaces / wg readings)
        // with the heartbeat. A collection failure is reported as `None` (server and console show "no snapshot",
        // so the missing evidence is visible), and never swallows the heartbeat itself.
        let diagnostics = self.backend.diagnostics_sync().ok();
        server::heartbeat(
            &self.server_url,
            &self.token,
            self.last_handshake(),
            Some(evidence),
            direct,
            direct_links,
            diagnostics,
            crate::ssh_sync::local_hostname(),
        )
        .map(|_| ())
        .map_err(|e| format!("heartbeat failed: {e}"))
    }

    /// §12 P2P: this machine's direct candidate endpoints (the WireGuard listen port + RFC1918 LAN addresses).
    /// Returns `None` when direct connect is disabled, the effective port is unresolved, or all candidates are
    /// blocked (WIN-PORT-1 B2) - the report is then omitted, the server treats it as unreported, and no endpoint
    /// is fabricated; a LAN enumeration failure only records empty candidates and never swallows the heartbeat.
    pub fn direct_report(&self) -> Option<DirectEndpointReport> {
        if !self.dataplane.direct_connect.enabled {
            return None;
        }
        direct_report_from(
            self.resolved_direct_port,
            self.backend.lan_addresses_sync().unwrap_or_default(),
        )
    }

    /// §12.3: this device's current direct link statuses per peer (for the heartbeat report and diagnostics export).
    /// Empty = all relay (no direct links). The status is the result of the most recent 30s probe.
    pub fn direct_link_statuses(&self) -> Vec<DirectLinkStatus> {
        self.direct.link_statuses()
    }

    /// Dataplane measured evidence (§7.5): kernel readings + the large-packet probe. A reading failure is
    /// reported as `None` (so the missing evidence is visible), and default values are never guessed - a failed
    /// probe and a missing probe are indistinguishable to the server, and both are treated as "not proven".
    pub fn collect_evidence(&self, plan: Option<&DevicePlan>) -> DataplaneEvidence {
        let snapshot = self.backend.inspect_sync().ok();
        DataplaneEvidence {
            tunnel_mtu: snapshot.as_ref().and_then(|s| s.tunnel_mtu),
            // The evidence's shape is unchanged (a boolean), but it is derived from the rule fingerprint set: a controlled SNAT
            // action appearing in a fingerprint means "an SNAT rule is present", which is closer to the semantics than enumerating the POSTROUTING chain alone.
            nat_rules_present: snapshot.as_ref().map(|s| !s.nat_rules.is_empty()),
            nat_snat_rules_present: snapshot.as_ref().map(|s| {
                s.nat_rules
                    .iter()
                    .any(|signature| signature.contains("|snat_to_gateway_lan|"))
            }),
            mtu_probe_payload: plan.and_then(|p| {
                // The underlay MTU is read only once (lane/dataplane-speed): the default-route interface's
                // MTU lets the probe payload adapt to jumbo/PPPoE underlays when the plan does not pin one;
                // if it cannot be read, fall back to the default size without guessing.
                let underlay = self.backend.underlay_path_mtu_sync();
                let (target, payload) = probe_decision(p, underlay)?;
                self.backend
                    .mtu_probe_sync(target, payload)
                    .then_some(payload)
            }),
        }
    }

    /// `wg show <if> latest-handshakes` -> the latest handshake time (ISO-8601); omitted when unavailable
    /// (the server treats that as "not obtained" and never fabricates online evidence).
    pub(super) fn last_handshake(&self) -> Option<String> {
        let out = std::process::Command::new("wg")
            .args(["show", &self.dataplane.interface, "latest-handshakes"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let ts: i64 = text
            .split_whitespace()
            .filter_map(|t| t.parse().ok())
            .filter(|t| *t > 0)
            .max()?;
        chrono::DateTime::from_timestamp(ts, 0).map(|d| d.to_rfc3339())
    }
}
