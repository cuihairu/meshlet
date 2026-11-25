//! P2P direct connect orchestration.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Instant;

use meshlet_domain::PeerLinkState;
use meshlet_domain::DIRECT_PROBE_INTERVAL_SECS;
use meshlet_network::dial::{self, DirectDialRequest, DirectDialResult};
use meshlet_network::{DevicePlan, NetworkDiagnostics};

use crate::agent::endpoint::parse_endpoint_candidate;
use crate::agent::handshake::dump_handshake_ages;
use crate::agent::rtt_source::honest_rtt_source;
use crate::agent::scope::direct_scope;
use crate::agent::verdict::dial_verdict;
use crate::agent::views::direct_peer_views;
use crate::direct::{
    is_viable_endpoint, keepalive_secs, merge_handshake_ages, DirectUpdate, PeerDecisionRecord,
};
use crate::direct_rtt::{RttCandidate, RttProbe};
use crate::server;

impl super::Agent {
    /// §12 P2P direct-connect probe loop (30s throttle): fetch candidates →
    /// domain state machine → `wg set` apply.
    ///
    /// Direct connect is a **gain**: every failure (candidate fetch / LAN
    /// enumeration / handshake reading / `wg set`) is logged only and never
    /// interrupts the hub relay path — the peer stays reachable by the hub
    /// full route and is retried next cycle; switch off clears established
    /// direct connects (handed to the hub; kernel drift reconciliation covers).
    ///
    /// `peer dial` intent ([`dial::DirectDialRequest`]): the CLI writes it to
    /// `{state_dir}/direct-dial.json`. With intent present, **skip the 30s
    /// throttle** and probe one round at once (dialing does not wait for the
    /// next cycle): feed the target candidates to the state machine and call
    /// `wg set` via [`crate::agent::Agent::apply_direct_update`] (executor dials through `meshlet-network`); then write the result back to `{state_dir}/direct-dial-result.json` and clear the intent. Dial failure / no path / non-candidate is always written as a failure result — never silently.
    ///
    /// In production, scheduled by [`Agent::tick`] after the heartbeat (the server sees our direct candidates first);
    /// netns integration tests can drive one round directly.
    pub fn reconcile_direct(&mut self, plan: &DevicePlan) {
        let request = dial::load_request(Path::new(&self.state_dir));
        if !self.dataplane.direct_connect.enabled {
            // Direct off → nothing to probe: clear the probe candidate cache and candidate table
            // (probe thread no-ops next round; roaming evidence dropped, rebuilt from the server view once re-enabled).
            self.probe.update_candidates(&[]);
            self.candidates = crate::candidates::CandidateTable::new();
            let updates = self.direct.demote_all();
            if !updates.is_empty() {
                for update in &updates {
                    self.apply_direct_update(update);
                }
                self.save_direct_ledger();
            }
            self.last_direct_probe = Some(Instant::now());
            if let Some(req) = request {
                self.finish_dial(
                    &req,
                    false,
                    "hub_relay",
                    "direct connect is disabled (config)",
                );
            }
            return;
        }
        let due = self
            .last_direct_probe
            .map(|last| last.elapsed().as_secs() >= DIRECT_PROBE_INTERVAL_SECS)
            .unwrap_or(true);
        // A dial intent forces this round (no waiting for the throttle); without one, normal throttle.
        // "Probe immediately" for a network-change event comes from run() resetting last_direct_probe at the network-event wakeup.
        if !due && request.is_none() {
            return;
        }
        self.last_direct_probe = Some(Instant::now());
        let mut wanted = match server::fetch_peer_endpoints(&self.server_url, &self.token) {
            Ok(wanted) => wanted,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: peer endpoints unavailable");
                if let Some(req) = request {
                    self.finish_dial(
                        &req,
                        false,
                        "hub_relay",
                        &format!("peer endpoints unavailable: {e}"),
                    );
                }
                return;
            }
        };
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // scope / LAN subnets **before** candidate table reconciliation: AGENT-ISO-3 filters unusable endpoints at the source,
        // else the candidate table, the probe window and the SEL-002 switch paths all get a bad face — patching them
        // one by one is bound to miss (2026-11-23 incident: the decision layer had already filtered, yet the probe
        // switch still picked the peer's ZeroTier address as the active face).
        let Some(scope) = direct_scope(plan) else {
            tracing::warn!("direct probe: no routable scope in the plan; keeping hub relay");
            if let Some(req) = request {
                self.finish_dial(&req, false, "hub_relay", "no routable scope in the plan");
            }
            return;
        };
        let my_lan_subnets = match self.backend.lan_subnets_sync() {
            Ok(subnets) => subnets,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: lan subnets unavailable");
                Vec::new()
            }
        };
        // AGENT-ISO-3: source filtering — keep only faces "reachable in the same subnet or punchable
        // on the public internet". The peer's own overlay address (hairpin) and foreign-subnet
        // addresses (e.g. its ZeroTier address) are all excluded; the peer itself is retained (no usable face = relay, same semantics as no candidate).
        for peer in &mut wanted {
            peer.endpoints
                .retain(|c| is_viable_endpoint(c, &my_lan_subnets, scope));
        }
        // FLIP-001 candidate table reconciliation: insert/refresh the config faces (server authoritative) → reap peers
        // that left the set and expired roaming faces → merge into the effective candidate set (config order first,
        // then new table faces appended sorted by address). SEL-001 hence probes **every known face** (including kernel
        // roaming faces), instead of watching only the server's single endpoint for degradation.
        self.candidates.sync_config(&wanted, now_secs);
        self.candidates.retain_peers(&wanted);
        self.candidates.expire(now_secs);
        // The table may still hold bad faces saved **before** filtering went live
        // (config faces were filtered, but roaming faces are a historical
        // accumulation and do not expire within the TTL) — filtering once more after the merge keeps them out of the probe window, so SEL-002 has no way to pick them as the active face.
        let mut effective = self.candidates.merge_into(&wanted);
        for peer in &mut effective {
            peer.endpoints
                .retain(|c| is_viable_endpoint(c, &my_lan_subnets, scope));
        }
        // SEL-001: candidate set refresh (reused by the probe thread; no extra server request — zero control-plane load).
        self.probe.update_candidates(&effective);
        let handshake_ages = match self.backend.handshake_ages_sync() {
            Ok(ages) => ages,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: handshake ages unavailable");
                BTreeMap::new()
            }
        };
        // Diagnostic snapshot collected once, reused in several places (direct enrich + the handshake
        // fallback of the promotion gate): `wg dump` and latest-handshakes are two projections of the
        // same kernel reading — when latest-handshakes is unreadable during a Windows tunnel flap, the
        // dump's handshake time is still a legitimate promotion-gate input (without it pending never gets handshake evidence and is stuck "dialing" forever).
        let net = match self.backend.diagnostics_sync() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: diagnostics unavailable");
                None
            }
        };
        let handshake_ages =
            merge_handshake_ages(handshake_ages, dump_handshake_ages(net.as_ref(), now_secs));
        // FLIP-001 kernel roaming observation: the current endpoint of each managed peer in the wg
        // dump (the kernel roams as soon as it receives a legitimate authenticated packet from a new
        // source face — the strongest evidence of a peer network change / new face, often absent
        // from the server candidate table). Feed it into the candidate table (valid within TTL); a
        // new face triggers re-merge + probe-cache refresh (the probe thread samples it in one cycle). hub peers and kernel-drift peers are not in the candidate set and not collected.
        let wanted_keys: std::collections::BTreeSet<&str> =
            wanted.iter().map(|p| p.public_key.as_str()).collect();
        if let Some(net) = &net {
            for wg_peer in &net.wg {
                if !wanted_keys.contains(wg_peer.public_key.as_str()) {
                    continue;
                }
                let Some(candidate) = parse_endpoint_candidate(&wg_peer.endpoint) else {
                    continue;
                };
                if self
                    .candidates
                    .observe_roaming(&wg_peer.public_key, candidate, now_secs)
                {
                    tracing::info!(
                        public_key = %wg_peer.public_key,
                        endpoint = %wg_peer.endpoint,
                        "candidate table: new roaming face observed"
                    );
                }
            }
        }
        drop(wanted_keys);
        // This round uniformly uses the effective candidate set with roaming faces (re-merge + probe-cache
        // refresh after observation). AGENT-ISO-3 is applied again: a face the kernel roamed back may be
        // the source address the peer used to route through its ZeroTier (the norm while the peer is not
        // upgraded); feeding it into the probe window lets SEL-002 pick it — i.e. we would actively choose a borrowed path. Roaming is observed and recorded as usual, but **never enters the selectable set**.
        let mut effective = self.candidates.merge_into(&wanted);
        for peer in &mut effective {
            peer.endpoints
                .retain(|c| is_viable_endpoint(c, &my_lan_subnets, scope));
        }
        self.probe.update_candidates(&effective);
        // SEL-003: derive from the probe window whether each peer's **current direct path** is degraded
        // (loss spikes / timeouts / deep RTT degradation — median ≥ degrade_rtt_ms). Only the active
        // endpoint's window counts: backup candidates in the candidate list that never answer ICMP
        // (public NAT / off-subnet LAN) are unrelated to the active path; degrading the whole peer on any candidate's degradation would wrongly demote healthy direct links.
        let current_paths: BTreeMap<_, _> = self
            .direct
            .link_statuses()
            .into_iter()
            .filter(|s| s.link_state == "direct")
            .filter_map(|s| parse_endpoint_candidate(&s.endpoint).map(|c| (s.public_key, c)))
            .collect();
        let degraded = self.probe.degraded_map(&current_paths);
        // promote prefers healthy faces: the set of faces degraded in the current probe window
        // (a pre-filter for promotion routing; see plan_updates_logged — re-promoting on a degraded face would only demote it again immediately).
        let unhealthy_faces = self.probe.degraded_faces();
        // FLIP-001 probe-evidence refresh: a single snapshot batch-collects the set of
        // "probe-confirmed healthy" faces — candidate-table refresh (roaming→discovered
        // promotion, last_seen moved forward) and recovery-gate bypass share one round of readings.
        let healthy_faces = self.probe.healthy_faces();
        self.candidates
            .refresh_probe_evidence(&healthy_faces, now_secs);
        // FLIP-002 health-evidence accounting: the peer has any probe-healthy face this round →
        // healthy rounds +1 (M consecutive rounds clears the backoff); no healthy face → healthy rounds reset to zero (continuity broken, suppression holds).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        for peer in &effective {
            let peer_has_healthy_face = healthy_faces
                .iter()
                .any(|(public_key, _)| public_key == &peer.public_key);
            self.backoff
                .note_health(&peer.public_key, peer_has_healthy_face, now_ms);
        }
        // FLIP-002 suppression table: a suppressed peer is not promoted this round (checked after the
        // domain-layer hold_relay, keeping the remembered face on relay).
        let suppress_promote = self.backoff.suppress_map(now_ms);
        // SEL-003 recovery gate: record this round's health for peers in the direct state; after
        // returning to relay, only N consecutive healthy rounds allow switching back. Healthy =
        // not degraded and handshake age inside the health window. FLIP-001 bypass: when the candidate
        // table holds a probe-healthy face, do not wait for the gate — once the new face is reachable
        // after a network change, go direct, skipping the old "demote first, then wait for the recovery
        // gate" path (the gate only covers "no healthy-face evidence at all"). FLIP-002 suppression wins — during backoff nothing is promoted even with a healthy face (retry interval widened).
        let mut hold_relay = std::collections::BTreeSet::new();
        let mut gate_bypassed: Vec<(String, String)> = Vec::new();
        for peer in &effective {
            let healthy = !degraded.get(&peer.public_key).copied().unwrap_or(false)
                && handshake_ages
                    .get(&peer.public_key)
                    .is_none_or(|age| *age <= meshlet_domain::DIRECT_HEALTH_WINDOW_SECS);
            let ready = self.recovery.record(&peer.public_key, healthy);
            if !ready
                && self
                    .direct
                    .status_of(&peer.public_key)
                    .is_some_and(|p| p.state == PeerLinkState::Relay)
            {
                let faces = self.candidates.faces(&peer.public_key);
                let healthy_face = faces
                    .iter()
                    .find(|(c, _)| healthy_faces.contains(&(peer.public_key.clone(), *c)));
                match healthy_face {
                    Some((face, source)) if !suppress_promote.contains_key(&peer.public_key) => {
                        tracing::info!(
                            public_key = %peer.public_key,
                            face = %face.socket(),
                            source = source.as_str(),
                            "recovery gate bypassed: probe-healthy face in candidate table"
                        );
                        gate_bypassed.push((peer.public_key.clone(), face.socket().to_string()));
                    }
                    _ => {
                        // Back on relay with no healthy-face evidence (or suppressed by backoff):
                        // keep relay (anti-flap switching back / widening the retry interval).
                        hold_relay.insert(peer.public_key.clone());
                    }
                }
            }
        }
        // Reap recovery counters for peers no longer in the candidate set.
        let live_keys: Vec<String> = wanted.iter().map(|p| p.public_key.clone()).collect();
        self.recovery.retain(&live_keys);
        self.backoff.retain(&live_keys);
        let (updates, decisions) = self.direct.apply_plan(
            &effective,
            &my_lan_subnets,
            scope,
            plan.tunnel.address,
            &handshake_ages,
            &degraded,
            &unhealthy_faces,
            &hold_relay,
            &suppress_promote,
        );
        if !updates.is_empty() {
            for update in &updates {
                self.apply_direct_update(update);
                // FLIP-002: demotes produced by degradation/handshake verdicts count toward backoff
                // (consecutive demotes widen the retry interval exponentially). Evictions outside
                // the candidate set and clearing when the switch is turned off do not count — those are administrative removals, not link-quality signals.
                if let DirectUpdate::Demote { public_key } = update {
                    if live_keys.contains(public_key) {
                        self.backoff.on_demote(public_key, now_ms);
                    }
                }
            }
            self.save_direct_ledger();
        }
        // Decision journal (2026-11-14 inspection-sheet observability debt): every classify /
        // switch-gate verdict is appended to the decision log, and a mode flip additionally records
        // a `mode_flip` switch event — degradation/promotion reasons can be replayed afterwards even
        // without a console context (Windows service / schtasks SYSTEM). The verdict input summary (probe window) is looked up against the window snapshot of **this round's** active path.
        self.record_decisions(&decisions, &current_paths);
        // FLIP-001 observation face: recovery-gate bypasses are appended one by one to the decision log
        // (so even without a console context one can replay "why the gate was not waited for").
        self.record_bypass_events(&gate_bypassed, &handshake_ages);
        // R-DIAG-2: refresh readings (wg endpoint/handshake/traffic) for peers in the direct state +
        // measured direct-path RTT — refreshed even when this cycle takes no action, for heartbeat and console/CLI display.
        self.enrich_direct_peers(net.as_ref(), now_secs);
        // SEL-002: hysteresis switching. For a peer with an established direct link, if another
        // path in its candidate window is better for N consecutive samples and ≥30% better than the
        // current path, roam via `wg set endpoint` (zero disconnection) and append a switch event
        // (queryable). Probe disabled / no direct link / no better path are all no-ops — never touching the data-plane loop.
        self.apply_switch_decisions();
        // Publish the direct-peer view (`direct-peers.json`): the data source for the tray's
        // "direct nodes / connected nodes…" submenu and for CLI `peer dial` resolving `<node>` (including candidate-table roaming faces).
        self.publish_direct_peers(&effective);
        if let Some(req) = request {
            self.finish_dial_for_request(&req);
        }
    }

    /// Resolve the dial outcome from the intent: the state machine finished this round; the target peer's current state is the verdict basis.
    fn finish_dial_for_request(&self, req: &DirectDialRequest) {
        let (ok, mode, message) = dial_verdict(self.direct.status_of(&req.public_key));
        self.finish_dial(req, ok, mode, message);
    }

    /// Write the dial result and clear the intent. The result file persists (the CLI polls it); the next dial overwrites it.
    fn finish_dial(&self, req: &DirectDialRequest, ok: bool, mode: &str, message: &str) {
        let result = DirectDialResult {
            request_id: req.request_id.clone(),
            ok,
            mode: mode.into(),
            message: message.into(),
            finished_at: dial::now_millis(),
        };
        if let Err(e) = dial::write_result(Path::new(&self.state_dir), &result) {
            tracing::warn!(error = %e, "direct dial result not written");
        }
        if let Err(e) = dial::clear_request(Path::new(&self.state_dir)) {
            tracing::warn!(error = %e, "direct dial request not cleared");
        }
    }

    /// Publish the direct-peer view: server candidate set merged with current link state (`direct-peers.json`).
    /// Candidates already direct / pending handshake take the link state; candidates with no path (Relay) are marked `hub_relay` (dialable).
    fn publish_direct_peers(&self, wanted: &[meshlet_domain::PeerEndpoints]) {
        let views = direct_peer_views(wanted, &self.direct.link_statuses());
        if let Err(e) = dial::write_direct_peers(Path::new(&self.state_dir), &views) {
            tracing::warn!(error = %e, "direct peers view not published");
        }
    }

    /// R-DIAG-2: refresh each direct peer's real state from the kernel (endpoint / last handshake /
    /// cumulative traffic); RTT takes the newest **runtime background** measured value (never inline `ping`).
    ///
    /// Probe candidates carry the underlay address of the peer's endpoint: when the overlay VIP
    /// does not answer ICMP (the WireGuard interface / firewall often drops packets while the
    /// link is fully alive), the background thread falls back to pinging the endpoint; "measured
    /// failure" only when both paths are unresponsive. rtt_source records the RTT honestly for the
    /// panel/console (probe_ok measured ok; handshake_fresh unmeasurable but fresh; probe_failed both unresponsive and handshake stale; unprobed in flight).
    ///
    /// Read failures are logged only — the display data source is "last known state", never letting
    /// diagnostics disturb the data plane; each record_* no-ops once the peer is no longer managed (demoted this cycle).
    fn enrich_direct_peers(&mut self, net: Option<&NetworkDiagnostics>, now_secs: u64) {
        let candidates = self.direct.direct_candidates();
        if candidates.is_empty() {
            // No direct peers: clear the RTT candidates (the background thread no-ops next round).
            self.direct_rtt.update_candidates(Vec::new());
            return;
        }
        // net is passed in by the caller (reconcile already collected it once, avoiding a duplicate `wg dump`);
        // None = the read failed, so no fallback path is available and only overlay probing runs (same as the old behaviour).
        let probed: Vec<RttCandidate> = candidates
            .into_iter()
            .map(|(public_key, vip)| {
                let endpoint_ip = net.as_ref().and_then(|net| {
                    net.wg
                        .iter()
                        .find(|p| p.public_key == public_key)
                        .map(|p| p.endpoint.clone())
                        .unwrap_or_default()
                        .rsplit_once(':')
                        .and_then(|(host, _)| host.parse::<Ipv4Addr>().ok())
                });
                (public_key, vip, endpoint_ip)
            })
            .collect();
        // The background thread pings per the latest candidate set; the main loop only reads the snapshot, never waiting on any ping.
        self.direct_rtt.update_candidates(probed.clone());
        let rtts = self.direct_rtt.snapshot();
        for (public_key, vip, _endpoint_ip) in probed {
            let wg_peer = net
                .as_ref()
                .and_then(|net| net.wg.iter().find(|p| p.public_key == public_key));
            let endpoint = wg_peer.map(|p| p.endpoint.clone()).unwrap_or_default();
            let last_handshake_at =
                wg_peer.and_then(|p| (p.last_handshake > 0).then_some(p.last_handshake));
            let (rx_bytes, tx_bytes) = wg_peer.map(|p| (p.rx_bytes, p.tx_bytes)).unwrap_or((0, 0));
            // Read the snapshot: the first read right after updating the candidate set may have no measured value
            // yet (None = unknown, consistent with "read failed", the display source being last known state). `vip` exists only to be logged.
            let probe = rtts
                .get(&public_key)
                .copied()
                .unwrap_or_else(RttProbe::unknown);
            let _ = vip;
            self.direct.record_peer_status(
                &public_key,
                probe.rtt_ms,
                honest_rtt_source(&probe, last_handshake_at, now_secs),
                last_handshake_at,
                rx_bytes,
                tx_bytes,
            );
            if !endpoint.is_empty() {
                self.direct.record_endpoint(&public_key, endpoint.clone());
            }
            // SEL-004: aggregate candidate endpoint details (endpoint / RTT / loss / current selection and reason),
            // for the heartbeat report → console peer detail rendering.
            let statuses = self.probe.candidate_statuses(&public_key, &endpoint);
            self.direct.record_candidates(&public_key, statuses);
        }
    }

    /// SEL-002: evaluate the hysteresis gate for every peer with an established direct link, roaming the endpoint when needed.
    ///
    /// Only peers in the `direct` state are touched (`direct_pending` is not yet verified and `Relay`
    /// has no direct link, so switching is meaningless). A failed `wg set endpoint` is logged only —
    /// direct is still a gain: keep the current endpoint and retry next cycle; only on success is a switch event recorded (appended by [`dial`]).
    fn apply_switch_decisions(&mut self) {
        if !self.dataplane.probe.enabled {
            return;
        }
        // Current-path candidate (endpoint) parsing + the direct-peer set: only non-Relay peers are evaluated.
        let statuses = self.direct.link_statuses();
        for status in statuses {
            if status.link_state != "direct" {
                continue;
            }
            let Some(current) = parse_endpoint_candidate(&status.endpoint) else {
                // No direct endpoint applied yet (anomalous state): no switching.
                continue;
            };
            // Plan 8: one-shot rollback of the old endpoint within the switch grace window — when the
            // new face goes "from good to persistently fully dark" (the window has an RTT baseline
            // plus consecutive Lost at the end), fall back to the pre-switch old face, saving the relay
            // detour of demote→recovery gate→re-promote. Permission (within grace + one-shot, the rollback
            // also passes grace) is decided uniformly inside the gate; a `wg set` failure is logged only (the one-shot is consumed; the next cycle re-judges by the normal gate).
            if let Some(old) = self.probe.switch_rollback(&status.public_key, current) {
                if let Err(e) = self
                    .backend
                    .set_direct_endpoint_sync(&status.public_key, old.socket())
                {
                    tracing::warn!(
                        public_key = %status.public_key,
                        error = %e,
                        "direct endpoint rollback failed; keeping current path"
                    );
                    continue;
                }
                let event = dial::SwitchEvent {
                    public_key: status.public_key.clone(),
                    from: status.endpoint.clone(),
                    to: old.socket().to_string(),
                    reason: "rollback within switch grace: path lost probe baseline".into(),
                    at_ms: dial::now_millis(),
                    kind: None,
                    detail: None,
                    ts: Some(dial::rfc3339_now()),
                };
                if let Err(e) = dial::append_switch_event(Path::new(&self.state_dir), &event) {
                    tracing::warn!(error = %e, "direct rollback event not recorded");
                }
                tracing::info!(
                    public_key = %status.public_key,
                    from = %event.from,
                    to = %event.to,
                    "direct endpoint rolled back (switch grace)"
                );
                self.direct
                    .record_endpoint(&status.public_key, event.to.clone());
                continue;
            }
            let Some(decision) = self
                .probe
                .evaluate_switch(&status.public_key, Some(current))
            else {
                continue;
            };
            if let Err(e) = self
                .backend
                .set_direct_endpoint_sync(&status.public_key, decision.to.socket())
            {
                tracing::warn!(
                    public_key = %status.public_key,
                    error = %e,
                    "direct endpoint switch failed; keeping current path"
                );
                continue;
            }
            let event = dial::SwitchEvent {
                public_key: status.public_key.clone(),
                from: status.endpoint.clone(),
                to: decision.to.socket().to_string(),
                reason: decision.reason.clone(),
                at_ms: dial::now_millis(),
                kind: None,
                detail: None,
                ts: Some(dial::rfc3339_now()),
            };
            if let Err(e) = dial::append_switch_event(Path::new(&self.state_dir), &event) {
                tracing::warn!(error = %e, "direct switch event not recorded");
            }
            tracing::info!(
                public_key = %status.public_key,
                from = %event.from,
                to = %event.to,
                reason = %event.reason,
                "direct endpoint switched (SEL-002)"
            );
            // Update the endpoint recorded by the direct-connect manager (the next round uses it as the current-path baseline).
            self.direct
                .record_endpoint(&status.public_key, event.to.clone());
        }
    }

    /// Decision journal (2026-11-14 inspection sheet: post-hoc replay without a console context):
    /// every state-machine verdict is appended to the decision log (`{state_dir}/agent-decisions.jsonl`,
    /// rolling on overflow); a mode flip (`from_mode ≠ to_mode`) additionally records a `mode_flip`
    /// switch event into `direct-switch-events.json` (old fields untouched, backward compatible).
    /// Write failures are logged only — observation is a gain and never disturbs the data-plane loop.
    fn record_decisions(
        &self,
        decisions: &[PeerDecisionRecord],
        current_paths: &BTreeMap<String, meshlet_domain::EndpointCandidate>,
    ) {
        let state_dir = Path::new(&self.state_dir);
        for d in decisions {
            let probe_window = current_paths
                .get(&d.public_key)
                .and_then(|c| self.probe.window_summary(&d.public_key, *c));
            let event = dial::DecisionEvent {
                ts: dial::rfc3339_now(),
                public_key: d.public_key.clone(),
                peer_name: d.peer_name.clone(),
                action: d.action.to_string(),
                from_mode: d.from_mode.to_string(),
                to_mode: d.to_mode.to_string(),
                reason: d.reason.clone(),
                handshake_age_secs: d.handshake_age_secs,
                degraded: d.degraded,
                endpoint: d.endpoint.clone(),
                probe_window,
            };
            if let Err(e) = dial::append_decision_event(state_dir, &event) {
                tracing::warn!(error = %e, "decision log not written");
            }
            if d.from_mode != d.to_mode {
                let flip = dial::SwitchEvent {
                    public_key: d.public_key.clone(),
                    from: d.from_mode.to_string(),
                    to: d.to_mode.to_string(),
                    reason: d.reason.clone(),
                    at_ms: dial::now_millis(),
                    kind: Some(dial::SWITCH_KIND_MODE_FLIP.into()),
                    detail: Some(format!(
                        "hs_age={:?} degraded={} ep={}",
                        d.handshake_age_secs, d.degraded, d.endpoint
                    )),
                    ts: Some(event.ts.clone()),
                };
                if let Err(e) = dial::append_switch_event(state_dir, &flip) {
                    tracing::warn!(error = %e, "mode flip event not recorded");
                }
                tracing::info!(
                    public_key = %d.public_key,
                    from = %d.from_mode,
                    to = %d.to_mode,
                    reason = %d.reason,
                    "direct mode flipped"
                );
            }
        }
    }

    /// FLIP-001: recovery-gate bypasses are appended one by one to the decision log (`agent-decisions.jsonl`,
    /// action=`probe` with the reason tagged FLIP-001, the endpoint being the healthy face that served as bypass evidence).
    /// Write failures are logged only — observation is a gain and never disturbs the data-plane loop.
    fn record_bypass_events(
        &self,
        bypassed: &[(String, String)],
        handshake_ages: &BTreeMap<String, u64>,
    ) {
        let state_dir = Path::new(&self.state_dir);
        for (public_key, face) in bypassed {
            let probe_window = parse_endpoint_candidate(face)
                .and_then(|c| self.probe.window_summary(public_key, c));
            let event = dial::DecisionEvent {
                ts: dial::rfc3339_now(),
                public_key: public_key.clone(),
                peer_name: self
                    .direct
                    .status_of(public_key)
                    .map(|p| p.peer_name.clone())
                    .unwrap_or_default(),
                action: "probe".into(),
                from_mode: "hub_relay".into(),
                to_mode: "hub_relay".into(),
                reason: "recovery gate bypassed: face probe-healthy (FLIP-001)".into(),
                handshake_age_secs: handshake_ages.get(public_key).copied(),
                degraded: false,
                endpoint: face.clone(),
                probe_window,
            };
            if let Err(e) = dial::append_decision_event(state_dir, &event) {
                tracing::warn!(error = %e, "bypass decision log not written");
            }
        }
    }

    /// Persist the direct keep set (§12 restart recovery): failures are logged only — losing the ledger costs
    /// at most one probe cycle to rebuild the direct link, never affecting the data-plane loop.
    fn save_direct_ledger(&self) {
        if let Err(e) = self.direct.save(&self.direct_ledger) {
            tracing::warn!(
                error = %e,
                "direct ledger not written; keep set may be rebuilt on restart"
            );
        }
    }

    /// Apply a single direct-connect action (`wg set`): failures are logged only — direct is a gain, never
    /// rolling back the hub (the peer stays reachable via the hub full route). On success, record/clear the peer's
    /// endpoint (the data source for §12.3 status reporting and the console/CLI direct-peers display).
    fn apply_direct_update(&mut self, update: &DirectUpdate) {
        match update {
            DirectUpdate::Promote {
                public_key,
                allowed_ips,
                endpoint,
            } => {
                if let Err(e) = self.backend.set_direct_peer_sync(
                    public_key,
                    allowed_ips,
                    *endpoint,
                    keepalive_secs(),
                ) {
                    tracing::warn!(
                        public_key = %public_key,
                        error = %e,
                        "direct promote failed; keeping hub relay"
                    );
                } else {
                    tracing::info!(
                        public_key = %public_key,
                        endpoint = %endpoint,
                        "direct link promoted"
                    );
                    self.direct
                        .record_endpoint(public_key, endpoint.to_string());
                }
            }
            DirectUpdate::Demote { public_key } => {
                if let Err(e) = self.backend.remove_peer_sync(public_key) {
                    tracing::warn!(
                        public_key = %public_key,
                        error = %e,
                        "direct demote failed; hub relay already covers this peer"
                    );
                } else {
                    tracing::info!(public_key = %public_key, "direct link demoted to hub relay");
                    self.direct.clear_endpoint(public_key);
                }
            }
        }
    }
}
