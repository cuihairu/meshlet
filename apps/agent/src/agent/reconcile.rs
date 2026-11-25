//! reconcile
use crate::agent::direct_port::{self, PortResolution};
use crate::agent::hub_failover::{self, HUB_HANDSHAKE_STALE_SECS};
use crate::agent::plan_adapter::{enforce_hub_keepalive, plan_with_hub_endpoint};
use crate::reconcile::{AgentState, Decision};

use meshlet_config::TunnelBackend;
use meshlet_network::DevicePlan;

use crate::reconcile::{needs_apply, stale_owners};

impl super::Agent {
    pub fn reconcile(&mut self, plan: &DevicePlan) -> Result<Decision, String> {
        let ledger = AgentState::load(&self.state_path);
        let state = ledger.clone().unwrap_or_default();
        let ledger_present = ledger.is_ok();
        let last_good = match ledger.as_ref() {
            Ok(entry) => entry.last_good_plan.clone(),
            Err(_) => None,
        };
        let snapshot = self
            .backend
            .inspect_sync()
            .map_err(|e| format!("inspect the local network state: {e}"))?;
        // §12: the direct keep-set comes from **ledger recovery + the probe-cycle state machine**, never
        // guessed from the kernel - a non-hub peer in the kernel that is not one of our own directs must be
        // cleared as drift (real-machine acceptance of injected foreign peers). The keep set is passed to the
        // kernel reconciliation: direct peers are preserved and not washed away by the replay.
        let direct_keys = self.direct.keep_keys();
        // Hub endpoint fallback + multi-endpoint failover (`hub_endpoint = "a:51820,b:51820"`):
        // with a single/zero endpoints the behavior is byte-identical to the old version (no handshake
        // lookup, no ledger write, no forced replay); with multiple endpoints, rotate candidates by the
        // incumbent's handshake age (incumbent dead -> next one), and a rotation forces a replay.
        let (hub_endpoint, hub_rotated) = self.select_hub_endpoint(plan);
        let mut local_plan = plan_with_hub_endpoint(plan, hub_endpoint.as_deref());
        local_plan.tunnel.name = self.dataplane.interface.clone();
        // SEL-003 hub fallback: the hub peer's keepalive never drops - any value in the plan below the constant
        // (or an old-version plan's default `None`) is forcibly raised to [meshlet_network::HUB_KEEPALIVE_SECS].
        enforce_hub_keepalive(&mut local_plan);
        // §12: with direct connect on, pin the wg interface to the "effective listen port" - the conf rendering, the
        // firewall allow (ensure_direct_udp_firewall_sync inside apply_device_plan_sync), and the direct_report
        // report must all use the same port (the WIN-PORT-1 B2 hard invariant). The effective port is resolved
        // here every round (on Windows, when the configured port is blocked by an excluded range or an occupant, a
        // probe fallback kicks in to prevent a `WireGuardTunnel$` 0xc0000022 bind failure; Linux always takes the
        // configured port, behavior unchanged). The local rewrite does not affect the desired hash (the same
        // footing as the hub_endpoint fallback).
        //
        // The nt model (tunnel_backend="nt") always needs a concrete listen port for its adapter:
        // wireguard-nt's `SetInterface.listen_port: None` does not mean "let the OS choose" but lands on the
        // default 51820 (design doc §2.5), and multiple networks (multiple adapters) landing there are guaranteed
        // to collide. So even with direct connect off, the nt model goes through the same probe-bind resolution to
        // allocate a collision-free port; that port does not become a direct candidate - direct_report is still
        // gated on direct_connect.enabled, and the firewall allow was always a precondition for the adapter
        // receiving packets (hub relay included). Linux behavior is unchanged (nt only applies to Windows).
        let nt_needs_port =
            cfg!(target_os = "windows") && self.dataplane.tunnel_backend == TunnelBackend::Nt;
        if self.dataplane.direct_connect.enabled || nt_needs_port {
            let configured = self.dataplane.direct_connect.listen_port;
            let is_windows = cfg!(target_os = "windows");
            let persisted = direct_port::load(&self.state_dir);
            match direct_port::resolve(
                configured,
                snapshot.tunnel_listen_port,
                persisted,
                is_windows,
                &direct_port::probe_bind,
            ) {
                PortResolution::Port(port) => {
                    // The ledger is written only on Windows (incumbency evidence against churn; Linux behavior
                    // unchanged), and only when the resolution changes - the 30s poll does not write repeatedly.
                    if is_windows && persisted != Some(port) {
                        if let Err(error) = direct_port::save(&self.state_dir, Some(port)) {
                            tracing::warn!(error = %error, "direct-port ledger not saved");
                        }
                        tracing::info!(port, configured, "direct listen port resolved");
                    }
                    if self.direct_port_blocked {
                        tracing::info!(port, "direct listen port recovered");
                        self.direct_port_blocked = false;
                    }
                    local_plan.tunnel.listen_port = Some(port);
                    self.resolved_direct_port = Some(port);
                }
                PortResolution::Blocked => {
                    // Report the error explicitly (recorded once when entering the state, never spammed every
                    // round): direct connect is gated shut - the plan pins no port (the hub relay's overlay is
                    // unaffected), and direct_report reports no candidates (reporting a port this machine cannot
                    // bind just points the peer at a dead port).
                    if !self.direct_port_blocked {
                        tracing::error!(
                            configured,
                            "direct connect blocked: no bindable UDP listen port (configured \
                             port and fallbacks all rejected); inspect with `netsh interface \
                             ipv4 show excludedportrange protocol=udp`"
                        );
                        self.direct_port_blocked = true;
                        if is_windows {
                            if let Err(error) = direct_port::save(&self.state_dir, None) {
                                tracing::warn!(error = %error, "direct-port ledger not saved");
                            }
                        }
                    }
                    local_plan.tunnel.listen_port = None;
                    self.resolved_direct_port = None;
                }
            }
        }
        for route in &mut local_plan.routes {
            route.interface = self.dataplane.interface.clone();
        }
        for rule in &mut local_plan.nat_rules {
            // `-i` only applies to PREROUTING (the same footing as `iptables_args`); rewriting the lazy
            // metadata of POSTROUTING rules would only make the fingerprints disagree with the kernel.
            if rule.chain == meshlet_network::nat::NatChain::Prerouting {
                rule.incoming_interface = Some(self.dataplane.interface.clone());
            }
        }
        local_plan.tunnel.private_key = self.private_key.clone();
        let mut decision = needs_apply(&state, &snapshot, plan, &direct_keys);
        if !decision.needs_apply
            && !self
                .backend
                .device_plan_matches_sync(&local_plan, &direct_keys)
                .unwrap_or(false)
        {
            decision = Decision {
                needs_apply: true,
                reason: crate::reconcile::Reason::KernelDrift,
            };
        }
        // Hub endpoint rotation: the local fallback takes no part in the desired hash (the same footing as the
        // hub_endpoint fallback), so the ledger's drift verdict cannot see the new endpoint - the rotation must
        // explicitly force one replay to push the new endpoint down to the kernel.
        if !decision.needs_apply && hub_rotated {
            decision = Decision {
                needs_apply: true,
                reason: crate::reconcile::Reason::HubEndpointRotated,
            };
        }
        if !decision.needs_apply {
            return Ok(decision);
        }
        // First clean up mapping units that vanished from the plan, by ownership (§12.6), then replay tunnel/routing/NAT.
        let kernel_nat_owners = self
            .backend
            .meshlet_nat_owners_sync()
            .map_err(|e| format!("enumerate meshlet nat owners: {e}"))?;
        for owner in stale_owners(&state, plan, &kernel_nat_owners, ledger_present) {
            if let Err(error) = self.backend.remove_nat_sync(&owner) {
                return Err(self.fail_transition(
                    last_good.as_ref(),
                    format!("remove meshlet nat rules of {owner}: {error}"),
                ));
            }
            tracing::info!(owner = %owner, "removed stale meshlet nat rules");
        }
        if let Err(error) = self
            .backend
            .remove_stale_meshlet_routes_sync(&local_plan.routes)
        {
            return Err(self.fail_transition(
                last_good.as_ref(),
                format!("remove stale meshlet routes: {error}"),
            ));
        }
        // Hub entry-address fallback (§16.4: the server does not deliver the agent's network location): when the
        // plan carries no endpoint, fill it from the local `[dataplane] hub_endpoint` - this only affects this
        // kernel push; the ledger still records the server's original plan (desired_config_hash does not change because of it).
        let transition = self.backend.apply_device_plan_sync(
            &local_plan,
            self.private_key.clone(),
            None,
            &direct_keys,
        );
        if let Err(error) = transition {
            return Err(self.fail_transition(
                last_good.as_ref(),
                format!("apply the desired plan: {error}"),
            ));
        }
        let matches = self
            .backend
            .device_plan_matches_sync(&local_plan, &direct_keys)
            .map_err(|error| {
                self.fail_transition(
                    last_good.as_ref(),
                    format!("read back the desired plan: {error}"),
                )
            })?;
        if !matches {
            return Err(self.fail_transition(
                last_good.as_ref(),
                "applied plan did not match kernel readback".to_string(),
            ));
        }
        let mut ledger_plan = local_plan;
        ledger_plan.tunnel.private_key = None;
        // The local public key fingerprint enters the ledger (BUG(2) drift detection): reconciliation uses it to
        // recognize a manual tunnel where "the peers match but this machine's private key was swapped". On a
        // derivation failure (missing wg, etc.), leave it empty - the drift verdict skips empty fingerprints and
        // the value is backfilled after a successful replay next round.
        let mut ledger = AgentState::from_plan(&ledger_plan);
        if let Some(key) = &self.private_key {
            if let Ok(public_key) = self.backend.public_key_from_private(key) {
                ledger.local_public_key = public_key;
            }
        }
        ledger.save(&self.state_path)?;
        tracing::info!(
            desired_config_hash = %plan.desired_config_hash,
            routes = plan.routes.len(),
            nat_rules = plan.nat_rules.len(),
            reason = ?decision.reason,
            "applied the desired device plan"
        );
        Ok(decision)
    }

    /// Hub endpoint fallback selection (with multi-endpoint failover, UI batch B3).
    ///
    /// Returns `(selected endpoint, whether a rotation happened)`. Single/zero endpoints: no handshake
    /// lookup, no ledger write, take the configured value directly (byte-identical to the old
    /// `plan_with_hub_endpoint(plan, hub_endpoint)` behavior); multiple endpoints: read the hub handshake age
    /// and rotate via [`hub_failover::decide`], persisting the rotation/preference in the ledger
    /// (`{state_dir}/hub-endpoint.json`).
    fn select_hub_endpoint(&mut self, plan: &DevicePlan) -> (Option<String>, bool) {
        let endpoints = self.dataplane.hub_endpoints();
        if endpoints.is_empty() {
            return (None, false);
        }
        if endpoints.len() == 1 {
            return (Some(endpoints[0].clone()), false);
        }
        // Health is only consulted with multiple endpoints (a single endpoint costs nothing extra - the old
        // behavior is unchanged). The hub peer is always plan tunnel.peers[0] (the server plan is built with a single hub peer).
        let hub_public_key = plan.tunnel.peers.first().map(|p| p.public_key.clone());
        let hub_age = match hub_public_key {
            Some(key) => self
                .backend
                .handshake_ages_sync()
                .ok()
                .and_then(|ages| ages.get(&key).copied()),
            None => None,
        };
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        // Grace period after a rotation while waiting for the first handshake: two polling periods (floor 60s)
        // - enough margin for a fresh start and the handshake after the first apply, so a rotation is never spurious.
        let grace_ms = (2 * self.dataplane.poll_interval_secs * 1000).max(60_000);
        let current = hub_failover::load(&self.state_dir);
        let decision = hub_failover::decide(
            &endpoints,
            current.as_ref(),
            hub_age,
            now_ms,
            HUB_HANDSHAKE_STALE_SECS,
            grace_ms,
        );
        if decision.save {
            if let Err(error) = hub_failover::save(&self.state_dir, &decision.ledger) {
                tracing::warn!(error = %error, "hub-endpoint ledger not saved");
            }
            tracing::info!(
                index = decision.index,
                endpoint = %decision.endpoint,
                rotated = decision.rotate,
                "hub endpoint selected"
            );
        }
        (Some(decision.endpoint), decision.rotate)
    }

    pub(super) fn fail_transition(
        &mut self,
        last_good: Option<&DevicePlan>,
        transition_error: String,
    ) -> String {
        match last_good {
            None => transition_error,
            Some(last_good) => {
                let direct_keys = self.direct.keep_keys();
                match self.backend.apply_device_plan_sync(
                    last_good,
                    self.private_key.clone(),
                    None,
                    &direct_keys,
                ) {
                    Ok(()) => {
                        let restored = self
                            .backend
                            .device_plan_matches_sync(last_good, &direct_keys)
                            .map_err(|e| e.to_string());
                        match restored {
                        Ok(true) => {
                            tracing::warn!(
                                error = %transition_error,
                                "restored the last successful device plan"
                            );
                            format!("{transition_error}; restored last good plan")
                        }
                        Ok(false) => format!(
                            "{transition_error}; restore failed: kernel readback did not match last good plan"
                        ),
                        Err(error) => format!(
                            "{transition_error}; restore readback failed: {error}"
                        ),
                    }
                    }
                    Err(restore_error) => {
                        tracing::error!(
                            error = %transition_error,
                            restore_error = %restore_error,
                            "could not restore the last successful device plan"
                        );
                        format!("{transition_error}; restore failed: {restore_error}")
                    }
                }
            }
        }
    }
}
