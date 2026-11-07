//! reconcile
use crate::agent::plan_adapter::{enforce_hub_keepalive, plan_with_hub_endpoint};
use crate::reconcile::{AgentState, Decision};

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
        // §12：直连保留集来自**ledger 恢复 + 探测周期状态机**，不从内核猜——
        // 内核里非 hub 的 peer 若非自有直连，必须按漂移清掉（外来 peer 注入
        // 的真机验收）。keep set 传给内核对账：直连对端被保留，不被重放冲掉。
        let direct_keys = self.direct.keep_keys();
        let mut local_plan = plan_with_hub_endpoint(plan, self.dataplane.hub_endpoint.as_deref());
        local_plan.tunnel.name = self.dataplane.interface.clone();
        // SEL-003 hub 兜底：hub peer 的 keepalive 永不掉——计划里低于常量
        // （或旧版计划缺省 `None`）都强制抬到 [meshlet_network::HUB_KEEPALIVE_SECS]。
        enforce_hub_keepalive(&mut local_plan);
        // §12：直连开启时把 wg 接口绑定到配置的监听端口——直连对端按
        // `listen_port` 发包（`direct_report` 上报的正是它）。本地改写不影响
        // 期望哈希（与 hub_endpoint 兜底同一口径）。
        if self.dataplane.direct_connect.enabled {
            local_plan.tunnel.listen_port = Some(self.dataplane.direct_connect.listen_port);
        }
        for route in &mut local_plan.routes {
            route.interface = self.dataplane.interface.clone();
        }
        for rule in &mut local_plan.nat_rules {
            // `-i` 只对 PREROUTING 生效（`iptables_args` 同一口径）；改写
            // POSTROUTING 规则的惰性元数据只会让指纹对不上内核。
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
        if !decision.needs_apply {
            return Ok(decision);
        }
        // 先按所有权清理计划里已消失的映射单元（§12.6），再重放隧道/路由/NAT。
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
        // hub 入口地址兜底（§16.4：服务端不下发 agent 的网络位置）：计划未带
        // endpoint 时用本地 `[dataplane] hub_endpoint` 填充——只影响本次内核下
        // 发，账本仍按服务端原计划记（desired_config_hash 不因此变化）。
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
        // 本机公钥指纹入账本（BUG② 漂移判定）：对账据此识别「peer 一致但
        // 本机私钥被换」的手动隧道。推导失败（wg 缺失等）按缺省留空——
        // 漂移判定对空指纹不判，下轮重放成功后再补齐。
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
