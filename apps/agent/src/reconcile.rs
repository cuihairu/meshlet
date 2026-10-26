//! 对账决策（**纯逻辑**：不碰内核，可无特权单测）。
//!
//! agent 只消费服务端下发的结构化计划（§16.4），需要判断的是「现在要不要重放」：
//! - 期望配置哈希变了（服务端有新修订）→ 改；
//! - 本机没有账本（首次安装 / 状态文件丢失）→ 改；
//! - 内核实际对象与期望不符（隧道没了 / 路由少了一条 / NAT 规则不见了）→ 改，
//!   这正是「主机重启后隧道消失但账本仍记 applied」（TODO #32）的修复路径；
//! - 三者都不成立 → 不改（有变更才重放，§10.1，幂等且不打扰现网）。
//!
//! NAT 清理按**所有权注释**（`meshlet alias {id}`，§12.6）：账本里装过、计划里
//! 不再出现的单元才移除——绝不触碰非 Meshlet 规则，也绝不误删计划里还在的规则。

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use meshlet_network::nat::NatRule;
use meshlet_network::{DevicePlan, NetworkSnapshot};
use serde::{Deserialize, Serialize};

/// 账本状态文件（`{state_dir}/applied.json`）：上次**真正应用成功**的计划
/// 摘要。文件损坏或缺失按「无账本」处理（触发重放，而不是假装已生效）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentState {
    /// 已应用的 `desired_config_hash`（与修订簿记同一来源）。
    pub desired_config_hash: String,
    /// 已应用的隧道地址（`a.b.c.d`）：隧道是否还是那一条的直接证据。
    #[serde(default)]
    pub tunnel_address: String,
    /// 已应用的路由目的前缀。
    #[serde(default)]
    pub routes: Vec<String>,
    /// 已应用的 NAT 规则指纹集合（`chain|match|action|owner`，与顺序无关）——
    /// 与计划不一致即触发按所有权注释的整单元清理 + 重新下发。
    #[serde(default)]
    pub nat_rules: Vec<String>,
    /// 已应用的 NAT 所有权单元（`meshlet alias {id}`）：删除映射时按它精确清理。
    #[serde(default)]
    pub nat_owners: Vec<String>,
    /// 最近一次应用成功时刻（ISO-8601 UTC，排查用；不影响决策）。
    #[serde(default)]
    pub applied_at: String,
    /// The full plan last applied to the kernel. It is the rollback source for
    /// a failed transition; older ledgers without this field replay safely.
    #[serde(default)]
    pub last_good_plan: Option<DevicePlan>,
}

/// 账本路径：`{state_dir}/applied.json`。
pub fn state_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("applied.json")
}

impl AgentState {
    /// 由一份计划生成「已应用」账本（应用成功后才写）。
    pub fn from_plan(plan: &DevicePlan) -> Self {
        Self {
            desired_config_hash: plan.desired_config_hash.clone(),
            tunnel_address: plan.tunnel.address.to_string(),
            routes: prefixes(plan.routes.iter().map(|r| r.destination)),
            nat_rules: rule_signatures(&plan.nat_rules),
            nat_owners: owners(&plan.nat_rules),
            applied_at: now(),
            last_good_plan: Some(plan.clone()),
        }
    }

    /// 读账本（不存在或损坏 → 默认空账本，调用方据此重放）。
    pub fn load(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&raw).map_err(|e| format!("parse {}: {e}", path.display()))
    }

    /// 原子落盘：先写临时文件再 rename——进程被杀不会留下半个 JSON。
    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        }
        let tmp = path.with_extension("json.tmp");
        let body = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&tmp, body).map_err(|e| format!("write {}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename into {}: {e}", path.display()))?;
        Ok(())
    }
}

/// 是否需要重放 + 判定原因（可观测，不只给 yes/no）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub needs_apply: bool,
    pub reason: Reason,
}

/// 重放原因：出现任意一条即必须重放。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// 无需变更（有变更才重放，§10.1）。
    UpToDate,
    /// 期望配置哈希变了：服务端有新修订。
    DesiredConfigChanged,
    /// 本机无账本（首装 / 状态文件丢失）。
    NoLocalLedger,
    /// 内核实际对象与账本不符：隧道/路由/NAT 漂移或丢失（TODO #32）。
    KernelDrift,
}

impl Reason {
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::UpToDate => "up_to_date",
            Reason::DesiredConfigChanged => "desired_config_changed",
            Reason::NoLocalLedger => "no_local_ledger",
            Reason::KernelDrift => "kernel_drift",
        }
    }
}

/// 对账：账本 vs 内核实际 vs 服务端期望。
///
/// 判定顺序：先看期望哈希（真变更优先说真变更），再看账本，最后看内核漂移。
pub fn needs_apply(state: &AgentState, snapshot: &NetworkSnapshot, plan: &DevicePlan) -> Decision {
    let reason = if state.desired_config_hash.is_empty() {
        Reason::NoLocalLedger
    } else if state.desired_config_hash != plan.desired_config_hash {
        Reason::DesiredConfigChanged
    } else if drifted(state, snapshot, plan) {
        Reason::KernelDrift
    } else {
        Reason::UpToDate
    };
    Decision {
        needs_apply: reason != Reason::UpToDate,
        reason,
    }
}

/// Kernel state versus desired drift（身份级，非数量级）。
///
/// 每一项都按**对象身份**判，不按计数——「数量相同」不代表「身份相同」：
/// - 隧道：不存在，或地址与期望不是同一个 → 漂移（重启后接口消失是常态）；
/// - peer：期望与实际按 `公钥 → allowed-ips` 集合逐项比对。少一个（手工删
///   peer）、多一个（受管接口上多装的本 meshlet peer）、allowed-ips 被改宽，
///   三条都判漂移；
/// - 路由：期望里有的目的前缀没装上，或受管接口上出现带 Meshlet 标记但不
///   再期望的路由 → 漂移（未标记路由属他人，不进观测集合）；
/// - NAT：期望与实际按规则指纹集合精确比对（所有权注释认领，重启清空
///   iptables 后两边都空也一致）。
fn drifted(state: &AgentState, snapshot: &NetworkSnapshot, plan: &DevicePlan) -> bool {
    if !snapshot.tunnel_exists || snapshot.forwarding_enabled != Some(true) {
        return true;
    }
    if !state.tunnel_address.is_empty() && state.tunnel_address != plan.tunnel.address.to_string() {
        return true;
    }
    // MTU：计划显式配置而内核读数不符 → 漂移（手工改动 / 半途失败的纠回）。
    // 计划未配置 MTU 时不判：内核默认值或管理员有意设置都不算违背计划。
    if plan.tunnel.mtu.is_some() && snapshot.tunnel_mtu != plan.tunnel.mtu {
        return true;
    }
    // Peer 身份（不是条数）：公钥 → allowed-ips 两侧逐项比对。数量相同但换了
    // 一个 peer、或某个 peer 的 allowed-ips 被改宽，与「少一个 peer」同样必须
    // 重放纠回——受管接口上的 peer 都是 Meshlet 自有对象，多出即漂移。
    let ips = |cidrs: &[meshlet_domain::Ipv4Cidr]| -> BTreeSet<String> {
        cidrs.iter().map(ToString::to_string).collect()
    };
    let expected_peers = plan
        .tunnel
        .peers
        .iter()
        .map(|peer| (peer.public_key.clone(), ips(&peer.allowed_ips)))
        .collect::<BTreeSet<_>>();
    let observed_peers = snapshot
        .peers
        .iter()
        .map(|peer| (peer.public_key.clone(), ips(&peer.allowed_ips)))
        .collect::<BTreeSet<_>>();
    if expected_peers != observed_peers {
        return true;
    }
    let installed: BTreeSet<String> = snapshot
        .installed_routes
        .iter()
        .map(|c| c.to_string())
        .collect();
    let missing = plan
        .routes
        .iter()
        .map(|r| r.destination.to_string())
        .any(|d| !installed.contains(&d));
    if missing {
        return true;
    }
    // A route previously installed by the same interface but no longer desired
    // is Meshlet-owned drift. Applying routes then removes it without sweeping
    // connected or foreign paths.
    let extra = snapshot.installed_routes.iter().any(|installed| {
        !plan
            .routes
            .iter()
            .any(|route| &route.destination == installed)
    });
    if extra {
        return true;
    }
    // NAT 身份：规则指纹集合精确比对（不是「有没有 NAT 规则」）。少一条要装的
    // DNAT/SNAT、或多出一条 Meshlet 注释下的规则（下发只增不删，旧单元残留），
    // 都必须重放；计划里已无 NAT 而内核里还有 Meshlet 规则（网关降级、映射被
    // 删但清理失败）同样命中。观测集合只含注释前缀认领的规则，非本 meshlet
    // 规则在此不可见，永远不会被判成漂移。
    let expected_nat: BTreeSet<String> =
        plan.nat_rules.iter().map(|rule| rule.signature()).collect();
    let observed_nat: BTreeSet<String> = snapshot.nat_rules.iter().cloned().collect();
    expected_nat != observed_nat
}

/// 本轮重放前要按所有权注释清理的 NAT 单元（§12.6 精确清理）。
///
/// 判据是**规则集合是否还一致**，不是「owner 是否还在」：
/// - 账本装过、计划里整个映射消失 → 该 owner 全部规则清理；
/// - 映射还在但规则集合变了（翻译模式 `dnat_snat` ↔ `dnat_only` 等）→ 同样
///   先整单元清理，随后 [`apply_device_plan_sync`] 按计划重新下发，避免
///   旧规则残留（backend 的下发只增不删，残留不会被自动发现）。
///
/// 只按 `meshlet alias {id}` 注释删规则，绝不触碰非 Meshlet 规则。
pub fn stale_owners(
    state: &AgentState,
    plan: &DevicePlan,
    kernel_owners: &[String],
    ledger_present: bool,
) -> Vec<String> {
    if !ledger_present {
        return kernel_owners.to_vec();
    }
    if rule_signatures(&plan.nat_rules) == state.nat_rules {
        // 规则集合一致：不动任何自有规则（幂等，§10.3）。
        return Vec::new();
    }
    // 账本丢失/损坏时，内核现存的 Meshlet 所有权清单是权威来源：
    // 枚举所有带 `meshlet alias *` 注释的规则 owner，排除计划仍期望的
    // 单元，余者全量清理；绝不触碰非 Meshlet 规则。
    let planned: std::collections::BTreeSet<_> = owners(&plan.nat_rules).into_iter().collect();
    let kernel_only: std::collections::BTreeSet<_> = kernel_owners.iter().cloned().collect();
    if state.nat_owners.is_empty() {
        return kernel_only.into_iter().collect();
    }
    let stale = kernel_only
        .difference(&planned)
        .cloned()
        .collect::<Vec<_>>();
    if !stale.is_empty() {
        return stale;
    }
    // 规则集合变了但内核侧没有额外对象：账本记录的旧单元整体清掉，
    // 随后由计划重新下发——只增不删的下发路径不会自动发现「旧规则已不该存在」。
    state.nat_owners.clone()
}

/// 计划 NAT 规则的指纹集合（`chain|目的|动作|所有权|源|入向接口`，去重且与
/// 顺序无关）：集合相同即认为内核里的规则无需重刷。指纹来自
/// [`NatRule::signature`]——内核侧解析出的指纹同一形状，两侧据此集合比对。
fn rule_signatures(rules: &[NatRule]) -> Vec<String> {
    rules
        .iter()
        .map(|r| r.signature())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

/// 计划里的 NAT 所有权单元集合（去重、排序，保证确定性）。
fn owners(rules: &[NatRule]) -> Vec<String> {
    rules
        .iter()
        .map(|r| r.owner.clone())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

fn prefixes(dests: impl Iterator<Item = meshlet_domain::Ipv4Cidr>) -> Vec<String> {
    dests.map(|c| c.to_string()).collect()
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

// ---------------------------------------------------------------------------
// 测试（纯逻辑，无需内核/网络）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::Ipv4Cidr;
    use meshlet_network::nat::{NatAction, NatChain};
    use meshlet_network::{PeerConfig, PeerObserved, RouteConfig, TunnelConfig};
    use std::net::Ipv4Addr;

    fn plan(hash: &str, with_nat: bool) -> DevicePlan {
        DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "wg0".into(),
                address: "10.240.0.7".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![PeerConfig {
                    public_key: "hub-pub".into(),
                    allowed_ips: vec!["10.240.0.0/16".parse::<Ipv4Cidr>().unwrap()],
                    endpoint: None,
                    persistent_keepalive_secs: None,
                }],
                mtu: None,
                private_key: None,
            },
            routes: vec![RouteConfig {
                destination: "192.168.9.0/24".parse().unwrap(),
                interface: "wg0".into(),
                gateway: Some("10.240.0.2".parse::<Ipv4Addr>().unwrap()),
            }],
            nat_rules: if with_nat {
                vec![
                    NatRule {
                        source_cidr: None,
                        incoming_interface: None,
                        chain: NatChain::Prerouting,
                        match_dest: "10.241.9.0/24".parse().unwrap(),
                        action: NatAction::NetMap {
                            to: "192.168.9.0/24".parse().unwrap(),
                        },
                        owner: "meshlet alias al-1".into(),
                    },
                    NatRule {
                        source_cidr: None,
                        incoming_interface: None,
                        chain: NatChain::Postrouting,
                        match_dest: "192.168.9.0/24".parse().unwrap(),
                        action: NatAction::SnatToGatewayLan,
                        owner: "meshlet alias al-1".into(),
                    },
                ]
            } else {
                Vec::new()
            },
            hub_address: None,
            publish: None,
            desired_config_hash: hash.into(),
        }
    }

    /// 与该计划一致的内核快照（“已按计划装好”）。peer 身份、路由与 NAT 指纹
    /// 全部**从计划派生**，而不是手写一份相似值——快照与计划本就应当同源，
    /// 手写容易悄悄漂移（那正是被改掉的旧测试）。
    fn healthy(plan: &DevicePlan) -> NetworkSnapshot {
        NetworkSnapshot {
            tunnel_exists: true,
            forwarding_enabled: Some(true),
            peers: plan
                .tunnel
                .peers
                .iter()
                .map(|peer| PeerObserved {
                    public_key: peer.public_key.clone(),
                    allowed_ips: peer.allowed_ips.clone(),
                })
                .collect(),
            installed_routes: plan.routes.iter().map(|route| route.destination).collect(),
            nat_rules: plan.nat_rules.iter().map(|rule| rule.signature()).collect(),
            tunnel_mtu: Some(1420),
        }
    }

    fn state_of(plan: &DevicePlan) -> AgentState {
        AgentState::from_plan(plan)
    }

    #[test]
    fn up_to_date_plan_is_not_reapplied() {
        let p = plan("hash-a", true);
        let d = needs_apply(&state_of(&p), &healthy(&p), &p);
        assert!(!d.needs_apply);
        assert_eq!(d.reason, Reason::UpToDate);
        assert_eq!(d.reason.as_str(), "up_to_date");
    }

    #[test]
    fn missing_ledger_triggers_apply() {
        // 首次安装：没有账本必须重放，不能凭“内存是空的”推断已生效。
        let p = plan("hash-a", false);
        let d = needs_apply(&AgentState::default(), &healthy(&p), &p);
        assert!(d.needs_apply);
        assert_eq!(d.reason, Reason::NoLocalLedger);
    }

    #[test]
    fn new_server_revision_triggers_apply() {
        let old = plan("hash-a", false);
        let new = plan("hash-b", false);
        let d = needs_apply(&state_of(&old), &healthy(&new), &new);
        assert!(d.needs_apply);
        assert_eq!(d.reason, Reason::DesiredConfigChanged);
    }

    #[test]
    fn host_reboot_losing_the_tunnel_triggers_replay() {
        // TODO #32：账本记着 hash-a，内核里的接口没了（主机重启）→ 必须重放。
        let p = plan("hash-a", false);
        let rebooted = NetworkSnapshot {
            tunnel_exists: false,
            ..healthy(&p)
        };
        let d = needs_apply(&state_of(&p), &rebooted, &p);
        assert!(d.needs_apply, "a vanished tunnel must be replayed");
        assert_eq!(d.reason, Reason::KernelDrift);
    }

    #[test]
    fn missing_route_peer_or_nat_counts_as_drift() {
        let p = plan("hash-a", true);
        let state = state_of(&p);

        let no_route = NetworkSnapshot {
            installed_routes: Vec::new(),
            ..healthy(&p)
        };
        assert_eq!(
            needs_apply(&state, &no_route, &p).reason,
            Reason::KernelDrift
        );

        let no_nat = NetworkSnapshot {
            nat_rules: Vec::new(),
            ..healthy(&p)
        };
        assert_eq!(needs_apply(&state, &no_nat, &p).reason, Reason::KernelDrift);

        let no_peer = NetworkSnapshot {
            peers: Vec::new(),
            ..healthy(&p)
        };
        assert_eq!(
            needs_apply(&state, &no_peer, &p).reason,
            Reason::KernelDrift
        );
    }

    #[test]
    fn a_substituted_or_extra_peer_is_drift_with_an_equal_count() {
        // 数量相同、身份不同（受管接口上被换了 peer）→ 必须重放。旧检查只看
        // `peer_count`，对这种注入判「未漂移」——这正是升级到身份级的动因。
        let p = plan("hash-a", false);
        let swapped = NetworkSnapshot {
            peers: vec![PeerObserved {
                public_key: "somebody-else".into(),
                allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
            }],
            ..healthy(&p)
        };
        assert_eq!(
            needs_apply(&state_of(&p), &swapped, &p).reason,
            Reason::KernelDrift
        );

        // 不替换、只是多一个 peer：本接口上的 peer 都是 Meshlet 自有对象，
        // 多出即漂移（同样会绕过错位的 peer_count 判定）。
        let extra = {
            let mut snapshot = healthy(&p);
            snapshot.peers.push(PeerObserved {
                public_key: "lurker".into(),
                allowed_ips: vec!["10.240.0.9/32".parse().unwrap()],
            });
            snapshot
        };
        assert_eq!(
            needs_apply(&state_of(&p), &extra, &p).reason,
            Reason::KernelDrift
        );
    }

    #[test]
    fn peer_allowed_ips_widened_is_drift_and_order_is_ignored() {
        // 身份相同、allowed-ips 被改宽（放行全网段）→ 必须重放纠回。
        let p = plan("hash-a", false);
        let widened = NetworkSnapshot {
            peers: vec![PeerObserved {
                public_key: "hub-pub".into(),
                allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            }],
            ..healthy(&p)
        };
        assert_eq!(
            needs_apply(&state_of(&p), &widened, &p).reason,
            Reason::KernelDrift
        );

        // 集合相同、顺序不同不算漂移（内核枚举顺序不由我们决定）。
        let mut multi = plan("hash-a", false);
        multi.tunnel.peers[0].allowed_ips = vec![
            "10.240.0.0/16".parse().unwrap(),
            "192.168.9.0/24".parse().unwrap(),
        ];
        let reordered = NetworkSnapshot {
            peers: vec![PeerObserved {
                public_key: multi.tunnel.peers[0].public_key.clone(),
                allowed_ips: vec![
                    "192.168.9.0/24".parse().unwrap(),
                    "10.240.0.0/16".parse().unwrap(),
                ],
            }],
            ..healthy(&multi)
        };
        assert!(!needs_apply(&state_of(&multi), &reordered, &multi).needs_apply);
    }

    #[test]
    fn missing_or_extra_nat_fingerprint_is_drift() {
        // 少一条：DNAT 被手工删掉、SNAT 还在 → 集合不一致。旧的
        // `nat_rules_present` 布尔值对此判「未漂移」——有一条在就等于全在。
        let p = plan("hash-a", true);
        let mut dnat_missing = healthy(&p);
        dnat_missing.nat_rules = vec![p.nat_rules[1].signature()];
        assert_eq!(
            needs_apply(&state_of(&p), &dnat_missing, &p).reason,
            Reason::KernelDrift
        );

        // 多一条：下发只增不删，旧映射单元的残留必须被检出（不能等它自己消失）。
        let mut stale_rule = p.nat_rules[0].clone();
        stale_rule.match_dest = "10.241.8.0/24".parse().unwrap();
        stale_rule.action = NatAction::NetMap {
            to: "192.168.8.0/24".parse().unwrap(),
        };
        stale_rule.owner = "meshlet alias al-0".into();
        let mut extra_rule = healthy(&p);
        extra_rule.nat_rules.push(stale_rule.signature());
        assert_eq!(
            needs_apply(&state_of(&p), &extra_rule, &p).reason,
            Reason::KernelDrift
        );
    }

    #[test]
    fn orphan_nat_rules_on_a_demoted_gateway_are_drift() {
        // 计划已无 NAT（网关降级 / 映射被删），内核里还留着 Meshlet 注释的规则
        // → 必须重放以走所有权清理。旧逻辑对「计划无 NAT」直接放行，残留会
        // 一直留到有人手动清理。
        let p = plan("hash-a", false);
        let orphan = NatRule {
            source_cidr: None,
            incoming_interface: None,
            chain: NatChain::Postrouting,
            match_dest: "192.168.9.0/24".parse().unwrap(),
            action: NatAction::SnatToGatewayLan,
            owner: "meshlet alias al-1".into(),
        };
        let mut leftover = healthy(&p);
        leftover.nat_rules = vec![orphan.signature()];
        assert_eq!(
            needs_apply(&state_of(&p), &leftover, &p).reason,
            Reason::KernelDrift
        );
    }

    #[test]
    fn planned_mtu_mismatch_counts_as_drift() {
        // 内核读数与计划不符（手工改动 / 半途失败）→ 必须重放纠回（#51）。
        let mut p = plan("hash-a", false);
        p.tunnel.mtu = Some(1380);

        let wrong = NetworkSnapshot {
            tunnel_mtu: Some(1420),
            ..healthy(&p)
        };
        assert_eq!(
            needs_apply(&state_of(&p), &wrong, &p).reason,
            Reason::KernelDrift
        );

        let matching = NetworkSnapshot {
            tunnel_mtu: Some(1380),
            ..healthy(&p)
        };
        assert!(!needs_apply(&state_of(&p), &matching, &p).needs_apply);
    }

    #[test]
    fn kernel_mtu_is_not_judged_when_plan_leaves_it_unset() {
        // 计划未配置 MTU：内核读多少都行（默认 1420 或管理员有意设置）。
        let p = plan("hash-a", false);
        let other = NetworkSnapshot {
            tunnel_mtu: Some(1300),
            ..healthy(&p)
        };
        assert!(!needs_apply(&state_of(&p), &other, &p).needs_apply);
    }

    #[test]
    fn no_nat_in_plan_does_not_require_nat_rules_in_kernel() {
        // 非网关设备：内核本来就没有 Meshlet NAT 规则，不算漂移。
        let p = plan("hash-a", false);
        let no_nat = NetworkSnapshot {
            nat_rules: Vec::new(),
            ..healthy(&p)
        };
        assert!(!needs_apply(&state_of(&p), &no_nat, &p).needs_apply);
    }

    #[test]
    fn stale_owners_covers_removed_and_changed_mappings() {
        let p = plan("hash-a", true);
        let state = state_of(&p);
        assert!(
            stale_owners(&state, &p, &[], true).is_empty(),
            "an unchanged plan has nothing stale"
        );

        // 映射被删（整单元清理，§12.6）：规则集合为空 → 账本单元全部清理。
        let mut without_alias = p.clone();
        without_alias.nat_rules.clear();
        assert_eq!(
            stale_owners(&state, &without_alias, &state.nat_owners, true),
            vec!["meshlet alias al-1"]
        );

        // 另一个映射接管：旧单元清理，新单元随计划下发。
        let mut other = p.clone();
        other.nat_rules[0].owner = "meshlet alias al-2".into();
        other.nat_rules[1].owner = "meshlet alias al-2".into();
        assert_eq!(
            stale_owners(&state, &other, &state.nat_owners, true),
            vec!["meshlet alias al-1"]
        );

        // 映射还在但规则少了（dnat_snat → dnat_only）：下发只增不删，必须先清
        // 再重刷，否则旧规则残留（白名单外的东西绝不动）。
        let mut dnat_only = p.clone();
        dnat_only.nat_rules.pop();
        assert_eq!(
            stale_owners(&state, &dnat_only, &state.nat_owners, true),
            vec!["meshlet alias al-1"]
        );

        // 顺序变化不算变更（指纹集合与顺序无关）。
        let mut reordered = p.clone();
        reordered.nat_rules.reverse();
        assert!(stale_owners(&state, &reordered, &state.nat_owners, true).is_empty());
    }

    #[test]
    fn missing_or_corrupt_ledger_uses_kernel_inventory() {
        let mut p = plan("hash-a", false);
        p.nat_rules.clear();
        assert_eq!(
            stale_owners(
                &AgentState::default(),
                &p,
                &["meshlet alias kept".into(), "meshlet alias old".into()],
                false
            ),
            [
                "meshlet alias kept".to_string(),
                "meshlet alias old".to_string(),
            ]
        );
    }

    #[test]
    fn state_round_trips_through_the_state_file() {
        let p = plan("hash-a", true);
        let state = state_of(&p);
        let dir = std::env::temp_dir().join("meshlet-agent-state-test");
        let path = state_path(dir.to_str().unwrap());
        std::fs::remove_file(&path).ok();

        state.save(&path).expect("save state");
        let loaded = AgentState::load(&path).expect("load state");
        assert_eq!(loaded, state);
        assert_eq!(loaded.desired_config_hash, "hash-a");
        assert_eq!(loaded.nat_owners, vec!["meshlet alias al-1"]);
        assert_eq!(loaded.routes, vec!["192.168.9.0/24"]);
        assert_eq!(loaded.nat_rules.len(), 2, "one fingerprint per rule");
        assert!(
            loaded
                .nat_rules
                .iter()
                .all(|f| f.contains("meshlet alias al-1")),
            "fingerprints carry the ownership comment: {:?}",
            loaded.nat_rules
        );

        // 计划本身不含私钥：账本也不会意外持久化私钥。
        assert!(!state.tunnel_address.contains("key"));

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn corrupt_state_file_reads_as_empty_ledger() {
        // 损坏的账本按“无账本”处理（触发重放），不让 agent 卡死或假装已生效。
        let dir = std::env::temp_dir().join("meshlet-agent-state-corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        let path = state_path(dir.to_str().unwrap());
        std::fs::write(&path, "{not json").unwrap();
        let loaded = AgentState::load(&path).unwrap_or_default();
        assert_eq!(loaded, AgentState::default());
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
