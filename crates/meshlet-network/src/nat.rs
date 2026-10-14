//! NAT 规则计划（[存档 §9.4–§9.5](../../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-006](../../../docs/decisions/adr-006-alias-prefix-nat.md)）。
//!
//! 本模块是**纯规划**：从 `AliasMapping` 确定性地推导网关侧应存在的 NAT 规则，
//! 不执行任何 iptables 调用。执行（规则下发/移除）随修订 apply 交网络后端
//! （[ADR-007](../../../docs/decisions/adr-007-linux-network-backend.md)），
//! 数据面未接线前 apply 确定性失败可见（§10.3，不假装成功）。
//!
//! 转换发生在**目标 LAN 网关**上（§9.4）：网关知道真实 LAN 出口、可直接访问
//! 目标主机，VPS 只按前缀转发（不必在 VPS 上建全部远端 LAN 的重叠路由）。

use meshlet_domain::{AliasMapping, Ipv4Cidr, TranslationMode};

/// NAT 表链：目的重写在路由决策前（PREROUTING），源重写在离开网关前
/// （POSTROUTING）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatChain {
    Prerouting,
    Postrouting,
}

impl NatChain {
    /// iptables 链名（渲染用）。
    pub fn as_str(self) -> &'static str {
        match self {
            NatChain::Prerouting => "PREROUTING",
            NatChain::Postrouting => "POSTROUTING",
        }
    }
}

/// 规则动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatAction {
    /// 1:1 等长前缀重写（iptables `NETMAP` 语义）。ADR-006 的等长约束保证
    /// alias 与 target 两侧地址一一对应（`AliasMapping::translate` 同一套
    /// 偏移数学）。
    NetMap { to: Ipv4Cidr },
    /// 受控 SNAT 到网关自身 LAN 地址（§9.5 默认兼容模式）。地址由执行期
    /// 网关解析——映射本身不携带网关 LAN 地址。
    SnatToGatewayLan,
}

/// 一条计划态 NAT 规则。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatRule {
    pub chain: NatChain,
    /// 按**目的**前缀匹配：DNAT 匹配 alias 前缀；受控 SNAT 匹配 target
    /// 前缀（即刚被 DNAT 改写为真实 LAN 目的、正要进入 LAN 的流量）。
    pub match_dest: Ipv4Cidr,
    pub action: NatAction,
    /// 所有权注释（§12.6 清理定位）：`meshlet alias {id}`——删除映射/整单元
    /// 清理时按注释精确匹配移除 Meshlet 自有规则，绝不触碰非 Meshlet 规则。
    pub owner: String,
}

impl NatRule {
    /// 渲染为 iptables 参数（`-t nat` 之外的部分；单测与未来执行器共用同
    /// 一渲染，避免计划与执行漂移）。`gateway_lan_addr` 供
    /// [NatAction::SnatToGatewayLan] 使用，NETMAP 规则不读它。
    pub fn iptables_args(&self, gateway_lan_addr: std::net::Ipv4Addr) -> Vec<String> {
        let mut args = vec![
            "-A".into(),
            self.chain.as_str().into(),
            "-d".into(),
            self.match_dest.to_string(),
        ];
        match self.action {
            NatAction::NetMap { to } => {
                args.extend(["-j".into(), "NETMAP".into(), "--to".into(), to.to_string()]);
            }
            NatAction::SnatToGatewayLan => {
                args.extend([
                    "-j".into(),
                    "SNAT".into(),
                    "--to-source".into(),
                    gateway_lan_addr.to_string(),
                ]);
            }
        }
        args.extend([
            "-m".into(),
            "comment".into(),
            "--comment".into(),
            self.owner.clone(),
        ]);
        args
    }
}

/// 从 Alias 映射计划网关侧 NAT 规则（§9.4–§9.5）：
///
/// - **DNAT 恒有**：`PREROUTING NETMAP alias → target`——客户端访问 Alias
///   地址，网关把目的改写为真实 LAN 前缀（等长一一对应）；
/// - `dnat_snat`（默认兼容模式）追加 `POSTROUTING` 受控 SNAT：进入 LAN 的
///   Alias 流量源地址改写为网关 LAN 地址——LAN 主机无需指向网关的返回
///   路由即可回复，代价是 LAN 侧看不到原始源地址（§9.5 明示限制，
///   控制台随映射显示该模式）；
/// - `dnat_only` 不加 SNAT（保留原始源地址）：要求 LAN 有指向网关的返回
///   路由（`dual_route` 语义），否则响应丢失。
///
/// 规则顺序确定（DNAT 在前、SNAT 在后），所有权注释携带映射 id。
pub fn alias_nat_rules(alias: &AliasMapping) -> Vec<NatRule> {
    let owner = format!("meshlet alias {}", alias.id);
    let mut rules = vec![NatRule {
        chain: NatChain::Prerouting,
        match_dest: alias.alias_cidr,
        action: NatAction::NetMap {
            to: alias.target_cidr,
        },
        owner: owner.clone(),
    }];
    if alias.translation_mode == TranslationMode::DnatSnat {
        rules.push(NatRule {
            chain: NatChain::Postrouting,
            match_dest: alias.target_cidr,
            action: NatAction::SnatToGatewayLan,
            owner,
        });
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlet_domain::{AliasMappingId, LanRouteId, NetworkId};

    fn mapping(mode: TranslationMode) -> AliasMapping {
        AliasMapping::new(
            AliasMappingId("al-7".into()),
            NetworkId("n-1".into()),
            LanRouteId("rt-3".into()),
            "10.241.1.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
            mode,
        )
        .unwrap()
    }

    #[test]
    fn dnat_only_plans_a_single_prerouting_netmap() {
        // §9.4：DNAT 恒有、在目标 LAN 网关上执行。
        let rules = alias_nat_rules(&mapping(TranslationMode::DnatOnly));
        assert_eq!(rules.len(), 1);
        let dnat = &rules[0];
        assert_eq!(dnat.chain, NatChain::Prerouting);
        assert_eq!(dnat.match_dest.to_string(), "10.241.1.0/24");
        assert_eq!(
            dnat.action,
            NatAction::NetMap {
                to: "192.168.1.0/24".parse().unwrap()
            }
        );
        // 保留原始源地址：无 SNAT 规则（要求 dual_route 返回路由）。
        assert!(!rules.iter().any(|r| r.chain == NatChain::Postrouting));
    }

    #[test]
    fn dnat_snat_adds_controlled_postrouting_snat() {
        // §9.5 默认兼容模式：进入 LAN 的 Alias 流量受控 SNAT 到网关 LAN 地址。
        let rules = alias_nat_rules(&mapping(TranslationMode::DnatSnat));
        assert_eq!(rules.len(), 2);
        // 顺序确定：DNAT 在前。
        assert_eq!(rules[0].chain, NatChain::Prerouting);
        let snat = &rules[1];
        assert_eq!(snat.chain, NatChain::Postrouting);
        // SNAT 匹配 target 前缀——刚被 DNAT 改写、正要进入 LAN 的流量。
        assert_eq!(snat.match_dest.to_string(), "192.168.1.0/24");
        assert_eq!(snat.action, NatAction::SnatToGatewayLan);
    }

    #[test]
    fn every_rule_carries_the_alias_ownership_comment() {
        // §12.6：删除映射时按注释精确清理 Meshlet 自有规则。
        for mode in [TranslationMode::DnatOnly, TranslationMode::DnatSnat] {
            for rule in alias_nat_rules(&mapping(mode)) {
                assert_eq!(rule.owner, "meshlet alias al-7");
            }
        }
    }

    #[test]
    fn planning_is_deterministic() {
        let alias = mapping(TranslationMode::DnatSnat);
        assert_eq!(alias_nat_rules(&alias), alias_nat_rules(&alias));
    }

    #[test]
    fn overlay_traffic_matches_no_rule_so_sources_stay_original() {
        // §7.4：普通 Overlay 设备间通信保留原始源地址——禁止把整个 Overlay
        // 网络无差别 SNAT 到 VPS 地址。这是计划层的结构性保证：规则按
        // **目的**前缀匹配，前缀只能是 alias 或真实 LAN（target）网段；
        // 目的落在 Overlay 内的流量匹配不到任何规则，原样通过。
        let overlay: Ipv4Cidr = "10.240.0.0/16".parse().unwrap();
        for mode in [TranslationMode::DnatOnly, TranslationMode::DnatSnat] {
            let rules = alias_nat_rules(&mapping(mode));

            // 没有任何规则的匹配前缀与 Overlay 网段重叠（不存在「整个
            // Overlay 网络无差别 SNAT」的规则形状）。
            for rule in &rules {
                assert!(
                    !overlay.overlaps(&rule.match_dest),
                    "rule must not match overlay destinations: {rule:?}"
                );
            }
            // Overlay 目的地址匹配不到任何规则。
            for dest in ["10.240.0.5", "10.240.200.9"] {
                let ip = dest.parse::<std::net::Ipv4Addr>().unwrap();
                assert!(
                    !rules.iter().any(|r| r.match_dest.contains(ip)),
                    "overlay dest {dest} must match no NAT rule"
                );
            }
            // 而 Alias 目的匹配得到规则——转换只针对 Alias 流量。
            let alias_dest = "10.241.1.5".parse::<std::net::Ipv4Addr>().unwrap();
            assert!(
                rules.iter().any(|r| r.match_dest.contains(alias_dest)),
                "alias destination must match a rule"
            );
        }
    }

    #[test]
    fn iptables_rendering_matches_the_plan() {
        // 计划与渲染共用同一结构：规则里出现什么，渲染就下什么。
        let gw: std::net::Ipv4Addr = "192.168.1.1".parse().unwrap();
        let rules = alias_nat_rules(&mapping(TranslationMode::DnatSnat));
        let (dnat, snat) = (&rules[0], &rules[1]);

        let expected: Vec<String> = [
            "-A",
            "PREROUTING",
            "-d",
            "10.241.1.0/24",
            "-j",
            "NETMAP",
            "--to",
            "192.168.1.0/24",
            "-m",
            "comment",
            "--comment",
            "meshlet alias al-7",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(dnat.iptables_args(gw), expected);

        let expected: Vec<String> = [
            "-A",
            "POSTROUTING",
            "-d",
            "192.168.1.0/24",
            "-j",
            "SNAT",
            "--to-source",
            "192.168.1.1",
            "-m",
            "comment",
            "--comment",
            "meshlet alias al-7",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        assert_eq!(snat.iptables_args(gw), expected);
    }
}
