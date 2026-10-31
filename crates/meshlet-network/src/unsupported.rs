//! 非 Linux 平台的明确占位后端（[ADR-008](../../../docs/decisions/adr-008-windows-network-backend.md)）。
//!
//! 构造与装配（`new` / `with_*`）照常成立，平台无关的调用方代码在任何
//! 平台都能编译运行；但**每一个触碰内核的操作**都返回
//! [`NetworkError::Unsupported`] 并点名操作与接口——Windows 网络后端
//! （WireGuard tunnel service + 系统路由 API）是 ADR-008 的后续实现项。
//! 占位的意义是**错误面**而不是假绿：应用失败可见、读数按「未证实」
//! 处理，绝不静默假装生效（§10.3、§12.2）。

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::nat::NatRule;
use crate::{
    ApplyResult, ConfigRevisionRef, DevicePlan, NetworkBackend, NetworkError, NetworkSnapshot,
    RouteConfig, TunnelConfig,
};
use meshlet_domain::Ipv4Cidr;

/// 非 Linux 平台的占位后端：所有数据面操作显式拒绝（ADR-008 待接入）。
#[derive(Clone, Default)]
pub struct UnsupportedBackend {
    interface: String,
}

impl UnsupportedBackend {
    pub fn new() -> Self {
        Self {
            interface: "meshlet".to_string(),
        }
    }

    /// 测试钩子对齐（Linux 后端同名装配方法）：占位后端无视 netns 与
    /// `sudo -n` 前缀——反正每个操作都会拒绝。
    pub fn with_netns(self, _netns: impl Into<String>) -> Self {
        self
    }

    /// 同 [`UnsupportedBackend::with_netns`]。
    pub fn with_sudo(self) -> Self {
        self
    }

    /// 记录受管接口名，使拒绝信息能点名它（与 Linux 后端同形）。
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    fn refuse(&self, operation: &str) -> NetworkError {
        NetworkError::Unsupported(format!(
            "operation `{operation}` on interface `{}` needs a platform dataplane backend \
             (windows backend pending, ADR-008)",
            self.interface
        ))
    }

    pub fn clear_hub_sync(&self) -> Result<(), NetworkError> {
        Err(self.refuse("clear_hub"))
    }

    pub fn isolate_hub_sync(&self, _address: Ipv4Addr) -> Result<(), NetworkError> {
        Err(self.refuse("isolate_hub"))
    }

    pub fn device_plan_matches_sync(
        &self,
        _plan: &DevicePlan,
        _extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        Err(self.refuse("device_plan_matches"))
    }

    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
        Err(self.refuse("inspect"))
    }

    pub fn apply_tunnel_sync(
        &self,
        _config: &TunnelConfig,
        _keep_keys: &BTreeSet<String>,
    ) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("apply_tunnel"))
    }

    pub fn apply_routes_sync(&self, _routes: &[RouteConfig]) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("apply_routes"))
    }

    pub fn apply_nat_sync(
        &self,
        _rules: &[NatRule],
        _gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("apply_nat"))
    }

    /// 设备计划组合应用（与 Linux 后端同签名）：先拒绝，不碰隧道/路由/NAT。
    pub fn apply_device_plan_sync(
        &self,
        _plan: &DevicePlan,
        _private_key: Option<String>,
        _gateway_lan_addr: Option<Ipv4Addr>,
        _keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        Err(self.refuse("apply_device_plan"))
    }

    pub fn remove_nat_sync(&self, _owner: &str) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("remove_nat"))
    }

    pub fn meshlet_nat_owners_sync(&self) -> Result<Vec<String>, NetworkError> {
        Err(self.refuse("enumerate meshlet nat owners"))
    }

    pub fn lan_addresses_sync(&self) -> Result<Vec<Ipv4Addr>, NetworkError> {
        Err(self.refuse("enumerate lan addresses"))
    }

    pub fn lan_subnets_sync(&self) -> Result<Vec<Ipv4Cidr>, NetworkError> {
        Err(self.refuse("enumerate lan subnets"))
    }

    /// P2P 直连执行层本平台无实现：显式拒绝（不假装直连成功）。
    pub fn handshake_ages_sync(&self) -> Result<BTreeMap<String, u64>, NetworkError> {
        Err(self.refuse("handshake_ages"))
    }

    /// P2P 直连 peer 下发本平台无实现：显式拒绝。
    pub fn set_direct_peer_sync(
        &self,
        _public_key: &str,
        _allowed_ips: &[Ipv4Cidr],
        _endpoint: SocketAddrV4,
        _persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        Err(self.refuse("set_direct_peer"))
    }

    /// P2P 直连 peer 移除本平台无实现：显式拒绝。
    pub fn remove_peer_sync(&self, _public_key: &str) -> Result<(), NetworkError> {
        Err(self.refuse("remove_peer"))
    }

    pub fn remove_stale_meshlet_routes_sync(
        &self,
        _routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("remove stale meshlet routes"))
    }

    pub fn rollback_sync(&self) -> Result<ApplyResult, NetworkError> {
        Err(self.refuse("rollback"))
    }

    /// `wg pubkey` 等价物在本平台无实现：hub 公钥推导显式失败（server 把
    /// 它作为可见错误返回，绝不下发空计划装作有 hub）。
    pub fn public_key_from_private(&self, _private_key: &str) -> Result<String, NetworkError> {
        Err(self.refuse("public_key_from_private"))
    }

    /// 大包探测在本平台无数据面：`false` = 「未证实」，不是绿（§7.5/§12.2
    /// 不假绿——探测失败绝不冒充路径可承载）。
    pub fn mtu_probe_sync(&self, _target: Ipv4Addr, _payload: u32) -> bool {
        false
    }
}

impl NetworkBackend for UnsupportedBackend {
    async fn inspect(&self) -> Result<NetworkSnapshot, NetworkError> {
        self.inspect_sync()
    }

    async fn apply_tunnel(&self, config: TunnelConfig) -> Result<ApplyResult, NetworkError> {
        self.apply_tunnel_sync(&config)
    }

    async fn apply_routes(
        &mut self,
        routes: Vec<RouteConfig>,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_routes_sync(&routes)
    }

    async fn apply_nat(
        &self,
        rules: Vec<NatRule>,
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        self.apply_nat_sync(&rules, gateway_lan_addr)
    }

    async fn remove_nat(&self, owner: &str) -> Result<ApplyResult, NetworkError> {
        self.remove_nat_sync(owner)
    }

    async fn rollback(&self, _revision: ConfigRevisionRef) -> Result<ApplyResult, NetworkError> {
        self.rollback_sync()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::{NatAction, NatChain};

    fn rule() -> NatRule {
        NatRule {
            source_cidr: None,
            incoming_interface: None,
            chain: NatChain::Prerouting,
            match_dest: "10.241.1.0/24".parse().unwrap(),
            action: NatAction::NetMap {
                to: "192.168.1.0/24".parse().unwrap(),
            },
            owner: "meshlet alias al-1".into(),
        }
    }

    /// 每个数据面操作都显式拒绝，且拒绝信息点名操作与接口（错误面，
    /// 不是静默吞掉假装通过）。
    #[test]
    fn every_operation_refuses_naming_the_operation() {
        let backend = UnsupportedBackend::new().with_interface("wg0");
        let tunnel = TunnelConfig {
            name: "wg0".into(),
            address: "10.240.0.1".parse().unwrap(),
            address_prefix: 24,
            listen_port: None,
            peers: vec![],
            mtu: None,
            private_key: None,
        };
        let route = RouteConfig {
            destination: "10.241.1.0/24".parse().unwrap(),
            interface: "wg0".into(),
            gateway: Some("10.240.0.4".parse().unwrap()),
        };
        for (operation, error) in [
            ("inspect", backend.inspect_sync().unwrap_err()),
            (
                "apply_tunnel",
                backend.apply_tunnel_sync(&tunnel).unwrap_err(),
            ),
            (
                "apply_routes",
                backend.apply_routes_sync(&[route]).unwrap_err(),
            ),
            (
                "apply_nat",
                backend
                    .apply_nat_sync(&[rule()], "192.168.1.1".parse().unwrap())
                    .unwrap_err(),
            ),
            (
                "remove_nat",
                backend.remove_nat_sync("meshlet alias al-1").unwrap_err(),
            ),
            (
                "apply_device_plan",
                backend
                    .apply_device_plan_sync(
                        &DevicePlan {
                            desired_revision: 0,
                            hub_port: None,
                            tunnel: tunnel.clone(),
                            routes: vec![],
                            nat_rules: vec![],
                            hub_address: None,
                            publish: None,
                            desired_config_hash: "hash".into(),
                        },
                        None,
                        None,
                    )
                    .unwrap_err(),
            ),
            ("rollback", backend.rollback_sync().unwrap_err()),
            (
                "public_key_from_private",
                backend.public_key_from_private("key").unwrap_err(),
            ),
        ] {
            match error {
                NetworkError::Unsupported(detail) => {
                    assert!(detail.contains(operation), "{operation}: {detail}");
                    assert!(detail.contains("wg0"), "{operation}: {detail}");
                }
                other => panic!("{operation} must refuse as Unsupported, got {other:?}"),
            }
        }
    }

    /// trait 面（async）与 sync 面同一拒绝语义：占位不是只在一条路上诚实。
    #[tokio::test]
    async fn the_trait_surface_refuses_the_same_way() {
        let backend = UnsupportedBackend::new();
        assert!(matches!(
            backend.inspect().await,
            Err(NetworkError::Unsupported(_))
        ));
    }

    /// 大包探测恒 false：占位后端下「未证实」不冒充绿（§7.5）。
    #[test]
    fn mtu_probe_reports_unverified() {
        assert!(!UnsupportedBackend::new().mtu_probe_sync("10.240.0.2".parse().unwrap(), 1392));
    }
}
