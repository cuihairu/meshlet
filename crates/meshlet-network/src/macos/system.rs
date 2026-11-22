//! macOS 平台 SystemBackend（③-C 接线）：默认占位 + boringtun 数据面分派。
//!
//! macOS 上 `SystemBackend` 原本落在 [crate::unsupported] 占位（一切操作
//! 显式拒绝）。本模块把 macOS 的默认后端换成**双模**结构：
//!
//! - **默认（Service 语义）**：逐操作委托 [crate::unsupported::UnsupportedBackend]
//!   ——保持既有行为（每操作 `Unsupported`，绝不静默假装生效）。`mac-boringtun`
//!   未选时就是它，**行为零变化**。
//! - **boringtun 模式**（[MacSystemBackend::with_mac_boringtun]）：隧道应用面
//!   走 [crate::macos::backend::bt_apply] 命令计划 → 执行器
//!   [crate::macos::backend::MacNetworkBackend]（sudo 白名单在
//!   [crate::macos::backend] 钩子守门）；其余操作仍占位拒绝（mac 无 NAT/
//!   peer 直连面）。
//!
//! 隧道配置面的 **wg 密钥/peer UAPI 与内核分配 utun 名（`WG_TUN_NAME_FILE`）
//! 是 ⑤ 真机验收项**——本文件不发明路径；boringtun 模式下计划名 `utun`（内核
//! 自选）时显式报错点名 ⑤，绝不把 `utun` 当真实接口名静默应用。
//!
//! 仅 `#[cfg(target_os = "macos")]` 编译（宿主 CI 不跑 macOS 测试，经
//! `x86_64-apple-darwin` 交叉 check 编译验证；命令计划语义由全平台单测覆盖）。

use super::backend::{bt_apply, MacNetworkBackend};
use crate::unsupported::UnsupportedBackend;
use crate::{
    ApplyResult, ConfigRevisionRef, NetworkBackend, NetworkError, NetworkSnapshot, RouteConfig,
    TunnelConfig,
};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, SocketAddrV4};

/// macOS 平台后端：占位底座 + 可选 boringtun 隧道面。
#[derive(Clone)]
pub struct MacSystemBackend {
    /// 占位底座（默认模式的一切操作 + boringtun 模式的非隧道操作）。
    base: UnsupportedBackend,
    /// 受管 utun 名（`utun` 让内核选 / `utun<N>` 显式）。
    interface: String,
    /// boringtun 数据面：`None` = 默认占位；`Some` = 隧道应用走命令计划。
    boringtun: Option<MacNetworkBackend>,
}

impl MacSystemBackend {
    pub fn new() -> Self {
        Self {
            base: UnsupportedBackend::new(),
            interface: "utun".to_string(),
            boringtun: None,
        }
    }

    /// 记录受管 utun 名（对齐各后端 `with_interface` 装配）。
    pub fn with_interface(mut self, interface: impl Into<String>) -> Self {
        self.interface = interface.into();
        self
    }

    /// 测试钩子（对齐各后端装配面）：boringtun 命令经 `sudo -n` 前缀。
    pub fn with_sudo(mut self) -> Self {
        if let Some(backend) = self.boringtun.take() {
            self.boringtun = Some(backend.with_sudo());
        }
        self
    }

    /// 测试钩子（对齐各后端装配面）：mac 无 netns，忽略（占位语义不变）。
    pub fn with_netns(self, _netns: impl Into<String>) -> Self {
        self
    }

    /// ③-C 接线：选择 boringtun 数据面（隧道应用走命令计划）。
    pub fn with_mac_boringtun(mut self) -> Self {
        self.boringtun = Some(MacNetworkBackend::new());
        self
    }

    /// 隧道应用面：boringtun 模式下走 bt 命令计划，否则占位拒绝。
    fn apply_tunnel_sync(&self, config: &TunnelConfig) -> Result<ApplyResult, NetworkError> {
        let backend = match self.boringtun.as_ref() {
            Some(backend) => backend,
            None => return self.base.apply_tunnel_sync(config, &BTreeSet::new()),
        };
        // 计划名 `utun`（内核自选）需 `WG_TUN_NAME_FILE` 才拿得到实际名——
        // 那是 ⑤ 真机项，本批不发明路径：显式报错，绝不把 `utun` 当真实接口。
        if self.interface == "utun" {
            return Err(NetworkError::ApplyRejected(
                "mac-boringtun with kernel-assigned utun name needs WG_TUN_NAME_FILE \
                 resolution (real-machine acceptance item)"
                    .into(),
            ));
        }
        let commands = bt_apply(config, &self.interface, &self.interface)?;
        backend.apply(&commands)?;
        Ok(ApplyResult::ok())
    }

    // ---- 占位委托面（默认与 boringtun 模式一致：mac 无这些面）----

    pub fn inspect_sync(&self) -> Result<NetworkSnapshot, NetworkError> {
        self.base.inspect_sync()
    }

    pub fn apply_routes_sync(&self, routes: &[RouteConfig]) -> Result<ApplyResult, NetworkError> {
        self.base.apply_routes_sync(routes)
    }

    pub fn apply_nat_sync(
        &self,
        rules: &[crate::nat::NatRule],
        gateway_lan_addr: Ipv4Addr,
    ) -> Result<ApplyResult, NetworkError> {
        self.base.apply_nat_sync(rules, gateway_lan_addr)
    }

    pub fn remove_nat_sync(&self, owner: &str) -> Result<ApplyResult, NetworkError> {
        self.base.remove_nat_sync(owner)
    }

    pub fn rollback_sync(&self) -> Result<ApplyResult, NetworkError> {
        self.base.rollback_sync()
    }

    pub fn diagnostics_sync(&self) -> Result<crate::NetworkDiagnostics, NetworkError> {
        self.base.diagnostics_sync()
    }

    pub fn ping_rtt_ms(&self, target: Ipv4Addr) -> Option<u128> {
        self.base.ping_rtt_ms(target)
    }

    pub fn lan_addresses_sync(&self) -> Result<Vec<Ipv4Addr>, NetworkError> {
        self.base.lan_addresses_sync()
    }

    pub fn lan_subnets_sync(&self) -> Result<Vec<meshlet_domain::Ipv4Cidr>, NetworkError> {
        self.base.lan_subnets_sync()
    }

    pub fn handshake_ages_sync(&self) -> Result<BTreeMap<String, u64>, NetworkError> {
        self.base.handshake_ages_sync()
    }

    pub fn set_direct_peer_sync(
        &self,
        public_key: &str,
        allowed_ips: &[meshlet_domain::Ipv4Cidr],
        endpoint: SocketAddrV4,
        persistent_keepalive_secs: u32,
    ) -> Result<(), NetworkError> {
        self.base
            .set_direct_peer_sync(public_key, allowed_ips, endpoint, persistent_keepalive_secs)
    }

    pub fn remove_peer_sync(&self, public_key: &str) -> Result<(), NetworkError> {
        self.base.remove_peer_sync(public_key)
    }

    pub fn set_direct_endpoint_sync(
        &self,
        public_key: &str,
        endpoint: SocketAddrV4,
    ) -> Result<(), NetworkError> {
        self.base.set_direct_endpoint_sync(public_key, endpoint)
    }

    pub fn remove_stale_meshlet_routes_sync(
        &self,
        routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        self.base.remove_stale_meshlet_routes_sync(routes)
    }

    pub fn public_key_from_private(&self, private_key: &str) -> Result<String, NetworkError> {
        self.base.public_key_from_private(private_key)
    }

    pub fn mtu_probe_sync(&self, target: Ipv4Addr, payload: u32) -> bool {
        self.base.mtu_probe_sync(target, payload)
    }

    pub fn underlay_path_mtu_sync(&self) -> Option<u32> {
        self.base.underlay_path_mtu_sync()
    }

    pub fn clear_hub_sync(&self) -> Result<(), NetworkError> {
        self.base.clear_hub_sync()
    }

    pub fn isolate_hub_sync(&self, address: Ipv4Addr) -> Result<(), NetworkError> {
        self.base.isolate_hub_sync(address)
    }

    pub fn device_plan_matches_sync(
        &self,
        plan: &crate::DevicePlan,
        extra_peer_keys: &BTreeSet<String>,
    ) -> Result<bool, NetworkError> {
        self.base.device_plan_matches_sync(plan, extra_peer_keys)
    }

    pub fn meshlet_nat_owners_sync(&self) -> Result<Vec<String>, NetworkError> {
        self.base.meshlet_nat_owners_sync()
    }

    /// 设备计划组合应用：隧道面走 boringtun（若选中），其余成分占位拒绝。
    /// 签名对齐 [UnsupportedBackend::apply_device_plan_sync]（&self）。
    pub fn apply_device_plan_sync(
        &self,
        plan: &crate::DevicePlan,
        private_key: Option<String>,
        _gateway_lan_addr: Option<Ipv4Addr>,
        keep_keys: &BTreeSet<String>,
    ) -> Result<(), NetworkError> {
        let mut tunnel = plan.tunnel.clone();
        tunnel.private_key = private_key;
        let tunnel_result = self.apply_tunnel_sync(&tunnel)?;
        if !tunnel_result.applied {
            return Err(NetworkError::ApplyRejected(
                tunnel_result.error.unwrap_or_default(),
            ));
        }
        // 其余成分（routes/nat）走占位：mac 无独立路由/NAT 面。boringtun 的
        // 路由已含在命令计划（peer allowed_ips），无独立路由表成分。
        let routes = self.apply_routes_sync(&plan.routes)?;
        if !routes.applied {
            return Err(NetworkError::ApplyRejected(
                routes.error.unwrap_or_default(),
            ));
        }
        if !plan.nat_rules.is_empty() {
            let nat = self.apply_nat_sync(&plan.nat_rules, Ipv4Addr::UNSPECIFIED)?;
            if !nat.applied {
                return Err(NetworkError::ApplyRejected(nat.error.unwrap_or_default()));
            }
        }
        let _ = keep_keys;
        Ok(())
    }
}

impl Default for MacSystemBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkBackend for MacSystemBackend {
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
        rules: Vec<crate::nat::NatRule>,
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

    /// ③-C 钉：默认模式（未选 mac-boringtun）行为与占位一致——隧道应用显式
    /// 拒绝，绝不静默假装生效。
    #[test]
    fn default_mode_refuses_tunnel_apply() {
        let backend = MacSystemBackend::new().with_interface("utun5");
        let err = backend.apply_tunnel_sync(&crate::TunnelConfig {
            name: "net-a".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 16,
            listen_port: Some(51821),
            peers: Vec::new(),
            mtu: Some(1420),
            private_key: None,
        });
        assert!(matches!(err, Err(NetworkError::Unsupported(_))));
    }

    /// ③-C 钉：boringtun 模式且计划名 `utun`（内核自选）→ 显式拒绝（
    /// WG_TUN_NAME_FILE 是 ⑤ 真机项，绝不把 `utun` 当真实接口名应用）。
    #[test]
    fn boringtun_bare_utun_fails_closed() {
        let backend = MacSystemBackend::new()
            .with_interface("utun")
            .with_mac_boringtun();
        let err = backend.apply_tunnel_sync(&crate::TunnelConfig {
            name: "net-a".into(),
            address: "10.240.0.7".parse().unwrap(),
            address_prefix: 16,
            listen_port: Some(51821),
            peers: Vec::new(),
            mtu: Some(1420),
            private_key: None,
        });
        assert!(matches!(err, Err(NetworkError::ApplyRejected(_))));
    }

    /// ③-C 钉：boringtun 模式显式 `utun<N>` 名走命令计划（不因内核名缺失而
    /// 拒——显式名不需要 WG_TUN_NAME_FILE）。
    #[test]
    fn boringtun_explicit_utun_reaches_command_plan() {
        let backend = MacSystemBackend::new()
            .with_interface("utun5")
            .with_mac_boringtun();
        // 命令计划层（bt_apply）对显式名成功——执行层 spawn 因无真实 utun 而
        // Io 失败，但这是执行错误不是计划拒绝；此处断言计划面不拒。
        let plan = crate::macos_wireguard_bt::bt_interface_plan(
            &crate::TunnelConfig {
                name: "net-a".into(),
                address: "10.240.0.7".parse().unwrap(),
                address_prefix: 16,
                listen_port: Some(51821),
                peers: Vec::new(),
                mtu: Some(1420),
                private_key: None,
            },
            "utun5",
        );
        assert!(plan.is_ok());
    }
}
