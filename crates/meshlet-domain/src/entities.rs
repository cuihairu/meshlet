//! 核心领域实体（[领域模型文档](../../docs/architecture/domain-model.md)、
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)）。
//!
//! 时间戳以 ISO-8601 字符串承载（由应用层写入），保持领域层零时间库依赖。

use crate::cidr::Ipv4Cidr;
use std::collections::HashSet;

/// ISO-8601 时间戳（由应用层提供，如 `2026-10-14T08:00:00Z`）。
pub type Timestamp = String;

macro_rules! string_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub String);

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

string_id!(NetworkId, "网络标识。");
string_id!(DeviceId, "设备标识。");
string_id!(LanRouteId, "LAN 路由标识。");
string_id!(AliasMappingId, "Alias 映射标识。");
string_id!(UserId, "控制台用户标识。");
string_id!(InviteId, "邀请标识。");

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkStatus {
    Active,
    Deleting,
}

/// 私人虚拟网络。**Overlay CIDR 创建后不可变**（ADR-004）：
/// 该类型不提供任何修改 `overlay_cidr` 的方法，修改须重建网络或走迁移流程。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Network {
    pub id: NetworkId,
    pub name: String,
    pub overlay_cidr: Ipv4Cidr,
    pub status: NetworkStatus,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

impl Network {
    pub fn new(
        id: NetworkId,
        name: impl Into<String>,
        overlay_cidr: Ipv4Cidr,
        created_at: Timestamp,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            overlay_cidr,
            status: NetworkStatus::Active,
            created_at: created_at.clone(),
            updated_at: created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// Device / DeviceKey
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStatus {
    Pending,
    Active,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    Linux,
    Windows,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub id: DeviceId,
    pub network_id: NetworkId,
    pub name: String,
    pub virtual_ipv4: std::net::Ipv4Addr,
    pub public_key: String,
    pub platform: Platform,
    pub status: DeviceStatus,
    /// 最新一次证据时间（加入/心跳/上报到达时刻）——控制台「最后在线时间」。
    pub last_seen_at: Option<Timestamp>,
    /// 最近一次 WireGuard 握手（agent 经心跳上报 `wg show` 本地读数，§12.4）。
    pub last_handshake_at: Option<Timestamp>,
    /// 最近一次 agent 心跳/状态上报时刻（§14.1）。
    pub last_report_at: Option<Timestamp>,
    pub created_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceError {
    #[error("device already revoked at {0}")]
    AlreadyRevoked(Timestamp),
}

impl Device {
    pub fn is_active(&self) -> bool {
        self.status == DeviceStatus::Active
    }

    /// 撤销设备（§11.5 第 1-2 步；Peer/路由清理属于配置应用层）。
    /// 重复撤销报错而不是静默成功。
    pub fn revoke(&mut self, at: Timestamp) -> Result<(), DeviceError> {
        if let Some(prev) = self.revoked_at.clone() {
            return Err(DeviceError::AlreadyRevoked(prev));
        }
        self.status = DeviceStatus::Revoked;
        self.revoked_at = Some(at);
        Ok(())
    }
}

/// 设备密钥记录（与 Device 分离，便于轮换与撤销，§5.5）。
/// 服务端**只**保存公钥侧信息；不存在长期私钥字段（ADR-010）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKey {
    pub device_id: DeviceId,
    pub public_key: String,
    pub fingerprint: String,
    pub created_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

impl DeviceKey {
    pub fn is_effective(&self) -> bool {
        self.revoked_at.is_none()
    }
}

// ---------------------------------------------------------------------------
// LAN Route / Alias Mapping
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteMode {
    Direct,
    Alias,
}

/// 返回路径模式（ADR-005）：真实双向路由 / 受控 SNAT。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnPathMode {
    DualRoute,
    ControlledSnat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesiredStateStatus {
    Pending,
    Applied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanRoute {
    pub id: LanRouteId,
    pub network_id: NetworkId,
    pub gateway_device_id: DeviceId,
    pub destination_cidr: Ipv4Cidr,
    pub route_mode: RouteMode,
    pub return_path_mode: ReturnPathMode,
    pub status: DesiredStateStatus,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TranslationMode {
    DnatOnly,
    DnatSnat,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AliasError {
    #[error("prefix length mismatch: alias /{alias} vs target /{target} (equal length required, ADR-006)")]
    PrefixLengthMismatch { alias: u8, target: u8 },
    #[error("alias prefix must not equal target prefix")]
    SamePrefix,
}

/// 重叠网段的虚拟前缀映射（ADR-006）：Alias 与 Target 前缀等长、一对一替换。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AliasMapping {
    pub id: AliasMappingId,
    pub network_id: NetworkId,
    pub lan_route_id: LanRouteId,
    pub alias_cidr: Ipv4Cidr,
    pub target_cidr: Ipv4Cidr,
    pub translation_mode: TranslationMode,
    pub status: DesiredStateStatus,
}

impl AliasMapping {
    pub fn new(
        id: AliasMappingId,
        network_id: NetworkId,
        lan_route_id: LanRouteId,
        alias_cidr: Ipv4Cidr,
        target_cidr: Ipv4Cidr,
        translation_mode: TranslationMode,
    ) -> Result<Self, AliasError> {
        if alias_cidr.prefix_len() != target_cidr.prefix_len() {
            return Err(AliasError::PrefixLengthMismatch {
                alias: alias_cidr.prefix_len(),
                target: target_cidr.prefix_len(),
            });
        }
        if alias_cidr == target_cidr {
            return Err(AliasError::SamePrefix);
        }
        Ok(Self {
            id,
            network_id,
            lan_route_id,
            alias_cidr,
            target_cidr,
            translation_mode,
            status: DesiredStateStatus::Pending,
        })
    }

    /// 一对一前缀替换映射：`10.241.1.10 → 192.168.1.10`（§9.2）。
    pub fn translate(&self, ip: std::net::Ipv4Addr) -> Option<std::net::Ipv4Addr> {
        if !self.alias_cidr.contains(ip) {
            return None;
        }
        let offset = u32::from(ip) - u32::from(self.alias_cidr.network());
        Some(std::net::Ipv4Addr::from(
            u32::from(self.target_cidr.network()) + offset,
        ))
    }
}

// ---------------------------------------------------------------------------
// Config Revision（ADR-009 状态机）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyStatus {
    Pending,
    Applying,
    Applied,
    Failed,
    RollbackPending,
    RolledBack,
}

impl ApplyStatus {
    /// 合法跃迁（§10.2 流程图）：
    /// pending → applying；applying → applied | failed；
    /// failed → rollback_pending；rollback_pending → rolled_back。
    pub fn can_transition_to(self, to: Self) -> bool {
        use ApplyStatus::*;
        matches!(
            (self, to),
            (Pending, Applying)
                | (Applying, Applied)
                | (Applying, Failed)
                | (Failed, RollbackPending)
                | (RollbackPending, RolledBack)
        )
    }

    /// API/控制台展示用小写蛇形标识（契约字段 `apply_status`）。
    pub fn as_str(self) -> &'static str {
        match self {
            ApplyStatus::Pending => "pending",
            ApplyStatus::Applying => "applying",
            ApplyStatus::Applied => "applied",
            ApplyStatus::Failed => "failed",
            ApplyStatus::RollbackPending => "rollback_pending",
            ApplyStatus::RolledBack => "rolled_back",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRevision {
    pub network_id: NetworkId,
    pub revision: u64,
    pub desired_config_hash: String,
    pub apply_status: ApplyStatus,
    pub created_at: Timestamp,
    pub applied_at: Option<Timestamp>,
    pub error_summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RevisionError {
    #[error("illegal transition: {from:?} -> {to:?}")]
    IllegalTransition { from: ApplyStatus, to: ApplyStatus },
}

impl ConfigRevision {
    pub fn new(
        network_id: NetworkId,
        revision: u64,
        desired_config_hash: String,
        created_at: Timestamp,
    ) -> Self {
        Self {
            network_id,
            revision,
            desired_config_hash,
            apply_status: ApplyStatus::Pending,
            created_at,
            applied_at: None,
            error_summary: None,
        }
    }

    pub fn transition(&mut self, to: ApplyStatus) -> Result<(), RevisionError> {
        let from = self.apply_status;
        if !from.can_transition_to(to) {
            return Err(RevisionError::IllegalTransition { from, to });
        }
        self.apply_status = to;
        Ok(())
    }
}

/// 网络内设备注册表：集中保障「同一网络内虚拟 IP 唯一」（§5.4）。
#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    devices: Vec<Device>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RegistryError {
    #[error("duplicate virtual ip {0} in network")]
    DuplicateVirtualIp(std::net::Ipv4Addr),
    #[error("duplicate device name {0:?}")]
    DuplicateName(String),
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn devices(&self) -> &[Device] {
        &self.devices
    }

    pub fn find_by_id(&self, id: &DeviceId) -> Option<&Device> {
        self.devices.iter().find(|d| d.id == *id)
    }

    pub fn find_by_id_mut(&mut self, id: &DeviceId) -> Option<&mut Device> {
        self.devices.iter_mut().find(|d| d.id == *id)
    }

    pub fn add(&mut self, device: Device) -> Result<(), RegistryError> {
        if self
            .devices
            .iter()
            .any(|d| d.virtual_ipv4 == device.virtual_ipv4)
        {
            return Err(RegistryError::DuplicateVirtualIp(device.virtual_ipv4));
        }
        if self.devices.iter().any(|d| d.name == device.name) {
            return Err(RegistryError::DuplicateName(device.name));
        }
        self.devices.push(device);
        Ok(())
    }

    pub fn active_virtual_ips(&self) -> HashSet<std::net::Ipv4Addr> {
        self.devices
            .iter()
            .filter(|d| d.is_active())
            .map(|d| d.virtual_ipv4)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const T0: &str = "2026-10-14T08:00:00Z";
    const T1: &str = "2026-10-14T09:00:00Z";

    fn net() -> Network {
        Network::new(
            NetworkId("net-1".into()),
            "home",
            "10.240.0.0/16".parse().unwrap(),
            T0.into(),
        )
    }

    #[test]
    fn network_cidr_is_immutable_by_construction() {
        // 领域层不提供 CIDR 修改途径；断言构造保留原值。
        let n = net();
        assert_eq!(n.overlay_cidr.to_string(), "10.240.0.0/16");
    }

    #[test]
    fn revoke_device_once_and_reject_twice() {
        let mut d = Device {
            id: DeviceId("dev-1".into()),
            network_id: NetworkId("net-1".into()),
            name: "laptop".into(),
            virtual_ipv4: "10.240.0.2".parse::<Ipv4Addr>().unwrap(),
            public_key: "pub".into(),
            platform: Platform::Linux,
            status: DeviceStatus::Active,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            created_at: T0.into(),
            revoked_at: None,
        };
        assert!(d.is_active());
        d.revoke(T1.into()).unwrap();
        assert_eq!(d.status, DeviceStatus::Revoked);
        assert_eq!(d.revoked_at.as_deref(), Some(T1));
        assert!(!d.is_active());
        assert!(matches!(
            d.revoke(T0.into()),
            Err(DeviceError::AlreadyRevoked(_))
        ));
    }

    #[test]
    fn device_key_effective_until_revoked() {
        let k = DeviceKey {
            device_id: DeviceId("dev-1".into()),
            public_key: "pub".into(),
            fingerprint: "fp".into(),
            created_at: T0.into(),
            revoked_at: None,
        };
        assert!(k.is_effective());
        let mut k2 = k.clone();
        k2.revoked_at = Some(T1.into());
        assert!(!k2.is_effective());
    }

    #[test]
    fn alias_requires_equal_prefix_length() {
        let err = AliasMapping::new(
            AliasMappingId("a-1".into()),
            NetworkId("net-1".into()),
            LanRouteId("r-1".into()),
            "10.241.1.0/24".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            AliasError::PrefixLengthMismatch {
                alias: 24,
                target: 16
            }
        ));
    }

    #[test]
    fn alias_rejects_identity_mapping() {
        let err = AliasMapping::new(
            AliasMappingId("a-1".into()),
            NetworkId("net-1".into()),
            LanRouteId("r-1".into()),
            "192.168.1.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap_err();
        assert!(matches!(err, AliasError::SamePrefix));
    }

    #[test]
    fn alias_translates_one_to_one() {
        let a = AliasMapping::new(
            AliasMappingId("a-1".into()),
            NetworkId("net-1".into()),
            LanRouteId("r-1".into()),
            "10.241.1.0/24".parse().unwrap(),
            "192.168.1.0/24".parse().unwrap(),
            TranslationMode::DnatSnat,
        )
        .unwrap();
        let t = |s: &str| a.translate(s.parse().unwrap());
        assert_eq!(t("10.241.1.10"), Some("192.168.1.10".parse().unwrap()));
        assert_eq!(t("10.241.1.20"), Some("192.168.1.20".parse().unwrap()));
        assert_eq!(t("10.241.1.255"), Some("192.168.1.255".parse().unwrap()));
        assert_eq!(t("10.241.2.10"), None); // 前缀外
        assert_eq!(t("10.240.0.2"), None);
    }

    #[test]
    fn apply_status_legal_transitions() {
        use ApplyStatus::*;
        let legal = [
            (Pending, Applying),
            (Applying, Applied),
            (Applying, Failed),
            (Failed, RollbackPending),
            (RollbackPending, RolledBack),
        ];
        for (from, to) in legal {
            assert!(
                from.can_transition_to(to),
                "{from:?} -> {to:?} should be legal"
            );
        }
        let illegal = [
            (Pending, Applied),
            (Pending, Failed),
            (Applied, Applying),
            (Applied, Failed),
            (Failed, Applying),
            (RolledBack, Applying),
            (RollbackPending, Applied),
            (Applied, Pending),
        ];
        for (from, to) in illegal {
            assert!(
                !from.can_transition_to(to),
                "{from:?} -> {to:?} should be illegal"
            );
        }
    }

    #[test]
    fn revision_full_lifecycle_and_reject_skip() {
        let mut r = ConfigRevision::new(NetworkId("net-1".into()), 1, "hash".into(), T0.into());
        assert_eq!(r.apply_status, ApplyStatus::Pending);

        // 跳过 applying 直接 applied 必须失败
        assert!(r.transition(ApplyStatus::Applied).is_err());

        r.transition(ApplyStatus::Applying).unwrap();
        r.transition(ApplyStatus::Failed).unwrap();
        r.error_summary = Some("nft rules rejected".into());
        r.transition(ApplyStatus::RollbackPending).unwrap();
        r.transition(ApplyStatus::RolledBack).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        // 终态后再跃迁失败
        assert!(r.transition(ApplyStatus::Applying).is_err());
    }

    #[test]
    fn registry_rejects_duplicate_ip_and_name() {
        let mk = |name: &str, ip: &str| Device {
            id: DeviceId(format!("dev-{name}")),
            network_id: NetworkId("net-1".into()),
            name: name.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: "pub".into(),
            platform: Platform::Linux,
            status: DeviceStatus::Active,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            created_at: T0.into(),
            revoked_at: None,
        };
        let mut reg = DeviceRegistry::new();
        reg.add(mk("laptop", "10.240.0.2")).unwrap();
        assert!(matches!(
            reg.add(mk("nas", "10.240.0.2")),
            Err(RegistryError::DuplicateVirtualIp(_))
        ));
        assert!(matches!(
            reg.add(mk("laptop", "10.240.0.3")),
            Err(RegistryError::DuplicateName(_))
        ));
        reg.add(mk("nas", "10.240.0.3")).unwrap();
        assert_eq!(reg.active_virtual_ips().len(), 2);
    }

    #[test]
    fn registry_find_by_id_returns_device_for_update() {
        let mk = |name: &str, ip: &str| Device {
            id: DeviceId(format!("dev-{name}")),
            network_id: NetworkId("net-1".into()),
            name: name.into(),
            virtual_ipv4: ip.parse().unwrap(),
            public_key: "pub".into(),
            platform: Platform::Linux,
            status: DeviceStatus::Active,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            created_at: T0.into(),
            revoked_at: None,
        };
        let mut reg = DeviceRegistry::new();
        let laptop = mk("laptop", "10.240.0.2");
        let id = laptop.id.clone();
        reg.add(laptop).unwrap();

        assert_eq!(reg.find_by_id(&id).unwrap().name, "laptop");
        assert!(reg.find_by_id(&DeviceId("dev-nope".into())).is_none());
        let d = reg.find_by_id_mut(&id).unwrap();
        d.last_report_at = Some(T0.into());
        assert_eq!(
            reg.find_by_id(&id).unwrap().last_report_at.as_deref(),
            Some(T0)
        );
    }
}
