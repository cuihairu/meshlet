//! Core domain entities ([domain model doc](../../docs/architecture/domain-model.md),
//! [ADR-009](../../docs/decisions/adr-009-config-revision-rollback.md)).
//!
//! Timestamps are carried as ISO-8601 strings (written by the application layer), keeping the domain layer free of any time-library dependency.

use crate::cidr::Ipv4Cidr;
use std::collections::{BTreeMap, HashSet};

/// ISO-8601 timestamp (provided by the application layer, e.g. `2026-10-14T08:00:00Z`).
pub type Timestamp = String;

macro_rules! string_id {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
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
string_id!(BootstrapTokenId, "自举码标识（设备自举注册入口凭据）。");
string_id!(SegmentId, "段标识。");
string_id!(SegmentGrantId, "段授权标识。");

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkStatus {
    Active,
    Deleting,
}

/// Private virtual network. **The overlay CIDR is immutable once created** (ADR-004):
/// no method on this type modifies `overlay_cidr`; changing it requires rebuilding the network or going through the migration flow.
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
    /// Time of the latest evidence (join/heartbeat/report arrival) — the console "last seen time".
    pub last_seen_at: Option<Timestamp>,
    /// Most recent WireGuard handshake (agent reports the local `wg show` reading via heartbeat, §12.4).
    pub last_handshake_at: Option<Timestamp>,
    /// Time of the most recent agent heartbeat/status report (§14.1).
    pub last_report_at: Option<Timestamp>,
    /// Dataplane evidence echoed back by the most recent heartbeat (§7.5: kernel readings + large-packet probe);
    /// `None` = no agent has reported yet (old agent / not running).
    pub dataplane_evidence: Option<DataplaneEvidence>,
    pub created_at: Timestamp,
    /// Approval time (bootstrap registration path, see [DeviceRegistration]); `None` on the invite-join path
    /// (`created_at` is the join time).
    pub approved_at: Option<Timestamp>,
    /// The segment the device uniquely belongs to (ADR-012). Backfilled by migrations 010/011 when restoring an old DB.
    pub segment_id: SegmentId,
    pub revoked_at: Option<Timestamp>,
    /// Node labels (role/capability etc., assigned by an operator; the match basis for MT-005 label routing).
    /// Empty = untagged, matches any task with no label requirement.
    pub labels: BTreeMap<String, String>,
}

/// Pending device registration application (ZeroTier-style bootstrap registration: a device bootstraps with a bootstrap token →
/// lands in this table → the control center approves/rejects it).
///
/// Design points: **Pending applications never enter `DeviceRegistry`**, so they take no overlay address, do not
/// enter the desired config, and do not enter Peer AllowedIPs — the virtual IP is only allocated and it moves
/// into [Device] at approval time (the ID was assigned at registration, approval does not change it, so `agent_tokens` refs need no migration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRegistration {
    pub id: DeviceId,
    pub network_id: NetworkId,
    pub name: String,
    pub public_key: String,
    pub platform: Platform,
    /// Request time (the start of the console "awaiting approval", and also the creation time of this device id).
    pub requested_at: Timestamp,
    /// Time the agent's most recent heartbeat arrived — a Pending device has no `devices` row yet, so evidence lands only here.
    pub last_report_at: Option<Timestamp>,
    /// Dataplane evidence echoed back by the agent heartbeat (§7.5); `None` = not yet reported.
    pub dataplane_evidence: Option<DataplaneEvidence>,
}

/// Bootstrap token: **stores only a SHA-256 digest**, under the same discipline as invite tokens (§11.3).
/// Semantic difference: it is a **long-term, reusable** registration entry point (admins can revoke/limit it),
/// not a single-use join credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapToken {
    pub id: BootstrapTokenId,
    pub network_id: NetworkId,
    pub token_hash: String,
    /// Maximum number of uses; `None` = unlimited.
    pub max_uses: Option<u32>,
    pub used_count: u32,
    pub created_at: Timestamp,
    pub revoked_at: Option<Timestamp>,
}

/// Dataplane evidence measured on the device side (echoed back by the agent heartbeat, §7.5/§12.4):
/// kernel readings + large-packet probe. Each field being `None` means "not obtainable locally"
/// (missing tool / probe unreachable); the server treats it as "evidence missing" and never invents defaults.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct DataplaneEvidence {
    /// Actual MTU of the tunnel interface (local reading from `ip link show`).
    pub tunnel_mtu: Option<u32>,
    /// Meshlet NAT rules exist in the local kernel (scanned by ownership comment; gateway-device related).
    pub nat_rules_present: Option<bool>,
    /// Meshlet-managed SNAT rules exist in the local kernel (POSTROUTING chain); combined with
    /// `nat_rules_present` to distinguish `dnat_snat` from `dnat_only` — the latter keeps the
    /// original source address, ADR-005 (kernel-measured reading; `None` = not reported or unobservable).
    pub nat_snat_rules_present: Option<bool>,
    /// Large-packet probe: `ping -M do` reached an overlay peer successfully with this payload size
    /// (`None` = not probed or the probe failed — the planned MTU is unavailable on the path or the peer is unreachable).
    pub mtu_probe_payload: Option<u32>,
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

    /// Label-route matching (MT-005, pure function): a task is admitted only if every
    /// `(key, value)` pair of its `required_labels` hits a device label. An empty requirement is
    /// unconstrained (any device may take it); a differing value counts as no match (role=worker does not satisfy role=builder).
    pub fn matches_labels(&self, required: &BTreeMap<String, String>) -> bool {
        required.iter().all(|(k, v)| self.labels.get(k) == Some(v))
    }

    /// Revoke the device (§11.5 steps 1-2; Peer/route cleanup belongs to the config-apply layer).
    /// Revoking twice is an error rather than a silent success.
    pub fn revoke(&mut self, at: Timestamp) -> Result<(), DeviceError> {
        if let Some(prev) = self.revoked_at.clone() {
            return Err(DeviceError::AlreadyRevoked(prev));
        }
        self.status = DeviceStatus::Revoked;
        self.revoked_at = Some(at);
        Ok(())
    }
}

/// Label-route selection (MT-005, pure function): among candidate devices, pick the first Active
/// one (in deterministic id order) that satisfies the label requirement. An empty requirement is
/// unconstrained, picking the first Active device; no hit returns `None` (the caller treats it as nothing dispatchable).
pub fn select_by_labels<'a>(
    devices: &'a [Device],
    required: &BTreeMap<String, String>,
) -> Option<&'a Device> {
    let mut sorted: Vec<&Device> = devices
        .iter()
        .filter(|d| d.is_active())
        .filter(|d| d.matches_labels(required))
        .collect();
    sorted.sort_by(|a, b| a.id.cmp(&b.id));
    sorted.into_iter().next()
}

/// Device key record (kept separate from Device to ease rotation and revocation, §5.5).
/// The server stores **only** public-key-side information; there is no long-lived private-key field (ADR-010).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RouteMode {
    Direct,
    Alias,
}

/// Return-path mode (ADR-005): real bidirectional routing / controlled SNAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReturnPathMode {
    DualRoute,
    ControlledSnat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DesiredStateStatus {
    Pending,
    Applied,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TranslationMode {
    DnatOnly,
    DnatSnat,
}

impl TranslationMode {
    /// Lowercase snake_case identifier for API/console display (contract field `translation_mode`).
    pub fn as_str(self) -> &'static str {
        match self {
            TranslationMode::DnatOnly => "dnat_only",
            TranslationMode::DnatSnat => "dnat_snat",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dnat_only" => Some(TranslationMode::DnatOnly),
            "dnat_snat" => Some(TranslationMode::DnatSnat),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AliasError {
    #[error("prefix length mismatch: alias /{alias} vs target /{target} (equal length required, ADR-006)")]
    PrefixLengthMismatch { alias: u8, target: u8 },
    #[error("alias prefix must not equal target prefix")]
    SamePrefix,
}

/// Virtual prefix mapping for overlapping subnets (ADR-006): Alias and Target prefixes have equal length and are swapped one-to-one.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

    /// One-to-one prefix replacement mapping: `10.241.1.10 → 192.168.1.10` (§9.2).
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
// Config Revision (ADR-009 state machine)
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
    /// Legal transitions (§10.2 flowchart):
    /// pending → applying; applying → applied | failed;
    /// failed → rollback_pending; rollback_pending → rolled_back.
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

    /// Lowercase snake_case identifier for API/console display (contract field `apply_status`).
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

impl RouteMode {
    /// Lowercase snake_case identifier for API/console display (contract field `route_mode`).
    pub fn as_str(self) -> &'static str {
        match self {
            RouteMode::Direct => "direct",
            RouteMode::Alias => "alias",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "direct" => Some(RouteMode::Direct),
            "alias" => Some(RouteMode::Alias),
            _ => None,
        }
    }
}

impl ReturnPathMode {
    /// Lowercase snake_case identifier for API/console display (contract field `return_path_mode`).
    pub fn as_str(self) -> &'static str {
        match self {
            ReturnPathMode::DualRoute => "dual_route",
            ReturnPathMode::ControlledSnat => "controlled_snat",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dual_route" => Some(ReturnPathMode::DualRoute),
            "controlled_snat" => Some(ReturnPathMode::ControlledSnat),
            _ => None,
        }
    }
}

impl DesiredStateStatus {
    /// Lowercase snake_case identifier for API/console display (contract field `status`).
    pub fn as_str(self) -> &'static str {
        match self {
            DesiredStateStatus::Pending => "pending",
            DesiredStateStatus::Applied => "applied",
            DesiredStateStatus::Failed => "failed",
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

/// Per-network device registry: centrally enforces "virtual IP uniqueness within a network" (§5.4).
#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    devices: Vec<Device>,
    /// Pending device registration applications ([DeviceRegistration]). Stored separately from `devices`:
    /// Pending devices do not participate in desired-config / Peer derivation / IPAM, and only move into `devices` on approval.
    registrations: Vec<DeviceRegistration>,
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
        if self.name_taken(&device.name) {
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

    // ------------------------------------------------------------------
    // Pending registration applications (ZeroTier-style bootstrap registration)
    // ------------------------------------------------------------------

    pub fn registrations(&self) -> &[DeviceRegistration] {
        &self.registrations
    }

    pub fn find_registration(&self, id: &DeviceId) -> Option<&DeviceRegistration> {
        self.registrations.iter().find(|r| r.id == *id)
    }

    pub fn find_registration_mut(&mut self, id: &DeviceId) -> Option<&mut DeviceRegistration> {
        self.registrations.iter_mut().find(|r| r.id == *id)
    }

    /// Register a registration application. **Name uniqueness is checked across both `devices` and `registrations`**
    /// (duplicate names are not allowed inside one network, whatever stage the device is in).
    pub fn add_registration(
        &mut self,
        registration: DeviceRegistration,
    ) -> Result<(), RegistryError> {
        if self.name_taken(&registration.name) {
            return Err(RegistryError::DuplicateName(registration.name));
        }
        if self.registrations.iter().any(|r| r.id == registration.id) {
            return Err(RegistryError::DuplicateName(registration.name));
        }
        self.registrations.push(registration);
        Ok(())
    }

    /// Remove a registration application (called on approve/reject); returns the removed application.
    pub fn remove_registration(&mut self, id: &DeviceId) -> Option<DeviceRegistration> {
        let pos = self.registrations.iter().position(|r| r.id == *id)?;
        Some(self.registrations.remove(pos))
    }

    /// Whether a name is already taken (on either the `devices` or `registrations` side).
    pub fn name_taken(&self, name: &str) -> bool {
        self.devices.iter().any(|d| d.name == name)
            || self.registrations.iter().any(|r| r.name == name)
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
        // The domain layer offers no CIDR-modification path; assert that construction kept the original value.
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
            dataplane_evidence: None,
            created_at: T0.into(),
            approved_at: None,
            revoked_at: None,
            segment_id: SegmentId("seg-net-1".into()),
            labels: BTreeMap::new(),
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
        assert_eq!(t("10.241.2.10"), None); // outside the prefix
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

        // Skipping applying and going straight to applied must fail
        assert!(r.transition(ApplyStatus::Applied).is_err());

        r.transition(ApplyStatus::Applying).unwrap();
        r.transition(ApplyStatus::Failed).unwrap();
        r.error_summary = Some("nft rules rejected".into());
        r.transition(ApplyStatus::RollbackPending).unwrap();
        r.transition(ApplyStatus::RolledBack).unwrap();
        assert_eq!(r.apply_status, ApplyStatus::RolledBack);
        // Transitioning after a terminal state fails
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
            dataplane_evidence: None,
            created_at: T0.into(),
            approved_at: None,
            revoked_at: None,
            segment_id: SegmentId("seg-net-1".into()),
            labels: BTreeMap::new(),
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
            dataplane_evidence: None,
            created_at: T0.into(),
            approved_at: None,
            revoked_at: None,
            segment_id: SegmentId("seg-net-1".into()),
            labels: BTreeMap::new(),
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

    // ---- MT-005 label routing (pure functions) ----

    fn device_with_labels(id: &str, labels: &[(&str, &str)], active: bool) -> Device {
        Device {
            id: DeviceId(id.into()),
            network_id: NetworkId("net-1".into()),
            name: id.into(),
            virtual_ipv4: "10.240.0.2".parse::<Ipv4Addr>().unwrap(),
            public_key: "pub".into(),
            platform: Platform::Linux,
            status: if active {
                DeviceStatus::Active
            } else {
                DeviceStatus::Revoked
            },
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: T0.into(),
            approved_at: None,
            revoked_at: active.then(|| T0.into()),
            segment_id: SegmentId("seg-net-1".into()),
            labels: labels
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn matches_labels_requires_every_required_pair() {
        let d = device_with_labels("dev-1", &[("role", "worker"), ("cap", "gpu")], true);
        let mut need = BTreeMap::new();
        need.insert("role".to_string(), "worker".to_string());
        need.insert("cap".to_string(), "gpu".to_string());
        assert!(d.matches_labels(&need));
    }

    #[test]
    fn matches_labels_rejects_missing_or_mismatched_pair() {
        let d = device_with_labels("dev-1", &[("role", "worker")], true);
        let mut missing = BTreeMap::new();
        missing.insert("cap".to_string(), "gpu".to_string());
        assert!(!d.matches_labels(&missing));
        let mut mismatch = BTreeMap::new();
        mismatch.insert("role".to_string(), "builder".to_string());
        assert!(!d.matches_labels(&mismatch));
    }

    #[test]
    fn matches_labels_empty_requirement_is_unconstrained() {
        let d = device_with_labels("dev-1", &[("role", "worker")], true);
        assert!(d.matches_labels(&BTreeMap::new()));
    }

    #[test]
    fn select_by_labels_picks_first_active_by_id_and_skips_others() {
        let devices = vec![
            device_with_labels("dev-b", &[("role", "worker")], true),
            device_with_labels("dev-a", &[("role", "worker")], true),
            // Labels do not match: not selected.
            device_with_labels("dev-c", &[("role", "builder")], true),
            // Revoked: not selected.
            device_with_labels("dev-d", &[("role", "worker")], false),
        ];
        let mut need = BTreeMap::new();
        need.insert("role".to_string(), "worker".to_string());
        let picked = select_by_labels(&devices, &need).expect("must select a device");
        // Deterministic id order: dev-a before dev-b.
        assert_eq!(picked.id, DeviceId("dev-a".into()));
    }

    #[test]
    fn select_by_labels_no_hit_returns_none() {
        let devices = vec![device_with_labels("dev-a", &[("role", "worker")], true)];
        let mut need = BTreeMap::new();
        need.insert("role".to_string(), "builder".to_string());
        assert!(select_by_labels(&devices, &need).is_none());
        // Empty requirement but everything revoked: no Active device to dispatch to.
        let revoked = vec![device_with_labels("dev-a", &[("role", "worker")], false)];
        assert!(select_by_labels(&revoked, &BTreeMap::new()).is_none());
    }
}
