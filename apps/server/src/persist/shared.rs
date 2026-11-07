//! Shared SQLite transaction helpers and row mappings.

use meshlet_domain::{
    AliasMapping, ConfigRevision, DesiredStateStatus, Device, DeviceStatus, LanRoute,
    NetworkStatus, Platform,
};

#[derive(Clone)]
pub struct AuditDraft<'a> {
    pub actor_id: Option<&'a str>,
    pub action: &'a str,
    pub target_type: &'a str,
    pub target_id: &'a str,
    pub detail: Option<serde_json::Value>,
}

/// Boot summary exposed through the persistence facade.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MeshStatePersistedView {
    pub networks: usize,
    pub devices: usize,
    pub registrations: usize,
    pub routes: usize,
    pub aliases: usize,
    pub publishes: usize,
    pub segments: usize,
    pub segment_grants: usize,
    pub invites: usize,
    pub revisions: usize,
}

pub(crate) async fn insert_audit_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_events \
         (actor_id, action, target_type, target_id, detail, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(audit.actor_id)
    .bind(audit.action)
    .bind(audit.target_type)
    .bind(audit.target_id)
    .bind(audit.detail.as_ref().map(serde_json::Value::to_string))
    .bind(crate::service::now())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn insert_revision_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    revision: &ConfigRevision,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO config_revisions
           (network_id, revision, desired_config_hash, apply_status, created_at,
            applied_at, error_summary)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(revision.network_id.to_string())
    .bind(revision.revision as i64)
    .bind(&revision.desired_config_hash)
    .bind(revision.apply_status.as_str())
    .bind(&revision.created_at)
    .bind(&revision.applied_at)
    .bind(&revision.error_summary)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn insert_device_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    device: &Device,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices
            (id, network_id, name, virtual_ipv4, public_key, platform, status, segment_id,
            last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
            created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(device.id.to_string())
    .bind(device.network_id.to_string())
    .bind(&device.name)
    .bind(device.virtual_ipv4.to_string())
    .bind(&device.public_key)
    .bind(platform_to_str(device.platform))
    .bind(device_status_to_str(device.status))
    .bind(device.segment_id.to_string())
    .bind(&device.last_seen_at)
    .bind(&device.last_handshake_at)
    .bind(&device.last_report_at)
    .bind(
        device
            .dataplane_evidence
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| {
                sqlx::Error::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            })?,
    )
    .bind(&device.created_at)
    .bind(&device.revoked_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn insert_route_row_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    route: &LanRoute,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO lan_routes
           (id, network_id, gateway_device_id, destination_cidr, route_mode,
            return_path_mode, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(route.id.to_string())
    .bind(route.network_id.to_string())
    .bind(route.gateway_device_id.to_string())
    .bind(route.destination_cidr.to_string())
    .bind(route.route_mode.as_str())
    .bind(route.return_path_mode.as_str())
    .bind(desired_status_to_str(route.status))
    .bind(&route.created_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) async fn insert_alias_row_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    alias: &AliasMapping,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO alias_mappings
           (id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode,
            status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(alias.id.to_string())
    .bind(alias.network_id.to_string())
    .bind(alias.lan_route_id.to_string())
    .bind(alias.alias_cidr.to_string())
    .bind(alias.target_cidr.to_string())
    .bind(alias.translation_mode.as_str())
    .bind(desired_status_to_str(alias.status))
    .bind(crate::service::now())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(crate) async fn save_seq_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    key: &str,
    seq: u64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mesh_meta (key, value) VALUES (?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(seq.to_string())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub(super) fn device_status_to_str(s: DeviceStatus) -> &'static str {
    match s {
        DeviceStatus::Pending => "pending",
        DeviceStatus::Active => "active",
        DeviceStatus::Revoked => "revoked",
    }
}

pub(super) fn device_status_parse(s: &str) -> Result<DeviceStatus, String> {
    match s {
        "pending" => Ok(DeviceStatus::Pending),
        "active" => Ok(DeviceStatus::Active),
        "revoked" => Ok(DeviceStatus::Revoked),
        other => Err(format!("unknown device status {other:?}")),
    }
}

pub(super) fn network_status_to_str(s: NetworkStatus) -> &'static str {
    match s {
        NetworkStatus::Active => "active",
        NetworkStatus::Deleting => "deleting",
    }
}

pub(super) fn network_status_parse(s: &str) -> Result<NetworkStatus, String> {
    match s {
        "active" => Ok(NetworkStatus::Active),
        "deleting" => Ok(NetworkStatus::Deleting),
        other => Err(format!("unknown network status {other:?}")),
    }
}

pub(super) fn desired_status_to_str(s: DesiredStateStatus) -> &'static str {
    s.as_str()
}

pub(super) fn desired_status_parse(s: &str) -> Result<DesiredStateStatus, String> {
    match s {
        "pending" => Ok(DesiredStateStatus::Pending),
        "applied" => Ok(DesiredStateStatus::Applied),
        "failed" => Ok(DesiredStateStatus::Failed),
        other => Err(format!("unknown desired status {other:?}")),
    }
}

pub(super) fn segment_status_parse(value: &str) -> Result<meshlet_domain::SegmentStatus, String> {
    meshlet_domain::SegmentStatus::parse(value).ok_or_else(|| format!("unknown status {value:?}"))
}

pub(super) fn segment_grant_status_parse(
    value: &str,
) -> Result<meshlet_domain::SegmentGrantStatus, String> {
    meshlet_domain::SegmentGrantStatus::parse(value)
        .ok_or_else(|| format!("unknown status {value:?}"))
}

pub(super) fn apply_status_parse(s: &str) -> Result<meshlet_domain::ApplyStatus, String> {
    use meshlet_domain::ApplyStatus;
    match s {
        "pending" => Ok(ApplyStatus::Pending),
        "applying" => Ok(ApplyStatus::Applying),
        "applied" => Ok(ApplyStatus::Applied),
        "failed" => Ok(ApplyStatus::Failed),
        "rollback_pending" => Ok(ApplyStatus::RollbackPending),
        "rolled_back" => Ok(ApplyStatus::RolledBack),
        other => Err(format!("unknown apply status {other:?}")),
    }
}

pub(super) fn platform_to_str(p: Platform) -> &'static str {
    match p {
        Platform::Linux => "linux",
        Platform::Windows => "windows",
    }
}

pub(super) fn platform_parse(s: &str) -> Result<Platform, String> {
    match s {
        "linux" => Ok(Platform::Linux),
        "windows" => Ok(Platform::Windows),
        other => Err(format!("unknown platform {other:?}")),
    }
}

pub(super) fn corrupt(what: &str, e: impl std::fmt::Display) -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("corrupt persisted state: {what}: {e}"),
    ))
}
