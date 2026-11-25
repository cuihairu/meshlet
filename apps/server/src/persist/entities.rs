//! SQLite write mirroring for mesh entities and transactional commits.

use super::shared::{
    desired_status_to_str, device_status_to_str, insert_alias_row_tx, insert_audit_tx,
    insert_device_tx, insert_revision_tx, insert_route_row_tx, network_status_to_str,
    platform_to_str, AuditDraft,
};
use meshlet_domain::{
    AliasMapping, BootstrapToken, BootstrapTokenId, ConfigRevision, Device, DeviceId,
    DeviceRegistration, Invite, LanRoute, Network, Segment, SegmentGrant,
};
use sqlx::SqlitePool;

pub async fn commit_network(
    pool: &SqlitePool,
    network: &Network,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(network.id.to_string())
    .bind(&network.name)
    .bind(network.overlay_cidr.to_string())
    .bind(network_status_to_str(network.status))
    .bind(&network.created_at)
    .bind(&network.updated_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
         VALUES (?, ?, 'default', ?, 'active', ?)",
    )
    .bind(meshlet_domain::default_segment_id(&network.id).to_string())
    .bind(network.id.to_string())
    .bind(network.overlay_cidr.to_string())
    .bind(&network.created_at)
    .execute(&mut *tx)
    .await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_enrollment(
    pool: &SqlitePool,
    device: &Device,
    revision: &ConfigRevision,
    invite: &Invite,
    audit: &AuditDraft<'_>,
) -> Result<String, sqlx::Error> {
    let raw_agent_token = meshlet_domain::generate_token();
    let mut tx = pool.begin().await?;
    insert_device_tx(&mut tx, device).await?;
    insert_revision_tx(&mut tx, revision).await?;
    sqlx::query(
        "INSERT INTO invitations
           (id, network_id, token_hash, expires_at, max_uses, used_count, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           used_count = excluded.used_count,
           revoked_at = excluded.revoked_at",
    )
    .bind(invite.id.to_string())
    .bind(invite.network_id.to_string())
    .bind(&invite.token_hash)
    .bind(&invite.expires_at)
    .bind(invite.max_uses)
    .bind(invite.used_count)
    .bind(&invite.created_at)
    .bind(&invite.revoked_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO agent_tokens (token_hash, device_id, created_at) VALUES (?, ?, ?)")
        .bind(meshlet_domain::token_hash(&raw_agent_token))
        .bind(device.id.to_string())
        .bind(crate::service::now())
        .execute(&mut *tx)
        .await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(raw_agent_token)
}

pub async fn commit_route(
    pool: &SqlitePool,
    route: &LanRoute,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_route_row_tx(&mut tx, route).await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_alias(
    pool: &SqlitePool,
    alias: &AliasMapping,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_alias_row_tx(&mut tx, alias).await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_host_forward(
    pool: &SqlitePool,
    route: &LanRoute,
    alias: &AliasMapping,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    insert_route_row_tx(&mut tx, route).await?;
    insert_alias_row_tx(&mut tx, alias).await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_segment(
    pool: &SqlitePool,
    segment: &Segment,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(segment.id.to_string())
    .bind(segment.network_id.to_string())
    .bind(&segment.name)
    .bind(segment.cidr.to_string())
    .bind(segment.status.as_str())
    .bind(&segment.created_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_segment_grant(
    pool: &SqlitePool,
    grant: &SegmentGrant,
    route_seq: u64,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO segment_grants
           (id, network_id, source_segment_id, destination_segment_id, status, created_at,
            revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(grant.id.to_string())
    .bind(grant.network_id.to_string())
    .bind(grant.source_segment_id.to_string())
    .bind(grant.destination_segment_id.to_string())
    .bind(grant.status.as_str())
    .bind(&grant.created_at)
    .bind(&grant.revoked_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_segment_grant_status(
    pool: &SqlitePool,
    grant: &SegmentGrant,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE segment_grants
         SET status = ?, revoked_at = ?
         WHERE id = ? AND network_id = ?",
    )
    .bind(grant.status.as_str())
    .bind(&grant.revoked_at)
    .bind(grant.id.to_string())
    .bind(grant.network_id.to_string())
    .execute(&mut *tx)
    .await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_route_delete(
    pool: &SqlitePool,
    route_id: &str,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM alias_mappings WHERE lan_route_id = ?")
        .bind(route_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM lan_routes WHERE id = ?")
        .bind(route_id)
        .execute(&mut *tx)
        .await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_approve_registration(
    pool: &SqlitePool,
    registration: &DeviceRegistration,
    device: &Device,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO devices
            (id, network_id, name, virtual_ipv4, public_key, platform, status, segment_id,
            last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
            created_at, approved_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                sqlx::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
            })?,
    )
    .bind(&device.created_at)
    .bind(&device.approved_at)
    .bind(&device.revoked_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM device_registrations WHERE id = ?")
        .bind(registration.id.to_string())
        .execute(&mut *tx)
        .await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub async fn commit_revoke_device(
    pool: &SqlitePool,
    device: &Device,
    revision: &ConfigRevision,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE devices SET status = ?, revoked_at = ? WHERE id = ?")
        .bind(device_status_to_str(device.status))
        .bind(&device.revoked_at)
        .bind(device.id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "DELETE FROM alias_mappings WHERE lan_route_id IN
           (SELECT id FROM lan_routes WHERE gateway_device_id = ?)",
    )
    .bind(device.id.to_string())
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM lan_routes WHERE gateway_device_id = ?")
        .bind(device.id.to_string())
        .execute(&mut *tx)
        .await?;
    insert_revision_tx(&mut tx, revision).await?;
    sqlx::query(
        "UPDATE agent_tokens SET revoked_at = ? WHERE device_id = ? AND revoked_at IS NULL",
    )
    .bind(crate::service::now())
    .bind(device.id.to_string())
    .execute(&mut *tx)
    .await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}
// ---------------------------------------------------------------------------
// Write path (mirror of new rows)
// ---------------------------------------------------------------------------

/// Persist one network row.
pub async fn insert_network(pool: &SqlitePool, n: &Network) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO networks (id, name, overlay_cidr, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(n.id.to_string())
    .bind(&n.name)
    .bind(n.overlay_cidr.to_string())
    .bind(network_status_to_str(n.status))
    .bind(&n.created_at)
    .bind(&n.updated_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
         VALUES (?, ?, 'default', ?, 'active', ?)",
    )
    .bind(meshlet_domain::default_segment_id(&n.id).to_string())
    .bind(n.id.to_string())
    .bind(n.overlay_cidr.to_string())
    .bind(&n.created_at)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Dataplane evidence -> JSON column value (`None` -> NULL).
fn evidence_json(d: &Device) -> Option<String> {
    d.dataplane_evidence
        .as_ref()
        .map(|e| serde_json::to_string(e).expect("DataplaneEvidence serialization cannot fail"))
}

/// Persist one device row (enroll).
pub async fn insert_device(pool: &SqlitePool, d: &Device) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO devices
            (id, network_id, name, virtual_ipv4, public_key, platform, status, segment_id,
            last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
            created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(d.id.to_string())
    .bind(d.network_id.to_string())
    .bind(&d.name)
    .bind(d.virtual_ipv4.to_string())
    .bind(&d.public_key)
    .bind(platform_to_str(d.platform))
    .bind(device_status_to_str(d.status))
    .bind(d.segment_id.to_string())
    .bind(&d.last_seen_at)
    .bind(&d.last_handshake_at)
    .bind(&d.last_report_at)
    .bind(evidence_json(d))
    .bind(&d.created_at)
    .bind(&d.revoked_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Write back device status (revocation: status/revoked_at).
pub async fn update_device_status(pool: &SqlitePool, d: &Device) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE devices SET status = ?, revoked_at = ? WHERE id = ?")
        .bind(device_status_to_str(d.status))
        .bind(&d.revoked_at)
        .bind(d.id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Persist device labels + audit (same transaction; no trace, no passage).
/// Labels do not count as a revision -- they are route metadata, not network
/// configuration.
pub async fn commit_device_labels(
    pool: &SqlitePool,
    device: &Device,
    audit: &AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    let json = serde_json::to_string(&device.labels).map_err(|e| {
        sqlx::Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            e.to_string(),
        ))
    })?;
    sqlx::query("UPDATE devices SET labels = ? WHERE id = ?")
        .bind(json)
        .bind(device.id.to_string())
        .execute(&mut *tx)
        .await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

/// Write back liveness evidence timestamps + measured dataplane evidence
/// (heartbeat path, §14.1/§7.5).
pub async fn update_device_presence(pool: &SqlitePool, d: &Device) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE devices SET last_seen_at = ?, last_handshake_at = ?, last_report_at = ?, \
         dataplane_evidence = ? WHERE id = ?",
    )
    .bind(&d.last_seen_at)
    .bind(&d.last_handshake_at)
    .bind(&d.last_report_at)
    .bind(evidence_json(d))
    .bind(d.id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist one LAN route + the current route id sequence (same transaction).
#[allow(dead_code)]
pub async fn insert_route(
    pool: &SqlitePool,
    r: &LanRoute,
    route_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO lan_routes
           (id, network_id, gateway_device_id, destination_cidr, route_mode,
            return_path_mode, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(r.id.to_string())
    .bind(r.network_id.to_string())
    .bind(r.gateway_device_id.to_string())
    .bind(r.destination_cidr.to_string())
    .bind(r.route_mode.as_str())
    .bind(r.return_path_mode.as_str())
    .bind(desired_status_to_str(r.status))
    .bind(&r.created_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    tx.commit().await?;
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

/// Persist one bootstrap token (only the digest is stored, §11.3) + the
/// current bootstrap sequence (same transaction).
/// `bootstrap_seq` drives `bt-N`; the registration request sequence
/// (`dev-reg-N`) lives in [`insert_registration`] -- the prefixes do not
/// collide, so each only needs to be monotonic on its own.
pub async fn save_bootstrap_token(
    pool: &SqlitePool,
    t: &BootstrapToken,
    bootstrap_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO bootstrap_tokens
           (id, network_id, token_hash, max_uses, used_count, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           used_count = excluded.used_count,
           revoked_at = excluded.revoked_at",
    )
    .bind(t.id.to_string())
    .bind(t.network_id.to_string())
    .bind(&t.token_hash)
    .bind(t.max_uses)
    .bind(t.used_count as i64)
    .bind(&t.created_at)
    .bind(&t.revoked_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "bootstrap_seq", bootstrap_seq).await?;
    tx.commit().await?;
    Ok(())
}

/// Revoke a bootstrap token: only write back the revocation time (whole-row
/// upsert, same semantics as `save_invite`).
pub async fn revoke_bootstrap_token_db(
    pool: &SqlitePool,
    id: &BootstrapTokenId,
    revoked_at: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE bootstrap_tokens SET revoked_at = ? WHERE id = ?")
        .bind(revoked_at)
        .bind(id.to_string())
        .execute(pool)
        .await?;
    Ok(())
}

/// Register one device registration request (Pending) + the current
/// registration sequence (same transaction).
pub async fn insert_registration(
    pool: &SqlitePool,
    r: &DeviceRegistration,
    registration_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO device_registrations
           (id, network_id, name, public_key, platform, requested_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(r.id.to_string())
    .bind(r.network_id.to_string())
    .bind(&r.name)
    .bind(&r.public_key)
    .bind(platform_to_str(r.platform))
    .bind(&r.requested_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "registration_seq", registration_seq).await?;
    tx.commit().await?;
    Ok(())
}

/// Delete one registration request (approve/reject), also clearing the agent
/// credential it issued.
/// A Pending request has no `devices` row, so there is no device row / route
/// to roll back.
pub async fn delete_registration_db(pool: &SqlitePool, id: &DeviceId) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM device_registrations WHERE id = ?")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM agent_tokens WHERE device_id = ?")
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Approve: turn the registration request (keeping its id) into a `devices`
/// row and release the request record (same transaction).
/// `virtual_ipv4` is the real address just allocated from IPAM at approval
/// time (no longer a placeholder value).
///
/// **The agent credential is not rotated**: the credential binds to the device
/// id (allocated at registration, carried over at approval), and the device
/// identity is unchanged; rotating it would put the raw credential only in the
/// approval response, unreachable by the device side forever (401 after
/// approval). The credential issued during the Pending period stays valid;
/// revocation goes through the existing `revoke_device` path.
pub async fn promote_registration(
    pool: &SqlitePool,
    r: &DeviceRegistration,
    device: &Device,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    // Same column set as insert_device plus approved_at: heartbeat evidence from
    // the Pending period is carried over directly (presence stays continuous
    // after approval; §7.5 evidence is not zeroed out by promotion).
    sqlx::query(
        "INSERT INTO devices
            (id, network_id, name, virtual_ipv4, public_key, platform, status, segment_id,
            last_seen_at, last_handshake_at, last_report_at, dataplane_evidence,
            created_at, approved_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
    .bind(evidence_json(device))
    .bind(&device.created_at)
    .bind(&device.approved_at)
    .bind(&device.revoked_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM device_registrations WHERE id = ?")
        .bind(r.id.to_string())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// A Pending device has no `devices` row, so heartbeat evidence lands only in
/// the registration table (§7.5/§12.4).
pub async fn update_registration_report(
    pool: &SqlitePool,
    id: &DeviceId,
    last_report_at: &str,
    dataplane_evidence: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE device_registrations SET last_report_at = ?, dataplane_evidence = ? WHERE id = ?",
    )
    .bind(last_report_at)
    .bind(dataplane_evidence)
    .bind(id.to_string())
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist one Alias mapping (§12.6). Alias ids share the `route_seq`
/// sequence with routes (`al-N` / `rt-N` are monotonic from the same source,
/// and deleted ids are never reused); the sequence is saved in the same
/// transaction.
pub async fn insert_alias(
    pool: &SqlitePool,
    a: &AliasMapping,
    route_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO alias_mappings
           (id, network_id, lan_route_id, alias_cidr, target_cidr, translation_mode,
            status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(a.id.to_string())
    .bind(a.network_id.to_string())
    .bind(a.lan_route_id.to_string())
    .bind(a.alias_cidr.to_string())
    .bind(a.target_cidr.to_string())
    .bind(a.translation_mode.as_str())
    .bind(desired_status_to_str(a.status))
    .bind(crate::service::now())
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    tx.commit().await?;
    Ok(())
}

/// Transactionally persist the two Host Forward mirror rows (LAN Route +
/// Alias).
///
/// The in-memory path already guarantees "creation is a whole unit"; this
/// brings the same atomic boundary to SQLite: if writing either row fails, the
/// route sequence and the other row roll back together.
pub async fn insert_host_forward(
    pool: &SqlitePool,
    route: &LanRoute,
    alias: &AliasMapping,
    route_seq: u64,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
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
    .execute(&mut *tx)
    .await?;
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
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "route_seq", route_seq).await?;
    tx.commit().await?;
    Ok(())
}

/// Delete one LAN route together with its bound Alias (§12.6 ownership
/// cleanup: an alias-route pair is a one-to-one unit; under the FK constraint
/// the child row must be deleted first). The route id sequence never steps
/// back, and deleted ids are not reused.
pub async fn delete_route(pool: &SqlitePool, route_id: &str) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM alias_mappings WHERE lan_route_id = ?")
        .bind(route_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM lan_routes WHERE id = ?")
        .bind(route_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// When a device is revoked, remove every route it published along with the
/// bound Aliases (§11.5 + §12.6 cascading cleanup).
pub async fn delete_routes_of_device(
    pool: &SqlitePool,
    gateway_device_id: &str,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "DELETE FROM alias_mappings WHERE lan_route_id IN
           (SELECT id FROM lan_routes WHERE gateway_device_id = ?)",
    )
    .bind(gateway_device_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM lan_routes WHERE gateway_device_id = ?")
        .bind(gateway_device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Write back the settled desired-item statuses (apply / rollback verdict,
/// §10.1).
///
/// The same discipline as [`update_revision_status`]: once the revision
/// verdict is persisted, the routes'/mappings' `status` must be persisted
/// too -- the ledger rebuilt by [`load`] after a restart must not call
/// "effective" `pending`, nor keep showing "rolled back" as `applied`.
pub async fn update_desired_status(
    pool: &SqlitePool,
    settle: &crate::service::DesiredStateSettle,
) -> Result<(), sqlx::Error> {
    if settle.routes.is_empty() && settle.aliases.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for (id, status) in &settle.routes {
        sqlx::query("UPDATE lan_routes SET status = ? WHERE id = ?")
            .bind(desired_status_to_str(*status))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    for (id, status) in &settle.aliases {
        sqlx::query("UPDATE alias_mappings SET status = ? WHERE id = ?")
            .bind(desired_status_to_str(*status))
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Persist a new revision (produced by `record`, always `pending`).
pub async fn insert_revision(pool: &SqlitePool, r: &ConfigRevision) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO config_revisions
           (network_id, revision, desired_config_hash, apply_status, created_at,
            applied_at, error_summary)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(r.network_id.to_string())
    .bind(r.revision as i64)
    .bind(&r.desired_config_hash)
    .bind(r.apply_status.as_str())
    .bind(&r.created_at)
    .bind(&r.applied_at)
    .bind(&r.error_summary)
    .execute(pool)
    .await?;
    Ok(())
}

/// Write back a revision's application status (apply/rollback/interrupted
/// settling).
pub async fn update_revision_status(
    pool: &SqlitePool,
    r: &ConfigRevision,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE config_revisions
         SET apply_status = ?, applied_at = ?, error_summary = ?
         WHERE network_id = ? AND revision = ?",
    )
    .bind(r.apply_status.as_str())
    .bind(&r.applied_at)
    .bind(&r.error_summary)
    .bind(r.network_id.to_string())
    .bind(r.revision as i64)
    .execute(pool)
    .await?;
    Ok(())
}

/// Persist/write back an invite (creation, redemption incrementing
/// `used_count`, revocation).
pub async fn save_invite(pool: &SqlitePool, i: &Invite) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO invitations
           (id, network_id, token_hash, expires_at, max_uses, used_count, created_at, revoked_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET
           used_count = excluded.used_count,
           revoked_at = excluded.revoked_at",
    )
    .bind(i.id.to_string())
    .bind(i.network_id.to_string())
    .bind(&i.token_hash)
    .bind(&i.expires_at)
    .bind(i.max_uses)
    .bind(i.used_count)
    .bind(&i.created_at)
    .bind(&i.revoked_at)
    .execute(pool)
    .await?;
    Ok(())
}
