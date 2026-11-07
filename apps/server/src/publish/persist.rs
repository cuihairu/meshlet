//! 发布对象的 SQL 落库与启动加载；对象、序列、修订和审计同事务提交。

use super::models::{PublishDnsRecord, PublishForward, PublishHttpRoute, PublishProbe};
use crate::persist::{insert_audit_tx, insert_revision_tx, save_seq_tx};
use crate::service::ServiceError;
use meshlet_domain::ConfigRevision;
use meshlet_publish::health::HealthState;
use sqlx::SqlitePool;

fn policy_cidrs_json(policy: &meshlet_publish::AuthorizationPolicy) -> String {
    serde_json::json!(policy
        .allowed_source_cidrs
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>())
    .to_string()
}

fn policy_tokens_json(policy: &meshlet_publish::AuthorizationPolicy) -> String {
    serde_json::json!(policy.allowed_bearer_tokens).to_string()
}

fn policy_from_json(
    cidrs_json: &str,
    tokens_json: &str,
) -> Result<meshlet_publish::AuthorizationPolicy, ServiceError> {
    let cidrs: Vec<String> = serde_json::from_str(cidrs_json)
        .map_err(|e| ServiceError::Internal(format!("publish cidrs json: {e}")))?;
    let tokens: Vec<String> = serde_json::from_str(tokens_json)
        .map_err(|e| ServiceError::Internal(format!("publish tokens json: {e}")))?;
    let mut parsed = Vec::new();
    for text in &cidrs {
        let cidr: meshlet_domain::Ipv4Cidr = text
            .parse()
            .map_err(|e| ServiceError::Internal(format!("publish cidr {text}: {e}")))?;
        parsed.push(cidr);
    }
    Ok(meshlet_publish::AuthorizationPolicy {
        allowed_source_cidrs: parsed,
        allowed_bearer_tokens: tokens,
    })
}

fn probe_target_columns(
    target: &meshlet_publish::health::ProbeTarget,
) -> (String, String, Option<String>, Option<u16>, f64) {
    match target {
        meshlet_publish::health::ProbeTarget::Tcp { address, timeout } => (
            "tcp".into(),
            address.to_string(),
            None,
            None,
            timeout.as_secs_f64(),
        ),
        meshlet_publish::health::ProbeTarget::Http {
            address,
            path,
            expected_status,
            timeout,
        } => (
            "http".into(),
            address.to_string(),
            Some(path.clone()),
            Some(*expected_status),
            timeout.as_secs_f64(),
        ),
    }
}

fn probe_target_from_columns(
    kind: &str,
    address: &str,
    path: Option<&str>,
    expected_status: Option<u16>,
    timeout_secs: f64,
) -> Result<meshlet_publish::health::ProbeTarget, ServiceError> {
    let address: std::net::SocketAddr = address
        .parse()
        .map_err(|e| ServiceError::Internal(format!("probe address {address}: {e}")))?;
    let timeout = std::time::Duration::from_secs_f64(timeout_secs);
    Ok(match kind {
        "tcp" => meshlet_publish::health::ProbeTarget::Tcp { address, timeout },
        "http" => meshlet_publish::health::ProbeTarget::Http {
            address,
            path: path.unwrap_or_default().to_string(),
            expected_status: expected_status.unwrap_or(200),
            timeout,
        },
        other => {
            return Err(ServiceError::Internal(format!(
                "unknown probe target_kind {other:?}"
            )));
        }
    })
}

pub(crate) async fn commit_forward(
    pool: &SqlitePool,
    forward: &PublishForward,
    publish_seq: u64,
    revision: &ConfigRevision,
    audit: &crate::persist::AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO publish_forwards
           (id, network_id, device_id, protocol, listener_address, backend_address,
            allowed_source_cidrs, allowed_bearer_tokens, enabled, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&forward.id)
    .bind(&forward.network_id)
    .bind(&forward.device_id)
    .bind(match forward.protocol {
        meshlet_publish::ForwardProtocol::Tcp => "tcp",
        meshlet_publish::ForwardProtocol::Udp => "udp",
    })
    .bind(forward.listener_address.to_string())
    .bind(forward.backend_address.to_string())
    .bind(policy_cidrs_json(&forward.policy))
    .bind(policy_tokens_json(&forward.policy))
    .bind(forward.enabled)
    .bind(&forward.created_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn commit_http_route(
    pool: &SqlitePool,
    route: &PublishHttpRoute,
    publish_seq: u64,
    revision: &ConfigRevision,
    audit: &crate::persist::AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO publish_http_routes
           (id, network_id, device_id, hostname, path_prefix, backend_address,
            listener_address, allowed_source_cidrs, allowed_bearer_tokens,
            tls_passthrough, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&route.id)
    .bind(&route.network_id)
    .bind(&route.device_id)
    .bind(&route.hostname)
    .bind(&route.path_prefix)
    .bind(route.backend_address.to_string())
    .bind(route.listener_address.to_string())
    .bind(policy_cidrs_json(&route.policy))
    .bind(policy_tokens_json(&route.policy))
    .bind(route.tls_passthrough)
    .bind(&route.created_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn commit_probe(
    pool: &SqlitePool,
    probe: &PublishProbe,
    publish_seq: u64,
    revision: &ConfigRevision,
    audit: &crate::persist::AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let (kind, address, path, expected, timeout) = probe_target_columns(&probe.target);
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO publish_probes
           (id, network_id, device_id, target_kind, address, path, expected_status,
            timeout_secs, interval_secs, enabled, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&probe.id)
    .bind(&probe.network_id)
    .bind(&probe.device_id)
    .bind(&kind)
    .bind(&address)
    .bind(&path)
    .bind(expected.map(i64::from))
    .bind(timeout)
    .bind(probe.interval_secs as i64)
    .bind(probe.enabled)
    .bind(&probe.created_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn commit_dns_record(
    pool: &SqlitePool,
    record: &PublishDnsRecord,
    publish_seq: u64,
    revision: &ConfigRevision,
    audit: &crate::persist::AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO publish_dns_records
           (id, network_id, device_id, name, address, ttl, priority, bind_address,
            internal_suffix, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&record.id)
    .bind(&record.network_id)
    .bind(&record.device_id)
    .bind(&record.name)
    .bind(record.address.to_string())
    .bind(record.ttl as i64)
    .bind(record.priority as i64)
    .bind(record.bind_address.to_string())
    .bind(&record.internal_suffix)
    .bind(&record.created_at)
    .execute(&mut *tx)
    .await?;
    save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

/// 通用删除：单表 + 序列 + 修订 + 审计（探针删除另有连带清证据的
/// [`commit_probe_delete`]）。
pub(crate) async fn commit_delete(
    pool: &SqlitePool,
    table: &str,
    id: &str,
    publish_seq: u64,
    revision: &ConfigRevision,
    audit: &crate::persist::AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    // 表名来自本模块调用点（白名单断言，杜绝拼接注入面）。
    assert!(
        matches!(
            table,
            "publish_forwards" | "publish_http_routes" | "publish_dns_records"
        ),
        "unexpected publish table {table}"
    );
    let mut tx = pool.begin().await?;
    sqlx::query(&format!("DELETE FROM {table} WHERE id = ?"))
        .bind(id)
        .execute(&mut *tx)
        .await?;
    save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn commit_probe_delete(
    pool: &SqlitePool,
    probe_id: &str,
    publish_seq: u64,
    revision: &ConfigRevision,
    audit: &crate::persist::AuditDraft<'_>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM publish_probe_reports WHERE probe_id = ?")
        .bind(probe_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM publish_probes WHERE id = ?")
        .bind(probe_id)
        .execute(&mut *tx)
        .await?;
    save_seq_tx(&mut tx, "publish_seq", publish_seq).await?;
    insert_revision_tx(&mut tx, revision).await?;
    insert_audit_tx(&mut tx, audit).await?;
    tx.commit().await?;
    Ok(())
}

/// 探针健康回报镜像：每探针一条最新证据（按主键 upsert），device_id
/// 守卫保证 agent 只能写归自己设备的报告。
pub(crate) async fn upsert_probe_reports(
    pool: &SqlitePool,
    device_id: &str,
    reports: &[meshlet_publish::ProbeReport],
) -> Result<(), sqlx::Error> {
    if reports.is_empty() {
        return Ok(());
    }
    let mut tx = pool.begin().await?;
    for report in reports {
        let state = match report.state {
            HealthState::Healthy => "healthy",
            HealthState::Unreachable => "unreachable",
        };
        sqlx::query(
            "INSERT INTO publish_probe_reports
               (probe_id, network_id, device_id, state, checked_at, detail, updated_at)
             SELECT p.id, p.network_id, p.device_id, ?, ?, ?, ?
             FROM publish_probes p
             WHERE p.id = ? AND p.device_id = ?
             ON CONFLICT (probe_id) DO UPDATE SET
               state = excluded.state,
               checked_at = excluded.checked_at,
               detail = excluded.detail,
               updated_at = excluded.updated_at",
        )
        .bind(state)
        .bind(&report.checked_at)
        .bind(&report.detail)
        .bind(crate::service::now())
        .bind(&report.probe_id)
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// 启动重建：灌回全部发布对象 + `mesh_meta.publish_seq`。行级错误以
/// `corrupt` 语义上抛（与 persist::load 其余部分一致，由调用方包装）。
pub(crate) async fn load(
    pool: &SqlitePool,
    state: &mut crate::service::MeshState,
) -> Result<(), sqlx::Error> {
    let seq: Option<String> =
        sqlx::query_scalar("SELECT value FROM mesh_meta WHERE key = 'publish_seq'")
            .fetch_optional(pool)
            .await?;
    if let Some(seq) = seq {
        let seq: u64 = seq
            .parse()
            .map_err(|e| sqlx::Error::Configuration(Box::new(e)))?;
        state.set_publish_seq(seq);
    }

    let forward_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            bool,
            String,
        ),
    >(
        "SELECT id, network_id, device_id, protocol, listener_address, backend_address,
                allowed_source_cidrs, allowed_bearer_tokens, enabled, created_at
         FROM publish_forwards ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    for (
        id,
        network_id,
        device_id,
        protocol,
        listener,
        backend,
        cidrs,
        tokens,
        enabled,
        created_at,
    ) in forward_rows
    {
        let policy = policy_from_json(&cidrs, &tokens)
            .map_err(|e| sqlx::Error::Configuration(format!("publish forward {id}: {e}").into()))?;
        let listener: std::net::SocketAddr = listener
            .parse()
            .map_err(|e| sqlx::Error::Configuration(format!("forward {id}: {e}").into()))?;
        let backend: std::net::SocketAddr = backend
            .parse()
            .map_err(|e| sqlx::Error::Configuration(format!("forward {id}: {e}").into()))?;
        let protocol = match protocol.as_str() {
            "tcp" => meshlet_publish::ForwardProtocol::Tcp,
            "udp" => meshlet_publish::ForwardProtocol::Udp,
            other => {
                return Err(sqlx::Error::Configuration(
                    format!("forward {id}: unknown protocol {other:?}").into(),
                ));
            }
        };
        state.restore_publish_forward(PublishForward {
            id,
            network_id,
            device_id,
            protocol,
            listener_address: listener,
            backend_address: backend,
            policy,
            enabled,
            created_at,
        });
    }

    let route_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            bool,
            String,
        ),
    >(
        "SELECT id, network_id, device_id, hostname, path_prefix, backend_address,
                listener_address, allowed_source_cidrs, allowed_bearer_tokens,
                tls_passthrough, created_at
         FROM publish_http_routes ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    for (
        id,
        network_id,
        device_id,
        hostname,
        path_prefix,
        backend,
        listener,
        cidrs,
        tokens,
        tls,
        created_at,
    ) in route_rows
    {
        let policy = policy_from_json(&cidrs, &tokens).map_err(|e| {
            sqlx::Error::Configuration(format!("publish http route {id}: {e}").into())
        })?;
        let backend: std::net::SocketAddr = backend
            .parse()
            .map_err(|e| sqlx::Error::Configuration(format!("route {id}: {e}").into()))?;
        let listener: std::net::SocketAddr = listener
            .parse()
            .map_err(|e| sqlx::Error::Configuration(format!("route {id}: {e}").into()))?;
        state.restore_publish_http_route(PublishHttpRoute {
            id,
            network_id,
            device_id,
            hostname,
            path_prefix,
            backend_address: backend,
            listener_address: listener,
            policy,
            tls_passthrough: tls,
            created_at,
        });
    }

    let probe_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            Option<u16>,
            f64,
            i64,
            bool,
            String,
        ),
    >(
        "SELECT id, network_id, device_id, target_kind, address, path, expected_status,
                timeout_secs, interval_secs, enabled, created_at
         FROM publish_probes ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    for (
        id,
        network_id,
        device_id,
        kind,
        address,
        path,
        expected,
        timeout,
        interval,
        enabled,
        created_at,
    ) in probe_rows
    {
        let target = probe_target_from_columns(&kind, &address, path.as_deref(), expected, timeout)
            .map_err(|e| sqlx::Error::Configuration(format!("publish probe {id}: {e}").into()))?;
        state.restore_publish_probe(PublishProbe {
            id,
            network_id,
            device_id,
            target,
            interval_secs: interval as u64,
            enabled,
            created_at,
            last_state: None,
            last_checked_at: None,
            last_detail: None,
        });
    }

    // 健康证据镜像回填（探针已删的孤儿证据不进内存）。
    let probe_ids: std::collections::HashSet<String> = state
        .publishes
        .values()
        .flat_map(|c| c.probes.iter().map(|p| p.id.clone()))
        .collect();
    let report_rows = sqlx::query_as::<_, (String, String, String, Option<String>, String)>(
        "SELECT probe_id, state, checked_at, detail, network_id
         FROM publish_probe_reports ORDER BY probe_id",
    )
    .fetch_all(pool)
    .await?;
    for (probe_id, state_text, checked_at, detail, _network_id) in report_rows {
        if !probe_ids.contains(&probe_id) {
            continue;
        }
        let health = match state_text.as_str() {
            "healthy" => HealthState::Healthy,
            "unreachable" => HealthState::Unreachable,
            other => {
                return Err(sqlx::Error::Configuration(
                    format!("probe report {probe_id}: unknown state {other:?}").into(),
                ));
            }
        };
        if let Some(catalog) = state
            .publishes
            .get_mut(&_network_id)
            .and_then(|c| c.probes.iter_mut().find(|p| p.id == probe_id))
        {
            catalog.last_state = Some(health);
            catalog.last_checked_at = Some(checked_at);
            catalog.last_detail = detail;
        }
    }

    let dns_rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            i64,
            i64,
            String,
            String,
            String,
        ),
    >(
        "SELECT id, network_id, device_id, name, address, ttl, priority, bind_address,
                internal_suffix, created_at
         FROM publish_dns_records ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    for (id, network_id, device_id, name, address, ttl, priority, bind, suffix, created_at) in
        dns_rows
    {
        let address: std::net::Ipv4Addr = address
            .parse()
            .map_err(|e| sqlx::Error::Configuration(format!("dns {id}: {e}").into()))?;
        let bind: std::net::SocketAddr = bind
            .parse()
            .map_err(|e| sqlx::Error::Configuration(format!("dns {id}: {e}").into()))?;
        state.restore_publish_dns_record(PublishDnsRecord {
            id,
            network_id,
            device_id,
            name,
            address,
            ttl: ttl as u32,
            priority: priority as u16,
            bind_address: bind,
            internal_suffix: suffix,
            created_at,
        });
    }
    Ok(())
}
