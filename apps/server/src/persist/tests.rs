#![cfg(test)]

#[cfg(unix)]
use super::backup::resolve_restored_database_owner;
use super::entities::{commit_device_labels, insert_device, insert_network};
use super::shared::{
    apply_status_parse, desired_status_parse, desired_status_to_str, device_status_parse,
    device_status_to_str, network_status_parse, network_status_to_str, platform_parse,
    platform_to_str,
};
use super::tasks::load;
use crate::persist::AuditDraft;
use meshlet_domain::{Device, DeviceId, DeviceStatus, Network, NetworkId, Platform, SegmentId};
use std::collections::BTreeMap;
#[cfg(unix)]
use std::path::Path;

#[cfg(test)]
// 文件本身经 `mod tests;` 引入，内层再叫 tests 触发 module_inception；
// 这是测试组织惯例而非缺陷，局部放行。
#[allow(clippy::module_inception)]
mod tests {
    use super::*;

    #[test]
    fn enums_round_trip_through_persisted_strings() {
        // 持久化字符串与 API 展示一致，往返无损（重启重建依赖）。
        for s in ["pending", "active", "revoked"] {
            assert_eq!(device_status_to_str(device_status_parse(s).unwrap()), s);
        }
        for s in ["active", "deleting"] {
            assert_eq!(network_status_to_str(network_status_parse(s).unwrap()), s);
        }
        for s in ["pending", "applied", "failed"] {
            assert_eq!(desired_status_to_str(desired_status_parse(s).unwrap()), s);
        }
        for s in [
            "pending",
            "applying",
            "applied",
            "failed",
            "rollback_pending",
            "rolled_back",
        ] {
            assert_eq!(apply_status_parse(s).unwrap().as_str(), s);
        }
        for s in ["linux", "windows"] {
            assert_eq!(platform_to_str(platform_parse(s).unwrap()), s);
        }
        assert!(device_status_parse("bogus").is_err());
    }

    #[tokio::test]
    async fn device_segment_assignment_survives_database_reload() {
        let pool = crate::store::connect("sqlite::memory:").await.unwrap();
        let network_id = NetworkId("net-1".into());
        let network = Network::new(
            network_id.clone(),
            "home",
            "10.240.0.0/16".parse().unwrap(),
            "2026-10-17T00:00:00Z".into(),
        );
        insert_network(&pool, &network).await.unwrap();
        let default_id = meshlet_domain::default_segment_id(&network_id);
        let persisted_default: String =
            sqlx::query_scalar("SELECT id FROM segments WHERE network_id = ? AND name = 'default'")
                .bind(network_id.to_string())
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(persisted_default, default_id.to_string());

        let custom_segment = SegmentId("seg-net-1-lab".into());
        sqlx::query(
            "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
             VALUES (?, ?, 'lab', '10.240.1.0/24', 'active', '2026-10-17T00:00:00Z')",
        )
        .bind(custom_segment.to_string())
        .bind(network_id.to_string())
        .execute(&pool)
        .await
        .unwrap();
        let device = Device {
            id: DeviceId("dev-1".into()),
            network_id: network_id.clone(),
            name: "lab-device".into(),
            virtual_ipv4: "10.240.1.2".parse().unwrap(),
            public_key: "public-key".into(),
            platform: Platform::Linux,
            status: DeviceStatus::Active,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: "2026-10-17T00:00:00Z".into(),
            approved_at: None,
            segment_id: custom_segment.clone(),
            revoked_at: None,
            labels: BTreeMap::new(),
        };
        insert_device(&pool, &device).await.unwrap();

        let boot = load(&pool, meshlet_domain::PresenceThresholds::default())
            .await
            .unwrap();
        let restored = boot
            .mesh
            .registry
            .find_by_id(&DeviceId("dev-1".into()))
            .unwrap();
        assert_eq!(restored.segment_id, custom_segment);
        assert_eq!(boot.summary.segments, 2);
        pool.close().await;
    }

    #[tokio::test]
    async fn device_labels_survive_database_reload() {
        // MT-005：标签经 commit_device_labels 落库，重启 load 后逐字恢复。
        let pool = crate::store::connect("sqlite::memory:").await.unwrap();
        let network_id = NetworkId("net-1".into());
        let network = Network::new(
            network_id.clone(),
            "home",
            "10.240.0.0/16".parse().unwrap(),
            "2026-10-17T00:00:00Z".into(),
        );
        insert_network(&pool, &network).await.unwrap();
        let mut device = Device {
            id: DeviceId("dev-1".into()),
            network_id: network_id.clone(),
            name: "worker".into(),
            virtual_ipv4: "10.240.0.2".parse().unwrap(),
            public_key: "public-key".into(),
            platform: Platform::Linux,
            status: DeviceStatus::Active,
            last_seen_at: None,
            last_handshake_at: None,
            last_report_at: None,
            dataplane_evidence: None,
            created_at: "2026-10-17T00:00:00Z".into(),
            approved_at: None,
            revoked_at: None,
            segment_id: meshlet_domain::default_segment_id(&network_id),
            labels: BTreeMap::new(),
        };
        insert_device(&pool, &device).await.unwrap();
        device.labels.insert("role".into(), "worker".into());
        device.labels.insert("cap".into(), "gpu".into());
        let audit = AuditDraft {
            actor_id: Some("user-1"),
            action: "device.labels_set",
            target_type: "device",
            target_id: "dev-1",
            detail: None,
        };
        commit_device_labels(&pool, &device, &audit).await.unwrap();

        let boot = load(&pool, meshlet_domain::PresenceThresholds::default())
            .await
            .unwrap();
        let restored = boot
            .mesh
            .registry
            .find_by_id(&DeviceId("dev-1".into()))
            .unwrap();
        assert_eq!(restored.labels["role"], "worker");
        assert_eq!(restored.labels["cap"], "gpu");
        pool.close().await;
    }

    #[tokio::test]
    async fn segment_grants_survive_database_reload() {
        let pool = crate::store::connect("sqlite::memory:").await.unwrap();
        let network_id = NetworkId("net-1".into());
        let network = Network::new(
            network_id.clone(),
            "home",
            "10.240.0.0/16".parse().unwrap(),
            "2026-10-17T00:00:00Z".into(),
        );
        insert_network(&pool, &network).await.unwrap();
        sqlx::query(
            "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
             VALUES ('seg-net-1-a', ?, 'a', '10.240.1.0/24', 'active', ?),
                    ('seg-net-1-b', ?, 'b', '10.240.2.0/24', 'active', ?)",
        )
        .bind(network_id.to_string())
        .bind(&network.created_at)
        .bind(network_id.to_string())
        .bind(&network.created_at)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO segment_grants
             (id, network_id, source_segment_id, destination_segment_id, status,
              created_at, revoked_at)
             VALUES ('sg-net-1-1', ?, 'seg-net-1-a', 'seg-net-1-b', 'applied', ?, NULL)",
        )
        .bind(network_id.to_string())
        .bind(&network.created_at)
        .execute(&pool)
        .await
        .unwrap();

        let boot = load(&pool, meshlet_domain::PresenceThresholds::default())
            .await
            .unwrap();
        assert_eq!(
            boot.mesh.segment_grants("net-1"),
            &[meshlet_domain::SegmentGrant {
                id: meshlet_domain::SegmentGrantId("sg-net-1-1".into()),
                network_id: network_id.clone(),
                source_segment_id: SegmentId("seg-net-1-a".into()),
                destination_segment_id: SegmentId("seg-net-1-b".into()),
                status: meshlet_domain::SegmentGrantStatus::Applied,
                created_at: network.created_at.clone(),
                revoked_at: None,
            }]
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn load_rejects_overlapping_segment_containment() {
        let pool = crate::store::connect("sqlite::memory:").await.unwrap();
        let network_id = NetworkId("net-1".into());
        let network = Network::new(
            network_id.clone(),
            "home",
            "10.240.0.0/16".parse().unwrap(),
            "2026-10-17T00:00:00Z".into(),
        );
        insert_network(&pool, &network).await.unwrap();
        sqlx::query(
            "INSERT INTO segments (id, network_id, name, cidr, status, created_at)
             VALUES ('seg-net-1-lab', ?, 'lab', '10.240.0.0/15', 'active', ?)",
        )
        .bind(network_id.to_string())
        .bind(&network.created_at)
        .execute(&pool)
        .await
        .unwrap();
        let error = match load(&pool, meshlet_domain::PresenceThresholds::default()).await {
            Ok(_) => panic!("overlapping segment containment must fail load"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("outside overlay"), "{error}");
        pool.close().await;
    }

    #[cfg(unix)]
    #[test]
    fn restored_database_owner_prefers_the_replaced_file_then_the_data_dir() {
        use std::os::unix::fs::MetadataExt as _;
        let dir =
            std::env::temp_dir().join(format!("meshlet-restore-owner-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let database = dir.join("meshlet.db");

        // The live file being replaced wins (in-place restore).
        assert_eq!(
            resolve_restored_database_owner(&database, Some((7, 9))),
            Some((7, 9))
        );

        // No live file: fall back to the data directory's owner. chown needs
        // privilege, so the directory is owned by the test user — exactly the
        // value the fallback must produce.
        let dir_owner = dir.metadata().unwrap();
        assert_eq!(
            resolve_restored_database_owner(&database, None),
            Some((dir_owner.uid(), dir_owner.gid()))
        );

        // An unresolvable parent yields None rather than inventing an owner.
        assert_eq!(
            resolve_restored_database_owner(Path::new("/nonexistent/meshlet/db"), None),
            None
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
