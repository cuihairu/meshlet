//! One guarded, serial cross-site lifecycle shared by all scenario modules.

#![cfg(target_os = "linux")]

use std::sync::{Mutex, MutexGuard};

use super::support::*;
use serde_json::json;

static TEST_LOCK: Mutex<()> = Mutex::new(());

pub(crate) struct Context {
    pub(crate) topo: Topology,
    pub(crate) dir: std::path::PathBuf,
    pub(crate) base: String,
    pub(crate) base_b: String,
    pub(crate) cookie: String,
    pub(crate) network_id: String,
    pub(crate) network_b_id: String,
    pub(crate) g1_id: String,
    pub(crate) g2_id: String,
    pub(crate) a_token: String,
    pub(crate) g1_token: String,
    pub(crate) g2_token: String,
    pub(crate) b_token: String,
    pub(crate) b_vip: String,
    pub(crate) route_ids: Vec<String>,
    pub(crate) alias_ids: Vec<String>,
    pub(crate) hub_endpoint: String,
    pub(crate) hub_b_endpoint: String,
    pub(crate) server: ServerHandle,
    pub(crate) server_b: ServerHandle,
}

pub(crate) fn lock() -> MutexGuard<'static, ()> {
    match TEST_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Context {
    pub(crate) fn setup() -> Option<Context> {
        let topo = match Topology::setup() {
            Some(topo) => topo,
            None => {
                eprintln!("SKIP: dataplane prerequisites unavailable");
                return None;
            }
        };
        assert!(topo.guard.bridge.is_some(), "bridge recorded for cleanup");
        let unique_id = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(format!("meshlet-dual-site-{unique_id}"));
        std::fs::create_dir_all(&dir).unwrap();
        let hub_key_path = dir.join("hub.key");
        std::fs::write(
            &hub_key_path,
            format!("{}\n", wg_genkey().expect("hub key")),
        )
        .unwrap();
        std::fs::write(dir.join("echo.py"), ECHO_PY).unwrap();
        std::fs::write(dir.join("send.py"), SEND_PY).unwrap();
        std::fs::write(dir.join("tcp-echo.py"), TCP_ECHO_PY).unwrap();
        std::fs::write(dir.join("tcp-send.py"), TCP_SEND_PY).unwrap();
        let local_route_before = kernel_routes(&topo.a.netns);
        assert!(
            local_route_before.contains("192.168.1.0/24"),
            "client local LAN must have its existing route before apply: {local_route_before}"
        );
        let (base, server) = start_stoppable_server(
            dir.join("db.sqlite3"),
            hub_key_path.clone(),
            topo.hub.netns.clone(),
        );
        wait_server_up(&base);
        let res = ureq::post(&format!("{base}/api/v1/auth/bootstrap"))
            .set("content-type", "application/json")
            .send_string(
                &json!({"email": "admin@e2e.local", "password": "e2e-password-123"}).to_string(),
            );
        let cookie = match res {
            Ok(resp) => resp
                .all("set-cookie")
                .iter()
                .find_map(|v| v.split(';').next().map(|s| s.to_string()))
                .expect("session cookie"),
            Err(ureq::Error::Status(409, _)) => login_cookie(&base),
            Err(e) => panic!("bootstrap: {e}"),
        };
        let net = admin(
            &base,
            &cookie,
            "POST",
            "/api/v1/networks",
            Some(json!({
                "name": "dual",
                "overlay_cidr": OVERLAY,
            })),
        );
        let network_id = net["id"].as_str().unwrap().to_string();
        let invite = admin(
            &base,
            &cookie,
            "POST",
            &format!("/api/v1/networks/{network_id}/invites"),
            Some(json!({"max_uses": 3})),
        );
        let invite_token = invite["token"].as_str().unwrap().to_string();
        let mut tokens = Vec::new();
        for (name, node) in [("gw1", &topo.g1), ("gw2", &topo.g2), ("laptop-a", &topo.a)] {
            let (code, device) = http_json(
                "POST",
                &format!("{base}/api/v1/enroll"),
                None,
                None,
                Some(json!({
                    "invite_token": invite_token,
                    "device_name": name,
                    "public_key": node.public_key,
                    "platform": "linux",
                })),
            );
            assert_eq!(code, 201, "enroll {name}: {device}");
            tokens.push((
                device["device_id"].as_str().unwrap().to_string(),
                device["agent_token"].as_str().unwrap().to_string(),
            ));
        }
        let (g1_id, g1_token) = tokens[0].clone();
        let (g2_id, g2_token) = tokens[1].clone();
        let (_a_id, a_token) = tokens[2].clone();
        let net_b = admin(
            &base,
            &cookie,
            "POST",
            "/api/v1/networks",
            Some(json!({"name": "dual-b", "overlay_cidr": OVERLAY_B})),
        );
        let network_b_id = net_b["id"].as_str().unwrap().to_string();
        let invite_b = admin(
            &base,
            &cookie,
            "POST",
            &format!("/api/v1/networks/{network_b_id}/invites"),
            Some(json!({"max_uses": 1})),
        );
        let invite_token_b = invite_b["token"].as_str().unwrap().to_string();
        let (code, device_b) = http_json(
            "POST",
            &format!("{base}/api/v1/enroll"),
            None,
            None,
            Some(json!({
                "invite_token": invite_token_b,
                "device_name": "laptop-b",
                "public_key": topo.b.public_key,
                "platform": "linux",
            })),
        );
        assert_eq!(code, 201, "enroll net-b laptop-b: {device_b}");
        let b_token = device_b["agent_token"].as_str().unwrap().to_string();
        let b_vip = device_b["virtual_ipv4"].as_str().unwrap().to_string();
        let hub_b_key_path = dir.join("hub-b.key");
        std::fs::write(&hub_b_key_path, format!("{}\n", topo.hub2.private_key)).unwrap();
        let (base_b, server_b) = start_stoppable_server(
            dir.join("db.sqlite3"),
            hub_b_key_path,
            topo.hub2.netns.clone(),
        );
        wait_server_up(&base_b);
        Some(Context {
            topo,
            dir,
            base,
            base_b,
            cookie,
            network_id,
            network_b_id,
            g1_id,
            g2_id,
            a_token,
            g1_token,
            g2_token,
            b_token,
            b_vip,
            route_ids: Vec::new(),
            alias_ids: Vec::new(),
            hub_endpoint: format!("{HUB_UNDERLAY_IP}:{HUB_LISTEN_PORT}"),
            hub_b_endpoint: format!("{HUB_B_UNDERLAY_IP}:{HUB_LISTEN_PORT}"),
            server,
            server_b,
        })
    }

    pub(crate) fn devices(&self) -> serde_json::Value {
        admin(
            &self.base,
            &self.cookie,
            "GET",
            &format!("/api/v1/networks/{}/devices", self.network_id),
            None,
        )
    }

    pub(crate) fn latest_revision(&self, base: &str, network_id: &str) -> u64 {
        let revisions = admin(
            base,
            &self.cookie,
            "GET",
            &format!("/api/v1/networks/{network_id}/config-revisions"),
            None,
        );
        revisions.as_array().unwrap().last().unwrap()["revision"]
            .as_u64()
            .unwrap()
    }

    pub(crate) fn apply_latest(&self, base: &str, network_id: &str) {
        let revision = self.latest_revision(base, network_id);
        let applied = admin(
            base,
            &self.cookie,
            "POST",
            &format!("/api/v1/networks/{network_id}/config-revisions/{revision}/apply"),
            Some(json!({})),
        );
        assert_eq!(
            applied["apply_status"], "applied",
            "apply network {network_id}: {applied}"
        );
    }
}
