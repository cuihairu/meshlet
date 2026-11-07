//! Shared single-instance dataplane test support: real namespaces and server boot.
#![cfg(target_os = "linux")]

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use std::process::{Command, Output};
use tower::ServiceExt;

pub(super) fn sudo(args: &[&str]) -> Output {
    Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .expect("sudo")
}
pub(super) fn require(args: &[&str]) {
    let out = sudo(args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
pub(super) fn ns(name: &str, args: &[&str]) -> Output {
    let mut command = vec!["ip", "netns", "exec", name];
    command.extend(args);
    sudo(&command)
}
pub(super) fn net(name: &str, args: &[&str]) {
    let out = ns(name, args);
    assert!(
        out.status.success(),
        "{name} {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
pub(super) struct Sandbox {
    pub(super) names: Vec<String>,
    pub(super) dir: std::path::PathBuf,
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = sudo(&["ip", "netns", "del", name]);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
pub(super) fn setup() -> Option<Sandbox> {
    let ready = sudo(&["true"]).status.success()
        && Command::new("wg")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
    if !ready {
        assert!(
            std::env::var_os("MESHLET_REQUIRE_DATAPLANE").is_none(),
            "kernel prerequisites required"
        );
        eprintln!("SKIP: single-instance test needs sudo and WireGuard");
        return None;
    }
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let suffix = std::process::id() * 10 + NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let sandbox = Sandbox {
        names: (0..7).map(|i| format!("mlsi{suffix}-{i}")).collect(),
        dir: std::env::temp_dir().join(format!("meshlet-single-{suffix}")),
    };
    std::fs::create_dir_all(&sandbox.dir).unwrap();
    for name in &sandbox.names {
        require(&["ip", "netns", "add", name]);
        net(name, &["ip", "link", "set", "lo", "up"]);
    }
    for i in 1..5 {
        let left = format!("ms{suffix}a{i}");
        let right = format!("ms{suffix}b{i}");
        require(&[
            "ip", "link", "add", &left, "type", "veth", "peer", "name", &right,
        ]);
        require(&["ip", "link", "set", &left, "netns", &sandbox.names[0]]);
        require(&["ip", "link", "set", &right, "netns", &sandbox.names[i]]);
        for (name, device, addr) in [
            (&sandbox.names[0], &left, format!("172.31.{i}.1/30")),
            (&sandbox.names[i], &right, format!("172.31.{i}.2/30")),
        ] {
            net(name, &["ip", "addr", "add", &addr, "dev", device]);
            net(name, &["ip", "link", "set", device, "up"]);
            net(
                name,
                &[
                    "ethtool", "-K", device, "gro", "off", "gso", "off", "tso", "off",
                ],
            );
        }
    }
    for (i, lan) in [60, 61].iter().enumerate() {
        let left = format!("ml{suffix}a{i}");
        let right = format!("ml{suffix}b{i}");
        require(&[
            "ip", "link", "add", &left, "type", "veth", "peer", "name", &right,
        ]);
        require(&["ip", "link", "set", &left, "netns", &sandbox.names[1]]);
        require(&["ip", "link", "set", &right, "netns", &sandbox.names[5 + i]]);
        for (name, device, address) in [
            (&sandbox.names[1], &left, format!("192.168.{lan}.1/24")),
            (&sandbox.names[5 + i], &right, format!("192.168.{lan}.5/24")),
        ] {
            net(name, &["ip", "addr", "add", &address, "dev", device]);
            net(name, &["ip", "link", "set", device, "up"]);
            net(
                name,
                &[
                    "ethtool", "-K", device, "gro", "off", "gso", "off", "tso", "off",
                ],
            );
        }
    }
    Some(sandbox)
}
pub(super) async fn request(
    app: &Router,
    method: &str,
    path: &str,
    body: Value,
    cookie: Option<&str>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        req = req
            .header("cookie", cookie)
            .header("x-requested-with", "XMLHttpRequest");
    }
    if let Some(token) = token {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let response = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
pub(super) async fn admin(app: &Router, cookie: &str, path: &str, body: Value) -> Value {
    let (status, value) = request(app, "POST", path, body, Some(cookie), None).await;
    assert!(status.is_success(), "{path}: {status} {value}");
    value
}
pub(super) async fn apply(app: &Router, cookie: &str, network: &str) -> Value {
    let (_, revisions) = request(
        app,
        "GET",
        &format!("/api/v1/networks/{network}/config-revisions"),
        Value::Null,
        Some(cookie),
        None,
    )
    .await;
    let revision = revisions.as_array().unwrap().last().unwrap()["revision"]
        .as_u64()
        .unwrap();
    admin(
        app,
        cookie,
        &format!("/api/v1/networks/{network}/config-revisions/{revision}/apply"),
        json!({}),
    )
    .await
}
pub(super) async fn apply_revision(
    app: &Router,
    cookie: &str,
    network: &str,
    revision: u64,
) -> Value {
    admin(
        app,
        cookie,
        &format!("/api/v1/networks/{network}/config-revisions/{revision}/apply"),
        json!({}),
    )
    .await
}
pub(super) fn ping(name: &str, target: &str) -> bool {
    ns(name, &["ping", "-c", "2", "-W", "1", target])
        .status
        .success()
}

pub(super) fn reconnects(name: &str, target: &str) -> bool {
    // 90s window: the device re-applies its plan (resets the WG session) and
    // the keepalive handshake is sub-second on an idle box, but the nightly
    // dataplane leg shares CPU with concurrent CI jobs — a 2026-11-05 schedule
    // run lost this race at 35s. Pace the probes too: a tight fork loop of
    // `ping` processes starves the very namespaces it is waiting on.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    while std::time::Instant::now() < deadline {
        if ping(name, target) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    false
}
