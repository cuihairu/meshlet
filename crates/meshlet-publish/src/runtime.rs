//! Device-side publish runtime (R-06): the local half of a `PublishPlan`.
//!
//! [`Publisher`] holds every listener the plan calls for: L4 forwarding,
//! HTTP(S) routing, split-horizon DNS sockets, and the probe scheduler; results
//! come back as [`ProbeReport`] for the agent to collect and report.
//! Reconciliation is **incrementally idempotent**: objects whose config is
//! unchanged keep their sockets (in-flight connections are not interrupted),
//! removed objects are stopped, and objects whose config changed are restarted.
//! The runtime only accepts typed objects and never executes any command handed
//! down by the control plane (§16.4).
//!
//! DNS binds the address given in the control-plane config; `0.0.0.0:53` needs
//! root, and the plan itself does not manage privileges (see the R-06
//! acceptance gap in the docs).

use crate::dns::{serve_udp, DnsCatalog};
use crate::forwarding::{
    bind_tcp, bind_udp, spawn_tcp_forwarder, spawn_udp_forwarder, ForwardProtocol,
};
use crate::health::{HealthState, ProbeOutcome};
use crate::http::{bind_http, run_http_router, RouteMode};
use crate::plan::{DnsPlan, ProbeReport, ProbeSchedule, PublishPlan};
use crate::{HttpRouteSet, PortForwardConfig, PublishError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

/// Probe report channel capacity: the backlog limit for one tick (anything
/// beyond it is dropped and rescheduled next cycle).
pub const REPORT_CHANNEL_CAPACITY: usize = 256;

/// The result of one reconciliation (for logs and test assertions). `failed`
/// records objects that could not start: the next reconciliation round retries
/// them instead of silently pretending they are live.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PublishEvents {
    pub started: usize,
    pub stopped: usize,
    pub failed: Vec<String>,
}

impl PublishEvents {
    pub fn is_empty(&self) -> bool {
        self.started == 0 && self.stopped == 0 && self.failed.is_empty()
    }
}

/// Task handle for a forwarding listener (TCP and UDP return different types,
/// unified into one enum so stopping is easy).
enum ForwardHandle {
    Tcp(JoinHandle<()>),
    Udp(JoinHandle<Result<(), PublishError>>),
}

impl ForwardHandle {
    /// Stop the listener and **wait for the task to actually exit**: `abort`
    /// only requests cancellation, the await guarantees the socket is dropped by
    /// the time `reconcile` returns and the port is immediately reusable.
    async fn stop(self) {
        match self {
            ForwardHandle::Tcp(task) => {
                task.abort();
                let _ = task.await;
            }
            ForwardHandle::Udp(task) => {
                task.abort();
                let _ = task.await;
            }
        }
    }
}

struct RunningForward {
    config: PortForwardConfig,
    handle: ForwardHandle,
}

struct RunningHttp {
    listener: SocketAddr,
    routes: HttpRouteSet,
    tls_passthrough: bool,
    task: JoinHandle<()>,
}

struct RunningDns {
    address: SocketAddr,
    suffix: String,
    task: JoinHandle<Result<(), PublishError>>,
}

/// One device's publish runtime. Must be driven inside a tokio runtime (the
/// agent's publish thread).
pub struct Publisher {
    forwards: HashMap<String, RunningForward>,
    http_router: Option<RunningHttp>,
    dns: Option<RunningDns>,
    probe_task: Option<JoinHandle<()>>,
    probe_schedules: Vec<ProbeSchedule>,
    reports_rx: mpsc::Receiver<ProbeReport>,
}

impl Default for Publisher {
    fn default() -> Self {
        Self::new()
    }
}

impl Publisher {
    pub fn new() -> Self {
        let (_sender, receiver) = mpsc::channel(REPORT_CHANNEL_CAPACITY);
        Self {
            forwards: HashMap::new(),
            http_router: None,
            dns: None,
            probe_task: None,
            probe_schedules: Vec::new(),
            reports_rx: receiver,
        }
    }

    /// Whether there is no listener at all (used for the startup catch-up: after
    /// an agent restart the ledger may say "applied" while this machine holds no
    /// listener, so the plan must be replayed as the empty state).
    pub fn is_idle(&self) -> bool {
        self.forwards.is_empty()
            && self.http_router.is_none()
            && self.dns.is_none()
            && self.probe_task.is_none()
    }

    /// Align the local publish state to `plan`: `None` = stop everything.
    ///
    /// Returns `Err` only when the plan contradicts itself
    /// ([`PublishPlan::validate`]) -- in that case nothing should take partial
    /// effect; a single object failing to bind is recorded in
    /// [`PublishEvents::failed`] and retried next round.
    pub async fn reconcile(
        &mut self,
        plan: Option<&PublishPlan>,
    ) -> Result<PublishEvents, PublishError> {
        let mut events = PublishEvents::default();
        let Some(plan) = plan else {
            self.stop_all(&mut events).await;
            return Ok(events);
        };
        plan.validate()?;
        self.reconcile_forwards(plan, &mut events).await;
        self.reconcile_http(plan, &mut events).await;
        self.reconcile_dns(plan, &mut events).await;
        self.reconcile_probes(plan, &mut events).await;
        Ok(events)
    }

    /// Drain the backlog of probe results (non-blocking): the agent calls this
    /// once per tick and reports them.
    pub fn drain_reports(&mut self) -> Vec<ProbeReport> {
        let mut reports = Vec::new();
        while let Ok(report) = self.reports_rx.try_recv() {
            reports.push(report);
        }
        reports
    }

    async fn reconcile_forwards(&mut self, plan: &PublishPlan, events: &mut PublishEvents) {
        let wanted: HashMap<String, PortForwardConfig> = plan
            .forwards
            .iter()
            .filter(|forward| forward.enabled)
            .map(|forward| (forward.id.clone(), forward.clone()))
            .collect();
        let stale: Vec<String> = self
            .forwards
            .keys()
            .filter(|id| !wanted.contains_key(id.as_str()))
            .cloned()
            .collect();
        for id in stale {
            self.stop_forward(&id).await;
            events.stopped += 1;
        }
        for config in wanted.values() {
            let unchanged = matches!(
                self.forwards.get(&config.id),
                Some(running) if running.config == *config
            );
            if unchanged {
                continue;
            }
            if let Some(running) = self.forwards.remove(&config.id) {
                running.handle.stop().await;
                events.stopped += 1;
            }
            match self.start_forward(config).await {
                Ok(()) => events.started += 1,
                Err(e) => events.failed.push(format!("{}: {e}", config.id)),
            }
        }
    }

    async fn start_forward(&mut self, config: &PortForwardConfig) -> Result<(), PublishError> {
        match config.protocol {
            ForwardProtocol::Tcp => {
                let (listener, _bound) = bind_tcp(config.listener_address).await?;
                let handle =
                    spawn_tcp_forwarder(listener, config.backend_address, config.policy.clone());
                self.forwards.insert(
                    config.id.clone(),
                    RunningForward {
                        config: config.clone(),
                        handle: ForwardHandle::Tcp(handle),
                    },
                );
            }
            ForwardProtocol::Udp => {
                let (socket, _bound) = bind_udp(config.listener_address).await?;
                let handle =
                    spawn_udp_forwarder(socket, config.backend_address, config.policy.clone());
                self.forwards.insert(
                    config.id.clone(),
                    RunningForward {
                        config: config.clone(),
                        handle: ForwardHandle::Udp(handle),
                    },
                );
            }
        }
        Ok(())
    }

    async fn stop_forward(&mut self, id: &str) {
        if let Some(running) = self.forwards.remove(id) {
            running.handle.stop().await;
        }
    }

    async fn reconcile_http(&mut self, plan: &PublishPlan, events: &mut PublishEvents) {
        let wanted = plan.http_listener;
        let wanted_routes = plan.http_routes.clone();
        // Whether TLS passes through changes each connection's handling path, so
        // it is part of the change detection too.
        let wanted_tls_passthrough = wanted_routes
            .routes()
            .iter()
            .any(|route| route.tls_passthrough);
        let unchanged = matches!(
            self.http_router.as_ref(),
            Some(running)
                if Some(running.listener) == wanted
                    && running.routes == wanted_routes
                    && running.tls_passthrough == wanted_tls_passthrough
        );
        if unchanged {
            return;
        }
        if let Some(running) = self.http_router.take() {
            running.task.abort();
            let _ = running.task.await;
            events.stopped += 1;
        }
        let Some(listener) = wanted else {
            return;
        };
        match self
            .start_http(listener, &wanted_routes, wanted_tls_passthrough)
            .await
        {
            Ok(()) => events.started += 1,
            Err(e) => events.failed.push(format!("http-router {listener}: {e}")),
        }
    }

    async fn start_http(
        &mut self,
        listener: SocketAddr,
        routes: &HttpRouteSet,
        tls_passthrough: bool,
    ) -> Result<(), PublishError> {
        let (tcp, _bound) = bind_http(listener).await?;
        let routes = routes.clone();
        let mode = if tls_passthrough {
            RouteMode::TlsPassThrough
        } else {
            RouteMode::PlainHttp
        };
        // One task per connection; the route set is cloned once on entry (a
        // cheap value type).
        let shared = routes.clone();
        let task = tokio::spawn(async move {
            while let Ok((stream, remote)) = tcp.accept().await {
                let routes = shared.clone();
                tokio::spawn(async move {
                    let _ = run_http_router(
                        stream,
                        &routes,
                        mode,
                        remote,
                        tokio::net::TcpStream::connect,
                    )
                    .await;
                });
            }
        });
        self.http_router = Some(RunningHttp {
            listener,
            routes,
            tls_passthrough,
            task,
        });
        Ok(())
    }

    async fn reconcile_dns(&mut self, plan: &PublishPlan, events: &mut PublishEvents) {
        let Some(dns) = &plan.dns else {
            if let Some(running) = self.dns.take() {
                running.task.abort();
                let _ = running.task.await;
                events.stopped += 1;
            }
            return;
        };
        let unchanged = matches!(
            self.dns.as_ref(),
            Some(running)
                if running.address == dns.bind_address && running.suffix == dns.internal_suffix
        );
        if unchanged {
            return;
        }
        if let Some(running) = self.dns.take() {
            running.task.abort();
            let _ = running.task.await;
            events.stopped += 1;
        }
        match self.start_dns(dns).await {
            Ok(()) => events.started += 1,
            Err(e) => events.failed.push(format!(
                "dns {} {}: {e}",
                dns.bind_address, dns.internal_suffix
            )),
        }
    }

    async fn start_dns(&mut self, plan: &DnsPlan) -> Result<(), PublishError> {
        let (socket, _bound) = bind_udp(plan.bind_address).await?;
        let catalog = DnsCatalog::new(plan.network_id.clone(), plan.internal_suffix.clone())?;
        for record in &plan.records {
            catalog.insert(record.clone())?;
        }
        let task = tokio::spawn(serve_udp(catalog, Arc::new(socket), None));
        self.dns = Some(RunningDns {
            address: plan.bind_address,
            suffix: plan.internal_suffix.clone(),
            task,
        });
        Ok(())
    }

    async fn reconcile_probes(&mut self, plan: &PublishPlan, events: &mut PublishEvents) {
        let wanted: Vec<ProbeSchedule> = plan.probes.clone();
        if self.probe_schedules == wanted {
            return;
        }
        if let Some(task) = self.probe_task.take() {
            task.abort();
            let _ = task.await;
            events.stopped += self.probe_schedules.len();
        }
        // New channel: the old results are unrelated to the new schedule, so
        // replace rather than concatenate.
        let (sender, receiver) = mpsc::channel(REPORT_CHANNEL_CAPACITY);
        self.reports_rx = receiver;
        if !wanted.is_empty() {
            self.probe_task = Some(spawn_probe_loop(wanted.clone(), sender));
            events.started += wanted.len();
        }
        self.probe_schedules = wanted;
    }

    async fn stop_all(&mut self, events: &mut PublishEvents) {
        let ids: Vec<String> = self.forwards.keys().cloned().collect();
        for id in ids {
            self.stop_forward(&id).await;
            events.stopped += 1;
        }
        if let Some(running) = self.http_router.take() {
            running.task.abort();
            let _ = running.task.await;
            events.stopped += 1;
        }
        if let Some(running) = self.dns.take() {
            running.task.abort();
            let _ = running.task.await;
            events.stopped += 1;
        }
        if let Some(task) = self.probe_task.take() {
            task.abort();
            let _ = task.await;
            events.stopped += self.probe_schedules.len();
        }
        self.probe_schedules.clear();
    }
}

/// Probe scheduling loop: every second check the due items and probe them
/// concurrently, one at a time, feeding the results into the channel.
fn spawn_probe_loop(
    schedules: Vec<ProbeSchedule>,
    sender: mpsc::Sender<ProbeReport>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut last_run: HashMap<String, Instant> = HashMap::new();
        loop {
            let now = Instant::now();
            let due: Vec<ProbeSchedule> = schedules
                .iter()
                .filter(|schedule| match last_run.get(schedule.id.as_str()) {
                    Some(last) => now.duration_since(*last) >= schedule.interval,
                    None => true,
                })
                .cloned()
                .collect();
            // Only record schedules that actually got a probe: refreshing the
            // whole table every round pushes the due check further out, which made
            // probes whose interval exceeds the tick step run once at startup
            // only (found during on-device acceptance).
            for schedule in &due {
                let sender = sender.clone();
                tokio::spawn(probe_once(schedule.clone(), sender));
                last_run.insert(schedule.id.clone(), now);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
}

async fn probe_once(schedule: ProbeSchedule, sender: mpsc::Sender<ProbeReport>) {
    let outcome = schedule.target.probe().await;
    let report = ProbeReport {
        probe_id: schedule.id,
        state: match outcome {
            ProbeOutcome::Healthy => HealthState::Healthy,
            ProbeOutcome::Unreachable => HealthState::Unreachable,
        },
        checked_at: now_rfc3339(),
        detail: None,
    };
    // Drop this one when the channel is full (the agent has not drained for a
    // long time): it is rescheduled next cycle, and evidence is not config.
    let _ = sender.send(report).await;
}

/// RFC-3339 UTC timestamp (the same convention as heartbeat / revision
/// bookkeeping).
fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuthorizationPolicy;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn events_report_partial_failures() {
        let mut events = PublishEvents::default();
        assert!(events.is_empty());
        events.failed.push("pf-1: address already in use".into());
        assert!(!events.is_empty());
    }

    /// Full-path unit test (no root needed, binds high local loopback ports):
    /// forwarding really delivers traffic to the backend, probes report on
    /// schedule, and reconciling away a plan releases the listener.
    #[tokio::test]
    async fn publisher_moves_traffic_and_reports_probes() {
        // Backend: echo back the bytes it receives, proving traffic really goes
        // through the forwarding listener.
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let backend_task = tokio::spawn(async move {
            let (mut stream, _remote) = backend.accept().await.unwrap();
            let mut buffer = [0_u8; 16];
            let n = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer)
                .await
                .unwrap();
            buffer[..n].to_vec()
        });
        // Probe a free high port with the 0-port trick for the forwarding
        // listener, then build the plan around it.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        drop(listener);

        let mut publisher = Publisher::new();
        let plan = PublishPlan {
            forwards: vec![PortForwardConfig {
                id: "pf-1".into(),
                network_id: "net-1".into(),
                protocol: ForwardProtocol::Tcp,
                listener_address: listener_addr,
                backend_address: backend_addr,
                // An empty allowlist rejects everything: the test traffic comes
                // from the loopback, so it must be allowed explicitly.
                policy: AuthorizationPolicy {
                    allowed_source_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
                    allowed_bearer_tokens: vec![],
                },
                enabled: true,
            }],
            probes: vec![ProbeSchedule {
                id: "pb-1".into(),
                target: crate::health::ProbeTarget::Tcp {
                    address: listener_addr,
                    timeout: Duration::from_secs(2),
                },
                interval: Duration::from_millis(200),
            }],
            ..PublishPlan::default()
        };
        plan.validate().unwrap();

        let events = publisher.reconcile(Some(&plan)).await.unwrap();
        assert_eq!(events.started, 2, "one forward + one probe");
        assert!(events.failed.is_empty(), "{events:?}");

        // Send one packet: the forwarding listener should hand it to the
        // backend.
        let mut client = tokio::net::TcpStream::connect(listener_addr).await.unwrap();
        client.write_all(b"meshlet").await.unwrap();
        let echo = backend_task.await.unwrap();
        assert_eq!(echo, b"meshlet");

        // The probe reports on schedule: healthy (the listener is alive), and the
        // timestamp is RFC-3339 (Z-suffixed UTC).
        let reports = wait_reports(&mut publisher, 1, Duration::from_secs(3)).await;
        let probe_report = reports
            .iter()
            .find(|report| report.probe_id == "pb-1")
            .expect("probe pb-1 must report at least once");
        assert_eq!(probe_report.state, HealthState::Healthy);
        assert!(
            probe_report.checked_at.ends_with('Z'),
            "checked_at must be RFC-3339 UTC: {}",
            probe_report.checked_at
        );

        // An empty plan stops everything: the listener is released at once and
        // the port becomes reusable.
        let events = publisher.reconcile(None).await.unwrap();
        assert_eq!(events.stopped, 2, "{events:?}");
        let reused = tokio::net::TcpListener::bind(listener_addr).await;
        assert!(reused.is_ok(), "port must be released by reconcile(None)");
        assert!(publisher.is_idle());
    }

    /// An object whose config is unchanged is not restarted (in-flight
    /// connections are not interrupted).
    #[tokio::test]
    async fn unchanged_forward_keeps_its_socket() {
        let backend = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_addr = backend.local_addr().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        drop(listener);
        let plan = PublishPlan {
            forwards: vec![PortForwardConfig {
                id: "pf-1".into(),
                network_id: "net-1".into(),
                protocol: ForwardProtocol::Tcp,
                listener_address: listener_addr,
                backend_address: backend_addr,
                // An empty allowlist rejects everything: the test traffic comes
                // from the loopback, so it must be allowed explicitly.
                policy: AuthorizationPolicy {
                    allowed_source_cidrs: vec!["127.0.0.0/8".parse().unwrap()],
                    allowed_bearer_tokens: vec![],
                },
                enabled: true,
            }],
            ..PublishPlan::default()
        };
        let mut publisher = Publisher::new();
        publisher.reconcile(Some(&plan)).await.unwrap();
        let events = publisher.reconcile(Some(&plan)).await.unwrap();
        assert!(
            events.is_empty(),
            "no restart for an identical plan: {events:?}"
        );
        publisher.reconcile(None).await.unwrap();
    }

    /// A DNS plan opens resolver sockets at the configured addresses and answers
    /// only names inside the internal suffix (a high port, no root required; the
    /// part needing root for `0.0.0.0:53` is the R-06 acceptance gap in the docs).
    #[tokio::test]
    async fn dns_listener_serves_only_the_internal_suffix() {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_address = socket.local_addr().unwrap();
        drop(socket);
        let plan = PublishPlan {
            dns: Some(DnsPlan {
                network_id: "net-1".into(),
                internal_suffix: "mesh".into(),
                bind_address,
                records: vec![crate::dns::DnsRecord {
                    // The recorded name must be an FQDN inside the internal
                    // suffix (validated by `DnsCatalog::insert`).
                    service_id: "svc-1".into(),
                    name: "app.mesh".into(),
                    address: "10.240.0.10".parse().unwrap(),
                    ttl: 60,
                    priority: 100,
                }],
            }),
            ..PublishPlan::default()
        };
        plan.validate().unwrap();
        let mut publisher = Publisher::new();
        let events = publisher.reconcile(Some(&plan)).await.unwrap();
        assert_eq!(events.started, 1, "{events:?}");
        assert!(!publisher.is_idle());

        // UDP ports can be bound repeatedly, so assert on behaviour instead:
        // internal names get answers, external names do not (split-horizon
        // boundary: public resolution is not rewritten).
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut buffer = [0_u8; 512];
        client
            .send_to(&dns_query("app.mesh"), bind_address)
            .await
            .unwrap();
        let answer =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buffer)).await;
        assert!(answer.is_ok(), "app.mesh must be answered: {answer:?}");
        client
            .send_to(&dns_query("example.com"), bind_address)
            .await
            .unwrap();
        // An async recv_from on an empty socket hangs, so use a timeout to
        // assert "no answer".
        let denied =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buffer)).await;
        assert!(
            denied.is_err(),
            "example.com must not be answered: {denied:?}"
        );

        publisher.reconcile(None).await.unwrap();
        assert!(publisher.is_idle());
    }

    /// A minimal DNS A-record query packet: id, the RD flag, QDCOUNT 1, a
    /// label-encoded name, and A/IN.
    fn dns_query(name: &str) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet
    }

    async fn wait_reports(
        publisher: &mut Publisher,
        want: usize,
        timeout: Duration,
    ) -> Vec<ProbeReport> {
        let deadline = Instant::now() + timeout;
        loop {
            let reports = publisher.drain_reports();
            if reports.len() >= want || Instant::now() >= deadline {
                return reports;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}
