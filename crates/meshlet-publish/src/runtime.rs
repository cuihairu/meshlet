//! 设备端发布运行层（R-06）：`PublishPlan` 的本机半边。
//!
//! [`Publisher`] 持有计划要求的全部监听：L4 转发、HTTP(S) 路由、
//! 分域 DNS 套接字，以及探针排程；结果以 [`ProbeReport`] 供 agent 回收上报。
//! 对账是**增量幂等**的：配置未变的对象保留原套接字（不打断在途连接），
//! 被删的对象停掉，配置变更的对象重启。运行层只接受类型化对象，不执行任何
//! 控制面下发的命令（§16.4）。
//!
//! DNS 绑定的是控制面配置里的地址；`0.0.0.0:53` 需要 root，计划本身不代管
//! 权限（见文档 R-06 验收缺口）。

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

/// 探针结果通道容量：一次 tick 的积压上限（超出即丢弃，下一周期重排）。
pub const REPORT_CHANNEL_CAPACITY: usize = 256;

/// 一次对账的结果（日志与测试断言用）。`failed` 记录未能起的对象：下一轮
/// 对账会重试，不静默假装生效。
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

/// 转发监听的任务句柄（TCP 与 UDP 的返回类型不同，收拢为同一枚举便于停止）。
enum ForwardHandle {
    Tcp(JoinHandle<()>),
    Udp(JoinHandle<Result<(), PublishError>>),
}

impl ForwardHandle {
    /// 停止该监听并**等待任务真正退出**：`abort` 只是请求取消，await 保证
    /// `reconcile` 返回时套接字已 drop、端口立即可复用。
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

/// 一台设备的发布运行时。必须在 tokio runtime 内驱动（agent 的发布线程）。
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

    /// 是否没有任何监听（用于启动补漏：agent 重启后账本记「已应用」但
    /// 本机没有监听，必须按空态重放）。
    pub fn is_idle(&self) -> bool {
        self.forwards.is_empty()
            && self.http_router.is_none()
            && self.dns.is_none()
            && self.probe_task.is_none()
    }

    /// 把本机发布态对齐到 `plan`：`None` = 全部停用。
    ///
    /// 返回 `Err` 仅当计划自身自相矛盾（[`PublishPlan::validate`]）——那种情况
    /// 不应部分生效；单个对象绑定失败记入 [`PublishEvents::failed`]，下一轮重试。
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

    /// 回收积压的探针结果（非阻塞）：agent 每轮 tick 调用一次并上报。
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
        // TLS 透传与否影响每个连接的处理路径，一并纳入变更检测。
        let wanted_tls_passthrough = wanted_routes
            .routes()
            .iter()
            .any(|route| route.tls_termination);
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
        // 每个连接一个任务；路由集在进入时克隆一次（轻量值类型）。
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
        // 新通道：旧结果与新排程无关，替换而不是拼接。
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

/// 探针排程循环：1 秒一拍检查到期项，逐个并发探测，结果进通道。
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
            // 只记录真正排了探针的 schedule：整表每轮刷新会把到期判断推远，
            // 让 interval 超过 tick 步长的探针只在启动时跑一次（真机验收发现）。
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
    // 通道满（agent 长时间不回收）时丢弃本条：下一周期会重排，证据不是配置。
    let _ = sender.send(report).await;
}

/// RFC-3339 UTC 时间戳（与心跳/修订簿记同口径）。
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

    /// 完整链路单测（不依赖 root，绑定本机回环高位端口）：转发真的把流量
    /// 送到后端，探针按周期回报，对账停用后监听即释放。
    #[tokio::test]
    async fn publisher_moves_traffic_and_reports_probes() {
        // 后端：回显收到的字节，验证流量确实穿过转发监听。
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
        // 转发监听先用 0 端口探测一个空闲高位端口，再据此构造计划。
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
                // 空白名单 = 全拒：测试流量来自回环，需显式放行。
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

        // 打一个包：转发监听应把它转给后端。
        let mut client = tokio::net::TcpStream::connect(listener_addr).await.unwrap();
        client.write_all(b"meshlet").await.unwrap();
        let echo = backend_task.await.unwrap();
        assert_eq!(echo, b"meshlet");

        // 探针到点回报：健康（监听活着），时间戳是 RFC-3339（Z 结尾的 UTC）。
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

        // 空计划 = 全部停用：监听立即释放，端口可复用。
        let events = publisher.reconcile(None).await.unwrap();
        assert_eq!(events.stopped, 2, "{events:?}");
        let reused = tokio::net::TcpListener::bind(listener_addr).await;
        assert!(reused.is_ok(), "port must be released by reconcile(None)");
        assert!(publisher.is_idle());
    }

    /// 同一个对象配置未变时不重启（不打断在途连接）。
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
                // 空白名单 = 全拒：测试流量来自回环，需显式放行。
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

    /// DNS 计划按配置地址起解析套接字并只应答内部后缀内的名字（高位端口，
    /// 不要求 root；`0.0.0.0:53` 需 root 的部分见文档 R-06 验收缺口）。
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
                    // 记录名须为内部后缀内的 FQDN（`DnsCatalog::insert` 校验）
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

        // UDP 端口可重复绑定，改看行为：内部名字有应答、外部名字无应答
        // （分域边界：不重写公网解析）。
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
        // 异步 recv_from 空套接字会挂起等待，用超时断言「无应答」。
        let denied =
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut buffer)).await;
        assert!(
            denied.is_err(),
            "example.com must not be answered: {denied:?}"
        );

        publisher.reconcile(None).await.unwrap();
        assert!(publisher.is_idle());
    }

    /// 最小 DNS A 记录查询包：id、RD 标志、QDCOUNT 1、标签化名字、A/IN。
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
