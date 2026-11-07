//! Agent 主体：拉计划 → 对账 → 应用 → 心跳，循环之。
//!
//! 一切内核操作都经 [`meshlet_network::SystemBackend`]（ADR-007；非 Linux
//! 平台为 ADR-008 的明确 Unsupported 占位，每个操作失败可见）：
//! 本模块只负责**何时**调用它与**喂什么配置**（计划来自 server，绝非本地拼装
//! 的 Shell 命令，§16.4）。

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use meshlet_config::{AgentConfig, DataplaneConfig, DirectConnectConfig};
use meshlet_domain::PeerLinkState;
use meshlet_domain::{
    DataplaneEvidence, DirectEndpointReport, DirectLinkStatus, EndpointCandidate, Ipv4Cidr,
    DIRECT_PROBE_INTERVAL_SECS,
};
use meshlet_network::dial::{self, DirectDialRequest, DirectDialResult, DirectPeerView};
use meshlet_network::probe::RecoveryGate;
use meshlet_network::{DevicePlan, NetworkDiagnostics, SystemBackend, DEFAULT_TUNNEL_MTU};
use meshlet_publish::{ProbeReport, PublishPlan, Publisher};

#[cfg(target_os = "linux")]
use crate::dbus::DesktopClient;
use crate::desktop::{desktop_trigger, DesktopPublish, DesktopTrigger};
#[cfg(not(target_os = "linux"))]
use crate::desktop_unsupported::DesktopClient;
use crate::direct::{keepalive_secs, merge_handshake_ages, DirectManager, DirectUpdate};
use crate::direct_rtt::{RttCandidate, RttProbe};
use crate::reconcile::{needs_apply, stale_owners, state_path, AgentState, Decision};
use crate::self_update;
use crate::server;
use crate::tray::{TraySink, TrayState, TrayStatus};
use meshlet_config::TrayConfig;

/// 拉取持续失败时的退避上限（秒）：服务端不可达时不打满日志。
pub const BACKOFF_MAX_SECS: u64 = 300;
/// 连续成功后的正常轮询间隔由 `[dataplane] poll_interval_secs` 决定。
const BACKOFF_MIN_SECS: u64 = 1;

/// 设备端 agent：拉计划 → 对账 → 应用 → 心跳，循环之。
pub struct Agent {
    server_url: String,
    token: String,
    dataplane: DataplaneConfig,
    backend: SystemBackend,
    private_key: Option<String>,
    /// 账本状态文件（`{state_dir}/applied.json`）。
    state_path: std::path::PathBuf,
    state_dir: String,
    upgrade: meshlet_config::UpgradeConfig,
    last_update_check: Option<Instant>,
    pending_receipts: std::collections::VecDeque<PendingReceipt>,
    /// 托盘状态落盘（`{state_dir}/tray/`）；headless 下 no-op，见
    /// [`crate::tray`] 与 TODO「运行时系统托盘 icon」。
    tray: TraySink,
    desktop: std::cell::RefCell<DesktopClient>,
    desktop_config: TrayConfig,
    last_desktop_state: std::cell::RefCell<Option<TrayState>>,
    /// 本机设备名（托盘 tooltip 的文本等价物用）。
    device_name: Option<String>,
    /// 服务发布运行时（R-06）：转发/HTTP/DNS 监听 + 探针排程 + 未送达报告。
    publish: PublishRuntime,
    /// §12 P2P 直连管理器：每对端的链路状态机 + 重启恢复（ledger）。
    direct: DirectManager,
    /// 直连 keep set 的持久化文件（`{state_dir}/direct.json`）。
    direct_ledger: std::path::PathBuf,
    /// 上次直连探测时刻（30s 节流；`None` = 未探测过，首轮即探）。
    last_direct_probe: Option<Instant>,
    /// R-DIAG-2 直连 RTT 后台运行时：独立线程 ping 直连对端（不阻塞 tick）。
    direct_rtt: crate::direct_rtt::DirectRttRuntime,
    /// MT-002 任务通道：后台 worker（独立线程拉取待办并 ack→执行→回执）。
    /// 主循环 tick 只 [kick](crate::tasks::TaskRuntime::kick) 投递、立即返回，
    /// 单任务最长 [DEFAULT_TIMEOUT_SECS] 不再阻塞心跳/数据面对账。账本
    /// （`{state_dir}/tasks.json`，断线补派据此补报、绝不重跑）由 worker 持有。
    task_runtime: crate::tasks::TaskRuntime,
    /// SEL-001 候选端点探测运行时：独立线程按 5s（可配）对每 peer 全部候选
    /// 端点发 ICMP 探测，采集 RTT/丢包/抖动滑动窗口。候选集由
    /// [`Agent::reconcile_direct`] 每 30s 刷新（零控制面负载）。
    probe: crate::probe::ProbeRuntime,
    /// SEL-003 恢复门：直连劣化回中继后连续 N 轮健康才允许切回（防抖）。
    recovery: RecoveryGate,
    /// SSH 别名同步开关与状态路径（默认全关：不写 `~/.ssh` 任何文件）。
    ssh_config_sync: meshlet_config::SshConfigSyncConfig,
    ssh_sync_status_path: std::path::PathBuf,
}

/// 发布运行时（R-06）：一个单 worker 的 tokio runtime 承载
/// [`meshlet_publish::Publisher`] 的监听任务与探针排程；`unreported` 是尚未
/// 送达控制面的探针结果（上报失败保留，下一轮重试）。
///
/// 运行层只由服务端计划驱动（§16.4：不下发命令），失败只记日志——发布问题
/// 绝不打断隧道/路由/NAT 的数据面循环。
struct PublishRuntime {
    /// 发布层专用运行时（Agent 主循环是同步线程，没有环境运行时可用）；
    /// 用 `Option` 持有是为了在 `Drop` 里取走它、放到独立线程关闭。
    runtime: Option<tokio::runtime::Runtime>,
    publisher: Publisher,
    unreported: Vec<ProbeReport>,
}

/// 单批上报上限（与控制面 `PublishHealthRequest` 的批上限一致）。
const PUBLISH_REPORT_BATCH: usize = 256;

impl PublishRuntime {
    fn new() -> Self {
        Self {
            runtime: Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .thread_name("meshlet-publish")
                    .enable_all()
                    .build()
                    .expect("spawn the publish runtime thread"),
            ),
            publisher: Publisher::new(),
            unreported: Vec::new(),
        }
    }

    /// 是否没有任何监听或探针在跑（决定能否跳过 tokio 调用）。
    fn is_idle(&self) -> bool {
        self.publisher.is_idle()
    }
}

impl Drop for PublishRuntime {
    fn drop(&mut self) {
        // tokio 不允许在异步上下文里 drop Runtime（关闭时要 block_on）。Agent
        // 主循环是同步线程，但测试/嵌入方可能在 async 上下文里构造并丢弃
        // Agent——把 Runtime 挪到独立线程关闭，任何调用方都不会踩这个坑。
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        let _ = std::thread::Builder::new()
            .name("meshlet-publish-shutdown".into())
            .spawn(move || drop(runtime))
            .map(|handle| {
                let _ = handle.join();
            });
    }
}

struct PendingReceipt {
    plan: DevicePlan,
    error: Option<String>,
}

impl Agent {
    /// 生产构造：默认 `sudo -n` 后端（agent 通常以 root 运行；`sudo -n` 在
    /// 已是 root 或已免密的环境下同样成立）。
    pub fn new(config: AgentConfig, private_key: Option<String>) -> Self {
        let backend = SystemBackend::new().with_interface(config.dataplane.interface.clone());
        Self::with_backend(config, private_key, backend)
    }

    /// 注入后端（netns 集成测试用；生产走 [`Agent::new`]）。
    #[allow(clippy::default_constructed_unit_structs)]
    pub fn with_backend(
        config: AgentConfig,
        private_key: Option<String>,
        backend: SystemBackend,
    ) -> Self {
        // 先起探测运行时再移动 config：字段初始化按书写顺序求值，`dataplane`
        // 会在 struct 字面量里先被 move，探测运行时须在此之前读到 probe 配置。
        let probe = crate::probe::ProbeRuntime::start(&config.dataplane.probe);
        let recovery_required = config.dataplane.probe.recovery_required;
        // 任务 worker 的参数提前取出（config 随后被逐字段 move，不能再借用）。
        let server_url = config.server_url.clone();
        let device_token = config.device_token.clone().unwrap_or_default();
        let task_ledger_path = task_ledger_path(&config.state_dir);
        let task_ledger = crate::tasks::TaskLedger::load(&task_ledger_path);
        let notify_enabled = config.tray.notifications;
        // R-DIAG-2：RTT 探测与数据面解耦（后台线程）。后端可 Clone（仅携带
        // netns/sudo/interface 配置），worker 线程内 `ping_rtt_ms` 不拖主循环。
        let direct_rtt = crate::direct_rtt::DirectRttRuntime::start(backend.clone());
        Self {
            server_url: config.server_url,
            token: config.device_token.unwrap_or_default(),
            state_path: state_path(&config.state_dir),
            state_dir: config.state_dir.clone(),
            upgrade: config.upgrade,
            last_update_check: None,
            pending_receipts: std::collections::VecDeque::new(),
            tray: TraySink::new(&config.state_dir),
            desktop: std::cell::RefCell::new(DesktopClient::default()),
            desktop_config: config.tray,
            last_desktop_state: std::cell::RefCell::new(None),
            device_name: config.device_name.clone(),
            dataplane: config.dataplane,
            private_key,
            backend,
            publish: PublishRuntime::new(),
            direct_ledger: direct_ledger_path(&config.state_dir),
            direct: DirectManager::load(&direct_ledger_path(&config.state_dir)),
            last_direct_probe: None,
            direct_rtt,
            task_runtime: crate::tasks::TaskRuntime::start(
                server_url,
                device_token,
                task_ledger,
                task_ledger_path,
                // MT-004：任务到达（ack 后）触发托盘气泡。通知是尽力而为：
                // 与状态气泡一致尊重 `tray.notifications`（默认关），并在 worker
                // 线程内发送——D-Bus 连接/调用可能阻塞（通知守护不响应），
                // 绝不影响主循环心跳与数据面对账。
                move |task: &meshlet_domain::Task| {
                    if !notify_enabled {
                        return;
                    }
                    let call =
                        crate::desktop::task_notify_call(&task.id.to_string(), &task.payload.cmd);
                    let env = crate::tray::EnvProbe::from_env();
                    let mut client = DesktopClient::default();
                    let result = client.notify_task(&call, &env);
                    if !matches!(result, DesktopPublish::Published) {
                        tracing::debug!(result = ?result, "task arrival not shown");
                    }
                },
            ),
            probe,
            recovery: RecoveryGate::new(recovery_required),
            ssh_config_sync: config.ssh_config_sync,
            ssh_sync_status_path: crate::ssh_sync::status_path(&config.state_dir),
        }
    }

    /// 账本状态文件路径（测试与运维排查用）。
    pub fn state_path(&self) -> &Path {
        &self.state_path
    }

    /// 主循环：首轮即对账（启动对账），之后按 `poll_interval_secs` 轮询；
    /// 连续失败指数退避至上限。
    pub fn run(mut self) -> ! {
        let mut backoff = Duration::from_secs(BACKOFF_MIN_SECS);
        loop {
            match self.tick() {
                Ok(()) => backoff = Duration::from_secs(BACKOFF_MIN_SECS),
                Err(e) => {
                    tracing::warn!(error = %e, retry_in_secs = backoff.as_secs(), "agent tick failed");
                }
            }
            let wait = if backoff <= Duration::from_secs(BACKOFF_MIN_SECS) {
                Duration::from_secs(self.dataplane.poll_interval_secs.max(1))
            } else {
                backoff
            };
            std::thread::sleep(wait);
            backoff = (backoff * 2).min(Duration::from_secs(BACKOFF_MAX_SECS));
        }
    }

    /// 一轮：拉计划 → 需要则应用 → 心跳上报。待审批（自举注册，ZeroTier 式）
    /// 时拉不到计划：心跳保活让控制中心看到设备活着，批准后自然转入正常循环。
    pub fn tick(&mut self) -> Result<(), String> {
        self.flush_pending_receipts();
        let plan = match server::fetch_plan(&self.server_url, &self.token) {
            Ok(plan) => plan,
            // 服务端契约：Pending 申请的 desired 端点 404 且消息含
            // "pending approval"（migration 008 取舍：批准前不进期望配置）。
            Err(e) if e.contains("pending approval") => {
                self.report_heartbeat(None);
                // 待审批无期望计划：撤掉上一轮留下的发布监听，不留本机监听。
                self.apply_publish(None);
                tracing::info!("registration pending approval: heartbeat sent, plan withheld");
                // 待审批 = 隧道尚未建立：按「已断开」呈现（`PresenceState::Offline`
                // 的对位），不用「在线」误导。无计划 → 虚拟 IP 未知（`None`）。
                self.publish_tray(TrayState::Offline, None);
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let result = self.reconcile(&plan);
        let error = result.as_ref().err().map(String::as_str);
        if let Err(error) = server::report_apply(&self.server_url, &self.token, &plan, error) {
            self.enqueue_receipt(plan.clone(), Some(error));
        }
        // 发布对账与内核对账相互独立（本机监听不依赖隧道）：即使内核重放失败
        // 也先把发布态对齐；发布失败只记日志，绝不打断数据面循环。
        self.apply_publish(plan.publish.as_ref());
        self.report_publish_health();
        self.apply_ssh_sync(&plan);
        let decision = result?;
        let control_ok = self.report_heartbeat(Some(&plan));
        // §12：心跳（带本机直连候选）之后探直连——服务端先看到本机端点，
        // 下一轮拉候选时数据已就位；直连失败只记日志，不影响数据面循环。
        self.reconcile_direct(&plan);
        // MT-002：任务通道（下发与回执）与数据面循环相互独立——任务失败只
        // 记日志，绝不打断隧道/路由/心跳；拉取失败同样只记日志，下轮重试。
        self.process_tasks();
        // 托盘态：reason × 控制通道 × 隧道握手（映射依据见 [`crate::tray`]）。
        // 虚拟 IP 与 `info` 命令同一链路：取计划隧道地址（`plan.tunnel.address`）。
        self.publish_tray(
            TrayState::derive(decision.reason, control_ok, self.last_handshake().is_some()),
            Some(plan.tunnel.address),
        );
        self.maybe_self_update();
        Ok(())
    }

    /// SSH 别名同步（`[ssh_config_sync]`）：据计划渲染 `~/.ssh/meshlet.conf`
    /// 的 `Host <alias>` 块；失败只记状态，绝不打断数据面循环。
    fn apply_ssh_sync(&mut self, plan: &DevicePlan) {
        let config = self.ssh_config_sync;
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let fallback = crate::ssh_sync::self_host(
            self.device_name.as_deref().unwrap_or("meshlet-node"),
            plan.tunnel.address,
        );
        let hosts = plan
            .ssh_config
            .as_ref()
            .map(crate::ssh_sync::hosts_from_plan);
        let status = crate::ssh_sync::sync(
            &home,
            hosts.as_deref(),
            &fallback,
            config.enabled,
            config.manage_include,
            &self.ssh_sync_status_path,
        );
        if let Some(error) = &status.last_error {
            tracing::warn!(error = %error, "ssh config sync failed");
        }
    }

    fn flush_pending_receipts(&mut self) {
        while let Some(receipt) = self.pending_receipts.pop_front() {
            let error = receipt.error.as_deref();
            if let Err(error) =
                server::report_apply(&self.server_url, &self.token, &receipt.plan, error)
            {
                self.pending_receipts.push_front(receipt);
                tracing::warn!(%error, "device apply receipt retry not delivered");
                break;
            }
        }
    }

    fn enqueue_receipt(&mut self, plan: DevicePlan, error: Option<String>) {
        if self.pending_receipts.len() == 16 {
            self.pending_receipts.pop_front();
        }
        self.pending_receipts
            .push_back(PendingReceipt { plan, error });
    }

    /// MT-002 任务通道：唤醒后台 worker 拉取本设备待办并逐个 ack→执行→回执。
    /// 只投递、立即返回（单任务最长 [DEFAULT_TIMEOUT_SECS]，内联会停心跳）；
    /// worker 失败只记日志（下轮重试），绝不打断数据面循环。
    fn process_tasks(&mut self) {
        self.task_runtime.kick();
    }

    fn maybe_self_update(&mut self) {
        if !self.upgrade.enabled {
            return;
        }
        let due = self
            .last_update_check
            .map(|last| last.elapsed() >= Duration::from_secs(self.upgrade.check_interval_secs))
            .unwrap_or_default();
        if !due {
            return;
        }
        self.last_update_check = Some(Instant::now());
        let Ok(manifest) = self_update::fetch_manifest(&self.server_url) else {
            return;
        };
        let Ok(self_update::UpdateCheck::Available(plan)) =
            self_update::plan_update(env!("CARGO_PKG_VERSION"), manifest)
        else {
            return;
        };
        let installed = self_update::install(&plan).and_then(|result| {
            self_update::request_restart(&self.state_dir, &result).map(|_| result)
        });
        if let Ok(result) = installed {
            tracing::info!(
                from_version = %result.from_version,
                to_version = %result.to_version,
                "agent update installed; restart requested"
            );
        }
    }

    /// 心跳上报并返回是否送达（失败只记日志，不让数据面循环退避）。
    fn report_heartbeat(&self, plan: Option<&DevicePlan>) -> bool {
        match self.heartbeat(plan) {
            Ok(()) => true,
            Err(e) => {
                // 上报失败不影响数据面：计划已按期望对账完毕。
                tracing::warn!(error = %e, "heartbeat not delivered");
                false
            }
        }
    }

    /// 发布段对账（R-06）：把本机监听与探针排程对齐到计划里属于本设备的期望
    /// 发布态。`None`（待审批、无计划）= 全部停用。
    fn apply_publish(&mut self, plan: Option<&PublishPlan>) {
        let wanted_empty = plan.map(|plan| plan.is_empty()).unwrap_or(true);
        if wanted_empty && self.publish.is_idle() {
            // 无发布对象且无监听：不起 tokio 任务，保持冷路径零开销。
            return;
        }
        let PublishRuntime {
            runtime,
            publisher,
            unreported: _,
        } = &mut self.publish;
        let events = match runtime
            .as_mut()
            .expect("the publish runtime is alive")
            .block_on(publisher.reconcile(plan))
        {
            Ok(events) => events,
            Err(e) => {
                // 计划自相矛盾：拒绝部分生效，保留现有监听，下一轮重试。
                tracing::warn!(error = %e, "publish plan rejected; keeping current listeners");
                return;
            }
        };
        if !events.is_empty() {
            tracing::info!(
                started = events.started,
                stopped = events.stopped,
                failed = ?events.failed,
                "reconciled the publish plan"
            );
        }
    }

    /// 探针结果上报（R-06）：回收本轮结果并入未送达队列，失败保留重试。
    /// 证据不是配置：上报失败只影响健康可见性，不影响发布监听。
    fn report_publish_health(&mut self) {
        let fresh = self.publish.publisher.drain_reports();
        self.publish.unreported.extend(fresh);
        if self.publish.unreported.is_empty() {
            return;
        }
        // 批上限对齐控制面；超出丢弃最旧的（探针会按周期重排，不会永久丢失）。
        let excess = self
            .publish
            .unreported
            .len()
            .saturating_sub(PUBLISH_REPORT_BATCH);
        if excess > 0 {
            self.publish.unreported.drain(..excess);
        }
        if let Err(e) =
            server::report_publish_health(&self.server_url, &self.token, &self.publish.unreported)
        {
            tracing::warn!(
                error = %e,
                count = self.publish.unreported.len(),
                "publish health not delivered"
            );
        } else {
            self.publish.unreported.clear();
        }
    }

    /// 托盘状态落盘（用户 2026-10-16：「运行时需要显示对应的 icon 的吧」「系统托盘
    /// icon 最好能体现状态变化」）。headless / CI 下 [`TraySink::publish`] no-op
    /// （不写文件、不 panic），失败同样只记日志——托盘永不影响数据面循环。
    pub fn publish_tray(&self, state: TrayState, virtual_ip: Option<std::net::Ipv4Addr>) {
        let status = TrayStatus::new(
            state,
            self.device_name.as_deref(),
            virtual_ip,
            &self.dataplane.interface,
        );
        if let Err(e) = self.tray.publish(&status) {
            tracing::warn!(
                error = %e,
                state = state.accessible_name(),
                "tray status not published"
            );
        }

        let trigger = desktop_trigger(*self.last_desktop_state.borrow(), state);
        if trigger != DesktopTrigger::Unchanged {
            let env = crate::tray::EnvProbe::from_env();
            let result = self.desktop.borrow_mut().publish(
                &status,
                &env,
                trigger == DesktopTrigger::Changed && self.desktop_config.notifications,
                self.desktop_config.status_notifier_item,
            );
            *self.last_desktop_state.borrow_mut() = Some(state);
            if !matches!(result, DesktopPublish::Published) {
                tracing::debug!(result = ?result, "desktop status not shown");
            }
        }
    }

    /// 对账并按需重放（§10.1 + TODO #32）。
    ///
    /// 拉不到计划时**不动内核**：数据面以服务端期望为唯一来源，宁可不改也不
    /// 按猜测重放（调用方 [`Agent::tick`] 因此让整轮失败并退避重试）。
    pub fn reconcile(&mut self, plan: &DevicePlan) -> Result<Decision, String> {
        let ledger = AgentState::load(&self.state_path);
        let state = ledger.clone().unwrap_or_default();
        let ledger_present = ledger.is_ok();
        let last_good = match ledger.as_ref() {
            Ok(entry) => entry.last_good_plan.clone(),
            Err(_) => None,
        };
        let snapshot = self
            .backend
            .inspect_sync()
            .map_err(|e| format!("inspect the local network state: {e}"))?;
        // §12：直连保留集来自**ledger 恢复 + 探测周期状态机**，不从内核猜——
        // 内核里非 hub 的 peer 若非自有直连，必须按漂移清掉（外来 peer 注入
        // 的真机验收）。keep set 传给内核对账：直连对端被保留，不被重放冲掉。
        let direct_keys = self.direct.keep_keys();
        let mut local_plan = plan_with_hub_endpoint(plan, self.dataplane.hub_endpoint.as_deref());
        local_plan.tunnel.name = self.dataplane.interface.clone();
        // SEL-003 hub 兜底：hub peer 的 keepalive 永不掉——计划里低于常量
        // （或旧版计划缺省 `None`）都强制抬到 [meshlet_network::HUB_KEEPALIVE_SECS]。
        enforce_hub_keepalive(&mut local_plan);
        // §12：直连开启时把 wg 接口绑定到配置的监听端口——直连对端按
        // `listen_port` 发包（`direct_report` 上报的正是它）。本地改写不影响
        // 期望哈希（与 hub_endpoint 兜底同一口径）。
        if self.dataplane.direct_connect.enabled {
            local_plan.tunnel.listen_port = Some(self.dataplane.direct_connect.listen_port);
        }
        for route in &mut local_plan.routes {
            route.interface = self.dataplane.interface.clone();
        }
        for rule in &mut local_plan.nat_rules {
            // `-i` 只对 PREROUTING 生效（`iptables_args` 同一口径）；改写
            // POSTROUTING 规则的惰性元数据只会让指纹对不上内核。
            if rule.chain == meshlet_network::nat::NatChain::Prerouting {
                rule.incoming_interface = Some(self.dataplane.interface.clone());
            }
        }
        local_plan.tunnel.private_key = self.private_key.clone();
        let mut decision = needs_apply(&state, &snapshot, plan, &direct_keys);
        if !decision.needs_apply
            && !self
                .backend
                .device_plan_matches_sync(&local_plan, &direct_keys)
                .unwrap_or(false)
        {
            decision = Decision {
                needs_apply: true,
                reason: crate::reconcile::Reason::KernelDrift,
            };
        }
        if !decision.needs_apply {
            return Ok(decision);
        }
        // 先按所有权清理计划里已消失的映射单元（§12.6），再重放隧道/路由/NAT。
        let kernel_nat_owners = self
            .backend
            .meshlet_nat_owners_sync()
            .map_err(|e| format!("enumerate meshlet nat owners: {e}"))?;
        for owner in stale_owners(&state, plan, &kernel_nat_owners, ledger_present) {
            if let Err(error) = self.backend.remove_nat_sync(&owner) {
                return Err(self.fail_transition(
                    last_good.as_ref(),
                    format!("remove meshlet nat rules of {owner}: {error}"),
                ));
            }
            tracing::info!(owner = %owner, "removed stale meshlet nat rules");
        }
        if let Err(error) = self
            .backend
            .remove_stale_meshlet_routes_sync(&local_plan.routes)
        {
            return Err(self.fail_transition(
                last_good.as_ref(),
                format!("remove stale meshlet routes: {error}"),
            ));
        }
        // hub 入口地址兜底（§16.4：服务端不下发 agent 的网络位置）：计划未带
        // endpoint 时用本地 `[dataplane] hub_endpoint` 填充——只影响本次内核下
        // 发，账本仍按服务端原计划记（desired_config_hash 不因此变化）。
        let transition = self.backend.apply_device_plan_sync(
            &local_plan,
            self.private_key.clone(),
            None,
            &direct_keys,
        );
        if let Err(error) = transition {
            return Err(self.fail_transition(
                last_good.as_ref(),
                format!("apply the desired plan: {error}"),
            ));
        }
        let matches = self
            .backend
            .device_plan_matches_sync(&local_plan, &direct_keys)
            .map_err(|error| {
                self.fail_transition(
                    last_good.as_ref(),
                    format!("read back the desired plan: {error}"),
                )
            })?;
        if !matches {
            return Err(self.fail_transition(
                last_good.as_ref(),
                "applied plan did not match kernel readback".to_string(),
            ));
        }
        let mut ledger_plan = local_plan;
        ledger_plan.tunnel.private_key = None;
        // 本机公钥指纹入账本（BUG② 漂移判定）：对账据此识别「peer 一致但
        // 本机私钥被换」的手动隧道。推导失败（wg 缺失等）按缺省留空——
        // 漂移判定对空指纹不判，下轮重放成功后再补齐。
        let mut ledger = AgentState::from_plan(&ledger_plan);
        if let Some(key) = &self.private_key {
            if let Ok(public_key) = self.backend.public_key_from_private(key) {
                ledger.local_public_key = public_key;
            }
        }
        ledger.save(&self.state_path)?;
        tracing::info!(
            desired_config_hash = %plan.desired_config_hash,
            routes = plan.routes.len(),
            nat_rules = plan.nat_rules.len(),
            reason = ?decision.reason,
            "applied the desired device plan"
        );
        Ok(decision)
    }

    fn fail_transition(
        &mut self,
        last_good: Option<&DevicePlan>,
        transition_error: String,
    ) -> String {
        match last_good {
            None => transition_error,
            Some(last_good) => {
                let direct_keys = self.direct.keep_keys();
                match self.backend.apply_device_plan_sync(
                    last_good,
                    self.private_key.clone(),
                    None,
                    &direct_keys,
                ) {
                    Ok(()) => {
                        let restored = self
                            .backend
                            .device_plan_matches_sync(last_good, &direct_keys)
                            .map_err(|e| e.to_string());
                        match restored {
                        Ok(true) => {
                            tracing::warn!(
                                error = %transition_error,
                                "restored the last successful device plan"
                            );
                            format!("{transition_error}; restored last good plan")
                        }
                        Ok(false) => format!(
                            "{transition_error}; restore failed: kernel readback did not match last good plan"
                        ),
                        Err(error) => format!(
                            "{transition_error}; restore readback failed: {error}"
                        ),
                    }
                    }
                    Err(restore_error) => {
                        tracing::error!(
                            error = %transition_error,
                            restore_error = %restore_error,
                            "could not restore the last successful device plan"
                        );
                        format!("{transition_error}; restore failed: {restore_error}")
                    }
                }
            }
        }
    }

    /// §12 P2P 直连探测循环（30s 节流）：拉候选 → 域层状态机 → `wg set` 下发。
    ///
    /// 直连是**增益**：所有失败（拉候选失败 / LAN 枚举失败 / 握手读数失败 /
    /// `wg set` 失败）只记日志，绝不打断 hub 中继路径——对端仍按 hub 整段
    /// 路由可达，下一周期重试。开关关闭时清空已建立的直连（交还 hub，由
    /// 内核对账的漂移清理兜底）。
    ///
    /// `peer dial` 意图（[`dial::DirectDialRequest`]）：CLI 写在
    /// `{state_dir}/direct-dial.json`。有意图时**跳过 30s 节流**立刻探测一轮
    /// （拨号不等下个周期），把目标候选喂给状态机并经
    /// [`crate::agent::Agent::apply_direct_update`] 调 `wg set`（executor 经
    /// `meshlet-network` 发起直连拨号）；随后把结果写回
    /// `{state_dir}/direct-dial-result.json` 并清除意图。拨号失败/无路径/
    /// 非候选都如实写失败结果——绝不静默。
    ///
    /// 生产由 [`Agent::tick`] 在心跳之后调度（服务端先看到本机直连候选）；
    /// netns 集成测试可直接驱动一轮。
    pub fn reconcile_direct(&mut self, plan: &DevicePlan) {
        let request = dial::load_request(Path::new(&self.state_dir));
        if !self.dataplane.direct_connect.enabled {
            // 直连关 → 无候选可探：清空探测候选缓存（探测线程下一轮 no-op）。
            self.probe.update_candidates(&[]);
            let updates = self.direct.demote_all();
            if !updates.is_empty() {
                for update in &updates {
                    self.apply_direct_update(update);
                }
                self.save_direct_ledger();
            }
            self.last_direct_probe = Some(Instant::now());
            if let Some(req) = request {
                self.finish_dial(
                    &req,
                    false,
                    "hub_relay",
                    "direct connect is disabled (config)",
                );
            }
            return;
        }
        let due = self
            .last_direct_probe
            .map(|last| last.elapsed().as_secs() >= DIRECT_PROBE_INTERVAL_SECS)
            .unwrap_or(true);
        // 有拨号意图即强制本轮（不等节流）；无意图按正常节流。
        if !due && request.is_none() {
            return;
        }
        self.last_direct_probe = Some(Instant::now());
        let wanted = match server::fetch_peer_endpoints(&self.server_url, &self.token) {
            Ok(wanted) => wanted,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: peer endpoints unavailable");
                if let Some(req) = request {
                    self.finish_dial(
                        &req,
                        false,
                        "hub_relay",
                        &format!("peer endpoints unavailable: {e}"),
                    );
                }
                return;
            }
        };
        // SEL-001：候选集刷新（探测线程复用，不额外请求 server——零控制面负载）。
        self.probe.update_candidates(&wanted);
        let Some(scope) = direct_scope(plan) else {
            tracing::warn!("direct probe: no routable scope in the plan; keeping hub relay");
            if let Some(req) = request {
                self.finish_dial(&req, false, "hub_relay", "no routable scope in the plan");
            }
            return;
        };
        let my_lan_subnets = match self.backend.lan_subnets_sync() {
            Ok(subnets) => subnets,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: lan subnets unavailable");
                Vec::new()
            }
        };
        let handshake_ages = match self.backend.handshake_ages_sync() {
            Ok(ages) => ages,
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: handshake ages unavailable");
                BTreeMap::new()
            }
        };
        // 诊断快照一次采集、多处复用（直连 enrich + 晋升门槛的握手兜底）：
        // `wg dump` 与 latest-handshakes 是同一次内核读数的两投影——Windows
        // 隧道抖动期 latest-handshakes 不可读时，dump 里的握手时间仍是晋升
        // 门槛的合法输入（缺失则 pending 拿不到握手证据，永卡「拨号中」）。
        let net = match self.backend.diagnostics_sync() {
            Ok(net) => Some(net),
            Err(e) => {
                tracing::warn!(error = %e, "direct probe: diagnostics unavailable");
                None
            }
        };
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let handshake_ages =
            merge_handshake_ages(handshake_ages, dump_handshake_ages(net.as_ref(), now_secs));
        // SEL-003：从探测窗口推导各对端直连路径是否劣化（丢包尖峰/超时）。
        let degraded = self.probe.degraded_map();
        // SEL-003 恢复门：对处于直连状态的对端记录本轮健康度；回中继后连续
        // N 轮健康才放行切回。健康 = 未劣化且握手年龄在健康窗口内。
        let mut hold_relay = std::collections::BTreeSet::new();
        for peer in &wanted {
            let healthy = !degraded.get(&peer.public_key).copied().unwrap_or(false)
                && handshake_ages
                    .get(&peer.public_key)
                    .is_none_or(|age| *age <= meshlet_domain::DIRECT_HEALTH_WINDOW_SECS);
            let ready = self.recovery.record(&peer.public_key, healthy);
            if !ready
                && self
                    .direct
                    .status_of(&peer.public_key)
                    .is_some_and(|p| p.state == PeerLinkState::Relay)
            {
                // 已回中继但尚未连续健康 N 轮：保持中继（防抖切回）。
                hold_relay.insert(peer.public_key.clone());
            }
        }
        // 回收不在候选集里的恢复计数。
        let live_keys: Vec<String> = wanted.iter().map(|p| p.public_key.clone()).collect();
        self.recovery.retain(&live_keys);
        let updates = self.direct.apply_plan(
            &wanted,
            &my_lan_subnets,
            scope,
            plan.tunnel.address,
            &handshake_ages,
            &degraded,
            &hold_relay,
        );
        if !updates.is_empty() {
            for update in &updates {
                self.apply_direct_update(update);
            }
            self.save_direct_ledger();
        }
        // R-DIAG-2：对处于直连状态的对端刷新读数（wg 端点/握手/流量）+ 实测
        // 直连路径 RTT——即使本周期无动作也要刷新，供心跳与控制台/CLI 展示。
        self.enrich_direct_peers(net.as_ref(), now_secs);
        // SEL-002：迟滞切换。已建立直连的对端，若其候选窗口中另有路径连续 N
        // 采样且优于现路径 ≥30%，则 `wg set endpoint` 漫游过去（零断线），
        // 并追加切换事件（事件可查）。探测未启用 / 无直连 / 无更优路径都
        // 是 no-op——绝不影响数据面循环。
        self.apply_switch_decisions();
        // 发布直连对端视图（`direct-peers.json`）：托盘「直连节点 / 连接节点…」
        // 子菜单与 CLI `peer dial` 解析 `<node>` 的数据源。
        self.publish_direct_peers(&wanted);
        if let Some(req) = request {
            self.finish_dial_for_request(&req);
        }
    }

    /// 按拨号意图确定结果：状态机已跑完本轮，目标对端当前状态即判定依据。
    fn finish_dial_for_request(&self, req: &DirectDialRequest) {
        let (ok, mode, message) = dial_verdict(self.direct.status_of(&req.public_key));
        self.finish_dial(req, ok, mode, message);
    }

    /// 写拨号结果并清除意图。结果文件常驻（CLI 轮询它），下次拨号覆盖。
    fn finish_dial(&self, req: &DirectDialRequest, ok: bool, mode: &str, message: &str) {
        let result = DirectDialResult {
            request_id: req.request_id.clone(),
            ok,
            mode: mode.into(),
            message: message.into(),
            finished_at: dial::now_millis(),
        };
        if let Err(e) = dial::write_result(Path::new(&self.state_dir), &result) {
            tracing::warn!(error = %e, "direct dial result not written");
        }
        if let Err(e) = dial::clear_request(Path::new(&self.state_dir)) {
            tracing::warn!(error = %e, "direct dial request not cleared");
        }
    }

    /// 发布直连对端视图：服务端候选集 + 当前链路状态合并（`direct-peers.json`）。
    /// 候选已直连/待握手取链路状态；候选无路径（Relay）标 `hub_relay`（可拨号）。
    fn publish_direct_peers(&self, wanted: &[meshlet_domain::PeerEndpoints]) {
        let views = direct_peer_views(wanted, &self.direct.link_statuses());
        if let Err(e) = dial::write_direct_peers(Path::new(&self.state_dir), &views) {
            tracing::warn!(error = %e, "direct peers view not published");
        }
    }

    /// R-DIAG-2：从内核刷新各直连对端的实际状态（endpoint / 最近握手 /
    /// 累计流量），RTT 取**后台运行时**的最新实测值（绝不内联 `ping`）。
    ///
    /// 探测候选带对端 endpoint 的 underlay 地址：overlay VIP 不答 ICMP
    /// （WireGuard 接口 / 防火墙常弃包，链路可能完全活着）时，后台线程回退
    /// ping endpoint——两路都无响应才「实测失败」，rtt_source 随 RTT 如实记录
    /// （实测成功 probe_ok；不可测但握手新鲜 handshake_fresh；两路无响应且
    /// 握手也不新鲜 probe_failed；探测在途 unprobed），供面板/控制台标注。
    ///
    /// 读数失败只记日志——展示数据源是「最后已知态」，绝不让诊断采集干扰
    /// 数据面；对端已不在管（本周期被 Demote）则各 record_* no-op。
    fn enrich_direct_peers(&mut self, net: Option<&NetworkDiagnostics>, now_secs: u64) {
        let candidates = self.direct.direct_candidates();
        if candidates.is_empty() {
            // 无直连对端：清空 RTT 候选（后台线程下一轮 no-op）。
            self.direct_rtt.update_candidates(Vec::new());
            return;
        }
        // net 由调用方传入（reconcile 已采集一次，避免重复 `wg dump`）；None =
        // 读数失败则没有回退路径可用，仅按 overlay 探测（与旧行为一致）。
        let probed: Vec<RttCandidate> = candidates
            .into_iter()
            .map(|(public_key, vip)| {
                let endpoint_ip = net.as_ref().and_then(|net| {
                    net.wg
                        .iter()
                        .find(|p| p.public_key == public_key)
                        .map(|p| p.endpoint.clone())
                        .unwrap_or_default()
                        .rsplit_once(':')
                        .and_then(|(host, _)| host.parse::<Ipv4Addr>().ok())
                });
                (public_key, vip, endpoint_ip)
            })
            .collect();
        // 后台线程按最新候选集 ping；主循环只读快照，不等任何 ping。
        self.direct_rtt.update_candidates(probed.clone());
        let rtts = self.direct_rtt.snapshot();
        for (public_key, vip, _endpoint_ip) in probed {
            let wg_peer = net
                .as_ref()
                .and_then(|net| net.wg.iter().find(|p| p.public_key == public_key));
            let endpoint = wg_peer.map(|p| p.endpoint.clone()).unwrap_or_default();
            let last_handshake_at =
                wg_peer.and_then(|p| (p.last_handshake > 0).then_some(p.last_handshake));
            let (rx_bytes, tx_bytes) = wg_peer.map(|p| (p.rx_bytes, p.tx_bytes)).unwrap_or((0, 0));
            // 读快照：刚更新候选集的第一次读可能尚未有实测值（None=未知，
            // 与「读数失败」一致，展示数据源最后已知态）。`vip` 仅供记录日志。
            let probe = rtts
                .get(&public_key)
                .copied()
                .unwrap_or_else(RttProbe::unknown);
            let _ = vip;
            self.direct.record_peer_status(
                &public_key,
                probe.rtt_ms,
                honest_rtt_source(&probe, last_handshake_at, now_secs),
                last_handshake_at,
                rx_bytes,
                tx_bytes,
            );
            if !endpoint.is_empty() {
                self.direct.record_endpoint(&public_key, endpoint.clone());
            }
            // SEL-004：汇总候选端点详情（端点/RTT/丢包/当前选中与原因），
            // 供心跳上报 → console peer 详情渲染。
            let statuses = self.probe.candidate_statuses(&public_key, &endpoint);
            self.direct.record_candidates(&public_key, statuses);
        }
    }

    /// SEL-002：对每个已建立直连的对端评估迟滞闸，需要时漫游 endpoint。
    ///
    /// 只作用于 `direct` 状态的对端（`direct_pending` 尚未验证、`Relay` 无直连
    /// 链路，切换无意义）。`wg set endpoint` 失败只记日志——直连仍是增益，
    /// 保持当前 endpoint 下一周期再试；成功才记录切换事件（[`dial`] 追加）。
    fn apply_switch_decisions(&mut self) {
        if !self.dataplane.probe.enabled {
            return;
        }
        // 现路径候选（endpoint）解析 + 直连对端集合：只评估非 Relay。
        let statuses = self.direct.link_statuses();
        for status in statuses {
            if status.link_state != "direct" {
                continue;
            }
            let Some(current) = parse_endpoint_candidate(&status.endpoint) else {
                // 尚无已下发的直连 endpoint（异常态）：不切换。
                continue;
            };
            let Some(decision) = self
                .probe
                .evaluate_switch(&status.public_key, Some(current))
            else {
                continue;
            };
            if let Err(e) = self
                .backend
                .set_direct_endpoint_sync(&status.public_key, decision.to.socket())
            {
                tracing::warn!(
                    public_key = %status.public_key,
                    error = %e,
                    "direct endpoint switch failed; keeping current path"
                );
                continue;
            }
            let event = dial::SwitchEvent {
                public_key: status.public_key.clone(),
                from: status.endpoint.clone(),
                to: decision.to.socket().to_string(),
                reason: decision.reason.clone(),
                at_ms: dial::now_millis(),
            };
            if let Err(e) = dial::append_switch_event(Path::new(&self.state_dir), &event) {
                tracing::warn!(error = %e, "direct switch event not recorded");
            }
            tracing::info!(
                public_key = %status.public_key,
                from = %event.from,
                to = %event.to,
                reason = %event.reason,
                "direct endpoint switched (SEL-002)"
            );
            // 更新直连管理器记录的 endpoint（下一轮以此为现路径基准）。
            self.direct
                .record_endpoint(&status.public_key, event.to.clone());
        }
    }

    /// 持久化直连 keep set（§12 重启恢复）：失败只记日志——ledger 丢失顶多
    /// 多一个探测周期重建直连，绝不影响数据面循环。
    fn save_direct_ledger(&self) {
        if let Err(e) = self.direct.save(&self.direct_ledger) {
            tracing::warn!(
                error = %e,
                "direct ledger not written; keep set may be rebuilt on restart"
            );
        }
    }

    /// 应用单个直连动作（`wg set`）：失败只记日志——直连是增益，绝不回滚
    /// hub（对端仍按 hub 整段路由可达）。成功时记录/清空对端 endpoint
    /// （§12.3 状态上报与控制台/CLI 直连 peers 展示的数据源）。
    fn apply_direct_update(&mut self, update: &DirectUpdate) {
        match update {
            DirectUpdate::Promote {
                public_key,
                allowed_ips,
                endpoint,
            } => {
                if let Err(e) = self.backend.set_direct_peer_sync(
                    public_key,
                    allowed_ips,
                    *endpoint,
                    keepalive_secs(),
                ) {
                    tracing::warn!(
                        public_key = %public_key,
                        error = %e,
                        "direct promote failed; keeping hub relay"
                    );
                } else {
                    tracing::info!(
                        public_key = %public_key,
                        endpoint = %endpoint,
                        "direct link promoted"
                    );
                    self.direct
                        .record_endpoint(public_key, endpoint.to_string());
                }
            }
            DirectUpdate::Demote { public_key } => {
                if let Err(e) = self.backend.remove_peer_sync(public_key) {
                    tracing::warn!(
                        public_key = %public_key,
                        error = %e,
                        "direct demote failed; hub relay already covers this peer"
                    );
                } else {
                    tracing::info!(public_key = %public_key, "direct link demoted to hub relay");
                    self.direct.clear_endpoint(public_key);
                }
            }
        }
    }

    /// 心跳上报（§12.4/§14.1）：带本地读到的最近握手时间 + 数据面实测证据
    /// （§7.5：内核读数 + 计划 MTU 大包探测）+ P2P 直连候选端点（§12）。
    pub fn heartbeat(&self, plan: Option<&DevicePlan>) -> Result<(), String> {
        let evidence = self.collect_evidence(plan);
        let direct = self.direct_report();
        // §12.3：随心跳上报各对端直连链路状态（P2P/中继），供控制台展示。
        // 状态是最近一次 30s 探测的结果——心跳比探测密，上报的是最后已知态。
        let direct_links = self.direct.link_statuses();
        // R-DIAG：随心跳上报本地网络诊断三快照（路由表/接口/wg 读数）。采集
        // 失败按 `None` 上报（服务端与控制台显示"无快照"，证据缺失可见），
        // 绝不吞掉心跳本身。
        let diagnostics = self.backend.diagnostics_sync().ok();
        server::heartbeat(
            &self.server_url,
            &self.token,
            self.last_handshake(),
            Some(evidence),
            direct,
            direct_links,
            diagnostics,
            crate::ssh_sync::local_hostname(),
        )
        .map(|_| ())
        .map_err(|e| format!("heartbeat failed: {e}"))
    }

    /// §12 P2P：本机直连候选端点（WireGuard 监听端口 + RFC1918 局域网地址）。
    /// 未开启直连时返回 `None`（上报省略，服务端按未上报处理）；LAN 枚举
    /// 失败只记空候选，不吞掉心跳本身。
    pub fn direct_report(&self) -> Option<DirectEndpointReport> {
        direct_report_from(
            &self.dataplane.direct_connect,
            self.backend.lan_addresses_sync().unwrap_or_default(),
        )
    }

    /// §12.3：本设备当前各对端直连链路状态（供心跳上报与诊断导出）。
    /// 空 = 全中继（无直连链路）。状态是最近一次 30s 探测的结果。
    pub fn direct_link_statuses(&self) -> Vec<DirectLinkStatus> {
        self.direct.link_statuses()
    }

    /// 数据面实测证据（§7.5）：内核读数 + 大包探测。读数失败按 `None` 上报
    /// （证据缺失可见），绝不臆测默认值——探测失败与未探测在服务端同形，
    /// 都按「未证实」处理。
    pub fn collect_evidence(&self, plan: Option<&DevicePlan>) -> DataplaneEvidence {
        let snapshot = self.backend.inspect_sync().ok();
        DataplaneEvidence {
            tunnel_mtu: snapshot.as_ref().and_then(|s| s.tunnel_mtu),
            // 证据口径不变（布尔），但从规则指纹集合推导：指纹里出现受控 SNAT
            // 动作即「SNAT 规则在场」，比单独枚举 POSTROUTING 链更贴近语义。
            nat_rules_present: snapshot.as_ref().map(|s| !s.nat_rules.is_empty()),
            nat_snat_rules_present: snapshot.as_ref().map(|s| {
                s.nat_rules
                    .iter()
                    .any(|signature| signature.contains("|snat_to_gateway_lan|"))
            }),
            mtu_probe_payload: plan.and_then(|p| {
                // 底层 MTU 只读一次（lane/dataplane-speed）：默认路由接口的
                // MTU 让未钉计划时的探测载荷自适应 jumbo/PPPoE 底层；读不到
                // 回退默认尺寸，不臆测。
                let underlay = self.backend.underlay_path_mtu_sync();
                let (target, payload) = probe_decision(p, underlay)?;
                self.backend
                    .mtu_probe_sync(target, payload)
                    .then_some(payload)
            }),
        }
    }

    /// `wg show <if> latest-handshakes` → 最近握手时刻（ISO-8601）；取不到则
    /// 省略（服务端按「未取到」处理，不虚构在线证据）。
    fn last_handshake(&self) -> Option<String> {
        let out = std::process::Command::new("wg")
            .args(["show", &self.dataplane.interface, "latest-handshakes"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let ts: i64 = text
            .split_whitespace()
            .filter_map(|t| t.parse().ok())
            .filter(|t| *t > 0)
            .max()?;
        chrono::DateTime::from_timestamp(ts, 0).map(|d| d.to_rfc3339())
    }
}

/// 直连 keep set 持久化路径（与 `applied.json` 同目录；§12 重启恢复）。
fn direct_ledger_path(state_dir: &str) -> std::path::PathBuf {
    Path::new(state_dir).join("direct.json")
}

/// MT-002 任务账本路径（`{state_dir}/tasks.json`）。
fn task_ledger_path(state_dir: &str) -> std::path::PathBuf {
    Path::new(state_dir).join("tasks.json")
}

/// §12：本设备可路由网段 = hub peer 的 AllowedIPs 中**包含本设备 overlay
/// 地址**的那条。分段网络时 hub peer 有多条 AllowedIPs 且 `normalize` 排序
/// 不保证（`allowed_ips[0]` 不一定是所属段），包含关系才是唯一可靠判据；
/// 与 `peer_endpoints_for` 的 scope 推导同一口径。取不到（无 hub peer /
/// 地址越出所有段）返回 `None`——无法安全下发 `/32`，保持 hub 中继。
/// 本设备可路由网段（直连 AllowedIPs `/32` 的冲突边界）：hub peer 的
/// AllowedIPs 里**最长前缀**且包含本机 overlay 地址的 CIDR。多段重叠时
/// 最具体的才是本机自己的段（宽段可能覆盖其他段）。
fn direct_scope(plan: &DevicePlan) -> Option<Ipv4Cidr> {
    plan.tunnel
        .peers
        .iter()
        .flat_map(|peer| peer.allowed_ips.iter().copied())
        .filter(|cidr| cidr.contains(plan.tunnel.address))
        .max_by_key(|cidr| cidr.prefix_len())
}

/// 本设备私钥（ADR-010：只在本机文件里，服务端永不携带；未配置则保留接口现有私钥）。
pub fn read_private_key(dp: &DataplaneConfig) -> Result<Option<String>, String> {
    let Some(path) = dp
        .private_key_file
        .as_deref()
        .filter(|p| !p.trim().is_empty())
    else {
        return Ok(None);
    };
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("read private_key_file {path}: {e}"))?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        return Err(format!("private_key_file {path} is empty"));
    }
    Ok(Some(key))
}

/// 大包探测决策（纯逻辑）：目标 = hub 的 overlay 地址（自 ping 不经过隧道，
/// 证据失真，跳过）；载荷 = 有效 MTU − 28B（IP 头 20B + ICMP 头 8B）。hub
/// 未知或载荷为 0 则不探测。计划未配置 MTU 时按底层接口 MTU 自适应
/// （lane/dataplane-speed）：1500 以太网推导回 1420（行为不变），jumbo/PPPoE
/// 底层推导出贴合真路径的载荷；底层读数不可得回退 WireGuard 默认。计划显式
/// 钉 MTU 时计划优先——内核权威始终是服务端计划，自适应只作用于探测证据。
fn probe_decision(plan: &DevicePlan, underlay_mtu: Option<u32>) -> Option<(Ipv4Addr, u32)> {
    let hub = plan.hub_address.filter(|h| *h != plan.tunnel.address)?;
    let effective = plan.tunnel.mtu.unwrap_or_else(|| {
        underlay_mtu.map_or(DEFAULT_TUNNEL_MTU, meshlet_network::derive_tunnel_mtu)
    });
    let payload = effective.saturating_sub(28);
    (payload > 0).then_some((hub, payload))
}

/// §12 P2P 直连候选（纯逻辑）：未开启直连 → `None`（上报省略）；开启则携带
/// WireGuard 监听端口与枚举到的 RFC1918 局域网地址（可为空，空候选仍合法——
/// 对端仍可尝试公网观测地址）。
fn direct_report_from(
    direct_connect: &DirectConnectConfig,
    lan_addrs: Vec<Ipv4Addr>,
) -> Option<DirectEndpointReport> {
    if !direct_connect.enabled {
        return None;
    }
    Some(DirectEndpointReport {
        listen_port: direct_connect.listen_port,
        lan_addrs,
    })
}

/// SEL-002：从直连端点字符串（`ip:port`）解析候选。无法解析（空 / 畸形）→
/// `None`（调用方按「无已下发直连候选」处理，不切换）。
fn parse_endpoint_candidate(endpoint: &str) -> Option<EndpointCandidate> {
    let (ip, port) = endpoint.rsplit_once(':')?;
    let ip = ip.parse::<Ipv4Addr>().ok()?;
    let port = port.parse::<u16>().ok()?;
    // 分类未知（端点字符串不携带 kind）：按私网判定，仅用于迟滞闸的
    // `current` 匹配——候选窗口按 (ip,port) 键匹配，kind 不影响相等判定
    // 之外的行为（EndpointCandidate 的 Ord 含 kind，但候选集来自同源，同
    // ip:port 的 kind 一致）。
    let kind = if meshlet_domain::is_private_ip(ip) {
        meshlet_domain::EndpointKind::Lan
    } else {
        meshlet_domain::EndpointKind::Public
    };
    Some(EndpointCandidate { ip, port, kind })
}

/// 诊断 dump → 握手年龄（纯函数）：`wg dump` 每 peer 的最近握手 Unix 秒翻译
/// 成「距今秒」。`last_handshake <= 0`（从未握手）或晚于当前时钟（时钟回拨）
/// 的行丢弃——证据缺失不臆造。
fn dump_handshake_ages(net: Option<&NetworkDiagnostics>, now_secs: u64) -> BTreeMap<String, u64> {
    let Some(net) = net else {
        return BTreeMap::new();
    };
    net.wg
        .iter()
        .filter(|p| p.last_handshake > 0 && p.last_handshake <= now_secs)
        .map(|p| (p.public_key.clone(), now_secs - p.last_handshake))
        .collect()
}

/// rtt_source 如实标注（纯函数，四态）：
/// - 实测成功（`probe_ok`）：RTT 有读数，来源就是实测；
/// - 没测到读数但**最近握手新鲜**（≤ [`meshlet_domain::DIRECT_PROMOTE_FRESH_SECS`]）
///   → `handshake_fresh`：活性证据是握手不是 ping——Windows 网格防火墙对
///   wg 接口 ICMP 100% 丢包（imac 2026-11-07 取证），「不可测」谎报成链路
///   结论会误导；
/// - 其余（两路均无响应且握手也不新鲜 / 读数缺失且无握手）→ 探测线程的如实
///   结论（`probe_failed` / `unprobed`）。
fn honest_rtt_source(
    probe: &RttProbe,
    last_handshake_at: Option<u64>,
    now_secs: u64,
) -> Option<&'static str> {
    if probe.rtt_ms.is_some() {
        return Some("probe_ok");
    }
    if last_handshake_at.is_some_and(|ts| {
        ts > 0 && ts <= now_secs && now_secs - ts <= meshlet_domain::DIRECT_PROMOTE_FRESH_SECS
    }) {
        return Some("handshake_fresh");
    }
    Some(probe.source.as_str())
}

/// hub 入口地址兜底（纯逻辑，§16.4）：服务端不知道 agent 的网络位置，计划里
/// hub peer 的 endpoint 为 `None`；agent 用本地 `[dataplane] hub_endpoint`
///（`host:port`）填充，设备才能主动发起握手。服务端已带值（未来通告
/// advertise endpoint）则尊重服务端，不覆盖；未配置兜底则原样返回。
fn plan_with_hub_endpoint(plan: &DevicePlan, hub_endpoint: Option<&str>) -> DevicePlan {
    let mut local = plan.clone();
    if let (Some(endpoint), Some(peer)) = (hub_endpoint, local.tunnel.peers.first_mut()) {
        if peer.endpoint.is_none() {
            peer.endpoint = Some(match plan.hub_port {
                Some(port) => endpoint
                    .rsplit_once(':')
                    .map(|(host, _)| format!("{host}:{port}"))
                    .unwrap_or_else(|| format!("{endpoint}:{port}")),
                None => endpoint.to_string(),
            });
        }
    }
    local
}

/// SEL-003 hub 兜底：hub peer（隧道配置第一个 peer，即服务端计划的 hub）的
/// persistent-keepalive 强制 ≥ [meshlet_network::HUB_KEEPALIVE_SECS]，让 hub 永不
/// 掉（NAT 映射常开，直连回退后随时可回）。计划显式给更高值则尊重。
fn enforce_hub_keepalive(plan: &mut DevicePlan) {
    if let Some(peer) = plan.tunnel.peers.first_mut() {
        let floor = meshlet_network::HUB_KEEPALIVE_SECS;
        if peer.persistent_keepalive_secs.unwrap_or(0) < floor {
            peer.persistent_keepalive_secs = Some(floor);
        }
    }
}

/// `peer dial` 结果判定（纯函数，可测）：目标对端当前状态 → (ok, mode, message)。
/// `None` = 对端不在管（本周期候选集外）——按失败呈现，绝不假装成功。
fn dial_verdict(status: Option<&crate::direct::DirectPeer>) -> (bool, &'static str, &'static str) {
    match status {
        Some(peer) => match peer.state {
            PeerLinkState::Direct => (true, "p2p_direct", "direct link established"),
            PeerLinkState::DirectPending { .. } => {
                (true, "direct_pending", "dial initiated, awaiting handshake")
            }
            PeerLinkState::Relay => (false, "hub_relay", "no direct path; keeping hub relay"),
        },
        None => (false, "hub_relay", "node is not a direct candidate"),
    }
}

/// 候选集 + 链路状态 → 直连对端视图（纯函数，可测）。候选已直连/待握手取
/// 链路状态；候选无路径（不在链路状态里）标 `hub_relay`（可拨号目标）。
fn direct_peer_views(
    wanted: &[meshlet_domain::PeerEndpoints],
    links: &[DirectLinkStatus],
) -> Vec<DirectPeerView> {
    let by_key: BTreeMap<&str, &DirectLinkStatus> =
        links.iter().map(|l| (l.public_key.as_str(), l)).collect();
    wanted
        .iter()
        .map(|c| {
            let link = by_key.get(c.public_key.as_str());
            DirectPeerView {
                name: c.name.clone(),
                virtual_ipv4: c.virtual_ipv4,
                public_key: c.public_key.clone(),
                mode: link
                    .map(|l| l.connection_mode.clone())
                    .unwrap_or_else(|| "hub_relay".into()),
                rtt_ms: link.and_then(|l| l.rtt_ms),
                rtt_source: link.and_then(|l| l.rtt_source.clone()),
                endpoint: link.map(|l| l.endpoint.clone()).unwrap_or_default(),
                last_handshake_at: link.and_then(|l| l.last_handshake_at),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(state_dir: &str) -> AgentConfig {
        AgentConfig {
            server_url: "http://127.0.0.1:1".into(),
            state_dir: state_dir.into(),
            device_token: Some("tok".into()),
            bootstrap_token: None,
            device_name: None,
            tray: TrayConfig::OFF,
            upgrade: meshlet_config::UpgradeConfig::default(),
            dataplane: DataplaneConfig {
                enabled: true,
                ..DataplaneConfig::default()
            },
            ssh_config_sync: meshlet_config::SshConfigSyncConfig::OFF,
        }
    }

    #[test]
    fn private_key_is_read_trimmed_and_absent_is_ok() {
        // 未配置私钥：None（保留接口现有私钥，幂等重放）。
        assert_eq!(read_private_key(&DataplaneConfig::default()).unwrap(), None);

        let dir = std::env::temp_dir().join("meshlet-agent-key-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dev.key");
        std::fs::write(&path, "key-material\n").unwrap();
        let dp = DataplaneConfig {
            private_key_file: Some(path.to_string_lossy().to_string()),
            ..DataplaneConfig::default()
        };
        assert_eq!(
            read_private_key(&dp).unwrap().as_deref(),
            Some("key-material")
        );

        // 空文件：明确报错，不当“没配”处理（首装必然握手失败）。
        std::fs::write(&path, "\n").unwrap();
        assert!(read_private_key(&dp).is_err());

        // 缺失文件：路径写错必须可见。
        let missing = DataplaneConfig {
            private_key_file: Some("/nonexistent/meshlet/dev.key".into()),
            ..DataplaneConfig::default()
        };
        assert!(read_private_key(&missing).is_err());

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn state_path_lives_under_the_configured_state_dir() {
        let agent = Agent::new(config("/var/lib/meshlet"), None);
        assert_eq!(
            agent.state_path(),
            Path::new("/var/lib/meshlet/applied.json")
        );
    }

    #[test]
    fn heartbeat_against_a_dead_server_fails_visibly() {
        // 拉不到服务端时报错（可见），而不是静默「成功」——tick 据此退避重试。
        let agent = Agent::new(config("/tmp/meshlet-agent-dead"), None);
        let err = agent.heartbeat(None).expect_err("dead server");
        assert!(!err.is_empty(), "failure must be reported: {err}");
    }

    fn probe_plan(mtu: Option<u32>, hub: Option<&str>, own: &str) -> DevicePlan {
        DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: meshlet_network::TunnelConfig {
                name: "wg0".into(),
                address: own.parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![],
                mtu,
                private_key: None,
            },
            routes: vec![],
            nat_rules: vec![],
            hub_address: hub.map(|h| h.parse().unwrap()),
            publish: None,
            ssh_config: None,
            desired_config_hash: "hash".into(),
        }
    }

    #[test]
    fn hub_endpoint_fills_a_plan_without_one() {
        // 服务端计划不携带 endpoint（§16.4：服务端不知道 agent 的网络位置）。
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        p.tunnel.peers.push(meshlet_network::PeerConfig {
            public_key: "hub-pub".into(),
            allowed_ips: vec!["10.240.0.0/16".parse().unwrap()],
            endpoint: None,
            persistent_keepalive_secs: None,
        });

        // 本地兜底填充 → 设备可主动发起握手。
        let filled = plan_with_hub_endpoint(&p, Some("10.98.0.10:51820"));
        assert_eq!(
            filled.tunnel.peers[0].endpoint.as_deref(),
            Some("10.98.0.10:51820")
        );
        // 哈希不被本地兜底改写：账本与漂移判定仍以服务端期望为准。
        assert_eq!(filled.desired_config_hash, p.desired_config_hash);

        // 服务端已带值（未来通告 advertise endpoint）→ 尊重服务端，不覆盖。
        let mut explicit = p.clone();
        explicit.tunnel.peers[0].endpoint = Some("10.98.0.99:51820".into());
        assert_eq!(
            plan_with_hub_endpoint(&explicit, Some("10.98.0.10:51820"))
                .tunnel
                .peers[0]
                .endpoint,
            explicit.tunnel.peers[0].endpoint
        );

        // 未配置兜底 → 原样返回；空 peer 计划不越界。
        assert_eq!(
            plan_with_hub_endpoint(&p, None).tunnel.peers[0].endpoint,
            None
        );
        let empty = probe_plan(None, None, "10.240.0.7");
        assert_eq!(
            plan_with_hub_endpoint(&empty, Some("10.98.0.10:51820"))
                .tunnel
                .peers
                .len(),
            0
        );
    }

    #[test]
    fn probe_decision_targets_the_hub_with_the_planned_payload() {
        let p = probe_plan(Some(1380), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, None),
            Some(("10.240.0.1".parse().unwrap(), 1352))
        );

        // 计划未配置 MTU：按默认 1420 探测（1420 − 28 = 1392）。
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, None),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );

        // hub 未知 / hub 就是自己（自 ping 不经过隧道）/ 载荷为 0：不探测。
        let p = probe_plan(Some(1380), None, "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
        let p = probe_plan(Some(1380), Some("10.240.0.7"), "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
        let p = probe_plan(Some(28), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(probe_decision(&p, None), None);
    }

    /// rtt_source 如实四态：实测成功 probe_ok；不可测但握手新鲜 handshake_fresh
    /// （「不可测」不再谎报链路结论）；握手不新鲜 probe_failed；没轮到 unprobed。
    #[test]
    fn rtt_source_is_honest_about_handshake_evidence() {
        let now = 1_800_000_000u64;
        // 实测成功：无论握手状态，来源都是 probe_ok。
        assert_eq!(
            honest_rtt_source(
                &RttProbe {
                    rtt_ms: Some(12),
                    source: crate::direct_rtt::RttSource::Overlay
                },
                None,
                now
            ),
            Some("probe_ok")
        );
        // 不可测（两路 ping 全静默）+ 握手新鲜 → handshake_fresh（链路活着）。
        assert_eq!(
            honest_rtt_source(
                &RttProbe {
                    rtt_ms: None,
                    source: crate::direct_rtt::RttSource::Unreachable
                },
                Some(now - meshlet_domain::DIRECT_PROMOTE_FRESH_SECS),
                now
            ),
            Some("handshake_fresh")
        );
        // 不可测 + 握手超过晋升阈值 → 如实 probe_failed（不再谎报「不可测=活着」）。
        assert_eq!(
            honest_rtt_source(
                &RttProbe {
                    rtt_ms: None,
                    source: crate::direct_rtt::RttSource::Unreachable
                },
                Some(now - meshlet_domain::DIRECT_PROMOTE_FRESH_SECS - 1),
                now
            ),
            Some("probe_failed")
        );
        // 没轮到（探测在途）+ 无握手 → unprobed（不是结论）。
        assert_eq!(
            honest_rtt_source(&RttProbe::unknown(), None, now),
            Some("unprobed")
        );
        // 从未握手（ts=0）不算新鲜证据。
        assert_eq!(
            honest_rtt_source(&RttProbe::unknown(), Some(0), now),
            Some("unprobed")
        );
    }

    /// 诊断 dump → 握手年龄：从未握手 / 时钟回拨的行丢弃，其余翻译成距今秒。
    #[test]
    fn dump_handshake_ages_skips_never_handshaked_and_future_timestamps() {
        let now = 1_800_000_000u64;
        let net = NetworkDiagnostics {
            collected_at: None,
            route_table: vec![],
            interfaces: vec![],
            wg: vec![
                meshlet_network::WgPeerDiagnostic {
                    public_key: "fresh".into(),
                    last_handshake: now - 42,
                    ..Default::default()
                },
                meshlet_network::WgPeerDiagnostic {
                    public_key: "never".into(),
                    last_handshake: 0,
                    ..Default::default()
                },
                meshlet_network::WgPeerDiagnostic {
                    public_key: "clock-skew".into(),
                    last_handshake: now + 10,
                    ..Default::default()
                },
            ],
        };
        let ages = dump_handshake_ages(Some(&net), now);
        assert_eq!(ages.len(), 1);
        assert_eq!(ages.get("fresh"), Some(&42));
        // 无快照 → 空（证据缺失不臆造）。
        assert!(dump_handshake_ages(None, now).is_empty());
    }

    #[test]
    fn probe_payload_adapts_to_the_underlay_when_plan_leaves_mtu_unset() {
        // 计划钉 MTU：计划优先，底层读数不影响探测载荷。
        let p = probe_plan(Some(1380), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, Some(9000)),
            Some(("10.240.0.1".parse().unwrap(), 1352))
        );

        // 计划未配置：按底层 MTU 推导。1500 以太网推导回 1420（默认行为
        // 不变）；jumbo 9000 → 8920 − 28；PPPoE 1492 → 1412 − 28。
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p, Some(1500)),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );
        assert_eq!(
            probe_decision(&p, Some(9000)),
            Some(("10.240.0.1".parse().unwrap(), 8892))
        );
        assert_eq!(
            probe_decision(&p, Some(1492)),
            Some(("10.240.0.1".parse().unwrap(), 1384))
        );

        // 底层读数不可得：回退 WireGuard 默认（行为与旧版一致）。
        assert_eq!(
            probe_decision(&p, None),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );
    }

    #[test]
    fn direct_scope_is_the_allowed_cidr_that_contains_own_address() {
        let hub = |allowed: &[&str]| meshlet_network::PeerConfig {
            public_key: "hub-pub".into(),
            allowed_ips: allowed.iter().map(|s| s.parse().unwrap()).collect(),
            endpoint: None,
            persistent_keepalive_secs: None,
        };

        // 单段：唯一 AllowedIPs 即 scope。
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.0.2");
        p.tunnel.peers.push(hub(&["10.240.0.0/16"]));
        assert_eq!(
            direct_scope(&p),
            Some("10.240.0.0/16".parse::<Ipv4Cidr>().unwrap())
        );

        // 分段路由：AllowedIPs 多条且排序不保证——包含自身地址的那条才是 scope
        //（不是 `allowed_ips[0]`）。
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.240.1.2");
        p.tunnel
            .peers
            .push(hub(&["10.240.0.0/16", "10.240.1.0/24"]));
        assert_eq!(
            direct_scope(&p),
            Some("10.240.1.0/24".parse::<Ipv4Cidr>().unwrap())
        );

        // 无 hub peer / 自身地址越出所有段：None（保持 hub 中继，不猜）。
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.2");
        assert_eq!(direct_scope(&p), None);
        let mut p = probe_plan(None, Some("10.240.0.1"), "10.250.0.2");
        p.tunnel.peers.push(hub(&["10.240.0.0/16"]));
        assert_eq!(direct_scope(&p), None);
    }

    #[test]
    fn direct_report_gates_on_enabled_and_carries_port() {
        let on = DirectConnectConfig {
            enabled: true,
            listen_port: 51820,
        };
        let report =
            direct_report_from(&on, vec!["192.168.1.50".parse().unwrap()]).expect("enabled");
        assert_eq!(report.listen_port, 51820);
        assert_eq!(
            report.lan_addrs,
            vec!["192.168.1.50".parse::<Ipv4Addr>().unwrap()]
        );

        // 空候选仍合法（对端可尝试公网观测地址）。
        let report = direct_report_from(&on, vec![]).expect("empty candidates");
        assert!(report.lan_addrs.is_empty());

        // 未开启直连：上报省略（None），不伪造端点。
        let off = DirectConnectConfig {
            enabled: false,
            listen_port: 51820,
        };
        assert_eq!(direct_report_from(&off, vec![]), None);
    }

    #[test]
    fn pending_receipt_queue_is_bounded_at_sixteen() {
        let root = std::env::temp_dir().join(format!(
            "meshlet-agent-receipt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let mut agent =
            Agent::with_backend(config(root.to_str().unwrap()), None, SystemBackend::new());
        let plan = DevicePlan {
            desired_revision: 1,
            hub_port: None,
            tunnel: meshlet_network::TunnelConfig {
                name: "wg0".into(),
                address: "127.0.0.1".parse().unwrap(),
                address_prefix: 32,
                listen_port: None,
                peers: Vec::new(),
                mtu: None,
                private_key: Some("private".into()),
            },
            routes: Vec::new(),
            nat_rules: Vec::new(),
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: "hash".into(),
        };
        for index in 0..17 {
            agent.enqueue_receipt(plan.clone(), Some(format!("error {index}")));
        }
        assert_eq!(agent.pending_receipts.len(), 16);
        assert_eq!(
            agent
                .pending_receipts
                .front()
                .and_then(|receipt| receipt.error.as_deref()),
            Some("error 1")
        );
        assert_eq!(
            agent
                .pending_receipts
                .back()
                .and_then(|receipt| receipt.error.as_deref()),
            Some("error 16")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// `peer dial` 结果判定：Direct/Pending = 成功；Relay/不在管 = 失败（绝不
    /// 假装成功）。
    #[test]
    fn dial_verdict_maps_state_to_success_or_failure() {
        use crate::direct::DirectPeer;
        let peer = |state| DirectPeer {
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            state,
            last_handshake_age_secs: None,
            peer_name: String::new(),
            endpoint: String::new(),
            rtt_ms: None,
            rtt_source: None,
            last_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
            candidates: vec![],
        };
        let (ok, mode, _) = dial_verdict(Some(&peer(PeerLinkState::Direct)));
        assert!(ok);
        assert_eq!(mode, "p2p_direct");
        let (ok, mode, _) = dial_verdict(Some(&peer(PeerLinkState::DirectPending { attempts: 1 })));
        assert!(ok);
        assert_eq!(mode, "direct_pending");
        let (ok, mode, _) = dial_verdict(Some(&peer(PeerLinkState::Relay)));
        assert!(!ok);
        assert_eq!(mode, "hub_relay");
        let (ok, mode, _) = dial_verdict(None);
        assert!(!ok);
        assert_eq!(mode, "hub_relay");
    }

    /// 直连对端视图合并：候选已直连/待握手取链路状态；候选无路径标
    /// `hub_relay`（可拨号）；候选集外但链路在管的对端不进视图（候选集为
    /// 服务端下发的可直连集合，视图只反映它）。
    #[test]
    fn direct_peer_views_merges_candidates_with_link_status() {
        use meshlet_domain::EndpointCandidate;
        let wanted = vec![
            meshlet_domain::PeerEndpoints {
                device_id: meshlet_domain::DeviceId("a".into()),
                public_key: "key-a".into(),
                virtual_ipv4: "10.240.0.3".parse().unwrap(),
                name: "peer-a".into(),
                endpoints: vec![EndpointCandidate::lan(
                    "192.168.1.50".parse().unwrap(),
                    51821,
                )],
            },
            meshlet_domain::PeerEndpoints {
                device_id: meshlet_domain::DeviceId("b".into()),
                public_key: "key-b".into(),
                virtual_ipv4: "10.240.0.4".parse().unwrap(),
                name: "peer-b".into(),
                endpoints: vec![EndpointCandidate::lan(
                    "192.168.1.60".parse().unwrap(),
                    51821,
                )],
            },
        ];
        let links = vec![DirectLinkStatus {
            public_key: "key-a".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            link_state: "direct".into(),
            last_handshake_age_secs: Some(7),
            peer_name: "peer-a".into(),
            connection_mode: "p2p_direct".into(),
            endpoint: "192.168.1.50:51821".into(),
            rtt_ms: Some(5),
            rtt_source: Some("overlay".into()),
            last_handshake_at: Some(1_700_000_000),
            rx_bytes: 0,
            tx_bytes: 0,
            candidates: vec![],
        }];
        let views = direct_peer_views(&wanted, &links);
        assert_eq!(views.len(), 2);
        // 已直连：取链路状态（mode/rtt/endpoint）。
        let a = views.iter().find(|v| v.public_key == "key-a").unwrap();
        assert_eq!(a.mode, "p2p_direct");
        assert_eq!(a.rtt_ms, Some(5));
        assert_eq!(a.endpoint, "192.168.1.50:51821");
        // 候选无路径：标 hub_relay（可拨号目标）。
        let b = views.iter().find(|v| v.public_key == "key-b").unwrap();
        assert_eq!(b.mode, "hub_relay");
        assert_eq!(b.rtt_ms, None);
        assert_eq!(b.endpoint, "");
    }

    #[test]
    fn parse_endpoint_candidate_reads_ip_port_and_kind() {
        use meshlet_domain::EndpointKind;
        // 私网 → Lan；畸形/空 → None。
        let lan = parse_endpoint_candidate("192.168.1.50:51821").expect("lan parses");
        assert_eq!(lan.ip, "192.168.1.50".parse::<Ipv4Addr>().unwrap());
        assert_eq!(lan.port, 51821);
        assert_eq!(lan.kind, EndpointKind::Lan);
        let public = parse_endpoint_candidate("203.0.113.10:51820").expect("public parses");
        assert_eq!(public.kind, EndpointKind::Public);
        assert!(parse_endpoint_candidate("").is_none());
        assert!(parse_endpoint_candidate("192.168.1.50").is_none());
        assert!(parse_endpoint_candidate("not-an-ip:51821").is_none());
        assert!(parse_endpoint_candidate("192.168.1.50:99999").is_none());
    }

    #[test]
    fn enforce_hub_keepalive_raises_none_or_low_to_floor() {
        use meshlet_network::PeerConfig;
        use meshlet_network::TunnelConfig;
        let mk = |ka: Option<u32>| DevicePlan {
            desired_revision: 0,
            hub_port: None,
            tunnel: TunnelConfig {
                name: "wg0".into(),
                address: "10.240.0.7".parse().unwrap(),
                address_prefix: 16,
                listen_port: None,
                peers: vec![PeerConfig {
                    public_key: "hub-pub".into(),
                    allowed_ips: vec![],
                    endpoint: None,
                    persistent_keepalive_secs: ka,
                }],
                mtu: None,
                private_key: None,
            },
            routes: vec![],
            nat_rules: vec![],
            hub_address: None,
            publish: None,
            ssh_config: None,
            desired_config_hash: "h".into(),
        };
        // 旧版计划缺省 None → 抬到 floor。
        let mut plan = mk(None);
        enforce_hub_keepalive(&mut plan);
        assert_eq!(
            plan.tunnel.peers[0].persistent_keepalive_secs,
            Some(meshlet_network::HUB_KEEPALIVE_SECS)
        );
        // 计划给低于 floor 的值 → 抬到 floor。
        let mut plan = mk(Some(5));
        enforce_hub_keepalive(&mut plan);
        assert_eq!(
            plan.tunnel.peers[0].persistent_keepalive_secs,
            Some(meshlet_network::HUB_KEEPALIVE_SECS)
        );
        // 计划给更高值 → 尊重（永不掉）。
        let mut plan = mk(Some(30));
        enforce_hub_keepalive(&mut plan);
        assert_eq!(plan.tunnel.peers[0].persistent_keepalive_secs, Some(30));
        // 空 peer 列表 → no-op。
        let mut plan = mk(None);
        plan.tunnel.peers.clear();
        enforce_hub_keepalive(&mut plan);
        assert!(plan.tunnel.peers.is_empty());
    }
}
