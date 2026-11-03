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
    DataplaneEvidence, DirectEndpointReport, DirectLinkStatus, Ipv4Cidr, DIRECT_PROBE_INTERVAL_SECS,
};
use meshlet_network::dial::{self, DirectDialRequest, DirectDialResult, DirectPeerView};
use meshlet_network::{DevicePlan, SystemBackend, DEFAULT_TUNNEL_MTU};
use meshlet_publish::{ProbeReport, PublishPlan, Publisher};

#[cfg(target_os = "linux")]
use crate::dbus::DesktopClient;
use crate::desktop::{desktop_trigger, DesktopPublish, DesktopTrigger};
#[cfg(not(target_os = "linux"))]
use crate::desktop_unsupported::DesktopClient;
use crate::direct::{keepalive_secs, DirectManager, DirectUpdate};
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
    /// MT-002 任务通道：已执行任务账本（`{state_dir}/tasks.json`，断线补派
    /// 据此补报、绝不重跑）。
    task_ledger: crate::tasks::TaskLedger,
    /// 任务账本持久化文件路径。
    task_ledger_path: std::path::PathBuf,
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
            task_ledger_path: task_ledger_path(&config.state_dir),
            task_ledger: crate::tasks::TaskLedger::load(&task_ledger_path(&config.state_dir)),
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

    /// MT-002 任务通道：拉取本设备待办并逐个 ack→执行→回执。失败只记日志
    /// （下轮重试），绝不打断数据面循环。
    fn process_tasks(&mut self) {
        // MT-004：任务到达（ack 后）触发托盘气泡。通知是尽力而为：与状态气泡
        // 一致尊重 `tray.notifications`（默认关），并在独立线程发送——D-Bus
        // 连接/调用可能阻塞（通知守护不响应），绝不拖住任务执行与数据面循环。
        let notify_enabled = self.desktop_config.notifications;
        let mut on_arrival = |task: &meshlet_domain::Task| {
            if !notify_enabled {
                return;
            }
            let call = crate::desktop::task_notify_call(&task.id.to_string(), &task.payload.cmd);
            std::thread::spawn(move || {
                let env = crate::tray::EnvProbe::from_env();
                let mut client = DesktopClient::default();
                let result = client.notify_task(&call, &env);
                if !matches!(result, DesktopPublish::Published) {
                    tracing::debug!(result = ?result, "task arrival not shown");
                }
            });
        };
        if let Err(e) = crate::tasks::process_pending(
            &self.server_url,
            &self.token,
            &mut self.task_ledger,
            &self.task_ledger_path,
            &mut on_arrival,
        ) {
            tracing::warn!(error = %e, "task processing deferred to next tick");
        }
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
        AgentState::from_plan(&ledger_plan).save(&self.state_path)?;
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
        let updates = self.direct.apply_plan(
            &wanted,
            &my_lan_subnets,
            scope,
            plan.tunnel.address,
            &handshake_ages,
        );
        if !updates.is_empty() {
            for update in &updates {
                self.apply_direct_update(update);
            }
            self.save_direct_ledger();
        }
        // R-DIAG-2：对处于直连状态的对端刷新读数（wg 端点/握手/流量）+ 实测
        // 直连路径 RTT——即使本周期无动作也要刷新，供心跳与控制台/CLI 展示。
        self.enrich_direct_peers();
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
    /// 累计流量）并对每条直连链路实测 RTT（`ping` 该对端 overlay 地址）。
    ///
    /// 读数失败只记日志——展示数据源是「最后已知态」，绝不让诊断采集干扰
    /// 数据面；对端已不在管（本周期被 Demote）则各 record_* no-op。
    fn enrich_direct_peers(&mut self) {
        let candidates = self.direct.direct_candidates();
        if candidates.is_empty() {
            return;
        }
        let net = match self.backend.diagnostics_sync() {
            Ok(net) => net,
            Err(e) => {
                tracing::warn!(error = %e, "direct enrich: diagnostics unavailable");
                return;
            }
        };
        for (public_key, vip) in candidates {
            let wg_peer = net.wg.iter().find(|p| p.public_key == public_key);
            let endpoint = wg_peer.map(|p| p.endpoint.clone()).unwrap_or_default();
            let last_handshake_at =
                wg_peer.and_then(|p| (p.last_handshake > 0).then_some(p.last_handshake));
            let (rx_bytes, tx_bytes) = wg_peer.map(|p| (p.rx_bytes, p.tx_bytes)).unwrap_or((0, 0));
            let rtt_ms = self
                .backend
                .ping_rtt_ms(vip)
                .map(|v| v.min(u64::MAX as u128) as u64);
            self.direct.record_peer_status(
                &public_key,
                rtt_ms,
                last_handshake_at,
                rx_bytes,
                tx_bytes,
            );
            if !endpoint.is_empty() {
                self.direct.record_endpoint(&public_key, endpoint);
            }
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
                let (target, payload) = probe_decision(p)?;
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
/// 证据失真，跳过）；载荷 = 计划 MTU − 28B（IP 头 20B + ICMP 头 8B），
/// 计划未配置 MTU 按默认 1420。hub 未知或载荷为 0 则不探测。
fn probe_decision(plan: &DevicePlan) -> Option<(Ipv4Addr, u32)> {
    let hub = plan.hub_address.filter(|h| *h != plan.tunnel.address)?;
    let payload = plan
        .tunnel
        .mtu
        .unwrap_or(DEFAULT_TUNNEL_MTU)
        .saturating_sub(28);
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
            probe_decision(&p),
            Some(("10.240.0.1".parse().unwrap(), 1352))
        );

        // 计划未配置 MTU：按默认 1420 探测（1420 − 28 = 1392）。
        let p = probe_plan(None, Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(
            probe_decision(&p),
            Some(("10.240.0.1".parse().unwrap(), 1392))
        );

        // hub 未知 / hub 就是自己（自 ping 不经过隧道）/ 载荷为 0：不探测。
        let p = probe_plan(Some(1380), None, "10.240.0.7");
        assert_eq!(probe_decision(&p), None);
        let p = probe_plan(Some(1380), Some("10.240.0.7"), "10.240.0.7");
        assert_eq!(probe_decision(&p), None);
        let p = probe_plan(Some(28), Some("10.240.0.1"), "10.240.0.7");
        assert_eq!(probe_decision(&p), None);
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
            last_handshake_at: None,
            rx_bytes: 0,
            tx_bytes: 0,
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
            last_handshake_at: Some(1_700_000_000),
            rx_bytes: 0,
            tx_bytes: 0,
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
}
