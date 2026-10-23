//! Agent 主体：拉计划 → 对账 → 应用 → 心跳，循环之。
//!
//! 一切内核操作都经 [`meshlet_network::SystemBackend`]（ADR-007；非 Linux
//! 平台为 ADR-008 的明确 Unsupported 占位，每个操作失败可见）：
//! 本模块只负责**何时**调用它与**喂什么配置**（计划来自 server，绝非本地拼装
//! 的 Shell 命令，§16.4）。

use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use meshlet_config::{AgentConfig, DataplaneConfig};
use meshlet_domain::DataplaneEvidence;
use meshlet_network::{DevicePlan, SystemBackend, DEFAULT_TUNNEL_MTU};
use meshlet_publish::{ProbeReport, PublishPlan, Publisher};

#[cfg(target_os = "linux")]
use crate::dbus::DesktopClient;
use crate::desktop::{desktop_trigger, DesktopPublish, DesktopTrigger};
#[cfg(not(target_os = "linux"))]
use crate::desktop_unsupported::DesktopClient;
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
                // 的对位），不用「在线」误导。
                self.publish_tray(TrayState::Offline);
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
        // 托盘态：reason × 控制通道 × 隧道握手（映射依据见 [`crate::tray`]）。
        self.publish_tray(TrayState::derive(
            decision.reason,
            control_ok,
            self.last_handshake().is_some(),
        ));
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
    pub fn publish_tray(&self, state: TrayState) {
        let status = TrayStatus::new(
            state,
            self.device_name.as_deref(),
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
        let mut local_plan = plan_with_hub_endpoint(plan, self.dataplane.hub_endpoint.as_deref());
        local_plan.tunnel.name = self.dataplane.interface.clone();
        for route in &mut local_plan.routes {
            route.interface = self.dataplane.interface.clone();
        }
        for rule in &mut local_plan.nat_rules {
            if rule.incoming_interface.is_some() {
                rule.incoming_interface = Some(self.dataplane.interface.clone());
            }
        }
        local_plan.tunnel.private_key = self.private_key.clone();
        let mut decision = needs_apply(&state, &snapshot, plan);
        if !decision.needs_apply
            && !self
                .backend
                .device_plan_matches_sync(&local_plan)
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
        let transition =
            self.backend
                .apply_device_plan_sync(&local_plan, self.private_key.clone(), None);
        if let Err(error) = transition {
            return Err(self.fail_transition(
                last_good.as_ref(),
                format!("apply the desired plan: {error}"),
            ));
        }
        let matches = self
            .backend
            .device_plan_matches_sync(&local_plan)
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
                match self
                    .backend
                    .apply_device_plan_sync(last_good, self.private_key.clone(), None)
                {
                    Ok(()) => {
                        let restored = self
                            .backend
                            .device_plan_matches_sync(last_good)
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

    /// 心跳上报（§12.4/§14.1）：带本地读到的最近握手时间 + 数据面实测证据
    /// （§7.5：内核读数 + 计划 MTU 大包探测）。
    pub fn heartbeat(&self, plan: Option<&DevicePlan>) -> Result<(), String> {
        let evidence = self.collect_evidence(plan);
        server::heartbeat(
            &self.server_url,
            &self.token,
            self.last_handshake(),
            Some(evidence),
        )
        .map(|_| ())
        .map_err(|e| format!("heartbeat failed: {e}"))
    }

    /// 数据面实测证据（§7.5）：内核读数 + 大包探测。读数失败按 `None` 上报
    /// （证据缺失可见），绝不臆测默认值——探测失败与未探测在服务端同形，
    /// 都按「未证实」处理。
    pub fn collect_evidence(&self, plan: Option<&DevicePlan>) -> DataplaneEvidence {
        let snapshot = self.backend.inspect_sync().ok();
        DataplaneEvidence {
            tunnel_mtu: snapshot.as_ref().and_then(|s| s.tunnel_mtu),
            nat_rules_present: snapshot.as_ref().map(|s| s.nat_rules_present),
            nat_snat_rules_present: snapshot.as_ref().map(|s| s.nat_snat_rules_present),
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
}
