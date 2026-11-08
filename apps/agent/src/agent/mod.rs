//! Agent 主体：拉计划 → 对账 → 应用 → 心跳，循环之。
//!
//! 一切内核操作都经 [`meshlet_network::SystemBackend`]（ADR-007；非 Linux
//! 平台为 ADR-008 的明确 Unsupported 占位，每个操作失败可见）：
//! 本模块只负责**何时**调用它与**喂什么配置**（计划来自 server，绝非本地拼装
//! 的 Shell 命令，§16.4）。
mod direct;
mod direct_report;
pub(super) mod endpoint;
mod evidence;
pub(super) mod handshake;
mod heartbeat;
pub(super) mod paths;
pub(super) mod plan_adapter;
mod publish;
mod receipts;
pub(super) mod reconcile;
pub(super) mod rtt_source;
pub(super) mod scope;
mod ssh;
mod tasks;
mod tray;
pub(super) mod update;
pub(super) mod verdict;
pub(super) mod views;

use crate::agent::paths::{direct_ledger_path, task_ledger_path};
use crate::agent::publish::PublishRuntime;
use crate::agent::receipts::PendingReceipt;
pub use paths::read_private_key;

use std::path::Path;
use std::time::Duration;
use std::time::Instant;

use meshlet_config::{AgentConfig, DataplaneConfig};
use meshlet_network::probe::RecoveryGate;
use meshlet_network::SystemBackend;

#[cfg(target_os = "linux")]
use crate::dbus::DesktopClient;
use crate::desktop::DesktopPublish;
#[cfg(not(target_os = "linux"))]
use crate::desktop_unsupported::DesktopClient;
use crate::direct::DirectManager;
use crate::reconcile::state_path;
use crate::server;
use crate::tray::{TraySink, TrayState};
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
    /// MCP 本地服务（`[mcp] enabled`，默认关）：AI 客户端 loopback 查询本机
    /// mesh 事实。`None` = 未开启（不监听）。
    ///
    /// **持有即运行**：字段值从不被读，drop 时 `McpServer` 的 `Drop` 停服务
    /// 并清 `mcp.json`——故意不读，故 `#[allow(dead_code)]`。
    #[allow(dead_code)]
    mcp_server: Option<crate::mcp::McpServer>,
}

impl Agent {
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
        // MCP 本地服务：`[mcp] enabled` 默认关（不监听）；显式开启才起。
        // 绑定失败不致命——如实记录并继续（agent 不因 MCP 端口占用而退出）。
        let mcp_server = if config.mcp.enabled {
            match crate::mcp::start(std::path::Path::new(&config.state_dir), config.mcp.port) {
                Ok(server) => {
                    tracing::info!(
                        port = server.port(),
                        "mcp server started (AI can query this node)"
                    );
                    Some(server)
                }
                Err(e) => {
                    tracing::warn!(error = %e, "mcp server failed to start; AI query unavailable");
                    None
                }
            }
        } else {
            None
        };
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
            mcp_server,
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
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
