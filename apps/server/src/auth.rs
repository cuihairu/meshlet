//! 控制台认证：会话存储 + 认证/CSRF 提取器 + 登录/引导端点
//! （[存档 §11.4](../../docs/review/chatgpt-2026-10-13.md)、
//! [ADR-010](../../docs/decisions/adr-010-console-auth-enrollment.md)）。
//!
//! - 管理 API（网络/邀请/设备）handler 一律挂 `AuthenticatedUser`（Cookie 会话
//!   或 `mlt_` API Token Bearer，见 api_token.rs）与写请求的 `CsrfHeader` +
//!   `WriteUser`（会话恒放行；token 需 `write` scope）提取器；提取器只在命中
//!   路由后求值，未知路径保持 404；
//! - `/api/v1/enroll` 与 `/api/v1/system/status` 保持公开（enroll 自带邀请 Token 鉴权）；
//! - Cookie：HttpOnly + SameSite=Strict + Max-Age=会话 TTL；`Secure` 由配置决定
//!   （生产部署在 HTTPS 反代后置 true）；
//! - CSRF：Cookie 认证的管理端「写」请求必须携带 `X-Requested-With: XMLHttpRequest`
//!   （Console 前端约定），配合 SameSite=Strict 构成双重防线；
//! - 登录限流：进程内固定窗口（按 email 维度），成功登录即清零；
//! - **无默认管理员密码**：首个管理员只能经「空库 bootstrap」创建。

// 按职责分档：存储（store）/ 错误（error）/ Cookie·请求头·提取器·审计（extract）/
// DTO·会话·端点（endpoints）；本文件保留限流常量与 AppState。
mod endpoints;
mod error;
mod extract;
mod store;

pub use endpoints::{
    bootstrap_handler, login_handler, logout_handler, me_handler, two_factor_activate_handler,
    two_factor_disable_handler, two_factor_enroll_handler, two_factor_status_handler,
    CredentialsRequest, SessionResponse, TotpCodeRequest, TotpEnrollResponse, TotpStatusResponse,
};
pub use error::AuthApiError;
pub use extract::{AuthenticatedUser, CsrfHeader, WriteUser};
pub use store::{AuthStore, UserRecord};

use meshlet_domain::auth::RateLimiter;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::service;

/// 登录限流参数：每 email 每窗口最多 5 次失败尝试，窗口 15 分钟。
pub const LOGIN_MAX_ATTEMPTS: u32 = 5;
pub const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

/// Argon2 阻塞任务上限：限制 CPU 密集哈希/校验同时占满 worker。
pub const AUTH_BLOCKING_CONCURRENCY: usize = 4;

/// 未知 email 的恒时校验目标（消除「用户不存在」的时间侧信道）。
/// 内容为 Argon2id PHC 格式的无效哈希——校验必然失败，但耗时与真哈希一致。
const DUMMY_HASH: &str = "$argon2id$v=19$m=32768,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 应用状态：内存 Mesh 状态 + SQLite 用户/会话/agent/API token + 登录限流器。
#[derive(Clone)]
pub struct AppState {
    pub mesh: service::SharedState,
    pub auth: AuthStore,
    pub agent_tokens: crate::agent::AgentTokenStore,
    pub api_tokens: crate::api_token::ApiTokenStore,
    /// 审计日志（存档 §16.5）：与凭证同库。
    pub audit: crate::audit::AuditStore,
    pub login_limiter: Arc<RateLimiter>,
    pub cookie_secure: bool,
    /// 配置应用/回滚 backend 工厂（§10.3 幂等、§10.4 回滚边界）；默认数据面
    /// 未接入（显式失败），测试可注入计数 backend 验证幂等与串行化。
    pub apply_backend: crate::revision::BackendFactory,
    /// 运行指标（§17.2）：进程内计数 + 抓取时现算量规；`GET /api/v1/system/metrics`。
    pub metrics: crate::metrics::Metrics,
    /// Mesh 持久化互斥（§17.3）：变更 + 落库在同一个互斥段内完成，任何并发
    /// 交错都不会让旧行快照覆盖新行（请求路径 DB 镜像的写序保证）。
    pub persist: Arc<tokio::sync::Mutex<()>>,
    /// 备份目录（§17.4）：`None` = 备份未配置（`POST /system/backup` 503）。
    pub backup_dir: Option<std::path::PathBuf>,
    /// 计划隧道 MTU（§7.5「MTU 可配置」）：`None` = 未显式配置，诊断按
    /// WireGuard 默认 1420 解释大包/分片风险；诊断第 13 项据此判读。
    pub tunnel_mtu: Option<u32>,
    /// 服务端 `[dataplane]` 配置（设备计划下发用：接口名/私钥文件）；
    /// `enabled = false` 时 `GET /agent/device/desired` 返回 503。
    pub dataplane: meshlet_config::DataPlaneConfig,
    /// SSH 别名分发段（生产来自 `[ssh_config]`）：`None` = hub 未开启，计划
    /// 不带 `ssh_config` 段；`Some` = 计划携带全网 Active 节点别名表。
    pub ssh_config: Option<meshlet_config::SshDistributeConfig>,
    /// 同一网络的 apply/rollback 串行门（§10.4）；不同网络仍可并行执行。
    pub revision_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// 可信反代来源（TODO-116）：仅当请求直接来自可信代理时才采信
    /// `X-Forwarded-For`/`X-Real-IP`；默认仅回环 127.0.0.1/::1。
    pub trusted_proxies: meshlet_config::TrustedProxyConfig,
    /// 密码哈希/校验阻塞任务并发上限（§11.4）。
    pub auth_blocking: Arc<tokio::sync::Semaphore>,
}

pub type SharedAppState = Arc<AppState>;

impl AppState {
    pub fn new(
        mesh: service::SharedState,
        auth: AuthStore,
        agent_tokens: crate::agent::AgentTokenStore,
        api_tokens: crate::api_token::ApiTokenStore,
        cookie_secure: bool,
    ) -> Self {
        // 审计与凭证同库；克隆池句柄而非共享借用（下方 auth 会被移动进 Self）。
        let audit = crate::audit::AuditStore::new(auth.pool().clone());
        Self {
            mesh,
            auth,
            agent_tokens,
            api_tokens,
            audit,
            login_limiter: Arc::new(RateLimiter::new(LOGIN_MAX_ATTEMPTS, LOGIN_WINDOW)),
            cookie_secure,
            apply_backend: crate::revision::unconfigured_backend_factory(),
            metrics: crate::metrics::Metrics::new(),
            persist: Arc::new(tokio::sync::Mutex::new(())),
            revision_locks: Arc::new(Mutex::new(HashMap::new())),
            auth_blocking: Arc::new(tokio::sync::Semaphore::new(AUTH_BLOCKING_CONCURRENCY)),
            backup_dir: None,
            tunnel_mtu: None,
            dataplane: meshlet_config::DataPlaneConfig::default(),
            ssh_config: None,
            trusted_proxies: meshlet_config::TrustedProxyConfig::default(),
        }
    }

    /// 注入自定义配置应用 backend（数据面接入 / 集成测试）。
    pub fn with_apply_backend(mut self, factory: crate::revision::BackendFactory) -> Self {
        self.apply_backend = factory;
        self
    }

    /// 注入备份目录（§17.4；生产来自 `[backup] dir`，测试注入临时目录）。
    pub fn with_backup_dir(mut self, dir: Option<std::path::PathBuf>) -> Self {
        self.backup_dir = dir;
        self
    }

    /// 注入计划隧道 MTU（§7.5；生产来自 `tunnel_mtu`，测试注入以验证诊断分支）。
    pub fn with_tunnel_mtu(mut self, mtu: Option<u32>) -> Self {
        self.tunnel_mtu = mtu;
        self
    }

    /// 注入服务端 `[dataplane]` 配置（生产来自 `config.dataplane`；测试注入以
    /// 验证设备计划下发与未配置分支）。
    pub fn with_dataplane(mut self, dataplane: meshlet_config::DataPlaneConfig) -> Self {
        self.dataplane = dataplane;
        self
    }

    /// 注入 SSH 别名分发配置（生产来自 `[ssh_config]`；`None` = hub 未开启）。
    pub fn with_ssh_config(
        mut self,
        ssh_config: Option<meshlet_config::SshDistributeConfig>,
    ) -> Self {
        self.ssh_config = ssh_config;
        self
    }

    /// 注入可信反代来源（TODO-116；生产来自 `config.trusted_proxies`，测试注入
    /// 验证「仅可信来源采信头部」安全口径）。
    pub fn with_trusted_proxies(
        mut self,
        trusted_proxies: meshlet_config::TrustedProxyConfig,
    ) -> Self {
        self.trusted_proxies = trusted_proxies;
        self
    }

    /// 注入指标注册表（集成测试断言计数用；生产走 `AppState::new` 默认值）。
    pub fn with_metrics(mut self, metrics: crate::metrics::Metrics) -> Self {
        self.metrics = metrics;
        self
    }

    /// 注入认证阻塞并发上限（生产保持默认，测试验证限并发）。
    pub fn with_auth_blocking_concurrency(mut self, concurrency: usize) -> Self {
        self.auth_blocking = Arc::new(tokio::sync::Semaphore::new(concurrency));
        self
    }

    /// 取某网络的 apply/rollback 串行门；其他网络不被这条配置操作阻塞。
    pub fn revision_lock(&self, network_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut guard = self.revision_locks.lock().unwrap();
        Arc::clone(
            guard
                .entry(network_id.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        )
    }
}
