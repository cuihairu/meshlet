//! meshlet-agent 库：设备端数据面协调（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! agent 只消费服务端下发的**结构化配置对象**（§16.4）：用 enrollment 凭证拉取
//! 自身的数据面计划，有变更时调 [`meshlet_network::SystemBackend`]
//! 应用隧道/路由/NAT，并周期心跳上报本地握手证据。
//!
//! 硬纪律：
//! - **绝不执行服务端下发的 Shell 命令**——只消费类型化的
//!   [`meshlet_network::DevicePlan`]；
//! - **启动即对账**（「进程活着」≠「内核还是上次的样子」）：核对实际对象与账本
//!   里记的 `desired_config_hash`，缺失/漂移即重放——覆盖「主机重启后隧道消失但
//!   账本仍记 applied」（TODO #32）；
//! - **私钥不出设备**（ADR-010）：计划里恒无私钥，agent 从
//!   `[dataplane] private_key_file` 本地注入。

pub mod agent;
pub mod bootstrap;
#[cfg(target_os = "linux")]
pub mod dbus;
pub mod desktop;
#[cfg(not(target_os = "linux"))]
pub mod desktop_unsupported;
pub mod reconcile;
pub mod server;
pub mod tray;

pub use agent::{read_private_key, Agent};
pub use bootstrap::resolve_device_token;
pub use desktop::{DesktopPublish, NotifyCall, StatusNotifierProperties};
pub use reconcile::{needs_apply, stale_owners, AgentState, Decision, Reason};
pub use tray::{IconSize, TraySink, TrayState, TrayStatus, TrayWrite};
