//! meshlet-agent 可执行入口（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! 业务逻辑在库层（[`meshlet_agent`]）：本文件只做**启动纪律**——读配置、
//! 校验数据面前置条件（默认全关时不碰内核）、注入本机私钥（ADR-010）、进入
//! 对账循环。
//!
//! 数据面纪律：agent 只消费服务端下发的结构化配置对象（§16.4），
//! **绝不执行任何服务端下发的 Shell 命令**。

use meshlet_agent::{read_private_key, Agent};
use meshlet_config::AgentConfig;

fn main() -> std::process::ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = match load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("meshlet-agent: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "agent starting");
    tracing::info!(
        server_url = %config.server_url,
        state_dir = %config.state_dir,
        dataplane_enabled = config.dataplane.enabled,
        interface = %config.dataplane.interface,
        poll_interval_secs = config.dataplane.poll_interval_secs,
        "agent config loaded"
    );

    // 数据面默认全关：不碰内核，只报状态（§16.4 agent 自主边界）。
    if !config.dataplane.enabled {
        tracing::info!("dataplane disabled: agent does not touch the kernel (see ADR-007)");
        return std::process::ExitCode::SUCCESS;
    }
    // 凭证解析（ZeroTier 式自举）：配置 device_token → 凭证文件 → 持自举码
    // 注册自身（落 Pending，控制中心批准前拉不到计划，心跳保活）。
    let config = match meshlet_agent::resolve_device_token(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("meshlet-agent: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let private_key = match read_private_key(&config.dataplane) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("meshlet-agent: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    Agent::new(config, private_key).run()
}

fn load_config() -> Result<AgentConfig, String> {
    let Some(path) = std::env::args().nth(1) else {
        return Ok(AgentConfig::default());
    };
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("read config {path}: {e}"))?;
    AgentConfig::from_toml(&raw).map_err(|e| format!("invalid config: {e}"))
}
