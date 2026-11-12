//! meshlet-agent 可执行入口（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! 业务逻辑在库层（[`meshlet_agent`]）：本文件只做**启动纪律**——读配置、
//! 校验数据面前置条件（默认全关时不碰内核）、**抢单实例锁**
//! （[`meshlet_agent::instance_lock`]，已锁即退出，不让两个进程互踢同一个
//! 设备身份）、注入本机私钥（ADR-010）、进入对账循环。
//!
//! 数据面纪律：agent 只消费服务端下发的结构化配置对象（§16.4），
//! **绝不执行任何服务端下发的 Shell 命令**。

use meshlet_agent::{read_private_key, Agent};
use meshlet_config::AgentConfig;

fn main() -> std::process::ExitCode {
    // `--version`/`--help` 先行处理，避免被当成配置文件路径而报错
    // （真机验收 NIGHTLY-MSI-1 抓到：`meshlet-agent --help` 曾 exit 1）。
    if let Some(flag) = std::env::args().nth(1).as_deref() {
        match flag {
            "--version" | "-V" => {
                println!("meshlet-agent {}", env!("CARGO_PKG_VERSION"));
                return std::process::ExitCode::SUCCESS;
            }
            "--help" | "-h" => {
                println!("meshlet-agent {}", env!("CARGO_PKG_VERSION"));
                println!();
                println!("Usage: meshlet-agent [agent.toml]");
                return std::process::ExitCode::SUCCESS;
            }
            _ => {}
        }
    }
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
    // 单实例守卫（2026-11-12 imac 实锤：计划任务 + 残留测试进程让 3 个
    // meshlet-agent 并存、互踢同一个 device_id，server 侧 0 条断连日志）：启动即
    // 对 `<state_dir>/agent.lock` 拿 OS 级锁（flock / LockFileEx）并持有到退出；
    // 已被别的实例拿着就明确报错退出——宁可这次启动失败，也不去抢设备身份。
    // 锁在凭证解析**之前**拿：并发 bootstrap 同样会互写账本。上面的纯状态路径
    // 已提前返回，不碰锁、不建目录。
    let state_dir = std::path::PathBuf::from(&config.state_dir);
    let lock_display = meshlet_agent::instance_lock::lock_path(&state_dir)
        .display()
        .to_string();
    let _instance_lock = match meshlet_agent::instance_lock::try_acquire(&state_dir) {
        Ok(lock) => lock,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                eprintln!(
                    "meshlet-agent: another instance is already running (lock {lock_display} held); stop the other meshlet-agent before starting a new one"
                );
            } else {
                // 锁文件打不开同样拒绝：无法证明没有别的实例在跑（对齐 server 的
                // 恢复守卫口径）。
                eprintln!(
                    "meshlet-agent: cannot acquire {lock_display} ({e}); refusing to start while another instance cannot be ruled out"
                );
            }
            return std::process::ExitCode::FAILURE;
        }
    };
    tracing::info!(instance_lock = %lock_display, "single-instance lock held");
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
