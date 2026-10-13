//! meshlet-agent：设备端 Agent（Phase 1 骨架）。
//!
//! 当前仅做配置引导与打印；WireGuard/路由操作经由 `meshlet-network::NetworkBackend`，
//! 实现（Linux）待特权测试环境接入（ADR-007）。**绝不执行服务端下发的任意 Shell 命令**（§16.4）。

use meshlet_config::AgentConfig;

fn main() {
    let config = match std::env::args().nth(1) {
        Some(path) => {
            let raw = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read config {path}: {e}"));
            AgentConfig::from_toml(&raw).unwrap_or_else(|e| panic!("invalid config: {e}"))
        }
        None => AgentConfig::default(),
    };
    println!("meshlet-agent {} starting", env!("CARGO_PKG_VERSION"));
    println!("  server: {}", config.server_url);
    println!("  state:  {}", config.state_dir);
    println!("no network backend attached yet (see ADR-007 / TODO)");
}
