//! Linux `NetworkBackend` 实装的真机集成测试（[ADR-007](../../docs/decisions/adr-007-linux-network-backend.md)）。
//!
//! 与 `wg_forwarding.rs` / `alias_nat.rs` 的区别：**全部内核操作走
//! `LinuxNetworkBackend`**（netns + sudo 测试钩子），不再用裸 `wg` / `ip`
//! 命令配置数据面——控制面 apply 路径与内核之间是同一套代码。裸命令只用于
//! 搭 underlay（网桥/veth/netns 本身，非后端职责）与「外部视角」探针。
//!
//! 场景模块共享同一个 `mltb` 前缀；进程内串行锁防止该 underlay 被并发
//! 改写。原有验收语义、SKIP 纪律和外部对象保护保持不变。

#![cfg(target_os = "linux")]

#[path = "backend_wiring/alias.rs"]
mod alias;
#[path = "backend_wiring/common.rs"]
mod common;
#[path = "backend_wiring/connectivity.rs"]
mod connectivity;
#[path = "backend_wiring/host_isolation.rs"]
mod host_isolation;
#[path = "backend_wiring/recovery.rs"]
mod recovery;
