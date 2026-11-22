//! macOS boringtun 后端模块（计划层见 [crate::macos_wireguard_bt]）。
//!
//! [backend] 的命令计划（[backend::BtCommand] / [backend::bt_apply_commands]）
//! 是**全平台纯函数**——本机 Linux 跑其单测 = 断言命令序列，不真执行；
//! `exec` 子模块是 `#[cfg(target_os = "macos")]` 执行器（宿主 CI 不跑
//! macOS 测试，仅经 `x86_64-apple-darwin` 交叉 check 编译验证）。

pub mod backend;
