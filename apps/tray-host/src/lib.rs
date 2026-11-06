//! `meshlet-tray-host` 的库目标：把**跨平台**的部分（本地面板）单独暴露。
//!
//! 二进制（Win32 托盘宿主）与 `examples/local_panel`（本机 curl 实测入口）
//! 共用这一份代码，面板逻辑只写一次、两侧同源。

pub mod panel;
