//! 本地面板：托盘「本地面板」打开的本机自托管只读页（loopback 随机端口）。
//!
//! 职责拆分为三块：[`runtime`] 管 loopback 服务与 URL/config 交接；
//! [`snapshot`] 从本机状态文件构建唯一数据源；[`html`] 只负责渲染与
//! 注入到页面的 JavaScript，不直接读状态文件或打开网络连接。

mod html;
mod runtime;
mod snapshot;

pub use html::{mode_label, render, REFRESH_SECS};
pub use runtime::{
    config_value, read_url_file, remove_url_file, start, url, write_url_file, URL_FILE,
};
pub use snapshot::{
    state_json, NodeSnapshot, PanelSnapshot, PeerRow, PeersSnapshot, RouteRow, RoutesSnapshot,
};
