//! 本地面板本机实测入口（不依赖 agent / server / 桌面会话）。
//!
//! 用法：
//!
//! ```text
//! cargo run -p meshlet-tray-host --example local_panel -- <state_dir>
//! curl -i http://127.0.0.1:<port>/      # 200 + 当前节点 / 直连节点 / 本地路由三块
//! ```
//!
//! `<state_dir>` 可以是任意目录：数据文件缺失时面板照样出三块（空态文案），
//! 便于用 mock 数据源做验收。进程常驻直到被杀。

use std::path::PathBuf;

fn main() {
    let state_dir = PathBuf::from(
        std::env::args()
            .nth(1)
            .expect("usage: local_panel <state_dir>"),
    );
    let port = meshlet_tray_host::panel::start(state_dir.clone()).expect("bind 127.0.0.1:0");
    println!("local panel: {}", meshlet_tray_host::panel::url(port));
    println!("state_dir:   {}", state_dir.display());
    // 常驻服务（面板线程在后台 accept）。
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
