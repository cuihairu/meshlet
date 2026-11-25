//! Local smoke-test entry point for the panel (needs no agent / server / desktop session).
//!
//! Usage:
//!
//! ```text
//! cargo run -p meshlet-tray-host --example local_panel -- <state_dir>
//! curl -i http://127.0.0.1:<port>/      # 200 + the three blocks: current node / direct peers / local routes
//! ```
//!
//! `<state_dir>` can be any directory: when the data files are missing the panel still renders all three blocks (empty-state wording),
//! which makes acceptance testing against a mock data source easy. The process stays resident until it is killed.

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
    // Keep serving forever (the panel thread accepts in the background).
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
