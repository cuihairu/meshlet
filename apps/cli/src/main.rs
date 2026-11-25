//! meshlet-cli: a ZeroTier-like command line tool.
//!
//! Common commands:
//!   meshlet info             Device info (name, IP, status)
//!   meshlet status           Agent runtime status
//!   meshlet peers            Directly connected nodes (IP/mode/RTT/endpoint/traffic)
//!   meshlet peer dial <node> Force a direct dial to the target node (name/IP)
//!   meshlet agent diag       Network diagnostics snapshot (route table/interface list/wg readings)
//!   meshlet agent diag --peers   Append the direct peers table after the snapshot
//!   meshlet task ls          Task queue (--network <id>)
//!   meshlet task assign      Dispatch a task (--network/--node/--cmd)
//!   meshlet task confirm <id>    Confirm completion (user-side action)
//!   meshlet task retry <id>      Reject and re-run (new generation task)
//!   meshlet networks         Subnet/route list
//!   meshlet config           Show configuration
//!   meshlet version          Version number

mod cli;

use cli::dispatch::dispatch;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    dispatch(args);
}
