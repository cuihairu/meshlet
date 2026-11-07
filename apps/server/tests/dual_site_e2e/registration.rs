//! Registration and control-plane lifecycle provisioning checks.

#![cfg(target_os = "linux")]

use super::context::*;

#[test]
fn registers_devices_and_boots_two_network_hubs() {
    let _guard = lock();
    let Some(ctx) = Context::setup() else {
        return;
    };
    ctx.apply_latest(&ctx.base_b, &ctx.network_b_id);
}
