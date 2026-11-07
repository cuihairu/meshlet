//! Cross-site route publication and revision application.

#![cfg(target_os = "linux")]

use super::context::*;
use super::support::*;
use serde_json::json;

#[test]
fn publishes_overlapping_lan_routes_as_two_distinct_aliases() {
    let _guard = lock();
    let Some(mut ctx) = Context::setup() else {
        return;
    };
    let routes_uri = format!("/api/v1/networks/{}/routes", ctx.network_id);
    let aliases_uri = format!("/api/v1/networks/{}/aliases", ctx.network_id);
    for (name, gateway, alias_cidr) in [
        ("gw1", ctx.g1_id.as_str(), "10.241.1.0/24"),
        ("gw2", ctx.g2_id.as_str(), "10.241.2.0/24"),
    ] {
        let (code, route) = http_json(
            "POST",
            &format!("{}{routes_uri}", ctx.base),
            Some(&ctx.cookie),
            None,
            Some(json!({
                "gateway_device_id": gateway,
                "destination_cidr": "192.168.1.0/24",
                "return_path_mode": "controlled_snat",
                "route_mode": "alias",
            })),
        );
        assert_eq!(code, 201, "route for {name}: {route}");
        let route_id = route["id"].as_str().unwrap().to_string();
        let (code, alias) = http_json(
            "POST",
            &format!("{}{aliases_uri}", ctx.base),
            Some(&ctx.cookie),
            None,
            Some(json!({
                "lan_route_id": route_id,
                "alias_cidr": alias_cidr,
                "translation_mode": "dnat_snat",
            })),
        );
        assert_eq!(code, 201, "alias for {name}: {alias}");
        ctx.alias_ids
            .push(alias["id"].as_str().unwrap().to_string());
        ctx.route_ids.push(route_id);
    }
    assert_ne!(
        ctx.route_ids[0], ctx.route_ids[1],
        "each site keeps its own route"
    );
    ctx.apply_latest(&ctx.base, &ctx.network_id);
}
