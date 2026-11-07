//! 服务发布 HTTP 路由装配。

use super::handlers::{
    create_dns_record_handler, create_forward_handler, create_http_route_handler,
    create_probe_handler, delete_dns_record_handler, delete_forward_handler,
    delete_http_route_handler, delete_probe_handler, get_dns_record_handler, get_forward_handler,
    get_http_route_handler, get_probe_handler, list_dns_records_handler, list_forwards_handler,
    list_http_routes_handler, list_probes_handler,
};
use super::health::publish_health_handler;
use crate::auth::SharedAppState;
use axum::routing::{get, post};
use axum::Router;

pub(crate) fn routes() -> Router<SharedAppState> {
    // 与 segments/aliases 同形：发布对象是网络范围内的期望配置。
    Router::new()
        .route(
            "/api/v1/networks/{network_id}/publish/forwards",
            post(create_forward_handler).get(list_forwards_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/forwards/{forward_id}",
            get(get_forward_handler).delete(delete_forward_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/http-routes",
            post(create_http_route_handler).get(list_http_routes_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/http-routes/{route_id}",
            get(get_http_route_handler).delete(delete_http_route_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/probes",
            post(create_probe_handler).get(list_probes_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/probes/{probe_id}",
            get(get_probe_handler).delete(delete_probe_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/dns-records",
            post(create_dns_record_handler).get(list_dns_records_handler),
        )
        .route(
            "/api/v1/networks/{network_id}/publish/dns-records/{record_id}",
            get(get_dns_record_handler).delete(delete_dns_record_handler),
        )
        .route("/api/v1/agent/publish-health", post(publish_health_handler))
}
