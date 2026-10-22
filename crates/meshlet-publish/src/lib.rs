//! Service publishing runtime.
//!
//! The publication runtime only accepts typed configuration. It never executes
//! commands supplied by the control plane. Split DNS answers only names in the
//! configured internal domain; it never installs a system resolver and never
//! rewrites public DNS configuration.

pub mod dns;
pub mod forwarding;
pub mod health;
pub mod http;

mod authorization;

pub use authorization::{AuthorizationDecision, AuthorizationPolicy, AuthorizedClient};
pub use forwarding::{
    bind_tcp, bind_udp, spawn_tcp_forwarder, spawn_udp_forwarder, ForwardProtocol,
    PortForwardConfig,
};
pub use http::{bind_http, run_http_router, sniff_sni, HttpRoute, HttpRouteSet, RouteMode};

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error("connection closed")]
    ConnectionClosed,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
