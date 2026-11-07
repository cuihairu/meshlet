//! 服务发布控制面（R-06）：四类发布对象（PortForward / HTTP 路由 / 探针 /
//! DNS 记录）的 CRUD + agent 健康回报。

mod auth;
mod crud;
mod device_plan;
mod handlers;
mod health;
mod models;
pub(crate) mod persist;
mod routes;
mod views;

pub use device_plan::device_publish_plan;
pub use health::{PublishHealthRequest, PublishHealthResponse};
pub use models::{
    PublishCatalog, PublishDnsRecord, PublishForward, PublishHttpRoute, PublishProbe,
};
pub use views::{
    CreatePublishDnsRecordRequest, CreatePublishForwardRequest, CreatePublishHttpRouteRequest,
    CreatePublishProbeRequest, PublishDnsRecordView, PublishForwardView, PublishHttpRouteView,
    PublishProbeView,
};

pub(crate) use auth::device_in_network;
pub(crate) use models::publish_object_count;
pub(crate) use routes::routes;
