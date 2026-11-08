//! HTTP 路由 handler，按资源族分组（对外私有模块，公开 API 集中在 crate 根）。
//! 各 handler 自带 `State`/`WriteUser`/`CsrfHeader` 等提取器与 `crate::persist`
//! 互斥纪律（变更/落库同一互斥段，「不落库不放行」）。

mod bootstrap_tokens;
mod devices;
mod enroll;
mod host_forwards;
mod invites;
mod networks;
mod registrations;
mod routes;
mod status;

pub(crate) use bootstrap_tokens::*;
pub(crate) use devices::*;
pub(crate) use enroll::*;
pub(crate) use host_forwards::*;
pub(crate) use invites::*;
pub(crate) use networks::*;
pub(crate) use registrations::*;
pub(crate) use routes::*;
pub(crate) use status::*;
