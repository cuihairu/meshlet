//! HTTP routing handlers, grouped by resource family (a private module; the public API is gathered at the crate root).
//! Each handler carries its own `State`/`WriteUser`/`CsrfHeader` extractors and the `crate::persist` mutual-exclusion discipline (mutate + persist
//! inside one critical section: no persist, no proceed).

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
