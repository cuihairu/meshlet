//! Control-plane service facade. Internal modules own state, contracts,
//! errors, operations and unit tests.

mod error;
mod operations;
mod operations_record;
mod shared;
mod state;
mod tests;
mod views;

pub use error::ServiceError;
pub use operations::{
    apply_segment_grant, approve_registration, check_forward_prefix, create_alias,
    create_bootstrap_token, create_host_forward, create_invite, create_network, create_route,
    create_segment, create_segment_grant, current_revision_ref, delete_alias, delete_host_forward,
    delete_route, deny_registration, device_view, enroll, evaluate_presence, fingerprint_of,
    gauge_snapshot, get_alias, get_route, list_aliases, list_bootstrap_tokens, list_devices,
    list_host_forwards, list_networks, list_registrations, list_routes, list_segment_grants,
    list_segments, record_agent_report, record_device_hostname, record_diagnostics,
    record_direct_state, record_pending_agent_report, register_device, revoke_bootstrap_token,
    revoke_device, revoke_invite, revoke_segment_grant, set_device_labels,
};
pub(crate) use operations_record::record_revision;
pub use shared::{now, now_unix, SharedState};
pub use state::{
    require_network, settle_desired_state, settle_desired_with_status, DesiredStateSettle,
    MeshState,
};
pub use views::{
    AliasView, ApproveRegistrationResponse, BootstrapTokenView, CreateAliasRequest,
    CreateBootstrapTokenRequest, CreateBootstrapTokenResponse, CreateHostForwardRequest,
    CreateInviteRequest, CreateInviteResponse, CreateNetworkRequest, CreateRouteRequest,
    CreateSegmentGrantRequest, CreateSegmentRequest, DeviceView, EnrollRequest, EnrollResponse,
    HostForwardView, NetworkView, RegisterDeviceRequest, RegisterDeviceResponse, RegistrationView,
    RevisionRef, RouteView, SegmentGrantView, SegmentView, SetDeviceLabelsRequest,
};
