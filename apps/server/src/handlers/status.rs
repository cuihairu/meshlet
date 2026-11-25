//! System status and update manifest endpoints: `/system/status`, `/update-manifest`.

use crate::{system_status, update_manifest, SystemStatus, UpdateManifest};
use axum::Json;

pub(crate) async fn status_handler() -> Json<SystemStatus> {
    Json(system_status())
}

pub(crate) async fn update_manifest_handler() -> Json<UpdateManifest> {
    Json(update_manifest(
        "https://releases.meshlet.dev/meshlet-agent",
        "0000000000000000000000000000000000000000000000000000000000000000",
    ))
}
