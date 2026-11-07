//! Shared service-layer type aliases and time helpers.

use std::sync::{Arc, Mutex};

use crate::service::state::MeshState;

pub fn now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

pub fn now_unix() -> i64 {
    chrono::Utc::now().timestamp()
}

pub type SharedState = Arc<Mutex<MeshState>>;
