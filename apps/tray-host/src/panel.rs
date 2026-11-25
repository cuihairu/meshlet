//! Local panel: the self-hosted read-only page (loopback on a random port) opened by the tray's "local panel" item.
//!
//! Responsibilities split into three parts: [`runtime`] owns the loopback service and the URL/config handoff;
//! [`snapshot`] builds the single source of truth from the local state files; [`html`] only renders and
//! injects the JavaScript into the page, never reading state files or opening network connections directly.

mod html;
mod runtime;
mod snapshot;

pub use html::{mode_label, render, REFRESH_SECS};
pub use runtime::{
    config_value, read_url_file, remove_url_file, start, url, write_url_file, URL_FILE,
};
pub use snapshot::{
    state_json, NodeSnapshot, PanelSnapshot, PeerRow, PeersSnapshot, RouteRow, RoutesSnapshot,
};
