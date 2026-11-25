//! Direct endpoint report.

use std::net::Ipv4Addr;

use meshlet_domain::DirectEndpointReport;

/// §12 P2P direct-connect candidate (pure logic): `listen_port` is `None` (direct
/// connect off, effective port unresolved, or all candidates blocked -- the
/// WIN-PORT-1 B2 gate-closed state) -> `None` (omitted from the report: reporting a
/// port this machine cannot bind just points the peer at a dead port); with an
/// effective port, carry it plus the enumerated RFC1918 LAN addresses (may be empty;
/// empty candidates are still legal -- the peer can still try publicly observed
/// addresses). The effective port, the conf `ListenPort`, and the firewall allow
/// all share one source (hard invariant, resolution in [`super::direct_port`]).
pub(super) fn direct_report_from(
    listen_port: Option<u16>,
    lan_addrs: Vec<Ipv4Addr>,
) -> Option<DirectEndpointReport> {
    Some(DirectEndpointReport {
        listen_port: listen_port?,
        lan_addrs,
    })
}
