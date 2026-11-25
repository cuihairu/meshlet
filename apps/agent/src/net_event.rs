//! Network-change events (the P1 companion, user directive 2026-11-12): wake the main loop's backoff wait
//! on interface up/down or address add/remove and **retry immediately** - after a disconnect, the worst case of
//! waiting out the whole backoff period (up to 5 minutes under the 300s cap) is the direct source of "it never
//! connects"; the network has long recovered while the agent is still sitting in backoff.
//!
//! Platform mechanisms (one of two, minimal implementation):
//! - **Linux**: a netlink subscription (`NETLINK_ROUTE` multicast
//!   `RTMGRP_LINK | RTMGRP_IPV4_IFADDR` - interface up/down and IPv4 address add/remove,
//!   via `libc` directly, adding no new dependency);
//! - **Windows**: a blocking `NotifyAddrChange(NULL, NULL)` - the official documentation states the two-NULL
//!   form blocks until the IPv4 address table changes (call again after each change for the next one).
//!   Interface up/down usually coincides with address add/remove and triggers it; the extreme case of a pure
//!   link flip without an address change is outside this minimal implementation's sensing surface (recorded as such).
//!
//! Disciplines:
//! - **A monitoring failure must never amplify the fault**: a thread-start / subscription failure only warns
//!   and exits, and the main loop falls back to a plain sleep cycle (indistinguishable from the module not
//!   existing) - probe-driven wakeup is an accelerator, not a dependency surface;
//! - **Never spin busy**: the receiver treats `Disconnected` (the monitor thread is gone) as "wait out the
//!   whole cycle", see [`crate::agent::Agent::run`].

use std::sync::mpsc::{self, Receiver, Sender};

/// Start network-change monitoring: returns the event receiver. Each message means "the interface/address
/// table changed" (no distinction of specific events - the main loop's retry is an idempotent pull and needs no
/// knowledge of what changed).
///
/// The monitor thread lives until process exit or subscription failure; a subscription failure warns once,
/// after which the receiver receives no events (the main loop falls back to a plain sleep cycle, see the module docs).
pub fn watch() -> Receiver<()> {
    let (tx, rx) = mpsc::channel();
    // The sender is cloned and kept alive here: when the thread cannot start, the receiver then sees neither
    // events nor `Disconnected` (otherwise the main loop would be woken at once and spin busy).
    let keeper = tx.clone();
    match std::thread::Builder::new()
        .name("meshlet-net-event".into())
        .spawn(move || monitor(tx))
    {
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(error = %e, "net-event monitor failed to start; retry stays interval-based");
            std::mem::forget(keeper);
        }
    }
    rx
}

#[cfg(target_os = "linux")]
fn monitor(events: Sender<()>) {
    // Minimal netlink subscription: the link (interface up/down) + IPv4 address (address add/remove) multicast groups.
    unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        );
        if fd < 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "netlink socket failed; retry stays interval-based");
            return;
        }
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_groups = (libc::RTMGRP_LINK | libc::RTMGRP_IPV4_IFADDR) as u32;
        let bound = libc::bind(
            fd,
            &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        );
        if bound < 0 {
            tracing::warn!(error = %std::io::Error::last_os_error(), "netlink bind failed; retry stays interval-based");
            libc::close(fd);
            return;
        }
        let mut buf = [0u8; 4096];
        loop {
            let n = libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0);
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                tracing::warn!(error = %err, "netlink recv failed; retry stays interval-based");
                libc::close(fd);
                return;
            }
            if n == 0 {
                // The kernel never closes netlink: treat it as an abnormal exit (on the run side, `Disconnected`
                // falls back to a plain sleep).
                libc::close(fd);
                return;
            }
            if events.send(()).is_err() {
                libc::close(fd);
                return;
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn monitor(events: Sender<()>) {
    loop {
        // The synchronous two-NULL form: blocks until the IPv4 address table changes (official documentation),
        // with no handle-ownership problem; call again after each change for the next.
        let rc = unsafe {
            windows_sys::Win32::NetworkManagement::IpHelper::NotifyAddrChange(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != 0 {
            tracing::warn!(
                error = rc,
                "NotifyAddrChange failed; retry stays interval-based"
            );
            return;
        }
        if events.send(()).is_err() {
            return;
        }
    }
}

/// Other platforms have no network-change mechanism: monitoring exits at once (the receiver's `Disconnected`
/// means the main loop waits out the whole cycle, see the module docs).
#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn monitor(events: Sender<()>) {
    drop(events);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A usable receiver exists as soon as monitoring starts; a subscription failure (CI containers often lack
    /// netlink permission) does not panic and the main loop falls back to pure periodic backoff - startup itself
    /// cannot be a fault point.
    #[test]
    fn watch_returns_a_receiver_without_panicking() {
        let rx = watch();
        // No assertion on whether events arrive (real network events are uncontrollable): the receiver existing is enough.
        drop(rx);
    }
}
