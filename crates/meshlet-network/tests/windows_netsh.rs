//! **Real-machine** integration tests for the Windows route planning layer
//! ([ADR-008](../../docs/decisions/adr-008-windows-network-backend.md), TODO #52): the full loop on a
//! real netsh -- add -> show read-back -> delete -> idempotent re-delete -- plus the assertion that
//! failure-text classification consumes real Windows messages rather than fixtures.
//!
//! The discipline mirrors `backend_wiring.rs`: the path under test goes through `windows_routes::exec`
//! (the planning layer builds the arguments and classifies the output), while raw netsh serves only as
//! the "external viewpoint" probe (reading back via `show route` and collecting the original messages
//! of the re-delete).
//!
//! Platform and execution environment:
//! - Compiled and run on Windows only (a file-level `#![cfg]`; on Linux this binary is empty and the
//!   CI linux job is unaffected); the CI windows-latest job's `cargo test --workspace` really runs
//!   this file;
//! - Prerequisite: an elevated shell (a hosted runner satisfies that by default); the output language
//!   does not matter -- after the zh-CN real-machine evidence collection (2026-10-25), both the probe
//!   decoding and the classifier close the loop on localized messages (netsh's redirected output is
//!   encoded in the active code page, see `windows_console`).
//!
//! Test-network hygiene: the prefix is taken from the RFC 5737 documentation range (`192.0.2.0/24`,
//! never carrying real traffic); the interface is the always-present loopback interface; `store=active`
//! does not persist across reboots; the failure path is cleaned up by `RouteGuard` (a Drop deletes the
//! prefix), the re-delete is itself idempotent, and repeated cleanup is harmless.
//!
//! **Still uncovered (an honestly kept gap; TODO #52 stays unchecked)**: the real elevation message of
//! the permission-denied path -- a hosted runner is elevated throughout, so `requires elevation` /
//! `access is denied` cannot arise naturally; that mapping is pinned by the `src/windows_routes.rs`
//! unit tests against the Windows canonical wording.

#![cfg(target_os = "windows")]

use std::process::Command;

use meshlet_network::windows_routes::exec::run_route_command;
use meshlet_network::windows_routes::{
    route_already_absent, route_prefixes_on_interface, NetshRouteCommand,
};
use meshlet_network::{NetworkError, RouteConfig};

/// RFC 5737 TEST-NET-1: a documentation-reserved range that should never appear in a routing table; deleted right after use.
const TEST_PREFIX: &str = "192.0.2.0/24";
/// The always-present Windows loopback interface (a multi-word name, incidentally covering the planning layer's quoting-rendering path).
const TEST_INTERFACE: &str = "Loopback Pseudo-Interface 1";
/// A nonexistent interface name: the evidence probe for a real netsh failure message.
const MISSING_INTERFACE: &str = "meshlet-no-such-if-01";

/// Loopback evidence collected in practice (2026-10-16 CI runner, three rounds of messages):
/// 1. an early planning-layer version embedded quotes around interface names containing spaces
///    (`interface="…"`); after std `Command` escaped them into `\"`, **netsh's own tokenizer did not
///    recognize them** and the tokens got shredded -- the fragment `Loopback` landed in turn in the
///    nexthop / siteprefixlength slots, raising `Invalid nexthop parameter (Loopback)` and then
///    `Invalid siteprefixlength parameter (Loopback)` (the fix, in the `named_value` note: a key-value
///    pair stays a single argv token with no embedded quotes);
/// 2. with the tokenization fixed, netsh rejected a route with `nexthop=127.0.0.1` on loopback --
///    `The parameter is incorrect.` (netsh's nexthop validation on loopback);
/// 3. conclusion: the usable form on loopback is an **on-link route** (no `nexthop=`). All three
///    rounds of real text fell correctly through `classify_netsh_route_failure` into `ApplyRejected`
///    carrying the original message -- failure-text classification closed the loop on real Windows messages.
fn test_route(interface: &str) -> RouteConfig {
    RouteConfig {
        destination: TEST_PREFIX.parse().unwrap(),
        interface: interface.into(),
        gateway: None,
    }
}

fn delete_command() -> NetshRouteCommand {
    NetshRouteCommand::Delete {
        destination: TEST_PREFIX.parse().unwrap(),
        interface: TEST_INTERFACE.into(),
        gateway: None,
    }
}

/// Raw netsh probe (bypassing the code under test): merges stdout+stderr and returns (exit, text).
fn netsh_raw(args: &[String]) -> (i32, String) {
    let output = Command::new("netsh")
        .args(args)
        .output()
        .expect("spawn netsh");
    let text = format!(
        "{}{}",
        meshlet_network::windows_console::decode_output(&output.stdout),
        meshlet_network::windows_console::decode_output(&output.stderr)
    );
    (output.status.code().unwrap_or(-1), text)
}

/// Keep only the lines carrying the test prefix/interface (for CI log evidence; do not dump the whole table).
fn relevant_lines(table: &str) -> String {
    table
        .lines()
        .filter(|l| l.contains(TEST_PREFIX) || l.contains(TEST_INTERFACE))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Clean up even on failure: Drop makes a best-effort deletion of the test prefix (deleting a route
/// that is already absent counts as an idempotent success, so cleanup repeated by a panic and by the
/// normal path is harmless).
struct RouteGuard(NetshRouteCommand);

impl Drop for RouteGuard {
    fn drop(&mut self) {
        let _ = run_route_command(&self.0);
    }
}

/// The acceptance backbone: add -> read back with `show route` (the planning layer's parser against
/// the real table output) -> delete -> the prefix is gone -> the **real message** of the re-delete
/// hits the idempotence verdict -> exec's idempotent-success contract.
#[test]
fn add_show_readback_delete_and_idempotent_redelete() {
    let add = NetshRouteCommand::Add {
        route: test_route(TEST_INTERFACE),
    };
    let delete = delete_command();

    // 1) add: must succeed on the elevated runner (if InsufficientPrivileges shows up, the runner's
    //    context has changed -- the error detail carries the raw netsh text).
    let result =
        run_route_command(&add).expect("netsh add route must succeed on the elevated CI runner");
    assert!(result.applied);

    // The guard covers things from the moment the route exists: any later assertion failure still gets cleaned up.
    let _guard = RouteGuard(delete.clone());

    // 2) Read back with show route: route_prefixes_on_interface parses the real table output, and the
    //    test prefix sits on the loopback interface.
    let (_, table) = netsh_raw(&[
        "interface".into(),
        "ipv4".into(),
        "show".into(),
        "route".into(),
    ]);
    eprintln!(
        "netsh show route (relevant lines):\n{}",
        relevant_lines(&table)
    );
    let prefixes = route_prefixes_on_interface(&table, TEST_INTERFACE);
    assert!(
        prefixes.iter().any(|p| p.to_string() == TEST_PREFIX),
        "added route must read back on `{TEST_INTERFACE}`; parsed: {prefixes:?}"
    );

    // 3) delete -> applied; 4) show: the prefix is gone from that interface.
    let result = run_route_command(&delete).expect("netsh delete route");
    assert!(result.applied);
    let (_, table_after) = netsh_raw(&[
        "interface".into(),
        "ipv4".into(),
        "show".into(),
        "route".into(),
    ]);
    let prefixes_after = route_prefixes_on_interface(&table_after, TEST_INTERFACE);
    assert!(
        !prefixes_after.iter().any(|p| p.to_string() == TEST_PREFIX),
        "deleted route must be gone; parsed: {prefixes_after:?}"
    );

    // 5) Evidence from the real re-delete message: the raw Windows text for deleting an absent route must
    //    hit route_already_absent (if the wording changes, this turns red -- better red than falsely green).
    let (code, text) = netsh_raw(&[
        "interface".into(),
        "ipv4".into(),
        "delete".into(),
        "route".into(),
        format!("prefix={TEST_PREFIX}"),
        format!("interface={TEST_INTERFACE}"),
        "store=active".into(),
    ]);
    eprintln!("re-delete exit={code} raw output: {text}");
    assert!(
        route_already_absent(&text),
        "real Windows absence text must classify as idempotent delete: {text}"
    );

    // 6) exec's three-state contract: deleting an already-absent route again = Ok (failures are cleanable, §10.3).
    let result = run_route_command(&delete)
        .expect("re-delete of an absent route must be idempotent success");
    assert!(result.applied);
}

/// Classification evidence for a real netsh failure text: adding a route on a nonexistent interface
/// fails closed into `ApplyRejected`, carrying the original text and the interface name; it must
/// **not** be misjudged as a privilege class (the real message contains no privilege wording -- this
/// is the reverse assertion that a broad match does not report false positives).
#[test]
fn add_route_to_missing_interface_fails_closed_with_real_text() {
    let add = NetshRouteCommand::Add {
        route: test_route(MISSING_INTERFACE),
    };
    match run_route_command(&add) {
        Err(NetworkError::ApplyRejected(detail)) => {
            assert!(detail.contains(MISSING_INTERFACE), "{detail}");
            assert!(
                !detail.contains("(no output)"),
                "real netsh error text must be carried: {detail}"
            );
        }
        Err(NetworkError::InsufficientPrivileges(detail)) => {
            panic!("runner is elevated; a privilege denial here is unexpected: {detail}")
        }
        other => panic!("add on a missing interface must fail closed, got {other:?}"),
    }
}
