use crate::cli::local_state::state_dir;
use crate::cli::render::format_dial_targets;
use meshlet_network::dial::{self, DirectDialRequest, DirectPeerView};

/// Upper bound (seconds) to wait for the dial result: the agent probes every 30s, so allow a full cycle plus headroom.
const DIAL_RESULT_TIMEOUT_SECS: u64 = 45;
/// Result polling interval (milliseconds).
const DIAL_POLL_MILLIS: u64 = 500;

/// `meshlet peer dial [<node>]` (R-AGENT-WIN-1 supplement ③).
///
/// Without `<node>`: list dialable candidates (name/IP/mode/RTT/endpoint) — the data source for
/// the tray's "connect to node..." submenu. With `<node>`: resolve the target (name/IP/public key
/// prefix), write the dial intent, poll the agent's result, and print success/failure.
pub(crate) fn cmd_peer_dial(node: Option<&str>) {
    let state = state_dir();
    let views = dial::load_direct_peers(&state);
    match node {
        None => print_dial_targets(&views),
        Some(node) => dial_node(&state, views, node),
    }
}

/// Argumentless mode: print the table of dialable candidates.
fn print_dial_targets(views: &Option<Vec<DirectPeerView>>) {
    let views = match views {
        Some(views) => views,
        None => {
            println!("(no direct candidates — agent not reporting yet)");
            return;
        }
    };
    if views.is_empty() {
        println!("(no direct candidates)");
        return;
    }
    print!("{}", format_dial_targets(views));
}

/// Resolve `<node>`: exact name / overlay IP / public key prefix (case-insensitive).
/// Pure function (testable); returns `None` when nothing matches.
fn resolve_dial_target<'a>(views: &'a [DirectPeerView], node: &str) -> Option<&'a DirectPeerView> {
    let node = node.trim();
    let lower = node.to_ascii_lowercase();
    views.iter().find(|view| {
        view.name == node
            || view.virtual_ipv4.to_string() == node
            || view.public_key.to_ascii_lowercase().starts_with(&lower)
    })
}

/// Argument mode: resolve the target, write the intent, poll the result, print success/failure.
fn dial_node(state: &std::path::Path, views: Option<Vec<DirectPeerView>>, node: &str) {
    let views = match views {
        Some(views) => views,
        None => {
            eprintln!("peer dial: no direct candidates (agent not reporting yet)");
            std::process::exit(1);
        }
    };
    let target = match resolve_dial_target(&views, node) {
        Some(target) => target,
        None => {
            eprintln!("peer dial: unknown node '{node}'");
            std::process::exit(1);
        }
    };
    let request = DirectDialRequest {
        node: node.trim().to_string(),
        public_key: target.public_key.clone(),
        virtual_ipv4: target.virtual_ipv4,
        request_id: dial_request_id(),
        requested_at: dial::now_millis(),
    };
    if let Err(error) = dial::write_request(state, &request) {
        eprintln!("peer dial: cannot write request: {error}");
        std::process::exit(1);
    }
    println!(
        "dialing {} ({}) — waiting for agent...",
        target.name, target.virtual_ipv4
    );
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(DIAL_RESULT_TIMEOUT_SECS);
    while std::time::Instant::now() < deadline {
        if let Some(result) = dial::load_result(state) {
            if result.request_id == request.request_id {
                if result.ok {
                    println!("ok: {} ({})", result.message, result.mode);
                } else {
                    eprintln!("failed: {}", result.message);
                    std::process::exit(1);
                }
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(DIAL_POLL_MILLIS));
    }
    eprintln!("peer dial: timeout waiting for agent (is the agent running?)");
    std::process::exit(1);
}

/// Dial request ID: Unix millis plus this process id (unique enough across processes).
fn dial_request_id() -> String {
    format!("{}-{}", dial::now_millis(), std::process::id())
}

#[cfg(test)]
mod tests {
    use super::{format_dial_targets, resolve_dial_target};
    use meshlet_network::dial::DirectPeerView;

    /// `peer dial <node>`: resolve the target (name/IP/public key prefix); unknown targets must not mis-match.
    #[test]
    fn resolve_dial_target_matches_name_ip_and_key_prefix() {
        let views = vec![DirectPeerView {
            name: "peer-b".into(),
            device_id: "d-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            public_key: "AbCdEfGh1234==".into(),
            mode: "hub_relay".into(),
            rtt_ms: None,
            rtt_source: None,
            endpoint: String::new(),
            last_handshake_at: None,
        }];
        assert_eq!(
            resolve_dial_target(&views, "peer-b").unwrap().name,
            "peer-b"
        );
        assert_eq!(
            resolve_dial_target(&views, "10.240.0.3").unwrap().name,
            "peer-b"
        );
        assert_eq!(
            resolve_dial_target(&views, "abcdefgh").unwrap().name,
            "peer-b"
        );
        assert!(resolve_dial_target(&views, "peer-c").is_none());
        assert!(resolve_dial_target(&views, "10.240.0.9").is_none());
    }

    /// Argumentless `peer dial`: the candidate table has a header and one row per node.
    #[test]
    fn format_dial_targets_lists_every_candidate() {
        let views = vec![DirectPeerView {
            name: "peer-b".into(),
            device_id: "d-b".into(),
            virtual_ipv4: "10.240.0.3".parse().unwrap(),
            public_key: "k==".into(),
            mode: "hub_relay".into(),
            rtt_ms: None,
            rtt_source: None,
            endpoint: String::new(),
            last_handshake_at: None,
        }];
        let text = format_dial_targets(&views);
        assert!(text.contains("NAME"));
        assert!(text.contains("peer-b"));
        assert!(text.contains("10.240.0.3"));
        assert!(text.contains("hub_relay"));
    }
}
