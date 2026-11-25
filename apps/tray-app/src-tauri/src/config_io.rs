//! Local state/config paths and agent TOML read/write.

/// Local Meshlet state dir: `%LOCALAPPDATA%/meshlet/state` (matches the
/// `state_dir = %LOCALAPPDATA%\meshlet\state` written by `scripts/install.ps1`).
pub(crate) fn meshlet_state_dir() -> String {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into());
    state_dir_from_local(&local)
}

/// Local agent config path: `%LOCALAPPDATA%/meshlet/agent.toml` (the installer
/// `scripts/install.ps1` writes the config there; the frontend must read and write
/// the same path, or tray settings would diverge from the agent's actual config).
pub(crate) fn meshlet_config_path() -> String {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into());
    config_path_from_local(&local)
}

/// Pure path construction (testable): `<local>/meshlet/state`.
pub(crate) fn state_dir_from_local(local: &str) -> String {
    std::path::Path::new(local)
        .join("meshlet")
        .join("state")
        .to_string_lossy()
        .into_owned()
}

/// Pure path construction (testable): `<local>/meshlet/agent.toml`.
pub(crate) fn config_path_from_local(local: &str) -> String {
    std::path::Path::new(local)
        .join("meshlet")
        .join("agent.toml")
        .to_string_lossy()
        .into_owned()
}

/// Minimal TOML key=value parsing (flat; ignores section headers/comments):
/// same parsing rules as `get_config`; returns key → unquoted value.
pub(crate) fn parse_agent_toml(text: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            map.insert(
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            );
        }
    }
    map
}

/// Wrap a TOML string in quotes (escaping embedded double quotes).
pub(crate) fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

/// Pure config rebuild (testable): replaces only the settings-page-managed keys
/// (server_url/device_name/hub_endpoint/interface/enabled) and **keeps** the
/// agent-managed ones (state_dir/bootstrap_token/private_key_file/poll_interval_secs
/// etc.) — otherwise saving settings would drop the keys install.ps1 wrote and break the agent config.
pub(crate) fn rebuild_config(
    existing: &str,
    server_url: &str,
    device_name: &str,
    hub_endpoint: &str,
) -> String {
    let config = parse_agent_toml(existing);
    let mut out = String::new();
    let push = |out: &mut String, key: &str, value: &str| {
        out.push_str(&format!("{key} = {value}\n"));
    };
    push(&mut out, "server_url", &quote(server_url));
    if let Some(value) = config.get("state_dir") {
        push(&mut out, "state_dir", &quote(value));
    }
    if let Some(value) = config.get("bootstrap_token") {
        push(&mut out, "bootstrap_token", &quote(value));
    }
    push(&mut out, "device_name", &quote(device_name));
    out.push('\n');
    out.push_str("[dataplane]\n");
    out.push_str("enabled = true\n");
    // The real tunnel name is wg-meshlet per install.ps1/README (backend default meshlet),
    // no longer hardcoded as "WireGuard".
    out.push_str("interface = \"wg-meshlet\"\n");
    if let Some(value) = config.get("private_key_file") {
        push(&mut out, "private_key_file", &quote(value));
    }
    push(&mut out, "hub_endpoint", &quote(hub_endpoint));
    if let Some(value) = config.get("poll_interval_secs") {
        out.push_str(&format!("poll_interval_secs = {value}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_matches_install_script_convention() {
        let got = state_dir_from_local(r"C:\Users\bob\AppData\Local");
        assert!(got.contains("meshlet"));
        assert!(got.contains("state"));
        assert!(got.starts_with(r"C:\Users\bob\AppData\Local"));
    }

    #[test]
    fn config_path_matches_install_script_convention() {
        let got = config_path_from_local(r"C:\Users\bob\AppData\Local");
        assert!(got.contains("meshlet"));
        assert!(got.contains("agent.toml"));
        assert!(got.starts_with(r"C:\Users\bob\AppData\Local"));
    }

    #[test]
    fn save_config_preserves_agent_managed_keys() {
        // The settings page may only change server_url/device_name/interface/hub_endpoint; the other keys must survive.
        let existing = "server_url = \"https://old.example.com\"\n\
                        state_dir = \"C:\\\\Users\\\\bob\\\\AppData\\\\Local\\\\meshlet\\\\state\"\n\
                        bootstrap_token = \"bt-123\"\n\
                        device_name = \"old-name\"\n\
                        \n\
                        [dataplane]\n\
                        enabled = true\n\
                        interface = \"meshlet\"\n\
                        private_key_file = \"C:\\\\keys\\\\priv.key\"\n\
                        hub_endpoint = \"1.2.3.4:51820\"\n\
                        poll_interval_secs = 30\n";
        let rebuilt = rebuild_config(
            existing,
            "https://new.example.com",
            "new-name",
            "5.6.7.8:51820",
        );
        assert!(rebuilt.contains("server_url = \"https://new.example.com\""));
        assert!(rebuilt.contains("device_name = \"new-name\""));
        assert!(rebuilt.contains("hub_endpoint = \"5.6.7.8:51820\""));
        assert!(rebuilt.contains("interface = \"wg-meshlet\""));
        assert!(rebuilt.contains("state_dir"));
        assert!(rebuilt.contains("bootstrap_token"));
        assert!(rebuilt.contains("private_key_file"));
        assert!(rebuilt.contains("poll_interval_secs = 30"));
        assert!(!rebuilt.contains("\"WireGuard\""));
    }

    #[test]
    fn save_config_handles_missing_optional_keys() {
        let rebuilt = rebuild_config("", "https://x", "dev", "9.9.9.9:1");
        assert!(rebuilt.contains("server_url = \"https://x\""));
        assert!(rebuilt.contains("interface = \"wg-meshlet\""));
        assert!(!rebuilt.contains("state_dir"));
    }
}
