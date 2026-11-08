//! 本地状态/配置路径与 agent TOML 读写。

/// 本机 Meshlet 状态目录：`%LOCALAPPDATA%/meshlet/state`（与安装脚本
/// `scripts/install.ps1` 生成 `state_dir = %LOCALAPPDATA%\meshlet\state` 一致）。
pub(crate) fn meshlet_state_dir() -> String {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into());
    state_dir_from_local(&local)
}

/// 本机 agent 配置路径：`%LOCALAPPDATA%/meshlet/agent.toml`（安装脚本
/// `scripts/install.ps1` 把配置写到该路径；前端读写必须与之一致，否则
/// 托盘设置的保存/读取与 agent 实际配置脱节）。
pub(crate) fn meshlet_config_path() -> String {
    let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into());
    config_path_from_local(&local)
}

/// 纯路径构造（可测）：`<local>/meshlet/state`。
pub(crate) fn state_dir_from_local(local: &str) -> String {
    std::path::Path::new(local)
        .join("meshlet")
        .join("state")
        .to_string_lossy()
        .into_owned()
}

/// 纯路径构造（可测）：`<local>/meshlet/agent.toml`。
pub(crate) fn config_path_from_local(local: &str) -> String {
    std::path::Path::new(local)
        .join("meshlet")
        .join("agent.toml")
        .to_string_lossy()
        .into_owned()
}

/// 简单 TOML 键值解析（扁平，忽略 section 头/注释）：与 `get_config` 同解析
/// 口径；返回 键→去引号后的值。
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

/// TOML 字符串引号包裹（转义内嵌双引号）。
pub(crate) fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\\\""))
}

/// 纯配置重建（可测）：只替换设置页管理的键（server_url/device_name/
/// hub_endpoint/interface/enabled），**保留** agent 自行管理的键
/// （state_dir/bootstrap_token/private_key_file/poll_interval_secs 等）——
/// 否则保存设置会丢掉 install.ps1 写入的键，破坏 agent 配置。
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
    // 实际隧道名按 install.ps1/README 为 wg-meshlet（后端默认 meshlet），
    // 不再写死 "WireGuard"。
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
        // 设置页只该改 server_url/device_name/interface/hub_endpoint，不得丢其余键。
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
