//! SSH alias 解析（hub 与 agent 共用同一实现，两端口径不漂移）。

/// SSH Host 别名三级来源解析：hub 显式覆写 > 节点真实主机名 >
/// meshlet peer name。返回的 alias 已 sanitize，来源字符串与计划/面板同口径。
pub fn resolve_alias(
    peer_name: &str,
    hostname: Option<&str>,
    hub_override: Option<&str>,
) -> (String, &'static str) {
    match hub_override.map(str::trim).filter(|s| !s.is_empty()) {
        Some(alias) => (sanitize_alias(alias), "hub-config"),
        None => match hostname.map(str::trim).filter(|s| !s.is_empty()) {
            Some(hostname) => (sanitize_alias(hostname), "hostname"),
            None => (sanitize_alias(peer_name), "peer-name"),
        },
    }
}

/// SSH Host 别名 sanitize：保留大小写，允许 `A-Za-z0-9._-`；其余字符转连
/// 字符，空名兜底 `node`。hub 与 agent 同一规则，保证下发段可直接渲染。
pub fn sanitize_alias(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "node".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use crate::ssh_alias;

    #[test]
    fn ssh_alias_prefers_hub_override_then_hostname_then_peer_name() {
        // 三级来源如实标注：hub 显式覆写 > 节点真实主机名 > peer name。
        let (alias, source) = ssh_alias::resolve_alias("win", Some("DESKTOP"), Some("wd"));
        assert_eq!((alias.as_str(), source), ("wd", "hub-config"));

        let (alias, source) = ssh_alias::resolve_alias("win", Some("DESKTOP"), None);
        assert_eq!((alias.as_str(), source), ("DESKTOP", "hostname"));

        let (alias, source) = ssh_alias::resolve_alias("win", None, None);
        assert_eq!((alias.as_str(), source), ("win", "peer-name"));

        // 空串/空白覆写与主机名都回落；非法字符 sanitize。
        let (alias, source) = ssh_alias::resolve_alias("win", Some("  "), Some("  "));
        assert_eq!((alias.as_str(), source), ("win", "peer-name"));
        let (alias, source) = ssh_alias::resolve_alias("win", Some("My PC"), None);
        assert_eq!((alias.as_str(), source), ("My-PC", "hostname"));
        assert_eq!(ssh_alias::sanitize_alias("  "), "node");
    }
}
