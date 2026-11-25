//! SSH alias resolution (hub and agent share one implementation so the two sides
//! never drift apart).

/// Three-tier SSH Host alias source resolution: explicit hub override > the
/// node's real hostname > meshlet peer name. The returned alias is sanitized,
/// and the source string matches what the plan/panel report.
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

/// SSH Host alias sanitizing: case is preserved and `A-Za-z0-9._-` is allowed;
/// any other character becomes a hyphen, and an empty name falls back to `node`.
/// Hub and agent apply the same rule so the distributed section renders as-is.
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
        // The three source tiers are labeled as-is: explicit hub override > the node's real hostname > peer name.
        let (alias, source) = ssh_alias::resolve_alias("win", Some("DESKTOP"), Some("wd"));
        assert_eq!((alias.as_str(), source), ("wd", "hub-config"));

        let (alias, source) = ssh_alias::resolve_alias("win", Some("DESKTOP"), None);
        assert_eq!((alias.as_str(), source), ("DESKTOP", "hostname"));

        let (alias, source) = ssh_alias::resolve_alias("win", None, None);
        assert_eq!((alias.as_str(), source), ("win", "peer-name"));

        // Empty/whitespace overrides and hostnames both fall through; illegal characters are sanitized.
        let (alias, source) = ssh_alias::resolve_alias("win", Some("  "), Some("  "));
        assert_eq!((alias.as_str(), source), ("win", "peer-name"));
        let (alias, source) = ssh_alias::resolve_alias("win", Some("My PC"), None);
        assert_eq!((alias.as_str(), source), ("My-PC", "hostname"));
        assert_eq!(ssh_alias::sanitize_alias("  "), "node");
    }
}
