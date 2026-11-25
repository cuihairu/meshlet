//! Bootstrap registration (ZeroTier-style): without a `device_token`, register this machine with the control center using a
//! bootstrap token, filing a **Pending** request to await approval or rejection.
//!
//! Lifecycle: first boot -> generate a local WireGuard keypair (private key written to a 0600 file, ADR-010:
//! the private key never leaves the device) -> `POST /api/v1/device-registrations` with the public key -> obtain the
//! agent credential (issued **this one time only**, written as 0600 `{state_dir}/device_token`) -> keep alive with
//! heartbeats during the pending-approval period (so the control center can see the device is alive) -> after
//! approval, enter the normal plan-fetch loop.
//!
//! Credential resolution order (first that resolves wins, no double registration):
//! 1. `device_token` from config (the invitation path, §11.2);
//! 2. the `{state_dir}/device_token` file (issued by an earlier bootstrap registration, reused across restarts);
//! 3. the bootstrap token `bootstrap_token` (the ZeroTier-style registration path, this module).

use std::path::{Path, PathBuf};

use meshlet_config::AgentConfig;
use meshlet_network::keys;

/// Agent credential file (issued by bootstrap registration, 0600; reused after a restart, never re-registered).
pub fn device_token_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("device_token")
}

/// Platform identifier (a registration-request field; shared with the server-side `Platform` enum).
fn platform_str() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// Resolve the device credential: config `device_token` -> credential file -> bootstrap registration.
/// Returns the config with the credential filled in (`device_token` in place).
pub fn resolve_device_token(config: AgentConfig) -> Result<AgentConfig, String> {
    if config
        .device_token
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
    {
        let token_path = device_token_path(&config.state_dir);
        if let Ok(saved) = std::fs::read_to_string(&token_path) {
            let saved = saved.trim();
            if !saved.is_empty() {
                tracing::info!(
                    path = %token_path.display(),
                    "using the saved agent token"
                );
                return Ok(with_token(config, saved.to_string()));
            }
        }
        let bootstrap = config
            .bootstrap_token
            .as_deref()
            .unwrap_or_default()
            .trim()
            .to_string();
        if bootstrap.is_empty() {
            return Err(
                "[dataplane] enabled but no device_token or bootstrap_token is configured \
                 (set agent.device_token, or agent.bootstrap_token + agent.device_name for \
                 self-registration)"
                    .into(),
            );
        }
        return register(config, &bootstrap);
    }
    Ok(config)
}

/// Bootstrap registration: keypair (private key written to disk as 0600) -> `POST /device-registrations` ->
/// credential file written (0600). Check the credential file before registering again
/// ([`resolve_device_token`]).
fn register(config: AgentConfig, bootstrap_token: &str) -> Result<AgentConfig, String> {
    let device_name = config.device_name.clone().ok_or(
        "agent.device_name must be configured for self-registration (it identifies the device \
         in the control center's approval queue)",
    )?;
    let key_file = config.dataplane.private_key_file.clone().ok_or(
        "agent.dataplane.private_key_file must be configured for self-registration (the \
             local private key is generated there, never sent to the server)",
    )?;

    // The local keypair: if the file already exists, derive the public key only (leave the private key alone - a
    // reinstall does not change the key); otherwise generate one and write it to disk.
    let (_private_key, public_key) = match std::fs::read_to_string(&key_file) {
        Ok(existing) => {
            let existing = existing.trim().to_string();
            let public = keys::public_from_private(&existing)?;
            (existing, public)
        }
        Err(_) => {
            let (private, public) = keys::generate_keypair()?;
            write_secret_file(Path::new(&key_file), &private)?;
            tracing::info!(path = %key_file, "generated the local wireguard keypair");
            (private, public)
        }
    };

    let resp = crate::server::register_device(
        &config.server_url,
        bootstrap_token,
        &device_name,
        &public_key,
        platform_str(),
    )?;
    tracing::info!(
        device_id = %resp.device_id,
        network_id = %resp.network_id,
        status = %resp.status,
        "self-registered: waiting for approval in the control center"
    );

    // The agent credential is issued this one time only: write it to the 0600 file immediately (reused after a restart, never re-registered).
    let token_path = device_token_path(&config.state_dir);
    if let Some(dir) = token_path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("create state dir {}: {e}", dir.display()))?;
    }
    write_secret_file(&token_path, &resp.agent_token)?;
    Ok(with_token(config, resp.agent_token))
}

fn with_token(mut config: AgentConfig, token: String) -> AgentConfig {
    config.device_token = Some(token);
    config
}

/// Write a 0600 secret file (credential / private key): tighten permissions, with a fallback to a default write on non-Unix platforms.
fn write_secret_file(path: &Path, content: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("open {}: {e}", path.display()))?;
        file.write_all(content.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_path_lives_in_state_dir() {
        assert_eq!(
            device_token_path("/var/lib/meshlet-agent"),
            PathBuf::from("/var/lib/meshlet-agent/device_token")
        );
    }

    #[test]
    fn platform_matches_server_enum() {
        // The server only accepts "linux" / "windows" (service::register_device).
        assert!(matches!(platform_str(), "linux" | "windows"));
    }

    #[test]
    fn missing_credentials_fail_with_guidance() {
        let config = AgentConfig {
            state_dir: "/tmp/meshlet-bootstrap-test/none".into(),
            ..AgentConfig::default()
        };
        let err = resolve_device_token(config).unwrap_err();
        assert!(err.contains("device_token or bootstrap_token"), "{err}");
    }

    #[test]
    fn existing_device_token_short_circuits() {
        let config = AgentConfig {
            device_token: Some("tok".into()),
            ..AgentConfig::default()
        };
        assert_eq!(
            resolve_device_token(config).unwrap().device_token,
            Some("tok".into())
        );
    }

    #[test]
    fn saved_device_token_short_circuits_registration() {
        let state_dir = std::env::temp_dir().join(format!(
            "meshlet-agent-token-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();
        let token_path = device_token_path(state_dir.to_str().unwrap());
        write_secret_file(&token_path, " saved-token \n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let config = AgentConfig {
            state_dir: state_dir.to_str().unwrap().into(),
            ..AgentConfig::default()
        };
        let resolved = resolve_device_token(config).unwrap();
        assert_eq!(resolved.device_token.as_deref(), Some("saved-token"));
        let _ = std::fs::remove_file(&token_path);
        let _ = std::fs::remove_dir(&state_dir);
    }

    #[test]
    fn self_registration_requires_key_and_name_before_network_call() {
        let state_dir = std::env::temp_dir().join(format!(
            "meshlet-agent-bootstrap-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&state_dir).unwrap();
        let config = AgentConfig {
            state_dir: state_dir.to_str().unwrap().into(),
            bootstrap_token: Some("bootstrap".into()),
            ..AgentConfig::default()
        };
        let error = resolve_device_token(config).unwrap_err();
        assert!(error.contains("device_name"), "{error}");
        let _ = std::fs::remove_dir(&state_dir);
    }
}
