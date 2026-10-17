//! 自举注册（ZeroTier 式）：无 `device_token` 时持自举码向控制中心注册自身，
//! 落 **Pending** 申请，等控制中心批准/拒绝。
//!
//! 生命周期：首启 → 生成本机 WireGuard 密钥对（私钥落 0600 文件，ADR-010：
//! 私钥不出设备）→ `POST /api/v1/device-registrations` 上报公钥 → 拿到
//! agent 凭证（**仅此一次**下发，写 0600 `{state_dir}/device_token`）→
//! 待审批期心跳保活（控制中心能看到设备活着）→ 批准后转入正常拉计划循环。
//!
//! 凭证解析顺序（先到先用，不重复注册）：
//! 1. 配置里的 `device_token`（邀请入会路径，§11.2）；
//! 2. `{state_dir}/device_token` 文件（此前自举注册已签发，重启复用）；
//! 3. 自举码 `bootstrap_token`（ZeroTier 式注册路径，本模块）。

use std::path::{Path, PathBuf};

use meshlet_config::AgentConfig;
use meshlet_network::keys;

/// agent 凭证文件（自举注册签发，0600；重启后复用，不重复注册）。
pub fn device_token_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("device_token")
}

/// 平台标识（注册请求字段；与服务端 `Platform` 枚举同源）。
fn platform_str() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else {
        "linux"
    }
}

/// 解析设备凭证：配置 `device_token` → 凭证文件 → 自举注册。
/// 返回补齐凭证后的配置（`device_token` 就位）。
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

/// 自举注册：密钥对（私钥 0600 落盘）→ `POST /device-registrations` →
/// 凭证文件落盘（0600）。重复注册前先查凭证文件（[`resolve_device_token`]）。
fn register(config: AgentConfig, bootstrap_token: &str) -> Result<AgentConfig, String> {
    let device_name = config.device_name.clone().ok_or(
        "agent.device_name must be configured for self-registration (it identifies the device \
         in the control center's approval queue)",
    )?;
    let key_file = config.dataplane.private_key_file.clone().ok_or(
        "agent.dataplane.private_key_file must be configured for self-registration (the \
             local private key is generated there, never sent to the server)",
    )?;

    // 本机密钥对：文件已存在则只推导公钥（私钥不动——重装不换钥匙）；
    // 不存在则生成并落盘。
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

    // agent 凭证仅此一次下发：立即落 0600 文件（重启复用，不重复注册）。
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

/// 写 0600 秘密文件（凭证/私钥）：权限收紧，非 Unix 平台退回默认写。
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
        // 服务端只认 "linux" / "windows"（service::register_device）。
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
