//! Agent self-update：manifest 拉取 → SHA-256 校验 → 原子落盘 → 替换本进程
//! 二进制 → 标记 systemd/ supervisor 重启。

use semver::Version;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::server;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct UpdateManifest {
    pub version: String,
    pub url: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdatePlan {
    pub current_version: Version,
    pub target_version: Version,
    pub url: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateCheck {
    Current,
    Available(UpdatePlan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallResult {
    pub from_version: Version,
    pub to_version: Version,
    pub binary_path: PathBuf,
    pub restart_requested: bool,
}

pub fn fetch_manifest(server_url: &str) -> Result<UpdateManifest, String> {
    let url = format!(
        "{}/api/v1/update-manifest",
        server_url.trim_end_matches('/')
    );
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build();
    let body = server::read_public(agent.get(&url).call())?;
    serde_json::from_str(&body).map_err(|e| format!("parse update manifest: {e}"))
}

pub fn download_binary(
    url: &str,
    expected_sha256: &str,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let expected = normalize_sha256(expected_sha256)?;
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(300))
        .build();
    let response = agent
        .get(url)
        .call()
        .map_err(|e| format!("download update: {e}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(timeout.as_secs().saturating_mul(8 * 1024 * 1024))
        .read_to_end(&mut body)
        .map_err(|e| format!("read update body: {e}"))?;
    let actual = sha256_hex(&body);
    if actual != expected {
        return Err(format!(
            "update sha256 mismatch: expected {expected}, got {actual}"
        ));
    }
    Ok(body)
}

pub fn plan_update(current_version: &str, manifest: UpdateManifest) -> Result<UpdateCheck, String> {
    let current =
        Version::parse(current_version).map_err(|e| format!("parse current agent version: {e}"))?;
    let target =
        Version::parse(&manifest.version).map_err(|e| format!("parse update version: {e}"))?;
    if target <= current {
        return Ok(UpdateCheck::Current);
    }
    Ok(UpdateCheck::Available(UpdatePlan {
        current_version: current,
        target_version: target,
        url: manifest.url,
        sha256: manifest.sha256,
    }))
}

pub fn install(plan: &UpdatePlan) -> Result<InstallResult, String> {
    let body = download_binary(&plan.url, &plan.sha256, Duration::from_secs(300))?;
    let current = current_binary()?;
    install_binary(&current, &body)?;
    Ok(InstallResult {
        from_version: plan.current_version.clone(),
        to_version: plan.target_version.clone(),
        binary_path: current,
        restart_requested: true,
    })
}

fn current_binary() -> Result<PathBuf, String> {
    std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|e| format!("resolve current executable: {e}"))
}

fn install_binary(binary: &Path, body: &[u8]) -> Result<(), String> {
    let directory = binary
        .parent()
        .ok_or_else(|| format!("executable has no parent: {}", binary.display()))?;
    std::fs::create_dir_all(directory)
        .map_err(|e| format!("create update stage directory {}: {e}", directory.display()))?;
    let stage = directory.join(format!(
        ".{}.update",
        binary
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("meshlet-agent")
    ));
    write_secret(&stage, body)?;
    let backup = directory.join(format!(
        "{}.previous",
        binary
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("meshlet-agent")
    ));
    if binary.exists() {
        std::fs::copy(binary, &backup).map_err(|e| format!("back up old binary: {e}"))?;
    }
    std::fs::rename(&stage, binary).map_err(|e| {
        let _ = std::fs::remove_file(&stage);
        format!("replace executable {}: {e}", binary.display())
    })?;
    Ok(())
}

fn write_secret(path: &Path, content: &[u8]) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(path)
            .map_err(|e| format!("create stage {}: {e}", path.display()))?;
        file.write_all(content)
            .map_err(|e| format!("write stage {}: {e}", path.display()))?;
        file.sync_all()
            .map_err(|e| format!("sync stage {}: {e}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    std::fs::write(path, content).map_err(|e| format!("write stage {}: {e}", path.display()))
}

pub fn request_restart(state_dir: &str, result: &InstallResult) -> Result<PathBuf, String> {
    let marker = restart_marker_path(state_dir);
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create update state directory {}: {e}", parent.display()))?;
    }
    let payload = serde_json::json!({
        "from_version": result.from_version.to_string(),
        "to_version": result.to_version.to_string(),
        "binary_path": result.binary_path,
        "backup_path": result.binary_path.with_file_name(format!(
            "{}.previous",
            result
                .binary_path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .unwrap_or("meshlet-agent")
        )),
    })
    .to_string();
    std::fs::write(&marker, payload)
        .map_err(|e| format!("write restart marker {}: {e}", marker.display()))?;
    Ok(marker)
}

pub fn restart_marker_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("restart-requested.json")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn normalize_sha256(value: &str) -> Result<String, String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!("invalid update sha256: {value:?}"));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn manifest() -> UpdateManifest {
        UpdateManifest {
            version: "0.2.0".into(),
            url: "https://example.com/meshlet-agent".into(),
            sha256: format!("{:x}", Sha256::digest(b"binary")),
        }
    }

    #[test]
    fn semantic_version_update_selects_strictly_newer_manifest() {
        assert_eq!(
            plan_update("0.1.0", manifest()).unwrap(),
            UpdateCheck::Available(UpdatePlan {
                current_version: "0.1.0".parse().unwrap(),
                target_version: "0.2.0".parse().unwrap(),
                url: "https://example.com/meshlet-agent".into(),
                sha256: manifest().sha256,
            })
        );
        assert_eq!(
            plan_update("0.2.0", manifest()).unwrap(),
            UpdateCheck::Current
        );
        assert_eq!(
            plan_update("0.3.0", manifest()).unwrap(),
            UpdateCheck::Current
        );
    }

    #[test]
    fn invalid_version_or_hash_fails_closed() {
        assert!(plan_update("not-semver", manifest()).is_err());
        let bad = UpdateManifest {
            version: "x".into(),
            ..manifest()
        };
        assert!(plan_update("0.1.0", bad).is_err());
        assert!(download_binary("http://127.0.0.1:1", "bad", Duration::from_secs(1)).is_err());
    }

    #[test]
    fn download_rejects_modified_payload() {
        let digest = format!("{:x}", Sha256::digest(b"expected"));
        let mut response = fake_response(b"tampered");
        let actual = sha256_hex(&response);
        assert_ne!(actual, digest);
        assert!(download_binary("http://127.0.0.1:1", &digest, Duration::from_secs(1)).is_err());
        response.clear();
    }

    fn fake_response(body: &[u8]) -> Vec<u8> {
        let mut value = Vec::new();
        value.write_all(body).unwrap();
        value
    }

    #[test]
    fn install_prepares_atomic_rename_backup_and_restart_marker() {
        let root = std::env::temp_dir().join(format!(
            "meshlet-self-update-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let binary = root.join("meshlet-agent");
        std::fs::write(&binary, b"old").unwrap();
        let plan = UpdatePlan {
            current_version: "0.1.0".parse().unwrap(),
            target_version: "0.2.0".parse().unwrap(),
            url: "unused".into(),
            sha256: format!("{:x}", Sha256::digest(b"new")),
        };
        let temp = std::env::temp_dir();
        let stage = binary.with_file_name(".meshlet-agent.update");
        install_binary(&binary, b"new").unwrap();
        let result = InstallResult {
            from_version: plan.current_version.clone(),
            to_version: plan.target_version.clone(),
            binary_path: binary.clone(),
            restart_requested: true,
        };
        let marker = request_restart(root.to_str().unwrap(), &result).unwrap();
        assert_eq!(std::fs::read(&binary).unwrap(), b"new");
        assert_eq!(
            std::fs::read(binary.with_file_name("meshlet-agent.previous")).unwrap(),
            b"old"
        );
        assert!(!stage.exists());
        assert_eq!(marker, restart_marker_path(root.to_str().unwrap()));
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&marker).unwrap()).unwrap();
        assert_eq!(saved["to_version"], "0.2.0");
        let _ = std::fs::remove_dir_all(root);
        let _ = temp;
    }
}
