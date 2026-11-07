//! State file paths and local key loading.

use std::path::{Path, PathBuf};

use meshlet_config::DataplaneConfig;

pub(super) fn direct_ledger_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("direct.json")
}

pub(super) fn task_ledger_path(state_dir: &str) -> PathBuf {
    Path::new(state_dir).join("tasks.json")
}

/// 本设备私钥（ADR-010：只在本机文件里，服务端永不携带；未配置则保留接口现有私钥）。
pub fn read_private_key(dp: &DataplaneConfig) -> Result<Option<String>, String> {
    let Some(path) = dp
        .private_key_file
        .as_deref()
        .filter(|p| !p.trim().is_empty())
    else {
        return Ok(None);
    };
    let raw =
        std::fs::read_to_string(path).map_err(|e| format!("read private_key_file {path}: {e}"))?;
    let key = raw.trim().to_string();
    if key.is_empty() {
        return Err(format!("private_key_file {path} is empty"));
    }
    Ok(Some(key))
}
