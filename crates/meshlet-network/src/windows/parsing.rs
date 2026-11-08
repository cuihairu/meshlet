/// 解析 `reg query IPEnableRouter` 输出为布尔（`0x1` → true、`0x0` → false，
/// 值缺失/其他 → None）。纯字符串判定：Windows 语言包不影响 `0x` 前缀。
pub(super) fn parse_ip_enable_router(text: &str) -> Option<bool> {
    if text.contains("0x1") {
        Some(true)
    } else if text.contains("0x0") {
        Some(false)
    } else {
        None
    }
}

/// 解析 `netsh interface ipv4 show addresses name=<if>` 输出中该接口的首个
/// IPv4 地址（BUG② 漂移判定的适配器地址读数；纯函数，跨平台单测）。
///
/// 行形如 en `   IP Address:                           10.240.0.7` 或
/// zh-CN `   IP 地址:                           10.240.0.7`——标签宽匹配
/// （`IP Address` / `IP 地址`），取行内最后一个可解析为 IPv4 的词元。
/// 「子网前缀」行的 `(masked …)` 不含独立 IPv4 词元、且匹配不到地址标签，
/// 不会误命中。读不到 → None。
pub(super) fn parse_netsh_interface_ipv4_address(text: &str) -> Option<std::net::Ipv4Addr> {
    for line in text.lines() {
        let is_address_label =
            line.to_ascii_lowercase().contains("ip address") || line.contains("IP 地址");
        if !is_address_label {
            continue;
        }
        if let Some(addr) = line
            .split_whitespace()
            .filter_map(|token| {
                token
                    .trim_end_matches(':')
                    .parse::<std::net::Ipv4Addr>()
                    .ok()
            })
            .next_back()
        {
            return Some(addr);
        }
    }
    None
}

pub(super) fn mask_to_prefix(mask: &str) -> u8 {
    let octets: Vec<u8> = mask.split('.').filter_map(|s| s.parse().ok()).collect();
    if octets.len() != 4 {
        return 0;
    }
    octets.iter().map(|b| b.count_ones() as u8).sum()
}

/// 从 Windows `ping` 输出解析首个 RTT（毫秒），支持英文 `time=1ms` 与
/// 中文 `时间=1ms`；无读数返回 `None`。
fn parse_ping_rtt_ms_windows(text: &str) -> Option<u128> {
    let marker = if text.contains("time") {
        "time"
    } else if text.contains("时间") {
        "时间"
    } else {
        return None;
    };
    let start = text.find(marker)?;
    let rest = &text[start + marker.len()..];
    let start = rest.find(|c: char| c.is_ascii_digit())?;
    let rest = &rest[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(rest.len());
    rest[..end].parse::<f64>().ok().map(|v| v.round() as u128)
}

/// 解析 `wg.exe show <name> dump` 的 peer 行为诊断读数（纯函数，任意平台
/// 单测）。官方格式为制表符分隔：首行接口，其后每行
/// `pubkey preshared endpoint allowed-ips latest-handshake transfer-rx
/// transfer-tx keepalive`。缺列按 0/空补。
fn parse_wg_dump_diag_line_windows(line: &str) -> Option<WgPeerDiagnostic> {
    let fields: Vec<&str> = line.split('\t').collect();
    let public_key = fields.first()?.trim();
    if public_key.is_empty() {
        return None;
    }
    let endpoint = fields.get(2).unwrap_or(&"").trim().to_string();
    let allowed_ips = fields.get(3).unwrap_or(&"").trim().to_string();
    let last_handshake: u64 = fields
        .get(4)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let rx_bytes: u64 = fields
        .get(6)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let tx_bytes: u64 = fields
        .get(7)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    Some(WgPeerDiagnostic {
        public_key: public_key.to_string(),
        endpoint,
        allowed_ips,
        last_handshake,
        rx_bytes,
        tx_bytes,
    })
}

/// 解析 `Get-NetIPConfiguration | ConvertTo-Json` 的接口清单（纯函数，任意
/// 平台单测）。输出为对象数组或单个对象；字段缺省按空/None 处理。
fn parse_windows_interfaces_json(text: &str) -> Vec<InterfaceDiagnostic> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let items: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return Vec::new(),
    };
    items
        .into_iter()
        .filter_map(|item| {
            let name = item.get("Name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                return None;
            }
            let ipv4 = item
                .get("IP")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let prefix = item.get("Prefix").and_then(|v| {
                v.as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| v.as_u64().and_then(|n| u8::try_from(n).ok()))
            });
            let state = item
                .get("State")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let mtu = item
                .get("Mtu")
                .and_then(|v| v.as_u64().and_then(|n| u32::try_from(n).ok()));
            Some(InterfaceDiagnostic {
                name: name.to_string(),
                ipv4,
                prefix,
                state,
                mtu,
            })
        })
        .collect()
}

/// Windows 局域网接口判定（§12 P2P 候选口径，镜像 Linux `is_lan_interface`）：
/// 排除本受管 wg 接口、回环、Hyper-V vEthernet、Tailscale 与其余 wg 接口；
/// ZeroTier 等私有网段**保留**（可路由的私有网段都是直连候选）。别名比对
/// 大小写不敏感（Windows 接口别名如 `Tailscale`、`vEthernet (WSL …)`）。
pub(super) fn is_windows_lan_interface(alias: &str, wg_interface: &str) -> bool {
    let lower = alias.to_ascii_lowercase();
    if alias == wg_interface || lower.starts_with("loopback") {
        return false;
    }
    for prefix in ["vethernet", "tailscale", "wg", "docker", "veth"] {
        if lower.starts_with(prefix) {
            return false;
        }
    }
    true
}

/// `Get-NetIPAddress … | ConvertTo-Json -Compress` 解析：`(别名, 地址, 前缀)`
/// 列表。PowerShell **单结果**输出对象、多结果输出数组——按 `Value` 统一归一
/// （[parse_windows_interfaces_json] 同惯例）。畸形行（缺字段/解析失败）
/// 逐条跳过，不吞掉整批读数。
pub(super) fn parse_lan_ip_json(text: &str) -> Result<Vec<(String, Ipv4Addr, u8)>, NetworkError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let value: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|error| NetworkError::ApplyRejected(format!("Get-NetIPAddress json: {error}")))?;
    let items: Vec<&serde_json::Value> = match &value {
        serde_json::Value::Array(arr) => arr.iter().collect(),
        serde_json::Value::Object(_) => vec![&value],
        _ => return Ok(Vec::new()),
    };
    Ok(items
        .into_iter()
        .filter_map(|item| {
            let alias = item.get("InterfaceAlias").and_then(|v| v.as_str())?;
            let addr: Ipv4Addr = item
                .get("IPAddress")
                .and_then(|v| v.as_str())?
                .parse()
                .ok()?;
            let prefix = item
                .get("PrefixLength")
                .and_then(|v| v.as_u64())
                .and_then(|n| u8::try_from(n).ok())?;
            Some((alias.to_string(), addr, prefix))
        })
        .collect())
}
