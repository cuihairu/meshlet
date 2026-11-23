//! 本地状态/配置路径与 agent TOML 读写（M-SET-UX-01 无损写入）。
//!
//! 保存口径：只改设置页管理的三个键（顶层 `server_url`/`device_name`、
//! `[dataplane]` 下的 `hub_endpoint`），逐行外科手术式替换，**逐字节保留**
//! 注释、未知键、其他节与原有引号/空白语义。整体经「同目录临时文件 + rename」
//! 原子落盘：并发保存是整文件后写者胜，不会出现半新半旧的交错内容。

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

/// 设置页从磁盘读的三项（IPC 只回界面使用的字段，不外泄
/// bootstrap_token/private_key_file 等 agent 自管键）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UiConfig {
    pub(crate) server_url: String,
    pub(crate) device_name: String,
    pub(crate) hub_endpoint: String,
}

/// 拆「值 + 行内注释」：注释从引号外的第一个 `#` 开始。返回
/// `(值部分, 含 # 的注释部分)`。引号内 `#` 不是注释（TOML 语义）。
fn split_inline_comment(rest: &str) -> (&str, &str) {
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in rest.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            '#' if !in_string => return (&rest[..index], &rest[index..]),
            _ => {}
        }
    }
    (rest, "")
}

/// 解析引号字符串字面量（TOML basic string）：输入须以 `"` 开头，处理
/// `\"`/`\\` 转义；不是引号开头（裸值/数字等）返回 None，由调用方按原样
/// 保留。仅实现设置页会用到的转义子集；`\n`/`\t` 等在路径/URL/端点值里
/// 不出现，遇到时按字面保留原值不重写该行（写入口只在值变化时才动行）。
fn parse_basic_string(raw: &str) -> Option<String> {
    let rest = raw.trim_start();
    let rest = rest.strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.char_indices();
    while let Some((index, ch)) = chars.next() {
        match ch {
            '"' => return Some(out),
            '\\' => {
                let (_, esc) = chars.next()?;
                match esc {
                    'n' => out.push('\n'),
                    't' => out.push('\t'),
                    'r' => out.push('\r'),
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    other => {
                        // 未知转义：按 TOML 属非法。原样保留转义序列与
                        // 其后内容（含转义符），交由 agent 侧解析器裁决。
                        out.push('\\');
                        out.push(other);
                        // 回退：把已消费的 other 之后内容继续按字面复制。
                        let tail = &rest[index + 1 + other.len_utf8()..];
                        out.push_str(tail);
                        return Some(out);
                    }
                }
            }
            other => out.push(other),
        }
    }
    // 引号未闭合：损坏行，按 None 处理（读取面视为缺键、写入面拒绝重写）。
    None
}

/// 行分类（可测）：仅区分设置页需要的形态，其余原样保留。
#[derive(Debug, PartialEq, Eq)]
enum Line<'a> {
    /// `key = value`（当前节内）；value 含行内注释原样。
    KeyValue { key: &'a str, rest: &'a str },
    /// `[section]`；记录原始头整行。
    SectionHeader { name: String },
    /// 空行/注释/无法识别的行——写入时逐字节保留。
    Verbatim,
}

fn classify_line(line: &str) -> Option<Line<'_>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Some(Line::Verbatim);
    }
    if trimmed.starts_with('[') {
        let name = trimmed
            .strip_prefix('[')?
            .strip_suffix(']')?
            .trim()
            .trim_matches('"')
            .to_string();
        return Some(Line::SectionHeader { name });
    }
    let (key, rest) = trimmed.split_once('=')?;
    let key = key.trim();
    if key.is_empty() {
        return None;
    }
    Some(Line::KeyValue { key, rest })
}

/// 读设置页三键（可测）：`server_url`/`device_name` 取顶层，`hub_endpoint`
/// 取 `[dataplane]`（与 install.ps1 写入布局一致）。同键多处出现取**首个**
/// 命中（TOML 本不允许重复键，重复属损坏面，读首个与 agent 侧重叠）。
/// 缺键返回空串——表单置空由用户补填，保存时校验拦住。
pub(crate) fn read_ui_config(text: &str) -> UiConfig {
    let mut config = UiConfig {
        server_url: String::new(),
        device_name: String::new(),
        hub_endpoint: String::new(),
    };
    let mut section: Option<String> = None;
    for line in text.lines() {
        match classify_line(line) {
            Some(Line::SectionHeader { name }) => section = Some(name),
            Some(Line::KeyValue { key, rest }) => {
                let value = parse_basic_string(split_inline_comment(rest).0).unwrap_or_default();
                match (key, section.as_deref()) {
                    ("server_url", None) if config.server_url.is_empty() => {
                        config.server_url = value
                    }
                    ("device_name", None) if config.device_name.is_empty() => {
                        config.device_name = value
                    }
                    ("hub_endpoint", Some("dataplane")) if config.hub_endpoint.is_empty() => {
                        config.hub_endpoint = value
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    config
}

/// TOML 字符串引号包裹（转义内嵌双引号与反斜杠）。此前只转义引号，
/// 值里出现 `\` 时会产出非法 TOML（`C:\keys` 之类 Windows 路径）。
pub(crate) fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// 纯外科手术编辑（可测，M-SET-UX-01 核心）：只改三个受管键所在行，其余
/// 行逐字节保留（注释/未知键/其他节/空白）。被替换行保留原行内注释与原
/// 缩进。键缺失时插到正确位置：顶层键插到文件首个键值行前（无键值行则
/// 文件头），`hub_endpoint` 插到 `[dataplane]` 头之后（节不存在则追加）。
pub(crate) fn edit_managed_keys(
    existing: &str,
    server_url: &str,
    device_name: &str,
    hub_endpoint: &str,
) -> String {
    let mut section: Option<String> = None;
    let mut dataplane_header: Option<usize> = None;
    // 顶层区插入锚点：第一个键值行（在任何节头之前），或首个节头，或文件尾。
    let mut first_top_key: Option<usize> = None;
    let mut first_section_header: Option<usize> = None;
    // 已完成替换的受管键槽位（0=server_url 1=device_name 2=hub_endpoint）。
    let mut done = [false; 3];
    let mut edits: std::collections::BTreeMap<usize, String> = std::collections::BTreeMap::new();

    let lines: Vec<&str> = existing.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        match classify_line(line) {
            Some(Line::SectionHeader { name }) => {
                if name == "dataplane" && dataplane_header.is_none() {
                    dataplane_header = Some(index);
                }
                if first_section_header.is_none() {
                    first_section_header = Some(index);
                }
                section = Some(name);
            }
            Some(Line::KeyValue { key, rest }) => {
                if first_top_key.is_none() && section.is_none() {
                    first_top_key = Some(index);
                }
                let slot = match (key, section.as_deref()) {
                    ("server_url", None) => 0,
                    ("device_name", None) => 1,
                    ("hub_endpoint", Some("dataplane")) => 2,
                    _ => continue,
                };
                // 重复键只改首个，多余行原样保留交 agent 裁决。
                if done[slot] {
                    continue;
                }
                done[slot] = true;
                let value = match slot {
                    0 => server_url,
                    1 => device_name,
                    _ => hub_endpoint,
                };
                // 保留原行的缩进与「=」后空白、行内注释（含注释前的空格）。
                let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
                // rest 是「=」之后原文：值前空白 + 值 + 注释前空白 + 注释。
                let leading_ws = &rest[..rest.len() - rest.trim_start().len()];
                let (_, comment) = split_inline_comment(rest);
                // 值尾到 `#` 之间的空白（split_inline_comment 的注释切片从
                // `#` 起，需从原文补回其前空白）。
                let ws_before_comment = if comment.is_empty() {
                    String::new()
                } else {
                    let idx = rest.rfind(comment).unwrap_or(rest.len());
                    let trimmed = rest[..idx].trim_end();
                    rest[trimmed.len()..idx].to_string()
                };
                edits.insert(
                    index,
                    format!(
                        "{indent}{key} ={leading_ws}{}{ws_before_comment}{comment}",
                        quote(value)
                    ),
                );
            }
            _ => {}
        }
    }

    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 3);
    // 顶层键插入锚点：首个顶层键值行前（保持键组），否则首个节头前，
    // 否则文件尾。这样缺失的顶层键绝不会误落进某个节里。
    let top_insert_at = first_top_key.or(first_section_header);
    let mut inserted_top = false;
    let push_missing_top = |out: &mut Vec<String>, server_url: &str, device_name: &str| {
        if !done[0] {
            out.push(format!("server_url = {}", quote(server_url)));
        }
        if !done[1] {
            out.push(format!("device_name = {}", quote(device_name)));
        }
    };

    for (index, line) in lines.iter().enumerate() {
        if Some(index) == top_insert_at && !inserted_top && (!done[0] || !done[1]) {
            push_missing_top(&mut out, server_url, device_name);
            inserted_top = true;
        }
        match edits.get(&index) {
            Some(new_line) => out.push(new_line.clone()),
            None => out.push((*line).to_string()),
        }
    }
    // 无顶层键也无节（空文件/纯注释）：末尾追加。
    if !inserted_top && (!done[0] || !done[1]) {
        push_missing_top(&mut out, server_url, device_name);
    }

    // hub_endpoint 缺失：插到 `[dataplane]` 头之后；无该节则追加新节。
    if !done[2] {
        let hub_line = format!("hub_endpoint = {}", quote(hub_endpoint));
        match dataplane_header {
            Some(header) => {
                // 头行在 out 中的位置需按顶层插入行数修正（顶层插入锚点
                // 在节头之前时）。
                let shift = if top_insert_at.is_some_and(|at| header >= at) {
                    (!done[0]) as usize + (!done[1]) as usize
                } else {
                    0
                };
                out.insert(header + 1 + shift, hub_line);
            }
            None => {
                if out.last().is_some_and(|last| !last.trim().is_empty()) {
                    out.push(String::new());
                }
                out.push("[dataplane]".to_string());
                out.push(hub_line);
            }
        }
    }

    let mut result = out.join("\n");
    if existing.ends_with('\n') && !result.ends_with('\n') {
        result.push('\n');
    }
    if result.is_empty() && existing.is_empty() {
        // 空输入 + 全缺失：仍产出合法最小配置。
    }
    result
}

/// 保存错误（IPC 直达表单的 err 文案，不本地化，前端按语言包映射）。
#[derive(Debug)]
pub(crate) enum SaveError {
    /// 磁盘上没有 agent.toml：拒绝凭空创建（配置由 install.ps1 生成，
    /// 半份配置会让 agent 起不来）。
    Missing,
    Read(String),
    Write(String),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SaveError::Missing => write!(f, "agent config file not found"),
            SaveError::Read(e) => write!(f, "read agent config failed: {e}"),
            SaveError::Write(e) => write!(f, "write agent config failed: {e}"),
        }
    }
}

/// 读取-编辑-原子落盘（可注入路径以便测试）。原子性：同目录临时文件 +
/// `rename`（Windows 走 MoveFileEx REPLACE_EXISTING），崩溃/并发不产生
/// 半截文件；无写权限在临时文件创建或 rename 一步以 Err 浮出。
pub(crate) fn save_ui_config_at(
    path: &std::path::Path,
    server_url: &str,
    device_name: &str,
    hub_endpoint: &str,
) -> Result<(), SaveError> {
    let existing = std::fs::read_to_string(path).map_err(|error| match error.kind() {
        std::io::ErrorKind::NotFound => SaveError::Missing,
        _ => SaveError::Read(error.to_string()),
    })?;
    let content = edit_managed_keys(&existing, server_url, device_name, hub_endpoint);
    write_atomic(path, content.as_bytes()).map_err(|error| SaveError::Write(error.to_string()))
}

/// 同目录临时文件 + rename。临时名带随机后缀避免并发保存互踩。
fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let directory = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let temporary = directory.join(format!(
        "{}.tmp-{}",
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "agent.toml".into()),
        std::process::id()
    ));
    std::fs::write(&temporary, bytes)?;
    match std::fs::rename(&temporary, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            // rename 失败不留垃圾临时文件。
            let _ = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
}

/// 连接表单校验（可测，M-SET-UX-02 复用）：设备名非空；控制地址必须是
/// http(s) URL；Hub 端点必须是 `host:port`（host 允许 IPv6 带方括号），
/// 端口 1..=65535。通过返回 Ok，不通过返回给用户的说明键。
pub(crate) fn validate_connection(
    server_url: &str,
    device_name: &str,
    hub_endpoint: &str,
) -> Result<(), &'static str> {
    if device_name.trim().is_empty() {
        return Err("deviceNameRequired");
    }
    // 口径与 agent 侧 `AgentConfig::from_toml`（crates/meshlet-config/src/agent.rs:474）
    // 完全一致：只要求 http:// 或 https:// 前缀，不自造更严的 URL 解析，
    // 免得界面放行/拒绝与 agent 装载判定打架。
    if !(server_url.starts_with("http://") || server_url.starts_with("https://")) {
        return Err("serverUrlInvalid");
    }
    // 前缀之后必须还有主机部分（`https://` 光杆无主机不是有效控制地址）。
    let after_scheme = server_url
        .strip_prefix("https://")
        .or_else(|| server_url.strip_prefix("http://"))
        .unwrap_or_default();
    if after_scheme.trim().is_empty() {
        return Err("serverUrlInvalid");
    }
    validate_hub_endpoint(hub_endpoint)
}

/// Hub 端点校验（可测）：`host:port`，host 允许 IPv6 方括号形，端口
/// 1..=65535。host 非空即可（域名/IPv4/IPv6 由 agent 侧使用时再裁决）。
pub(crate) fn validate_hub_endpoint(hub_endpoint: &str) -> Result<(), &'static str> {
    let endpoint = hub_endpoint.trim();
    let (host, port) = match endpoint.rsplit_once(':') {
        Some((host, port)) if host.starts_with('[') && host.ends_with(']') => (host, port),
        Some((host, _port)) if host.matches(':').count() > 0 => {
            // 裸 IPv6 多冒号：rsplit_once 取到的 host 仍含冒号且无方括号，
            // 形如 `::1` 的合法裸 IPv6 端点写法不成立（必须有端口），整串
            // 视为缺端口。
            return Err("hubEndpointInvalid");
        }
        Some((host, port)) => (host, port),
        None => return Err("hubEndpointInvalid"),
    };
    let host = host.trim();
    let host_ok = if host.starts_with('[') {
        host.ends_with(']') && host.len() > 2
    } else {
        !host.is_empty() && !host.contains(char::is_whitespace)
    };
    if !host_ok {
        return Err("hubEndpointInvalid");
    }
    match port.parse::<u16>() {
        Ok(0) => Err("hubEndpointInvalid"),
        Ok(_) => Ok(()),
        Err(_) => Err("hubEndpointInvalid"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 01 验收夹具：注释、引号转义、附加节、自定义 dataplane 键。
    const FIXTURE: &str = "# agent 配置（安装脚本生成）\n\
        server_url = \"https://old.example.com\"  # 控制地址勿删\n\
        state_dir = \"C:\\\\Users\\\\bob\\\\AppData\\\\Local\\\\meshlet\\\\state\"\n\
        bootstrap_token = \"bt-\\\"quoted\\\"-123\"\n\
        device_name = \"old-name\"\n\
        poll_extra = 42\n\
        \n\
        [dataplane]\n\
        enabled = true\n\
        interface = \"wg-meshlet\" # 隧道名\n\
        private_key_file = \"C:\\\\keys\\\\priv.key\"\n\
        hub_endpoint = \"1.2.3.4:51820\"\n\
        tunnel_backend = \"nt\"\n\
        \n\
        [hub_failover]\n\
        index = 1\n";

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

    /// 01 验收核心：夹具仅改设备名，其余行逐字节不变。
    #[test]
    fn edit_only_device_name_keeps_everything_else_byte_identical() {
        let edited = edit_managed_keys(
            FIXTURE,
            "https://old.example.com",
            "new-name",
            "1.2.3.4:51820",
        );
        let before: Vec<&str> = FIXTURE.lines().collect();
        let after: Vec<&str> = edited.lines().collect();
        assert_eq!(before.len(), after.len(), "line count must not change");
        let mut changed = Vec::new();
        for (index, (old, new)) in before.iter().zip(after.iter()).enumerate() {
            if old != new {
                changed.push((index, *old, *new));
            }
        }
        assert_eq!(changed.len(), 1, "exactly one line changes: {changed:?}");
        let (index, old, new) = changed[0];
        assert!(old.contains("old-name"), "old line is device_name: {old}");
        assert!(new.contains("new-name"), "new line is device_name: {new}");
        // 行内注释跨行保留（其他行原样）。
        assert!(edited.contains("# 控制地址勿删"));
        assert!(edited.contains("interface = \"wg-meshlet\" # 隧道名"));
        assert!(edited.contains("tunnel_backend = \"nt\""));
        assert!(edited.contains("[hub_failover]"));
        assert!(edited.contains("poll_extra = 42"));
        assert!(edited.contains("bootstrap_token = \"bt-\\\"quoted\\\"-123\""));
        assert_eq!(index, 4, "device_name line index in fixture");
    }

    /// 三键全改：只有三行变化，注释/未知键仍在。
    #[test]
    fn edit_all_three_keys_changes_only_three_lines() {
        let edited = edit_managed_keys(
            FIXTURE,
            "https://new.example.com",
            "new-name",
            "5.6.7.8:51820",
        );
        let before: Vec<&str> = FIXTURE.lines().collect();
        let after: Vec<&str> = edited.lines().collect();
        let changed: Vec<usize> = before
            .iter()
            .zip(after.iter())
            .enumerate()
            .filter_map(|(index, (old, new))| (old != new).then_some(index))
            .collect();
        assert_eq!(changed, vec![1, 4, 11], "server/device/hub lines change");
        assert!(edited.contains("server_url = \"https://new.example.com\"  # 控制地址勿删"));
        assert!(edited.contains("hub_endpoint = \"5.6.7.8:51820\""));
    }

    /// 受管键缺失：插入正确位置，已有内容不动。
    /// 首个键值行是 `[dataplane]` 内的 `enabled`，故顶层键插在 `enabled`
    /// 前（即节头之前），hub 插在节头之后。
    #[test]
    fn insert_missing_keys_at_right_positions() {
        let existing = "# only a comment\n\n[dataplane]\nenabled = true\n";
        let edited = edit_managed_keys(existing, "https://x", "dev", "9.9.9.9:1");
        assert!(edited.contains("# only a comment"));
        assert!(edited.contains("server_url = \"https://x\"\ndevice_name = \"dev\"\n[dataplane]"));
        let after_header = edited.split("[dataplane]\n").nth(1).unwrap();
        assert!(after_header.starts_with("hub_endpoint = \"9.9.9.9:1\""));
        assert!(edited.contains("enabled = true"));
    }

    /// `[dataplane]` 节整个缺失：追加新节，不污染顶层。
    #[test]
    fn append_dataplane_section_when_missing() {
        let edited = edit_managed_keys("device_name = \"d\"\n", "https://x", "d", "1.2.3.4:51820");
        assert!(edited.contains("[dataplane]\nhub_endpoint = \"1.2.3.4:51820\""));
        let head_end = edited.find("[dataplane]").unwrap();
        assert!(!edited[..head_end].contains("hub_endpoint"));
    }

    /// 引号语义：新值内嵌引号/反斜杠被转义后再落盘。
    #[test]
    fn quote_escapes_quotes_and_backslashes() {
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    /// 读面：三键按节取值，附加节不串。
    #[test]
    fn read_ui_config_reads_three_keys_by_section() {
        let config = read_ui_config(FIXTURE);
        assert_eq!(config.server_url, "https://old.example.com");
        assert_eq!(config.device_name, "old-name");
        assert_eq!(config.hub_endpoint, "1.2.3.4:51820");
    }

    /// 读面：值里带行内注释不串进值。
    #[test]
    fn read_strips_inline_comment() {
        let config = read_ui_config("device_name = \"d\" # note\n");
        assert_eq!(config.device_name, "d");
    }

    /// 引号内 `#` 不是注释。
    #[test]
    fn read_keeps_hash_inside_quotes() {
        let config = read_ui_config("device_name = \"a#b\"\n");
        assert_eq!(config.device_name, "a#b");
    }

    /// 损坏行（未闭合引号）：读面按空值、其余键照常。
    #[test]
    fn read_tolerates_broken_line() {
        let config = read_ui_config("device_name = \"unclosed\nserver_url = \"https://x\"\n");
        assert_eq!(config.device_name, "");
        assert_eq!(config.server_url, "https://x");
    }

    /// 原子保存端到端（临时目录）：改前后只差受管行。
    #[test]
    fn save_roundtrip_edits_only_managed_lines() {
        let directory =
            std::env::temp_dir().join(format!("meshlet-tray-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.toml");
        std::fs::write(&path, FIXTURE).unwrap();
        save_ui_config_at(&path, "https://old.example.com", "renamed", "1.2.3.4:51820").unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("device_name = \"renamed\""));
        assert!(after.contains("private_key_file"));
        assert!(after.contains("[hub_failover]"));
        // 无临时文件残留。
        let leftovers: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "no temp files left: {leftovers:?}");
        std::fs::remove_dir_all(&directory).ok();
    }

    /// 原文件缺失：拒绝保存（不凭空创建半份配置）。
    #[test]
    fn save_fails_when_config_missing() {
        let directory =
            std::env::temp_dir().join(format!("meshlet-tray-missing-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("agent.toml");
        let error = save_ui_config_at(&path, "https://x", "d", "1.2.3.4:51820").unwrap_err();
        assert!(matches!(error, SaveError::Missing));
        std::fs::remove_dir_all(&directory).ok();
    }

    /// 无写权限/路径是目录：写错误浮出，不静默。
    #[test]
    fn save_surfaces_write_errors() {
        let directory =
            std::env::temp_dir().join(format!("meshlet-tray-dir-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        // 路径本身是目录：read 报错（非 NotFound → Read）。
        let error = save_ui_config_at(&directory, "https://x", "d", "1.2.3.4:51820").unwrap_err();
        assert!(matches!(error, SaveError::Read(_)) || matches!(error, SaveError::Write(_)));
        std::fs::remove_dir_all(&directory).ok();
    }

    // ── 02 校验夹具：HTTPS / 自定义端口 / IPv6 / 无改动 / 错误 ──

    #[test]
    fn validate_accepts_https_and_custom_port() {
        assert!(
            validate_connection("https://mesh.example:8443", "dev", "hub.example:51820").is_ok()
        );
        assert!(validate_connection("http://10.0.0.1", "dev", "10.0.0.2:51820").is_ok());
    }

    #[test]
    fn validate_accepts_ipv6_bracket_endpoint() {
        assert!(validate_connection("https://x.example", "dev", "[2001:db8::1]:51820").is_ok());
        assert!(validate_hub_endpoint("[::1]:9").is_ok());
    }

    #[test]
    fn validate_rejects_bad_server_urls() {
        assert_eq!(
            validate_connection("ftp://x", "dev", "h:1"),
            Err("serverUrlInvalid")
        );
        assert_eq!(
            validate_connection("not a url", "dev", "h:1"),
            Err("serverUrlInvalid")
        );
        assert_eq!(
            validate_connection("", "dev", "h:1"),
            Err("serverUrlInvalid")
        );
    }

    #[test]
    fn validate_rejects_empty_device_name() {
        assert_eq!(
            validate_connection("https://x", "  ", "h:1"),
            Err("deviceNameRequired")
        );
        assert_eq!(
            validate_connection("https://x", "", "h:1"),
            Err("deviceNameRequired")
        );
    }

    #[test]
    fn validate_rejects_bad_endpoints() {
        assert_eq!(
            validate_connection("https://x", "d", "no-port"),
            Err("hubEndpointInvalid")
        );
        assert_eq!(
            validate_connection("https://x", "d", "h:0"),
            Err("hubEndpointInvalid")
        );
        assert_eq!(
            validate_connection("https://x", "d", "h:99999"),
            Err("hubEndpointInvalid")
        );
        assert_eq!(
            validate_connection("https://x", "d", "h:abc"),
            Err("hubEndpointInvalid")
        );
        assert_eq!(
            validate_connection("https://x", "d", ""),
            Err("hubEndpointInvalid")
        );
        // 裸 IPv6 无方括号缺端口：rsplit 取到的「host」仍含冒号 → 拒。
        assert_eq!(
            validate_connection("https://x", "d", "::1"),
            Err("hubEndpointInvalid")
        );
        // 空方括号拒。
        assert_eq!(
            validate_connection("https://x", "d", "[]:1"),
            Err("hubEndpointInvalid")
        );
    }

    /// 编辑器幂等：同一输入连改两次，第二次零行变化。
    #[test]
    fn edit_is_idempotent() {
        let once = edit_managed_keys(FIXTURE, "https://n.example", "n", "5.6.7.8:51820");
        let twice = edit_managed_keys(&once, "https://n.example", "n", "5.6.7.8:51820");
        assert_eq!(once, twice);
    }

    /// 尾换行保留：原文件无尾换行时替换行不引入额外空行。
    #[test]
    fn trailing_newline_is_preserved() {
        let no_newline =
            "server_url = \"a\"\ndevice_name = \"d\"\n[dataplane]\nhub_endpoint = \"h:1\"";
        let edited = edit_managed_keys(no_newline, "b", "d", "h:1");
        // 原文件无尾换行 → 输出也不补（逐字节保真）。
        assert!(edited.ends_with("hub_endpoint = \"h:1\""));
        assert!(!edited.ends_with('\n'));
        // 原文件有尾换行 → 输出保留单个尾换行，不叠加空行。
        let with_newline = format!("{no_newline}\n");
        let edited = edit_managed_keys(&with_newline, "b", "d", "h:1");
        assert!(edited.ends_with('\n'));
        assert!(!edited.ends_with("\n\n"));
    }
}
