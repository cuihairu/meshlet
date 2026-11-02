//! Windows 系统托盘宿主：消费 [TraySink] 的 PNG 状态图。
//!
//! 监听 agent 写出的 `status.json` + `icon-*.png`，通过 `Shell_NotifyIcon`
//! 在系统托盘显示当前状态。状态变化即换图，无需轮询。
//!
//! 用法：`meshlet-tray-host <state_dir>`

#[cfg(windows)]
use std::sync::atomic::{AtomicIsize, AtomicPtr, Ordering};
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, HWND, INVALID_HANDLE_VALUE, LPARAM, LRESULT, POINT, RECT, WPARAM,
};
#[cfg(windows)]
use windows_sys::Win32::Graphics::Gdi::*;
#[cfg(windows)]
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::{
    ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
    NIM_MODIFY, NOTIFYICONDATAW,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// 右键菜单命令 ID（`TPM_RETURNCMD` 下 `TrackPopupMenuEx` 的返回值）。
#[cfg(windows)]
const CMD_QUIT: usize = 1;
#[cfg(windows)]
const CMD_OPEN_PANEL: usize = 2;
/// 「连接状态」展示项（禁用态，文本随 `status.json` 的 state 更新）。
#[cfg(windows)]
const CMD_STATUS: usize = 3;
/// 托盘回调之外的第二内部消息：agent 进程已死，托盘随之退出（④）。
#[cfg(windows)]
const WM_TRAY_EXIT: u32 = WM_APP + 2;
/// agent 可执行名（`install.ps1` 装到 `%LOCALAPPDATA%\meshlet` 的二进制）。
#[cfg(any(windows, test))]
const AGENT_EXE: &str = "meshlet-agent.exe";
/// agent 进程探测轮询间隔。
#[cfg(windows)]
const AGENT_POLL: std::time::Duration = std::time::Duration::from_secs(2);
/// agent 首次现身前的宽限轮数（~30s）：`tray_dir` 已存在说明 agent 至少写过
/// 一次状态，进程枚举仍未命中则大概率已死，托盘不留孤儿图标。
#[cfg(windows)]
const FIRST_SIGHT_POLLS: u32 = 15;
/// agent 死后（已见过）持续缺席的轮数（~6s）→ 托盘退出。
#[cfg(windows)]
const GONE_POLLS: u32 = 3;

/// 全局状态，供窗口过程访问。
#[cfg(windows)]
static G_HWND: AtomicIsize = AtomicIsize::new(0);
#[cfg(windows)]
static G_NID: AtomicPtr<NOTIFYICONDATAW> = AtomicPtr::new(std::ptr::null_mut());
#[cfg(windows)]
static G_MENU: AtomicIsize = AtomicIsize::new(0);
#[cfg(windows)]
static G_EXIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// agent 状态目录（「打开面板」据此定位 agent.toml / config.toml）。
#[cfg(windows)]
static G_STATE_DIR: std::sync::OnceLock<&'static std::path::Path> = std::sync::OnceLock::new();

#[cfg(windows)]
fn main() {
    use std::path::PathBuf;

    let args: Vec<String> = std::env::args().collect();
    let state_dir = args.get(1).map(PathBuf::from).unwrap_or_else(|| {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| "C:/Users/Public".into());
        PathBuf::from(local).join("meshlet").join("state")
    });
    let tray_dir = state_dir.join("tray");
    let status_path = tray_dir.join("status.json");

    eprintln!("meshlet-tray-host: watching {}", tray_dir.display());

    while !tray_dir.exists() {
        std::thread::sleep(std::time::Duration::from_secs(2));
    }

    // 「打开面板」需要 agent 配置文件（`{state_dir}/..` 下）里的 server_url。
    let _ = G_STATE_DIR.set(Box::leak(state_dir.into_boxed_path()));

    unsafe {
        let class_name: Vec<u16> = "MeshletTrayHost\0".encode_utf16().collect();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(tray_wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: GetModuleHandleW(std::ptr::null()),
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class_name.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        RegisterClassExW(&wc);

        let hwnd = CreateWindowExW(
            0,
            class_name.as_ptr(),
            std::ptr::null(),
            0,
            0,
            0,
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        );
        eprintln!("meshlet-tray-host: hwnd={hwnd:p}");
        G_HWND.store(hwnd as isize, Ordering::SeqCst);

        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_APP + 1;
        nid.hIcon = load_status_icon(&status_path)
            .map(|(w, h, rgba)| rgba_to_icon(&rgba, w, h))
            .unwrap_or_else(create_green_icon);
        eprintln!("meshlet-tray-host: hIcon={:p}", nid.hIcon);
        let tip: Vec<u16> = "Meshlet\0".encode_utf16().collect();
        for (i, &w) in tip.iter().enumerate().take(127) {
            nid.szTip[i] = w;
        }
        let ok = Shell_NotifyIconW(NIM_ADD, &nid);
        eprintln!("meshlet-tray-host: NIM_ADD = {ok}");

        let hmenu = CreatePopupMenu();
        // 连接状态（禁用展示项）：文本随 status.json 的 state 更新，见 update_tray。
        let status_text: Vec<u16> = "Meshlet\0".encode_utf16().collect();
        AppendMenuW(
            hmenu,
            MF_STRING | MF_GRAYED,
            CMD_STATUS,
            status_text.as_ptr(),
        );
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
        let panel_text: Vec<u16> = "打开面板\0".encode_utf16().collect();
        AppendMenuW(hmenu, MF_STRING, CMD_OPEN_PANEL, panel_text.as_ptr());
        AppendMenuW(hmenu, MF_SEPARATOR, 0, std::ptr::null());
        let exit_text: Vec<u16> = "退出\0".encode_utf16().collect();
        AppendMenuW(hmenu, MF_STRING, CMD_QUIT, exit_text.as_ptr());
        G_NID.store(&mut nid as *mut _, Ordering::SeqCst);
        G_MENU.store(hmenu as isize, Ordering::SeqCst);

        // 启动时立即读取当前状态并应用图标
        update_tray(&status_path, &mut nid);

        // ④ agent 进程联动：agent 退出 → 托盘消失（watchdog 轮询进程名）。
        spawn_agent_watchdog(hwnd);

        // 文件监听放独立线程，主循环专心处理消息
        let watch_path = status_path.clone();
        std::thread::spawn(move || {
            let mut last_mtime: Option<std::time::SystemTime> = None;
            loop {
                if G_EXIT.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(meta) = std::fs::metadata(&watch_path) {
                    if let Ok(mtime) = meta.modified() {
                        if last_mtime.is_none_or(|old| mtime > old) {
                            last_mtime = Some(mtime);
                            let nid_ptr = G_NID.load(Ordering::SeqCst);
                            if !nid_ptr.is_null() {
                                update_tray(&watch_path, &mut *nid_ptr);
                            }
                        }
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(500));
            }
        });

        // 阻塞消息循环
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        eprintln!("meshlet-tray-host: message loop exited");
    }
}

/// 将 RGBA 像素缓冲转为 HICON（含透明通道）。
#[cfg(windows)]
fn rgba_to_icon(rgba: &[u8], width: u32, height: u32) -> HICON {
    use windows_sys::Win32::Foundation::HWND;

    unsafe {
        let hdc = GetDC(0 as HWND);
        let mem_dc = CreateCompatibleDC(hdc);
        let bmp = CreateCompatibleBitmap(hdc, width as i32, height as i32);
        let old = SelectObject(mem_dc, bmp);

        // SetDIBits 需要 BITMAPINFO
        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = width as i32;
        bmi.bmiHeader.biHeight = -(height as i32); // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = 0; // BI_RGB

        SetDIBits(mem_dc, bmp, 0, height, rgba.as_ptr() as *const _, &bmi, 0);

        SelectObject(mem_dc, old as isize as _);

        let mut ii: ICONINFO = std::mem::zeroed();
        ii.fIcon = 1;
        ii.hbmColor = bmp;
        ii.hbmMask = CreateCompatibleBitmap(hdc, width as i32, height as i32);
        let icon = CreateIconIndirect(&ii);

        DeleteObject(ii.hbmMask as isize as _);
        DeleteObject(bmp as isize as _);
        DeleteDC(mem_dc);
        ReleaseDC(0 as HWND, hdc);

        icon
    }
}

/// 读取 `status.json` 声明的托盘 PNG 并解码为 RGBA（优先 `icon_24`，回退
/// `icon_16`——Windows 任务栏小图标随 DPI 缩放，24px 在常见 DPI 下更接近）。
///
/// 图标内容完全来自 [TraySink] 写出的 PNG（四态轮廓互异，见 tray.rs 的
/// `tray_state_silhouettes_are_pairwise_distinct`），宿主不做状态→图标映射
/// ——状态已编码在像素里，换图即换状态。
#[cfg(any(windows, test))]
fn load_status_icon(status_path: &std::path::Path) -> Option<(u32, u32, Vec<u8>)> {
    let text = std::fs::read_to_string(status_path).ok()?;
    let status: serde_json::Value = serde_json::from_str(&text).ok()?;
    let parent = status_path.parent()?;
    for key in ["icon_24", "icon_16"] {
        // 缺失/非字符串 → 继续尝试下一档（回退 icon_16），而非 `?` 早退——
        // 否则 icon_24 缺席时 icon_16 永远不被尝试（审核发现）。
        let Some(name) = status.get(key).and_then(|v| v.as_str()) else {
            continue;
        };
        let path = parent.join(name);
        if let Ok(data) = std::fs::read(&path) {
            if let Some(rgba) = png_decode(&data) {
                return Some(rgba);
            }
        }
    }
    None
}

/// 解码 TraySink 写出的 PNG：8-bit RGBA（color type 6）、逐行 filter 0、
/// zlib **stored** deflate 块——与 [crate] 的编码器（`tray.rs::png_encode`）
/// 严格对称，零新增依赖。非此格式返回 `None`（fail closed，不假装成功）。
#[cfg(any(windows, test))]
fn png_decode(data: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    const SIG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    if data.len() < 8 || &data[..8] != SIG {
        return None;
    }
    let mut i = 8usize;
    let mut width = 0u32;
    let mut height = 0u32;
    let mut idat = Vec::new();
    while i + 8 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let ctype = &data[i + 4..i + 8];
        let body = i + 8;
        let end = body + len;
        if end + 4 > data.len() {
            return None;
        }
        match ctype {
            b"IHDR" => {
                if len < 13 {
                    return None;
                }
                width = u32::from_be_bytes([
                    data[body],
                    data[body + 1],
                    data[body + 2],
                    data[body + 3],
                ]);
                height = u32::from_be_bytes([
                    data[body + 4],
                    data[body + 5],
                    data[body + 6],
                    data[body + 7],
                ]);
                // 只支持本模块产出的固定格式：bit depth 8、RGBA、interlace 0。
                if data[body + 8] != 8 || data[body + 9] != 6 || data[body + 12] != 0 {
                    return None;
                }
            }
            b"IDAT" => idat.extend_from_slice(&data[body..end]),
            b"IEND" => break,
            _ => {}
        }
        i = end + 4; // 跳过 CRC
    }
    if width == 0 || height == 0 {
        return None;
    }
    let raw = zlib_inflate_stored(&idat)?;
    let row_len = width as usize * 4;
    let stride = row_len + 1; // 每行前置 1 字节 filter
    if raw.len() < stride * height as usize {
        return None;
    }
    let mut rgba = Vec::with_capacity(row_len * height as usize);
    for y in 0..height as usize {
        let row = &raw[y * stride..(y + 1) * stride];
        if row[0] != 0 {
            return None; // 只支持 filter None（本模块唯一写出的形式）
        }
        rgba.extend_from_slice(&row[1..]);
    }
    Some((width, height, rgba))
}

/// zlib 容器解压（仅 stored 块）。`0x78` 头 + 逐块 `BFINAL|BTYPE=00` +
/// `LEN/NLEN` + 原始字节 + adler32 尾。
#[cfg(any(windows, test))]
fn zlib_inflate_stored(stream: &[u8]) -> Option<Vec<u8>> {
    if stream.len() < 6 || stream[0] != 0x78 {
        return None;
    }
    let mut out = Vec::new();
    let mut i = 2usize;
    while i < stream.len().saturating_sub(4) {
        let last = stream[i] & 0x01 != 0;
        if stream[i] >> 1 != 0 {
            return None; // 只支持 stored 块
        }
        i += 1;
        if i + 4 > stream.len() {
            return None;
        }
        let len = u16::from_le_bytes([stream[i], stream[i + 1]]) as usize;
        i += 4; // LEN + NLEN
        if i + len > stream.len() - 4 {
            return None;
        }
        out.extend_from_slice(&stream[i..i + len]);
        i += len;
        if last {
            break;
        }
    }
    Some(out)
}

/// GDI 绿色方块兜底图标。
#[cfg(windows)]
fn create_green_icon() -> HICON {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Graphics::Gdi::*;

    unsafe {
        let hdc = GetDC(0 as HWND);
        let mem_dc = CreateCompatibleDC(hdc);
        let bmp = CreateCompatibleBitmap(hdc, 16, 16);
        let old = SelectObject(mem_dc, bmp);

        let brush = CreateSolidBrush(0x0000FF00);
        let rect = RECT {
            left: 0,
            top: 0,
            right: 16,
            bottom: 16,
        };
        FillRect(mem_dc, &rect, brush);
        DeleteObject(brush as isize as _);

        SelectObject(mem_dc, old as isize as _);

        let mut ii: ICONINFO = std::mem::zeroed();
        ii.fIcon = 1;
        ii.hbmColor = bmp;
        ii.hbmMask = CreateCompatibleBitmap(hdc, 16, 16);
        let icon = CreateIconIndirect(&ii);

        DeleteObject(ii.hbmMask as isize as _);
        DeleteObject(bmp as isize as _);
        DeleteDC(mem_dc);
        ReleaseDC(0 as HWND, hdc);

        icon
    }
}

#[cfg(windows)]
fn update_tray(status_path: &std::path::Path, nid: &mut NOTIFYICONDATAW) {
    let status = std::fs::read_to_string(status_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

    if let Some(status) = status {
        let tooltip = status["tooltip"].as_str().unwrap_or("Meshlet");
        eprintln!("meshlet-tray-host: tooltip={tooltip}");

        // 菜单「连接状态」展示项：随 state（accessible_name）同步，禁用态。
        let state = status["state"].as_str().unwrap_or("Meshlet");
        set_status_item(state);

        let tip_wide: Vec<u16> = tooltip.encode_utf16().collect();
        for i in 0..127 {
            nid.szTip[i] = tip_wide.get(i).copied().unwrap_or(0);
        }
        nid.uFlags |= NIF_TIP | NIF_ICON;
        unsafe {
            // 换图标：解码 TraySink 写出的状态 PNG；解码失败/缺失时以 GDI
            // 绿色方块兜底（绝不静默保留旧图，避免状态卡死）。
            let new_icon = match load_status_icon(status_path) {
                Some((w, h, rgba)) => rgba_to_icon(&rgba, w, h),
                None => create_green_icon(),
            };
            if !nid.hIcon.is_null() {
                DestroyIcon(nid.hIcon);
            }
            nid.hIcon = new_icon;
            Shell_NotifyIconW(NIM_MODIFY, nid);
        }
    }
}

/// ④ agent 进程联动：轮询 `meshlet-agent.exe`。已见过 agent 后持续缺席
/// （~6s）→ 托盘退出；从未见过但 `tray_dir` 已存在（agent 写过状态后即死）
/// → ~30s 宽限后退出，不留无主托盘。
#[cfg(windows)]
fn spawn_agent_watchdog(hwnd: HWND) {
    // HWND 是裸指针（!Send），闭包须捕获 isize 才能在独立线程发送。
    let hwnd_raw = hwnd as isize;
    std::thread::spawn(move || {
        let mut seen = false;
        let mut gone_polls = 0u32;
        let mut first_sight_polls = 0u32;
        loop {
            if G_EXIT.load(Ordering::SeqCst) {
                return;
            }
            if agent_alive() {
                seen = true;
                gone_polls = 0;
            } else if seen {
                gone_polls += 1;
                if gone_polls >= GONE_POLLS {
                    unsafe {
                        PostMessageW(hwnd_raw as HWND, WM_TRAY_EXIT, 0, 0);
                    }
                    return;
                }
            } else {
                first_sight_polls += 1;
                if first_sight_polls >= FIRST_SIGHT_POLLS {
                    unsafe {
                        PostMessageW(hwnd_raw as HWND, WM_TRAY_EXIT, 0, 0);
                    }
                    return;
                }
            }
            std::thread::sleep(AGENT_POLL);
        }
    });
}

/// 按名字找 agent 进程 PID（Toolhelp32 快照；不打开进程句柄，跨特权可用）。
#[cfg(windows)]
fn agent_pid() -> Option<u32> {
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return None;
        }
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        let mut found = None;
        if Process32FirstW(snap, &mut entry) != 0 {
            loop {
                if exe_name_matches(&entry.szExeFile) {
                    found = Some(entry.th32ProcessID);
                    break;
                }
                if Process32NextW(snap, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
        found
    }
}

#[cfg(windows)]
fn agent_alive() -> bool {
    agent_pid().is_some()
}

/// `szExeFile`（`[u16; 260]`，NUL 结尾）是否等于 [`AGENT_EXE`]（大小写不敏感）。
#[cfg(any(windows, test))]
fn exe_name_matches(name: &[u16]) -> bool {
    let want: Vec<u16> = AGENT_EXE.encode_utf16().collect();
    let actual_len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    actual_len == want.len()
        && name[..actual_len]
            .iter()
            .zip(want.iter())
            .all(|(a, b)| ascii_lower(*a) == ascii_lower(*b))
}

/// ASCII 大写转小写（进程名/文件名均为 ASCII）；非字母原样返回。
#[cfg(any(windows, test))]
fn ascii_lower(c: u16) -> u16 {
    if (b'A' as u16..=b'Z' as u16).contains(&c) {
        c + 32
    } else {
        c
    }
}

/// 「退出」停止 agent：按名找 PID → `TerminateProcess`。best-effort：权限不足
/// 或进程已死只记日志，托盘仍会退出（D4：退出仅停 agent，不删持久隧道）。
#[cfg(windows)]
fn terminate_agent() {
    let Some(pid) = agent_pid() else {
        eprintln!("meshlet-tray-host: no agent process to stop");
        return;
    };
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            eprintln!(
                "meshlet-tray-host: OpenProcess({pid}) failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        eprintln!("meshlet-tray-host: stopping agent pid={pid}");
        TerminateProcess(handle, 0);
        CloseHandle(handle);
    }
}

/// 「打开面板」：默认浏览器打开面板 URL（server 根路径托管的控制台）。
#[cfg(windows)]
fn open_panel(hwnd: HWND) {
    let Some(state_dir) = G_STATE_DIR.get() else {
        eprintln!("meshlet-tray-host: state dir unknown, cannot open panel");
        return;
    };
    let Some(url) = panel_url(state_dir) else {
        eprintln!("meshlet-tray-host: no panel URL (server_url missing from agent.toml)");
        return;
    };
    let op: Vec<u16> = "open\0".encode_utf16().collect();
    let wide: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        ShellExecuteW(
            hwnd,
            op.as_ptr(),
            wide.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
    }
}

/// 面板 URL：agent 配置文件（`{state_dir}/..`）的 `server_url`。控制台由
/// server 根路径托管（`router_with_console` 的 `ServeDir` 兜底），故
/// `server_url` 即面板入口。本地 API/面板（ADR-013）尚未实现，无法提供
/// 本地面板 URL。兼容旧部署的 `config.toml` 文件名。
#[cfg(any(windows, test))]
fn panel_url(state_dir: &std::path::Path) -> Option<String> {
    let parent = state_dir.parent()?;
    for name in ["agent.toml", "config.toml"] {
        let Ok(text) = std::fs::read_to_string(parent.join(name)) else {
            continue;
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == "server_url" {
                    let value = v.trim().trim_matches('"');
                    if !value.is_empty() {
                        return Some(value.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(windows))]
fn main() {
    eprintln!("meshlet-tray-host is Windows-only");
    std::process::exit(1);
}

#[cfg(windows)]
unsafe extern "system" fn tray_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if msg == WM_APP + 1 {
        let event = lparam as u32;
        eprintln!("meshlet-tray-host: tray event={event:#x}");
        if event == WM_RBUTTONUP || event == WM_LBUTTONUP {
            let mut pt: POINT = std::mem::zeroed();
            GetCursorPos(&mut pt);
            let hmenu = G_MENU.load(Ordering::SeqCst) as HMENU;
            SetForegroundWindow(hwnd);
            PostMessageW(hwnd, WM_NULL, 0, 0);
            let cmd = TrackPopupMenuEx(
                hmenu,
                TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                pt.x,
                pt.y,
                hwnd,
                std::ptr::null(),
            ) as usize;
            eprintln!("meshlet-tray-host: menu cmd={cmd}");
            match cmd {
                // 退出：停止当前用户会话 agent（best-effort，D4：不删持久隧道），
                // 再清托盘；若 agent 已死则仅清托盘（④ 的 watchdog 也会触发）。
                CMD_QUIT => {
                    terminate_agent();
                    do_exit();
                }
                // 打开面板：浏览器打开 server_url（server 根路径托管控制台）。
                CMD_OPEN_PANEL => open_panel(hwnd),
                _ => {}
            }
        }
        return 0;
    }
    // ④ watchdog：agent 进程已死，托盘随之退出。
    if msg == WM_TRAY_EXIT {
        eprintln!("meshlet-tray-host: agent process gone, exiting tray");
        do_exit();
        return 0;
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

/// 清托盘并退出消息循环（幂等：G_EXIT 已置位则直接返回）。
#[cfg(windows)]
fn do_exit() {
    if G_EXIT.swap(true, Ordering::SeqCst) {
        return;
    }
    let nid_ptr = G_NID.load(Ordering::SeqCst) as *mut NOTIFYICONDATAW;
    if !nid_ptr.is_null() {
        unsafe {
            Shell_NotifyIconW(NIM_DELETE, &*nid_ptr);
        }
    }
    let hmenu = G_MENU.load(Ordering::SeqCst) as HMENU;
    if !hmenu.is_null() {
        unsafe {
            DestroyMenu(hmenu);
        }
    }
    let hwnd = G_HWND.load(Ordering::SeqCst) as HWND;
    if !hwnd.is_null() {
        unsafe {
            DestroyWindow(hwnd);
        }
    }
}

/// 更新菜单「连接状态」展示项文本（禁用态）。
#[cfg(windows)]
fn set_status_item(state: &str) {
    let wide: Vec<u16> = state.encode_utf16().chain(std::iter::once(0)).collect();
    let hmenu = G_MENU.load(Ordering::SeqCst) as HMENU;
    if hmenu.is_null() {
        return;
    }
    unsafe {
        ModifyMenuW(
            hmenu,
            CMD_STATUS as u32,
            MF_BYCOMMAND | MF_STRING | MF_GRAYED,
            CMD_STATUS,
            wide.as_ptr(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 与 tray.rs `png_encode` 对称的最小编码器（stored-deflate、filter 0、
    /// RGBA）：只为构造测试 fixture，验证解码器还原像素。
    fn png_encode(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
        fn chunk(out: &mut Vec<u8>, type_: &[u8; 4], data: &[u8]) {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(type_);
            out.extend_from_slice(data);
            out.extend_from_slice(&[0; 4]); // CRC 不校验（解码器不依赖）
        }
        let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA 非隔行
        chunk(&mut out, b"IHDR", &ihdr);

        let row_len = 1 + width as usize * 4;
        let mut raw = Vec::with_capacity(row_len * height as usize);
        for y in 0..height as usize {
            raw.push(0);
            raw.extend_from_slice(&rgba[y * width as usize * 4..(y + 1) * width as usize * 4]);
        }
        // zlib: 0x78 0x01 头 + stored 块 + adler32（占位）
        let mut idat = vec![0x78u8, 0x01u8];
        idat.push(0x01); // BFINAL=1, BTYPE=00
        idat.extend_from_slice(&(raw.len() as u16).to_le_bytes());
        idat.extend_from_slice(&(raw.len() as u16).wrapping_neg().to_le_bytes());
        idat.extend_from_slice(&raw);
        idat.extend_from_slice(&[0; 4]);
        chunk(&mut out, b"IDAT", &idat);
        chunk(&mut out, b"IEND", &[]);
        out
    }

    #[test]
    fn png_roundtrip_restores_the_same_pixels() {
        let (w, h) = (16u32, 16u32);
        let mut rgba = vec![0u8; (w * h * 4) as usize];
        for i in 0..(w * h) as usize {
            let px = &mut rgba[i * 4..i * 4 + 4];
            px.copy_from_slice(&[(i % 256) as u8, ((i / 256) % 256) as u8, 0, 255]);
        }
        let decoded = png_decode(&png_encode(w, h, &rgba)).expect("decode");
        assert_eq!(decoded.0, w);
        assert_eq!(decoded.1, h);
        assert_eq!(decoded.2, rgba);
    }

    #[test]
    fn png_rejects_non_signature_or_unsupported_format() {
        assert!(png_decode(&[0, 1, 2, 3, 4, 5, 6, 7]).is_none());
        assert!(png_decode(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]).is_none());
        // 8-bit 灰度（color type 0）不受支持：IHDR 数据从偏移 16 起，
        // 结构为 width(4)+height(4)+bitdepth(1)+colortype(1) → colortype 在 25。
        let mut p = png_encode(2, 2, &[0; 16]);
        p[25] = 0;
        assert!(png_decode(&p).is_none());
    }

    #[test]
    fn load_status_icon_prefers_icon24_and_decodes() {
        let dir = std::env::temp_dir().join(format!(
            "meshlet-tray-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (w, h) = (24u32, 24u32);
        let mut rgba = vec![0u8; (w * h * 4) as usize];
        rgba[0] = 0x22;
        rgba[1] = 0xc5;
        rgba[2] = 0x5e;
        rgba[3] = 0xff;
        std::fs::write(dir.join("icon-24.png"), png_encode(w, h, &rgba)).unwrap();
        std::fs::write(
            dir.join("status.json"),
            r#"{"state":"Meshlet online","tooltip":"Meshlet：在线","icon_16":"icon-16.png","icon_24":"icon-24.png"}"#,
        )
        .unwrap();
        let got = load_status_icon(&dir.join("status.json")).expect("load");
        assert_eq!(got.0, w);
        assert_eq!(got.1, h);
        assert_eq!(&got.2[..4], &[0x22, 0xc5, 0x5e, 0xff]);
        // icon_16 缺席时回退（status.json 声明但文件缺失 → None）。
        std::fs::remove_file(dir.join("icon-24.png")).unwrap();
        assert!(load_status_icon(&dir.join("status.json")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 回退回归（审核发现）：status.json 只声明 icon_16（icon_24 键缺席）
    /// 时必须回退加载 icon_16——此前循环内 `?` 在 icon_24 缺席时早退 None，
    /// icon_16 永远不被尝试，与注释声明的回退语义不符。
    #[test]
    fn load_status_icon_falls_back_to_icon16_when_icon24_key_absent() {
        let dir = std::env::temp_dir().join(format!(
            "meshlet-tray-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let (w, h) = (16u32, 16u32);
        let mut rgba = vec![0u8; (w * h * 4) as usize];
        rgba[0] = 0x22;
        rgba[1] = 0xc5;
        rgba[2] = 0x5e;
        rgba[3] = 0xff;
        std::fs::write(dir.join("icon-16.png"), png_encode(w, h, &rgba)).unwrap();
        // 仅声明 icon_16——icon_24 键缺席，正是此前 `?` 早退的场景。
        std::fs::write(
            dir.join("status.json"),
            r#"{"state":"Meshlet online","tooltip":"Meshlet：在线","icon_16":"icon-16.png"}"#,
        )
        .unwrap();
        let got = load_status_icon(&dir.join("status.json")).expect("fall back to icon_16");
        assert_eq!(got.0, w);
        assert_eq!(got.1, h);
        assert_eq!(&got.2[..4], &[0x22, 0xc5, 0x5e, 0xff]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_status_icon_missing_status_or_files_is_none() {
        let dir = std::env::temp_dir().join(format!(
            "meshlet-tray-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(load_status_icon(&dir.join("status.json")).is_none());
        std::fs::write(dir.join("status.json"), "not json").unwrap();
        assert!(load_status_icon(&dir.join("status.json")).is_none());
        std::fs::write(dir.join("status.json"), r#"{"icon_24":"icon-24.png"}"#).unwrap();
        assert!(load_status_icon(&dir.join("status.json")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── agent 进程名匹配（④ watchdog / 退出）─────────────────────────────

    #[test]
    fn exe_name_matches_agent_binary_case_insensitively() {
        let want: Vec<u16> = "Meshlet-Agent.Exe".encode_utf16().collect();
        assert!(exe_name_matches(&want));
        let exact: Vec<u16> = "meshlet-agent.exe\0".encode_utf16().collect();
        assert!(exe_name_matches(&exact));
    }

    #[test]
    fn exe_name_matches_rejects_other_names() {
        let other: Vec<u16> = "meshlet-tray-host.exe".encode_utf16().collect();
        assert!(!exe_name_matches(&other));
        // 前缀不匹配：不能把 meshlet-agent 误认为别的（或反之）。
        let prefix: Vec<u16> = "meshlet-agent".encode_utf16().collect();
        assert!(!exe_name_matches(&prefix));
        // 全 NUL / 空名。
        let empty = [0u16; 260];
        assert!(!exe_name_matches(&empty));
    }

    // ── 面板 URL（打开面板）───────────────────────────────────────────────

    /// 建一个 `<base>/state` 结构（与 `install.ps1` 的
    /// `%LOCALAPPDATA%\meshlet\{agent.toml,state}` 同形），返回 state 目录。
    fn temp_state_dir(tag: &str) -> std::path::PathBuf {
        let base = std::env::temp_dir().join(format!(
            "meshlet-tray-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let state = base.join("state");
        std::fs::create_dir_all(&state).unwrap();
        state
    }

    #[test]
    fn panel_url_reads_server_url_from_agent_toml() {
        let state = temp_state_dir("panel-agent");
        let base = state.parent().unwrap();
        std::fs::write(
            base.join("agent.toml"),
            "server_url = \"https://meshlet.example.com\"\nstate_dir = \"./state\"\n",
        )
        .unwrap();
        assert_eq!(
            panel_url(&state).as_deref(),
            Some("https://meshlet.example.com")
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn panel_url_falls_back_to_config_toml() {
        // 旧部署（2026-10-31 真机）把配置写成 config.toml；面板入口仍要工作。
        let state = temp_state_dir("panel-config");
        let base = state.parent().unwrap();
        std::fs::write(
            base.join("config.toml"),
            "server_url = \"https://old.example.com\"\n",
        )
        .unwrap();
        assert_eq!(
            panel_url(&state).as_deref(),
            Some("https://old.example.com")
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn panel_url_missing_config_is_none() {
        let state = temp_state_dir("panel-none");
        let base = state.parent().unwrap();
        // 无 agent.toml / config.toml。
        assert!(panel_url(&state).is_none());
        // server_url 为空 → None（不返回空字符串打开默认页）。
        std::fs::write(base.join("agent.toml"), "server_url = \"\"\n").unwrap();
        assert!(panel_url(&state).is_none());
        let _ = std::fs::remove_dir_all(base);
    }
}
