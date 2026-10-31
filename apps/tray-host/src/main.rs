//! Windows 系统托盘宿主：消费 [TraySink] 的 PNG 状态图。
//!
//! 监听 agent 写出的 `status.json` + `icon-*.png`，通过 `Shell_NotifyIcon`
//! 在系统托盘显示当前状态。状态变化即换图，无需轮询。
//!
//! 用法：`meshlet-tray-host <state_dir>`

#[cfg(windows)]
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
#[cfg(windows)]
use windows_sys::Win32::Graphics::Gdi::*;
#[cfg(windows)]
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
#[cfg(windows)]
use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW,
};
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::HICON;
#[cfg(windows)]
use windows_sys::Win32::UI::WindowsAndMessaging::*;

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

    unsafe {
        let class_name: Vec<u16> = "MeshletTrayHost\0".encode_utf16().collect();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(def_window_proc),
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
            HWND_MESSAGE,
            std::ptr::null_mut(),
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        );

        let mut nid: NOTIFYICONDATAW = std::mem::zeroed();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_APP + 1;
        nid.hIcon = icon_for_state("unknown");
        eprintln!("meshlet-tray-host: hIcon={:p}", nid.hIcon);
        let tip: Vec<u16> = "Meshlet\0".encode_utf16().collect();
        for (i, &w) in tip.iter().enumerate().take(127) {
            nid.szTip[i] = w;
        }
        let ok = Shell_NotifyIconW(NIM_ADD, &nid);
        eprintln!("meshlet-tray-host: NIM_ADD = {ok}");

        let hmenu = CreatePopupMenu();
        let exit_text: Vec<u16> = "退出\0".encode_utf16().collect();
        AppendMenuW(hmenu, MF_STRING, 1, exit_text.as_ptr());

        // 启动时立即读取当前状态并应用图标
        update_tray(&status_path, &mut nid);

        let mut last_mtime: Option<std::time::SystemTime> = None;

        loop {
            if let Ok(meta) = std::fs::metadata(&status_path) {
                if let Ok(mtime) = meta.modified() {
                    if last_mtime.map_or(true, |old| mtime > old) {
                        last_mtime = Some(mtime);
                        update_tray(&status_path, &mut nid);
                    }
                }
            }

            let mut msg: MSG = std::mem::zeroed();
            while PeekMessageW(&mut msg, hwnd, 0, 0, PM_REMOVE) > 0 {
                if msg.message == WM_APP + 1 {
                    let lparam = msg.lParam as u32;
                    if lparam == WM_RBUTTONUP {
                        let mut pt: POINT = std::mem::zeroed();
                        GetCursorPos(&mut pt);
                        SetForegroundWindow(hwnd);
                        // Windows 要求 SetForegroundWindow 后发 WM_NULL 否则菜单不显示
                        PostMessageW(hwnd, WM_NULL, 0, 0);
                        let cmd = TrackPopupMenuEx(
                            hmenu,
                            TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                            pt.x,
                            pt.y,
                            hwnd,
                            std::ptr::null(),
                        );
                        if cmd == 1 {
                            Shell_NotifyIconW(NIM_DELETE, &nid);
                            DestroyMenu(hmenu);
                            DestroyWindow(hwnd);
                            return;
                        }
                    }
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }

            std::thread::sleep(std::time::Duration::from_millis(100));
        }
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

/// 用 resvg 渲染内嵌 SVG 为 HICON。
#[cfg(windows)]
fn render_svg_icon(svg_data: &[u8], size_px: u32) -> HICON {
    let opt = resvg::usvg::Options::default();
    let tree = match resvg::usvg::Tree::from_data(svg_data, &opt) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("meshlet-tray-host: SVG parse error: {e}");
            return create_green_icon();
        }
    };

    let size = tree.size().to_int_size();
    let scale = (size_px as f32) / (size.width().max(size.height()) as f32);
    let pixmap_size = (size.width() as f32 * scale).round() as u32;
    let pixmap_size = pixmap_size.max(1);

    let mut pixmap = match tiny_skia::Pixmap::new(pixmap_size, pixmap_size) {
        Some(p) => p,
        None => {
            eprintln!("meshlet-tray-host: pixmap alloc failed");
            return create_green_icon();
        }
    };

    let transform = tiny_skia::Transform::from_scale(scale, scale);
    resvg::render(&tree, transform, &mut pixmap.as_mut());

    // 居中裁剪到目标尺寸
    let mut rgba = vec![0u8; (size_px * size_px * 4) as usize];
    let src = pixmap.data();
    let sw = pixmap.width() as u32;
    let sh = pixmap.height() as u32;
    let ox = ((sw as f32 - size_px as f32) / 2.0).max(0.0) as u32;
    let oy = ((sh as f32 - size_px as f32) / 2.0).max(0.0) as u32;
    let cw = size_px.min(sw);
    let ch = size_px.min(sh);
    for y in 0..ch {
        for x in 0..cw {
            let si = (((y + oy) * sw + (x + ox)) * 4) as usize;
            let di = ((y * size_px + x) * 4) as usize;
            if si + 3 < src.len() && di + 3 < rgba.len() {
                rgba[di] = src[si];     // R
                rgba[di + 1] = src[si + 1]; // G
                rgba[di + 2] = src[si + 2]; // B
                rgba[di + 3] = src[si + 3]; // A
            }
        }
    }

    rgba_to_icon(&rgba, size_px, size_px)
}

/// 根据状态选择 SVG 并渲染为 HICON。
#[cfg(windows)]
fn icon_for_state(state: &str) -> HICON {
    const SVG_TEAL: &[u8] = include_bytes!("../../../logo-teal.svg");
    const SVG_COPPER: &[u8] = include_bytes!("../../../logo-copper.svg");
    const SVG_GRAY: &[u8] = include_bytes!("../../../logo.svg");

    let svg = match state {
        "connected" | "ready" | "up" | "online" | "ok" => SVG_TEAL,
        "error" | "failed" | "disconnected" | "down" | "unreachable" => SVG_COPPER,
        _ => SVG_GRAY,
    };

    render_svg_icon(svg, 32)
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
        let state = status["state"].as_str().unwrap_or("unknown");
        let tooltip = status["tooltip"].as_str().unwrap_or("Meshlet");
        eprintln!("meshlet-tray-host: state={state} tooltip={tooltip}");

        let tip_wide: Vec<u16> = tooltip.encode_utf16().collect();
        for i in 0..127 {
            nid.szTip[i] = tip_wide.get(i).copied().unwrap_or(0);
        }
        nid.uFlags |= NIF_TIP | NIF_ICON;
        unsafe {
            // 换图标（释放旧的）
            let new_icon = icon_for_state(state);
            if !new_icon.is_null() {
                if !nid.hIcon.is_null() {
                    DestroyIcon(nid.hIcon);
                }
                nid.hIcon = new_icon;
            }
            Shell_NotifyIconW(NIM_MODIFY, nid);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("meshlet-tray-host is Windows-only");
    std::process::exit(1);
}

#[cfg(windows)]
unsafe extern "system" fn def_window_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    DefWindowProcW(hwnd, msg, wparam, lparam)
}
