//! Windows 系统托盘宿主：消费 [TraySink] 的 PNG 状态图。
//!
//! 监听 agent 写出的 `status.json` + `icon-*.png`，通过 `Shell_NotifyIcon`
//! 在系统托盘显示当前状态。状态变化即换图，无需轮询。
//!
//! 用法：`meshlet-tray-host <state_dir>`

#[cfg(windows)]
use std::sync::atomic::{AtomicIsize, AtomicPtr, Ordering};
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
use windows_sys::Win32::UI::WindowsAndMessaging::*;

/// 全局状态，供窗口过程访问。
#[cfg(windows)]
static G_HWND: AtomicIsize = AtomicIsize::new(0);
#[cfg(windows)]
static G_NID: AtomicPtr<NOTIFYICONDATAW> = AtomicPtr::new(std::ptr::null_mut());
#[cfg(windows)]
static G_MENU: AtomicIsize = AtomicIsize::new(0);
#[cfg(windows)]
static G_EXIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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
        let exit_text: Vec<u16> = "退出\0".encode_utf16().collect();
        AppendMenuW(hmenu, MF_STRING, 1, exit_text.as_ptr());
        G_NID.store(&mut nid as *mut _, Ordering::SeqCst);
        G_MENU.store(hmenu as isize, Ordering::SeqCst);

        // 启动时立即读取当前状态并应用图标
        update_tray(&status_path, &mut nid);

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
                        if last_mtime.map_or(true, |old| mtime > old) {
                            last_mtime = Some(mtime);
                            let nid_ptr = G_NID.load(Ordering::SeqCst);
                            if !nid_ptr.is_null() {
                                update_tray(&watch_path, unsafe { &mut *nid_ptr });
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
    for key in ["icon_24", "icon_16"] {
        let name = status.get(key).and_then(|v| v.as_str())?;
        let path = status_path.parent()?.join(name);
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
            );
            eprintln!("meshlet-tray-host: menu cmd={cmd}");
            if cmd == 1 {
                let nid_ptr = G_NID.load(Ordering::SeqCst) as *mut NOTIFYICONDATAW;
                if !nid_ptr.is_null() {
                    Shell_NotifyIconW(NIM_DELETE, &*nid_ptr);
                }
                G_EXIT.store(true, Ordering::SeqCst);
                DestroyMenu(hmenu);
                DestroyWindow(hwnd);
            }
        }
        return 0;
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
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
}
