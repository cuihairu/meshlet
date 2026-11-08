use windows_sys::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, DestroyIcon, ICONINFO};

/// 将 RGBA 像素缓冲转为 HICON（含透明通道）。
#[cfg(windows)]
pub(crate) fn rgba_to_icon(
    rgba: &[u8],
    width: u32,
    height: u32,
) -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Graphics::Gdi::*;

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

use windows_sys::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_TIP, NIM_MODIFY, NOTIFYICONDATAW,
};

#[cfg(windows)]
pub(crate) fn update_tray(status_path: &std::path::Path, nid: &mut NOTIFYICONDATAW) {
    let status = std::fs::read_to_string(status_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());

    if let Some(status) = status {
        let tooltip = status["tooltip"].as_str().unwrap_or("Meshlet");
        tracing::info!("tooltip={tooltip}");

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

#[cfg(any(windows, test))]
pub(crate) fn load_status_icon(status_path: &std::path::Path) -> Option<(u32, u32, Vec<u8>)> {
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

/// 最小 PNG 解码器（TraySink 产出的 8-bit RGBA、filter 0、无隔行）。
#[cfg(any(windows, test))]
pub(crate) fn png_decode(data: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
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
pub(crate) fn create_green_icon() -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Graphics::Gdi::*;

    unsafe {
        let hdc = GetDC(0 as HWND);
        let mem_dc = CreateCompatibleDC(hdc);
        let bmp = CreateCompatibleBitmap(hdc, 16, 16);
        let old = SelectObject(mem_dc, bmp);

        let brush = CreateSolidBrush(0x0000FF00);
        let rect = windows_sys::Win32::Foundation::RECT {
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
        idat.extend_from_slice(&(!(raw.len() as u16)).to_le_bytes()); // NLEN = ~LEN
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
}
