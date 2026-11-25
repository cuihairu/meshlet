use windows_sys::Win32::UI::WindowsAndMessaging::{CreateIconIndirect, DestroyIcon, ICONINFO};

/// RGBA (PNG decode output) -> BGRA (32bpp BI_RGB DIB byte order, byte0=Blue).
/// Pure function, tested cross-platform; the input is always a multiple of 4 in length (w*h*4).
#[cfg(any(windows, test))]
fn rgba_to_bgra(rgba: &[u8]) -> Vec<u8> {
    let mut out = rgba.to_vec();
    let (pixels, _) = out.as_chunks_mut::<4>();
    for px in pixels {
        px.swap(0, 2);
    }
    out
}

/// BGRA pixel buffer -> HICON.
///
/// Two root causes found on real machines (imac 2026-11-12: NIM_ADD=1, the registry slot
/// existed, yet the tray showed 0 pixels):
/// ① hbmColor must be a **32bpp DIB section** ([CreateDIBSection]) — the bitmap memory
///    is exactly the bytes written, and per-pixel Alpha takes effect by value; the earlier
///    `CreateCompatibleBitmap` produced a DDB with no stable Alpha semantics, and paired with
///    a 1bpp all-zero mask it rendered no pixels at all (even after changing hbmMask to a
///    monochrome bitmap in the 406b597 re-check it was still invisible, proving the mask was
///    not the only root cause).
/// ② 32bpp BI_RGB byte order is BGRA (byte0=Blue), while decoders produce RGBA; passing it
///    through directly swaps R/B — even if something were drawn, the pixel scan for the status
///    color (50,96,114) would miss everything, which looks the same as "invisible".
/// hbmMask uses a 1bpp all-zero bitmap (bit semantics: 0 = opaque; when hbmColor carries Alpha
/// the mask takes no part in blending, but it is still a required ICONINFO field).
#[cfg(windows)]
fn bgra_to_icon(
    bgra: &[u8],
    width: u32,
    height: u32,
) -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Graphics::Gdi::*;

    unsafe {
        let hdc = GetDC(0 as HWND);
        let mem_dc = CreateCompatibleDC(hdc);

        let mut bmi: BITMAPINFO = std::mem::zeroed();
        bmi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        bmi.bmiHeader.biWidth = width as i32;
        bmi.bmiHeader.biHeight = -(height as i32); // top-down
        bmi.bmiHeader.biPlanes = 1;
        bmi.bmiHeader.biBitCount = 32;
        bmi.bmiHeader.biCompression = BI_RGB;
        bmi.bmiHeader.biSizeImage = bgra.len() as u32;

        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let dib = CreateDIBSection(
            mem_dc,
            &bmi,
            DIB_RGB_COLORS,
            &mut bits,
            std::ptr::null_mut(),
            0,
        );
        if dib.is_null() || bits.is_null() {
            tracing::warn!("CreateDIBSection failed for {width}x{height}");
            DeleteDC(mem_dc);
            ReleaseDC(0 as HWND, hdc);
            return std::ptr::null_mut();
        }
        std::ptr::copy_nonoverlapping(bgra.as_ptr(), bits as *mut u8, bgra.len());

        let mut ii: ICONINFO = std::mem::zeroed();
        ii.fIcon = 1;
        ii.hbmColor = dib;
        ii.hbmMask = CreateBitmap(width as i32, height as i32, 1, 1, std::ptr::null());
        let icon = CreateIconIndirect(&ii);

        DeleteObject(ii.hbmMask as isize as _);
        DeleteObject(dib as isize as _);
        DeleteDC(mem_dc);
        ReleaseDC(0 as HWND, hdc);

        icon
    }
}

/// Converts an RGBA pixel buffer to an HICON (including the alpha channel).
#[cfg(windows)]
pub(crate) fn rgba_to_icon(
    rgba: &[u8],
    width: u32,
    height: u32,
) -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
    bgra_to_icon(&rgba_to_bgra(rgba), width, height)
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
            // Swap the icon: decode the status PNG written by TraySink; on decode failure or
            // missing file fall back to a GDI green square (never silently keep the old icon,
            // which would leave the status stuck).
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
        // Missing / not a string -> go on to try the next tier (fall back to icon_16) instead
        // of bailing out early with `?` — otherwise, when icon_24 is absent, icon_16 would never
        // be attempted (found in review).
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

/// Minimal PNG decoder (the 8-bit RGBA, filter 0, non-interlaced output that TraySink produces).
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
                // Only the fixed format this module produces is supported: bit depth 8, RGBA, interlace 0.
                if data[body + 8] != 8 || data[body + 9] != 6 || data[body + 12] != 0 {
                    return None;
                }
            }
            b"IDAT" => idat.extend_from_slice(&data[body..end]),
            b"IEND" => break,
            _ => {}
        }
        i = end + 4; // skip the CRC
    }
    if width == 0 || height == 0 {
        return None;
    }
    let raw = zlib_inflate_stored(&idat)?;
    let row_len = width as usize * 4;
    let stride = row_len + 1; // 1 filter byte prefixing each row
    if raw.len() < stride * height as usize {
        return None;
    }
    let mut rgba = Vec::with_capacity(row_len * height as usize);
    for y in 0..height as usize {
        let row = &raw[y * stride..(y + 1) * stride];
        if row[0] != 0 {
            return None; // only filter None is supported (the only form this module writes)
        }
        rgba.extend_from_slice(&row[1..]);
    }
    Some((width, height, rgba))
}

/// zlib container decompression (stored blocks only). `0x78` header + per-block
/// `BFINAL|BTYPE=00` + `LEN/NLEN` + raw bytes + adler32 trailer.
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
            return None; // stored blocks only are supported
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

/// Fallback icon: a plain green square. No longer goes through GDI FillRect (Alpha semantics on a
/// DDB are equally unstable, COLORREF has no Alpha byte, and the 4th byte written to a DDB is
/// undefined); it writes DIB-section pixels just like the status icon — B=0/G=255/R=0/A=255, i.e. #00FF00.
#[cfg(windows)]
pub(crate) fn create_green_icon() -> windows_sys::Win32::UI::WindowsAndMessaging::HICON {
    let size = 16u32;
    let mut bgra = vec![0u8; (size * size * 4) as usize];
    let (pixels, _) = bgra.as_chunks_mut::<4>();
    for px in pixels {
        *px = [0x00, 0xFF, 0x00, 0xFF];
    }
    bgra_to_icon(&bgra, size, size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal encoder symmetric with `png_encode` in tray.rs (stored-deflate,
    /// filter 0, RGBA): exists only to build test fixtures and verify the decoder
    /// restores the pixels.
    fn png_encode(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
        fn chunk(out: &mut Vec<u8>, type_: &[u8; 4], data: &[u8]) {
            out.extend_from_slice(&(data.len() as u32).to_be_bytes());
            out.extend_from_slice(type_);
            out.extend_from_slice(data);
            out.extend_from_slice(&[0; 4]); // CRC not verified (the decoder does not rely on it)
        }
        let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA, non-interlaced
        chunk(&mut out, b"IHDR", &ihdr);

        let row_len = 1 + width as usize * 4;
        let mut raw = Vec::with_capacity(row_len * height as usize);
        for y in 0..height as usize {
            raw.push(0);
            raw.extend_from_slice(&rgba[y * width as usize * 4..(y + 1) * width as usize * 4]);
        }
        // zlib: 0x78 0x01 header + stored block + adler32 (placeholder)
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

    /// RGBA -> BGRA byte order: R/B swapped, G/A kept in place. After conversion the status
    /// color (50,96,114) scanned on the real machine has R/B swapped — without the conversion
    /// the tray would paint the swapped color, the pixel scan would miss everything
    /// (looks the same as "invisible").
    #[test]
    fn rgba_to_bgra_swaps_red_blue_and_keeps_green_alpha() {
        assert_eq!(rgba_to_bgra(&[10, 20, 30, 40]), [30, 20, 10, 40]);
        assert_eq!(rgba_to_bgra(&[50, 96, 114, 255]), [114, 96, 50, 255]);
        // Multiple pixels, swapped one by one.
        assert_eq!(
            rgba_to_bgra(&[1, 2, 3, 4, 5, 6, 7, 8]),
            [3, 2, 1, 4, 7, 6, 5, 8]
        );
        // Empty input -> empty output.
        assert!(rgba_to_bgra(&[]).is_empty());
    }

    #[test]
    fn png_rejects_non_signature_or_unsupported_format() {
        assert!(png_decode(&[0, 1, 2, 3, 4, 5, 6, 7]).is_none());
        assert!(png_decode(&[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a]).is_none());
        // 8-bit grayscale (color type 0) is not supported: IHDR data starts at offset 16,
        // with layout width(4)+height(4)+bitdepth(1)+colortype(1) -> colortype sits at 25.
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
        // Fall back when icon_16 is absent (declared in status.json but the file is missing -> None).
        std::fs::remove_file(dir.join("icon-24.png")).unwrap();
        assert!(load_status_icon(&dir.join("status.json")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fallback regression (found in review): when status.json declares only icon_16
    /// (the icon_24 key absent), loading must fall back to icon_16 — previously the in-loop `?`
    /// bailed out with None when icon_24 was absent, so icon_16 was never attempted,
    /// contradicting the fallback semantics stated in the comment.
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
        // Declare only icon_16 — the icon_24 key is absent, exactly the case where the old `?` bailed out early.
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
