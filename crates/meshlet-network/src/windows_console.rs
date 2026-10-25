//! Windows 控制台输出解码（执行层共享，ADR-008 TODO #52 真机取证）。
//!
//! 真机证据（2026-10-25，中文 Windows Server，CP936）：netsh / sc.exe 的
//! **重定向输出是活动代码页编码而非 UTF-8**——netsh 删除不存在路由返回
//! 字节 `D5 D2 B2 BB B5 BD D4 AA CB D8 A1 A3`（「找不到元素。」的 GBK
//! 编码）。执行层此前用 `String::from_utf8_lossy` 解码，中文在 U+FFFD
//! 乱码中丢失，幂等删除文案分类全部失效（`windows_netsh` 真机集成测试
//! 抓到）。
//!
//! 纪律：
//! - **UTF-8 优先**：合法 UTF-8（en-US runner 与任何 UTF-8 输出）原样
//!   通过，既有绿路径零变化；
//! - **非 UTF-8 按活动代码页解码**（`MultiByteToWideChar(CP_ACP)`），
//!   覆盖中文/繁中/日文等本地化部署，不引入新的外部依赖；
//! - **绝不 panic、绝不返回空文本伪装成功**：解码不可断时按 UTF-8
//!   lossy 兜底（§10.3 失败可见）。

/// 按活动代码页解码进程输出（UTF-8 优先）。
pub fn decode_output(bytes: &[u8]) -> String {
    // CP_ACP = 0：控制台工具（netsh/sc.exe）按系统 ANSI 代码页输出。
    decode_output_with(bytes, 0)
}

/// 指定代码页的解码核心（测试注入 936/GBK 验证真机取证字节，
/// 不依赖宿主系统语言）。
pub fn decode_output_with(bytes: &[u8], code_page: u32) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    if bytes.is_empty() {
        return String::new();
    }
    decode_via_code_page(bytes, code_page)
}

/// Windows：`MultiByteToWideChar` 按指定代码页转 UTF-16 再转 `String`。
#[cfg(target_os = "windows")]
fn decode_via_code_page(bytes: &[u8], code_page: u32) -> String {
    // SAFETY：lpmultibytestr 指向 bytes 且 cbmultibyte 与其长度一致；
    // 第一次调用取目标 UTF-16 长度，第二次写入等长的自持缓冲。
    unsafe {
        use windows_sys::Win32::Globalization::MultiByteToWideChar;
        let len = MultiByteToWideChar(
            code_page,
            0,
            bytes.as_ptr(),
            bytes.len() as i32,
            std::ptr::null_mut(),
            0,
        );
        if len > 0 {
            let mut utf16 = vec![0u16; len as usize];
            let written = MultiByteToWideChar(
                code_page,
                0,
                bytes.as_ptr(),
                bytes.len() as i32,
                utf16.as_mut_ptr(),
                len,
            );
            if written == len {
                return String::from_utf16_lossy(&utf16);
            }
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// 非 Windows：无系统代码页语义，UTF-8 lossy 兜底。该分支只为让计划层
/// 单测在 Linux CI 编译；真实解码只发生在 Windows 执行层。
#[cfg(not(target_os = "windows"))]
fn decode_via_code_page(bytes: &[u8], _code_page: u32) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 真机取证字节（2026-10-25，本机 CP936）：netsh 删除不存在路由的
    /// 完整报文「找不到元素。」。
    const GBK_ELEMENT_ABSENT: &[u8] = &[
        0xD5, 0xD2, 0xB2, 0xBB, 0xB5, 0xBD, 0xD4, 0xAA, 0xCB, 0xD8, 0xA1, 0xA3,
    ];

    /// 真机取证字节：「没有与指定标准相匹配的规则。」（netsh 防火墙删除
    /// 不存在规则的完整报文）。
    const GBK_NO_RULE_MATCH: &[u8] = &[
        0xC3, 0xBB, 0xD3, 0xD0, 0xD3, 0xEB, 0xD6, 0xB8, 0xB6, 0xA8, 0xB1, 0xEA, 0xD7, 0xBC,
        0xCF, 0xE0, 0xC6, 0xA5, 0xC5, 0xE4, 0xB5, 0xC4, 0xB9, 0xE6, 0xD4, 0xF2, 0xA1, 0xA3,
    ];

    #[test]
    fn valid_utf8_passes_through_unchanged() {
        assert_eq!(
            decode_output_with(b"Element not found.\r\n", 936),
            "Element not found.\r\n"
        );
        assert_eq!(decode_output_with(&[], 936), "");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn gbk_absence_text_decodes_via_code_page_936() {
        assert_eq!(decode_output_with(GBK_ELEMENT_ABSENT, 936), "找不到元素。");
        assert_eq!(
            decode_output_with(GBK_NO_RULE_MATCH, 936),
            "没有与指定标准相匹配的规则。"
        );
    }

    #[test]
    fn gbk_bytes_never_panic_and_never_decode_to_empty() {
        // 全部高位字节逐个探测：任何输入都不 panic、解码结果非空
        //（空文本会被上游误读为「成功」，§10.3）。
        for lead in 0x80u8..=0xFF {
            let decoded = decode_output_with(&[lead, b'x'], 936);
            assert!(!decoded.is_empty(), "lead {lead:#04x} decoded to empty");
        }
    }
}
