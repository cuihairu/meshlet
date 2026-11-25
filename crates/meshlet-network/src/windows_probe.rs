//! SEL-001 Windows probe transport (P0, wired 2026-11-13): the measured ICMP
//! echo RTT (milliseconds) of `ping -n 1 -w 1000`.
//!
//! Previously [`crate::probe::default_transport`] returned `None` on every
//! non-Linux system (recorded as packet loss), and all three primary machines
//! are Windows — SEL-001 probing / SEL-002 switching were completely blind on
//! the primary platform.
//!
//! The sampling window is aligned with Linux's
//! [`crate::linux::run_ping_rtt`]: a single echo with a 1s wait (Linux `-W 1` /
//! Windows `-w 1000`); probing is a frequent lightweight operation, and a
//! diagnostic-grade long wait would slow the probe thread.
//!
//! The wording discipline matches [`crate::windows_firewall`]: **the parsing
//! layer is a cross-platform pure function that can be unit-tested on Linux
//! itself**; the execution layer (running ping.exe) is `#[cfg(windows)]`. A
//! real zh-CN machine's redirected output is CP936/GBK; decode it through
//! [`crate::windows_console::decode_output`] before parsing. The parser accepts
//! both the en `time=` and the zh time label, while other locales are outside
//! the acceptance surface (the same en+zh convention as the firewall probing,
//! recorded as-is).
//!
//! Do not trust ping.exe's exit code (the code for unreachable varies by
//! version): **only a parsed reply RTT counts as a successful probe**; timeout /
//! unreachable / an unrecognized label are all `None` —
//! [`crate::probe::probe_round`] records a packet loss and never pretends a
//! probe succeeded.
//!
//! Real-machine acceptance (a walkthrough of the RTT readings on a real
//! Windows) awaits seat R-05.

#[cfg(target_os = "windows")]
use crate::windows_console::NoWindowCommand;
#[cfg(target_os = "windows")]
use std::net::Ipv4Addr;

/// The zh-CN reply line's time label (the UTF-8 text after CP936 decoding); en
/// uses `time`.
const ZH_TIME_LABEL: &str = "时间";

/// Parse the first RTT (milliseconds) out of the `ping` output (already decoded
/// in the active code page).
///
/// Supports the en `time=2ms` and the zh-CN localized equivalent, including
/// both sub-1ms forms `time<1ms` / the zh variant (recorded as 0ms, the same
/// convention as Linux iputils `time<1 ms`). No reading at all (timeout /
/// unreachable / unrecognized label) returns `None` — the caller records packet
/// loss.
///
/// **The label must be followed immediately by `=` / `:` / whitespace and then
/// a number**: the en statistics line "Approximate round trip **times** in
/// milli-seconds:" and the zh statistics header both contain the time word, but
/// what follows is ordinary text / `(` — without this gate in an all-timeout
/// output, Minimum's `0ms` would be misread as RTT 0 (a fake probe success).
pub fn parse_ping_rtt_ms(text: &str) -> Option<u128> {
    rtt_after_label(text, "time").or_else(|| rtt_after_label(text, ZH_TIME_LABEL))
}

/// The first reading where `label` is immediately followed by a separator and
/// then a number; malformed occurrences are skipped and the search continues.
fn rtt_after_label(text: &str, label: &str) -> Option<u128> {
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(label) {
        let after = &text[from + rel + label.len()..];
        // Only `=`/`:`/whitespace may sit between the label and the reading (a
        // reply line actually has a tight `=`).
        let rest = after.trim_start_matches(['=', ':', ' ', '\t']);
        if let Some(sub_ms) = rest.strip_prefix('<') {
            // `time<1ms` / the zh variant: a sub-millisecond reading; Windows
            // gives no decimals — record 0.
            let digit_end = sub_ms
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(sub_ms.len());
            if digit_end > 0 {
                return Some(0);
            }
            // What follows `<` is not a digit: not a reading, keep looking.
        } else if rest.starts_with(|c: char| c.is_ascii_digit()) {
            let end = rest
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(rest.len());
            return rest[..end].parse::<f64>().ok().map(|v| v.round() as u128);
        }
        from += rel + label.len();
    }
    None
}

/// SEL-001 probe transport (the Windows execution layer): `ping -n 1 -w 1000
/// <ip>` measures the ICMP RTT (milliseconds). The sampling window is aligned
/// with Linux's [`crate::linux::run_ping_rtt`] (`ping -c 1 -W 1`): a single
/// echo, 1s wait.
///
/// The output is decoded in the active code page (a real zh-CN machine is
/// CP936, see [`crate::windows_console`]); when no reading can be parsed (a
/// spawn failure / timeout / unreachable) it is always `None` — recorded as
/// packet loss, never pretending a probe succeeded.
#[cfg(target_os = "windows")]
pub fn run_ping_rtt(target: Ipv4Addr) -> Option<u128> {
    let out = std::process::Command::new("ping")
        .args(["-n", "1", "-w", "1000", &target.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .no_window()
        .output()
        .ok()?;
    parse_ping_rtt_ms(&crate::windows_console::decode_output(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_en_reply_rtt() {
        let out = "\
Pinging 10.240.0.1 with 32 bytes of data:
Reply from 10.240.0.1: bytes=32 time=2ms TTL=64

Ping statistics for 10.240.0.1:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 2ms, Maximum = 2ms, Average = 2ms";
        assert_eq!(parse_ping_rtt_ms(out), Some(2));
    }

    #[test]
    fn parses_zh_reply_rtt() {
        // The real zh-CN machine's output shape (the UTF-8 text after CP936 is
        // decoded by windows_console).
        let out = "\
正在 Ping 10.240.0.1 具有 32 字节的数据:
来自 10.240.0.1 的回复: 字节=32 时间=9ms TTL=64

10.240.0.1 的 Ping 统计信息:
    数据包: 已发送 = 1，已接收 = 1，丢失 = 0 (0% 丢失)，
往返行程的估计时间(以毫秒为单位):
    最短 = 9ms，最长 = 9ms，平均 = 9ms";
        assert_eq!(parse_ping_rtt_ms(out), Some(9));
    }

    #[test]
    fn sub_millisecond_reads_as_zero() {
        assert_eq!(
            parse_ping_rtt_ms("Reply from 10.0.0.1: bytes=32 time<1ms TTL=64"),
            Some(0)
        );
        assert_eq!(
            parse_ping_rtt_ms("来自 10.0.0.1 的回复: 字节=32 时间<1ms TTL=64"),
            Some(0)
        );
    }

    #[test]
    fn timeout_and_unreachable_have_no_reading() {
        // All-timeout (en): only the statistics line's "times" contains the time
        // substring, and no reading follows it — Minimum's 0ms must not be
        // misread as an RTT.
        let en_timeout = "\
Request timed out.

Ping statistics for 10.0.0.1:
    Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms";
        assert_eq!(parse_ping_rtt_ms(en_timeout), None);
        // All-timeout (zh).
        let zh_timeout = "请求超时。";
        assert_eq!(parse_ping_rtt_ms(zh_timeout), None);
        // Unreachable: the reply line carries no time reading.
        assert_eq!(
            parse_ping_rtt_ms("Reply from 10.0.0.1: Destination host unreachable."),
            None
        );
        // Parse failure (ping cannot find the host).
        assert_eq!(parse_ping_rtt_ms("Ping 请求找不到主机。"), None);
    }

    #[test]
    fn zh_stats_header_time_label_is_not_a_reading() {
        // The zh statistics header contains the time word but it is followed
        // directly by `(`, not a reading — an all-timeout output must not have an
        // RTT misread out of its statistics section.
        let out = "\
请求超时。

往返行程的估计时间(以毫秒为单位):
    最短 = 0ms，最长 = 0ms，平均 = 0ms";
        assert_eq!(parse_ping_rtt_ms(out), None);
    }
}
