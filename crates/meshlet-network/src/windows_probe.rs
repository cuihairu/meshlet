//! SEL-001 Windows 探测传输（P0，2026-11-13 接线）：`ping -n 1 -w 1000` 的
//! ICMP echo 实测 RTT（毫秒）。
//!
//! 此前 [`crate::probe::default_transport`] 非 Linux 一律 `None`（记丢包），
//! 三台主力机全是 Windows——SEL-001 探测 / SEL-002 切换在主力平台全盲。
//!
//! 采样窗口与 Linux [`crate::linux::run_ping_rtt`] 对齐：单次 echo、1s 等待
//!（Linux `-W 1` / Windows `-w 1000`），探测是高频轻量操作，诊断级长等待会
//! 拖慢探测线程。
//!
//! 文案纪律与 [`crate::windows_firewall`] 一致：**解析层是跨平台纯函数，
//! Linux 本机可单测**；执行层（跑 ping.exe）`#[cfg(windows)]`。真机 zh-CN 的
//! 重定向输出是 CP936/GBK，先经 [`crate::windows_console::decode_output`]
//! 解码再解析；解析同时认 en `time=` 与 zh `时间=`，其余语系不在验收面内
//!（与防火墙探测的 en+zh 口径一致，如实记录）。
//!
//! 不信任 ping.exe 的退出码（unreachable 的退出码随版本而异）：**解析到回应
//! RTT 才算探测成功**，超时 / 不可达 / 标签不认识一律 `None`——
//! [`crate::probe::probe_round`] 记为丢包，绝不假装探测到。
//!
//! 真机验收（真实 Windows 上的 RTT 读数走查）待 R-05 席位。

#[cfg(target_os = "windows")]
use std::net::Ipv4Addr;

/// zh-CN 回应行的时间标签（CP936 解码后的 UTF-8 文本）；en 为 `time`。
const ZH_TIME_LABEL: &str = "时间";

/// 从（已按活动代码页解码的）`ping` 输出解析首个 RTT（毫秒）。
///
/// 支持 en `time=2ms`、zh `时间=8ms`，与两者的小于 1ms 表示 `time<1ms` /
/// `时间<1ms`（记 0ms，与 Linux iputils `time<1 ms` 同口径）。没有任何读数
///（超时 / 不可达 / 标签不认识）返回 `None`——调用方记为丢包。
///
/// **标签后必须紧跟 `=` / `:` / 空白再接数值**：en 统计行
/// 「Approximate round trip **times** in milli-seconds:」与 zh 统计表头
/// 「往返行程的估计**时间**(以毫秒为单位):」都含时间词，但后面跟的是
/// 普通文字/`(`——全超时的输出里若不设此闸，Minimum 的 `0ms` 会被误读成
/// RTT 0（假探测成功）。
pub fn parse_ping_rtt_ms(text: &str) -> Option<u128> {
    rtt_after_label(text, "time").or_else(|| rtt_after_label(text, ZH_TIME_LABEL))
}

/// `label` 之后紧跟分隔符再接数值的首个读数；不合式的出现处跳过继续找。
fn rtt_after_label(text: &str, label: &str) -> Option<u128> {
    let mut from = 0usize;
    while let Some(rel) = text[from..].find(label) {
        let after = &text[from + rel + label.len()..];
        // 标签与读数之间只允许 `=`/`:`/空白（回应行实为紧贴的 `=`）。
        let rest = after.trim_start_matches(['=', ':', ' ', '\t']);
        if let Some(sub_ms) = rest.strip_prefix('<') {
            // `time<1ms` / `时间<1ms`：亚毫秒读数，Windows 不给小数——记 0。
            let digit_end = sub_ms
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(sub_ms.len());
            if digit_end > 0 {
                return Some(0);
            }
            // `<` 后不是数字：不是读数，继续找下一处。
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

/// SEL-001 探测层传输（Windows 执行层）：`ping -n 1 -w 1000 <ip>` 实测
/// ICMP RTT（毫秒）。采样窗口与 Linux [`crate::linux::run_ping_rtt`]
///（`ping -c 1 -W 1`）对齐：单次 echo、1s 等待。
///
/// 输出按活动代码页解码（真机 zh-CN 是 CP936，见 [`crate::windows_console`]），
/// 解析不到读数（spawn 失败 / 超时 / 不可达）一律 `None`——记为丢包，
/// 绝不假装探测到。
#[cfg(target_os = "windows")]
pub fn run_ping_rtt(target: Ipv4Addr) -> Option<u128> {
    let out = std::process::Command::new("ping")
        .args(["-n", "1", "-w", "1000", &target.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
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
        // 真机 zh-CN 输出形状（CP936 经 windows_console 解码后的 UTF-8 文本）。
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
        // 全超时（en）：仅统计行的「times」含 time 子串，且其后不是读数——
        // 不得把 Minimum 的 0ms 误读成 RTT。
        let en_timeout = "\
Request timed out.

Ping statistics for 10.0.0.1:
    Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),
Approximate round trip times in milli-seconds:
    Minimum = 0ms, Maximum = 0ms, Average = 0ms";
        assert_eq!(parse_ping_rtt_ms(en_timeout), None);
        // 全超时（zh）。
        let zh_timeout = "请求超时。";
        assert_eq!(parse_ping_rtt_ms(zh_timeout), None);
        // 不可达：回应行无时间读数。
        assert_eq!(
            parse_ping_rtt_ms("Reply from 10.0.0.1: Destination host unreachable."),
            None
        );
        // 解析失败（ping 请求找不到主机）。
        assert_eq!(parse_ping_rtt_ms("Ping 请求找不到主机。"), None);
    }

    #[test]
    fn zh_stats_header_time_label_is_not_a_reading() {
        // zh 统计表头「往返行程的估计时间(以毫秒为单位):」含「时间」但紧跟
        // `(`，不是读数——全超时输出不得从统计段误读出 RTT。
        let out = "\
请求超时。

往返行程的估计时间(以毫秒为单位):
    最短 = 0ms，最长 = 0ms，平均 = 0ms";
        assert_eq!(parse_ping_rtt_ms(out), None);
    }
}
