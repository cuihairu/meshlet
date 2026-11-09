use super::backend::WindowsNetworkBackend;
use super::parsing::{
    parse_ping_rtt_ms_windows, parse_wg_dump_diag_line_windows, parse_windows_interfaces_json,
};
use crate::{NetworkDiagnostics, NetworkError, WgPeerDiagnostic};
use std::net::Ipv4Addr;

impl WindowsNetworkBackend {
    /// R-DIAG 网络诊断信息面采集（Windows，2026-11-01 用户令）：三类快照。
    ///
    /// - 路由表：`route print`（IPv4 全表原文）；
    /// - 接口清单：`Get-NetIPConfiguration`（Name / IPv4 / Prefix / MTU /
    ///   InterfaceOperationalStatus）；
    /// - wg-mlt 读数：`wg.exe show <if> dump` 解析（[parse_wg_dump_peers] 同
    ///   源但保留 endpoint / 握手 / 流量列，[WgPeerDiagnostic]）。
    ///
    /// 采集只读；单项失败按空/缺上报（诊断面如实展示「未取到」）。
    pub fn diagnostics_sync(&self) -> Result<NetworkDiagnostics, NetworkError> {
        let route_table = std::process::Command::new("route")
            .args(["print"])
            .output()
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let interfaces = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "Get-NetIPConfiguration | Where-Object { $_.IPv4Address } | ForEach-Object {                  $addr = $_.IPv4Address | Select-Object -First 1;                  $name = $_.InterfaceAlias;                  $state = $_.NetAdapter.Status;                  $mtu = (Get-NetAdapter -Name $name -ErrorAction SilentlyContinue).MtuSize;                  $prefix = if ($addr) { $addr.PrefixLength } else { '' };                  [PSCustomObject]@{ Name=$name; IP=$addr.IPAddress; Prefix=$prefix; State=$state; Mtu=$mtu } } |                  ConvertTo-Json -Compress",
            ])
            .output()
            .map(|out| String::from_utf8_lossy(&out.stdout).to_string())
            .unwrap_or_default();
        let interfaces = parse_windows_interfaces_json(&interfaces);

        let wg = if self.tunnel_service_exists(&self.interface) {
            self.read_tunnel_diag(&self.interface)
        } else {
            Vec::new()
        };

        Ok(NetworkDiagnostics {
            collected_at: Some(now_iso_utc()),
            route_table,
            interfaces,
            wg,
        })
    }

    /// 读 `wg.exe show <if> dump` 的诊断读数（保留 endpoint / 握手 / 流量列）。
    fn read_tunnel_diag(&self, tunnel_name: &str) -> Vec<WgPeerDiagnostic> {
        let Some(exe) = self.find_wg_exe() else {
            return Vec::new();
        };
        let Ok(out) = std::process::Command::new(&exe)
            .args(["show", tunnel_name, "dump"])
            .output()
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .skip(1)
            .filter_map(parse_wg_dump_diag_line_windows)
            .collect()
    }

    /// 以 `ping -n 1` 实测直连路径 RTT（毫秒）。Windows 输出
    /// `Reply from 10.0.0.2: bytes=32 time=12ms TTL=64`（中文为
    /// `时间=12ms`，二者 `time` / `时间` 均匹配）；失败按 `None`。
    pub fn ping_rtt_ms(&self, target: Ipv4Addr) -> Option<u128> {
        let out = std::process::Command::new("ping")
            .args(["-n", "1", "-w", "2000", &target.to_string()])
            .output()
            .ok()?;
        parse_ping_rtt_ms_windows(&String::from_utf8_lossy(&out.stdout))
    }
}

/// 当前 UTC 时刻的 ISO-8601 字符串（Windows；不引 chrono）。用
/// `powershell` 读取，失败回退纪元秒。
fn now_iso_utc() -> String {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')",
        ])
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            let text = text.trim();
            if !text.is_empty() {
                return text.to_string();
            }
        }
    }
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{secs}")
}
