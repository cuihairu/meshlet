use super::backend::WindowsNetworkBackend;
use super::parsing::{
    parse_ping_rtt_ms_windows, parse_wg_dump_diag_line_windows, parse_windows_interfaces_json,
};
use crate::windows_console::NoWindowCommand;
use crate::{NetworkDiagnostics, NetworkError, WgPeerDiagnostic};
use std::net::Ipv4Addr;

impl WindowsNetworkBackend {
    /// R-DIAG network diagnostics information surface collection (Windows,
    /// ordered by the user 2026-11-01): three kinds of snapshots.
    ///
    /// - route table: `route print` (raw full IPv4 table);
    /// - interface list: `Get-NetIPConfiguration` (Name / IPv4 / Prefix / MTU /
    ///   InterfaceOperationalStatus);
    /// - wg-mlt readings: parsed from `wg.exe show <if> dump` (same source as
    ///   [parse_wg_dump_peers] but keeping the endpoint / handshake / transfer
    ///   columns, [WgPeerDiagnostic]).
    ///
    /// Collection is read-only; a failing item is reported as empty/missing
    /// (the diagnostic surface faithfully shows "not fetched").
    pub fn diagnostics_sync(&self) -> Result<NetworkDiagnostics, NetworkError> {
        // Console tools emit redirected output as OEM/ANSI code page bytes
        // (GBK/936 on zh-CN); it must go through windows_console::decode_output —
        // a raw from_utf8_lossy would turn Chinese interface names / gateway
        // descriptions into U+FFFD garbage (pinned down on the imac real machine).
        let route_table = std::process::Command::new("route")
            .args(["print"])
            .no_window()
            .output()
            .map(|out| {
                crate::windows_console::decode_output(&out.stdout)
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
            .no_window()
            .output()
            .map(|out| crate::windows_console::decode_output(&out.stdout))
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

    /// Read diagnostic readings from `wg.exe show <if> dump` (keeps the
    /// endpoint / handshake / transfer columns).
    fn read_tunnel_diag(&self, tunnel_name: &str) -> Vec<WgPeerDiagnostic> {
        let Some(exe) = self.find_wg_exe() else {
            return Vec::new();
        };
        let Ok(out) = std::process::Command::new(&exe)
            .args(["show", tunnel_name, "dump"])
            .no_window()
            .output()
        else {
            return Vec::new();
        };
        let text = crate::windows_console::decode_output(&out.stdout);
        text.lines()
            .skip(1)
            .filter_map(parse_wg_dump_diag_line_windows)
            .collect()
    }

    /// Measure the direct path RTT (milliseconds) with `ping -n 1`. Windows
    /// prints `Reply from 10.0.0.2: bytes=32 time=12ms TTL=64` (Chinese output
    /// uses the localized `time=` label; both the `time` form and the localized
    /// label are matched); failure → `None`.
    pub fn ping_rtt_ms(&self, target: Ipv4Addr) -> Option<u128> {
        let out = std::process::Command::new("ping")
            .args(["-n", "1", "-w", "2000", &target.to_string()])
            .no_window()
            .output()
            .ok()?;
        parse_ping_rtt_ms_windows(&crate::windows_console::decode_output(&out.stdout))
    }
}

/// ISO-8601 string for the current UTC time (Windows; no chrono dependency).
/// Read via `powershell`, falling back to epoch seconds on failure.
fn now_iso_utc() -> String {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "[DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')",
        ])
        .no_window()
        .output();
    if let Ok(out) = out {
        if out.status.success() {
            let text = crate::windows_console::decode_output(&out.stdout);
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
