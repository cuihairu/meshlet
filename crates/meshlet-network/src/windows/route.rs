impl WindowsNetworkBackend {
    pub fn remove_stale_meshlet_routes_sync(
        &self,
        _routes: &[RouteConfig],
    ) -> Result<ApplyResult, NetworkError> {
        Ok(ApplyResult::ok())
    }

    pub fn mtu_probe_sync(&self, target: std::net::Ipv4Addr, payload: u32) -> bool {
        std::process::Command::new("ping")
            .args([
                "-n",
                "1",
                "-f",
                "-l",
                &payload.to_string(),
                &target.to_string(),
            ])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    /// 默认路由底层 MTU 在 Windows 暂无读数实现：`None` = 「读数不可得」，
    /// 探测回退默认尺寸 1392（lane/dataplane-speed 仅落 Linux 读数；Windows
    /// 侧以文档建议 `New-NetIPInterface`/`netsh` 手工核对，见
    /// docs/guide/performance.md）。
    pub fn underlay_path_mtu_sync(&self) -> Option<u32> {
        None
    }
}
