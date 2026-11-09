use super::backend::WindowsNetworkBackend;
use super::parsing::parse_ip_enable_router;
use crate::NetworkError;

impl WindowsNetworkBackend {
    pub(super) fn tunnel_service_exists(&self, tunnel_name: &str) -> bool {
        let service_name = format!("WireGuardTunnel${tunnel_name}");
        std::process::Command::new("sc")
            .args(["query", &service_name])
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }

    pub(super) fn forwarding_enabled(&self) -> Option<bool> {
        let output = std::process::Command::new("reg")
            .args([
                "query",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "/v",
                "IPEnableRouter",
            ])
            .output()
            .ok()?;
        parse_ip_enable_router(&String::from_utf8_lossy(&output.stdout))
    }

    /// 确保 IP 转发开启（镜像 Linux `sysctl -w net.ipv4.ip_forward=1`）。
    ///
    /// [crate::NetworkSnapshot] 的 `forwarding_enabled` 读 `IPEnableRouter`
    /// 注册表；[`apps/agent` 的漂移判定] 要求其为 `Some(true)`，否则
    /// `KernelDrift` 每轮重放。Windows 客户端默认缺失/为 0，必须在此置 1
    /// 才能收敛（幂等：已为 1 则跳过，`/f` 覆盖写仅在实际变更时）。
    pub(super) fn ensure_ip_forwarding_sync(&self) -> Result<(), NetworkError> {
        if self.forwarding_enabled() == Some(true) {
            return Ok(());
        }
        let status = std::process::Command::new("reg")
            .args([
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                "/v",
                "IPEnableRouter",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .status()
            .map_err(|error| {
                NetworkError::Io(format!(
                    "enable IP forwarding (reg add IPEnableRouter): {error}"
                ))
            })?;
        if !status.success() {
            return Err(NetworkError::ApplyRejected(
                "enable IP forwarding failed: `reg add IPEnableRouter=1` did not succeed \
                 (run the agent elevated)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// AGENT-FW-1 接线：设备计划 apply 时按档位走 mesh 可达性防火墙。
    ///
    /// 镜像 Linux `ensure_host_firewall_sync` 的纪律——探测
    /// 失败按「未满足」处理（fail toward action；档位 set 与规则 add 均幂等），
    /// 执行失败显式报错，绝不假装生效。置于隧道与路由之后调用：
    /// `SetNetworkCategoryPrivate` 需接口已存在。
    pub(super) fn ensure_mesh_reachability_sync(
        &self,
        device_addr: std::net::Ipv4Addr,
    ) -> Result<(), NetworkError> {
        let category_is_private = self.probe_net_category_is_private();
        let icmp_rule_state = self.probe_icmp_rule_state(device_addr);
        let commands = crate::windows_firewall::mesh_reachability_commands(
            &self.interface,
            device_addr,
            category_is_private,
            icmp_rule_state,
        )?;
        for command in &commands {
            crate::windows_firewall::exec::run_mesh_firewall_command(command)?;
        }
        Ok(())
    }

    /// `(Get-NetConnectionProfile -InterfaceAlias <if>).NetworkCategory` 探测：
    /// exit 0 且值为 Private → 已满足；接口未找到 / 命令失败 → 未满足（宁补
    /// 不漏，档位 set 天然幂等）。只取档位值，绝不在整段输出搜 `private`——
    /// 否则连接名含该词的 Public 档会被误判（审核发现 #4）。
    pub(super) fn probe_net_category_is_private(&self) -> bool {
        let Ok(output) = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "(Get-NetConnectionProfile -InterfaceAlias '{}').NetworkCategory",
                    self.interface
                ),
            ])
            .output()
        else {
            return false;
        };
        if !output.status.success() {
            return false;
        }
        crate::windows_firewall::net_category_is_private(&String::from_utf8_lossy(&output.stdout))
    }

    /// `netsh advfirewall firewall show rule name=Meshlet-ICMPv4-In` 在场状态。
    ///
    /// 仅按名判在场会在地址变更 / 同名规则被禁用后误报为已满足（审核发现
    /// #1）：需逐块核对「已启用 且 localip 匹配当前设备地址」。netsh 输出按
    /// 活动代码页编码，走 GBK 兑底解码。
    pub(super) fn probe_icmp_rule_state(
        &self,
        device_addr: std::net::Ipv4Addr,
    ) -> crate::windows_firewall::IcmpRuleState {
        let Ok(output) = std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                "name=Meshlet-ICMPv4-In",
            ])
            .output()
        else {
            return crate::windows_firewall::IcmpRuleState::Absent;
        };
        if !output.status.success() {
            return crate::windows_firewall::IcmpRuleState::Absent;
        }
        let text = format!(
            "{}{}",
            crate::windows_console::decode_output(&output.stdout),
            crate::windows_console::decode_output(&output.stderr),
        );
        if !crate::windows_firewall::firewall_rule_present(&text) {
            return crate::windows_firewall::IcmpRuleState::Absent;
        }
        if crate::windows_firewall::rule_output_has_satisfied_icmp_rule(&text, device_addr) {
            crate::windows_firewall::IcmpRuleState::Satisfied
        } else {
            crate::windows_firewall::IcmpRuleState::Stale
        }
    }

    /// 直连 UDP 端口入站放行（批次④ Windows 接线）：`Meshlet-Direct-UDP-In`
    /// 规则（protocol=udp / localport=<port> / profile=any）。在场且端口匹配
    /// → 跳过；在场但端口已变（审核发现 #3）→ 先 `delete name=<rule>` 清掉
    /// 全部同名旧端口规则再 add——netsh 重复 add 同名规则会叠出重复项，
    /// 只加不清会在端口漂移后同时放行新旧两个端口。
    pub(super) fn ensure_direct_udp_firewall_sync(&self, port: u16) -> Result<(), NetworkError> {
        let output = self.direct_udp_rule_output();
        if crate::windows_firewall::firewall_rule_present(&output) {
            if crate::windows_firewall::rule_output_mentions_port(&output, port) {
                return Ok(());
            }
            // 端口漂移：清空同名规则（delete 按 name 删全部同名项，幂等），
            // 落到下方 add 重建当前端口的新规则。
            let cleanup = crate::windows_firewall::FirewallRuleCommand::Delete {
                name: crate::windows_firewall::DIRECT_UDP_RULE_NAME.into(),
            };
            let result = crate::windows_firewall::exec::run_firewall_command(&cleanup)?;
            if !result.applied {
                return Err(NetworkError::ApplyRejected(format!(
                    "stale direct UDP firewall rule not removed: {}",
                    result.error.as_deref().unwrap_or("unknown")
                )));
            }
        }
        let command = crate::windows_firewall::FirewallRuleCommand::Add {
            rule: crate::windows_firewall::direct_udp_rule(port),
        };
        let result = crate::windows_firewall::exec::run_firewall_command(&command)?;
        if result.applied {
            return Ok(());
        }
        Err(NetworkError::ApplyRejected(format!(
            "direct UDP firewall rule not applied: {}",
            result.error.as_deref().unwrap_or("unknown")
        )))
    }

    /// `netsh advfirewall firewall show rule name=Meshlet-Direct-UDP-In` 输出
    /// （GBK 兑底解码；命令失败 / spawn 失败 → 空文本，判为不在场）。
    fn direct_udp_rule_output(&self) -> String {
        std::process::Command::new("netsh")
            .args([
                "advfirewall",
                "firewall",
                "show",
                "rule",
                &format!("name={}", crate::windows_firewall::DIRECT_UDP_RULE_NAME),
            ])
            .output()
            .map(|out| {
                format!(
                    "{}{}",
                    crate::windows_console::decode_output(&out.stdout),
                    crate::windows_console::decode_output(&out.stderr),
                )
            })
            .unwrap_or_default()
    }
}
