# AGENT-WIN-2 Windows 真机验收 (2026-10-31)

## 环境
- Windows 11, 16 vCPU / 31 GB
- WireGuardNT 驱动已安装
- meshlet server: 106.14.216.177:51820 (dev)

## 验收结果

| # | 项目 | 结果 |
|---|------|------|
| 1 | WireGuard 隧道服务 | PASS - WireGuardTunnel\ [Running] |
| 2 | ping hub (10.240.0.1) | PASS - 11ms, 0% loss |
| 3 | ping self (10.240.0.5) | PASS |
| 4 | agent 进程 (计划任务) | PASS - PID=12844, State=Running |
| 5 | 路由表 10.240.0.0/16 | PASS |
| 6 | 防火墙 ICMP 规则 | PASS - Meshlet ICMP (WireGuard) In/Out |
| 7 | tray-host | PASS - PID=56920, 绿色方块图标 |
| 8 | tray-host 右键菜单 | PASS - TPM_RETURNCMD 已修复 |

**5/5 项通过**

## 已知问题
- KernelDrift: agent 持续重放 plan（隧道手动安装过，状态不一致，功能正常）
- tray 图标为 GDI 占位绿块，未解码 PNG

## 部署方式
- agent: 计划任务 MeshletAgent (SYSTEM, AtStartup)
- tray: 计划任务 MeshletTrayHost (admin, AtLogOn)
- 二进制: C:\ProgramData\meshlet\meshlet-agent.exe
- 配置: C:\ProgramData\meshlet\config.toml
