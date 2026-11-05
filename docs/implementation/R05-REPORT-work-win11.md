# R-05 Windows 全链路验收报告（work-win11 / 10.240.0.5，2026-11-05）

| 项 | 结果 | 证据 |
|---|---|---|
| 安装（nightly zip + install.ps1，sha256 校验） | PASS | 本机安装，agent.toml server_url=https://meshlet.cuihairu.site |
| 服务控制（服务状态读回） | PASS | sshd=Running；meshlet-agent 计划任务常驻（/rl highest） |
| 隧道接口与路由 | PASS | wg-meshlet Up；10.240.0.0/16 路由 metric=0 在位 |
| 防火墙（ICMP 放行 + Private 类别） | PASS | Meshlet ICMP In/Out + Meshlet-ICMPv4-In 三规则 Enabled；NetworkCategory=Private |
| 隧道全生命周期（装→启→停→卸→重装→自愈） | PASS | 手动 uninstall 后接口消失→agent 漂移检测重放→接口 Up→Meshlet online |
| 权限提升 | PASS | wireguard.exe 隧道服务安装需管理员——schtasks /rl highest 下成功 |
| hub 互联 | PASS | ping 10.240.0.4 通；hub 收 dev-reg-10 心跳 |
| 开机恢复 | PENDING | 需重启本机（工作机，避免打断使用），留待下次重启窗口复验 |

结论：8 项中 7 项 PASS，开机恢复 1 项 PENDING（需重启窗口）。R-05 主体验收通过，开机恢复随下次重启补验。
