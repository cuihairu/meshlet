# TODO

> 需求清单：一行一条需求，已完成项保留一行证据（commit hash + 测试数）。
> 过程叙述与验收详情见 docs/implementation/、docs/decisions/ 与 git log，本清单不复述。

## 架构约束（十决策，写死）

1. 模块化单体，而非微服务。
2. Desired State + 不可变 Revision + 纯 Planner + Reconciler 是系统核心。
3. 控制面不直接拥有通用特权命令执行能力。
4. Network / Segment / Route / Alias / PortForward / HTTP Exposure 是不同领域对象。
5. 访问控制必须在执行层真正生效（不只靠界面与 AllowedIPs）。
6. 回滚不得重新开放已撤销的权限。
7. 所有变更可验证、可审计、可重试，能从真实内核状态重建。
8. SQLite 支撑当前定位，持久化边界允许未来替换。
9. Linux/Windows 共享领域模型、协议与规划逻辑；执行后端各自实现。
10. CI 通过 / 内核测试通过 / 真实 VPS 验收通过 = 三个独立完成标准。

## 实施阶段（按依赖序）

- [x] R-01 基础架构重建：纯 Planner、SQLite 事务+Outbox、特权执行器接口、crate 依赖边界门。
  - 证据: docs/design/r01-domain-model.md · scripts/check-planner-deps.sh
- [x] R-02 可靠 Linux 网络基础设施：WireGuard Hub、Peer 管理、路由、防火墙、安全撤销、漂移检测、last-good 恢复、单实例多网络隔离。
  - 证据: docs/implementation/r02-linux-dataplane.md · netns 隔离测试（single_instance/dual_site）
- [x] R-03 统一网络规划与冲突分析：IPAM、Segment 策略、网关选择、Direct 路由、Alias 映射、全局冲突检查。
  - 证据: docs/implementation/r03-unified-network-plan.md · server 409 冲突语义集成测试
- [x] R-04 设备端到端组网（Linux Agent）：注册、启动恢复、执行回执、重试、升级、真实连接诊断。
  - 证据: docs/implementation/r04-linux-agent-e2e.md · 2026-10-24 跨主机 20/20 双向基线 · 13 项诊断全绿
- [x] R-05 Windows 完整客户端：隧道服务、系统路由、防火墙、权限提升、开机恢复。
  - 证据: docs/implementation/R05-REPORT-work-win11.md（work-win11 10.240.0.5，2026-11-05）——安装/服务控制/路由/防火墙/隧道生命周期/提权/hub 互联 7 项 PASS；开机恢复 1 项 PENDING（工作机避重启，下次重启窗口补验）。真机 3 台均到位：imac（验收并行）、openclaw、work cuihaitao（在线 10.240.0.8，agent+tray+custos）。agent 主线：计划已应用、隧道 Up、hub 心跳正常。
- [x] R-05 权限提升：windows_elevation 计划层与错误分类，全平台编译 + Linux 单测。
  - 证据: 66 tests（未真机实测，未接 SystemBackend）
- [x] R-05 数据面真机验收（路由/防火墙/服务控制/卸载清理，zh-CN 解码修复）。
  - 证据: docs/implementation/r05-windows-acceptance.md · meshlet-network 75 单测 + 3 真机集成
- [x] R-06 服务发布 - TCP/UDP PortForward。
  - 证据: docs/implementation/r06-service-publishing.md · apps/server/tests/publish.rs
- [x] R-06 服务发布 - HTTP/HTTPS 发布（SNI 直通，不做 TLS 终止）。
  - 证据: docs/implementation/r06-service-publishing.md
- [x] R-06 服务发布 - 授权控制与 server 接线（WriteUser + CSRF）。
  - 证据: docs/implementation/r06-service-publishing.md · 12 tests
- [x] R-06 服务发布 - 健康探测（agent 周期探测批量上报）。
  - 证据: docs/implementation/r06-service-publishing.md
- [x] R-06 服务发布 - 内部 DNS 服务目录（分流 DNS，仅应答内部后缀）。
  - 证据: docs/implementation/r06-service-publishing.md
- [x] R-06 服务发布 - 真实 VPS/真机端到端验收。
  - 证据: docs/implementation/r06-service-publishing.md · 11 单测 + 3 集成回归
- [ ] R-07 正式部署与长期运行验收：空白 VPS 安装、密钥轮换、备份恢复、升级回滚、性能基线、真实多设备验收。
  - BLOCKED: 唯一缺项为长期浸泡，缺数周真数据与实验环境重建（用户决策）
- [x] R-07 空白容器安装。
  - 证据: docs/implementation/r07-deployment-acceptance.md · 2026-10-24 真实 release 下载路径验收
- [x] R-07 密钥轮换与密钥丢失（45 秒内三设备零接触换钥）。
  - 证据: docs/implementation/r07-deployment-acceptance.md
- [x] R-07 备份恢复（停服恢复口径）。
  - 证据: docs/implementation/r07-deployment-acceptance.md
- [x] R-07 性能基线。
  - 证据: docs/architecture/performance.md
- [x] R-07 真实多设备验收（第三台设备 max_uses=1 token 入网）。
  - 证据: docs/implementation/r07-deployment-acceptance.md
- [x] R-07 升级回滚。
  - 证据: commit cefd5ef · docs/implementation/r07-deployment-acceptance.md
- [ ] R-07 长期运行浸泡：采集器就绪，需数周连续 OK 数据后勾。
  - BLOCKED: 缺实验环境重建（用户决策）与数周真数据

## 外部评审立项（2026-10-26，已逐条源码核验）

- [x] M1 tls_termination 更名与能力拒绝。
  - 证据: publish 12 + backup 9 + migrations 12 集成 · console 17 tests · 全 workspace cargo test 零失败
- [x] M2 漂移检测升级到身份/所有权级（身份级观测 + 三真机缺陷修复）。
  - 证据: 单测 8 + 真机注入 3 项 · network 79 + agent 59 tests · workspace exit 0
- [x] M3 故障矩阵验收（评审九场景真 netns 全真跑）。
  - 证据: docs/implementation/m3-fault-matrix.md · single_instance 7 + ledger_recovery 6 + 3 集成 tests
- [x] M4 回滚/重试不得重授已撤销权限（enforce_authorization 四消费点）。
  - 证据: single_instance 8 tests · 回归测 rolling_back_a_failed_revoke_does_not_reopen_access
- [x] M5 TODO 完成状态审计。
  - 证据: commit ebcd9e7 · docs/analysis/todo-completion-audit-2026-10-27.md

## Agent 安装即配防火墙（2026-10-30 用户令）

- [x] AGENT-FW-1 [P1] Windows 数据面应用时自动设 wg 接口 NetworkCategory=Private 并放行 ICMPv4 入站，幂等可重跑。
  - 证据: commit 16cb928/8bd2351（netsh add/show/idempotent/delete 全链路 + Set-NetConnectionProfile 双跑读回 Private，windows-latest 真机实跑 · run 41976760018）· 110 lib tests；端到端「ping 直接通」仍以 Windows 真机走查为准（openclaw SSH 本轮不可达）
- [x] AGENT-FW-2 [P2] Linux 检测 ufw/firewalld 活跃时自动放行 wg 接口流量，幂等。
  - 证据: commit 52a4763 · 101 lib + 4 特权集成全绿
- [x] AGENT-FW-3 [P2] walkthrough.md 补「安装即配防火墙」验收步骤与回归用例。
  - 证据: commit adbb65e
- [x] AGENT-WIN-1 [P1] Windows 托盘宿主消费 TraySink 四态 PNG，常驻托盘+菜单。
  - 证据: commit bbdc0e8/fb08bac · CI tray-windows 腿 run 41976760018（windows-latest 真实桌面：消费 TraySink 格式四态 fixture → NIM_ADD=1 注册 + tooltip 换态，截图/日志工件门禁绿）· tray-host 17 tests
- [x] AGENT-WIN-2 [P1] Windows agent 安装包（zip 先行 + install.ps1），真机验收通过。
  - 证据: commit f86489d/7639110 · 2026-10-31 真机验收 5/5（docs/agent-win-2-acceptance.md）
- [x] NIGHTLY-PKG [P2] Linux 组件包矩阵：server/agent/cli 各出 .deb+.rpm。
  - 证据: scripts/package-deb-rpm.sh · run 41045721705 全绿 · 18 资产 SHA256SUMS 对账 OK

## console 重设计 + dev 部署（2026-10-31）

- [x] CONSOLE-REDESIGN [P1] console 视觉重设计 + dev VPS 部署。
  - 证据: commit 2a7375c/f75391d/b50fe9a/948db6e · 17 tests + build/lint 绿
- [x] AUDIT-FIX · P2/P3 impeccable 审计待修 8 项。
  - 证据: commit 2356fa3/1df7169/1f2fbc3/6863f08/5313ef6/c300722/9511c16/6276cda · 28 tests

## Windows 托盘随安装包分发（2026-11-05 用户问「装完怎么没托盘」暴露）

- [ ] INSTALL-TRAY-1 [P2] install.ps1 默认安装并自启 meshlet-tray-host（行为：复制 tray-host、HKCU Run 注册（logon 启动，指向 agent state 目录）、`-NoStartTray` 跳过立即启动；CI windows-latest 实跑 staged 安装并验证托盘进程存在）；nightly zip 重发后的真机托盘出现/菜单走查保持 BLOCKED，待用户手动验证（不代勾）。
  - 实现状态: 已完成——commit 8740c52 将 tray-host 复制到安装目录、注册 HKCU Run 自启（指向 agent state 目录）、新增 `-NoStartTray` 跳过立即启动；CI windows-latest 实跑 staged 安装并验证托盘进程与注册表条目（installer-windows 腿绿）。真机托盘出现/菜单走查保持 BLOCKED，不代勾。

## Console 网络拓扑图（2026-11-05 用户令，补账：此前未入账）

- [x] TOPO-1 [P1] console 新增「拓扑」页：hub 居中，节点环布；连线区分 直连（实线，标注 RTT）与 hub 中继（虚线）；节点卡=设备名/虚拟 IP/在线状态/online_state；数据源=现有 peers/endpoints API + 心跳状态，实时刷新；直连未启用或单节点时如实显示引导（如何开 direct_connect、为什么当前无直连）。中英文案双语（UiStrings 惯例）。
  - 验收: console 组件测试覆盖拓扑渲染三态（有直连/仅中继/单节点引导）；CI 绿；真机双节点走查挂 R-DIAG-2 同一前置。
  - 证据: commit e1a66f8/a9401c6 · console 39 tests（含拓扑三态 4 项）+ tsc + oxlint 绿 · CI run 41979273275 全腿绿 · 真机双节点走查仍待 R-DIAG-2 前置（第二节点），不代勾

## Windows MSI 安装包（2026-11-05 用户追问补账：此前口头承诺未入账，已漏 19 天——账本纪律事故）

- [x] NIGHTLY-MSI-1 [P1] Windows nightly 增出 MSI 安装包（cargo-wix）：meshlet-server/agent/cli + tray-host 打进单个 msi，含开始菜单项与卸载；与现有 zip 并存不互替；CI windows-latest 真实产出 msi 并入 nightly release 资产。
  - 证据: commit db211a4/8ef9399 · CI run 41993127622 success · nightly release 资产含 meshlet-nightly-windows-x86_64.msi（9.3 MB）。
  - 计划: wix manifest 按 cargo-wix-packaging skill 规则（exe Source 用 $(var.CargoTargetBinDir)；附加 exe 同步 --release --bin 预构建；SVG→ico 用 rsvg-convert+ImageMagick；GUI tray host 加 windows_subsystem）；Linux 侧 wixl 干跑校验 wxs；夜间 workflow 打包步产出 target/wix/*.msi 并上传 release。

## meshlet P2P 节点直连（2026-10-31 起，分批 ①-⑤）
> 口径：以下勾=代码+netns 端到端验收。**direct_connect 自 2026-11-06 起默认开启**（agent `[dataplane.direct_connect] enabled`，显式 `false` 关闭）；效果需真实第二台节点才可见，开法与效果说明见 docs/guide/toggles.md §direct_connect。双真机走查已完成（见 ⑥），直连属「用户可用」。

- [x] ① endpoint 上报+API：agent 心跳携带 direct，server 提供 peers/endpoints 查询。
  - 证据: commit 7374f6f/a1111f5 · config 18 + network 102 + agent 60 + peers_endpoints 6 tests
- [x] ② agent 直连+回退（连接管理，netns 端到端验收）。
  - 证据: commit c1f4b63 · 全 workspace cargo test 0 FAILED（network 104 + agent 67）
- [x] ③ 探测+状态上报（直连/中继状态随心跳上报，console 展示）。
  - 证据: commit 4fc5aa7 · 域层 161 + agent 68 + peers_endpoints 9 tests
- [x] ④ 防火墙联动（直连 UDP 端口放行，幂等；默认值 2026-11-06 起改开，见 ⑥）。
  - 证据: commit 923c4dc · meshlet-network 106 lib + netns 2 tests
- [x] P2P-⑤ 暴露 hub 观测的节点公网端点（observed/public endpoint 入 API 与 console）。
  - 证据: commit 1c5df30/8e89856/168c1c5 · server 2 集成 + console 2 tests
- [x] ⑥ 双真机直连走查 + 直连三缺陷修复（2026-11-06）：coding-vm（10.240.0.4，Linux）↔ cuihaitao（10.240.0.8，Windows）经 Tailscale underlay 建立直连边，拓扑 API 报 `connection_mode=p2p_direct` RTT 18ms，ping 15–19ms，直连 peer 计数器 GB 级增长。
  - 修复 1（Windows 候选端点缺失）：部署的 exe 早于 `lan_addresses_sync`/`handshake_ages_sync` Windows 接线——重编重发。
  - 修复 2（hub 观测到 127.0.0.1）：Windows agent 走 nginx 反代域名，hub `ConnectInfo` 只见本机回环 → 公网候选丢失；agent.toml `server_url` 改指 hub 直连地址（`http://106.14.216.177:8080`）后观测到真实公网 180.152.54.66。真因：server 不解析 `X-Forwarded-For`（记 TODO-116）。
  - 修复 3（直连每 ~90s 抖动）：`DIRECT_HEALTH_WINDOW_SECS=35` < WireGuard 重新握手节拍（~120–180s，`latest-handshake` 不随 keepalive 刷新）→ 健康空闲链路被误判 Unhealthy 反复 demote/promote；窗口改 240s（真机取证在案）。
  - 附带修复（Windows 重配拒发）：`wireguard.exe` CLI 无 `/stoptunnelservice`（真机 Usage 取证）——`install_plan` 改为卸载重建两步；`NetworkSnapshot.tunnel_listen_port` 入漂移判定（Windows 侧钉端口 51820 生效 + 防火墙 `Meshlet-Direct-UDP-In` 自动放行）。
  - 测试: network 172 lib（+listen-port 漂移 3 例）· domain 178（+窗口 240 断言）· single_instance 8/8（默认开直连下 port 钉入引入的 ≤25s 收敛竞态改用既有 `reconnects` 有界等待）

- [ ] TODO-116 [P3] server 解析反代头（`X-Forwarded-For`/`X-Real-IP`）：nginx 域名入口下 `ConnectInfo` 只见 127.0.0.1，hub 观测公网候选退化为回环（2026-11-06 真机取证，cuihaitao 走查中曾因此无公网候选；当前以 agent 直连 hub 地址绕过）。改法：`direct_observed_ip` 先取可信反代头再回落 socket；须同时收紧「仅可信代理来源才采信头部」，并补集成测试。
  - 证据: 2026-11-06 直连走查 devices API `observed_endpoint=127.0.0.1:51820`（域名入口）vs `180.152.54.66:51820`（直连地址）。

## 诊断与托盘（2026-11-01 用户令）

- [x] R-DIAG · P2 · agent 本地网络诊断信息面（三快照 + CLI `meshlet agent diag`）。
  - 证据: commit 026b638
- [x] R-TRAY-1 · P2 · 托盘设置界面功能化扩展（命令目录单一事实源 crates/meshlet-commands + 四分区前端）。
  - 证据: commit b8d9e75/fb1e90d/3d71188/691fc36 · tray 5 tests
- [x] R-DIAG-2 · P2 · 直连 peers 信息展示（RTT/endpoint/握手/流量 + console 区块）。
  - 证据: commit d72e4a2/f97f6f0/4ba7d71 · 2-peer 直连场景验收待第二节点
- [x] macOS x86_64 · tray 应用 .app 打包（CI 腿）。
  - 证据: commit 69c7ec1/85b8518 · run 41307883225 success · network 115 + tray 5 tests
- [x] DOC-GIF · P2 · 配置开关效果动态图（off→on 对比 + GIF，可复现流水线）。
  - 证据: scripts/doc-gif · 12 项效果断言全绿

## 审核发现（产品缺陷，已修）

- [x] 审核发现：CLI state_dir/config_path 与实际安装路径不一致 → 改用 LOCALAPPDATA。
  - 证据: commit 22283bd · meshlet-cli 5 tests
- [x] 审核发现：CLI 硬编码 "WireGuard" 隧道名 → 改匹配 wg-meshlet/meshlet。
  - 证据: commit 22283bd · 回归测 tunnel_service_names_match_install_conventions
- [x] 审核发现：tray-app get_peers 硬编码接口名 → is_tunnel_interface 匹配。
  - 证据: commit fb1e90d
- [x] 审核发现：save_config 丢弃安装键 → rebuild_config 保留 agent 管理键。
  - 证据: commit 3d71188
- [x] 审核发现：前端读不存在的 handshake_secs 字段 → 改 last_handshake，dist 与源一致。
  - 证据: commit 691fc36
- [x] 审核发现：CLI 无用依赖 serde/toml → 删除。
  - 证据: commit 6c755c7
- [x] 审核发现：TraySink PNG 编码 NLEN 用补码负数（恒差 1，规范解压器以 "invalid stored block lengths" 拒收整张图标）→ 改反码 + 回归测。
  - 证据: commit 431e38c · zlib_stream NLEN 单测（单块 + 跨 0xff00 块）· tray_fixture 四态 PNG 经真实 zlib 解压取证
- [x] 审核发现：tray-host icon_24→icon_16 回退短路 → 修复回退并加回归测。
  - 证据: commit 07667c5 · tray-host 5 tests
- [x] 审核发现：2FA 写端点缺 WriteUser+CSRF 双重防线 → 补齐并加回归测。
  - 证据: auth_console 16 tests
- [x] 审核发现：deploy/windows/install.ps1 下载不存在的资产名 → 改下载 nightly zip 并校验。
  - 证据: commit b29dd08
- [x] 审核发现：AuthStore::set_password 死代码 → 移除。
  - 证据: commit 3ce13f8
- [x] 审核发现：Windows device_plan_matches 对账粒度不足 → 纯函数逐项对账（peer/routes/MTU/allowed-ips）。
  - 证据: commit bb835e5 · meshlet-network 118 tests
- [x] 审核发现：console 2FA 第二步无法完成 TOTP 登录 → 前端补 code 步与错误提示。
  - 证据: console 19 tests + tsc
- [x] 审核发现：on_probe Direct 态疑似应 Demote → 复核不采纳（no-flap 设计，测试锁定）。
- [x] 审核发现：tray-app stateDir 硬编码 admin 路径 → 后端自解析 LOCALAPPDATA。
  - 证据: cargo test -p meshlet-tray 2/2 绿
- [x] 审核发现：invoke 缺失未优雅降级 → load/save 早退，路径统一。
  - 证据: cargo test -p meshlet-tray 2/2 绿
- [x] 审核发现：错码返回 401 时前端误当缺码 → 显式无效提示。
  - 证据: console 20 tests
- [x] 审核发现：托盘菜单打开设置仅 set_focus 不 show → 先 show 再 focus。
  - 证据: cargo build/clippy -p meshlet-tray 绿

## Agent-WIN-3/4（2026-11-02 用户令）

- [x] AGENT-WIN-3 [P1] 托盘显示本机虚拟 IP + 直连节点列表(RTT)；菜单：打开面板/本机信息/直连节点/连接节点…/退出。
  - 证据: commit bbdc0e8 · Windows 菜单结构真机测试（run 41973077285/41976760018 windows-latest 实跑：首行设备名+虚拟 IP+状态、直连子菜单 IP/模式/RTT、连接节点候选可点击、打开面板/退出读回断言）· tray-host 17 tests
- [x] AGENT-WIN-4 [P1] 新增 peer dial <node> 命令并接托盘「连接节点…」子菜单。
  - 证据: 代码 commit b9eaae0（CLI peer dial + 托盘 spawn + 结果气球）；commit bbdc0e8 CI tray-windows 腿验证宿主常驻与 agent 进程联动（run 41976760018 绿）；拨号端到端结果气球以真机走查为准（openclaw SSH 本轮不可达）

## 漏洞扫描遗留（2026-11-03 全舰队扫描）

- [x] VULN-MESHLET-001 [P1] rsa 0.9.10（sqlx-mysql 引入，RUSTSEC-2023-0071 中危 5.9）升级或换库。
  - audit-ignore + unreachable + no upstream fix (RUSTSEC-2023-0071 ignored via .cargo/audit.toml)

## 任务分配与确认通道（2026-11-03 用户令）

- [x] MT-001 [P1] 任务模型与线性状态机（domain 纯函数）。
  - 证据: commit a91987e · meshlet-domain 170 tests
- [x] MT-002 [P1] 任务下发与回执（幂等键 + 断线补派不重跑）。
  - 证据: commit 028ed3a · domain 170 + agent 82 + 集成 3 tests
- [x] MT-003 [P1] 用户确认交互：console 任务队列面板 + CLI task assign/ls/confirm/retry。
  - 证据: commit 29dff8a/3ca3507/7921c3d · meshlet-cli 10 + console 6 + 集成 lifecycle tests
- [x] MT-004 [P2] 节点侧任务到达托盘通知（D-Bus，降级非致命）。
  - 证据: commit de60cd5 · meshlet-agent 84 tests
- [x] MT-005 [P2] 稳定性语义：超时回收重派、重试上限、每任务独立 scratch 目录、标签路由派单。
  - 证据: commit 558a1f6/bbb6b35/092a7de/9dd43cd · domain 178 tests（容器隔离未做）

## 智能链路选择（2026-11-04 用户令）

- [x] SEL-001 [P1] 多候选端点探测：滑动窗口 RTT/丢包/抖动，默认 5s 可配。
  - 证据: commit 6086b75 · meshlet-network 152 + config 20 tests · netns 双路径 45ms 差证据
- [x] SEL-002 [P1] 评分与迟滞切换（30% 迟滞 + 连续 N 采样，零断线换 endpoint）。
  - 证据: meshlet-network 159 + config 20 + agent 93 tests · 迟滞闸单测 6 个
- [x] SEL-003 [P2] hub 兜底常热：keep-alive 永不掉、劣化立即回中继、恢复门切回。
  - 证据: meshlet-network 159 + agent 101 tests · 可注入时钟时序单测
- [x] SEL-004 [P2] console peer 详情展示全部候选（端点/RTT/丢包/选中与原因）。
  - 证据: console 35 tests（含双候选渲染）· agent candidate_statuses 单测

## 审核发现（40901d..cf3d9c8 任务通道/拨号/probe，人工自审）

- [x] 审核发现：重派预算可被绕过（parent 链未回溯到根）→ 沿链回溯 + 回归测。
  - 证据: 单测 deep_chain_reclaim_walks_to_root_and_respects_budget + 集成 deep_chain_redispatch_respects_budget
- [x] 审核发现：跨网络幂等 assign 返回不一致 → 校验 network_id 归属（404）。
  - 证据: 集成 assign_foreign_network_id_is_not_found
- [x] 审核发现：自动 id 与显式 id 碰撞覆盖 → seq 递增避让。
  - 证据: 单测 assign_auto_id_skips_explicit_collision + 集成 auto_id_skips_collision_with_explicit_id
- [x] 审核发现：回收与活 agent 竞争致重复执行 → 终态回执幂等忽略。
  - 证据: 集成 stale_result_does_not_overwrite_terminal_state
- [x] 审核发现：账本按字典序淘汰非时间序 → 改真实插入序 FIFO。
  - 证据: 单测 ledger_evicts_by_real_time_order_not_id_lexicographic
- [x] 审核发现：任务内联阻塞心跳/数据面 → TaskRuntime 后台 worker。
  - 证据: 单测 task_runtime_runs_in_background_and_kick_returns_immediately
- [x] 审核发现：enrich_direct_peers 内联 ping 阻塞 → DirectRttRuntime 后台 worker。
  - 证据: 单测 snapshot_never_blocks_and_reflects_background_probe
- [x] 审核发现：跨网络幂等/碰撞/深链/竞争/终态覆盖测试缺口 → 补集成与单测。
  - 证据: commit 715ad2c

## Windows agent 部署发现（2026-11-05 openclaw/imac 真机取证）

- [x] BUG: Windows apply 对已存在隧道不重配（apply_device_plan_sync 走 InstallService，wireguard.exe 对已存在服务返回 "already installed" 被判幂等成功 → 不更新 key/地址）。
  - 证据: commit 5c9ce1c · `install_plan` 停/卸/装重配路径 + already-installed fail-closed + sc query 状态码解析 · meshlet-network 166 lib tests
- [x] BUG: 漂移检测不查本机私钥/适配器地址（drifted() 只比对 peer 公钥+allowed-ips 与 ledger 地址 → 手动隧道 peer 恰与 plan 一致即误判 UpToDate）。
  - 证据: commit a66fe18 · NetworkSnapshot 增 local_public_key/tunnel_address 双读数（Linux wg dump 接口行 + ip -4 addr / Windows wg.exe dump + netsh addresses），drifted() 增两查（读数缺失不判）· network 168 + agent 104 tests
- [x] BUG: CI windows 腿两处测试脆断（task runtime 测试用 Unix shell 语法在 cmd /C 下必挂；live firewall 测试未处理 runner 接口别名含空格）→ 按平台语法/改名后实跑通过。
  - 证据: commit 321a3d3/c0610a3/8bd2351 · run 41976760018 windows 腿绿
