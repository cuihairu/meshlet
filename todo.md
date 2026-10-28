# TODO（重构基线版 · 2026-10-20）

> 依据：docs/architecture/target-architecture.md（ChatGPT 重构计划评审，用户令重写）。
> 旧版清单已归档 docs/archive/todo-pre-refactor-2026-10-20.md，不再作为实现前提。

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

- [x] R-01 基础架构重建（骨架已落：crates/meshlet-planner 零依赖纯逻辑+状态机+确定性计划；crates/meshlet-store SQLite Revision+Outbox 事务；crates/meshlet-executor Prepare→Verify→Recover 契约；docs/design/r01-domain-model.md；r01-schemas/outbox.sql+openapi.yaml；scripts/check-planner-deps.sh 依赖门）：领域模型（五资源+Device/NetworkAttachment 分离）、Revision/Plan/Receipt、协议 Schema、crate 依赖边界；纯 Planner；SQLite 事务+Outbox；特权执行器接口。
- [x] R-02 可靠 Linux 网络基础设施：WireGuard Hub、Peer 管理、路由、防火墙、安全撤销、漂移检测、last-good 恢复、单实例多网络隔离。（**2026-10-27 事实修正（M5 审计）**：产品路径的防火墙引擎是 **iptables**（`crates/meshlet-network/src/linux.rs` 的 `LinuxNetworkBackend`，server 与 agent 均消费），本行原写「nftables」有误——nftables 实现只存在于从未被任何 app 依赖的 `crates/meshlet-net-linux`，该 crate 已于同日删除，`docs/implementation/r02-linux-dataplane.md` 顶部已加注；原「隔离已在编译器与防火墙规则层覆盖」一句随 crate 删除失效，现由 `single_instance.rs:212`/`dual_site_end_to_end.rs` 在 netns 层证明（M3 场景 5）。真实 VPS 转发/连通验收与安全撤销 API 细化拆入 R-04/R-07 适配层与验收；跨 netns 部署隔离留待部署主线。）
- [x] R-03 统一网络规划与冲突分析：IPAM、Segment 策略、网关选择（确定性）、Direct 路由、Alias 映射、全局且与创建顺序无关的冲突检查。（**2026-10-27 事实修正（M5 审计）**：`meshlet-netplan` 从未被 server 消费——server 在 `apps/server/src` 内自建冲突检查（409 语义：`routes.rs:239` 同网段重叠、`aliases.rs:288` 重叠前缀点名对端等集成测试覆盖），计划哈希对路由重排的稳定性由产品路径测试 `device_plan.rs:590` 保证；该纯库连同其打乱顺序独立性测试已于同日删除，`docs/implementation/r03-unified-network-plan.md` 顶部已加注。本项已勾的依据是 server 产品路径的上述性质，不再引用已删除 crate。）
- [x] R-04 设备端到端组网（Linux Agent）：注册（Bootstrap Token 只存摘要）、启动恢复、执行回执、重试、升级、真实连接诊断。（2026-10-24 PVE 实验台真机验收：空库真实 bootstrap→登录→409 负例→建网→token 只回原文一次→两台设备持 token 自注册→approve→apply→收敛；跨主机基线 20/20 双向、DF 1392 通/1419 与 1472 `+2 errors 100% loss`；13 项诊断收敛后全绿（`recent_handshake 2/2`、`mtu_planned` 引用设备读数 `1420 probe 1392`）；MTU 漂移 1480→1420 一个 tick 愈合（`KernelDrift`）、显式 `tunnel_mtu=1480` 一个 tick 生效（设备探测 `probe 1452`）、删键后自行愈合（`DesiredConfigChanged`）；验收还实测 hub 侧 MTU 跟随已 apply 修订而设备侧读实时配置的不对称，已记为后续项。证据：docs/implementation/r04-linux-agent-e2e.md）
  - [x] 注册摘要化、启动恢复、执行回执、重试、升级。
  - [x] 真实连接诊断：大包探测逻辑已进仓；真实 VPS 到设备的端到端连通验收已于 2026-10-24 完成（见父行与 docs/implementation/r04-linux-agent-e2e.md）。
- [ ] R-05 Windows 完整客户端：隧道服务、系统路由、防火墙、权限提升、开机恢复、~~卸载清理（真平台后端）~~。（缺的条件，如实记录：一台可实际安装的 Windows 机器——Win10/11 或 Server、管理员权限、允许装 WireGuardNT 驱动并能重启验证开机恢复；编译门不缺：CI 已在 windows-latest 原生跑全 workspace `clippy -D warnings` + `cargo test --workspace`，本机也有单 crate msvc 交叉 check/clippy 绿。2026-10-26 起本机（中文 Windows Server 2022）以 GNU 工具链补齐全 workspace 测试/clippy 绿，路由/防火墙/服务数据面真机验收见子项。仍缺：WireGuardNT 驱动安装后的隧道全生命周期、提权执行层与开机恢复重启验证，以及据此做出的 SystemBackend 接线决策。）

2026-10-28 巡检（不勾，BLOCKED）：剩余三项真机缺项与 #52 接线决策全部卡在「需一台可实际安装、可重启的 Windows 真机」——win-worker 已永久停用，**需用户手动提供机器**，然后按 docs/implementation/r05-windows-acceptance.md「Still blocked」的手动动作清单逐项验收（装 WireGuardNT 驱动跑隧道全生命周期、提权执行层真机运行、重启验证开机恢复）；此前仓内无任何可推进面。

2026-10-27 注记（隧道计划层+执行层原语已落地，父项与三项真机缺项均未勾）：新增 `crates/meshlet-network/src/windows_tunnel.rs`——按 ADR-008 选型 **WireGuardNT**（官方 `wireguard.exe` + `wireguard-nt` 内核驱动，一条受管服务一个隧道；wintun 只是 TUN 适配器，需再押用户态 WireGuard 栈，故不取）。计划层任意平台编译+单测（本机 Linux 94 项 lib 测试绿，`cargo clippy --workspace --all-targets -- -D warnings` 绿，`cargo fmt --check` 绿）：conf 渲染（`[Interface]` Name/Address/可选 ListenPort/MTU/可选 PrivateKey + 每 peer 一节；**私钥仅 `private_key=Some` 时渲染，agent 本地注入、服务端永不携带，`None`=服务沿用现存密钥=幂等重应用**）、`wireguard.exe` 安装/启动/停止/卸载命令构造（`/installtunnelservice <conf>` 等官方 CLI 形状）、幂等 re-apply（卸载不存在隧道=1060/「指定的服务未安装」复用已真机取证的 `windows_service::service_absent` 文案放行；停止未运行=1062 同理）、失败分类（权限文案→InsufficientPrivileges，未知→ApplyRejected fail-closed，**不含任何未真机取证的 fixture**）。`#[cfg(windows)]` 执行层：conf 写盘（私钥落客户端受保护目录）+ `run_wireguard_command`（经 `windows_console` 解码）；文件级 `tests/windows_tunnel.rs`（`#![cfg(windows)]`）由 CI windows-latest `cargo test --workspace` 真跑（conf 写回读/覆盖重写/签名锁定，**不触发真实隧道安装**）。lib.rs 仅注册 `pub mod windows_tunnel`，**未接 SystemBackend、未动 `crate::unsupported`**。仍缺（如实记录，禁止冒充）：WireGuardNT 驱动安装后隧道全生命周期真机、提权执行层真机报文、开机恢复重启验证，及据此的 SystemBackend 接线决策。）
  - [x] 权限提升：`windows_elevation` 计划层（受管 `.exe` 路径校验、`runas` 命令行转义、错误码/文案 → `InsufficientPrivileges` 分类）全平台编译 + Linux 单测（66 通过）；`#[cfg(windows)]` 执行层（ShellExecuteW runas + TokenElevation 查询）已过 `x86_64-pc-windows-msvc` clippy/check，**未在真机 Windows 实测，不得接为 SystemBackend**。
  - [x] 数据面真机验收（2026-10-25/26，中文 Windows Server 本机）：抓到并修复本地化根因——netsh/sc.exe 重定向输出是活动代码页（CP936/GBK）而非 UTF-8，`from_utf8_lossy` 丢失全部 zh-CN 文案；新增 `windows_console`（UTF-8 优先 + `MultiByteToWideChar(CP_ACP)` 解码，windows-sys 现有依赖加 `Win32_Globalization`），routes/service/firewall 执行层接入，分类器补真机报文：路由缺失「找不到元素。」、sc 1060「指定的服务未安装。」、防火墙缺失「没有与指定标准相匹配的规则。」、非提权「请求的操作需要提升(作为管理员运行)。」；真机新发现 sc stop 未启动服务返回 1062「服务尚未启动。」——Stop 目标状态是已停止，未运行即已达成，新增幂等成功（含退出码 1060/1062 双通道判定）。新增卸载链重入集成测试 `windows_cleanup_e2e`（服务 create→stop→delete→re-delete、防火墙 add→show→delete→re-delete、空态 CleanupPlan 全步幂等，真机闭环）；`windows_netsh` 原失败用例（幂等 re-delete）转绿。验证：meshlet-network 75 单测 + 3 真机集成全绿；全 workspace `cargo test` 与 clippy（stable-x86_64-pc-windows-gnu）exit 0。
- [x] R-06 服务发布 - TCP/UDP PortForward。（crate 实现与单测；2026-10-24 已接控制面 CRUD + agent 运行链路：DevicePlan 携带 publish 段，agent 对账后在进程内绑定监听（回环高位端口验证，真机端到端见下条），端口冲突按设备/协议/监听地址判定，见 apps/server/tests/publish.rs）
- [x] R-06 服务发布 - HTTP/HTTPS 发布。（crate 实现与单测；已接 CRUD。`tls_passthrough: true` 走 SNI 嗅探 + TLS 字节直通，**不做 TLS 终止**：无证书、不解密；字段于 M1 由 `tls_termination` 更名，旧名仍被接受）
- [x] R-06 服务发布 - 授权控制与 server 接线。（2026-10-23 VPS 实测：CIDR 放行、Bearer 拒绝、缺 CSRF 403 三路径通过；2026-10-24 CRUD 写入端点接入 WriteUser + CSRF，12 个集成测试覆盖）
- [x] R-06 服务发布 - 健康探测。（crate 实现与单测；2026-10-24 已排程：agent 按 interval 周期探测并批量上报 /api/v1/agent/publish-health，服务端按 (probe, device) 守卫 upsert 到 publish_probe_reports）
- [x] R-06 服务发布 - 内部 DNS 服务目录（分流 DNS，不覆盖公共 DNS）。（crate 实现与单测；2026-10-24 已接 agent reconcile：按计划起 DNS 套接字、仅应答内部后缀，每设备一个套接字）
- [x] R-06 服务发布 - 真实 VPS/真机端到端验收。（2026-10-24 验收完成，完整证据见 docs/implementation/r06-service-publishing.md「真实 VPS 验收运行（2026-10-24）」）真实 agent 从服务端计划真实绑定并跑出流量：2 条 L4 转发（18080 允许 0.0.0.0/0 → `L4-FORWARD-BACKEND-OK`；18083 仅允许 10.9.9.9/32 → reset 零字节）、HTTP 路由 18090（本地与经 80 端口的发布域名均回 `HTTP-ROUTE-BACKEND-OK`）、UDP 15353 分流 DNS（`dig @127.0.0.1 -p 15353 app.mesh.internal` → 10.240.0.5，公共域名不应答）、TLS SNI 直通（客户端取回**后端**证书 `CN=tls.mesh.internal`，200 + `TLS-PASSTHROUGH-BACKEND-OK`，未知 SNI 与纯 HTTP 均 reset 且不触碰后端）、探针健康持续上报（`publish_probe_reports.checked_at` 跨周期推进）。验收中发现并修复三个真缺陷：SNI 嗅探器无边界检查在真机 panic 崩掉发布 worker（另附未剥握手头、吃掉 ClientHello 不回灌两个缺陷，11 单测 + 3 集成测试回归）、第二监听口/混合终止模式被静默接受（改为创建期 409，与既有每设备一 DNS 套接字守卫对称）、探针调度整表刷新导致每条探针只跑一次（`checked_at` 曾冻结数小时，已改为只记录真正排出去的 schedule）。**真机未验证，不冒充**：`0.0.0.0:53` 从未绑定过（只在 15353 上验收，53 需 root）；发布端口 15353/18080/18083/18090 被云安全组挡住，外部实测 BLOCKED（该盒子仅 22/80/443/8080 开放，控制面 8080 外部可达并返回 401）；TLS 无外部入口（443 被 cockpit 业务 vhost 占用，加 stream 直通会与线上业务冲突）；经发布域名走 80 的外部流量只在临时 nginx vhost 存在期间成立，该 vhost 已按可回退原则删除。控制台已补创建入口：`App.tsx` 的 `PublishSection` + `api.ts` 四个方法 + `publish.test.tsx`，行字段词汇抄 Portainer 服务「Port publishing」编辑器与 Dokploy 端口表、冲突用同一张 nothing-was-published 卡片、两步内联删除，真浏览器走查通过。历史真机证据与本次验收同见该文档
- [ ] R-07 正式部署与长期运行验收：空白 VPS 安装、密钥轮换、备份恢复（含显式加密恢复包口径）、升级回滚、性能基线、真实多设备验收。（除长期浸泡外六个子项均已带证据验收，见子行与 docs/implementation/r07-deployment-acceptance.md；父项保持未勾，等浸泡数据。2026-10-28 巡检复核：状态不变——六个子项证据在案，父项唯一缺项仍为长期浸泡。）
  - [x] 空白容器安装（2026-10-24，真实 GitHub release 下载路径）：原版 debian-12 容器无 curl/sudo——README 一行式 `curl|sudo` 实测 127 失败（文档已补前置与 wget 形式）；install.sh 经 Recommends 链给容器装了 107 MB 内核镜像（已改 `--no-install-recommends`）；wget 形式装通：依赖齐、资产 sha256 与发布 `SHA256SUMS` 一致、单元加固与 `0600` 文件逐项核对。
  - [x] 密钥轮换与密钥丢失（2026-10-24）：独立密钥备份→`wg genkey` 轮换→重启后 **45 秒**内三台设备全部零接触换到新 hub 公钥（`reason=DesiredConfigChanged`，`3/3` 握手新鲜）；删 `hub.key` 服务仍 `active`（隧道死、控制面活，记 `hub recovery failed` ERROR——只看 systemctl 发现不了，已如实记录）；从独立备份恢复即回滚轮换，设备零动作跟随。
  - [x] 备份恢复（2026-10-24）：API 备份 385024 B（`networks=1 devices=2 revisions=3`）；工件为**明文** SQLite `0600 meshlet:meshlet`（显式加密恢复包口径：无加密包，见 docs/zh/architecture/backup-restore.md）；缺 CSRF 头 403；文档顺序 stop→restore→start 实测通过，恢复出的库 `0600 meshlet:meshlet`（修复前 root:root 会 crash-loop），`NRestarts=0`，`system.restore` 审计带源路径，会话随库存活（旧 cookie `/auth/me` 200），无 restore-tmp 残留；**实测发现运行中恢复会把写入送进脱链 inode（一次 201 的 token 铸造消失），重启才重新采用恢复库——文档已把「先停服务」定为强制**。
  - [x] 性能基线（2026-10-24）：进程内 bench 矩阵（file/memory，c=1/16/64/256，footprint 3.5 KiB/网络、0.2 KiB/token）入 docs/architecture/performance.md；运行中服务真实 socket 基线：`/system/status` 126 req/s 串行 / 261 req/s 8 并发、`/networks` 130 req/s、backup 63 req/s（curl 每次 fork，是下限不是上限）。
  - [x] 真实多设备验收（2026-10-24）：第三台设备经 `max_uses=1` token 入网（`dev-reg-3`→10.240.0.4→修订 4 apply），hub 三 peer `/32` 握手新鲜，诊断 `3/3 handshakes`、`mtu_planned` 三设备证据一致（`1420 probe 1392`），token 记账 `bt-1 2/5`、`bt-2 1/1`。
  - [x] 升级回滚（2026-10-24，CT 113 真实 release 资产）：修复 nightly.yml 的 E0463 后 workflow_dispatch 构建成功并发布（`commit=cefd5ef`、`source_dirty=false`）；重建前先把当时已发布的 2026-10-17 资产存到宿主机（对照发布 `SHA256SUMS` 校验 `OK`）。升级=重跑 install.sh：二进制 `4845343087249b66…` → `089893187da04786…`，配置/私钥/设备 token 三哈希逐字节不变，设备未重新注册（`using the saved agent token`），首个 tick 三 peer 握手 11/12/32 秒、DF 1472B ping 3/3 零丢包（平均 0.684 ms）。回滚=旧压缩包走 `MESHLET_INSTALL_ARCHIVE`+`MESHLET_INSTALL_SHA256SUMS` 离线安装（打印 `Verifying staged Meshlet nightly (x86_64)…`）：二进制回到 `4845343087249b66…`、三哈希未动、ping 3/3 零丢包，再次升级后设备停在修复版。回滚到「已发布的旧 tag」仍做不到（无带日期 release），按离线口径覆盖。
  - [ ] 长期运行浸泡：观察采集器 2026-10-24 起已在跑（PVE 宿主机 `/root/meshlet-soak/collect.sh`，cron 每 30 分钟一行：`status` 标记 + hub 服务状态/`NRestarts`/启动时间、三 agent active 与否、CT111→hub 与 →dev-3 ping 延迟、三 peer 握手时刻）。**首采 `2026-10-24T00:15Z hub=active nrestarts=0 agents=active/active/active` 有效**：01:03Z 复查 `nrestarts=0`、`since` 未变、库内仍 3 台设备、22:59:50 起 server 日志 `self-registered` 计数 0。**修过的真缺陷**：采集器首版在 cron 下每行都是空数据——PVE cron 的 `PATH=/usr/bin:/bin` 不含 `/usr/sbin/pct`，`2026-10-24T00:37:01Z` 那行全空（log 内已标 `[BAD: pre-fix cron PATH, empty data, not soak evidence]`，不作浸泡证据）；现已在脚本开头 `export PATH=/usr/sbin:/usr/bin:/bin` 并加有效性标记，任一关键字段为空即输出 `status=BAD`（用不可路由目标实测触发过 `status=BAD`），修后在模拟 cron 环境 `env -i PATH=/usr/bin:/bin collect.sh` 连跑两次均 `status=OK`、hub/agents/ms/handshakes 全有值。移除方式：`crontab -l | grep -v meshlet-soak | crontab -` 并删 `/root/meshlet-soak`。判据不变：hub 无非预期重启、agent 无重新注册、mesh 内 ping 连续；需数周真数据复查后才勾，禁止提前冒充。
**首日复查 `2026-10-25T01:16CST`（窗口 `2026-10-24T00:15Z`→`17:07Z`，宿主机 `192.168.5.10` 的 `/root/meshlet-soak/soak.log` 共 35 行）**：33 行 `status=OK`（`01:07:09Z`→`17:07:11Z`，30 分钟节拍无缺行）、1 行首采未打标（`00:15:56Z`，有效）、1 行 `[BAD]`（`00:37:01Z`，即上述 cron PATH 缺陷留下的空行，排除）；hub 全程 `active`、`NRestarts=0`、`ActiveEnterTimestamp` 恒为 `Fri 2026-10-23 22:59:53 UTC`；三 agent `active/active/active`，CT111/112/113 的 `meshlet-agent` 均 `NRestarts=0`（分别自 `22:11:52Z` / `22:11:57Z` / `23:28:16Z` 起）；`wg0` 三 peer 最新握手年龄 −6s..120s（无隧道断点）；CT111→hub ping min/avg/max = 0.121 / 0.703 / 2.980 ms（n=34），CT111→dev-3 = 0.228 / 1.189 / 4.550 ms，各 1 次 `loss` 全来自那行 `[BAD]`；无新增注册：`devices` 仍 3 行且全 `active`（创建于 `22:11:52Z` / `22:11:57Z` / `22:52:10Z`，均早于 hub 启动）、`device_registrations`=0、hub 启动后 `audit_events` 仅 `system.backup`×20（注册类动作计数 0）、server 日志 `22:59:50Z` 起 34070 行中匹配 `enroll|register` 计数 0。**首日未见异常，无需修缺陷；16.85 h 不足以判长期稳定，仍不勾。**

2026-10-28 巡检（不勾）：仓内最后一条浸泡证据仍是上述首日复查（2026-10-25，16.85 h）；当日后采集器/`soak.log` 状态在用户 PVE 宿主机（`192.168.5.10`）上，本侧无法核实——「确认采集器持续运行、按周复查 `soak.log`、数周后按判据复查」是**用户侧手动动作**；数据满足判据（hub 无非预期重启、agent 无重新注册、mesh 内 ping 连续，数周真数据）前禁止勾选。

**终局记录（2026-10-27 巡检，环境已被拆除）**：PVE 任务日志证实实验环境为主动拆除，非故障——2026-10-25 23:48 CST root@pam 停 CT 110/111（浸泡自 2026-10-25T16:07:09Z 起转 status=BAD）；2026-10-26 21:51 CST 四 CT 全部 vzstart，22:03 vzstop，22:07:07 起 vzdestroy×4（110/111/112/113）销毁，无本地备份。浸泡有效窗口 2026-10-24T00:15Z→2026-10-25T15:37Z（78 行 OK + 首采 1 行，约 39.4 h，仍远不足数周判据，R-07 浸泡不勾）；其后 65 行 BAD 全是环境不存在所致，不作证据。采集 cron 已从 PVE crontab 移除，/root/meshlet-soak/（collect.sh + soak.log 全量 145 行）原样保留。浸泡判据在实验环境重建决策明确前为外部 BLOCKED，本仓代码侧无对应工作可派。

## 关键设计要点（来自评审，实现时逐条对照）
- 状态四类不混用；Revision 执行态机：Pending/Preparing/…（弃单一 Applied）；回滚=新增修订。
- Planner 纯逻辑：不落库、不执行系统命令、不持私钥；输出确定性计划。
- 安全三层：设备身份+入网审批 / Segment 与访问策略 / 执行层（nftables 真实施）。
- 四引擎分离：LAN 路由 / Alias 映射 / L4 发布 / HTTP 发布，各自独立。
- Rust 工作区 crate 边界按评审第七章目录重建；测试五层 L1-L5 各立验收。
- 协议：HTTPS+JSON 起步，OpenAPI 为契约源；执行器 Prepare→Verify→Recover 可验证恢复。

## 外部评审建议立项（2026-10-26 用户令，来源：ChatGPT 深度评审分享，已逐条源码核验）

来源与可信度：评审全文 2.1 万字，核心实现声称已逐条对照源码核验（UnsupportedBackend、needs_apply 四态、
last_good_plan、tls_termination+sniff_sni、Outbox、drift 按 peer 数、R-04 真机验收、netd 仅存于目标架构、
deps 检查脚本）全部命中；唯一事实错误：评审称 R-04 验收为三设备，实录 2 设备（TODO R-04 行）。
评审 P0（Windows 闭环、长期运行验收）与既有 R-05/R-07 完全收敛，不重复立项；下面是仓内 TODO 尚无的增量。

- [x] M1 tls_termination 更名与能力拒绝（2026-10-26）：当前 http.rs `tls_termination: bool` 实为 SNI 嗅探+TLS 字节
      透传（R-06 验收实录后端证书）。改为显式 `tls_passthrough`（词汇沿用 Luban/Envoy 等通行术语，
      不自造）。**更名范围**：`crates/meshlet-publish` 的 `HttpRoute`（serde `alias = "tls_termination"`，旧序列化计划仍可读，
      响应只出新名）、`plan.rs`/`runtime.rs`/单测；`apps/server` 的请求结构 `CreatePublishHttpRouteRequest`（同样带 alias，
      仍 `deny_unknown_fields`）、视图、INSERT 列、恢复 SELECT 全量更名；console `api.ts`/`App.tsx` 同步。**能力显式拒绝**：新增
      `check_publish_mode_supported`，passthrough 路由若带 `allowed_bearer_tokens` → 409（路由器只建 socket 级
      `AuthorizedClient::from_socket`，`auth_header` 永不填充，token 永不校验），`path_prefix != "/"` → 409（选路恒
      `select(&sni, "/")`，路径前缀永不参与匹配）——把两个此前静默 no-op 的组合改为创建期拒绝。**旧字段名映射**：serde alias 双向兼容 +
      `migrations/013_publish_tls_passthrough.sql`（仅 `ALTER TABLE … RENAME COLUMN`，值与语义不变），`backup.rs` 迁移硬计数 12→13、
      `migrations/README.md` 当前版本 013。**单测**：新增 `tls_passthrough_rejects_capabilities_it_cannot_enforce`（旧名请求可读、
      `tls_termination` 不再出现在响应、两条非法组合各 409 并断言文案、plain HTTP 路由仍允许 token+前缀）；生命周期 fixture 原以
      `tls_termination: true` 静默接受（正是本缺陷），已改 plain HTTP。验证：meshlet-server publish 12 集成 + backup 9 + migrations 12、
      meshlet-publish 全绿、console 17 通过（3 文件）、全 workspace `cargo test` 零失败、`cargo clippy --workspace --all-targets -D warnings`
      与 `cargo fmt --all -- --check` exit 0、`pnpm run docs:build` 成功。**顺带修既有红**：`windows_console.rs` 两个真机取证常量仅被
      windows 门禁测试引用，Linux 上 clippy `-D warnings` 报 dead_code（临时 worktree 于 pristine HEAD 复现，确认与本单无关），已加同
      cfg 门禁。
- [x] M2 漂移检测升级到身份/所有权级（2026-10-27 落地）。`NetworkSnapshot` 改为携带身份
      （`lib.rs:169`/`PeerObserved lib.rs:182`）：peer 按 `wg show` 逐行解析公钥+allowed-ips
      （`linux.rs:238`，公钥须 44 位 base64 且以 `=` 结尾）；路由只统计 `proto 198` 标记
      （`linux.rs:40`）；NAT 指纹 `chain|目的|动作|所有权|源|入向接口`（`nat.rs:79`，内核侧
      `linux.rs:941` 解析同形），集合比对见 `reconcile.rs:165/179/209`。未标记路由与无 Meshlet
      注释的 NAT 规则进不了观测集合，结构上不会被判漂移也不会被删。新增计划外 meshlet 规则清理
      （`linux.rs:913`，解析不出形状则跳过不删），`apply_device_plan_sync` 调用（`:1142`）。
      真机测试抓出并修掉三个真实缺陷：① `iptables -S` 把 `--to` 与取值渲染为两个 token，
      旧解析器只读一个 → 所有 DNAT 指纹为空 target；② 计划侧指纹用 `{:?}` 打印结构体内部字段，
      与内核裸 CIDR 串永不对齐；③ POSTROUTING 被塞 `-i` 永不渲染的 `incoming_interface`，
      计划指纹 `|wg0` 对内核 `|none`，新清理逻辑误删计划内 SNAT 致读回失败
      （已改为链级规范化：`nat.rs:87`，`device_plan.rs:189`/`agent.rs:409` 只对 PREROUTING 赋值）。
      验收：单测 8 个（`reconcile.rs:419-544` 五个 + `linux.rs:1470-1551` 三个，含 peer 解析、
      指纹 round-trip、拒绝渲染器永不产出的形状）；真机注入三项各带修复断言
      （`backend_wiring.rs:1048-1245` 陌生 peer 移除/计划 peer 存活、未标记路由 `10.245.0.0/24
      dev wg0` 原行原样存活、多余 meshlet 注释 SNAT 移除且计划 SNAT 与外部规则存活；
      `agent_reconcile.rs:878-1003` 同三项走真实 agent 判定，逐项 `reason=KernelDrift`）。
      验证：`cargo test --workspace` exit 0、`backend_wiring` 1/1 (31.66s)、
      `agent_reconcile` 1/1 (26.95s)、`dual_site_end_to_end` 1/1 (36.63s)、
      meshlet-agent lib 59 通过、meshlet-network lib 79 通过、
      `cargo clippy --workspace --all-targets -D warnings` 与 `cargo fmt --all -- --check` exit 0、
      `pnpm run docs:build` 成功。证据入 `docs/implementation/r04-linux-agent-e2e.md` 及其 zh 镜像。
- [x] M3 故障矩阵验收（评审 54.2 九场景，2026-10-27 落地）：九场景全真跑（真 netns +
      sudo ip/wg/iptables，`MESHLET_REQUIRE_DATAPLANE=1` 门禁——无门禁时静默 SKIP，
      证据全部来自设门禁的运行）。串行单测实测：①hub 重启恢复受管状态
      （`single_instance.rs:1389` 9.38s：重建后 hub 密钥不变、peer 身份行逐字相同、
      hub 路由与网关 NAT 相等）；②agent 重启不信账本（`ledger_recovery.rs:379` 1.19s：
      真实 apply 对照组 `UpToDate`，同标记换路由 → `KernelDrift`，外部路由幸存）；
      ③改路由被杀（`ledger_recovery.rs:442` 3.01s：三个被杀断点各为真实半途内核状态，
      收敛到计划 B、账本记 `rev-b`）；④删 LAN 路由连带撤销（`single_instance.rs:1522`
      6.78s：DELETE 204、alias 列表清空、hub 路由与 allowed-ips 收敛、网关
      `NoLocalLedger` 所有权清扫 owner NAT、overlay 不断）；⑤双网络并行不串网
      （`single_instance.rs:212` 53.70s，既有测试：A 重启重建/失败修订回滚不动 B）；
      ⑥宿主机规则不误删（`backend_wiring.rs:704` 场景 12 主体 `:1247` 32.96s：根命名
      空间 apply，外来路由/NAT/FORWARD/ip_forward 逐字幸存，`RootGuard` 兜底清理）；
      ⑦撤销在线设备旧计划不重授（`single_instance.rs:1833` 5.94s：凭证 401、旧修订
      回执 400 过期、当前修订配旧哈希 400 哈希不符、新修订不回加 peer、存活设备握手
      与流量计数持续；内核侧 `:624-673`）；⑧hub 公钥轮换（`single_instance.rs:1468`
      6.20s：hub 换钥、peer 身份不变、设备计划与内核持新钥）；⑨库恢复后内核重新一致
      （`single_instance.rs:1662` 9.81s：备份→删除→恢复→重启→recover_once→hub 路由
      逐字复原、网关 NAT 复原、LAN 通路恢复）。
      如实记录两处非缺陷观察：a) hub 接口重建不带会话密钥，设备旧会话 keepalive
      （REJECT_AFTER_TIME ≈180s）无法解密、hub 学不到 endpoint——WireGuard 标准行为，
      身份级重建为本场景合同，数据面回归由设备自身收敛步骤验证（`single_instance.rs:1441`
      注释）；b) 回滚式恢复后「点 apply」不重收敛——`ConfigLedger::apply` 对已
      `Applied` 修订幂等返回（`config_state.rs:230`），备份后新增修订又不在恢复出的
      库里，受支持路径是生产启动恢复 `recover_once`（`main.rs:113`）；产品语义决策留作
      后续项，本轮不改代码。验证：`single_instance` 7 通过（串行 105.89s）、
      `ledger_recovery` 6 通过 6.35s、`backend_wiring` 1 通过 32.96s、`agent_reconcile`
      1 通过 27.06s、`dual_site_end_to_end` 1 通过 33.82s、
      `cargo clippy --workspace --all-targets -D warnings` 与 `cargo fmt --all -- --check`
      exit 0、`pnpm run docs:build` 成功；证据入 `docs/implementation/m3-fault-matrix.md`
      及 zh 镜像，侧栏已注册（`docs/.vitepress/config.mts:102`/`:190`）；可并入 R-07
      浸泡验收执行（场景 2/3/5/6/7 触碰共享内核状态，最值得在浸泡机重复）。
- [x] M4 回滚/重试不得重授已撤销权限：安全语义优先于机械恢复。撤销权限、删 Peer、删路由、
      清 NAT 有明确优先级；失败恢复 last_good_plan 前先过当前授权快照。验收：撤销后诱导回滚的
      单测证明访问未重新打开。
      → 已落地（2026-10-27）。优先级顺序落在两处：撤销动作本身 `service.rs:2417`
      `revoke_device` 即按 §11.5/§12.6 先删该设备发布的 LAN 路由及其绑定 alias（撤销 >
      删路由 > 清 NAT，NAT 随路由集合在网关收敛）；恢复侧新增 `revision.rs:165`
      `enforce_authorization` 作为唯一过滤点——先删被撤销设备的 peer，再删网关不再活跃的
      路由，再删失去所属路由的 alias，最后删失去 peer allowed-ips 依据的 hub 转发路由。
      四个消费边界共用它：内核目标 `revision.rs:208`（apply/rollback/recover 的
      last_good_plan）、回滚结算 `revision.rs:915`（写回内存恢复日志前）、装载
      `persist.rs:1562`（失败修订让日志短暂滞留旧计划时，重启读到的是已授权子集）、
      回滚落库 `persist.rs:2247`（回滚把过滤后的部署写回 `hub_deployments`；原先只写
      路由/alias，下次重启会从日志读回含被撤销设备的计划）。验收测试
      `single_instance.rs:2008` `rolling_back_a_failed_revoke_does_not_reopen_access`
      （日志断言走 `journal_plan`，`:1311`）：撤销 + 两次失败 apply（外来路由占住目的段）
      → 隧道步已移除被撤销 peer 而 apply 仍失败（撤销优先于机械恢复）→ 回滚后 hub peer
      列表仍不含被撤销公钥、`ping` 仍不通、日志 JSON 的 peer 与路由均不含它（`journal["aliases"]`
      未单独断言，alias 无孤儿在内核侧收敛验证）、
      存活设备握手与流量计数持续累加 → `persist::load` + `recover_once` 重启后同样不复活。
      取证反向验证：临时摘掉回滚结算的过滤，该测在 `single_instance.rs:2123` 失败，日志
      JSON 记录回两个 peer（含被撤销公钥 `zdzp…`）——证明断言抓的是本次修的缺陷，而非
      已被 `from_mesh_with` 覆盖的内核侧。实测：该测单跑 8.44s；`single_instance` 8 通过
      （串行 116.83s）；`cargo test --workspace`、`cargo clippy --workspace --all-targets
      -- -D warnings`、`cargo fmt --all -- --check`、`pnpm run docs:build` 全绿。
      门禁说明：`setup()` 以「sudo 可用 + `wg --version` 成功」判前置条件，本机两者齐备，
      所以 `MESHLET_REQUIRE_DATAPLANE=1` 在本机只是「缺前置条件时硬失败」的开关，不设也真跑
      （workspace 运行即真跑：8 测 71.43s）——验收不能只看 exit code。
- [x] M5 TODO 完成状态审计（作为 TODO #52 SystemBackend 接线决策的前置）：逐条核对已勾项的
      实现路径、测试覆盖、真实验收证据，重点权限撤销/回滚/多网络隔离/Windows 后端，产出审计报告
      （结论三分类：有证据/证据弱/仅代码存在）。验收：报告入 `docs/analysis/`（用户令改为
      analysis，非 review）并进 vitepress 站，#52 决策引用它。
      → 已落地（2026-10-27，审计基线 `ebcd9e7`）。证据：
      `docs/analysis/todo-completion-audit-2026-10-27.md` 及 zh 镜像，侧栏已注册
      （`docs/.vitepress/config.mts` `/analysis/` 与 `/zh/analysis/` 各一条）。核对已勾项 20 条：
      **有证据 15**（R-04 与两个子项、R-05 数据面子项、R-06 六个子项含真实 VPS 端到端、
      R-07 空白安装/密钥轮换/备份恢复/多设备/升级回滚、M1/M2/M3/M4）、
      **证据弱 5**（R-01、R-02、R-03、R-05 权限提升子项、R-07 性能基线）、
      **仅代码存在 1 处子面**（`windows_elevation.rs:194` 的 `#[cfg(windows)]` 执行层，
      模块内零测试、从未在真机运行）。三个重点结论：①权限撤销/回滚链路无旁路——
      `enforce_authorization` 四个消费点（`revision.rs:208/915`、`persist.rs:1562/2225`）
      全部核实，并遍历所有 `hub_deployments` 写入与内存计划插入点，未找到绕过；
      ②多网络隔离由 `single_instance.rs:212` 的正负成对断言证明（B 活着且 A 到不了 B），
      系单机 netns 级证据而非 WAN/NAT 穿越；③Windows **无法接线**——隧道实现整体缺席
      （`wireguardnt`/`wintun`/`tun2socks`/`OpenAdapter` 在 `crates/`+`apps/` 下零代码，仅
      `windows_routes.rs:13,207` 两处注释提及），而 `apply_tunnel` 正是 agent 的首个调用
      （`apps/agent/src/agent.rs:124`），接线需新建子系统而非改一行 `cfg`。另记 12 处 TODO
      表述与实际不符（R-02 写 nftables 实为 iptables 且 nftables crate 无任何 app 依赖、
      `meshlet-netplan` 未被 server 消费、`check-planner-deps.sh` 未接任何 CI、R-04 第 25 行
      自相矛盾、R-06 第 31 行计数过时、M2 行号区间漂移等，详见报告「发现的不一致」）。
      指针已加两处：`crates/meshlet-network/src/lib.rs` 模块头（接线决策本体）与
      `docs/zh/guide/walkthrough.md` §4 判定段（#52 验收门）。验证：`pnpm run docs:build` 绿、
      `cargo test --workspace` 与 `cargo clippy --workspace --all-targets -D warnings` 绿、
      `cargo fmt --all -- --check` 绿。落 commit = 本提交（单提交无法自引哈希，见 git log 首条）。
- 说明：评审的「备份明文加密恢复包」已在 R-07 显式加密恢复包口径内（不重复立项）；
  服务发布授权清单（监听地址/来源 CIDR/UDP 会话生命周期等）在 M1 落地时并入检查单。

## 审核发现
- [x] 审核通过：efb206c5..3e3101b 无发现
  - 巡检注记（2026-10-28 第二次）：浸泡环境已被销毁，浸泡无法继续。PVE task log 实证：CT 110/111/112/113 于 `2026-10-26T14:06Z` 依次 vzstop、`14:07Z` 依次 vzdestroy（root@pam），soak cron 条目随后被移除；`/root/meshlet-soak/soak.log` 保留（145 行），末行 `2026-10-27T00:07Z status=BAD`。有效干净窗口仅 `2026-10-24T00:15Z`→`2026-10-25T15:37Z`（约 39.5h，hub nrestarts=0、三 agent active、ping 正常）；`10-25T16:07Z` 起 hub 即失联（agents 仍 active）直至销毁，「数周浸泡」判据远未达成。判定：环境级 BLOCKED 升级——非等数据，而是等环境重建。用户手动动作：确认销毁是否有意；若要完成浸泡需重建 CT110-113 网格并重跑采集器（判据不变）。
