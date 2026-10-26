# TODO 完成状态审计 — 2026-10-27

**范围**：`TODO.md` 的 M5 —— 逐条核对**已勾**项的实现路径、测试覆盖与真实验收证据。本
报告同时是尚未落定的 **TODO #52 SystemBackend 接线决策**（`crates/meshlet-network/src/lib.rs:44-49`）
要求的前置输入。

**审计条件**：2026-10-27 于 `/home/cui/workspaces/meshlet` 的 `ebcd9e7`（M4 之后），
只读核对代码、测试与验收文档，并在那一修订上真跑了一次 `cargo test --workspace`
（exit 0；`single_instance` 8 测并行 71.14 s —— 佐证 M4 记录的 71.43 s）。

## 结论口径

| 标记 | 含义 |
| --- | --- |
| **有证据** | 真机或真内核运行产生了实测数值，并记入实施文档。 |
| **证据弱** | 实现与测试都真实存在，但没有实测验收记录 —— 或被测代码不在产品路径上。 |
| **仅代码存在** | 代码存在且能编译，但从未在测试中执行过。 |

只有一个子面落入**仅代码存在**：Windows 提权**执行层**
（`crates/meshlet-network/src/windows_elevation.rs:194` 的 `#[cfg(windows)]` 模块）——
其 11 个测试（`:282`）全部位于门禁模块之外，只测计划层。

## 汇总

| TODO 项 | 结论 | 依据 |
| --- | --- | --- |
| R-01 基础架构重建 | 证据弱 | 代码真实 + 15 个无门禁单测，但无验收文档，且依赖门未接入 CI。 |
| R-02 Linux 数据面 | 证据弱 | 隔离/恢复/撤销由真内核 netns 测试证明，但文档无数值且 TODO 写错了引擎（见不一致 1）。 |
| R-03 统一网络规划 | 证据弱 | 12 个测试含顺序无关性打乱，但该 crate 未被 server 消费。 |
| R-04 Linux Agent 端到端 | **有证据** | 2026-10-24 PVE 真机运行，两台设备，DF/MTU/漂移数值。 |
| R-04 子项：注册/恢复/回执/重试/升级 | **有证据** | 代码 + 空库真实 bootstrap 走查。 |
| R-04 子项：连接诊断 | **有证据** | 大包探测经真实隧道验证两次。 |
| R-05 子项：权限提升 | 证据弱（执行层仅代码存在） | 计划层 + 11 个测试；`#[cfg(windows)]` 执行层零测试、从未在真机运行。 |
| R-05 子项：数据面真机验收 | **有证据** | 2026-10-25/26 中文 Server 2022 真机，CP936 修复带字节级回归。 |
| R-06 转发/HTTP-TLS/授权/探测/DNS | **有证据** | 2026-10-24 真实 VPS 原始主机日志；入向缺口如实记录。 |
| R-06 真实 VPS 端到端 | **有证据** | 同一次运行；TODO 的 R-06 真机验收条目全部数值与文档一致。 |
| R-07 空白容器安装 | **有证据** | sha256 与发布 `SHA256SUMS` 一致，107 MB 镜像泄漏已修。 |
| R-07 密钥轮换 | **有证据** | 45 秒三设备收敛；负例检测是遗留缺口。 |
| R-07 备份恢复 | **有证据** | 11 个集成测试 + 真实运行；验收以「先停」这一约定为前提。 |
| R-07 性能基线 | 证据弱 | 数值真实但自标为下限，无门禁、无趋势。 |
| R-07 真实多设备 | **有证据** | 第三台设备、`max_uses=1` token、记账 `bt-1 2/5`。 |
| R-07 升级回滚 | **有证据** | 双向真实二进制哈希；回滚到旧 tag 做不到。 |
| M1 `tls_passthrough` | **有证据** | 全部声称的测试计数逐一精确核对（12/9/12/17，11+3）。 |
| M2 身份级漂移检测 | **有证据** | 8 个被引单测全部在被引行找到；门禁注入测试存在。 |
| M3 故障矩阵 | **有证据** | 九场景全部在被引位置，断言抽查通过，耗时自洽。 |
| M4 回滚不重授 | **有证据** | 过滤点 + 四个调用点全部在精确行，未见旁路。 |

未勾项不在本次范围内且**一律未改动**：R-05 父项、R-07 父项与浸泡、M5 自身门禁、#52
—— 全部卡在外部条件（见「外部条件阻塞」）。

## 重点一 —— 权限撤销与回滚

安全关键链路真实成立，我扫过的路径上没有缺口。

- **撤销动作本身**（`apps/server/src/service.rs:2417` `revoke_device`）在记录修订**之前**
  先删被撤销设备的 LAN 路由及其绑定的 alias。优先级 撤销 > 删路由 > 清 NAT 成立。
- **唯一过滤点**（`apps/server/src/revision.rs:165` `enforce_authorization`）：删被撤销
  peer → 删网关不活跃的路由 → 删失去所属路由的 alias → 删失去 peer allowed-ips 依据的
  hub 转发路由。
- **四个消费边界全部核对**：`revision.rs:208`（apply/rollback/recover 的
  `last_good_plan` 内核目标）、`revision.rs:915`（回滚结算，写内存恢复日志之前）、
  `apps/server/src/persist.rs:1562`（`load`，从 `hub_deployments` 读出的每行都过滤）、
  `persist.rs:2225`（回滚落库）。
- **旁路扫描**：枚举了所有 `hub_deployments` 写入与所有内存 `deployments` 插入 ——
  `persist.rs:2163`（apply）、`persist.rs:2225`（回滚）、`revision.rs:760`（apply 成功）、
  `revision.rs:922`（回滚）、`convergence.rs:267`（旧恢复路径）、`convergence.rs:305`
  （只写错误列）。三个「新算计划」的写入点会重算计划并过滤 `DeviceStatus::Active`，
  被撤销设备进不了新计划。**未发现旁路。**
- **测试** `single_instance.rs:2008`
  `rolling_back_a_failed_revoke_does_not_reopen_access` 逐条断言了声称的所有性质：回滚后
  peer 列表不含被撤销公钥、`!ping`、路由为空、日志 peer/路由不含它、存活设备握手与
  rx 计数继续累加，且 `persist::load` + `recover_once` 重启后同样不复活。
- **结论：有证据。** 一处如实保留：`:2123` 的反向取证（「摘掉过滤该测必失败」）是作者的
  自述反事实运行，无法靠审阅复现；只有断言位置可核验。

## 重点二 —— 多网络隔离

- `single_instance.rs:212` `two_networks_isolate_reconcile_and_rollback_on_one_hub` 是承载
  测试：7 个 netns、两条不相交 overlay，既断言 B 自身活着（`ping(ns[1], 10.240.0.3)`）
  **又**断言 A 到不了 B（`!ping(ns[1], 10.242.0.3)` / `10.242.0.1`，`:335-353`），随后
  确认 B 在 reapply + reboot 后存活（`:355-367`、`:388`）、回滚还原计划而不牵连 B
  （`:395-409`）。
- `dual_site_end_to_end.rs`（1675 行）经生产启动路径覆盖同一性质，并使用第二个服务端实例。
- **结论：有证据** —— 但这是单机 netns 级证据，不是 WAN/NAT 穿越；且它归在 M3 名下，
  这正是 R-02 单独看只能算证据弱的原因。

## 重点三 —— Windows 后端（#52 的输入）

**Windows 今天无法接为 `SystemBackend`，而阻塞点不是一行缺了的 `cfg`。**

- **决策点**是单个别名（`lib.rs:44-49`）：Linux → `linux::LinuxNetworkBackend`，非 Linux
  → `unsupported::UnsupportedBackend`。它的 `refuse()` 返回点名操作的
  `NetworkError::Unsupported`，文案 `"(windows backend pending, ADR-008)"`；
  `mtu_probe_sync` 返回 `false`（未证实，绝不假绿）。锁定测试：
  `every_operation_refuses_naming_the_operation`。
- **隧道实现为零。** 在 `crates/` 与 `apps/` 下 grep
  `wireguardnt|wintun|tun2socks|OpenAdapter` 只有两处命中，都是 `windows_routes.rs:13,207`
  的注释。无驱动加载、无适配器创建、无适配器名发现。Windows 目前只有
  **路由 + 防火墙 + 服务 + 提权 + 清理**，而 `apply_tunnel` 正是 agent 的第一个调用
  （`apps/agent/src/agent.rs:124`）。接线要新建整个隧道子系统（驱动安装、隧道服务、
  配置持久化、接口发现、MTU），ADR-008 已将其列为后续项。
- **已有部分相当扎实**：路由、防火墙、服务、清理四个执行层在中文 Windows Server 2022
  真机（2026-10-25/26）跑通了全生命周期测试；CP936/GBK 重定向缺陷被发现并修复，带字节级
  回归（`windows_console.rs:43` `MultiByteToWideChar(CP_ACP)`，
  `[target.'cfg(windows)'.dependencies]` 已含 `Win32_Globalization`）。
- **剩余缺口**与 TODO 的 R-05 条目一致：隧道全生命周期、提权执行层（从未在真机运行、零测试）、
  以及开机恢复的**重启**验证（因验收机是不许重启的常驻 worker 而跳过，仅做设计核对）。
- 一处内部不一致：`windows_firewall.rs` 模块头（`:3-7`）仍写「执行层未在 Windows 上实测」，
  而它自己的执行层文档（`:261-263`）已记录 2026-10-26 真机运行。模块头过时了。

## 逐项结论

### R-01 — 证据弱
`crates/meshlet-planner`（零依赖，`Cargo.toml` 的 `[dependencies]` 确实为空）、
`crates/meshlet-store`（修订与 outbox 同一事务，经
`include_str!("docs/design/r01-schemas/outbox.sql")`）、`crates/meshlet-executor`
（`trait Executor { prepare, verify, recover }`）。测试：planner 3 + outbox 5 + store 3 +
executor 4，全部无门禁。设计文档齐备。**但没有任何验收记录** ——
`docs/implementation/` 没有 R-01 文件。`scripts/check-planner-deps.sh` 本身正确，却
**没有被任何 CI 任务或 Makefile 引用**，依赖边界实际未强制执行。

### R-02 — 证据弱
接线的后端是 `meshlet-network` 的 `LinuxNetworkBackend`（`lib.rs:45`，两个 app 都消费），
用的是 **iptables**（`linux.rs` 内 49 处引用）。peer 管理 `linux.rs:215-298`、路由 `:744`、
隔离 `:484`、回滚 `:1158`、漂移检测 `:819/1388/1435`。撤销顺序由
`apps/server/tests/device_revoke.rs`（8 测）覆盖；last-good 恢复在
`apps/agent/src/agent.rs:502`。`docs/implementation/r02-linux-dataplane.md` 是九行散文，
**没有任何日期、哈希或数值**，描述的是 `crates/meshlet-net-linux` —— 而**没有任何 app
依赖它**（nftables 实现，实质是死代码）。**已于 2026-10-27 删除**，该文档现带有「已不随产品发布」的注记。

### R-03 — 证据弱
**`crates/meshlet-netplan` 已于 2026-10-27 删除**（后续项 #2），所以下面的 symbol:行号引用是历史记录，仅为留档保留：
`crates/meshlet-netplan`（`canonical_conflicts:18`、`analyze_network_conflicts:103`、
`validate_network:131`、`plan_hub_peers:330`、`plan_network:411`）。12 个测试 / 23 个函数，
无门禁，含顺序无关性声称：`stable_ipam_allocates_lowest_free_addresses_independent_of_input_order:248`、
`overlapping_alias_space_is_rejected_without_favoring_input_order:321`、
`hub_plan_is_identical_after_shuffling_creation_order:366`、
`global_conflict_set_and_plan_error_are_order_independent:519`。但 `meshlet-netplan`
**没有**出现在任何 `apps/*/Cargo.toml` 或任何 server 源文件里；server 自己做冲突处理
（`apps/server/src/alias.rs:63`、`lib.rs:282/360`）。

### R-04 — 有证据
bootstrap token 只存 SHA-256（`meshlet-domain/src/entities.rs:141`），agent token `0600`
（`apps/agent/src/bootstrap.rs:17/67/146`），启动恢复（`apps/agent/src/reconcile.rs:68/86`），
回执在下个 tick 前刷出且上限 16（`apps/agent/src/agent.rs:222-239`、`:236`），指数退避
（`:163-177`），自更新哈希校验（`apps/agent/src/self_update.rs:219-262`），诊断恰好
13 项（`apps/server/src/diagnostics.rs:161-174`），真实 `ping -M do` 探测
（`meshlet-network/src/linux.rs:672`）。

验收 `docs/implementation/r04-linux-agent-e2e.md`：PVE 实验台，**两台**设备 CT
（TODO 的「两台设备」准确，文档还指出外部评审的三设备说法是错的）。基线 20×64 B 双向
20/20，均值 0.47–0.94 ms；DF 1392 双向 5/5；1419/1472 → `0 received, +2 errors, 100% loss`；
MTU 漂移 1480→1420 一个 tick 愈合（`KernelDrift`，22:24:53Z）；显式
`tunnel_mtu=1480` → 探测 1452。

### R-05 子项 — 证据弱 / 有证据
**权限提升**：计划层已验证（受管 `.exe` 路径校验、`runas` 转义、错误分类）配 11 个 Linux
测试；`#[cfg(windows)]` 执行层（`windows_elevation.rs:194`）**模块内没有任何测试**，其自身
在 `:196` 写明从未在真机实测。子项标注诚实，但「权限提升」实际只覆盖了编译门。
**数据面真机验收**：两个 `#![cfg(target_os = "windows")]` 集成文件
（`tests/windows_netsh.rs`、`tests/windows_cleanup_e2e.rs`）在 CI 的 windows-latest 上原生
运行（`.github/workflows/ci.yml` 矩阵 `os: [ubuntu-latest, windows-latest]` +
`cargo test --workspace`）。中文真机字节被写成断言常量
（`GBK_ELEMENT_ABSENT` = `D5 D2 B2 BB B5 BD D4 AA CB D8 A1 A3` → `找不到元素。`），含
sc 1060/1062 幂等。注意解码器是 `#[cfg(windows)]`、Linux 侧是 `utf8_lossy` 桩，所以 CP936
解码只在真 Windows 上验证过。另外
`docs/implementation/r05-windows-acceptance.md` **并不存在**，也从未提交 ——
`dispatch/` 只是未跟踪的草稿目录。

### R-06 — 有证据（六个子项）
`forwarding.rs`（TCP `:53/59`、UDP `:95/101/128`）、`http.rs`（选路 `:75`、TLS 分支 `:165`、
明文 `:187`、带边界检查的 SNI 嗅探 `:227`）、`authorization.rs`（OR 语义、仅 IPv4）、
`health.rs:35`、`dns.rs:85/108/134/159`。

声称计数逐一精确核对通过：publish 集成 **12**、backup **9**（`:361`
`assert_eq!(migrations, 13)`）、migrations **12**、console **17**；SNI 修复 **11 单测 +
3 集成**。

验收 `docs/implementation/r06-service-publishing.md` 是 `106.14.216.177` 的原始主机日志：
`18080` → `L4-FORWARD-BACKEND-OK`；`18083`（`10.9.9.9/32`）→ reset 零字节；`18090` →
`HTTP-ROUTE-BACKEND-OK`；`dig @127.0.0.1 -p 15353` → `10.240.0.5` 而公共域名不应答；
TLS 直通经 `openssl s_client` 从 `127.0.0.1` 与 `172.19.169.82` 两处取回**后端**证书
`CN=tls.mesh.internal`；探针 `checked_at` 在两个相隔 35 s 的快照间推进。发现并修掉三个真
缺陷并加回归。

**明确未验证**的部分，TODO 的 R-06 真机验收条目全部如实披露：`0.0.0.0:53` 从未绑定（root 绑定需要
特权）；`15353/18080/18083/18090` 被云安全组挡住，故所有数据面证据都只在回环/内网地址上
成立；无外部 TLS 入口（443 被 cockpit vhost 占用）；经发布域名的公网 HTTP 入口只在临时
nginx vhost 存在期间成立，该 vhost 已删除。缺口在**入向**，不在证据。

### R-07 子项 — 有证据（带保留）
六项均在 2026-10-24 的本地 PVE 主机上跑（hub + 3 个容器 CT）—— 真实硬件与真实发布工件，
但这是实验台，不是租来的 VPS。

- **空白安装**：`install.sh` 加 `--no-install-recommends` 修掉 107 MB 内核镜像泄漏；资产
  sha256 与发布 `SHA256SUMS` 一致；文件 `0600`。没有测试覆盖安装流程，且只测了一个原版
  模板。
- **密钥轮换**：公钥变更，45 秒内 3/3 peer 全收敛（`reason=DesiredConfigChanged`）；删
  `hub.key` 后服务仍 `active`，但记 `hub recovery failed` ERROR。这条 ERROR 恰是
  `systemctl` 看不见的情况，而没有任何自动化检测它。
- **备份恢复**：11 个集成测试（六项里最强）加真实运行（`385024 B`、
  `networks=1 devices=2 revisions=3`、明文 SQLite `0600`）。**遗留风险**：运行中恢复会把
  新文件改名覆盖 `meshlet.db`，而进程仍持有旧 inode —— 此后每次写入（包括一次返回
  **201** 的 token 铸造）都落到脱链 inode，永不落盘。先停服务这一步已在两份文档中定为强制，
  但只靠散文约束，没有代码守卫也没有测试。
- **性能**：真实 socket 数值（`/system/status` 串行 126 / 8 并发 261，`/networks` 130，
  backup 63 req/s；足迹 3.5 KiB/网络、0.2 KiB/token）—— 但文档两次自标为下限，基准是未
  入门禁的 example，也没有趋势化或回归门禁。是「记录了基线」，不是「证明了容量」。
- **真实多设备**：第三台设备经 `max_uses=1` token 入网，`dev-reg-3` → `10.240.0.4`，
  `bt-1 2/5`、`bt-2 1/1`，三 peer 握手新鲜。单网络、单机 L2 桥 —— 无 WAN/NAT 穿越。
- **升级回滚**：双向真实二进制哈希（`4845343087249b66…` → `089893187da04786…` 再回），
  三个状态哈希逐字节不变，未重新注册，1472 B ping 3/3 零丢包。**回滚到「已发布的旧 tag」
  做不到** —— 只有一个滚动的 `nightly`，因此回滚只覆盖离线压缩包口径，且要求事先保存过
  上一个工件。

### M1 — 有证据
`http.rs:18-21` `tls_passthrough` 带 `#[serde(alias = "tls_termination")]`；请求结构在
`deny_unknown_fields` 下保留 alias；`publish.rs:736` `check_publish_mode_supported` 对
passthrough 路由带 `allowed_bearer_tokens` 与 `path_prefix != "/"` 各返回 409；
`migrations/013` 只是单条 `ALTER TABLE … RENAME COLUMN`；控制台同步。测试
`tls_passthrough_rejects_capabilities_it_cannot_enforce` 断言旧 alias 仍可读写入、响应不再
出现 `tls_termination`、两条 409 各自点名原因。**`meshlet-publish` 的测试全部无门禁**，
每次都会真跑。

### M2 — 有证据
被引行号全部落在范围内。复核时（2026-10-27）发现并修正一处几行偏差：`NetworkSnapshot`/`PeerObserved` 被引为 `lib.rs:160/177`，但 `peers` 字段与结构体实际在 `:169`/`:182`——`TODO.md` 与 `r04-linux-agent-e2e.md` 现已改为这两个行号。其余引用与所写完全一致：`wg show` peer
解析（`linux.rs:238`，44 位 base64 且以 `=` 结尾）、`proto 198` 标记（`linux.rs:40`）、
NAT 指纹 `chain|dest|action|owner|source|interface`（`nat.rs:79`，`:87` 处
POSTROUTING→`none`）、内核侧解析（`linux.rs:941`）、集合比对（`reconcile.rs:165/179/209`）、
陈旧规则清理（解析不出形状则跳过不删，`linux.rs:913`，在 `:1142` 调用）。**8 个被引单测
全部在被引行找到**。门禁注入测试存在于 `backend_wiring.rs` 与 `agent_reconcile.rs`。

### M3 — 有证据
九场景全部在被引位置存在，承载断言逐条抽查通过，包括场景 5 的正负成对断言与场景 7 的
重启后内核断言（`recovered_peers == 1`、ping 不通）。门禁存在于 40 余处；缺
`MESHLET_REQUIRE_DATAPLANE` 时，缺 sudo/`wg` 只打印 `SKIP:` 并返回 —— 单看绿码证明不了
什么。dataplane CI 任务会设该变量、装 wireguard-tools，并在出现 `SKIP:` 时让整次运行失败。
`docs/implementation/m3-fault-matrix.md`（201 行）记录每场景单独耗时，并把两处非缺陷观察
放在显眼位置：接口重建后 ~180 s 的 `REJECT_AFTER_TIME` 会话密钥限制（WireGuard 标准行为），
以及恢复后手动 apply 不再收敛（`ConfigLedger::apply` 对 `Applied` 幂等，
`config_state.rs:230`）—— 支持的恢复路径是启动时 `recover_once`。

### M4 — 有证据
见重点一。测试耗时与记录自洽：7 测 `105.89 s` 加单测 `8.44 s` ≈ 声称的串行 `116.83 s`；
并行数值与我自己的运行一致。

## 发现的不一致（TODO 表述 vs 实际）

1. **R-02 写「nftables」，但接线的后端用 iptables。** nftables 实现只存在于
   `crates/meshlet-net-linux`，没有任何 app 依赖它，而 `r02-linux-dataplane.md` 描述的正是
   那个未接线的 crate。
2. **`crates/meshlet-netplan` 不在产品路径上。** server 自己做冲突处理，R-03 的已勾表述
   暗示了相反情况。
3. **planner 依赖门未被执行。** `scripts/check-planner-deps.sh` 本身正确，但没有任何 CI
   任务或 Makefile 引用它。
4. **R-02 与 R-03 的验收文档不含任何实测值** —— 各九行散文，只是复述单测覆盖范围。这是
   两者只能算证据弱的原因。
5. **R-04 的「真实连接诊断」子项自相矛盾**：「真实 VPS 到设备的端到端连通验收仍留下轮」紧跟着
   「（2026-10-24 完成，见父行…）」。实施文档把它标为已完成。
6. **TODO 的 R-06「授权控制」条目测试计数过时**：11 个集成测试是 M1 之前的数字，M1 新增一个测试后为
   12。`r06-service-publishing.md` 内部也不自洽（覆盖小节写 11，能力表写 12）。
7. **`backup.rs` 的「迁移硬计数」不在源码里。** `apps/server/src/backup.rs` 没有计数常量；
   迁移数来自 `store.rs:17` 的 `sqlx::migrate!("../../migrations")`，13 是测试里的断言
   （`backup.rs:368`、`:1086`）。结论成立，措辞暗示了不存在的源码常量。
8. **「crate 实现与单测」对 DNS、健康探测与转发的单测位置说过头了**（TODO 的 R-06 DNS、健康探测与 PortForward 条目）：这些源文件内部没有单测，覆盖来自 `tests/` 下的集成测试与 `runtime.rs` 的 lib 测试。
9. **M2 的 TODO 行号区间已漂移**：`backend_wiring.rs:977-1182` 是场景 11——该区段实际从 `:1035`（标记行）到 `:1245`，三类注入自 `:1048` 开始；`agent_reconcile.rs:878-992` 实际到 `:1003` 结束。被引内容都在，只是行号不对。R-04 文档的引用也在 M2 提交后漂移：回执 `:136/:140` → `enqueue_receipt :235` / `flush_pending_receipts :222`；上限 `:701` → `:236`（测试在 `:842`）；心跳 `:422` → `collect_evidence :555`（探测载荷 `:567`）；`/api/v1/update-manifest` 的 `lib.rs:941` → `:945`；自更新测试区间 `:219-259` → `:227-275`。均于 2026-10-27 修正。
10. **`windows_firewall.rs` 模块头过时** —— 见重点三。
11. **「真实 VPS」用于 R-04 与 R-07 不准确** —— 两者都跑在本地 PVE 实验台 + 容器上；
    R-06 那次才是真正的云 VPS。不算错，但用词松。
12. **M4 的测试并未显式断言 `journal["aliases"]` 为空**，alias 为空只是传递成立。TODO 的
    「peer/路由/alias 均不含它」略有超出。

## 外部条件阻塞

| 项 | 缺什么 |
| --- | --- |
| R-05 父项 | WireGuardNT/wintun 隧道子系统（目前零代码）、提权执行层真机运行、以及一台可重启的机器做开机恢复重启验证。 |
| R-07 父项 + 浸泡 | 数周浸泡数据。采集器 2026-10-24 起跑，首日复查 16.85 h 全部 `status=OK`、`NRestarts=0`、无新增注册 —— 健康，但离既定判据还差得远。 |
| #52 SystemBackend 接线 | 上述 R-05 前置，加上隧道-only Windows v1 的设计定案（ADR-008：仅 Overlay 客户端，不做网关/NAT）。 |

这三项都**无法在本地推进**。相关 TODO 行一律未改动。

## 本次审计未确立的内容

- 反事实类声称（如 M4 的「摘掉过滤该测必失败」）是作者记录，审阅只能核验断言位置。
- 测试**数量**通过读源码核对；**通过结果**只在那一次 `cargo test --workspace`（`ebcd9e7`）
  中验证过。
- 性能数值是 curl fork 客户端下的下限，未重新测量。
- Windows 执行层行为未在本机（Linux）执行；其证据是 CI windows-latest 与 2026-10-25/26
  本机运行记录在文件头的内容。

## 本地可推进的后续项

**状态（2026-10-27，同日）：四项全部落地。** #1 见 `ee1cf12`，#2 见 `eb6ce1b`，#3 见
`2fe3fd5`（flock 实例锁，而非只加探测），#4 见覆盖 `TODO.md`、`r04-linux-agent-e2e.md`、
`r06-service-publishing.md` 与两个 `windows_*.rs` 模块头的行号清理（本报告自己的 TODO 行号
引用也一并改为按条目名引用，避免再次腐化）。

1. 把 `scripts/check-planner-deps.sh` 接入 CI（或删掉它），让 R-01 的依赖边界真正被
   强制执行。
2. 修正 `TODO.md` 的两处事实错误（nftables → iptables；`meshlet-netplan` 不在产品路径上），
   或删掉那两个未接线的 crate。
3. 就备份恢复守卫做决定：要么在代码层拒绝「服务持有打开的数据库时恢复」，要么加一个能
   捕获脱链 inode 丢写问题的自动化检查。
4. 更新 `TODO.md` 与 `r04-linux-agent-e2e.md` 中过时的行号区间和测试计数，并修
   `windows_firewall.rs` 的过时模块头。
