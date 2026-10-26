# M3：故障矩阵验收

M3 要求把评审 54.2 的九个故障场景真跑一遍并留可重复证据——不 mock。九个场景已于
2026-10-27 在开发机（`/home/cui/workspaces/meshlet`，免密 sudo、`NET_ADMIN`、
`wireguard-tools`、`iptables`）上跑完。

## 为什么这些测试是「真的」

下述每个测试都由 `MESHLET_REQUIRE_DATAPLANE=1` 门禁
（`apps/server/tests/single_instance.rs:60`、`apps/agent/tests/ledger_recovery.rs:38`）。
没有门禁时测试只打印 `SKIP:` 并以 0 退出，所以单看 exit code 说明不了任何事——
下面的证据全部来自设了门禁的运行。

需要 hub 的场景走生产启动路径（`boot_app`，`apps/server/tests/single_instance.rs:1146`）：
`store::connect` → `persist::load` → `AppState::new(...).with_dataplane(...).with_apply_backend(hub_backend_factory_with(...))`
→ 真实 axum 路由表、真实管理员 bootstrap、真实设备入网，再用真实 `SystemBackend`
在每个测试自己的 network namespace 里 `sudo` 执行。每个测试 7 个 netns
（`mlsi{pid}-0..6`）：hub `10.240.0.1` 在 `wg0` 上（51820，MTU 1380）、
网关 `10.240.0.2` 带两个 LAN 网段、客户端 `10.240.0.3`，另有两条 underlay `/30`
和两台 LAN 主机。断言直接读内核（`ip route`、`wg show`、`iptables -S`、`ping`），
比对的是身份集合而不是数量。

## 九个场景

| # | 场景 | 测试 | 单跑耗时 |
| --- | --- | --- | --- |
| 1 | Hub 重启恢复受管状态 | `hub_reboot_rebuilds_managed_kernel_state_by_identity`，`single_instance.rs:1377` | 9.38 s |
| 2 | Agent 重启不信账本单独判断 | `a_matching_ledger_does_not_shield_kernel_drift`，`ledger_recovery.rs:379` | 1.19 s |
| 3 | 改路由时进程被杀 | `a_half_applied_route_change_from_a_killed_apply_converges`，`ledger_recovery.rs:442` | 3.01 s |
| 4 | 删 LAN 路由连带撤销 | `deleting_a_lan_route_cascades_managed_kernel_objects`，`single_instance.rs:1510` | 6.78 s |
| 5 | 双网络并行不串网 | `two_networks_isolate_reconcile_and_rollback_on_one_hub`，`single_instance.rs:212` | 53.70 s |
| 6 | 宿主机规则不误删 | `backend_driven_tunnel_routes_and_nat` 的场景 12，`backend_wiring.rs:704`（主体在 `:1247`） | 32.96 s |
| 7 | 撤销在线设备后旧计划重试不重授 | `revoked_device_cannot_reauthorize_its_stale_plan`，`single_instance.rs:1821` | 5.94 s |
| 8 | Hub 公钥轮换迁移 | `hub_key_rotation_converges_devices_after_restart`，`single_instance.rs:1456` | 6.20 s |
| 9 | 库恢复后内核重新一致 | `restoring_a_backup_reconverges_the_kernel`，`single_instance.rs:1650` | 9.81 s |

耗时为单测串行运行（`--test-threads=1`）实测值；`single_instance` 整文件 7 个测试
105.89 s，`ledger_recovery` 6 个测试合计 6.35 s（场景 2、3 单跑分别 1.19 s、3.01 s），
`backend_wiring` 1 个测试 32.96 s。

## 场景证据

### 1. Hub 重启恢复受管状态

建一个两设备的网络加一条 `direct`/`controlled_snat` 路由，apply 并让两台设备收敛，
客户端到网关后面的 `192.168.60.5` 能通。然后记录 hub 自身公钥、peer 身份行
（公钥 + allowed-ips；endpoint 与握手时间故意不参与比对）、hub 路由、网关 NAT，
`ip link del wg0` 删掉 hub 接口，用 `persist::load` 从 SQLite 重新装载，
`convergence::recover_once` 重建。重建后 hub 密钥未变、peer 身份行逐字相同、
hub 路由相同、网关 NAT 相同。

如实记录、不是缺陷：重建后的接口不带会话密钥，而设备仍用**旧会话**（在
WireGuard 的 `REJECT_AFTER_TIME` ≈180 s 内依然有效）发 keepalive，hub 无法解密，
因此学不到对端 endpoint，也不会发起握手，于是静默丢包——这是 WireGuard 的标准
行为。本场景的合同是身份级重建，断言的就是这部分；数据面回归通过设备自己的
收敛步骤验证（重新应用即重置 peer 会话），见 `single_instance.rs:1441` 的注释。

### 2. Agent 重启不信账本单独判断

先用真实 apply 把内核带到与计划一致的状态并留下账本，这样一个对照 tick 返回
`UpToDate`——证明下一处检测不可能来自账本。随后把受管路由整条换成另一条**同标记**
路由：条数仍是 1，变的只是身份。tick 判定 `KernelDrift`，重装期望路由、移走
替换进来的那条，同时不碰预埋的外部路由；再 tick 一次为 `UpToDate`。

### 3. 改路由时进程被杀

三个被杀断点，每个都在计划 A 已应用并记账之后，种下真实的半途内核状态：
新路由已加但旧路由还没删、两条都不在场、一条都没动。每个断点在下一轮 tick 都
收敛到计划 B——新路由在场、旧路由不残留、外部路由幸存——账本最终描述计划 B
（`rev-b`）。之后再 tick 为 `UpToDate`。

### 4. 删 LAN 路由连带撤销

建一条 `alias` 模式路由加其 alias（`dnat_only`）并 apply，先留三处受管证据：
hub 侧 alias 前缀路由、注释为 `meshlet alias {alias_id}` 的网关 NAT、hub 的
`allowed-ips`。删除 LAN 路由返回 204，alias 列表为空。hub 在下一次 apply 收敛：
alias 路由消失、alias 前缀离开 hub 的 allowed IPs。网关的新计划不再有 NAT 规则，
而 `apply_device_plan_sync` 在空规则列表上会提前返回，所以这里走
`Agent::reconcile` 并给一个全新 state 目录：判定为 `NoLocalLedger`，所有权清扫
移走 alias NAT，overlay 连通性保持。

### 5. 双网络并行不串网

一个 hub、两个网络（`10.240.0.0/16` 与 `10.242.0.0/16`），两侧都是真实 netns
与设备。恶意客户端想给另一网络加路由/allowed-ips，仍被 hub 强制执行拒绝；
重新 apply 网络 A 不会动到 B 的 peer 与隧道；删掉 A 的内核接口再从 SQLite 重建
状态（重启模拟）只恢复 A。失败修订回滚时还原上一次可工作计划，而不是把隧道扫掉。
`single_instance.rs:337`、`:354`、`:357`、`:427`。

### 6. 宿主机规则不误删

受管 apply 直接跑在**根命名空间**——生产形态，agent 与别人家的路由同处一台机器。
测试先预埋一条外来路由、一条外来 NAT、一条 FORWARD 规则和特定 `ip_forward` 基线，
证明受管对象落在它们旁边，然后只删受管 NAT（`remove_nat_sync`）并回滚
（`rollback_sync`）。外来对象逐字幸存、`ip_forward` 不变，只剩隧道。
`RootGuard`（`backend_wiring.rs:245`）保证断言失败时也不把测试对象留在宿主机上。
同样的三种形状在 `apps/agent/tests/agent_reconcile.rs:878` 走真实 agent 判定，
逐项 `reason=KernelDrift`。

### 7. 撤销在线设备后旧计划重试不重授

被撤销设备仍在线，三层验证：

1. **凭证边界。** 撤销并 apply 后，同一个 token 取 desired 得 401，提交回执也 401，
   无论回执写的是旧修订号还是当前修订号（`convergence.rs:133-146` 在任何修订逻辑
   之前先拒绝非 active 设备）。
2. **修订/哈希边界。** 换成**存活设备**的合法凭证，旧计划照样不成立：旧修订号得
   400（过期回执），当前修订号配旧哈希也得 400（哈希不符）。过期编号与过期哈希
   都无法为撤销后的修订背书。
3. **不再入名单。** 存活设备的计划哈希已变、peer 里不再含被撤销公钥；再新建一条
   路由并 apply，也不会把它加回 hub 的 peer 列表；被撤销设备持续不可达；存活设备
   仍在握手且流量计数持续累加（读自 `wg show wg0 dump`）。

同一撤销的内核侧（hub 移除 peer、另一网络不受影响、从持久化状态重启不会把 peer
从 last-good 日志里复活）在 `single_instance.rs:624-674` 覆盖。

### 8. Hub 公钥轮换迁移

替换私钥文件，删掉 hub 接口，重新装载并 `recover_once`。hub 以新密钥起来，
peer 身份不变。随后每台设备收敛：计划携带新公钥、内核持有新公钥，旧密钥两侧都不
再出现。overlay 连通性恢复。

### 9. 库恢复后内核重新一致

建路由、apply、两台设备收敛，`192.168.60.5` 可达。记录 hub 路由与网关 NAT 作为
备份时刻证据，`persist::backup_once` 写备份（`summary.routes = 1`、`aliases = 0`、
无中断修订）。备份之后删掉该路由、apply，并让网关按空 NAT 计划 reconcile——证明
备份后的变更确实进了内核。随后关闭连接池，`restore_from_backup` 原子换回数据库，
服务重新拉起（此时 bootstrap 已 409，于是改走登录，拿到的是同一种会话）。

如实记录：**回滚式恢复后，「点一次 apply」无法让内核重新一致。** `ConfigLedger::apply`
对已 `Applied` 的修订直接返回（`crates/meshlet-domain/src/config_state.rs:230`），
而备份之后新增的修订在恢复出的库里已经不存在，因此根本没有可 apply 的修订。
受支持的恢复路径是生产启动恢复——`convergence::recover_once`，即
`apps/server/src/main.rs:98` 启动的 `start_recovery` 任务的同步形态——它拿恢复出的
期望计划比对内核，缺什么补什么。走完这一步，hub 路由与备份时刻逐字相同，网关 NAT
回到备份时刻的集合，LAN 通路恢复。把手工 apply 也做成「内核已漂移时重收敛」属
于产品语义决策，不属于验收缺口，作为后续项记录，本轮不改产品代码。

## 验证

```sh
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-server --test single_instance
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-agent --test ledger_recovery
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-network --test backend_wiring
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-agent --test agent_reconcile
MESHLET_REQUIRE_DATAPLANE=1 cargo test -p meshlet-server --test dual_site_end_to_end
```

设门禁后的结果：`single_instance` 7 通过 105.89 s、`ledger_recovery` 6 通过
6.35 s、`backend_wiring` 1 通过 32.96 s、`agent_reconcile` 1 通过 27.06 s、
`dual_site_end_to_end` 1 通过 33.82 s。`cargo clippy --workspace --all-targets
-- -D warnings` 与 `cargo fmt --all -- --check` 均干净，宿主机上没有留下测试对象
（`RootGuard` 加逐测试 netns 清理）。

矩阵可并入 R-07 浸泡验收执行：这些场景都不依赖时钟年龄。其中 2、3、5、6、7
最值得在浸泡机上重复跑，因为它们是唯一触碰共享内核状态的一组。
