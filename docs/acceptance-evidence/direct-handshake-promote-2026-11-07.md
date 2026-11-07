# DIRECT 直连状态机：握手证据优先晋升（imac 真机取证，2026-11-07）

对应 commit `e5de19f`（`fix(agent): promote direct links on WireGuard handshake
evidence, honest rtt_source`），修用户实测缺陷：**「每次查看直连节点都是拨号中，
等通了关掉下次又是拨号中」**——直连对端永卡 `direct_pending`，握手已成功但状态
不晋升。

## 根因（真机实锤，imac）

1. **晋升门槛实际拿不到握手证据**：状态机 pending→Direct 需要 `wg show
   latest-handshakes` 读数；Windows 隧道服务抖动期该命令直接失败
   （`Unable to access interface: No such file or directory`, exit 1）——
   而诊断 `wg dump`（同一次内核读数的另一投影）里握手时间是有的
   （`direct-peers.json` 中 2 个对端 `last_handshake_at` 新鲜）。
2. **Windows 网格 ICMP 100% 丢包**（防火墙不答 wg 接口/overlay VIP，本机
   复核 `ping 10.240.0.3` 全丢）——任何把「探测成功」当晋升/活性前提的逻辑
   在该网格永不成立。
3. **隧道重装竞态把隧道打挂**（事件日志实锤）：`install_plan` 卸载后立刻装新
   服务，旧服务进程退出前仍持有 conf 文件 → 新服务启动报 7023「The process
   cannot access the file because it is being used by another process」→
   7045 安装 → 7023 停止连环失败（16:41 / 16:46 / 16:51，每 ~5min 一轮）→
   隧道永远起不来 → 所有直连对端每 ~90s promote/pending/demote 抖动。
4. **rtt_source 谎报**：握手新鲜、链路活着的对端被标 `unprobed`（没轮到）/
   `unreachable`（不可测），展示层无法区分「链路可疑」和「测不出」。

## 修复

- **域层**（`DIRECT_PROMOTE_FRESH_SECS=180` + `classify_promote_probe`）：
  pending→Direct 只认 WireGuard 握手证据——latest-handshake 年龄 ≤180s 即晋升；
  (180,240] rekey 间隙继续等；>240s 健康窗口判失效回退。对齐 hub keepalive 与
  CLI `peer_mode` 口径。**SEL-003 劣化回中继原样保留**（劣化优先级最高，
  丢包尖峰/超时仍立即降级）。
- **agent**：握手年龄 = `latest-handshakes` 专项读数 ∪ `wg dump` 兜底合并
  （专项不可读时晋升门槛仍有输入）；rtt_source 如实四态
  `probe_ok` / `handshake_fresh` / `probe_failed` / `unprobed`。
- **windows.rs**：卸载后轮询等旧服务退干净（≤4s）再装新服务。
- **panel.rs**：tooltip 映射四态；旧 agent 落盘的 `overlay`/`endpoint`/
  `unreachable` 保留兼容映射。

## 门禁（本机 Linux）

| 项 | 结果 |
|---|---|
| `cargo test --workspace` | 全绿 0 failed（新增 9 测：晋升门槛边界 / pending 新鲜握手经 plan_updates 晋升 / pending 握手过期回退 / ages 兜底合并 / rtt_source 四态 / dump 年龄过滤 / panel 四态 tooltip） |
| `cargo clippy --workspace --all-targets -- -D warnings` | 净 |
| `cargo fmt --all -- --check` | 净 |
| CI（push `e5de19f`） | `CI` success、`Dataplane acceptance` success |

## 部署（imac，SSH 别名 `imac` = 192.168.5.117）

- Linux 交叉编译 `x86_64-pc-windows-gnu` release，scp 后远程 `Get-FileHash`
  与本地一致：
  - `meshlet-agent.exe` SHA256 `CAC5DA9D…33F5D` → `%LOCALAPPDATA%\meshlet\`
  - `meshlet-tray-host.exe` SHA256 `0A518470…1A216` → `C:\Program Files\Meshlet\`
- 双进程经计划任务重启（agent 75036 / tray-host 64148，均 17:10:58 起新二进制）。

## 前后对比（direct-peers.json + 内核读数）

**Before（旧 agent，16:14 冻结态）**：4 对端全部
`mode:"direct_pending"` + `rtt_source:"unprobed"`；隧道服务 **Stopped**；
`wg show wg-meshlet latest-handshakes` exit 1（Unable to access interface）；
事件日志 7045→7023 重装连环失败。

**After（新 agent，17:13-17:16）**：

```json
{"name":"cuihaitao",       "mode":"p2p_direct","rtt_source":"handshake_fresh","last_handshake_at":1794042823}
{"name":"coding-vm",       "mode":"p2p_direct","rtt_source":"handshake_fresh","last_handshake_at":1794042819}
{"name":"windows-desktop", "mode":"p2p_direct","rtt_source":"handshake_fresh","last_handshake_at":1794042823}
{"name":"openclaw-win",    "mode":"p2p_direct","rtt_source":"handshake_fresh","last_handshake_at":1794042797}
```

- 隧道服务 **Running**（重装竞态修复后首装即成）；
- `wg show wg-meshlet latest-handshakes` 正常输出 5 条新鲜握手；
- **4/4 对端 `p2p_direct`**（直连），90s 复查无回抖（握手时间戳持续刷新，
  rtt_source 稳定 `handshake_fresh`——如实：ICMP 不可测但握手新鲜=链路活）；
- 面板 RTT tooltip：`来源：握手新鲜（对端不答 ICMP，最近握手即链路活性证据）`。

## 证据文件

- `panel-direct-fix-2026-11-07.png`：imac 面板截图（直连节点 4 行全部
  「直连」、最近握手 32-51 秒前、无 direct_pending/拨号中字样）。
- 事件日志 7023/7045 序列、修复前后 `wg show` 输出见上文（SSH 实采）。
