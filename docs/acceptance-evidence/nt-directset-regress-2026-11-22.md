# nt direct `wg set` OS-alias fix — real-machine regression (imac, 2026-11-22)

**对象**：dce5e92 `fix(nt): resolve os alias for direct wg set`（rebase 前 hash ef6a16b）
**验证口径**：`~/.hermes/cache/scratch/tasks/meshlet-nt-directset-regress.md`
**结论**：机制 **PASS**；直连 P2P 持久性 **未达成（如实记录，11-13 口径）**；周期 KernelDrift 重放 **仍存且属 pre-existing**（非本 fix 引入）。**本条不虚勾**。

---

## 1. 部署

- 本机 `x86_64-pc-windows-gnu` 交叉构建 `main`（HEAD 18cef2e，含 dce5e92），产物：
  - `meshlet-agent.exe` sha256 `36feb05940727fcafec27411ac20ce7a11e40ebbee534290272d8e40158684d8`
  - `wireguard.dll` sha256 `b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3`
  - `BUILD_INFO`：`repository=cuihairu/meshlet` / `commit=18cef2ea54cfb975f08035dd6c58fe4fc8ab3ffc` / `built_at=2026-11-21T23:19:03Z` / `target=x86_64-pc-windows-gnu` / `source_dirty=false`
- imac（LAN `ssh imac`）替换 agent（**保 tray 不动**）：停 `MeshletAgentDeploy` → kill 旧 agent（PID 8572）→ 覆盖 exe/dll/BUILD_INFO 到 `C:\Users\cui\AppData\Local\meshlet\` → `Start-ScheduledTask`。
- 恢复：新 agent **PID 544**，CreationDate `2026/11/22 7:22:37`（本地）= `2026-11-21T23:22:37Z`（= 二进制切换边界）；`MeshletAgentDeploy` = **Running**；adapter `WireGuard` **Up**；hub `106.14.216.177` ping **True**；账本 `applied.json` `applied_at` 持续刷新。**agent 起得来，无需回滚**。

## 2. 机制验证 —— PASS（决定性证据）

### 2.1 wg set 失败 187 → 0

`meshlet-agent.log.2026-11-21/22` 按切换边界 `2026-11-21T23:22:37Z` 分裂：

| 文件 | 失败总数 | pre（旧二进制） | post（新二进制） |
|---|---|---|---|
| 2026-11-21 | 187 | **187** | 0 |
| 2026-11-22 | 0 | 0 | 0 |

- pre 失败错误形状全为：`wg set wg-meshlet :: Unable to modify interface: No such file or directory` —— 旧代码按**配置隧道名** `wg-meshlet` 寻址，但 nt 模型的 OS 别名是 `WireGuard`（隧道名只在 `InterfaceDescription`），寻址不存在 → 恒失败。
- post 失败 0，且日志出现新寻址形式（`effective_interface_alias` → OS 别名 `WireGuard`）。

### 2.2 直连 peer 真进 nt adapter

切换后 `wg show WireGuard`（dump 第 1 行=接口行 `private_key/public_key/listen_port/fwmark`，其后为 peer）：

```
SL6Nx13UeamrYMyIiYMjTtskZF1l+9TVYvWBA2/w0VI=  QmAFaSKbFqm3qGql/DH+mJOWSfN1n6VyNhXwaRrXdlg=  51820  off   ← 接口行（本机私钥/公钥/端口/fwmark）
vLkJb0o0T3ljv6LmvDawzrE+3m9AvNSBEW/n/UKLLHM=  (none)  106.14.216.177:51820  10.240.0.0/16  <hs>  rx  tx  25   ← hub
qaa2xB4O7Tno26+gO3qDI5vvm5SZjgCJ+iJHZ+GDllE=  (none)  10.147.19.97:52931  10.240.0.8/32   <hs>  15440  …  15  ← 直连 peer
FSaf/1S9kdPMrZASj8+mrjmPSixzXpTMU1anfDLXV2g=  (none)  192.168.5.11:51820  10.240.0.3/32   …  684  …  15       ← 直连 peer
b6txQ61FHR82eciDlw6G/4x0Z+n7FJvajjIBVv8APnc=  (none)  10.147.19.130:51820  10.240.0.4/32   <hs 16s>  508  271MiB  15  ← 直连 peer（握手新鲜）
```

直连 peer 以 `/32` allowed-ips + 直连 endpoint + keepalive 15 装入 nt adapter，且观测到**新鲜握手**与传输。旧二进制下 `wg set` 恒失败，这些 peer **不可能**装入——本 fix 的寻址修复端到端坐实。

### 2.3 直连下发结果（post 边界）

`promote/demote` 计数（2026-11-21 post + 2026-11-22）：**promoted=50、demoted=49、promote_failed=0**。`set_direct_peer_sync` 每轮返回 Ok（日志 `INFO direct link promoted … endpoint=…`），无一条 `direct promote failed; keeping hub relay`。

## 3. 直连 P2P 持久性 —— 未达成（如实记录，不冒充已验）

- `direct-peers.json` 三对端模式恒为 `hub_relay`（cuihaitao / openclaw-win）或 `direct_pending`（coding-vm），**无 `p2p_direct`**。
- `direct-switch-events.json` 呈固定环：`hub_relay → direct_pending`（`promote attempt via candidate table (probe Unhealthy)`）→ `hub_relay`（`pending attempts exhausted after 3 rounds (probe Unknown)`）。
- 候选端点（10.147.19.97 / .130 / .49、192.168.5.11、180.153.160.8）为 **stranded ZT 成员 / 公网漫游面**，握手/探针不达（probe Unhealthy→Unknown）。imac 现网本就骑这些匿名 ZT 面 —— 属 **11-13 已知 stranded 口径**，非本 fix 缺陷。
- 直连链路短暂建立（peer 装入 + 握手）后即被探针判定不达而 demote，形成 re-promote 循环。**P2P 在 imac 当前网络不驻留**，如实记录。

## 4. 周期 KernelDrift 重放 —— 仍存，属 pre-existing（非本 fix 引入）

### 4.1 计数

| 文件 | pre（旧二进制） | post（新二进制） |
|---|---|---|
| 2026-11-21 | **185** | 46 |
| 2026-11-22 | 0 | 64 |

- post 合计 **110** 次，间隔 ~45s，持续整个观察窗（`2026-11-21T23:22:37Z` → `2026-11-22T00:47:44Z`，≈ 85 min ≫ 10 min）。
- **pre 边界即 185 次**（旧二进制、**零直连 peer 在场**——所有 wg set 均失败）→ 重放**先于**且**独立于**直连 peer 机制，非 dce5e92 引入。

### 4.2 代码级归因（本机 nt 数据面）

- `crates/meshlet-network/src/windows/backend.rs:201-207`：nt `inspect_sync` 的 `installed_routes` = **peers allowed-ips 的并集**（驱动 `set_default_route` 装配）。hub `vLkJb0o0` 的 `10.240.0.0/16` 恒在并集内。
- `apps/agent/src/reconcile.rs:253-261`：`drifted()` 对「已装但不在 `plan.routes`」的路由判漂移（`extra`）。本机 `applied.json` `routes=[]`（叶节点，无路由计划）→ hub `/16` 恒读作「计划外路由」→ **确定性 KernelDrift**，与直连 peer 是否在场无关（直连 `/32` 只是叠加）。
- 结论：nt 模型 `installed_routes`（peer allowed-ips 并集）与 `drifted()` 的「`plan.routes` 为权威」假设**不匹配**——pre-existing nt 对账缺陷，**非本次 fix 所致**，留待另案（本批纯文档，不改 rust）。

## 5. 证据文件（`docs/acceptance-evidence/nt-directset-regress-2026-11-22/`）

| 文件 | 内容 |
|---|---|
| `build-info.txt` | 本机构建产物 sha256 + git_commit + built_at_utc |
| `deploy-recovery.txt` | BUILD_INFO / PID 544 / task Running / hub ping True / applied.json 账本 |
| `wg-set-boundary.txt` | 失败 187→0 分裂 + pre 错误形状（`wg-meshlet :: No such file or directory`）+ post 新形式计数 |
| `promote-demote.txt` | post 边界 promoted=50/demoted=49/failed=0 + 样本日志行 |
| `adapter-wg-show.txt` | `wg show WireGuard`（人读 + dump 原始）+ 接口地址 10.240.0.7 |
| `direct-peers-state.txt` | direct-peers.json 三端模式 + 最近 switch 事件 |
| `kerneldrift-split.txt` | KernelDrift 185/110 分裂 + post 样本（routes=0 nat_rules=0 reason=KernelDrift） |

## 6. 判定

- **dce5e92 机制**：真机 **验证通过**（187→0；直连 peer 装入 nt adapter；0 promote 失败）。
- **直连 P2P 持久性**：**未达成**（stranded ZT 候选面，11-13 口径）——记录差异，不冒充已验。
- **周期 KernelDrift 重放**：**仍存、pre-existing**（185 次旧二进制无直连 peer 在场为证；归因 nt installed_routes vs plan.routes 不匹配），非本 fix 引入。
- **WG-NT-SWITCH 条目**：仍 `[ ]`（item 1 修复实证，但 P2P 不驻留 + KernelDrift 重放 + 灰度/2-peer 未走 → 不虚勾整条）。
