# bc2d356（promote 偏好健康面）真机部署复验 — 2026-11-14 15:1x–15:2x

巡检单 meshlet-nov14-promote-verify。07fda5f+bc2d356（Relay 晋升选路前置过滤劣化面，
只剩劣化面 → defer 保持中继）随 nightly 部署双机并做字段验证。win-worker 未触碰。

## 构建

- nightly run `43569255524`（workflow_dispatch，head `bc2d356`）success；
  `gh api .../git/refs/tags/nightly` = `bc2d3569f0d50c3bc6ecb2d8a393934bc5445d70`（= HEAD）。
- MSI 11,128,832B，SHA256 `60d545c00ab99825e03cf1ffaabc263f5891b0d1e75c14f2fa4864806d7d92cf`
  对 release SHA256SUMS `sha256sum -c` **OK**。

## 部署（两机）

| 机器 | 时刻(+08:00) | 方式 | PID | 双位 exe 哈希 | --version |
|---|---|---|---|---|---|
| imac | 15:19:46 | scp + `powershell -File`（imac-up.ps1） | 37448→35644 | `05F75C40…BDA6`（PF=AD） | 0.1.0 |
| openclaw | 15:19:43 | router 隧道 `127.0.0.1:2222`（ZT 面 No route to host）+ schtasks 分离任务 MeshletOcUp3 | 8988→8128 | `05F75C40…BDA6`（与 imac 同构建） | 0.1.0 |

- 两机 MSIEXEC_RC=0；MSI_SHA256 与本机下载件逐字节同哈希。
- 收尾：imac Temp 三文件清；openclaw 任务自删（TASK_GONE_OK）+ Temp 净；隧道关
  （ss 无 2222 监听）+ known_hosts 清条目。

## 修复生产实证（agent-decisions.jsonl）

1. **全 fleet 首条生产 `defer`**（openclaw 新构建，07:20:26Z）：
   `{"action":"defer","peer_name":"windows-desktop","reason":"promote deferred:
   candidate face degraded (probe window)","degraded":true,"endpoint":"10.147.19.97:51821"}`
   ——JMrE 候选面 .97 正处劣化窗 → 不晋升（旧构建此处会 promote→立即再降级成翻转）。
2. **同机旧构建对照**（升级前 07:17:44Z）：`promote attempt via memory face (last_direct)
   (probe Unhealthy)` 上劣化 .226 面 → 07:21:38Z 即被 SEL-003 demote（75% 丢窗）——
   07fda5f 靶点的翻转循环原样留档。
3. **合规再晋升**（imac 07:23:50Z）：FSaf 恢复门 3 连健康轮通过、面级窗口已出劣化集 →
   记忆面 .49 选回。日志解读注记：promote reason 的 `(probe Unhealthy)` 后缀 =
   **握手年龄 classify**（relay 态无握手恒 Unhealthy），不是面级探测闸判定。

## 字段验证

- openclaw overlay 数据面：ping 10.240.0.3 4/4 包 0% 丢（均值 54ms，ZT underlay 抖动）。
- b6tx（coding-vm）台账 4 轮采样（07:25:58–07:27:28Z，30s 间隔，raw 见
  `bc2d356-b6tx-sample-2026-11-14.txt`）：三对端恒 p2p_direct 零翻转
  （JMrE 稳 .97 / FSaf 稳 .49 / imac 稳 192.168.5.117 rtt≤1）。

## 判据如实口径（不冒充）

- **JMrE/FSaf 未脱离 ZT 面**：几何必然——两台 Windows 均漫游在外（wd@192.168.88.x、
  openclaw@192.168.36.x），候选表只有 ZT 面 + 公网 NAT 面，无真 L2 面可回。
- **stranded 是否随之解待长窗复验**：defer 翻转抑制已见生产实证，但「≥20min 零
  hub_relay 回收」判据未跑；todo 103 行维持不勾。
- 观察 24-48h 窗以 bc2d356 部署完成（15:19–15:20 +08:00）为新起点（todo 108 行已归零
  重计），长跑观察留给后续巡检。

## raw 清单

- `bc2d356-imac-up-2026-11-14.txt` / `bc2d356-oc-up3-2026-11-14.txt`（升级日志）
- `bc2d356-imac-decisions-swevents-2026-11-14.txt` / `bc2d356-oc-decisions-swevents-2026-11-14.txt`（升级窗口前后决策+mode_flip 事件尾巴，SWEV 分隔）
- `bc2d356-b6tx-sample-2026-11-14.txt`（台账 4 轮）
