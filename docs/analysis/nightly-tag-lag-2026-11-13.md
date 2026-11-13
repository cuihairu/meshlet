# Nightly tag 滞后核查（2026-11-13）

结论先行：**nightly tag 滚动机制正常，schedule 腿没有条件跳过，无需改 workflow**。今晨 schedule
run（43336364759）成功把 nightly tag PATCH 到了它构建的 commit 92fe428；tag 停在 92fe428 不是
机制失效，而是纯时序滞后——schedule 00:21 UTC 开跑时 main HEAD 还是 92fe428，探测默认开的
00da12b 在 06:40 UTC 才推上 main。已用 workflow_dispatch 补跑（run 43382147308）把 tag 滚到
00da12b 并发布对应产物，imac 已升级到该构建（见文末）。

## 背景

- main HEAD = 00da12b（`fix(config): default candidate probe on with direct connect`），
  2026-11-13 14:40 +0800（06:40 UTC）推送，CI 绿。
- 巡检时 nightly tag 指向 92fe428（含 df21f88 Windows 探测传输，不含 00da12b 探测默认开）。
- imac 部署版 `meshlet-agent.exe` 构建于当日 00:37 +0800（b988ed8 时代，**不含** df21f88 /
  00da12b——`git merge-base --is-ancestor df21f88 b988ed8` 为假）。

## 机制（nightly.yml publish 腿）

- `publish` job 条件 `if: github.ref == 'refs/heads/main'`：schedule 与 workflow_dispatch
  触发时 ref 同为 main，两种触发一视同仁，不存在「仅 dispatch 才滚 tag」的分支。
- tag 更新语句：`gh api --method PATCH repos/$GITHUB_REPOSITORY/git/refs/tags/nightly
  -f sha="$GITHUB_SHA" -F force=true`，在 `gh release view nightly` 探测到既有 release 时
  执行（PATCH + upload --clobber + edit），否则 `gh release create --target $GITHUB_SHA`。
- cron `17 19 * * *` UTC（= 03:17 +0800）。

## schedule 腿实锤（run 43336364759）

| 项 | 值 |
|---|---|
| event / conclusion | schedule / success |
| createdAt | 2026-11-13T00:21:05Z |
| headSha（构建对象） | 92fe42808c29900ba94487c0b53fb9386548fb05（当时 main HEAD） |
| publish job | success（job 131602455925，00:41:57Z 结束） |

publish job 日志关键行（2026-11-13T00:41:53Z），PATCH 的 API 响应回显
`object.sha` = 92fe428 = 该 run 的 `GITHUB_SHA`，证明 tag 更新步骤真实执行且成功：

```
{"ref":"refs/tags/nightly","node_id":"REF_kwDOVHqvNrFyZWZzL3RhZ3MvbmlnaHRseQ",
"url":"https://api.github.com/repos/cuihairu/meshlet/git/refs/tags/nightly",
"object":{"sha":"92fe42808c29900ba94487c0b53fb9386548fb05","type":"commit",...}}
https://github.com/cuihairu/meshlet/releases/tag/nightly
```

## 时序表

| 时刻（UTC） | 事件 |
|---|---|
| 11-12 19:17 | cron 计划触发点（GitHub 调度延迟约 5h，平台常态） |
| 11-13 00:21:05 | run 43336364759 实际开跑，HEAD = 92fe428 |
| 00:41:53 | publish PATCH tag → 92fe428 成功 |
| 06:40 | 00da12b 推上 main（晚于 schedule 快照） |
| 06:56 | workflow_dispatch 补跑 run 43382147308（HEAD = 00da12b） |

结论：tag 指向 92fe428 是「schedule 构建的是触发时刻的 HEAD、新 push 要等下一次触发才能
进 nightly」的固有滞后，机制层面无缺陷。要消除这类滞后只能 push 后手动 dispatch（本次做法），
或改用 push 触发的滚动构建——后者不在本次范围。

## 补跑验证（run 43382147308）

- event = workflow_dispatch，headSha = 00da12b73f33d5fbf004f9488738e1461169e210，
  conclusion = success（06:56:13Z → 07:11:51Z，15.6 分钟，全部 job 绿）。
- publish 腿 PATCH 响应回显 `"object":{"sha":"00da12b73f33d5fbf004f9488738e1461169e210"}`；
  `gh api repos/cuihairu/meshlet/git/refs/tags/nightly` 复核同值——**nightly tag 已滚到
  00da12b**，release 产物同步刷新。
- 产物核验：`meshlet-nightly-windows-x86_64.msi`（11,104,256 B）本地 `sha256sum` =
  SHA256SUMS 对应行 = `5393763334eceb46f3f8810edafaed16371daf7c02b1f02a6c54e56058741bfe`。

## imac 升级到 00da12b 构建（2026-11-13 15:0x–15:3x +0800）

沿用 11-13 晨间升级链路（MSI → Program Files 服务位 → 覆盖 AppData 运行位 → 重启 agent）：

1. **产物**：上述 MSI scp 到 imac 后远端 `certutil -hashfile` 复核哈希与本地一致。
2. **服务位**：`msiexec /i … /qn /norestart` exit=0；`C:\Program Files\Meshlet` 4 exe 落位
   （mtime 2026-11-13 7:07–7:11 UTC = 本次安装时刻）。
3. **运行位**：停 `MeshletAgentDeploy` 任务 → 杀旧 agent（PID 44248，upgrade 前实测运行的就是
   AppData 位 exe）→ `meshlet-agent.exe` 从 Program Files 覆盖到
   `%LOCALAPPDATA%\meshlet\` → 重启任务。
4. **血缘链**：AppData 与 Program Files 两份 `meshlet-agent.exe` SHA256 一致 =
   `96FA2777D4B0C819CFCC00D9EEAC2FC6C8AD58B940E4ED8FC01F341B49EAE3C3`；
   MSI 哈希被 SHA256SUMS 背书、SHA256SUMS 随 00da12b 构建 publish——三环闭合。
5. **进程与版本**：新 agent PID 1584（15:28:31 +0800 起）单进程；
   `meshlet-agent.exe --version` = `meshlet-agent 0.1.0`（6a9ec71 修复保持，exit 0）。
6. **隧道恢复**：重启后约 3 分钟 warmup 瞬态（RTT 先飙 1.9s、短暂 100% 丢后收敛；期间对照
   ZT underlay 直路径 10.147.19.226 全程 0% 丢 / 1.6ms，排除 underlay 故障窗）；稳定后
   coding-vm → imac VIP（10.240.0.7）20/20 包 0% 丢、均值 1.84ms（优于升级前基线 16.9ms），
   WG 握手持续刷新。服务恢复在线。

升级后 imac 构建含 df21f88（`git merge-base --is-ancestor df21f88 00da12b` 为真）+
00da12b 探测默认开——SEL-002 Windows 侧验收的 imac 侧前置满足（openclaw 待升同版，
见 todo.md）。
