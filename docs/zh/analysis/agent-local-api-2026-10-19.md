# Agent 本地 API 与授权方案 · 2026-10-19

## 现状结论

当前 agent 是后台拉取客户端，不是本地 API 服务。它读取配置、解析设备凭证、从 Meshlet server 拉取类型化期望计划，在本机应用/对账，再上报应用回执和心跳；不会执行服务端下发的 Shell 命令。Agent 入口没有本地 TCP listener 或 Unix socket。本方案讨论同机脚本、CLI 和后续桌面控制台使用的新本地控制面。

## 当前行为与安全证据

| 证据 | 仓库位置 |
|---|---|
| Agent 入口读取配置、解析设备 Token、读取本机私钥后进入 `Agent::run`；数据面关闭时不碰内核并退出 | [`apps/agent/src/main.rs:20`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L20)、[`:37`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L37)、[`:42`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L42)、[`:51`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L51)、[`:59`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L59) |
| `Agent::run` 是循环调用 `tick` 的 worker 生命周期 | [`apps/agent/src/agent.rs:85`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L85) |
| Agent 使用设备 Bearer Token 请求 `/api/v1/agent/device/desired`，并向 `/applied`、`/heartbeat` 回报 | [`apps/agent/src/server.rs:17`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/server.rs#L17)、[`:71`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/server.rs#L71)、[`:91`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/server.rs#L91) |
| Agent API 契约是拉期望计划、心跳和证据；服务端不下发命令 | [`apps/agent/src/server.rs:1`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/server.rs#L1)、[`apps/agent/src/main.rs:7`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/main.rs#L7) |
| Agent reconcile 检查内核、应用类型化计划、读回核验并保存不含私钥的 last-good；失败时恢复 last-good | [`apps/agent/src/agent.rs:184`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L184)、[`:253`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L253)、[`:276`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L276)、[`:289`](https://github.com/cuihairu/meshlet/blob/main/apps/agent/src/agent.rs#L289) |
| Server 当前只绑定配置的 TCP 地址；启动时没有接入 agent 本地 listener | [`apps/server/src/main.rs:46`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/main.rs#L46) |
| Agent desired/applied/heartbeat 路由是 server 端点 | [`apps/server/src/lib.rs:981`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/lib.rs#L981) |
| 管理认证接受会话或管理 API Token；无效会话不回退 Bearer；agent Token 是独立凭证边界 | [`apps/server/src/auth.rs:411`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/auth.rs#L411) |
| 管理写入需要 `WriteUser`；会话写入还需要 CSRF Header | [`apps/server/src/auth.rs:464`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/auth.rs#L464)、[`:483`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/auth.rs#L483) |
| API Token 区分 read/write、只存摘要、可撤销并记录最近使用时间 | [`apps/server/src/api_token.rs:38`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/api_token.rs#L38)、[`:76`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/api_token.rs#L76)、[`:100`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/api_token.rs#L100) |
| 注册申请需管理员批准；批准前不进入活动设备集，也不能获得计划 | [`apps/server/src/agent.rs:303`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/agent.rs#L303)、[ADR-011](../decisions/adr-011-device-self-registration.md) |
| 敏感管理操作写入审计；审计记录接口不能接收原始凭证材料 | [`apps/server/src/audit.rs:1`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/audit.rs#L1)、[`:45`](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/audit.rs#L45) |

Server 已有实质认证/审计能力：一次性管理员自举、会话、CSRF、分范围管理 API Token、独立设备凭证、审批门槛与敏感写入审计；敏感操作审计失败时拒绝放行。与本地 API 相关的缺口是：没有本地调用者身份、本地权限策略、本地审计 actor、listener 生命周期或状态/应用/日志 IPC 契约。现有 Token 只有宽泛 read/write 两档；浏览器会话是用户身份，不应变成本地 agent 密钥。

## 本地 API 边界

**调用者：**(1) 同用户脚本/自动化，(2) 本机 Meshlet CLI，(3) 后续桌面/托盘控制台。配置网络需要提权时，root/系统服务应另有明确调用者策略。远程调用不在范围内；本 API 不应成为另一个网络管理 listener。

**根据现有功能推导的首批能力：**

| 能力 | 初始语义 | 授权类别 |
|---|---|---|
| 读状态 | Agent 运行/版本、最近成功 reconcile、期望修订/哈希、最近错误和连通证据；不含秘密 | 只读 |
| 触发 reconcile/apply | 要求现有 worker 立即拉取服务端最新计划并 reconcile；不接受任意 Shell、内核命令、私钥或调用者自制 `DevicePlan` | 写入/控制 |
| 读近期日志/诊断 | 有界结构化事件和当前诊断快照；脱敏凭证与私钥 | 只读 |
| 关闭/重启（后续） | 协调系统服务管理器，不提供 agent 自我提权入口 | 管理/平台相关 |

Apply 是要求 reconcile 服务端当前已批准的期望状态，不是本地覆盖。设备审批和服务端修订/应用回执仍为权威状态。本地调用者不能借本地 API 完成服务端审批。

## 授权方案对比

外部资料检索日期统一为：**2026-10-19**。

| 方案 | 安全模型 | 实现复杂度 | Windows 可行性 | 与现有 auth/audit 整合 | 主要风险 |
|---|---|---|---|---|---|
| **Unix Domain Socket + 文件权限 + `SO_PEERCRED`** | 内核提供连接对端 PID/UID/GID；Socket 目录和文件权限限制连接者；每次 accept 后校验 peer credentials，按 UID（可选明确配置的组）授权。Linux 文档说明其用于已连接 AF_UNIX stream。 [Linux `unix(7)`](https://www.man7.org/linux/man-pages/man7/unix.7.html)（2026-10-19） | Linux 低到中；需定义轻量帧协议、socket 生命周期/清理和 UID 策略 | 不是 Windows transport；Windows 需另做 named pipe | 将本地身份映射为 `local:uid:1000` 等内部 actor，共用操作策略和审计 action 名；不签发 server 会话、不暴露设备 Token | 同一已授权用户下的所有进程均可调用；目录/Socket 权限过宽、残留路径、特权 agent 被诱导执行不当操作 |
| **Loopback HTTP + 随机 Bearer Token** | 明确绑定 `127.0.0.1`（IPv6 loopback 需另决）；持有高熵 Token 即授权。服务端可只存摘要；以权限 0600/ACL 文件存随机秘密，不能放 argv/env/日志。原子替换轮换并立即撤销旧值；可由本地 CLI 签发短期 Token。Bearer Token 必须保护存储/传输，loopback 本身不等于认证。 [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html)（2026-10-19） | 低到中；可复用 HTTP/JSON，但增加 Token 配置轮换、CSRF/Origin 策略和 listener 生命周期 | 高，同一 HTTP 形态，但需在 Windows 验证绑定与防火墙假设 | 可建独立本地 Token 表及审计 actor；不复用管理 `mlt_` Token 或设备 Token。现有 read/write scope 可借鉴，但可能需 status/control/logs 权限 | 本机进程可从文件/进程调试面窃取；hostname 接受不严导致 DNS rebinding/Origin 错误；浏览器 CSRF、本机恶意软件、主机备份拷走 Token |
| **双向 TLS / 本地客户端证书** | 本地服务信任指定 CA/固定客户端证书；客户端证明私钥持有。证书可标识身份并撤销/轮换；TLS 1.3 定义客户端 Certificate/CertificateVerify 认证。 [RFC 8446](https://www.rfc-editor.org/info/rfc8446/)（2026-10-19） | 单机 agent 场景高：CA/签发、存储、续期、撤销和信任迁移 | 可在 Windows 实现；系统证书库有帮助，但跨平台配置成本大 | 证书指纹/SAN 映射本地主体，再接本地授权和审计；自身不等同于当前浏览器会话语义 | 单机边界承担过多密钥生命周期；证书可被复制；本地 TLS listener 仍需做应用级授权 |
| **OS 授权/系统凭据（polkit、systemd credentials、Windows Pipe ACL）** | 由 OS 策略决定调用者/动作授权及凭据隔离。polkit 对 subject/action 求授权；systemd `LoadCredential=` 只向服务 UID 暴露只读 unit 凭据；Windows named-pipe DACL 控制客户端。 [polkit 参考](https://polkit.pages.freedesktop.org/polkit/)、[systemd `systemd.exec`](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec)、[Microsoft named-pipe 安全](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)（2026-10-19） | 中到高；Linux polkit/D-Bus 集成与 systemd 打包，Windows 安全描述符和模拟身份校验 | Windows named pipe ACL 很适合；Linux polkit/systemd 专属，需要平台适配 | 将 OS 主体/动作结果映射到统一本地身份，再交 Meshlet 审计。systemd credentials 适用于服务秘密传递，不是交互请求授权 | 策略/打包漂移；默认 ACL 意外放宽；无图形 polkit agent 的 headless 主机体验差；管理员授权过宽；OS 策略不够跨平台且排错门槛高 |

## 推荐方案

**推荐基于 OS peer identity 的本地 IPC：Linux 首期用 Unix Domain Socket + `SO_PEERCRED`；Windows Agent 控制实现时用显式限制 DACL 的 named pipe 适配器。**协议和授权逻辑保持 transport-neutral。这是一个方案：由宿主认证本地主体，再按平台提供等价 IPC。不将 loopback Bearer Token 作为主要身份机制。

理由：脚本和桌面配置无需复制秘密；内核直接给出调用者身份；Linux 与当前 server/agent 部署一致；Windows named pipe 有成熟 ACL 模型，避免引入本地 HTTP Token 特例。Server 现有凭证继续各司其职：OS 本地身份授权本地操作，设备凭证认证 agent 到 server。审计增加明确的本地 actor 和操作结果；本地 OS 身份不会隐式变成 Meshlet 管理员账号。

### 分阶段路径

1. **先定契约和威胁边界：**读状态、请求 reconcile、有界日志；禁止任意命令、调用者自带计划、读取私钥和管理 server 写操作。确定请求大小/时限及审计字段。
2. **Linux MVP：**在 agent runtime 目录下使用一个 AF_UNIX socket；目录和 socket 采用严格 owner/mode；accept 后验证 peer credentials；默认仅允许服务属主 UID，只有有依据时才配置额外组。返回结构化状态；触发 reconcile 应入队给现有 worker，避免第二条并发 apply 路径。
3. **CLI 接入：**CLI 连接本地 socket，不读取 agent 的设备 Token 或私钥。审计记录 peer UID、操作、结果、期望修订/哈希和时间；不记录凭证。
4. **Windows 适配器：**Named Pipe 使用明确 DACL 限定目标用户/管理员组，拒绝远程客户端并校验对端身份；保持同一协议/授权语义。此项独立于 PN-03 的完整数据面支持。
5. **桌面 UI 与策略细化：**CLI 稳定后再接桌面；若特权操作需要交互提权，再评估 polkit 确认。只有真实消费者提出需求后才细分更多 scope。

### 与 MOD-05 的关系及 ADR

这是 agent 本地控制协议，不是 MOD-05 所述管理 SDK/公共 API。它可成为 CLI/桌面消费的独立本地接口。MOD-05 仍指 server 管理 API DTO、稳定消费者文档和独立 SDK；本地协议不因此发布或承诺兼容。MOD-02 可在本地 API 契约成形后再考虑抽取共享授权词汇。

建议决策记录：**ADR-013 — Agent Local Control API and OS-Principal Authorization（Agent 本地控制 API 与 OS 主体授权）**。决策内容包括 socket/pipe 协议、本地主体映射、默认用户/组策略、允许操作、审计 schema、特权操作边界和协议版本策略。若先不实现 Windows，应明确 Linux-first 范围，并要求后续适配器保持同一策略。

## 范围声明

本文仅调研与推荐，不写实现代码、不修改认证契约，也不承诺时间。

