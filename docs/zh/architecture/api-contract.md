# API 契约（初稿）

> 来源：[存档 §13](../review/chatgpt-2026-10-13.md#_13-api-设计)。机器可读版本：[openapi.yaml](/api/openapi.yaml)（OpenAPI 3.1）。初稿待评审；实现以本文件 + openapi.yaml 为契约，代码生成或类型同步（§4.2）。

## 约定

- 所有 API 使用版本前缀 `/api/v1`；JSON 请求与响应；统一错误响应结构（见下）；
- 输入验证在服务端执行；有副作用的操作记录审计事件（ADR-010）；
- 列表接口分页（`limit`/`offset`，响应带 `total`）；
- 可区分的错误码：`conflict` / `unauthorized` / `forbidden` / `not_found` / `validation_failed` / `too_many_requests` / `apply_failed` / `backup_not_configured`；
- 配置修改类响应必须携带 `revision_id` 与 `apply_status`（ADR-009）；
- 敏感可重试操作提供幂等语义；
- **Agent API 与管理 API 认证边界清晰分离**（§13.7）。


> **契约 ↔ 实现对账（2026-10-15）**：本表与 [openapi.yaml](/api/openapi.yaml) 已与 `apps/server` 注册的 33 条路由逐一对齐——规格先行的端点（网络/设备详情与更新删除、 `rotate-key`、逐网络 `status`、路由 `PATCH`）从未实现且不在第一版验收（§22）内， 已从机器契约移除，避免代码生成出 404 客户端；重复的 `diagnostics` 路径块已去重（保留与实现一致的一份：`POST` 返回 `200` + 报告，非 `202`）。

## 统一错误响应

```json
{ "error": { "code": "conflict", "message": "alias prefix overlaps overlay cidr", "details": {} } }
```

## 端点清单

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/auth/bootstrap` | 空库创建首个管理员（有用户后 409 关闭） |
| POST | `/api/v1/auth/login` | 登录（限流：每 email 15 分钟 5 次失败，ADR-010） |
| POST | `/api/v1/auth/logout` | 登出（撤销会话） |
| GET | `/api/v1/auth/me` | 当前用户 |
| POST | `/api/v1/auth/tokens` | 签发 API Token（外部机器凭据；原始 Token 仅此一次返回）🔒 |
| GET | `/api/v1/auth/tokens` | 当前用户的 Token 列表（不含任何 Token 材料）🔒 |
| DELETE | `/api/v1/auth/tokens/{token_id}` | 撤销 API Token（即失效；仅属主可撤）🔒 |
| GET/POST | `/api/v1/networks` | 网络列表 / 创建（CIDR 验证，ADR-004）🔒 |
| GET | `/api/v1/networks/{network_id}/devices` | 设备列表 🔒 |
| POST | `/api/v1/networks/{network_id}/invites` | 生成一次性邀请（ADR-010）🔒 |
| DELETE | `/api/v1/networks/{network_id}/invites/{invite_id}` | 撤销邀请（ADR-010）🔒 |
| GET/POST | `/api/v1/networks/{network_id}/bootstrap-tokens` | 自举码列表 / 签发（设备自举注册入口；原始码仅此一次返回，§11.3）🔒 |
| DELETE | `/api/v1/networks/{network_id}/bootstrap-tokens/{token_id}` | 撤销自举码（立即失效；重复撤销 409、未知 id 404）🔒 |
| POST | `/api/v1/enroll` | 设备加入（邀请 Token + 公钥；私钥不出客户端，§11.2） |
| POST | `/api/v1/device-registrations` | 设备自举注册（ZeroTier 式：自举码 + 公钥 → Pending 待审批；原始 agent 凭证即签即用，§11.6） |
| GET | `/api/v1/networks/{network_id}/registrations` | 待审批注册申请列表（Pending 心跳证据在此可见）🔒 |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/approve` | 批准注册（此刻才分配虚拟 IP + 记修订；沿用注册期凭证，不轮换）🔒 |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/deny` | 拒绝注册（纯状态清理：申请与凭证一并作废，不记修订）🔒 |
| POST | `/api/v1/agent/heartbeat` | Agent 心跳/状态上报（Bearer agent_token；可带 `last_handshake_at`，§14.1） |
| POST | `/api/v1/agent/device/applied` | 回报当前修订和实际设备计划哈希；旧回执/哈希不符拒绝，错误与成功分别记录 |
| GET | `/api/v1/agent/device/desired` | 本设备的期望数据面计划（Bearer agent_token；**结构化配置对象**：隧道/路由/NAT + `desired_config_hash`，**绝无 Shell 命令**，§16.4；`private_key` 恒为 `null`，ADR-010；服务端 `[dataplane] enabled = false` → `503 dataplane_not_configured`，agent 重试而非把「未配置」当「已生效」） |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/revoke` | 撤销设备（完整链路，§11.5）🔒 |
| GET/POST | `/api/v1/networks/{network_id}/routes` | LAN Route 列表 / 创建（含返回路径模式，ADR-005）；与 overlay/既有路由重叠 → `409 conflict` 且**消息点名冲突对端**（既有路由 id + 网段），拒绝发生在任何状态变更前——既有路由绝不被覆盖，客户端应提示改用 Alias 等长前缀映射（§8.3 不静默）。**例外（ADR-006 旗舰场景）**：新路由与既有路由**均为 Alias 模式**时允许真实前缀重叠——两个站点各有一个 `192.168.1.0/24`，经各自不同 Alias 前缀区分可达；对外可见的转发前缀是 Alias（唯一性由 Alias 创建时的互叠拒绝保证），真实前缀不进隧道转发表面 🔒 |
| GET/DELETE | `/api/v1/networks/{network_id}/routes/{route_id}` | 详情 / 删除（无更新路径——修改 = 删除后重建，各记一个修订）🔒 |
| GET/POST | `/api/v1/networks/{network_id}/aliases` | Alias 列表 / 创建（等长前缀校验，ADR-006；**已实现**）：绑定本网络 `alias` 模式路由（每路由一映射）、网关须 Active；`target_cidr` 服务端由绑定路由推导、**客户端不可指定**；前缀不等长或与 target 相同 → `400`；Alias 前缀与 overlay / 既有 Alias / 既有路由目的网段重叠 → `409 conflict` 且**消息点名对端**（计入路由冲突指标，§17.2）；拒绝发生在任何状态变更前。**协议边界**：只覆盖 IP 单播路由层——广播/组播/二层发现（ARP/NDP、mDNS、DHCP 广播域）不跨 Alias 透传，协议负载内嵌 IP 的应用可能失效（§9.6，详见 [ADR-006](../decisions/adr-006-alias-prefix-nat.md)）；内核侧 NAT 执行随数据面（ADR-007），未接线时修订 apply 确定性失败可见（§10.3）🔒 |
| GET/DELETE | `/api/v1/networks/{network_id}/aliases/{alias_id}` | 详情 / 删除（**已实现**）：删除 = **整单元清理**（§12.6）——映射与其绑定路由同删、记录**一个**修订；内核侧 NAT 规则移除随该修订 apply 交 backend；反向同理：删除绑定路由级联删除 Alias；无更新路径——修改 = 删除后重建（各记一个修订）🔒 |
| GET/POST | `/api/v1/networks/{network_id}/segments` | Segment 列表 / 创建（ADR-012 控制面；**已实现**）：默认段由建网事务固定且不可改；新段名唯一，CIDR 必须是 overlay 的严格子段且不与已有精确 CIDR 重复；越界、整 overlay、重名或重复 CIDR 均在状态变更前拒绝 🔒 |
| GET/POST | `/api/v1/networks/{network_id}/segment-grants` | 单向 SegmentGrant 列表 / 创建：源、目标须同网且不同；新建恒为 `pending`；未知段为 `404`，重复活动方向为 `409`；仅 `applied` 授权参与计划可见性与期望哈希 🔒 |
| POST | `/api/v1/networks/{network_id}/segment-grants/{segment_grant_id}/apply` | 仅把 `pending` 授权改为 `applied` 并记录修订：这是**期望状态跃迁**，不是网络级 revision apply；响应 `apply_status` 表示外层修订状态，仍可为 `pending` 🔒 |
| DELETE | `/api/v1/networks/{network_id}/segment-grants/{segment_grant_id}` | 撤销 `pending` 或 `applied` 授权：写入 `revoked_at` 并记录修订；撤销后不进入期望哈希，重复撤销 `409` 🔒 |
| GET/POST | `/api/v1/networks/{network_id}/host-forwards` | 单主机全端口转发列表 / 创建（**已实现**）：服务端把 `target_ipv4`/`alias_ipv4` 固定为等长 `/32`，原子创建 alias 模式 LAN Route + Alias（一个修订）；所有 IPv4 协议/端口随既有 NETMAP 路径转发，**不提供逐端口防火墙规则**；target/Alias 与 overlay、既有 Route 或 Alias 重叠 → `409 conflict` 且拒绝零变更；网关须本网络 Active 🔒 |
| DELETE | `/api/v1/networks/{network_id}/host-forwards/{alias_id}` | 删除单主机转发（**已实现**）：alias 与绑定 `/32` route 按所有权单元同删，记录一个修订；无更新路径——修改 = 删除后重建 🔒 |
| GET | `/api/v1/system/status` | 服务端状态（公开） |
| GET/POST | `/api/v1/networks/{network_id}/diagnostics` | 诊断结果 / 触发诊断（§12.7 十三项检查）🔒 |
| GET | `/api/v1/networks/{network_id}/config-revisions` | 配置版本列表 🔒 |
| GET | `/api/v1/networks/{network_id}/config-revisions/{revision}` | 版本详情（含 apply_status）🔒 |
| POST | `/api/v1/networks/{network_id}/config-revisions/{revision}/apply` | 应用指定版本到实际环境（响应即该版本视图）🔒 |
| POST | `/api/v1/networks/{network_id}/config-revisions/{revision}/rollback` | 回滚失败版本（仅删除/恢复 Meshlet 自有对象，ADR-007；只允许回滚当前修订，被取代者 409，§10.4）🔒 |
| GET | `/api/v1/audit` | 审计事件列表（§16.5：敏感操作全记录，秘密材料不入表）🔒 |
| GET | `/api/v1/system/metrics` | 运行指标（§17.2 八项，Prometheus 文本格式）🔒 |
| POST | `/api/v1/system/backup` | 一致性本地备份（SQLite 在线备份语义；只写 `[backup] dir`，不覆盖既有文件 → 409；目录未配置 → 503 `backup_not_configured`；响应含备份文件内容摘要）🔒 |

- 撤销设备语义（§11.5，已实现）：`POST .../devices/{device_id}/revoke`
  返回 `202` + `RevisionRef`（新修订号）；设备状态转 `revoked`（列表可见），
  该设备的 agent 凭证**立即失效**，且**其已发布的全部 LAN Route 一并移除**
  （不给 AllowedIPs 推导留下指向已撤销 Peer 的网段）；重复撤销 → `409 conflict`。

## 设备自举注册（ZeroTier 式，已实现）

邀请制的补充入口：管理员先开**自举码**（长期、可撤销、可选使用次数上限），
新设备持码自注册 → 落 **Pending 待审批** → 控制中心批准或拒绝。

- **自举码**（`bootstrap_tokens` 表，migration 008）与邀请/会话同一纪律：
  只存 SHA-256 摘要，原始码仅在签发响应里出现**一次**；列表绝无凭据材料；
  撤销立即生效（设备出示无效/撤销/耗尽的码 → `401 unauthorized`，
  管理侧对未知 id 操作 → `404 not_found`——两条错误面分离）；
  `used_count` 只在**校验通过后**递增，无效输入（400）不消耗次数。
- **Pending 不进 `devices` 表**（migration 008 取舍）：批准前不分配虚拟 IP、
  不进期望配置哈希、不出现在设备列表——待审批队列是唯一可视面
  （`GET .../registrations`）。设备名唯一性跨 `devices` + `device_registrations`
  两侧（重名 → `409 conflict`），拒绝后名字立即可复用。
- **Pending 期心跳**：agent 持注册即签发的 agent 凭证正常心跳，
  证据（`last_report_at` / `dataplane_evidence`）落注册申请行而非设备行，
  心跳回执 `online_state = "pending"` 明示状态；
  `desired` 端点对 Pending 设备 `404` 且消息点名 `pending approval`
  ——**身份判定先于全局数据面开关**（`503 dataplane_not_configured`
  不得掩盖 pending 信号），agent 退避重试，批准后本端点即返回计划。
- **批准** = 此刻才发生状态变更：分配虚拟 IP（IPAM）、设备入册
  （`devices` 表，`approved_at` 记审批时刻）、记录**一个**修订（§10.1）；
  **凭证不轮换**——注册期签发的 agent 凭证原样沿用（设备 id 不变，
  批准动作对设备透明，审批者无需传递任何秘密）。
- **拒绝** = 纯状态清理：注册申请删除、agent 凭证一并作废（`401`）、
  不记修订（期望配置从未包含过 Pending 申请）。
- 审计事件：`bootstrap_token.created` / `bootstrap_token.revoked` /
  `device.registered`（actor 为空——设备自举） / `device.approved` / `device.denied`。
- Agent 侧流程见 [安装指南](../guide/install.md)：`bootstrap_token` + `device_name`
  + `private_key_file` 三项配置即可开机自举，密钥对本机生成（§11.2），
  私钥不出设备。

## 设备数据面计划（`GET /api/v1/agent/device/desired`，已实现）

agent 只消费**类型化配置对象**（§16.4）：服务端不向 agent 下发任何 Shell 命令，
agent 也绝不执行下发的脚本。响应 `DevicePlan`（serde 形状见
[openapi.yaml](/api/openapi.yaml)）：

- `tunnel`：本设备虚拟 IP + **到 hub 的单一 peer**；AllowedIPs = Overlay +
  **他人**已发布的 LAN/Alias 前缀（自己发布的本地网段不回灌，避免环路，§7.2），
  推导复用域层唯一入口 `peer_routes::client_hub_peer_allowed_ips`；
- `routes`：他人网关发布的 LAN（`direct` → 真实目的段）或 Alias 前缀
  （`alias` → 绑定映射的 alias 前段），经该网关设备虚拟 IP；
- `nat_rules`：**本设备作为网关**时按 Alias 映射渲染的规则（DNAT NETMAP +
  受控 SNAT），每条带所有权注释 `meshlet alias {id}`（§12.6）——映射删除即整单元清理；
- `desired_config_hash`：与修订簿记同一来源（§10.1「有变更才重放」）；
- `tunnel.private_key` 恒为 `null`（ADR-010：私钥不出设备，agent 本地注入）；
  hub 公钥由服务端在请求时从 `[dataplane] private_key_file` 现算（`wg pubkey`，
  不落库、不出站）。

**期望项状态 = 已下发内核**：路由/Alias 映射的 `status` 在 apply/rollback 结论
处收敛（`service::settle_desired_state`）——只有真下发到内核的前缀才转 `applied`，
其余转 `failed`。因此「已记录但未应用」的期望配置不进计划（失败可见，不假装生效），
失败或回滚后计划随之撤下这些前缀。

失败语义：`503 dataplane_not_configured`（服务端数据面未开启，agent 退避重试）、
`401`（凭证无效/已撤销）、`404`（设备不在册）、`500`（hub 私钥文件缺失或
`wg pubkey` 失败——明确报错，不返回空计划）。

## 备份与恢复（§17.4，已实现）

- **备份 ≠ 同步**：只写本地 `[backup] dir`，无任何外发/云上传/遥测；
  默认不自动备份（`auto` 默认 `false`，开自动备份必须显式配置位）；
  目录未配置时 `POST /api/v1/system/backup` 返回 `503 backup_not_configured`。
- **一致性备份**：SQLite 在线备份语义（`VACUUM INTO`）——单一自洽快照，
  备份文件可独立打开、表结构（14 表）与迁移（001–006）完整；目标文件已存在
  拒绝（`409 conflict`），既有备份绝不被静默覆盖；落盘权限 `0600`；写后独立
  只读复验（`quick_check` + 必需表齐全），响应摘要来自备份文件本体读取。
- **审计**：备份 `system.backup`（端点触发 actor = 操作者，定时任务 actor 为空）；
  恢复 `system.restore`（actor 为空，detail 记源路径与内容摘要）。
- **恢复是离线操作**：`meshlet-server restore <backup.db> [config.toml]`
  （先停服务）——校验备份（损坏/缺表明确拒绝并点名缺失表）→ 拒绝未合并 WAL
  （非空 `-wal` 旁挂即拒，防静默丢已提交事务）→ 活动库占用检查 →
  拷贝复验后原子换名（任何失败都不触碰活动库，不留半恢复状态）→ 审计留痕 →
  按 §17.3 语义收敛（`applying`→`failed`、`rollback_pending` 保留、`applied`
  不重放），与正常启动完全一致，不比启动更弱。
- 运维细节见 [备份与恢复](backup-restore.md)。

## 网络诊断（§12.7，已实现）

- `GET/POST /api/v1/networks/{network_id}/diagnostics`（🔒）：13 项检查按故障层
  归类（控制面 / 隧道 / 路由 / 转发 / Alias）；第一版**只诊断不修复**。
- **快照语义**：`POST` 计算 → 落一行快照（migration 006 `diagnostics_runs`）→
  返回报告并记审计 `diagnostics.run`；`GET` 返回**最近一次**运行的同一份 JSON
  （不现算）；从未运行 → `404 not_found`（消息点名 POST 触发方式）——
  「没有结果」不等于「结果都好」。
- **状态词表**（封闭）：`pass` / `fail` / `warning` / `unavailable` / `not_applicable`。
  - `unavailable` = 控制面**观测不到**（WireGuard 接口、内核路由、IP forwarding、
    防火墙、NAT 规则五项恒如此：本机状态需本地特权读数）——**不是 pass**，
    `suggestion` 给出目标机器上可执行的检查命令；
  - `not_applicable` = 本网络没有该检查的对象（无设备/无路由/无 Alias/无修订），
    如实区分于 `pass`；
  - 每个 `fail`/`warning`/`unavailable` 都带可执行 `suggestion`。
- **判读纪律**（§17.2 / §12.4）：③`server_peer_configured` 的 detail 必须点名
  「registration only」——控制面在册 ≠ 隧道正常，隧道层唯一证据是 ④ 的握手新鲜
  （`handshake_window`，默认 120s）；⑨`lan_route_published` 的 pass 只表示
  控制面口径（路由已记录 + 最新修订已应用），不证明网关内核装了路由；
  ⑩用域层冲突检测（overlay 重叠 / alias 互叠 / 绑定路由不一致，ADR-006）；
  ⑬`mtu_planned` 只报 server 配置的计划值（§7.5）：显式配置 `pass`，未配置
  `warning`（默认 1420 + `ping -M do -s 1392` 实测建议），不假装观测实际接口/路径 MTU。
- 语义文档见 [网络诊断](diagnostics.md)。

## 认证与 CSRF（已实现）

- 🔒 管理端点要求 Cookie 会话：`meshlet_session`（HttpOnly、SameSite=Strict、
  Path=/api/v1、Max-Age=12h；生产在 HTTPS 反代后由 `cookie_secure = true` 加 `Secure`）；
  无效/缺失会话 → `401 unauthorized`；
- 🔒 管理端「写」请求（POST/PUT/PATCH/DELETE）必须携带
  `X-Requested-With: XMLHttpRequest` 请求头，否则 `403 forbidden`（CSRF 双重防线，
  Console 前端约定）；
- 登录失败统一 `401`（不区分用户不存在/密码错误，含恒时校验）；
  超限 `429 too_many_requests`（每 email 15 分钟 5 次失败，成功登录清零）；
- 密码 Argon2id 哈希存储（32 MiB/2 轮/4 并行）；**无默认管理员密码**，
  首个管理员仅经空库 `POST /api/v1/auth/bootstrap` 创建；
- `/api/v1/enroll`（邀请 Token 即凭证）、`/api/v1/device-registrations`
  （自举码即凭证，§11.6）、`/api/v1/system/status` 与
  `/api/v1/agent/heartbeat` 与 `GET /api/v1/agent/device/desired`（Bearer
  `agent_token`）不属于管理 API；agent_token
  由加入/自举注册时签发、原始 Token 仅返回一次，服务端只存 SHA-256 摘要（`agent_tokens`
  表，migration 003）——agent 凭证与控制台会话是两条互不交叉的认证边界（§13.7）。

### API Token（外部机器凭据，已实现）

外部系统（如 cockpit）可长期调用管理 API，不必依赖浏览器会话：

- **签发**：已认证用户 `POST /api/v1/auth/tokens`（同样要求 CSRF 头），
  请求 `{"name": "cockpit", "scopes": "read" | "write"}`；响应 `201` 携带
  `{"id", "token", "name", "scopes", "created_at"}`——原始 Token
  （`mlt_` 前缀 + 64 hex）**仅此一次返回**，服务端只存 SHA-256 摘要
  （`api_tokens` 表，migration 004）；
- **调用**：`Authorization: Bearer mlt_…` 请求头。管理端点（🔒）接受
  Cookie 会话或 API Token；请求带会话 Cookie 时按会话校验（无效一律 401，
  不回退到 Bearer），无会话头时按 Bearer 校验；
- **最小权限**：`read` 可调所有读端点；`write` 可调读写端点并隐含 `read`。
  scope 不足的写请求 → `403 forbidden`；
- **CSRF 防线不削弱**：管理端「写」请求（含 Token 调用方）仍必须携带
  `X-Requested-With: XMLHttpRequest`，否则 `403 forbidden`——与 Cookie 会话
  完全同一防线（Bearer 本不可被浏览器跨站伪造，此处为语义统一与纵深防御）；
- **可撤销 + 审计归属**：Token 归属创建者（`user_id`），`last_used_at`
  节流记录使用时刻（60s 内不重复写）；`DELETE /api/v1/auth/tokens/{token_id}`
  撤销后立即失效（`401`），撤销后的 Token 仍留在列表中并带 `revoked_at`；
  列表/撤销仅限属主，未知或不属于自己的 id → `404 not_found`；
- **边界分离**：API Token 只对管理 API 有效；`/api/v1/agent/heartbeat` 与
  `GET /api/v1/agent/device/desired` 仍只认 agent_token，反之 agent_token 也过不了
  管理 API 认证（§13.7）。

## 在线状态判定（已实现）

设备列表每个设备携带 `online_state` / `presence_source` / `last_seen_at`——
**状态必须标注数据来源与更新时间**（§12.2），不允许只给一个绿色「在线」图标：

| `online_state` | 判定条件 | `presence_source` |
|---|---|---|
| `online` | agent 上报在窗口内（默认 5 分钟） | `agent_report` |
| `tunnel_only` | 仅握手在窗口内（默认 2 分钟） | `handshake` |
| `offline` | 无任何新鲜证据 | 最新一条证据的来源：`handshake` / `agent_report` / `enrollment` / `none` |

- **握手新鲜 ≠ 在线**（§12.4）：WireGuard latest-handshake 只证明隧道连通，
  不能等同于设备全部网络功能正常，因此单独握手证据只给 `tunnel_only`；
- 判定输入是三类证据时间戳（`devices.last_handshake_at` /
  `last_report_at` / 加入时刻），纯函数实现于 `meshlet-domain/src/presence.rs`
  （窗口与判定时刻可注入，确定性单测）；
- 握手时间由 agent 从本地 `wg show` 读取后随心跳上报（§14.1），不需要
  WireGuard 内核集成即可采集；
- 窗口可配置：`presence_agent_window_secs`（默认 300）/
  `presence_handshake_window_secs`（默认 120）；
- 证据时间戳随心跳写入 SQLite（`devices.last_handshake_at` /
  `last_report_at`，migration 003），重启后按保守判定恢复——无新鲜证据
  不虚构 `online`（§17.3，`recovery.rs::presence_is_conservative_after_restart`）。

## 配置版本与应用状态（已实现）

「数据库写入成功 ≠ WireGuard/路由/NAT 已生效」（§10.1）：期望配置的每次变更
（建网络、设备加入等）只生成新的配置修订，初始状态 `pending`；只有把配置
应用到实际网络环境成功后才是 `applied`。控制台与外部调用方以 `apply_status`
为准，不以 DB 写入为准。

| `apply_status` | 含义 | `applied_at` | `error_summary` |
|---|---|---|---|
| `pending` | 已记录期望配置，尚未应用 | `null` | `null` |
| `applying` | 应用进行中（同步 API 内短暂出现） | `null` | `null` |
| `applied` | 已生效 | 应用时刻 | `null` |
| `failed` | 应用失败，含**结果不确定**（§10.3：不确定时进入明确失败态，不假装成功） | `null` | 失败诊断 |
| `rollback_pending` | 回滚发起但未能确认 | `null` | 应用失败 + 回滚失败诊断 |
| `rolled_back` | 已回滚（当前期望回落至更早版本） | `null` | 原失败诊断 |

- **失败可见**：apply 失败返回 `200` + 该修订视图（`apply_status: "failed"`
  与 `error_summary`），错误同时在版本详情与列表中可见；命令本身不吞失败；
- **幂等**：对已 `applied` 的版本重复 apply 直接返回该版本视图，**不再调用
  backend**（重复执行不破坏网络，§10.3）；
- **并发顺序（§10.4）**：修订号在同一网络内单调递增，配置修改由「先记录修订、
  再应用修订」串行化；对 `failed` 版本原地重试返回 `409 conflict`
  ——重试路径是记录新修订（版本号递增）；
- **回滚**只针对 `failed` 版本，且只删除/恢复 Meshlet 自有对象，
  **不得清空系统路由**（ADR-007、§10.3）；已生效版本的撤销走前滚新版本；
- 状态机与哈希实现于 `meshlet-domain/src/config_state.rs`（`ConfigLedger` /
  `ConfigApplyBackend` / `desired_config_hash`（覆盖 overlay/hub/Active 设备/LAN 路由，标签 `meshlet-desired-v2`），纯函数 + 22 项单测，含 `restore`/`interrupt_applying` 重启恢复路径）；
  SQLite `config_revisions` 表字段与之逐列对齐（migration 001），
  写路径已接线：期望状态每次变更（网络/设备/路由/邀请/修订）在内存变更后
  同步落库（`persist` 模块，§17.3）；停机重启后从 DB 重建 `MeshState`
  （IPAM 已分配集合、路由 id 序列、修订序列与 apply 状态逐字段恢复），
  停在 `applying` 的修订启动时按 §10.3 收敛为 `failed`（error_summary
  点名进程中断），`rollback_pending` 原样保留可重试。



## 已核验的最小实现

`apps/server` 已实现：`GET /api/v1/system/status`、`GET/POST /api/v1/networks`、`POST /api/v1/networks/{id}/invites`、`DELETE /api/v1/networks/{id}/invites/{invite_id}`、`GET/POST /api/v1/networks/{id}/bootstrap-tokens`、`DELETE /api/v1/networks/{id}/bootstrap-tokens/{token_id}`、`GET /api/v1/networks/{id}/devices`、`POST /api/v1/enroll`、`POST /api/v1/device-registrations`、`GET /api/v1/networks/{id}/registrations`、`POST /api/v1/networks/{id}/devices/{device_id}/approve`、`POST /api/v1/networks/{id}/devices/{device_id}/deny`、`POST /api/v1/auth/bootstrap`、`POST /api/v1/auth/login`、`POST /api/v1/auth/logout`、`GET /api/v1/auth/me`、`GET/POST /api/v1/auth/tokens`、`DELETE /api/v1/auth/tokens/{token_id}`、`POST /api/v1/agent/heartbeat`、`GET /api/v1/agent/device/desired`、`GET/POST /api/v1/networks/{id}/routes`、`GET/DELETE /api/v1/networks/{id}/routes/{route_id}`、`POST /api/v1/networks/{id}/devices/{device_id}/revoke`、`GET /api/v1/audit`、`GET /api/v1/networks/{id}/config-revisions`、`GET/POST /api/v1/networks/{id}/config-revisions/{revision}`、`POST /api/v1/networks/{id}/config-revisions/{revision}/apply`、`POST /api/v1/networks/{id}/config-revisions/{revision}/rollback`、`GET /api/v1/system/metrics`、`POST /api/v1/system/backup`（§17.4）；管理端点已挂会话/Token 认证 + CSRF 提取器（写端点另挂 `WriteUser` scope 检查），agent 端点挂 Bearer 提取器；全部 `/api` 路由另挂访问日志中间件（结构化日志 + HTTP 指标）。测试见 `apps/server/tests/{status,enroll,auth_console,api_token,migrations,presence,revisions,routes,aliases,agent_plan,device_revoke,device_registration,audit,observability,recovery,backup}.rs`。控制平面 Mesh 状态（网络/设备/路由/邀请/自举码/注册申请/配置修订簿记）持久化 SQLite 并在启动时重建（migrations 001/002/003/004/005/008 + `persist` 模块，§17.3：重启后逐字段一致、`applying` 收敛 `failed`、路由 id 不复用、presence 保守判定）；用户/会话/agent/API Token 凭证持久化 SQLite（migrations 001/002/003/004）；审计事件持久化 SQLite（`audit_events`，migration 001，§16.5：敏感操作全记录、秘密材料不入表）。运行指标（§17.2 八项，Prometheus 文本格式，`GET /api/v1/system/metrics`）与结构化日志（§17.1 八字段，JSON 行）见 [可观测性](observability.md)。

## 2026-10-17 应用确认与恢复

`ConfigRevision.apply_status` 描述 hub 执行结果。当前版本的 `convergence` 独立报告设备收敛状态、等待设备、设备错误、hub 恢复错误和业务健康。`business_health=not_probed` 表示未进行业务探测。

设备计划携带 `desired_revision`、网络独立 `hub_port` 和设备专属 `desired_config_hash`。设备哈希包含实际隧道、MTU、公钥与 NAT 等完整计划，区别于网络修订簿记哈希。hub 未应用当前版本时，计划端点返回 503；hub 成功后下发候选计划，不以资源 Pending 状态过滤所需配置，避免等待 ACK 的循环依赖。设备读回确认后调用 `/agent/device/applied`，仅当前版本且哈希一致的回执可更新状态。全部相关 Active 设备确认后，路由与 Alias 才转 Applied。

旧 Pending/Applied 修订的 apply 请求返回 409，未知修订仍为 404。失败应用的回滚恢复上次成功计划，随后重新等待设备回执。
