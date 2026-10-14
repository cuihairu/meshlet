# 外部调用方指南

> 面向把 meshlet 控制面并入自身系统的调用方（如 cockpit）。本文回答四个问题：
> 认证怎么做、有哪些控制端点、统一错误响应怎么读、**哪些操作会影响数据面**。
> 机器可读契约见 [openapi.yaml](/api/openapi.yaml)；端点逐条对照见
> [API 契约](/architecture/api-contract)。

## 1. 认证

三条**互不相通**的认证边界（ADR-010）：

| | Console 会话（浏览器） | API Token（外部机器） | Agent Token（设备） |
|---|---|---|---|
| 形态 | `meshlet_session` Cookie | `Authorization: Bearer mlt_…` | `Authorization: Bearer <agent_token>` |
| 适用 | 控制台页面 | 外部系统长期调用 | 仅 `POST /api/v1/agent/heartbeat` |
| 落库材料 | 仅摘要 | 仅 SHA-256 摘要（migration 004） | 仅 SHA-256 摘要（migration 003） |
| 互相替代 | **否**：带 Cookie 的请求按会话校验，无效一律 401，**不回退**到 Bearer | 否 | 否 |

- **签发**：已认证用户 `POST /api/v1/auth/tokens`，请求 `{"name","scopes"}`，
  `scopes` ∈ `read` | `write`（write 隐含 read）。响应 201 携带
  `{"id","token","name","scopes","created_at"}`——原始 Token（`mlt_` + 64 hex）
  **仅此一次返回**，服务端只存摘要。
- **调用**：所有管理端点（🔒）接受 Cookie 会话或 Bearer Token。
- **撤销**：`DELETE /api/v1/auth/tokens/{token_id}` → 204，**立即失效**（再使用
  401）。仅属主可撤；未知或不属于自己的 id 一律 404（不泄露存在性）。
- **CSRF 头统一要求**：管理端「写」请求（POST/PATCH/DELETE）**包括 Token
  调用方**都必须带 `X-Requested-With: XMLHttpRequest`，否则 403。Bearer 本身
  不可被浏览器跨站伪造，此要求是语义统一与纵深防御，**不因认证方式放宽**。
- 会话 12h（`Max-Age`），`HttpOnly`、`SameSite=Strict`、`Path=/api/v1`；
  生产 HTTPS 反代后由 `cookie_secure = true` 加 `Secure`。
- 登录限流：每 email 15 分钟 5 次失败 → 429；成功登录清零。失败统一 401
  （不区分用户不存在/密码错误）。
- 公开端点：`GET /api/v1/system/status`、`POST /api/v1/enroll`。
- `POST /api/v1/auth/bootstrap` 仅空库可用：成功 201，已有用户 409。

## 2. 控制端点（当前已实现）

**读**

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/v1/system/status` | 服务端状态（公开） |
| GET | `/api/v1/networks` | 网络列表（含 `revision_id` / `apply_status`） |
| GET | `/api/v1/auth/me` | 当前用户 |
| GET | `/api/v1/auth/tokens` | 自己的 Token 列表（无任何 Token 材料） |
| GET | `/api/v1/networks/{id}/devices` | 设备列表（含 `online_state` / `presence_source` / `last_seen_at`） |
| GET | `/api/v1/networks/{id}/routes` | LAN 路由列表 |
| GET | `/api/v1/networks/{id}/routes/{route_id}` | 路由详情 |
| GET | `/api/v1/networks/{id}/config-revisions` | 配置版本列表 |
| GET | `/api/v1/networks/{id}/config-revisions/{n}` | 版本详情 |

**写**

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/auth/bootstrap` | 建首个管理员（空库 201） |
| POST | `/api/v1/auth/login` | 登录（限流见上） |
| POST | `/api/v1/auth/logout` | 登出（撤销会话） |
| POST | `/api/v1/auth/tokens` | 签发 API Token（201，原始 Token 仅此一次） |
| GET / DELETE | `/api/v1/auth/tokens[/{id}]` | 列表 / 撤销（204） |
| POST | `/api/v1/networks` | 建网络（CIDR 校验） |
| POST | `/api/v1/networks/{id}/invites` | 生成一次性邀请（201） |
| DELETE | `/api/v1/networks/{id}/invites/{invite_id}` | 撤销邀请（204） |
| POST | `/api/v1/enroll` | 设备加入（邀请 Token + 公钥；201，返回 `agent_token` + `revision_id`） |
| GET / POST | `/api/v1/networks/{id}/routes` | 路由列表 / 创建（201） |
| GET / DELETE | `/api/v1/networks/{id}/routes/{route_id}` | 详情 / 删除（204） |
| POST | `/api/v1/networks/{id}/devices/{device_id}/revoke` | 撤销设备（202 + `RevisionRef`） |
| POST | `/api/v1/networks/{id}/config-revisions/{n}/apply` | 应用配置（返回该版本视图） |
| POST | `/api/v1/networks/{id}/config-revisions/{n}/rollback` | 回滚失败版本 |
| POST | `/api/v1/agent/heartbeat` | Agent 心跳（仅 agent_token） |

**未实现（契约里列了、服务端没有，调用方不得依赖）**：网络/设备/路由/别名的
`PATCH` 更新、`rotate-key`、aliases、diagnostics、`GET /networks/{id}/status`。
设备**没有删除端点**——只能 `revoke`（状态 + 凭证失效 + 出期望配置）。

## 3. 统一错误响应怎么读

```json
{ "error": { "code": "conflict", "message": "...", "details": {} } }
```

| HTTP | code | 调用方动作 |
|---|---|---|
| 401 | `unauthorized` | 会话失效或 Bearer 无效 → 重新认证；Token 被撤销则重新签发 |
| 403 | `forbidden` | 两类原因：缺 CSRF 头；Token scope 不足（read Token 调写端点） |
| 404 | `not_found` | 资源不存在；Token 列表/撤销遇到未知 id 同码，勿据此探测存在性 |
| 400 | `validation_failed` | 入参校验失败（读 message） |
| 409 | `conflict` | 业务冲突：重复 bootstrap、重复撤销设备、非法修订跃迁（见 §4） |
| 429 | `too_many_requests` | 登录限流 → 退避后重试 |
| 500 | `internal` | 服务内部错误，可重试 |

**两个容易踩的读法**：

1. **apply 失败不是 HTTP 错误**：`POST .../config-revisions/{n}/apply` 在
   backend 失败时返回 **200** + 该版本视图，`apply_status: "failed"` 且
   `error_summary` 说明原因——命令不吞失败、不假装成功。判断生效要读状态码，
   不要只看 HTTP 2xx。
2. **先读 HTTP 状态判断「能不能重试」，再读 `code` 判断「谁的错」**，最后读
   `message`/`details` 做日志；不要靠字符串匹配 message——message 是给人看的。

## 4. 幂等性与并发控制语义

**没有 ETag / If-Match / 条件写**。同一网络的写操作需调用方自行串行化；
meshlet 提供的是**修订号**而非乐观锁。

- 每次配置变更 → 记录新修订（网络内单调递增）→ 响应携带 `revision_id` +
  `apply_status`。**DB 写入 ≠ 生效**：
  `pending` → `applying` → `applied` | `failed` →（回滚）`rollback_pending` →
  `rolled_back`。
- **apply 幂等**：对已 `applied` 的版本重复 apply 直接返回该版本视图，
  **不再调用 backend**（重复执行不破坏网络）。
- **failed 版本原地重试 → 409**（非法跃迁）；重试路径是记录**新修订**
  （版本号递增）。
- **并发顺序**：同网络配置修改由「先记录修订、再应用修订」串行化；修订号
  即顺序凭据——调用方看到更大的 `revision_id` = 更新的期望配置。
- **回滚只针对 `failed` 版本**，且只删除/恢复 Meshlet 自有对象，
  **不清空系统路由**（ADR-007）。
- **撤销设备返回 202 + `RevisionRef`**（不是 200/204）：它触发配置变更，
  返回的 `revision_id` 是新一轮期望配置的编号；重复撤销同一设备 → 409。

## 5. 哪些操作会影响数据面，哪些不会

**会影响数据面**（生成/改变期望配置修订，最终经 apply 落到 WireGuard/路由/NAT）：

| 操作 | 效果 |
|---|---|
| `POST /api/v1/networks` | 建网络（新 overlay） |
| `POST /api/v1/enroll`（经邀请） | 设备加入 → 新修订 |
| `POST` / `DELETE /networks/{id}/routes[/{route_id}]` | LAN 路由增删 → 新修订 |
| `POST /networks/{id}/devices/{device_id}/revoke` | 设备撤销 → 状态 revoked + agent 凭证**立即失效** + 新修订 |
| `POST /networks/{id}/config-revisions/{n}/apply` | 把期望配置应用到实际环境 |
| `POST /networks/{id}/config-revisions/{n}/rollback` | 回滚 failed 版本 |

**不影响数据面**：

| 操作 | 说明 |
|---|---|
| 全部 GET | 只读 |
| `POST` / `DELETE /api/v1/auth/tokens[/{id}]` | 只影响控制面认证（撤 Token 不改网络配置） |
| `POST` / `DELETE /networks/{id}/invites[/{invite_id}]` | 邀请是**未消费的凭证**：撤销未用邀请不产生修订；已消费邀请对应的设备需单独 revoke |
| `POST /auth/login` / `logout`、`GET /auth/me` | 会话生命周期 |
| `POST /api/v1/agent/heartbeat` | 只更新在线状态（presence），不进期望配置 |
| `GET /api/v1/system/status` | 公开只读 |

**判断依据**：期望配置的内容由 `desired_config_hash`（标签 `meshlet-desired-v2`）
界定 = overlay + hub 地址 + Active 设备 + 全部 LAN 路由（按 (目的网段, id)
排序）。上表「影响」的操作正是会改动这个哈希的操作；不落进哈希的变更
（heartbeat、邀请）不改变数据面。

## 6. 接入清单

1. 空库 `POST /auth/bootstrap` 建管理员 → `POST /auth/login` 拿会话；
2. 用会话 `POST /auth/tokens` 签 Token 给外部系统（只读集成签 `read`）；
3. 外部系统用 Bearer 调管理端点，**所有写请求带 CSRF 头**；
4. 写操作后读响应里的 `revision_id` / `apply_status`；需要确认生效时轮询
   `GET /config-revisions/{n}` 直到 `applied`（失败读 `error_summary`）；
5. 撤 Token：`DELETE /auth/tokens/{token_id}`（立即失效）。

## 关联

- [API 契约](/architecture/api-contract)（逐端点 + `openapi.yaml`）
- [ADR-010 认证与注册安全](/decisions/adr-010-console-auth-enrollment)
- [ADR-009 配置版本与回滚](/decisions/adr-009-config-revision-rollback)
- [性能方案与基准](/architecture/performance)（控制面吞吐与延迟）
