# API 契约（初稿）

> 来源：[存档 §13](../review/chatgpt-2026-10-13.md#_13-api-设计)。机器可读版本：[openapi.yaml](/api/openapi.yaml)（OpenAPI 3.1）。初稿待评审；实现以本文件 + openapi.yaml 为契约，代码生成或类型同步（§4.2）。

## 约定

- 所有 API 使用版本前缀 `/api/v1`；JSON 请求与响应；统一错误响应结构（见下）；
- 输入验证在服务端执行；有副作用的操作记录审计事件（ADR-010）；
- 列表接口分页（`limit`/`offset`，响应带 `total`）；
- 可区分的错误码：`conflict` / `unauthorized` / `forbidden` / `not_found` / `validation_failed` / `too_many_requests` / `apply_failed`；
- 配置修改类响应必须携带 `revision_id` 与 `apply_status`（ADR-009）；
- 敏感可重试操作提供幂等语义；
- **Agent API 与管理 API 认证边界清晰分离**（§13.7）。

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
| GET/POST | `/api/v1/networks` | 网络列表 / 创建（CIDR 验证，ADR-004）🔒 |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}` | 网络详情 / 更新 / 删除 🔒 |
| GET | `/api/v1/networks/{network_id}/devices` | 设备列表 🔒 |
| POST | `/api/v1/networks/{network_id}/invites` | 生成一次性邀请（ADR-010）🔒 |
| DELETE | `/api/v1/networks/{network_id}/invites/{invite_id}` | 撤销邀请（ADR-010）🔒 |
| POST | `/api/v1/enroll` | 设备加入（邀请 Token + 公钥；私钥不出客户端，§11.2） |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/devices/{device_id}` | 设备详情 / 更新 / 删除 🔒 |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/rotate-key` | 密钥轮换 🔒 |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/revoke` | 撤销设备（完整链路，§11.5）🔒 |
| GET/POST | `/api/v1/networks/{network_id}/routes` | LAN Route 列表 / 创建（含返回路径模式，ADR-005）🔒 |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/routes/{route_id}` | 详情 / 更新 / 删除 🔒 |
| GET/POST | `/api/v1/networks/{network_id}/aliases` | Alias 列表 / 创建（等长前缀校验，ADR-006）🔒 |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/aliases/{alias_id}` | 详情 / 更新 / 删除（删除同步清理 NAT）🔒 |
| GET | `/api/v1/system/status` | 服务端状态（公开） |
| GET | `/api/v1/networks/{network_id}/status` | 网络状态 🔒 |
| GET/POST | `/api/v1/networks/{network_id}/diagnostics` | 诊断结果 / 触发诊断（§12.7 十二项检查）🔒 |
| GET | `/api/v1/networks/{network_id}/config-revisions` | 配置版本列表 🔒 |
| GET | `/api/v1/networks/{network_id}/config-revisions/{revision}` | 版本详情（含 apply_status）🔒 |

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
- `/api/v1/enroll`（邀请 Token 即凭证）与 `/api/v1/system/status` 保持公开。

## 已核验的最小实现

`apps/server` 已实现：`GET /api/v1/system/status`、`GET/POST /api/v1/networks`、`POST /api/v1/networks/{id}/invites`、`DELETE /api/v1/networks/{id}/invites/{invite_id}`、`GET /api/v1/networks/{id}/devices`、`POST /api/v1/enroll`、`POST /api/v1/auth/bootstrap`、`POST /api/v1/auth/login`、`POST /api/v1/auth/logout`、`GET /api/v1/auth/me`；管理端点已挂会话认证 + CSRF 提取器。测试见 `apps/server/tests/{status,enroll,auth_console,migrations}.rs`。控制平面 Mesh 状态当前存于内存（`MeshState`）；用户/会话持久化 SQLite（migrations 001/002）。
