# API 契约（初稿）

> 来源：[存档 §13](../review/chatgpt-2026-10-13.md#_13-api-设计)。机器可读版本：[openapi.yaml](/api/openapi.yaml)（OpenAPI 3.1）。初稿待评审；实现以本文件 + openapi.yaml 为契约，代码生成或类型同步（§4.2）。

## 约定

- 所有 API 使用版本前缀 `/api/v1`；JSON 请求与响应；统一错误响应结构（见下）；
- 输入验证在服务端执行；有副作用的操作记录审计事件（ADR-010）；
- 列表接口分页（`limit`/`offset`，响应带 `total`）；
- 可区分的错误码：`conflict` / `unauthorized` / `forbidden` / `not_found` / `validation_failed` / `apply_failed`；
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
| POST | `/api/v1/auth/login` | 登录（限流，ADR-010） |
| POST | `/api/v1/auth/logout` | 登出 |
| GET | `/api/v1/auth/me` | 当前用户 |
| GET/POST | `/api/v1/networks` | 网络列表 / 创建（CIDR 验证，ADR-004） |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}` | 网络详情 / 更新 / 删除 |
| GET | `/api/v1/networks/{network_id}/devices` | 设备列表 |
| POST | `/api/v1/networks/{network_id}/invites` | 生成一次性邀请（ADR-010） |
| DELETE | `/api/v1/networks/{network_id}/invites/{invite_id}` | 撤销邀请（ADR-010） |
| POST | `/api/v1/enroll` | 设备加入（邀请 Token + 公钥；私钥不出客户端，§11.2） |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/devices/{device_id}` | 设备详情 / 更新 / 删除 |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/rotate-key` | 密钥轮换 |
| POST | `/api/v1/networks/{network_id}/devices/{device_id}/revoke` | 撤销设备（完整链路，§11.5） |
| GET/POST | `/api/v1/networks/{network_id}/routes` | LAN Route 列表 / 创建（含返回路径模式，ADR-005） |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/routes/{route_id}` | 详情 / 更新 / 删除 |
| GET/POST | `/api/v1/networks/{network_id}/aliases` | Alias 列表 / 创建（等长前缀校验，ADR-006） |
| GET/PATCH/DELETE | `/api/v1/networks/{network_id}/aliases/{alias_id}` | 详情 / 更新 / 删除（删除同步清理 NAT） |
| GET | `/api/v1/system/status` | 服务端状态（本仓 `apps/server` 已有最小实现） |
| GET | `/api/v1/networks/{network_id}/status` | 网络状态 |
| GET/POST | `/api/v1/networks/{network_id}/diagnostics` | 诊断结果 / 触发诊断（§12.7 十二项检查） |
| GET | `/api/v1/networks/{network_id}/config-revisions` | 配置版本列表 |
| GET | `/api/v1/networks/{network_id}/config-revisions/{revision}` | 版本详情（含 apply_status） |

## 已核验的最小实现

`apps/server` 已实现：`GET /api/v1/system/status`、`GET/POST /api/v1/networks`、`POST /api/v1/networks/{id}/invites`、`DELETE /api/v1/networks/{id}/invites/{invite_id}`、`GET /api/v1/networks/{id}/devices`、`POST /api/v1/enroll`；测试见 `apps/server/tests/{status,enroll}.rs`。控制平面状态当前存于内存（`MeshState`），持久化（SQLx/SQLite）随「核心实体 migrations」条目接入。认证/控制台端点（`/api/v1/auth/*`）随 Phase 2 落地。
