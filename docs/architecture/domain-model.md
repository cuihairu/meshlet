# 领域模型

> 来源：[存档 §5](../review/chatgpt-2026-10-13.md#_5-核心领域模型) + [ADR-004](../decisions/adr-004-overlay-ipam.md)、[ADR-006](../decisions/adr-006-alias-prefix-nat.md)、[ADR-009](../decisions/adr-009-config-revision-rollback.md)。本文为设计稿；实现以 `crates/meshlet-domain` 代码与测试为准，冲突时回到 [ADR](../decisions/index.md) 修订。

## 实体关系

```mermaid
erDiagram
    USER ||--o{ NETWORK_MEMBERSHIP : joins
    NETWORK ||--o{ NETWORK_MEMBERSHIP : contains
    NETWORK ||--o{ DEVICE : contains
    DEVICE ||--o{ DEVICE_KEY : owns
    NETWORK ||--o{ LAN_ROUTE : publishes
    DEVICE ||--o{ LAN_ROUTE : "gateway of"
    LAN_ROUTE ||--o| ALIAS_MAPPING : has
    NETWORK ||--o{ CONFIG_REVISION : produces
    DEVICE ||--o{ DEVICE_STATUS : reports
    USER ||--o{ AUDIT_EVENT : performs
```

## User（控制台用户）

| 字段 | 说明 |
|---|---|
| `id` | 标识 |
| `email` / 登录标识 | 本地管理员账号（ADR-010） |
| `password_hash` | Argon2id；不存明文 |
| `status` / `created_at` / `updated_at` | 状态与时间戳 |

第一版本地管理员即可；数据模型从一开始区分 Network 归属（§12.1）。

## Network（私人虚拟网络）

| 字段 | 说明 |
|---|---|
| `id` / `name` | 标识与名称 |
| `overlay_ipv4_cidr` | 创建时选定，**默认 `10.240.0.0/16`，创建后不可变**（ADR-004） |
| `status` / `created_at` / `updated_at` | 状态与时间戳 |

约束：不同 Network 默认隔离；设备不能因知道其他网络的虚拟 IP 获得访问权；CIDR 修改必须走冲突检查+迁移（第一版不提供）。

## Device（设备）

| 字段 | 说明 |
|---|---|
| `id` / `network_id` / `name` | 标识与归属 |
| `virtual_ipv4` | 网络内唯一；hub 保留地址不可分配（ADR-004） |
| `public_key` | 绑定设备身份；密钥与 Device 记录分离（DeviceKey） |
| `platform` / `status` / `last_seen_at` | 平台、在线状态（握手+心跳+上报综合判定，§12.4） |
| `created_at` / `revoked_at` | 创建与撤销时间 |

约束：撤销后服务端必须移除其有效 Peer 与授权；离线状态不能只看数据库旧值。

## DeviceKey（设备密钥）

公钥、密钥版本/指纹、创建/撤销时间、是否生效。**服务端不要求也不保存长期私钥**（ADR-010）。

## LAN Route（发布的真实局域网网段）

| 字段 | 说明 |
|---|---|
| `id` / `network_id` / `gateway_device_id` | 网段由哪个设备负责转发 |
| `destination_cidr` | 真实 LAN 网段 |
| `route_mode` | `direct`（普通路由）/ `alias`（经虚拟前缀） |
| `status` / `created_at` | 期望态 ≠ 已应用态 |

约束：同一网络内互相冲突的路由不能静默接受；返回路径模式（ADR-005）在此记录并显示。

## Alias Mapping（重叠网段虚拟前缀映射）

| 字段 | 说明 |
|---|---|
| `id` / `network_id` / `lan_route_id` | 绑定的 LAN Route |
| `alias_cidr` / `target_cidr` | **前缀长度必须相等**（ADR-006） |
| `translation_mode` / `status` | NAT 模式与应用状态 |

约束：删除 Alias 必须同步清理路由与 NAT 规则；转换前六项检查（§9.2）。

## Config Revision（配置版本）

| 字段 | 说明 |
|---|---|
| `id` / `network_id` / `revision` | network 内单调递增 |
| `desired_config_hash` | 期望态哈希，幂等与重启恢复依据（ADR-009） |
| `apply_status` | `pending` / `applying` / `applied` / `failed` / `rollback_pending` / `rolled_back` |
| `created_at` / `applied_at` / `error_summary` | 时间与失败信息 |

状态机（合法跃迁）：

```text
pending → applying → applied
                └──→ failed → rollback_pending → rolled_back
```

红线：控制台不得把数据库写入成功当作网络配置已生效。

## Peer AllowedIPs 推导（§7.2）

实现：`crates/meshlet-domain/src/peer_routes.rs`（纯函数 + 单测）。

原则：AllowedIPs 与目标路由一致，**不得全量指隧道**。第一版默认只路由三类网段：

| 视角 | AllowedIPs |
|---|---|
| VPS 侧某设备 Peer | 本机 Overlay `/32` + 该设备已发布（`Applied`）的 LAN 目标网段 + 对应 Alias 网段 |
| 客户端 → VPS Peer | 整个 Overlay + **其他**设备已发布的 LAN + Alias（自己发布的本地网段不回灌隧道，避免环路） |

约束：

- 只有 `Applied` 状态的 LAN Route / Alias Mapping 进 AllowedIPs；`Pending` / `Failed` 不进。
- Alias 只有在对应 LAN Route 已发布时才进。
- 设备虚拟 IP 必须在 Overlay 内（`PeerRouteError::DeviceOutsideOverlay`）。
- 结果去重 + 确定性排序（网络地址、前缀长度）。
- VPS 为每个设备创建独立 Peer（`hub_device_peers`）。

