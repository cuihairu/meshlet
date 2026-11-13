# meshlet DNS 调研：要不要自己的 DNS？对标 ZeroTier

> 调研日期：2026-11-13。结论先行：**meshlet 已经有一个内置 DNS server（发布服务域名解析用），缺的不是"再建一个 DNS"，而是三件小事：成员设备名解析（node.name → 10.240.0.x）、客户端接入指引、以及把它挂到 hub 的 53/5353 端口。**

## 1. 现状盘点（代码实证）

### 已有：发布服务的 DNS server（crates/meshlet-publish/src/dns.rs，353 行）
- 完整 UDP DNS 应答器：`serve_udp(address)` 可绑任意端口
- `DnsCatalog`：insert/remove/resolve 内存记录表
- 记录来源：**已发布服务的域名**（device_plan.rs:72 把设备发布的服务 name→address 注册为 DnsRecord）
- 支持 A/CNAME、Internet/Chaos class、FQDN + internal_suffix

**即：服务发现 DNS（service.meshlet.internal → 服务地址）已经存在且可用。**

### 缺：节点名解析（member DNS）
- 现在访问对端设备只能用 10.240.0.x IP，没有 `imac.meshlet.internal` 这种名字
- ZeroTier 的做法（v2.2+）：控制中心为每个网络分配 DNS 搜索域（如 `networkname.zerotier`），成员设备名自动注册为该域下记录；客户端把该域加入系统 DNS 搜索列表，`ssh imac` 即解析到虚拟 IP
- ZeroTier 的实现要点：**DNS 数据来源就是网络成员表**（无独立数据库），server 端起一个权威 DNS 应答 A 记录，TTL 短（跟随成员变化）

## 2. meshlet 补齐节点 DNS 的成本评估（低）

ZeroTier 的 DNS 库本身没有独立开源库可直接引（其 DNS 是 One 客户端内嵌逻辑），但 meshlet **不需要引库**——`meshlet-publish/src/dns.rs` 的 DnsCatalog/serve_udp 已是现成的权威 DNS 内核，补节点解析只需：

1. **数据源**：把 network membership 表（devices: device_name → tunnel_address）灌入一个 `NodeCatalog`（仿 DnsCatalog，~50 行）
2. **挂载**：hub 的 server 进程在 53 或 5353 端口起第二个 `serve_udp`（端口可配）
3. **记录**：`<device_name>.m.internal` A 记录 → tunnel_address，TTL 30s（跟随成员增删/撤销即时生效——撤销设备后 DNS 记录同步消失，天然反审计漏洞）
4. **客户端指引**：文档写三行（Windows/macOS/Linux 各自把 `m.internal` 加搜索域或手动解析），或后续 agent 安装时自动配

预估工作量：**0.5~1 天**（含测试）。不引任何外部库。

## 3. 和 ZeroTier 方案的架构差异（诚实评估）

| | ZeroTier DNS | meshlet 现有 service DNS | meshlet 补节点 DNS 后 |
| --- | --- | --- | --- |
| 数据源 | 网络成员表（中心） | 已发布服务表 | 成员表 + 服务表 |
| 域名 | `<network>.zerotier` | `<service>.<internal_suffix>` | `<device>.m.internal` |
| 生效延迟 | 随成员同步 | 随发布计划 | 随成员/计划同步 |
| 撤销设备 | 记录消失 | — | 记录消失（天然反审计） |
| 依赖 | 中心 root | 自托管 hub | 自托管 hub |

架构上 meshlet 方案无劣化：数据就在自己的控制面 DB 里，比 ZeroTier 还少一跳外部依赖。

## 4. 建议

- **做**：节点名 DNS（P2，0.5~1 天）——补齐后 `ssh admin@imac`、RDP `imac:3389` 等体验对齐 ZeroTier，且撤销设备即失名，审计闭环
- **不做**：独立 DNS 基础设施（recursive resolver、转发公网查询）——超范围，系统已有上游 DNS
- **顺带**：device_plan 已把服务注册进 DnsCatalog，把「节点记录」与「服务记录」统一挂同一 serve_udp 实例（53 或 5353 一个端口服务两类记录），避免两个监听

## 5. 决策点（需拍板）

1. 域名后缀定什么：建议 `m.internal`（短、无冲突、语义清楚）或 `<network_name>.internal`（多网络隔离更好）
2. 端口：53 需 root/NET_ADMIN（hub 是 root 部署无碍）；5353 零权限但客户端要显式指定
3. 是否下发给客户端自动配置搜索域（Windows 下发搜索域列表需要 agent 动网卡 DNS 设置——涉及提权，建议 v1 只写文档手动配）
