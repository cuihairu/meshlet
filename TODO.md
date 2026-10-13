# Meshlet TODO

条目来源：[ChatGPT 存档 · 落地跟踪](docs/review/chatgpt-2026-10-13.md)（外部意见，**执行前必须对代码核验**；本仓当前无实现代码，全部条目为「待核」状态）。

期次对应存档 §19 的 Phase 0–5。每条含：建议（链接回存档锚点）、期次、验收标准。

## Phase 0 · 架构审查与原型

- [ ] 锁定第一版边界与排除项（[存档 §1.3](docs/review/chatgpt-2026-10-13.md)）— 验收：边界清单进入 docs 并经用户确认（清单已就绪：[docs/analysis/scope.md](docs/analysis/scope.md)；**待用户一句确认**）
- [x] 确认单 VPS 部署形态，排除 K8s/微服务/消息队列（[存档 §3.3](docs/review/chatgpt-2026-10-13.md)）— 验收：部署形态写入 ADR-002 ✅ [ADR-002](docs/decisions/adr-002-vps-hub-relay.md)
- [ ] 技术选型核验：Rust/Tokio/Axum/Serde/SQLx/SQLite/Tracing（[存档 §4.1](docs/review/chatgpt-2026-10-13.md)）— 验收：选型写入 ADR 并通过最小 spike（ADR 已入库；spike 已验证 tokio/axum/serde/toml/tracing 编译+运行，**sqlx/SQLite 待持久化落地时验证**）
- [ ] WireGuard 中心转发原型：A→B、B→A、未授权不可达、撤销后失效（[存档 §7.3](docs/review/chatgpt-2026-10-13.md)）— 验收：四项真实集成测试通过 ⛔ **卡点：开发环境无 root/CAP_NET_ADMIN，user namespace 禁用（uid_map 拒写），`wg` 未安装**；需 root 环境或特权 CI runner（ADR-007 已记录该前提）
- [ ] Alias DNAT/SNAT 原型：等长前缀映射 + 受控 SNAT 返回路径（[存档 §9.2–§9.5](docs/review/chatgpt-2026-10-13.md)）— 验收：双 `192.168.1.0/24` 经不同 Alias 访问成功 ⛔ **卡点同上（nftables/NET_ADMIN/netns 不可用）**；可先落等长前缀映射的纯逻辑单测（见 meshlet-domain）
- [x] Windows/Linux 配置管理差异调研（[存档 §15.2–§15.3](docs/review/chatgpt-2026-10-13.md)）— 验收：差异清单 + ADR-007/008 ✅ [platform-notes](docs/architecture/platform-notes.md)、[ADR-007](docs/decisions/adr-007-linux-network-backend.md)、[ADR-008](docs/decisions/adr-008-windows-network-backend.md)
- [x] 建立 ADR-001~010（[存档 §21](docs/review/chatgpt-2026-10-13.md)）— 验收：10 份 ADR 入库，含背景/方案/取舍/风险 ✅ [docs/decisions/](docs/decisions/index.md)
- [ ] 领域模型与 API 契约初稿（[存档 §5、§13](docs/review/chatgpt-2026-10-13.md)）— 验收：实体关系图 + OpenAPI 初稿评审通过（初稿就绪：[domain-model](docs/architecture/domain-model.md) + [api-contract](docs/architecture/api-contract.md) + [openapi.yaml](docs/public/api/openapi.yaml)；**待用户评审**）

## 仓库事务

- [ ] License 徽章与许可证一致性 — README 徽章按实际 LICENSE 挂 **Apache-2.0**；**待用户确认是否换 MIT**（许可证变更属用户拍板事项，不代改；确认换则同步改 LICENSE 文件与两份 README 徽章）

## Phase 1 · 最小 Overlay

- [ ] Rust workspace 骨架（[存档 §4.4](docs/review/chatgpt-2026-10-13.md)）— 验收：cargo build 通过，目录边界与 §3.2 职责一致
- [ ] 控制平面/数据平面职责拆分落地（[存档 §3.2](docs/review/chatgpt-2026-10-13.md)）— 验收：控制平面无逐包代理路径
- [ ] 核心实体：User/Network/Device/DeviceKey/LAN Route/Alias Mapping/Config Revision（[存档 §5](docs/review/chatgpt-2026-10-13.md)）— 验收：migrations + 单元测试覆盖实体约束
- [ ] Overlay IPAM：默认 `10.240.0.0/16` 可配置、按 CIDR 计算分配（[存档 §6.1](docs/review/chatgpt-2026-10-13.md)）— 验收：分配无重复；CIDR 校验单测通过
- [ ] CIDR 冲突检测六项（[存档 §6.2–§6.3](docs/review/chatgpt-2026-10-13.md)）— 验收：三类冲突（服务端/客户端/未知）区分上报，未知时仅警告
- [ ] 每设备独立 Peer；AllowedIPs 与目标路由一致（[存档 §7.2](docs/review/chatgpt-2026-10-13.md)）— 验收：默认只路由 Overlay+已发布 LAN+Alias
- [ ] 设备加入邀请流程，私钥不出客户端（[存档 §11.2](docs/review/chatgpt-2026-10-13.md)）— 验收：端到端加入成功；DB 无私钥
- [ ] 两台 Linux 客户端经 VPS 互通（[存档 §19 Phase 1](docs/review/chatgpt-2026-10-13.md)）— 验收：互访/重启恢复/撤销失效/IP 不重复

## Phase 2 · Web 控制台

- [ ] 用户认证与管理授权（[存档 §11.4](docs/review/chatgpt-2026-10-13.md)）— 验收：全部管理 API 需认证；哈希/限流/Cookie 安全属性/CSRF 就位
- [ ] 邀请 Token 安全（[存档 §11.3](docs/review/chatgpt-2026-10-13.md)）— 验收：只存摘要；过期/撤销/一次性可测；日志无 Token
- [ ] React 控制台：Network/Device/邀请/撤销/配置版本页面（[存档 §12](docs/review/chatgpt-2026-10-13.md)）— 验收：不手工改库即可完成基本管理
- [ ] 在线状态判定（握手+心跳+上报）（[存档 §12.4](docs/review/chatgpt-2026-10-13.md)）— 验收：状态标注数据来源与更新时间
- [ ] 配置状态机（[存档 §10](docs/review/chatgpt-2026-10-13.md)）— 验收：DB 写入 ≠ 显示生效；失败可见；状态可区分
- [ ] 撤销设备完整链路（[存档 §11.5](docs/review/chatgpt-2026-10-13.md)）— 验收：Peer/路由/Alias 关系全部移除；不确定生效时报失败
- [ ] 审计日志（[存档 §16.5](docs/review/chatgpt-2026-10-13.md)）— 验收：敏感操作全记录；无密码/私钥/Token 明文

## Phase 3 · LAN Subnet Routing

- [ ] LAN Route 模型与网关配置（[存档 §8.1](docs/review/chatgpt-2026-10-13.md)）— 验收：发布 CIDR 后远端可访问
- [ ] 返回路径双模式（真实双向 / 受控 SNAT），UI 显示所采用模式（[存档 §8.2](docs/review/chatgpt-2026-10-13.md)）— 验收：SNAT 模式 LAN 响应可返回 Overlay
- [ ] 路由冲突不静默（[存档 §8.3](docs/review/chatgpt-2026-10-13.md)）— 验收：同网段冲突提示配 Alias；不覆盖已有路由
- [ ] SNAT 纪律（[存档 §7.4](docs/review/chatgpt-2026-10-13.md)）— 验收：Overlay 设备间保留原始源地址
- [ ] MTU 可配置 + 诊断（[存档 §7.5](docs/review/chatgpt-2026-10-13.md)）— 验收：大包问题可解释
- [ ] Windows 路由处理（[存档 §15.3](docs/review/chatgpt-2026-10-13.md)）— 验收：权限不足提示明确；失败可清理

## Phase 4 · Alias Routing

- [ ] Alias 模型与等长前缀映射（[存档 §9.2](docs/review/chatgpt-2026-10-13.md)）— 验收：六项转换前检查全过；非等长被拒
- [ ] 网关侧 DNAT/SNAT 实施（[存档 §9.4–§9.5](docs/review/chatgpt-2026-10-13.md)）— 验收：双重叠 LAN 各自可达；默认 SNAT 限制 UI 可见
- [ ] NAT 规则所有权与清理（[存档 §12.6](docs/review/chatgpt-2026-10-13.md)）— 验收：删除 Alias 同步清理路由与 NAT；失败不报成功
- [ ] Alias 协议边界声明（[存档 §9.6](docs/review/chatgpt-2026-10-13.md)）— 验收：文档明示不保证广播/组播/二层发现

## Phase 5 · 稳定性与发布

- [ ] 配置应用幂等与回滚安全（[存档 §10.3–§10.4](docs/review/chatgpt-2026-10-13.md)）— 验收：重复应用不破坏网络；回滚不触碰非 Meshlet 规则
- [ ] 并发版本顺序（[存档 §10.4](docs/review/chatgpt-2026-10-13.md)）— 验收：并发修改不交叉破坏 Peer/路由/NAT
- [ ] 结构化日志与指标（[存档 §17.1–§17.2](docs/review/chatgpt-2026-10-13.md)）— 验收：规定字段齐全；不依赖单一指标
- [ ] 故障恢复（[存档 §17.3](docs/review/chatgpt-2026-10-13.md)）— 验收：服务端/客户端重启后按期望状态恢复
- [ ] 备份与恢复（[存档 §17.4](docs/review/chatgpt-2026-10-13.md)）— 验收：一致性备份；恢复后协调到期望状态
- [ ] 测试体系：单元 + 集成 12 项 + 跨平台 + 安全（[存档 §18](docs/review/chatgpt-2026-10-13.md)）— 验收：全部通过并入 CI
- [ ] Diagnostics 页面 12 项检查（[存档 §12.7](docs/review/chatgpt-2026-10-13.md)）— 验收：能区分隧道/路由/转发/Alias 故障层
- [ ] 安装流程与自启动（[存档 §19 Phase 5](docs/review/chatgpt-2026-10-13.md)）— 验收：新用户从空 VPS 完成部署
- [ ] 第一版最终验收逐条核对（[存档 §22](docs/review/chatgpt-2026-10-13.md)）— 验收：五组验收全绿后方可谈发布

## 说明

- 本文件是外部建议的登记表，不代表承诺的路线图；每条落地前先与实际代码核验。
- 按用户红线：**发布正式版本必须由用户明确给出版本号并触发**，验收未通过的二进制不进 Releases 页面。
