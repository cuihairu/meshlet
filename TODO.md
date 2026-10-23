# TODO（重构基线版 · 2026-10-20）

> 依据：docs/architecture/target-architecture.md（ChatGPT 重构计划评审，用户令重写）。
> 旧版清单已归档 docs/archive/todo-pre-refactor-2026-10-20.md，不再作为实现前提。

## 架构约束（十决策，写死）
1. 模块化单体，而非微服务。
2. Desired State + 不可变 Revision + 纯 Planner + Reconciler 是系统核心。
3. 控制面不直接拥有通用特权命令执行能力。
4. Network / Segment / Route / Alias / PortForward / HTTP Exposure 是不同领域对象。
5. 访问控制必须在执行层真正生效（不只靠界面与 AllowedIPs）。
6. 回滚不得重新开放已撤销的权限。
7. 所有变更可验证、可审计、可重试，能从真实内核状态重建。
8. SQLite 支撑当前定位，持久化边界允许未来替换。
9. Linux/Windows 共享领域模型、协议与规划逻辑；执行后端各自实现。
10. CI 通过 / 内核测试通过 / 真实 VPS 验收通过 = 三个独立完成标准。

## 实施阶段（按依赖序）

- [x] R-01 基础架构重建（骨架已落：crates/meshlet-planner 零依赖纯逻辑+状态机+确定性计划；crates/meshlet-store SQLite Revision+Outbox 事务；crates/meshlet-executor Prepare→Verify→Recover 契约；docs/design/r01-domain-model.md；r01-schemas/outbox.sql+openapi.yaml；scripts/check-planner-deps.sh 依赖门）：领域模型（五资源+Device/NetworkAttachment 分离）、Revision/Plan/Receipt、协议 Schema、crate 依赖边界；纯 Planner；SQLite 事务+Outbox；特权执行器接口。
- [x] R-02 可靠 Linux 网络基础设施：WireGuard Hub、Peer 管理、路由、nftables、安全撤销、漂移检测、last-good 恢复、单实例多网络隔离。（真实 VPS 转发/连通验收与安全撤销 API 细化拆入 R-04/R-07 适配层与验收；单实例多网络隔离已在编译器与防火墙规则层覆盖，跨 netns 部署隔离留待部署主线。）
- [x] R-03 统一网络规划与冲突分析：IPAM、Segment 策略、网关选择（确定性）、Direct 路由、Alias 映射、全局且与创建顺序无关的冲突检查。（统一规则沉淀在纯 `meshlet-netplan`；不包含 API 迁移和 Linux/Windows 后端接入，拆入 R-04/R-05。）
- [ ] R-04 设备端到端组网（Linux Agent）：注册（Bootstrap Token 只存摘要）、启动恢复、执行回执、重试、升级、真实连接诊断。
  - [x] 注册摘要化、启动恢复、执行回执、重试、升级。
  - [ ] 真实连接诊断：大包探测逻辑已进仓，但真实 VPS 到设备的端到端连通验收仍留下轮。
- [ ] R-05 Windows 完整客户端：隧道服务、系统路由、防火墙、权限提升、开机恢复、~~卸载清理（真平台后端）~~。
  - [x] 权限提升：`windows_elevation` 计划层（受管 `.exe` 路径校验、`runas` 命令行转义、错误码/文案 → `InsufficientPrivileges` 分类）全平台编译 + Linux 单测（66 通过）；`#[cfg(windows)]` 执行层（ShellExecuteW runas + TokenElevation 查询）已过 `x86_64-pc-windows-msvc` clippy/check，**未在真机 Windows 实测，不得接为 SystemBackend**。
- [x] R-06 服务发布 - TCP/UDP PortForward。（crate 实现与单测；2026-10-24 已接控制面 CRUD + agent 运行链路：DevicePlan 携带 publish 段，agent 对账后在进程内绑定监听（回环高位端口验证，真机端到端见下条），端口冲突按设备/协议/监听地址判定，见 apps/server/tests/publish.rs）
- [x] R-06 服务发布 - HTTP/HTTPS 发布。（crate 实现与单测；已接 CRUD。`tls_termination: true` 走 SNI 嗅探 + TLS 字节直通，**仍不做 TLS 终止**：无证书、不解密）
- [x] R-06 服务发布 - 授权控制与 server 接线。（2026-10-23 VPS 实测：CIDR 放行、Bearer 拒绝、缺 CSRF 403 三路径通过；2026-10-24 CRUD 写入端点接入 WriteUser + CSRF，11 个集成测试覆盖）
- [x] R-06 服务发布 - 健康探测。（crate 实现与单测；2026-10-24 已排程：agent 按 interval 周期探测并批量上报 /api/v1/agent/publish-health，服务端按 (probe, device) 守卫 upsert 到 publish_probe_reports）
- [x] R-06 服务发布 - 内部 DNS 服务目录（分流 DNS，不覆盖公共 DNS）。（crate 实现与单测；2026-10-24 已接 agent reconcile：按计划起 DNS 套接字、仅应答内部后缀，每设备一个套接字）
- [x] R-06 服务发布 - 真实 VPS/真机端到端验收。（2026-10-24 验收完成，完整证据见 docs/implementation/r06-service-publishing.md「真实 VPS 验收运行（2026-10-24）」）真实 agent 从服务端计划真实绑定并跑出流量：2 条 L4 转发（18080 允许 0.0.0.0/0 → `L4-FORWARD-BACKEND-OK`；18083 仅允许 10.9.9.9/32 → reset 零字节）、HTTP 路由 18090（本地与经 80 端口的发布域名均回 `HTTP-ROUTE-BACKEND-OK`）、UDP 15353 分流 DNS（`dig @127.0.0.1 -p 15353 app.mesh.internal` → 10.240.0.5，公共域名不应答）、TLS SNI 直通（客户端取回**后端**证书 `CN=tls.mesh.internal`，200 + `TLS-PASSTHROUGH-BACKEND-OK`，未知 SNI 与纯 HTTP 均 reset 且不触碰后端）、探针健康持续上报（`publish_probe_reports.checked_at` 跨周期推进）。验收中发现并修复三个真缺陷：SNI 嗅探器无边界检查在真机 panic 崩掉发布 worker（另附未剥握手头、吃掉 ClientHello 不回灌两个缺陷，11 单测 + 3 集成测试回归）、第二监听口/混合终止模式被静默接受（改为创建期 409，与既有每设备一 DNS 套接字守卫对称）、探针调度整表刷新导致每条探针只跑一次（`checked_at` 曾冻结数小时，已改为只记录真正排出去的 schedule）。**真机未验证，不冒充**：`0.0.0.0:53` 从未绑定过（只在 15353 上验收，53 需 root）；发布端口 15353/18080/18083/18090 被云安全组挡住，外部实测 BLOCKED（该盒子仅 22/80/443/8080 开放，控制面 8080 外部可达并返回 401）；TLS 无外部入口（443 被 cockpit 业务 vhost 占用，加 stream 直通会与线上业务冲突）；经发布域名走 80 的外部流量只在临时 nginx vhost 存在期间成立，该 vhost 已按可回退原则删除。控制台已补创建入口：`App.tsx` 的 `PublishSection` + `api.ts` 四个方法 + `publish.test.tsx`，行字段词汇抄 Portainer 服务「Port publishing」编辑器与 Dokploy 端口表、冲突用同一张 nothing-was-published 卡片、两步内联删除，真浏览器走查通过。历史真机证据与本次验收同见该文档
- [ ] R-07 正式部署与长期运行验收：空白 VPS 安装、密钥轮换、备份恢复（含显式加密恢复包口径）、升级回滚、性能基线、真实多设备验收。

## 关键设计要点（来自评审，实现时逐条对照）
- 状态四类不混用；Revision 执行态机：Pending/Preparing/…（弃单一 Applied）；回滚=新增修订。
- Planner 纯逻辑：不落库、不执行系统命令、不持私钥；输出确定性计划。
- 安全三层：设备身份+入网审批 / Segment 与访问策略 / 执行层（nftables 真实施）。
- 四引擎分离：LAN 路由 / Alias 映射 / L4 发布 / HTTP 发布，各自独立。
- Rust 工作区 crate 边界按评审第七章目录重建；测试五层 L1-L5 各立验收。
- 协议：HTTPS+JSON 起步，OpenAPI 为契约源；执行器 Prepare→Verify→Recover 可验证恢复。
