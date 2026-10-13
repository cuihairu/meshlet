# 总体架构与技术选型

> 来源：[ChatGPT 存档 §3.2、§4](/review/chatgpt-2026-10-13#_3-2-控制平面与数据平面)。外部意见，全部【待核】。

## 控制平面 / 数据平面（§3.2）

【待核】职责切分（[存档 §3.2](/review/chatgpt-2026-10-13#_3-2-控制平面与数据平面)）：

- **控制平面**：用户认证与授权；网络/设备/网段元数据；设备身份与公钥；虚拟 IP 分配；LAN 路由与 Alias 配置；配置生成、版本控制与下发；配置应用错误状态；诊断与审计。
- **数据平面**：WireGuard 加密隧道；Linux 内核路由与转发；防火墙规则；Alias 地址转换；数据包转发。
- **客户端 Agent**：安装/启动/管理 WireGuard；建隧道；应用本机路由与网络规则；可选作为 LAN 网关发布网段；上报状态；失败时回滚自身管理的修改。
- 红线：**控制平面不逐包代理用户数据流量**。

## 技术选型（§4.1 / §4.2）

【待核】建议选型，实现时结合目标平台与依赖版本核验（[存档 §4.1](/review/chatgpt-2026-10-13#_4-1-后端)、[§4.2](/review/chatgpt-2026-10-13#_4-2-前端)）：

| 层 | 选型 |
|---|---|
| 后端语言 | Rust |
| 异步运行时 | Tokio |
| HTTP API | Axum |
| 序列化 | Serde |
| 数据访问 | SQLx（migrations） |
| 初期数据库 | SQLite |
| 日志诊断 | Tracing |
| 配置格式 | TOML |
| API 文档 | OpenAPI |
| 前端 | React + TypeScript + Vite（仅一个控制台，不做独立桌面应用） |

## 隧道与网络工具（§4.3）

【待核】（[存档 §4.3](/review/chatgpt-2026-10-13#_4-3-隧道与网络工具)）：

- WireGuard 作为隧道与加密基础；
- Linux 内核接口优先（`wg-quick`/Netlink/受控系统命令按配置事务与可测试性选择）；
- Windows 优先评估官方 WireGuard for Windows 的受支持管理方式；
- NAT 用 nftables 等受支持的规则管理；防火墙**只管理 Meshlet 自有规则**；
- **不得把随意拼接的 Shell 命令作为核心网络配置抽象**。

## Rust Workspace 建议（§4.4）

【待核】建议布局（[存档 §4.4](/review/chatgpt-2026-10-13#_4-4-rust-workspace-建议)）：

```text
meshlet/
├── Cargo.toml
├── crates/          # domain, api-types, config, network, observability
├── apps/            # server, agent, cli
├── web/             # React 控制台
├── migrations/      # SQLx migrations
├── deploy/          # systemd, docker
├── docs/            # architecture, decisions, implementation
└── tests/
```

约束：**不为目录整齐而过度拆分 crate**；初期模块可放在应用内部，边界清晰且有复用/测试价值时再拆。
