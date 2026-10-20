# ADR-013：Cockpit Agent 作为本机基础信息源

状态：2026-10-20 采纳（用户裁决）

## 背景

Cockpit 在主机上驻留 agent 做资产与运维；Meshlet 需要节点基础事实（主机名、地址、
OS、网卡）来把设备放进网络与分段。两个项目同属一人，两边重复采集必然漂移浪费。

## 决定

- **mesh 组网归 Meshlet**：Cockpit 不生长 mesh 数据面；既有 frp/WireGuard overlay
  保留为观测/历史集成，今后 Cockpit 侧的 mesh 能力一律以集成 Meshlet 方式实现。
- **Meshlet 从本机 cockpit-agent 读取基础事实**（本地只读 API），不再自采；
  范围仅限节点基础信息——不含密钥、不越界到资产语义。
- cockpit-agent 是**可选来源而非硬依赖**：缺失时 Meshlet 必须仍能自描述网卡与基本信息。
- 具体本地只读接口契约随 Cockpit 的 Agent Capability 协议片落地（见 cockpit todo）。

## 影响

- 消除重复采集器，边界清晰（Cockpit=控制面与运维，Meshlet=mesh 数据面）。
- 本机调用、离线可用，不绕云。
- Meshlet 多一个可选边缘依赖，必须优雅降级。
- Cockpit 的本地读 API 须保持范围窄且稳定。

## 重开条件

Meshlet 需要更丰富事实（服务、端口、容器）时，走 Cockpit 能力协议工作线重开，
不允许临时扩口。
