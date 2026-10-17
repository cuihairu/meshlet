# 产品边界与范围

> 来源：[ChatGPT 存档 §1–§3.3](/zh/review/chatgpt-2026-10-13#_1-项目概述)。外部意见，全部【待核】。

## 产品定位

Meshlet 是基于 Rust 的自托管私人虚拟网络工具（Self-hosted Private Networking，口号 "Your network. Your rules."）：

- 用户准备一台有公网 IPv4 的 VPS，部署 Meshlet Server；
- 在个人电脑、家庭服务器、办公室电脑等 Linux/Windows 设备上安装 Agent；
- 设备间先通过 VPS 中继通信，形成由用户自己管理的私人网络。

用户能力（[§1.1](/zh/review/chatgpt-2026-10-13#_1-1-产品定位)）：稳定虚拟 IP 互访、访问异地真实 LAN、重叠网段 Alias 访问、Web 控制台管理、状态查看与诊断、撤销设备、数据面完全在自有基础设施。

## 核心设计原则（§1.2）

【待核】八条原则作为实现取舍依据：

1. Self-hosted first —— 用户自行部署和控制服务端
2. Simple first —— 第一版以 VPS 为中心，不做复杂 P2P
3. Mature transport first —— 复用 WireGuard，不自研加密隧道协议
4. Explicit routing —— 虚拟 IP、LAN 路由、Alias 路由均有明确数据模型
5. Fail safely —— 配置失败不留下不可控网络状态
6. Observable by default —— 用户能知道连接为何成功或失败
7. Security by design —— 设备身份、成员关系、管理授权从第一版开始设计
8. Incremental architecture —— 先做可靠的单 VPS 版本

## 第一版不做什么（§1.3）

【待核】明确排除，不属于第一版验收范围（[存档 §1.3](/zh/review/chatgpt-2026-10-13#_1-3-第一版不做什么)）：

- 公共中继网络、陌生用户间资源共享
- 区块链、代币、贡献积分、经济结算
- 自研 WireGuard 替代协议
- 复杂多跳中继
- 自动 NAT 打洞、P2P 直连、动态中继切换
- 通用远程桌面、远程执行、运维任务调度
- 企业组织目录、复杂计费、多租户 SaaS
- 全局互联网出口 VPN
- 任意 L2 以太网广播与二层桥接
- DNS 服务作为第一版强制依赖

## 用户场景（§2）

【待核】四个验收场景（[存档 §2](/zh/review/chatgpt-2026-10-13#_2-用户场景)）：

| 场景 | 内容 | 关键点 |
|---|---|---|
| A · 虚拟 IP 互访 | `10.240.0.2` ↔ `10.240.0.3` 经 VPS 中继 | 第一版不要求设备间直连 |
| B · 异地 LAN | 家庭 `192.168.10.0/24` 发布，办公室可访问 | 前提：无路由冲突、网关能转发 |
| C · 重叠网段 | 两地都是 `192.168.1.0/24`，用 Alias 前缀 `10.241.x` / `10.242.x` 区分 | Alias 是路由+地址转换，不只是名称 |
| D · 控制台管理 | 建网络、加设备、配路由/Alias、撤销、看诊断 | — |

## 部署形态（§3.3）

【待核】第一版单 VPS：一个 Server、一个 Web 控制台（Server 提供静态文件）、一个 SQLite、一个 WireGuard 数据面、多个 Agent。控制 API 与 WireGuard 可同机但逻辑分离。**不引入 Kubernetes、微服务集群、独立消息队列**（[存档 §3.3](/zh/review/chatgpt-2026-10-13#_3-3-部署形态)）。
