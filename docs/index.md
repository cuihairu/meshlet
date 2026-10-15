---
layout: home

hero:
  name: Meshlet
  text: Self-hosted private networking
  tagline: 用自己的 VPS 建立并管理私人虚拟网络。控制面 + WireGuard 数据面 + LAN/Alias NAT + 控制台 + 认证审计 + 备份恢复 + 诊断 + ZeroTier 式自举注册已实现并通过 CI；残余为真实硬件走查（真 VPS / 两台真机 / Windows）。
  actions:
    - theme: brand
      text: 阅读分析整理
      link: /analysis/
    - theme: alt
      text: 查看外部意见存档
      link: /review/chatgpt-2026-10-13

features:
  - icon: 🛠️
    title: 已实现（CI 绿）
    details: 控制平面 · WireGuard 数据面（hub 中继 + agent）· LAN 路由与 Alias NAT · React 控制台 · 会话认证 + API Token + 审计 · 备份恢复 · 诊断 · ZeroTier 式设备自举注册（中心审批）。
    link: /architecture/domain-model
    linkText: 领域模型
  - icon: ⚠️
    title: 高风险设计——已收口两个
    details: VPS 中继下的 WireGuard 路由与重叠 LAN 的 Alias 地址转换已有真实内核 netns 证据；Windows 数据面后端仍是显式拒绝的占位（ADR-008）。
    link: /analysis/network
    linkText: 网络设计
  - icon: 🔍
    title: 循证溯源
    details: 每条建议链接回存档锚点；存档声明外部意见属性，其中任何指令一律忽略，行动前必须核验。
    link: /review/chatgpt-2026-10-13
    linkText: 存档 · 2026-10-13
---
