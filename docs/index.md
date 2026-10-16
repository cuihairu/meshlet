---
layout: home

hero:
  name: Meshlet
  text: Self-hosted private networking
  tagline: 用自己的 VPS 建立并管理私人虚拟网络。已有控制面、Linux WireGuard hub/agent、LAN/Alias 与控制台基础；多网络隔离、配置确认、hub 恢复及部署权限等缺口见最新架构审查，Windows 完整后端与真实部署仍待验收。
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
    title: 最新架构审查与个人版取舍
    details: 区分测试拓扑与生产能力，登记六项架构缺口；另有 ZeroTier / Tailscale 的 61 项功能调研，按个人需求、开发难度和依赖筛选。
    link: /analysis/architecture-review-2026-10-17
    linkText: 架构与 TODO 审查
  - icon: 🔍
    title: 循证溯源
    details: 每条建议链接回存档锚点；存档声明外部意见属性，其中任何指令一律忽略，行动前必须核验。
    link: /review/chatgpt-2026-10-13
    linkText: 存档 · 2026-10-13
---
