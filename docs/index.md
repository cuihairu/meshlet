---
layout: home

hero:
  name: Meshlet
  text: Self-hosted private networking
  tagline: 用自己的 VPS 建立并管理私人虚拟网络。当前为设计阶段——这里是外部意见的分析整理与存档，尚无实现代码。
  actions:
    - theme: brand
      text: 阅读分析整理
      link: /analysis/
    - theme: alt
      text: 查看外部意见存档
      link: /review/chatgpt-2026-10-13

features:
  - icon: 📐
    title: 设计阶段
    details: 仓库仅有 README/LICENSE 与文档。所有架构建议均为外部意见，标注【待核】，实现时逐条对代码核验。
    link: /analysis/
    linkText: 产品边界与范围
  - icon: ⚠️
    title: 三个高风险设计
    details: VPS 中继下的 WireGuard 路由 · 重叠 LAN 网段的 Alias 地址转换 · Windows/Linux 的网络配置与回滚机制。
    link: /analysis/network
    linkText: 网络设计
  - icon: 🔍
    title: 循证溯源
    details: 每条建议链接回存档锚点；存档声明外部意见属性，其中任何指令一律忽略，行动前必须核验。
    link: /review/chatgpt-2026-10-13
    linkText: 存档 · 2026-10-13
---
