---
layout: home
hero:
  name: Meshlet
  text: 自托管私人组网
  tagline: 用自己的 VPS 建立并管理私人虚拟网络。控制面、Linux WireGuard hub/agent、LAN 路由与 Alias NAT、服务发布与控制台今天在 Linux 上就能跑；Windows 未验收，TODO 里如实挂着。
  actions:
    - theme: brand
      text: 阅读分析整理
      link: /zh/analysis/
    - theme: alt
      text: 查看架构
      link: /zh/architecture/domain-model
features:
  - icon: 🛰️
    title: 今天在 Linux 上跑着的
    details: 控制平面 · WireGuard hub 与 agent · LAN 路由与 Alias NAT · L4/HTTP/DNS 服务发布 · React 控制台 · 会话与 API Token 认证 · 审计 · 备份恢复 · 诊断 · 中心审批的设备自举注册。
    link: /zh/architecture/domain-model
    linkText: 领域模型
  - icon: 📋
    title: 真机验收，带数字
    details: 2026-10-24 跨主机验收——三台设备经 bootstrap token 入网、13 项诊断全绿、DF-MTU 边界实测；部署验收覆盖空白容器安装、密钥轮换、备份恢复、原地升级与离线回滚。
    link: /zh/implementation/r04-linux-agent-e2e
    linkText: 验收记录
  - icon: ⚠️
    title: 没做到的不打勾
    details: 没有可用 Windows 真机（R-05 未勾）；长期浸泡采集器 2026-10-24 起在跑，需要数周数据；尚无带日期的 release。TODO 里这三项都保持可见。
    link: /zh/implementation/r07-deployment-acceptance
    linkText: 部署验收
---

Meshlet 是一个自托管私人组网项目。这些页面记录它的架构、决策、实现证据与运维流程。中文页面保留完整的中文原始文档，英文页面是精编版。
