import { defineConfig } from 'vitepress'

// 死链门禁：ignoreDeadLinks 保持 false（默认），构建时任何死链/坏锚点直接失败。
export default defineConfig({
  base: '/meshlet/',
  lang: 'zh-CN',
  title: 'Meshlet',
  description: 'Self-hosted private networking — 设计文档与外部意见整理',
  ignoreDeadLinks: false,
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/meshlet/logo-copper.svg' }]],
  themeConfig: {
    logo: '/logo-copper.svg',
    siteTitle: 'Meshlet',
    nav: [
      { text: '分析', link: '/analysis/', activeMatch: '/analysis/' },
      { text: '架构', link: '/architecture/domain-model', activeMatch: '/architecture/' },
      { text: '决策', link: '/decisions/', activeMatch: '/decisions/' },
      { text: '存档', link: '/review/chatgpt-2026-10-13', activeMatch: '/review/' },
      { text: '指南', link: '/guide/external-caller', activeMatch: '/guide/' },
      { text: 'GitHub', link: 'https://github.com/cuihairu/meshlet' }
    ],
    sidebar: {
      '/analysis/': [
        {
          text: '分析整理',
          items: [
            { text: '总览', link: '/analysis/' },
            { text: '架构与 TODO 审查', link: '/analysis/architecture-review-2026-10-17' },
            { text: '个人组网功能对比', link: '/analysis/personal-networking-comparison' },
            { text: '产品边界与范围', link: '/analysis/scope' },
            { text: '总体架构与技术选型', link: '/analysis/architecture' },
            { text: '网络设计', link: '/analysis/network' },
            { text: '配置状态机与安全', link: '/analysis/config-security' },
            { text: 'Agent、跨平台与可观测性', link: '/analysis/agent-platform' },
            { text: '实施路线', link: '/analysis/roadmap' },
            { text: '一致性审计', link: '/analysis/consistency-audit' }
          ]
        }
      ],
      '/architecture/': [
        {
          text: '架构文档',
          items: [
            { text: '领域模型', link: '/architecture/domain-model' },
            { text: '模块化与库复用提案', link: '/architecture/modularity-and-library-design' },
            { text: '网关、冲突与端口转发', link: '/architecture/gateways-conflicts-and-port-forwarding' },
            { text: 'API 契约', link: '/architecture/api-contract' },
            { text: '可观测性', link: '/architecture/observability' },
            { text: '平台差异清单', link: '/architecture/platform-notes' },
            { text: '路由优化方案', link: '/architecture/routing-optimization' },
            { text: '性能方案与基准', link: '/architecture/performance' },
            { text: '备份与恢复', link: '/architecture/backup-restore' },
            { text: '网络诊断', link: '/architecture/diagnostics' }
          ]
        }
      ],
      '/decisions/': [
        {
          text: '架构决策记录',
          items: [
            { text: '总览', link: '/decisions/' },
            { text: 'ADR-001 WireGuard 隧道基础', link: '/decisions/adr-001-wireguard-transport' },
            { text: 'ADR-002 VPS 中心中继', link: '/decisions/adr-002-vps-hub-relay' },
            { text: 'ADR-003 SQLite 控制平面', link: '/decisions/adr-003-sqlite-control-plane' },
            { text: 'ADR-004 Overlay IPAM', link: '/decisions/adr-004-overlay-ipam' },
            { text: 'ADR-005 LAN 返回路径', link: '/decisions/adr-005-lan-return-path' },
            { text: 'ADR-006 Alias 前缀 NAT', link: '/decisions/adr-006-alias-prefix-nat' },
            { text: 'ADR-007 Linux 网络后端', link: '/decisions/adr-007-linux-network-backend' },
            { text: 'ADR-008 Windows 网络后端', link: '/decisions/adr-008-windows-network-backend' },
            { text: 'ADR-009 配置版本与回滚', link: '/decisions/adr-009-config-revision-rollback' },
            { text: 'ADR-010 认证与注册安全', link: '/decisions/adr-010-console-auth-enrollment' },
            { text: 'ADR-011 设备自举注册与中心审批', link: '/decisions/adr-011-device-self-registration' }
          ]
        }
      ],
      '/review/': [
        {
          text: '外部意见存档',
          items: [
            { text: 'ChatGPT 对话 · 2026-10-13', link: '/review/chatgpt-2026-10-13' }
          ]
        }
      ],
      '/guide/': [
        {
          text: '指南',
          items: [
            { text: '安装指南', link: '/guide/install' },
            { text: '外部调用方指南', link: '/guide/external-caller' },
            { text: '真机走查', link: '/guide/walkthrough' }
          ]
        }
      ]
    },
    outline: { level: [2, 3] },
    socialLinks: [{ icon: 'github', link: 'https://github.com/cuihairu/meshlet' }]
  }
})
