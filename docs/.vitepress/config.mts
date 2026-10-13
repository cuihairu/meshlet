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
      { text: '存档', link: '/review/chatgpt-2026-10-13', activeMatch: '/review/' },
      { text: 'GitHub', link: 'https://github.com/cuihairu/meshlet' }
    ],
    sidebar: {
      '/analysis/': [
        {
          text: '分析整理',
          items: [
            { text: '总览', link: '/analysis/' },
            { text: '产品边界与范围', link: '/analysis/scope' },
            { text: '总体架构与技术选型', link: '/analysis/architecture' },
            { text: '网络设计', link: '/analysis/network' },
            { text: '配置状态机与安全', link: '/analysis/config-security' },
            { text: 'Agent、跨平台与可观测性', link: '/analysis/agent-platform' },
            { text: '实施路线', link: '/analysis/roadmap' }
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
      ]
    },
    outline: { level: [2, 3] },
    socialLinks: [{ icon: 'github', link: 'https://github.com/cuihairu/meshlet' }]
  }
})
