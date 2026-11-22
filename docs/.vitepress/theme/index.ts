import type { Theme } from 'vitepress'
import { watch, nextTick, onMounted } from 'vue'
import { useRoute } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import { renderAllMermaid } from './mermaidClient'
import './custom.css'

// 显式切换语言时落 localStorage，与 console 的 language-provider 共用 meshlet-lang 键：
// 落盘后首页的自动跳转脚本（config.mts localeRedirectScript）不再覆盖用户选择。
// 只认语言切换器（.VPNavBarTranslations）内的 locale 链接，不误伤正文里的 zh 链接。
function recordLocaleSwitch(e: Event): void {
  const target = e.target as HTMLElement | null
  const link = target?.closest('a[href]')
  if (!link) return
  if (!link.closest('.VPNavBarTranslations')) return
  const href = link.getAttribute('href') ?? ''
  const lang = href.startsWith('/meshlet/zh/')
    ? 'zh'
    : href === '/meshlet/' || href === '/meshlet'
      ? 'en'
      : null
  if (lang) localStorage.setItem('meshlet-lang', lang)
}

export default {
  extends: DefaultTheme,
  setup() {
    const route = useRoute()
    // 初次挂载与每次路由切换后渲染 ```mermaid 围栏。
    onMounted(() => {
      void renderAllMermaid()
      // 捕获语言切换器点击（capture 阶段，先于 VitePress 客户端路由跳转执行）。
      document.addEventListener('click', recordLocaleSwitch, true)
      // 深浅色切换时重渲染（mermaid 主题在渲染期固化，需重画）。
      const observer = new MutationObserver(() => {
        void renderAllMermaid()
      })
      observer.observe(document.documentElement, {
        attributes: true,
        attributeFilter: ['class'],
      })
    })
    watch(
      () => route.path,
      () => {
        void nextTick(() => renderAllMermaid())
      },
    )
  },
} satisfies Theme
