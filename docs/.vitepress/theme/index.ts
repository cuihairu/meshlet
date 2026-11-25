import type { Theme } from 'vitepress'
import { watch, nextTick, onMounted } from 'vue'
import { useRoute } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import { renderAllMermaid } from './mermaidClient'
import './custom.css'

// An explicit language switch persists to localStorage under the meshlet-lang key shared with the console's
// language-provider, so the homepage auto-redirect script (config.mts localeRedirectScript) stops overriding
// the user's choice. Only locale links inside the language switcher (.VPNavBarTranslations) count.
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
    // Render ```mermaid fences on initial mount and after every route change.
    onMounted(() => {
      void renderAllMermaid()
      // Capture language-switcher clicks (capture phase, before VitePress client-side routing runs).
      document.addEventListener('click', recordLocaleSwitch, true)
      // Re-render on dark/light toggle (mermaid bakes the theme in at render time, so it must be redrawn).
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
