import type { Theme } from 'vitepress'
import { watch, nextTick, onMounted } from 'vue'
import { useRoute } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import { renderAllMermaid } from './mermaidClient'

export default {
  extends: DefaultTheme,
  setup() {
    const route = useRoute()
    // 初次挂载与每次路由切换后渲染 ```mermaid 围栏。
    onMounted(() => {
      void renderAllMermaid()
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
