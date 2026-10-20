// 渲染 vitepress 产出的 div.language-mermaid 代码块为 mermaid SVG。
// 渲染失败时保留原始代码块并告警，绝不让整页挂掉。
let seq = 0
let queue: Promise<unknown> = Promise.resolve()

export function renderAllMermaid(): Promise<unknown> {
  const task = queue.then(async () => {
    const { default: mermaid } = await import('mermaid')
    await document.fonts.ready
    const dark = document.documentElement.classList.contains('dark')
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: 'base',
      look: 'classic',
      fontFamily: 'system-ui, sans-serif',
      flowchart: { htmlLabels: false, useMaxWidth: true },
      er: { useMaxWidth: true },
      themeVariables: {
        darkMode: dark,
        fontSize: '14px',
        primaryColor: dark ? '#243e3d' : '#e8f1ee',
        primaryTextColor: dark ? '#eef3ef' : '#203630',
        primaryBorderColor: dark ? '#7aaba0' : '#54776b',
        lineColor: dark ? '#a4b8b0' : '#51665e',
      },
    })
    const blocks = document.querySelectorAll<HTMLDivElement>('div.language-mermaid')
    for (const block of blocks) {
      const pre = block.querySelector('pre')
      if (!pre || block.classList.contains('mermaid-rendered')) continue
      // 首次渲染前把源码固化到 dataset，深浅色重渲染时不丢失原文。
      const source =
        block.dataset.mermaidSrc ??
        (block.querySelector('code')?.textContent ?? pre.textContent ?? '')
      block.dataset.mermaidSrc = source
      if (!source.trim()) continue
      try {
        const { svg } = await mermaid.render(`meshlet-diagram-${++seq}`, source)
        pre.innerHTML = svg
        pre.classList.add('mermaid-rendered')
        block.classList.add('mermaid-rendered')
      } catch (err) {
        console.warn('[mermaid] render failed:', err)
      }
    }
  })
  queue = task.catch(() => undefined)
  return task
}
