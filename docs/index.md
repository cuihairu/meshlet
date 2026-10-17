---
layout: home
hero:
  name: Meshlet
  text: Self-hosted private networking
  tagline: Build and manage private virtual networks through your own VPS. The repository contains a control plane, a Linux WireGuard hub and agent, LAN routes, Alias NAT, and a web console. Architecture gaps, Windows support, and real deployment acceptance remain tracked separately.
  actions:
    - theme: brand
      text: Browse analysis
      link: /analysis/
    - theme: alt
      text: Read the architecture
      link: /architecture/domain-model
features:
  - icon: 🛠️
    title: A working foundation
    details: Network control plane · WireGuard hub and agent · LAN routes and Alias NAT · React console · session and API-token authentication · audit log · backup and restore · diagnostics · device registration with operator approval.
    link: /architecture/domain-model
    linkText: Domain model
  - icon: ⚠️
    title: Evidence-led scope
    details: Reviews distinguish tested topologies from production capability. The current review records architecture gaps, while a separate study compares 61 ZeroTier and Tailscale capabilities against personal use cases.
    link: /analysis/architecture-review-2026-10-17
    linkText: Architecture review
  - icon: 🔍
    title: Traceable decisions
    details: Architecture decisions, implementation records, and acceptance evidence are kept alongside the code. External material is treated as reference material and verified before it guides an action.
    link: /decisions/
    linkText: Decision records
---

<script setup lang="ts">
// 首次访问按浏览器语言选择文档语言（vitepress 无此能力，GitHub Pages 不支持 _redirects）
// 优先级：localStorage 手动选择 > navigator.language > 保持当前 locale
import { onBeforeMount } from 'vue'
const KEY = 'meshlet-lang-auto-picked'
const BASE = '/meshlet/'
const ROOT_PATH = BASE
const ZH_PATH = BASE + 'zh/'
onBeforeMount(() => {{
  if (typeof window === 'undefined') return
  const p = window.location.pathname
  if (p !== ROOT_PATH && p !== ROOT_PATH.slice(0, -1)) return
  const picked = localStorage.getItem(KEY)
  if (picked) {{ if (picked !== p) window.location.replace(picked); return }}
  const langs = (navigator.languages?.length ? navigator.languages : [navigator.language]).map(l => l.toLowerCase())
  if (langs.some(l => l.startsWith('zh'))) window.location.replace(ZH_PATH)
}})
if (typeof window !== 'undefined') {{
  window.addEventListener('click', (e) => {{
    const a = (e.target as HTMLElement)?.closest?.('a') as HTMLAnchorElement | null
    const href = a?.getAttribute('href') || ''
    if (href.startsWith(ZH_PATH) || href.startsWith('zh/')) localStorage.setItem(KEY, ZH_PATH)
    else if (href === ROOT_PATH || href === ROOT_PATH.slice(0, -1)) localStorage.setItem(KEY, ROOT_PATH)
  }}, true)
}}
</script>


Meshlet is a self-hosted private networking project. These pages document its architecture, decisions, implementation evidence, and operating procedures. The English pages are concise editorial editions; the Simplified Chinese locale preserves the full Chinese source documents.
