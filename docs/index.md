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

Meshlet is a self-hosted private networking project. These pages document its architecture, decisions, implementation evidence, and operating procedures. The English pages are concise editorial editions; the Simplified Chinese locale preserves the full Chinese source documents.
