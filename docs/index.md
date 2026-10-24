---
layout: home
hero:
  name: Meshlet
  text: Self-hosted private networking
  tagline: Build and manage private virtual networks through your own VPS. The control plane, Linux WireGuard hub and agent, LAN routes, Alias NAT, service publishing and the web console run on Linux today; Windows is not accepted and the TODO says so.
  actions:
    - theme: brand
      text: Browse analysis
      link: /analysis/
    - theme: alt
      text: Read the architecture
      link: /architecture/domain-model
features:
  - icon: 🛰️
    title: What runs on Linux today
    details: Control plane · WireGuard hub and agent · LAN routes and Alias NAT · L4, HTTP and DNS service publishing · React console · session and API-token auth · audit log · backup and restore · diagnostics · operator-approved device registration.
    link: /architecture/domain-model
    linkText: Domain model
  - icon: 📋
    title: Accepted on real machines, with numbers
    details: Cross-host acceptance on 2026-10-24 — three devices joined through bootstrap tokens, 13-check diagnostics green, DF-MTU boundaries measured. Deployment acceptance covers blank-container install, key rotation, backup and restore, in-place upgrade and offline rollback.
    link: /implementation/r04-linux-agent-e2e
    linkText: Acceptance records
  - icon: ⚠️
    title: What is not done stays unchecked
    details: No Windows machine has run the client (R-05); the long-run soak collector started on 2026-10-24 and needs weeks of data; no dated release exists yet. The TODO keeps all three visible.
    link: /implementation/r07-deployment-acceptance
    linkText: Deployment acceptance
---

Meshlet is a self-hosted private networking project. These pages document its architecture, decisions, implementation evidence, and operating procedures. English is the default locale; the Simplified Chinese locale preserves the full Chinese source documents.
