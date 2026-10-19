# Readiness Assessment · 2026-10-19

## Scope and counting method

This assessment answers “how long until Meshlet can be used?” without making a calendar promise. It counts the 33 top-level entries in `TODO.md`'s “Current execution checklist (2026-10-17)” (AR-01…06, REL-01/02, CR-01…05, QA-01, RG-01…03, PN-01…10, MOD-01…06). A partially implemented item is counted by its remaining acceptance work, not by the code that already exists. IM-01…12 are implementation records and are not additional product checklist items.

## Status by acceptance state

| State | Count | Entries |
|---|---:|---|
| Accepted within stated scope | 6 | REL-01; CR-01…05 |
| Implemented evidence, environment walkthrough pending | 11 | AR-01…06; REL-02; QA-01; RG-01; RG-02 (partial acceptance); PN-07 (partial acceptance) |
| Design needed | 13 | RG-03; PN-02, PN-04…06, PN-08…09; MOD-01…06 |
| Implementation/acceptance work remains | 2 | PN-01 (authorization model/API and kernel enforcement); PN-03 (complete Windows client) |
| Deferred | 1 | PN-10 |
| **Total** | **33** | |

“Accepted” is scoped to the evidence written in TODO; it does not mean the product is fully accepted for deployment. RG-02 and PN-07 retain substantial unaccepted behavior and are therefore in the environment-validation bucket for this status rollup, with design/implementation dependencies called out below.

## P0 closure dependencies

The explicit P0 rows total 14 (AR-01…06, REL-01/02, CR-01…05 and QA-01); including RG-02, marked “P0 verification”, makes 15. Six are accepted within scope; the remaining nine are environment-validation items by top-level status. RG-02 is not environment-only: its remaining return-mode, same-gateway, business-failure, backup/restore and conflict/preflight criteria depend on design and implementation, notably RG-03. The status count describes the current primary state, not a claim that all acceptance criteria are runnable as-is.

| P0 item(s) | Remaining dependency | Engineering time vs. waiting for environment |
|---|---|---|
| AR-01…05 | Real VPS deployment/topology walkthrough to confirm isolation, receipt state, drift recovery, last-good rollback and Direct/Alias × source-preservation/SNAT behavior together | Test execution and evidence collection; waiting for access to a disposable VPS and its network. Local netns evidence already exists. |
| AR-06, REL-02 | Empty Linux VPS install/upgrade using the published package, then inspect service account, key/config preservation and service behavior | Walkthrough and any defects found; waiting for an empty VPS. |
| QA-01 | Run and record the final independent dataplane acceptance matrix on a real VPS; skipped privileged cases remain non-passes | Mostly execution/evidence; waiting for VPS access. |
| AR-02, RG-02 real-device portions | Exercise approval, plan receipt, LAN access, revoke/restart and failure behavior with actual devices and networks | Walkthrough; waiting for at least two reachable real devices and the relevant LAN topology. Local Linux netns cases cover only their stated scope. |

**Immediately dispatchable / environment-only closure list:** AR-01…06, REL-02 and QA-01 can be assigned now to an operator with an empty/disposable Linux VPS; the real-device portions of RG-02 need devices and LAN access. RG-01 also has code-level route-model evidence but needs topology testing. RG-02 still has specified design/implementation gaps (return-mode changes, same-gateway ambiguity, failure recovery, backup/restore and RG-03 conflict/preflight), so it is not environment-only as a whole. PN-07 needs implementation/design work for listener ingress, loopback backends, per-port mapping, UDP sessions and PN-02 policy, in addition to any live-network validation.

## What “usable for daily use” means

The product boundary remains personal self-hosting on user-controlled devices and networks, with grouped devices, controlled port forwarding and HTTP service routing (TODO.md opening paragraph). Under that boundary:

**Minimum usable set (MVP):** a self-hosted Linux VPS hub; Linux agent install and enrollment; administrator bootstrap/login, device approval and scoped API token; versioned desired-plan apply with device receipt; recovery and rollback; private Overlay connectivity; LAN route/Alias configuration for an explicitly tested topology; backup/restore procedure; logs/status sufficient to diagnose whether hub, device and business connectivity succeeded. This is **10 concrete capability groups**: (1) install/server, (2) agent, (3) identity/enrollment, (4) plan/apply receipt, (5) recovery/rollback, (6) Overlay, (7) LAN route/Alias, (8) backup/restore, (9) status/diagnostics, (10) deployment and data-plane acceptance on target topology. This is a usable *Linux personal self-hosting slice*, not a claim that all ten groups are presently production-accepted: the real VPS/device walkthroughs remain outstanding.

**Complete usable set** adds the remaining intended personal workflow: fully accepted multi-network isolation and gateways, complete conflict detection, segment authorization enforced in the kernel, complete Windows agent/tunnel lifecycle, tested inbound TCP/UDP port forwarding and HTTP routing, supported platform/device walkthroughs, and the remaining operational acceptance matrix. P2/P1 connection experiments (NAT traversal, TCP fallback, public relay) and PN-10 are not required to call the stated MVP usable; their value should be judged from measured need.

## Recommended order, by dependency

1. Provide a disposable empty Linux VPS and close AR-06/REL-02 first; this validates the install and service boundary.
2. On that deployment, run AR-01…05 and QA-01, recording each independent acceptance result rather than a single “works” verdict.
3. Walk through a real Linux device enrollment/apply/receipt, LAN access, revoke and restart; close AR-02 and the environment-dependent portions of RG-02.
4. Resolve RG-03 conflict semantics and PN-01/PN-02 design/implementation before expanding segment policy or treating forwarding as broadly available.
5. Implement and validate PN-03 only when Windows is part of the target device set; complete PN-07/PN-08 when controlled service exposure is required.
6. Consider MOD work and PN-04…06 from actual consumer/connection needs; MOD-05 remains explicitly on-demand.

The answer to “how long?” is therefore a dependency list, not a date: the P0 remainder is presently dominated by environment access and walkthrough work, while the complete personal product still has explicit design and implementation work. A VPS can close the listed VPS-only items immediately once supplied; it cannot close Windows, real-device, RG-03, PN-01/02 or the remaining PN-07 behavior by itself.

