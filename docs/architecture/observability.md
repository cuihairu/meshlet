# Observability: Structured Logs and Metrics

## Structured events

Server logs use stable fields for operation, network, device or resource, revision, result, and error category. Credential material and private keys must never appear in event payloads. Stable categories make failures filterable without depending on message wording.

## Metrics

Metrics expose request outcomes, revision application, device receipts, route conflicts, and data-plane health. Counters describe events; gauges describe current state. A success ratio is meaningful only after observations exist.

## Read signals together

A recent agent report does not prove a working tunnel. A WireGuard handshake does not prove that routes and NAT are correct. A successful hub apply does not mean every device acknowledged the revision. Operators should correlate these signals with diagnostics and the revision record.

## Operations

Metrics and audit APIs are authenticated. Agent-side status artifacts should tell the user what the agent observed and when it last reconciled. Logging and metrics help locate faults but do not replace network tests.

## Agent-side artifacts

The agent writes its ledger and decision history under `{state_dir}`. These are the operator-facing evidence for dataplane behavior:

| Artifact | Written by | What it records |
| --- | --- | --- |
| `applied.json` | agent reconcile loop | last successfully applied plan hash, routes/NAT ownership |
| `direct.json`, `direct-peers.json` | `apps/agent/src/agent/direct.rs:194,225` | direct-peer view: server candidates merged with current link state (topology page source) |
| `agent-decisions.jsonl` | `crates/meshlet-network/src/dial.rs:245` (`DecisionEvent`, `:217`) | one line per candidate decision — `action` ∈ `promote` / `demote` / `hold_relay` / `probe` / `defer`, with from/to mode, handshake age, SEL-003 degraded flag, endpoint and probe window. Rolls to `.jsonl.1` at 8 MiB |
| `direct-switch-events.json` | `crates/meshlet-network/src/dial.rs:127` (`SwitchEvent`, `:95`) | one line per successful `wg set endpoint` roam; `kind = mode_flip` events carry direct mode changes (`p2p_direct` ↔ `direct_pending` ↔ `hub_relay`) with the criteria summary (written at `apps/agent/src/agent/direct.rs:370`) |
| `direct-dial.json` | `crates/meshlet-network/src/dial.rs:122` | active dial requests |
| `status.json`, `tasks.json`, `ssh-sync.json`, `restart-requested.json`, `agent.lock`, `tray/` | agent | state, task queue, tray status PNGs and lock state |

Read `agent-decisions.jsonl` and `direct-switch-events.json` first when a link flaps or a direct edge disappears; the metrics only show that a switch happened, these show why.
