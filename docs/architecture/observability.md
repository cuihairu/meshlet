# Observability: Structured Logs and Metrics

## Structured events

Server logs use stable fields for operation, network, device or resource, revision, result, and error category. Credential material and private keys must never appear in event payloads. Stable categories make failures filterable without depending on message wording.

## Metrics

Metrics expose request outcomes, revision application, device receipts, route conflicts, and data-plane health. Counters describe events; gauges describe current state. A success ratio is meaningful only after observations exist.

## Read signals together

A recent agent report does not prove a working tunnel. A WireGuard handshake does not prove that routes and NAT are correct. A successful hub apply does not mean every device acknowledged the revision. Operators should correlate these signals with diagnostics and the revision record.

## Operations

Metrics and audit APIs are authenticated. Agent-side status artifacts should tell the user what the agent observed and when it last reconciled. Logging and metrics help locate faults but do not replace network tests.
