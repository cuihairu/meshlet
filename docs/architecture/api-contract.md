# API Contract

This page summarizes the versioned HTTP API. JSON endpoints use `/api/v1`; management writes require an authenticated session or a token with write scope, plus CSRF protection when session-authenticated. Errors use a consistent envelope with a stable status and a human-readable message.

## Main endpoint groups

- **Authentication:** bootstrap the first administrator once, then log in, inspect the current session, and log out.
- **Networks and devices:** create networks, issue invitations or bootstrap tokens, enroll devices, and inspect registrations and device status.
- **Configuration:** manage LAN routes, Alias mappings, segments, and one-way segment grants; inspect revisions, apply or roll back eligible revisions, and read per-device desired plans.
- **Operations:** read audit events and metrics, run diagnostics, and create or restore database backups.

## Enrollment and data plane

Invite enrollment allocates an Overlay address immediately. Self-registration creates a pending request; an operator must approve it before the device joins the active registry and receives a plan. Agent endpoints authenticate independently from console users and never return private key material.

## Segment grants

Segment management has four endpoints: list/create segments, list/create grants, apply a Pending grant, and revoke a grant. New grants start `pending`; only `applied` grants participate in plan visibility and the desired-config hash. `pending` and `revoked` grant revisions therefore keep the previous plan hash, while applying or revoking an Applied grant changes it.

This grant `apply` transition is not the network-wide revision `apply` operation. It only moves a grant into desired state. The returned `apply_status` always describes the enclosing config revision, so it may remain `pending` until an operator applies that revision. Kernel policy enforcement remains a separate acceptance gate; the API does not claim that traffic has changed until data-plane evidence exists.

The console lists both segments and grants, offers apply/revoke controls for Pending grants, and shows validation errors rather than treating a rejected create as an empty list.

## State and compatibility

Writes that affect desired network state create revisions. `pending` means the desired change is recorded, not that it is active. API tokens are scoped and stored by digest. Presence combines agent reports and tunnel evidence. Clients should handle errors explicitly and avoid treating missing data as an empty success.
