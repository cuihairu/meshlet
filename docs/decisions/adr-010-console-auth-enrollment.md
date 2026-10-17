# ADR-010: Console Authentication and Device Enrollment Security

**Status:** Accepted

## Context

The console manages network-wide changes, while endpoint devices have a separate identity and credential lifecycle. Secrets must not leak into the database or logs.

## Decision

Bootstrap the first administrator once, then use authenticated sessions with CSRF protection for browser writes. External automation uses scoped API tokens. Agents authenticate with device-bound credentials. Store token digests, never raw tokens; device private keys stay on endpoints.

## Enrollment

Invitations provide a controlled join path. Bootstrap registration can create a pending device request that an operator reviews before it receives an address or data-plane plan.

## Rationale and trade-offs

Separating user, API, and agent credentials limits accidental privilege reuse. The first-admin bootstrap window must close after successful setup. Authentication errors should avoid revealing whether a credential or account exists.

## Revisit when

Multi-user roles, delegated network ownership, or an external identity provider become explicit requirements.
