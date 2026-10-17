# External Caller Guide

This guide is for scripts and services that call the Meshlet management API. The API is versioned under `/api/v1`; use a scoped API token for automation rather than reusing a browser session.

## Authentication

Create an API token through the authenticated console. The raw token is returned once; the server stores only its digest. Read-only tokens cannot perform writes. Session-authenticated browser writes also require the CSRF header.

## Main operations

Call the network and device endpoints to inspect state, create invitations or bootstrap tokens, and review pending registrations. Route and Alias changes update desired configuration and create a revision. Agents retrieve their own desired plan using their device credential. Diagnostics and audit endpoints expose operational evidence to authorized users.

## Errors and concurrency

Errors use a JSON envelope with an HTTP status and a stable message. Treat `401` as authentication failure, `403` as insufficient scope or CSRF failure, `404` as a missing or intentionally hidden resource, and `409` as a state or conflict rejection. Do not retry a write blindly after an ambiguous network failure; first inspect the resource and revision state.

## Data-plane effects

A successful management response means the control-plane operation was accepted and persisted. It does not necessarily mean the hub and all devices applied the change. Follow the revision and device receipts, then use diagnostics or direct connectivity tests.

## Integration checklist

Keep tokens out of logs, request only required scopes, handle non-2xx responses, use stable resource IDs, and distinguish desired state from applied state. Never submit private keys to the server.
