# Hands-on Acceptance Walkthrough

Use this checklist to record real-device behavior that automated tests cannot establish. Record versions, host topology, commands, timestamps, and the result for each step. Never paste private keys, raw bootstrap tokens, or session secrets into the report.

## A. Clean VPS deployment

Install the release artifacts and systemd unit on a clean Linux host. Verify unit syntax, service account, file permissions and loopback binding. Also verify the HTTPS reverse proxy and the configured WireGuard port. Bootstrap the first administrator and confirm later bootstrap attempts are rejected.

## B. Network and device lifecycle

Create a network and issue a short-lived join credential. Then enroll a Linux device and confirm it receives a stable Overlay address. Restart the server and confirm the device and revision remain present. For self-registration, verify the pending device cannot fetch a plan until an operator approves it.

## C. Data-plane behavior

Confirm the hub and agent WireGuard interfaces, inspect peer AllowedIPs, and test bidirectional Overlay traffic. Publish a LAN route and test traffic through the selected gateway and return-path mode. If using an Alias, test both directions and verify the intended translation on the gateway.

**Firewall automation (AGENT-FW-1/2):** with the mesh interface applied, confirm the agent opened it in the host firewall. No manual intervention is needed. On Windows: the interface must report NetworkCategory **Private** (not Public). An inbound Meshlet-ICMPv4-In rule must exist, scoped to the device's Overlay address for ICMPv4 echo. A remote peer then pings the device's Overlay address directly. On Linux: start with ufw (or firewalld) active before the agent starts. The apply must add `ufw allow in on <if>` or place the interface in the trusted zone. A remote peer pings the device after apply. Re-run the apply and confirm no duplicate rules are added (idempotent regression).

## D. Failure and recovery

Interrupt application at controlled points and restart the service. Check that uncertain revisions are visibly failed rather than reported as applied. Restore a backup in a staging environment and verify network and device state. Then confirm the hub reconciles its kernel state.

## E. Report

Separate passed, failed, blocked, and untested cases. Include logs and configuration with secrets removed. A test that could not run because of missing privilege or hardware is untested, not passed.
