# Hands-on Acceptance Walkthrough

Use this checklist to record real-device behavior that automated tests cannot establish. Record versions, host topology, commands, timestamps, and the result for each step. Never paste private keys, raw bootstrap tokens, or session secrets into the report.

## A. Clean VPS deployment

Install the release artifacts and systemd unit on a clean Linux host. Verify unit syntax, service account, file permissions, loopback binding, HTTPS reverse proxy, and configured WireGuard port. Bootstrap the first administrator and confirm later bootstrap attempts are rejected.

## B. Network and device lifecycle

Create a network, issue a short-lived join credential, enroll a Linux device, and confirm it receives a stable Overlay address. Restart the server and confirm the device and revision remain present. For self-registration, verify the pending device cannot fetch a plan until an operator approves it.

## C. Data-plane behavior

Confirm the hub and agent WireGuard interfaces, inspect peer AllowedIPs, and test bidirectional Overlay traffic. Publish a LAN route and test traffic through the selected gateway and return-path mode. If using an Alias, test both directions and verify the intended translation on the gateway.

## D. Failure and recovery

Interrupt application at controlled points, restart the service, and check that uncertain revisions are visibly failed rather than reported as applied. Restore a backup in a staging environment, verify network and device state, then confirm the hub reconciles its kernel state.

## E. Report

Separate passed, failed, blocked, and untested cases. Include logs and configuration with secrets removed. A test that could not run because of missing privilege or hardware is untested, not passed.
