# Configuration State, Identity, and Security

## Revision lifecycle

Every change that affects desired network behavior creates a numbered revision. Revisions move through pending,
 applying, applied, failed, and rollback states. A database write is not proof of application;
 device acknowledgements and backend results provide separate evidence.

## Identity and credentials

Console users authenticate with sessions protected by CSRF checks on writes.
 External automation can use scoped API tokens. Agents use their own credentials.
 Invitations and bootstrap tokens are stored as digests, and device private keys remain on the device.

## Security boundaries

Pending registrations do not enter the active device registry or receive network plans.
 Operators approve them before address allocation and configuration inclusion.
 Audit events record management actions without exposing raw credentials.

## Verification

Tests cover validation, credential boundaries, revision transitions, and recovery.
 Privileged Linux networking and real-host behavior require the corresponding network-namespace or deployment evidence;
 unit tests alone do not establish them.

## SSH alias distribution

The hub can distribute SSH host aliases for every active device in a network, so operators can reach peers as `ssh <alias>` through the overlay.

- Hub side: the `[ssh_config]` TOML section is the explicit enable switch. Its absence means the hub does not distribute aliases at all.
  Per-device overrides live under `[ssh_config.overrides.<device-name>]` with optional `alias`, `user`, and `port` keys.
- Agent side: `[ssh_config_sync]` defaults to off. Enabling it (`enabled = true`) writes only the meshlet-owned fragment `~/.ssh/meshlet.conf` atomically with mode `0600`.
  The optional `manage_include = true` appends a single `Include meshlet.conf` line to `~/.ssh/config`, backing up the user's file once before the first modification.
- Alias resolution is three-tier and honestly labeled: hub override (`hub-config`) > the device's reported hostname (`hostname`) > meshlet peer name (`peer-name`).
- Absent plans (hub off or an older server) do not serialize the `ssh_config` field, so the existing `desired_config_hash` stays byte-identical and upgrades never trigger a full replay.
