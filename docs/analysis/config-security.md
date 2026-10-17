# Configuration State, Identity, and Security

## Revision lifecycle

Every change that affects desired network behavior creates a numbered revision. Revisions move through pending, applying, applied, failed, and rollback states. A database write is not proof of application; device acknowledgements and backend results provide separate evidence.

## Identity and credentials

Console users authenticate with sessions protected by CSRF checks on writes. External automation can use scoped API tokens. Agents use their own credentials. Invitations and bootstrap tokens are stored as digests, and device private keys remain on the device.

## Security boundaries

Pending registrations do not enter the active device registry or receive network plans. Operators approve them before address allocation and configuration inclusion. Audit events record management actions without exposing raw credentials.

## Verification

Tests cover validation, credential boundaries, revision transitions, and recovery. Privileged Linux networking and real-host behavior require the corresponding network-namespace or deployment evidence; unit tests alone do not establish them.
