# System Architecture and Technology Choices

## Control plane and data plane

The server owns network membership, addressing, invitations, desired configuration revisions, authentication, and audit records. The WireGuard hub and endpoint agents carry traffic and apply network changes. A database write records desired state; it does not by itself prove that the data plane has converged.

## Technology

The project is a Rust workspace. SQLite is the initial control-plane store, with SQLx migrations and a single-writer connection pool. The web console is a React application built separately and served as static content. WireGuard provides the encrypted tunnel, while Linux networking tools implement routes and NAT.

## Workspace boundaries

The domain crate owns entities, IPAM, validation, and revision logic. The server crate exposes APIs and persists state. The agent reconciles desired plans with the local host. Network backends isolate operating-system effects so that planning can be tested separately from privileged execution.

## Constraints

The first topology uses a VPS hub as a relay. Linux is the initial complete backend; Windows support remains a separate implementation and acceptance effort. Keep the control plane independent from kernel effects, and make every production claim match its actual test topology.
