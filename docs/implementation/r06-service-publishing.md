# R-06: Service Publishing Progress

R-06 remains open. Service forwarding, web publishing, authorization, health checks, and the internal service directory are implemented in the current codebase; a real VPS/device end-to-end acceptance pass is still required.

## Implemented

- TCP and UDP PortForward publish local services through the mesh and preserve the selected transport protocol.
- HTTP and HTTPS publishing routes external traffic to mesh services, including TLS termination at the edge.
- Authorization control is exposed through `POST /api/v1/publish/routes/check`; the server route is wired through the `meshlet-publish` service adapter in `apps/server/src/lib.rs:1015`.
- Health probes validate that a published target is reachable before traffic is admitted.
- The internal DNS service directory supports split-horizon service discovery without overriding public DNS resolution.
- Automated coverage currently reports `cargo test -p meshlet-publish` as 8 passed and `cargo test -p meshlet-server --test publish_check` as 2 passed.

## Outstanding

- Run and archive the real VPS/real-device end-to-end acceptance for published services. The TODO record leaves this item open pending live verification.
