# Windows and Linux Platform Notes

## Support status

Linux is the first complete networking target. It uses WireGuard and host route/NAT operations with explicit ownership and reconciliation. Windows is a second backend, now wired: `SystemBackend` maps to the real Windows implementation for tunnel, routes and device plans, and the R-05 real-machine acceptance items passed on 2026-11-12 ([R-05](../implementation/r05-windows-acceptance.md), ADR-008).

## Windows acceptance state

The tunnel service lifecycle, elevation exec, boot recovery and route management items passed on real machines on 2026-11-12; the MSI/tray-host installer and the end-to-end apply walkthrough passed on 2026-11-13. A command wrapper or partial prototype does not establish a complete agent — the acceptance record is what counts. Remaining open items: NAT-bearing plans are explicitly rejected per ADR-008, wide cross-NAT punch scenarios still need real-machine acceptance, and the long-run soak needs weeks of data.

## Linux constraints

The hub and agent need a clear privilege boundary. Service account permissions must match the chosen execution model, and every route or firewall change must be attributable to Meshlet. Tests in a network namespace are valuable but should be distinguished from verification on a real host.

## Planning

Keep platform-specific operations behind backend interfaces while sharing domain rules and plan semantics. Prioritize support using user need and a verifiable acceptance environment.
