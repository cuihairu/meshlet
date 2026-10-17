# Windows and Linux Platform Notes

## Support status

Linux is the first complete networking target. It uses WireGuard and host route/NAT operations with explicit ownership and reconciliation. Windows support is a separate backend effort; a command wrapper or partial prototype does not establish a complete agent.

## Windows work still needed

A production Windows client needs tunnel service lifecycle, elevation and least privilege, route management, reboot recovery, cleanup after interrupted operations, and clear reporting. Test service install/uninstall, repeated apply, failures at each operation stage, and recovery after restart.

## Linux constraints

The hub and agent need a clear privilege boundary. Service account permissions must match the chosen execution model, and every route or firewall change must be attributable to Meshlet. Tests in a network namespace are valuable but should be distinguished from verification on a real host.

## Planning

Keep platform-specific operations behind backend interfaces while sharing domain rules and plan semantics. Prioritize support using user need and a verifiable acceptance environment.
