# Backup and Restore

A backup is a consistent SQLite snapshot, not a synchronization mechanism. The server creates a standalone database snapshot and validates its integrity and schema before reporting success.

## Restore procedure

Stop the server before replacing its active database. The restore command validates the source, upgrades it in a staging file, checks the upgraded schema, and only then atomically replaces the live file. A failed migration leaves the existing database in place.

## Recovery semantics

Startup and restore share the same state-reconstruction path. Device addresses, registrations, routes, invitations, counters, and revision history are loaded from persisted state. A revision interrupted while applying is marked failed with an explicit diagnostic; rollback-pending work remains retryable. Applied state is not inferred merely because a database row exists.

## Operations

Protect backup files because they contain account and network metadata. Keep backups on an independent storage system, test restoration periodically, and retain the migration history needed to upgrade older snapshots. A restored database does not itself restore kernel state; the hub must reconcile its desired plan after startup.
