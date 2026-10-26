# Backup and Restore

A backup is a consistent SQLite snapshot, not a synchronization mechanism. The server creates a standalone database snapshot and validates its integrity and schema before reporting success.

## Restore procedure

Stop the server before replacing its active database. The restore command validates the source, upgrades it in a staging file, checks the upgraded schema, and only then atomically replaces the live file. A failed migration leaves the existing database in place.

The order is not just documentation: it is enforced in code. A serving `meshlet-server` holds an exclusive lock on `<database>.lock` ([instance_lock](https://github.com/cuihairu/meshlet/blob/main/apps/server/src/instance_lock.rs)) for the life of the process, and `restore` tries to take the same lock before touching any file — if a server is running, the restore refuses as a whole (`BackupError::Locked`, "stop meshlet-server before restore") and the live database is left untouched. The pre-existing `BEGIN EXCLUSIVE` probe could not catch this case: under WAL an idle server holds no write transaction, so the probe succeeded while the process still owned the old inode. The lock is advisory — it constrains meshlet processes; a foreign process holding a raw SQLite connection still falls through to the `BEGIN EXCLUSIVE` backstop.

Two measured facts from the 2026-10-24 deployment acceptance make that order mandatory:

- **The server must be stopped.** Restoring over a running service renames a new file over the database while the process still holds its old inode: the service stays `active` and the control plane keeps answering, but every later write — including a bootstrap-token mint that returned HTTP 201 — goes to the detached file and never reaches disk. A restart re-adopts the restored database. This is the scenario the instance lock now refuses outright.
- **Ownership repairs itself.** `restore` usually runs as root while the packaged unit runs as an unprivileged user (`User=meshlet`), so a root-owned file would make the service fail with `unable to open database file` and crash-loop. The restore now reinstates the previous owner — the replaced live database, else the data directory. The acceptance run produced `0600 meshlet:meshlet meshlet.db` with the service `active` and `NRestarts=0`.

## Recovery semantics

Startup and restore share the same state-reconstruction path. Device addresses, registrations, routes, invitations, counters, and revision history are loaded from persisted state. A revision interrupted while applying is marked failed with an explicit diagnostic; rollback-pending work remains retryable. Applied state is not inferred merely because a database row exists.

## Operations

Protect backup files because they contain account and network metadata. Keep backups on an independent storage system, test restoration periodically, and retain the migration history needed to upgrade older snapshots. A restored database does not itself restore kernel state; the hub must reconcile its desired plan after startup. Backups are **plaintext** SQLite, equivalent to the database itself and `0600` until they leave the machine — the transport key lives outside the database and needs its own independent copy, which is what undoes a bad key rotation.
