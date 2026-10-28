# P0 Fixes and Nightly Build Record · 2026-10-17

This record summarizes the fixes and release evidence gathered on this date. It distinguishes code checks and hosted workflows from real deployment acceptance.

## Implemented work

The work addressed high-priority correctness and recovery issues, added the Segment domain model and initial persistence path, and tightened server startup and operational behavior. Each implementation item should be read with its corresponding TODO status and tests.

## Nightly delivery

The repository's nightly workflow builds and packages supported artifacts for its configured targets. The recorded hosted run verified artifact creation and download/install-script checks. A successful hosted build is evidence for those targets and steps only; it does not prove a clean VPS deployment or end-to-end device connectivity.

## Evidence and limits

Rust checks, unit and integration suites, console builds, shell linting, and hosted CI provide distinct evidence. Real service installation, effective permissions, WireGuard traffic, LAN forwarding, and restore behavior on a production-like host require the walkthrough. The latest project status lives in `todo.md`; historical green checks must not override current failures or pending acceptance.
