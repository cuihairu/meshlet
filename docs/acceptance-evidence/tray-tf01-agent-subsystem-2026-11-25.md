# TRAY-TF-01 plan item 1 — agent release build is a Windows GUI subsystem

Date: 2026-11-25
Scope: static / install-surface verification of fix commit `41afc88` only. No real-machine run.

## What was verified

`41afc88` gates the subsystem attribute on the build profile:

```
apps/agent/src/main.rs:1
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
```

`debug_assertions` is on by default in the release profile (`[profile.release]` sets only
`lto = "thin"`), so the attribute is active for every release build and the exe lands in
`IMAGE_SUBSYSTEM_WINDOWS_GUI` (2) instead of `IMAGE_SUBSYSTEM_WINDOWS_CUI` (3). Debug builds
keep the console subsystem, which is what local development and CI expect.

Because the release binary has no console, `main` reattaches to the parent console before doing
anything else, so log output still reaches a console when one exists:

```rust
#[cfg(all(windows, not(debug_assertions)))]
fn attach_parent_console() -> bool {
    use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // SAFETY: called once at process start; the argument is the documented parent-console handle
    // constant. Failure only means there is no parent console to attach to (Explorer double-click,
    // an S4U session), which is side-effect free.
    unsafe { AttachConsole(ATTACH_PARENT_PROCESS) != 0 }
}
```

The commit adds the matching `Win32_System_Console` feature to `apps/agent/Cargo.toml`, so the
call resolves rather than failing to link.

## Build and PE readback

Source tree: main at `453951c`.

```
$ cargo build --release --target x86_64-pc-windows-gnu --bin meshlet-agent
    Finished `release` profile [optimized] target(s) in 43.68s

$ python3 -c "import pefile; pe=pefile.PE(path); print(pe.OPTIONAL_HEADER.Subsystem)"
subsystem=2 (IMAGE_SUBSYSTEM_WINDOWS_GUI)

$ sha256sum target/x86_64-pc-windows-gnu/release/meshlet-agent.exe
20c9713212ed3b243befb441ef68402fd9c1214ba185005eab1b19b546fefca4

$ stat -c '%s bytes  %y' target/x86_64-pc-windows-gnu/release/meshlet-agent.exe
17599929 bytes  2026-11-25 16:09:39 +0800
```

Toolchain on the builder: `pefile 2024.8.26` reading the PE optional header directly from the
artifact cargo just produced.

## What this does and does not prove

Proves: a release build of `meshlet-agent` on current main is linked as a GUI subsystem process,
so launching it from Task Scheduler or the startup chain no longer asks Windows to create a
terminal host process. That is the mechanism the field evidence on imac pointed at (a resident
Windows Terminal window with the agent at `subsystem=3`).

Does not prove: the user-visible "terminal pops up then flashes away" behaviour is gone on a real
machine. `schtasks /run` cannot reproduce it (it only proves the process starts) and a headless
SSH session is session 0, where tray icon work is a dead end per the tray-host precedent. Real
click-through reproduction needs plan item 3 (UIAutomation on a machine with a console session),
which is recorded as BLOCKED in todo.md.

## Related

- `26f665d` covers plan item 2: `build_settings_window` / `toggle_popup_window` failures that used
  to go only to `eprintln` (a GUI process has no console, so the message vanished) are now
  appended to `%LOCALAPPDATA%\meshlet\logs\tray.err.log`, write failures staying silent so the
  diagnostic channel cannot become a new failure source.
- A stale `meshlet-agent.exe` (mtime 2026-11-25 06:38, i.e. before `41afc88` was committed at
  07:36) also read back `subsystem=2`. Its source provenance is unknown — the working tree may
  already have carried the attribute uncommitted — so it is **not** usable as a pre-fix
  counterexample. The authoritative readback is the fresh build from current main above; the
  pre-fix `subsystem=3` finding stands on the imac field evidence already recorded in todo.md.