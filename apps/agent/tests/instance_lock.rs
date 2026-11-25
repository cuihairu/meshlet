//! Single-instance guard coverage (P0, confirmed on the 2026-11-12 imac: three meshlet-agent
//! processes coexisted and kicked each other off the same device_id, with 0 disconnect logs on the server).
//!
//! This exercises **real process** behaviour, not library functions: the first process holds the
//! lock, and the second must fail to start with a nonzero exit code and print the reason to
//! stderr. The mutual exclusion itself is the OS's job (flock / LockFileEx — the lock attaches to
//! the open file description and is released automatically on process crash); the library-level
//! unit tests for [`meshlet_agent::instance_lock`] separately cover rejection and release across two opens.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const LOCK_HOLD_MESSAGE: &str = "another instance is already running";

fn bin() -> PathBuf {
    let name = if cfg!(windows) {
        "meshlet-agent.exe"
    } else {
        "meshlet-agent"
    };
    let exe = env!("CARGO_BIN_EXE_meshlet-agent");
    assert!(
        exe.ends_with(name),
        "unexpected binary name: {exe} (expected it to end with {name})"
    );
    PathBuf::from(exe)
}

/// Write a **minimally bootable** config: the data plane is enabled (so it reaches the
/// lock-acquisition step), and it carries a `device_token` while the server points at an address
/// that can never connect. The holder therefore does not bail out during credential resolution, but stays in its poll loop — **it must stay alive**, otherwise exiting releases the lock, the second process grabs an empty lock, and this test degrades to a false green.
fn write_config(root: &Path, state_dir: &Path) -> PathBuf {
    let path = root.join("agent.toml");
    let toml = format!(
        r#"state_dir = "{state}"
server_url = "https://127.0.0.1:9"
device_token = "test-token"

[dataplane]
enabled = true
interface = "wg-meshlet"
hub_endpoint = "127.0.0.1:9"
poll_interval_secs = 30
"#,
        state = state_dir.display().to_string().replace('\\', "\\\\"),
    );
    fs::write(&path, toml).unwrap();
    path
}

fn spawn(config: &Path) -> Child {
    Command::new(bin())
        .arg(config)
        .env("RUST_LOG", "info")
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn meshlet-agent")
}

fn stderr_text(child: &mut Child) -> String {
    let Some(mut handle) = child.stderr.take() else {
        return String::new();
    };
    let mut buf = String::new();
    if handle.read_to_string(&mut buf).is_ok() {
        return buf;
    }
    String::new()
}

/// Wait for the process to drop the lock file (it does its own `create_dir_all` plus lock open).
fn wait_for_lock_file(lock_file: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !lock_file.is_file() {
        assert!(
            Instant::now() < deadline,
            "the lock file {} never appeared",
            lock_file.display()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Two-process mutual exclusion: while the holder is alive, the second process must exit with
/// failure and state the reason; after the holder exits (releasing the lock), a third process must acquire it normally — the guard must not block ordinary restarts.
#[test]
fn second_process_is_rejected_while_the_first_holds_the_lock() {
    let root = std::env::temp_dir().join(format!(
        "meshlet-agent-instance-lock-it-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let state_dir = root.join("state");
    let config = write_config(&root, &state_dir);
    let lock_file = state_dir.join("agent.lock");

    // Phase 1: the holder grabs the lock and stays in the loop.
    let mut first = spawn(&config);
    wait_for_lock_file(&lock_file);
    // Give it a moment to finish initializing (bailing out mid-init would release the lock and make this test falsely green).
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        first.try_wait().expect("peek at the holder").is_none(),
        "the holder must stay alive while holding the lock, otherwise there is no contention to measure"
    );

    // Phase 2: the second process must be rejected immediately, naming the held lock as the reason.
    let mut second = spawn(&config);
    let start = Instant::now();
    let status = second.wait().expect("the second process exits");
    let rejected = stderr_text(&mut second);
    assert!(
        !status.success(),
        "the second process must fail to start, but it exited successfully (stderr: {rejected})"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "rejection must be immediate, took {:?}",
        start.elapsed()
    );
    assert!(
        rejected.contains(LOCK_HOLD_MESSAGE),
        "stderr must name the reason, got: {rejected}"
    );
    assert!(
        rejected.contains("agent.lock"),
        "stderr must point at the lock file, got: {rejected}"
    );

    // Phase 3: the holder exiting releases the lock, so the next process can start normally.
    let _ = first.kill();
    let _ = first.wait();

    let mut third = spawn(&config);
    // A rejected process exits **immediately**; a healthy one stays polling. Exiting within 2s counts as failure.
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if third
            .try_wait()
            .expect("peek at the third process")
            .is_some()
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if third.try_wait().expect("peek again").is_some() {
        panic!(
            "after the holder exits the lock must be acquirable, but the third process died (stderr: {})",
            stderr_text(&mut third)
        );
    }

    let _ = third.kill();
    let _ = third.wait();
    let _ = fs::remove_dir_all(&root);
}
