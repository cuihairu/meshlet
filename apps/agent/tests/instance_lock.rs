//! Single-instance guard coverage（P0，2026-11-12 imac 实锤：3 个 meshlet-agent
//! 并存互踢同一个 device_id，server 侧 0 条断连日志）。
//!
//! 这里测的是**真实进程**的行为，不是库函数：第一个进程持有锁，第二个进程必须
//! 以失败退出码启动不了、并把原因打到 stderr。互斥本身由 OS 做（flock /
//! LockFileEx，锁挂在打开的文件描述上、进程崩溃自动释放）；库层
//! [`meshlet_agent::instance_lock`] 的单测另覆盖双路 open 的拒绝与释放。

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

/// 写一份**最小可启动**的配置：数据面打开（才会走到抢锁那一步）；带一个
/// `device_token` 但 server 指到必然连不上的地址。持有者因此不会在凭证解析上
/// 立刻退出，而是留在轮询循环里——**它必须活着**，否则一退出就释放锁，
/// 第二个进程会抢空锁，这个测试就退化成假绿。
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

/// 等进程把锁文件落下来（它自己 `create_dir_all` + 开锁）。
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

/// 双进程互斥：持有者活着时，第二个进程必须失败退出并说清原因；持有者退出
/// （释放锁）后，第三个进程必须能正常拿到锁——守卫不能把正常重启也挡住。
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

    // 阶段一：持有者拿到锁并留在循环里。
    let mut first = spawn(&config);
    wait_for_lock_file(&lock_file);
    // 留一点时间让它走完初始化（初始化途中退出会释放锁，把测试变成假绿）。
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        first.try_wait().expect("peek at the holder").is_none(),
        "the holder must stay alive while holding the lock, otherwise there is no contention to measure"
    );

    // 阶段二：第二个进程必须立刻被拒，且说清是锁被占。
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

    // 阶段三：持有者退出即释放锁，下一个进程可以正常启动。
    let _ = first.kill();
    let _ = first.wait();

    let mut third = spawn(&config);
    // 被拒的进程会**立刻**退出；正常的进程会留下来轮询。2 秒内退出即判失败。
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
