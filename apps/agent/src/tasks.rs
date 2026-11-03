//! 任务执行（MT-002 下发与回执）：agent 拉取服务端下发的待办任务，ack →
//! 执行 → 回执结果。
//!
//! 这是既有「绝不执行服务端下发的任意 Shell 命令」纪律的**显式例外**（MT-002
//! 用户令）：任务由控制台用户经 `task.assigned` 审计显式派发，agent 端点一律
//! Bearer 凭证认证（[`crate::server`] 同一认证边界）。
//!
//! 幂等语义（断线补派不重复执行，对齐服务端 `task id` 幂等键）：
//! - 本地账本 `{state_dir}/tasks.json` 记录**已执行**任务 id → 结果；
//! - 账本里已有的 id 只**补报结果、绝不重跑**（服务端对重复回执幂等：终态
//!   重复回执只更新日志尾部，不改变终态）；
//! - 执行顺序：ack（失败本轮不跑，下轮重试）→ 跑命令 → **先落账本** → 回执。
//!   崩溃在「跑完未回执」间隙 → 账本已落 → 重连补报不重跑；崩溃在「ack 后
//!   未跑完」→ 账本没有 → 服务端重派 → 重跑（上次未跑完，重跑正确）。
//!
//! 边界：任务在 agent 主循环内联执行（同步 tick），长任务会暂时挡住心跳——
//! MT-005 再引入并发排程/超时重派；本版只保证「执行 + 幂等 + 回执」。

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use meshlet_domain::{Task, TaskPayload};

use crate::server;

/// 账本容量上限：超出剔除最旧（task id 按 `task-{seq}` 递增，字典序=时间序）。
const LEDGER_CAP: usize = 512;
/// 命令输出尾部保留字节数（超出丢弃头部，保留最近段）。
const TAIL_BYTES: usize = 4096;
/// 进程状态轮询间隔（毫秒）。
const POLL: Duration = Duration::from_millis(20);
/// 命令无法启动的退出码（shell 惯例 127 = command not found）。
const SPAWN_FAIL_EXIT: i32 = 127;
/// 未显式指定超时时的默认超时（秒，`TaskPayload.timeout_secs` 契约值）。
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// 一次执行的结果（与服务端 `TaskResultReport` 同构：exit_code + log_tail）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskResult {
    /// 进程退出码（0 = 成功，非 0 = 失败）。
    pub exit_code: i32,
    /// 命令输出尾部（stdout+stderr 合并后的最后若干字节）。
    pub log_tail: String,
}

/// 已执行任务账本：task id → 结果。断线重连后据此**补报**，绝不重跑。
#[derive(Debug, Default)]
pub struct TaskLedger {
    entries: BTreeMap<String, TaskResult>,
}

impl TaskLedger {
    /// 从 `{state_dir}/tasks.json` 载入；缺失/损坏按空账本处理（损坏要显式
    /// 告警，绝不静默——空账本意味着「全部任务可重跑」，这是安全边界）。
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => {
                let entries = serde_json::from_slice::<BTreeMap<String, TaskResult>>(&bytes)
                    .unwrap_or_else(|e| {
                        tracing::warn!(path = %path.display(), error = %e, "task ledger corrupt; starting empty");
                        BTreeMap::new()
                    });
                Self { entries }
            }
            Err(_) => Self::default(),
        }
    }

    /// 落盘（先建父目录；失败显式报出，由调用方决定）。
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec(&self.entries).unwrap_or_default();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, bytes)
    }

    /// 是否已执行过（幂等：已执行的只补报，不重跑）。
    pub fn has(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    /// 已执行任务的结果。
    pub fn result(&self, id: &str) -> Option<&TaskResult> {
        self.entries.get(id)
    }

    /// 记录一次执行结果；超出容量剔除最旧（`task-{seq}` 字典序最小=最早）。
    pub fn record(&mut self, id: String, result: TaskResult) {
        self.entries.insert(id.clone(), result);
        if self.entries.len() > LEDGER_CAP {
            if let Some(oldest) = self.entries.keys().next().cloned() {
                self.entries.remove(&oldest);
            }
        }
    }
}

/// 纯决策（可单测）：账本已有该任务 → 补报结果；否则执行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decide {
    /// 已执行过：断线补派只补报，绝不重跑。
    ReReport(TaskResult),
    /// 未执行：ack → 跑 → 落账本 → 回执。
    Execute,
}

/// 决策（幂等去重，纯函数，无 I/O）。
pub(crate) fn decide(ledger: &TaskLedger, task: &Task) -> Decide {
    match ledger.result(&task.id.to_string()) {
        Some(result) => Decide::ReReport(result.clone()),
        None => Decide::Execute,
    }
}

/// 拉取本设备待办（assigned / acked）。
pub fn fetch_pending(server_url: &str, token: &str) -> Result<Vec<Task>, String> {
    let url = format!(
        "{}/api/v1/agent/tasks/pending",
        server_url.trim_end_matches('/')
    );
    let req = ureq::get(&url).set("authorization", &format!("Bearer {token}"));
    let body = server::read_response(req.call())?;
    serde_json::from_str(&body).map_err(|e| format!("parse pending tasks: {e}"))
}

/// 确认接收（幂等：已越过 assigned 时服务端仍返回 200，不跃迁不落库）。
pub fn ack_task(server_url: &str, token: &str, id: &str) -> Result<(), String> {
    let url = format!(
        "{}/api/v1/agent/tasks/{id}/ack",
        server_url.trim_end_matches('/')
    );
    server::read_response(
        ureq::post(&url)
            .set("authorization", &format!("Bearer {token}"))
            .send_bytes(&[]),
    )
    .map(|_| ())
}

/// 回传结果（幂等：终态重复回执只更新日志尾部，不改变终态）。
pub fn report_result(
    server_url: &str,
    token: &str,
    id: &str,
    result: &TaskResult,
) -> Result<(), String> {
    let url = format!(
        "{}/api/v1/agent/tasks/{id}/result",
        server_url.trim_end_matches('/')
    );
    let payload = serde_json::json!({
        "exit_code": result.exit_code,
        "log_tail": result.log_tail,
    })
    .to_string();
    server::read_response(
        ureq::post(&url)
            .set("authorization", &format!("Bearer {token}"))
            .set("content-type", "application/json")
            .send(payload.as_bytes()),
    )
    .map(|_| ())
}

/// 处理一个任务：账本已有 → 补报；否则 ack → 跑 → 落账本 → 回执。
/// `on_arrival` 在 ack 成功后、执行前触发一次（MT-004：任务到达即托盘气泡；
/// 断线补派的 ReReport 不是到达，不触发）。
/// `Err` 表示本轮跳过（网络失败，下轮重试）；回执失败已在内部记日志并落账本，
/// 不返回 `Err`（账本已记录，下轮补报，不触发外层退避）。
pub fn process_one(
    server_url: &str,
    token: &str,
    ledger: &mut TaskLedger,
    ledger_path: &Path,
    task: &Task,
    on_arrival: &mut dyn FnMut(&Task),
) -> Result<(), String> {
    let id = task.id.to_string();
    match decide(ledger, task) {
        Decide::ReReport(result) => {
            tracing::info!(task = %id, "task already executed; re-reporting result");
            report_result(server_url, token, &id, &result)?;
            Ok(())
        }
        Decide::Execute => {
            // ack 失败本轮不跑：保证服务端状态机顺序（assigned → acked → ...）。
            ack_task(server_url, token, &id)?;
            on_arrival(task);
            let result = run_task(&task.payload);
            // 先落账本再回执：崩溃在间隙 → 重连补报不重跑。
            ledger.record(id.clone(), result.clone());
            ledger
                .save(ledger_path)
                .map_err(|e| format!("persist task ledger: {e}"))?;
            if let Err(e) = report_result(server_url, token, &id, &result) {
                tracing::warn!(task = %id, error = %e, "task result not delivered; will re-report");
            }
            tracing::info!(task = %id, exit_code = result.exit_code, "task executed");
            Ok(())
        }
    }
}

/// 处理本设备全部待办。拉取失败 `Err`（下轮重试）；单任务失败只记日志，
/// 不影响其余任务与数据面循环。`on_arrival` 对每个新到达任务触发一次。
pub fn process_pending(
    server_url: &str,
    token: &str,
    ledger: &mut TaskLedger,
    ledger_path: &Path,
    on_arrival: &mut dyn FnMut(&Task),
) -> Result<(), String> {
    let pending = fetch_pending(server_url, token)?;
    for task in &pending {
        if let Err(e) = process_one(server_url, token, ledger, ledger_path, task, on_arrival) {
            tracing::warn!(task = %task.id, error = %e, "task processing deferred to next tick");
        }
    }
    Ok(())
}

/// 执行一次任务（MT-002 显式例外：运行服务端下发的命令）。
///
/// 平台 shell：unix `sh -c`，Windows `cmd /C`。超时默认
/// [DEFAULT_TIMEOUT_SECS]；超时 kill 子进程（退出码非 0 → 服务端判失败）。
pub fn run_task(payload: &TaskPayload) -> TaskResult {
    let mut cmd = shell_command(&payload.cmd);
    if let Some(workdir) = &payload.workdir {
        cmd.current_dir(workdir);
    }
    // unix：把子进程放进自己的进程组——shell 会 fork 子命令（如
    // `sh -c "sleep 30"` 里 `sleep` 是直接子进程的孙进程），超时 kill 必须
    // 杀掉整组，否则孤儿子进程会继续跑满超时并占着管道。
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = match cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(child) => child,
        Err(e) => {
            return TaskResult {
                exit_code: SPAWN_FAIL_EXIT,
                log_tail: format!("spawn failed: {e}"),
            };
        }
    };
    // 后台读 stdout/stderr 尾部（否则管道缓冲填满会阻塞子进程）。两类管道
    // 类型不同（ChildStdout/ChildStderr），擦成 `Box<dyn Read + Send>` 统一处理。
    let tail = Arc::new(Mutex::new(TailBuffer::new()));
    let mut readers = Vec::new();
    let pipes: [Option<Box<dyn Read + Send>>; 2] = [
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    ];
    for pipe in pipes.into_iter().flatten() {
        let tail = Arc::clone(&tail);
        readers.push(std::thread::spawn(move || {
            let mut pipe = pipe;
            let mut buf = [0u8; 4096];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => tail.lock().unwrap().push(&buf[..n]),
                    Err(_) => break,
                }
            }
        }));
    }
    let status = wait_with_timeout(
        &mut child,
        payload.timeout_secs.unwrap_or(DEFAULT_TIMEOUT_SECS),
    );
    for reader in readers {
        let _ = reader.join();
    }
    let log_tail = tail.lock().unwrap().drain();
    TaskResult {
        exit_code: status.code().unwrap_or(1),
        log_tail,
    }
}

/// 平台 shell 命令构造。
fn shell_command(cmd: &str) -> Command {
    #[cfg(windows)]
    {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(cmd);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    }
}

/// 等待子进程退出，超过 `timeout_secs` kill 后收割。返回退出状态（kill 后
/// `code()` 为 `None`，由调用方映射为失败）。
fn wait_with_timeout(child: &mut Child, timeout_secs: u64) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Some(status) = child.try_wait().expect("poll child status") {
            return status;
        }
        if Instant::now() >= deadline {
            kill_child(child);
            loop {
                if let Some(status) = child.try_wait().expect("reap child") {
                    return status;
                }
                std::thread::sleep(POLL);
            }
        }
        std::thread::sleep(POLL);
    }
}

/// 终止子进程（含整组）：unix 先 `kill(-pid, SIGKILL)` 杀进程组（见
/// `run_task` 的 `process_group(0)`），再兜底 `child.kill()` 杀直接子进程；
/// Windows 无进程组，退化为 `child.kill()`。
fn kill_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let pgid = child.id() as libc::pid_t;
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
}

/// 输出尾部缓冲：只保留最近 [TAIL_BYTES] 字节。
struct TailBuffer {
    bytes: Vec<u8>,
}

impl TailBuffer {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn push(&mut self, chunk: &[u8]) {
        self.bytes.extend_from_slice(chunk);
        if self.bytes.len() > TAIL_BYTES {
            let drop = self.bytes.len() - TAIL_BYTES;
            self.bytes.drain(..drop);
        }
    }

    fn drain(&mut self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(cmd: &str) -> TaskPayload {
        TaskPayload {
            cmd: cmd.to_string(),
            workdir: None,
            timeout_secs: None,
        }
    }

    fn task(id: &str, cmd: &str) -> Task {
        use meshlet_domain::TaskState;
        use meshlet_domain::{DeviceId, TaskId};
        Task {
            id: TaskId(id.to_string()),
            target_node: DeviceId("dev-1".to_string()),
            payload: payload(cmd),
            state: TaskState::Assigned,
            retry_limit: 0,
            result_ref: None,
        }
    }

    #[test]
    fn ledger_round_trips_through_disk() {
        let dir = std::env::temp_dir().join(format!("meshlet-task-ledger-{}", std::process::id()));
        let path = dir.join("tasks.json");
        let mut ledger = TaskLedger::default();
        ledger.record(
            "task-1".into(),
            TaskResult {
                exit_code: 0,
                log_tail: "ok".into(),
            },
        );
        ledger.save(&path).expect("save");
        let loaded = TaskLedger::load(&path);
        assert!(loaded.has("task-1"));
        assert_eq!(loaded.result("task-1").unwrap().exit_code, 0);
        assert!(!loaded.has("task-2"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ledger_corrupt_file_starts_empty_without_panic() {
        let dir = std::env::temp_dir().join(format!("meshlet-task-corrupt-{}", std::process::id()));
        let path = dir.join("tasks.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "not json").unwrap();
        let ledger = TaskLedger::load(&path);
        assert!(!ledger.has("task-1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ledger_evicts_oldest_over_capacity() {
        let mut ledger = TaskLedger::default();
        for i in 0..(LEDGER_CAP + 10) {
            ledger.record(
                format!("task-{i}"),
                TaskResult {
                    exit_code: 0,
                    log_tail: String::new(),
                },
            );
        }
        assert_eq!(ledger.entries.len(), LEDGER_CAP);
        // 最旧的被剔除，最新的保留。
        assert!(!ledger.has("task-0"));
        assert!(ledger.has(&format!("task-{}", LEDGER_CAP + 9)));
    }

    #[test]
    fn decide_reruns_only_unexecuted_tasks() {
        let mut ledger = TaskLedger::default();
        ledger.record(
            "task-1".into(),
            TaskResult {
                exit_code: 7,
                log_tail: "boom".into(),
            },
        );
        assert_eq!(
            decide(&ledger, &task("task-1", "true")),
            Decide::ReReport(TaskResult {
                exit_code: 7,
                log_tail: "boom".into()
            })
        );
        assert_eq!(decide(&ledger, &task("task-2", "true")), Decide::Execute);
    }

    #[test]
    fn run_task_captures_output_and_exit_code() {
        let result = run_task(&payload("echo hello-task"));
        assert_eq!(result.exit_code, 0);
        assert!(result.log_tail.contains("hello-task"));
    }

    #[test]
    fn run_task_workdir_applies() {
        #[cfg(not(target_os = "windows"))]
        {
            let dir = std::env::temp_dir().join(format!("meshlet-workdir-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let p = TaskPayload {
                cmd: "pwd".into(),
                workdir: Some(dir.to_string_lossy().into_owned()),
                timeout_secs: None,
            };
            let result = run_task(&p);
            assert_eq!(result.exit_code, 0);
            assert!(result
                .log_tail
                .contains(&dir.to_string_lossy().into_owned()));
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn run_task_timeout_kills_and_reports_failure() {
        #[cfg(not(target_os = "windows"))]
        {
            let p = TaskPayload {
                cmd: "sleep 30".into(),
                workdir: None,
                timeout_secs: Some(1),
            };
            let start = Instant::now();
            let result = run_task(&p);
            assert_ne!(result.exit_code, 0, "timeout must report failure");
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "timeout must kill promptly"
            );
        }
    }

    #[test]
    fn run_task_spawn_failure_is_visible() {
        #[cfg(not(target_os = "windows"))]
        {
            let p = TaskPayload {
                cmd: "exit 3".into(),
                workdir: Some("/nonexistent".into()),
                timeout_secs: None,
            };
            let result = run_task(&p);
            // 工作目录不存在 → 派生失败 → 127，失败可见。
            assert_eq!(result.exit_code, SPAWN_FAIL_EXIT);
            assert!(result.log_tail.contains("spawn failed"));
        }
    }

    /// 微型 HTTP mock（按路径应答脚本）。处理 `requests` 个连接后退出；
    /// 返回 (base_url, join_handle)。
    fn spawn_mock(
        routes: std::collections::HashMap<String, (u16, String)>,
        requests: usize,
    ) -> (String, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming().take(requests) {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                let header_end;
                loop {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        header_end = pos + 4;
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let path = head.lines().next().unwrap_or("").split_whitespace().nth(1);
                let clen = head
                    .lines()
                    .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                    .and_then(|l| l.split_once(':').map(|(_, v)| v))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                while buf.len() < header_end + clen {
                    let n = stream.read(&mut tmp).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                let (status, body) = path
                    .and_then(|p| routes.get(p).cloned())
                    .unwrap_or((404, "{}".to_string()));
                let reason = if status == 200 { "OK" } else { "Error" };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.flush();
            }
        });
        (base, handle)
    }

    /// MT-004 验收「托盘通知触发测试」：真实 socket + 真实 ureq。新到达任务
    /// ack 成功后 `on_arrival` 恰好触发一次（到达=ack 后、执行前）；账本已有
    /// 的补派任务不是到达，不触发。
    #[test]
    fn arrival_callback_fires_once_for_new_tasks_only() {
        let pending_body = serde_json::json!([{
            "id": "task-1", "target_node": "dev-1",
            "payload": { "cmd": "echo hi", "workdir": null, "timeout_secs": null },
            "state": "assigned", "retry_limit": 0, "result_ref": null,
        }])
        .to_string();
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "/api/v1/agent/tasks/pending".to_string(),
            (200, pending_body),
        );
        routes.insert(
            "/api/v1/agent/tasks/task-1/ack".to_string(),
            (200, "{}".to_string()),
        );
        routes.insert(
            "/api/v1/agent/tasks/task-1/result".to_string(),
            (200, "{}".to_string()),
        );
        let dir = std::env::temp_dir().join(format!("meshlet-task-arrival-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ledger_path = dir.join("tasks.json");

        // 第一轮：新任务 → 触发一次。
        let (base, handle) = spawn_mock(routes.clone(), 3);
        let mut ledger = TaskLedger::default();
        let mut arrived: Vec<String> = Vec::new();
        let mut on_arrival = |t: &Task| arrived.push(t.id.to_string());
        process_pending(&base, "tok", &mut ledger, &ledger_path, &mut on_arrival).unwrap();
        handle.join().unwrap();
        assert_eq!(
            arrived,
            vec!["task-1".to_string()],
            "new task must trigger arrival exactly once"
        );

        // 第二轮（补派同一任务）：账本已有 → 只补报（pending + result，无 ack），
        // 不再触发。
        let (base, handle) = spawn_mock(routes, 2);
        let mut arrived_again: Vec<String> = Vec::new();
        let mut on_arrival = |t: &Task| arrived_again.push(t.id.to_string());
        process_pending(&base, "tok", &mut ledger, &ledger_path, &mut on_arrival).unwrap();
        handle.join().unwrap();
        assert!(
            arrived_again.is_empty(),
            "re-dispatched (already executed) task must not re-trigger arrival"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
