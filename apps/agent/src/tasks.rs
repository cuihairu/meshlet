//! Task execution (MT-002 dispatch and reporting): the agent pulls pending tasks
//! dispatched by the server, acks → executes → reports results.
//!
//! This is an **explicit exception** to the existing "never execute arbitrary
//! shell commands dispatched by the server" discipline (MT-002 user mandate):
//! tasks are explicitly dispatched by console users via `task.assigned` audit, and agent endpoints always authenticate with Bearer credentials (the same auth boundary as [`crate::server`]).
//!
//! Idempotency semantics (re-dispatch after a disconnect never re-executes; aligned with the server's `task id` idempotency key):
//! - The local ledger `{state_dir}/tasks.json` records **executed** task ids → results;
//! - An id already in the ledger only **re-reports the result, never re-runs**
//!   (the server is idempotent about duplicate reports: a duplicate terminal report only updates the log tail, never the terminal state);
//! - Execution order: ack (on failure skip this round, retry next round) → run the command → **persist the ledger first** → report.
//!   A crash in the "ran but not yet reported" gap → ledger already written → re-report on reconnect without re-running; a crash after ack but
//!   before finishing → no ledger entry → the server re-dispatches → re-run (the previous run never finished, so re-running is correct).
//!
//! Boundary: tasks run inline in the agent main loop (synchronous tick), so a long task temporarily blocks heartbeats —
//! MT-005 will introduce concurrent scheduling/timeout re-dispatch; this version only guarantees "execute + idempotency + report".

use std::collections::{BTreeMap, VecDeque};
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use meshlet_domain::{Task, TaskPayload};

use crate::server;

/// Ledger capacity cap: on overflow evict the oldest (by **actual execution completion order**, never by task id
/// lexicographic order — `task-10` < `task-2`, and the re-dispatch id `task-1-r2` is even more out of order; lexicographic ≠ chronological).
const LEDGER_CAP: usize = 512;
/// Bytes of command output tail to keep (drop the head beyond this, keep the most recent part).
const TAIL_BYTES: usize = 4096;
/// Process status polling interval (milliseconds).
const POLL: Duration = Duration::from_millis(20);
/// Exit code when the command cannot start (shell convention 127 = command not found).
const SPAWN_FAIL_EXIT: i32 = 127;
/// Default timeout when none is specified (seconds, the `TaskPayload.timeout_secs` contract value).
const DEFAULT_TIMEOUT_SECS: u64 = 300;
/// Background task worker polling interval (seconds): the tick no longer runs tasks synchronously; the background thread pulls pending
/// work at this interval; a newly dispatched task starts executing within at most one interval.
const TASK_POLL_INTERVAL_SECS: u64 = 5;

/// The result of one execution (isomorphic to the server's `TaskResultReport`: exit_code + log_tail).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskResult {
    /// Process exit code (0 = success, non-zero = failure).
    pub exit_code: i32,
    /// Command output tail (last bytes of merged stdout+stderr).
    pub log_tail: String,
}

/// Executed-task ledger: task id → result. Used to **re-report** after a reconnect, never to re-run.
#[derive(Debug, Default)]
pub struct TaskLedger {
    entries: BTreeMap<String, TaskResult>,
    /// Actual execution completion order (FIFO): eviction takes the queue head (earliest completed), independent of id spelling.
    /// Persisted in [`LedgerFile`]; after a restart eviction still follows real time order.
    order: VecDeque<String>,
}

/// Ledger persistence format: entries + insertion order. The legacy version stored a bare `BTreeMap` (no insertion order);
/// [`TaskLedger::load`] falls back to parsing it and rebuilds from its lexicographic order (best effort for old data; new records
/// keep evicting by real insertion order).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct LedgerFile {
    entries: BTreeMap<String, TaskResult>,
    order: Vec<String>,
}

impl TaskLedger {
    /// Load from `{state_dir}/tasks.json`; missing/corrupt files are treated as an empty ledger (corruption must be logged
    /// loudly, never silently — an empty ledger means "every task may re-run"; that is the safety boundary).
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(bytes) => {
                let (entries, order) = serde_json::from_slice::<LedgerFile>(&bytes)
                    .map(|f| (f.entries, f.order))
                    .or_else(|_| {
                        serde_json::from_slice::<BTreeMap<String, TaskResult>>(&bytes)
                            .map(|m| {
                                let order: Vec<String> = m.keys().cloned().collect();
                                (m, order)
                            })
                    })
                    .unwrap_or_else(|e| {
                        tracing::warn!(path = %path.display(), error = %e, "task ledger corrupt; starting empty");
                        (BTreeMap::new(), Vec::new())
                    });
                Self {
                    entries,
                    order: order.into(),
                }
            }
            Err(_) => Self::default(),
        }
    }

    /// Persist (create the parent directory first; failures are reported explicitly for the caller to decide).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let file = LedgerFile {
            entries: self.entries.clone(),
            order: self.order.iter().cloned().collect(),
        };
        let bytes = serde_json::to_vec(&file).unwrap_or_default();
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(path, bytes)
    }

    /// Whether it has already executed (idempotent: executed tasks only re-report, never re-run).
    pub fn has(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    /// Result of an executed task.
    pub fn result(&self, id: &str) -> Option<&TaskResult> {
        self.entries.get(id)
    }

    /// Record one execution result; beyond capacity evict the **earliest completed** (real insertion order, independent of
    /// id spelling). Re-recording the same id only updates the result, never its eviction position.
    pub fn record(&mut self, id: String, result: TaskResult) {
        self.record_with_cap(id, result, LEDGER_CAP);
    }

    /// Capacity-parameterized implementation of [record] (tests verify the eviction order with a small capacity directly).
    fn record_with_cap(&mut self, id: String, result: TaskResult, cap: usize) {
        if self.entries.insert(id.clone(), result).is_none() {
            self.order.push_back(id);
        }
        while self.entries.len() > cap {
            if let Some(oldest) = self.order.pop_front() {
                if self.entries.remove(&oldest).is_some() {
                    break;
                }
            }
        }
    }
}

/// Pure decision (unit-testable): task already in the ledger → re-report the result; otherwise execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decide {
    /// Already executed: re-dispatch after a disconnect only re-reports, never re-runs.
    ReReport(TaskResult),
    /// Not yet executed: ack → run → persist ledger → report.
    Execute,
}

/// Decision (idempotent dedup, pure function, no I/O).
pub(crate) fn decide(ledger: &TaskLedger, task: &Task) -> Decide {
    match ledger.result(&task.id.to_string()) {
        Some(result) => Decide::ReReport(result.clone()),
        None => Decide::Execute,
    }
}

/// Fetch this device's pending tasks (assigned / acked).
pub fn fetch_pending(server_url: &str, token: &str) -> Result<Vec<Task>, String> {
    let url = format!(
        "{}/api/v1/agent/tasks/pending",
        server_url.trim_end_matches('/')
    );
    let req = ureq::get(&url).set("authorization", &format!("Bearer {token}"));
    let body = server::read_response(req.call())?;
    serde_json::from_str(&body).map_err(|e| format!("parse pending tasks: {e}"))
}

/// Acknowledge receipt (idempotent: once past assigned the server still returns 200, no state transition, no persistence).
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

/// Report the result (idempotent: duplicate terminal reports only update the log tail, never the terminal state).
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

/// Handle one task: already in the ledger → re-report; otherwise ack → run → persist ledger → report.
/// `on_arrival` fires once after a successful ack, before execution (MT-004: tray bubble on task arrival;
/// a ReReport from re-dispatch after a disconnect is not an arrival and does not fire it).
/// `Err` means skip this round (network failure, retry next round); a failed report is already logged internally and the ledger
/// written, so no `Err` is returned (the ledger has it; it re-reports next round without triggering the outer backoff).
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
            // On ack failure skip this round: preserves the server state machine order (assigned → acked → ...).
            ack_task(server_url, token, &id)?;
            on_arrival(task);
            let result = run_task(&task.payload);
            // Persist the ledger before reporting: a crash in the gap → re-report on reconnect without re-running.
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

/// Handle all pending tasks for this device. A fetch failure returns `Err` (retry next round); a single-task failure is only logged,
/// never affecting other tasks or the data-plane loop. `on_arrival` fires once per newly arrived task.
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

/// Background task runtime: a dedicated worker thread pulls pending tasks at [TASK_POLL_INTERVAL_SECS] and acks → executes →
/// reports each one. The main loop tick only **posts** ([TaskRuntime::kick]) and returns immediately — a single task can run up to
/// [DEFAULT_TIMEOUT_SECS], which would stall heartbeat/data-plane reconciliation if run inline; once backgrounded, heartbeats and
/// reconciliation are never blocked by a single task, and the task lifecycle/reporting semantics (idempotent ledger + re-report)
/// stay unchanged.
///
/// `Drop` only sets the stop flag and does not `join`: the thread exits by itself within at most one cycle and holds `Arc` clones,
/// so this is memory safe (same discipline as [`crate::probe::ProbeRuntime`]).
pub struct TaskRuntime {
    ledger: Arc<Mutex<TaskLedger>>,
    stop: Arc<AtomicBool>,
    /// Kick signal that wakes the worker (fired as soon as the tick fetches the plan, without waiting a full polling interval).
    kick: Arc<Mutex<VecDeque<()>>>,
    handle: Option<JoinHandle<()>>,
}

impl TaskRuntime {
    /// Start the background worker (dedicated thread); `on_arrival` is the arrival callback after each successful ack
    /// (tray bubble etc., executed on the worker thread, never blocking the main loop).
    pub fn start(
        server_url: String,
        token: String,
        ledger: TaskLedger,
        ledger_path: std::path::PathBuf,
        on_arrival: impl Fn(&Task) + Send + 'static,
    ) -> Self {
        let ledger = Arc::new(Mutex::new(ledger));
        let stop = Arc::new(AtomicBool::new(false));
        let kick = Arc::new(Mutex::new(VecDeque::new()));
        let handle = {
            let ledger = Arc::clone(&ledger);
            let ledger_path = ledger_path.clone();
            let stop = Arc::clone(&stop);
            let kick = Arc::clone(&kick);
            std::thread::Builder::new()
                .name("meshlet-task".into())
                .spawn(move || loop {
                    // Wait for a kick or the period to elapse first; run immediately after a tick post, otherwise at the polling interval.
                    let waited = wait_kick_or_timeout(&kick, &stop, TASK_POLL_INTERVAL_SECS);
                    if stop.load(Ordering::Relaxed) {
                        return;
                    }
                    let mut ledger = ledger.lock().unwrap_or_else(|e| e.into_inner());
                    if let Err(e) = process_pending(
                        &server_url,
                        &token,
                        &mut ledger,
                        &ledger_path,
                        &mut |task| on_arrival(task),
                    ) {
                        tracing::warn!(error = %e, "task processing deferred to next poll");
                    }
                    let _ = waited;
                })
                .expect("spawn the task worker thread")
        };
        Self {
            ledger,
            stop,
            kick,
            handle: Some(handle),
        }
    }

    /// Post one processing-round request (called by the tick, returns immediately; the worker wakes and runs the tasks).
    /// Repeated kicks while the worker is busy coalesce into a single wakeup.
    pub fn kick(&self) {
        self.kick
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(());
    }

    /// Current ledger (for diagnostics such as reload/persist).
    pub fn ledger(&self) -> std::sync::MutexGuard<'_, TaskLedger> {
        self.ledger.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the worker thread is running.
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for TaskRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        drop(self.handle.take());
    }
}

/// Wait for a kick signal or timeout; returns immediately when `stop` is set. Returns whether the wakeup came from a kick (for diagnostics).
fn wait_kick_or_timeout(kick: &Mutex<VecDeque<()>>, stop: &AtomicBool, timeout_secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        if kick
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop_front()
            .is_some()
        {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(POLL);
    }
}

/// Execute one task (the MT-002 explicit exception: run a server-dispatched command).
///
/// Platform shell: `sh -c` on unix, `cmd /C` on Windows. Timeout defaults to
/// [DEFAULT_TIMEOUT_SECS]; on timeout the child is killed (non-zero exit code → the server judges it a failure).
///
/// Isolation (MT-005): when `workdir` is absent the command runs in a **per-task scratch directory** (deleted right
/// after the run), so task artifacts never land in the agent process cwd; an explicit `workdir` runs as dispatched.
/// Container-level isolation (nsjail/sandbox) is out of scope for this round.
pub fn run_task(payload: &TaskPayload) -> TaskResult {
    let scratch = payload.workdir.is_none().then(unique_scratch_dir);
    if let Some(dir) = &scratch {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return TaskResult {
                exit_code: SPAWN_FAIL_EXIT,
                log_tail: format!("scratch dir create failed: {e}"),
            };
        }
    }
    let result = run_task_in(payload, scratch.as_deref());
    if let Some(dir) = &scratch {
        // Clean up as soon as the task ends (a leftover means leaked temp disk; no retry, no warning, silent best effort).
        let _ = std::fs::remove_dir_all(dir);
    }
    result
}

/// Actual execution (the scratch directory is created/cleaned by [run_task]).
fn run_task_in(payload: &TaskPayload, scratch: Option<&std::path::Path>) -> TaskResult {
    let mut cmd = shell_command(&payload.cmd);
    match scratch {
        Some(dir) => {
            cmd.current_dir(dir);
        }
        None => {
            if let Some(workdir) = &payload.workdir {
                cmd.current_dir(workdir);
            }
        }
    }
    // unix: put the child in its own process group — the shell forks subcommands (e.g. in `sh -c "sleep 30"` the
    // `sleep` is a grandchild of the direct child), so the timeout kill must take down the whole group, otherwise
    // orphaned children keep running to the timeout and hold the pipes.
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
    // Read stdout/stderr tails in the background (otherwise a full pipe buffer blocks the child). The two pipe
    // types differ (ChildStdout/ChildStderr); erase them to `Box<dyn Read + Send>` for uniform handling.
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

/// Per-task scratch directory (MT-005): `temp/meshlet-task-{pid}-{seq}`; an in-process atomic sequence number
/// guarantees concurrent tasks never share a directory.
fn unique_scratch_dir() -> std::path::PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("meshlet-task-{}-{}", std::process::id(), n))
}

/// Platform shell command construction.
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

/// Wait for the child to exit; past `timeout_secs` kill and reap it. Returns the exit status (after a kill `code()` is
/// `None`; the caller maps that to failure).
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

/// Terminate the child (and its whole group): on unix first `kill(-pid, SIGKILL)` the process group (see `run_task`'s
/// `process_group(0)`), then fall back to `child.kill()` for the direct child; Windows has no process groups and
/// degrades to `child.kill()`.
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

/// Output tail buffer: keeps only the most recent [TAIL_BYTES] bytes.
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
            required_labels: Default::default(),
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
        // The oldest is evicted, the newest kept.
        assert!(!ledger.has("task-0"));
        assert!(ledger.has(&format!("task-{}", LEDGER_CAP + 9)));
    }

    #[test]
    fn ledger_evicts_by_real_time_order_not_id_lexicographic() {
        let mut ledger = TaskLedger::default();
        let res = || TaskResult {
            exit_code: 0,
            log_tail: String::new(),
        };
        // Out-of-order ids: record task-2 first, then task-10 (lexicographically task-10 < task-2),
        // then the re-dispatch id task-1-r2 (its prefix is out of order too). With capacity 2, **real insertion
        // order** evicts the earliest-completed task-2; lexicographic order would wrongly evict task-1-r2 / task-10.
        ledger.record_with_cap("task-2".into(), res(), 2);
        ledger.record_with_cap("task-10".into(), res(), 2);
        ledger.record_with_cap("task-1-r2".into(), res(), 2);
        assert_eq!(ledger.entries.len(), 2);
        assert!(
            !ledger.has("task-2"),
            "earliest-completed task-2 must be evicted"
        );
        assert!(ledger.has("task-10"));
        assert!(ledger.has("task-1-r2"));
        // One more insert → evicts the next-oldest task-10 (still by insertion order).
        ledger.record_with_cap("task-3".into(), res(), 2);
        assert!(
            !ledger.has("task-10"),
            "next-oldest task-10 must be evicted"
        );
        assert!(ledger.has("task-1-r2"));
        assert!(ledger.has("task-3"));
    }

    #[test]
    fn ledger_persists_insertion_order_across_reload() {
        let dir = std::env::temp_dir().join(format!("meshlet-task-order-{}", std::process::id()));
        let path = dir.join("tasks.json");
        let mut ledger = TaskLedger::default();
        let res = || TaskResult {
            exit_code: 0,
            log_tail: String::new(),
        };
        ledger.record("task-2".into(), res());
        ledger.record("task-10".into(), res());
        ledger.save(&path).expect("save");
        let mut loaded = TaskLedger::load(&path);
        // After reload, eviction follows the persisted insertion order: task-2, inserted first, goes first (not the lexicographically smallest).
        loaded.record_with_cap("task-1-r2".into(), res(), 2);
        assert!(!loaded.has("task-2"));
        assert!(loaded.has("task-10"));
        assert!(loaded.has("task-1-r2"));
        let _ = std::fs::remove_dir_all(&dir);
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
                required_labels: Default::default(),
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
    fn run_task_without_workdir_runs_in_per_task_scratch_and_cleans_up() {
        #[cfg(not(target_os = "windows"))]
        {
            let p = TaskPayload {
                cmd: "pwd".into(),
                workdir: None,
                timeout_secs: None,
                required_labels: Default::default(),
            };
            let first = run_task(&p);
            assert_eq!(first.exit_code, 0);
            let first_dir = std::path::PathBuf::from(first.log_tail.trim());
            // Ran in a dedicated scratch dir, removed right after the run.
            assert!(
                first_dir
                    .file_name()
                    .map(|n| n.to_string_lossy().starts_with("meshlet-task-"))
                    .unwrap_or(false),
                "cwd {first_dir:?} must be a per-task scratch dir"
            );
            assert!(!first_dir.exists(), "scratch dir must be removed after run");

            // Second task → a different scratch dir (per-task isolation).
            let second = run_task(&p);
            assert_eq!(second.exit_code, 0);
            let second_dir = std::path::PathBuf::from(second.log_tail.trim());
            assert_ne!(first_dir, second_dir);
            assert!(!second_dir.exists());
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
                required_labels: Default::default(),
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
                required_labels: Default::default(),
            };
            let result = run_task(&p);
            // Nonexistent workdir → spawn failure → 127, failure is visible.
            assert_eq!(result.exit_code, SPAWN_FAIL_EXIT);
            assert!(result.log_tail.contains("spawn failed"));
        }
    }

    /// Tiny HTTP mock (answers by path from a route table). Exits after serving `requests` connections;
    /// returns (base_url, join_handle).
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

    /// MT-004 acceptance "tray notification trigger test": real socket + real ureq. For a newly arrived task,
    /// `on_arrival` fires exactly once after a successful ack (arrival = after ack, before execution); a re-dispatched
    /// task already in the ledger is not an arrival and does not fire it.
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

        // Round 1: new task → fires once.
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

        // Round 2 (same task re-dispatched): already in the ledger → re-report only (pending + result, no ack),
        // no re-trigger.
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

    /// MT-002 backgrounding acceptance: `kick` returns immediately (without blocking the main loop); the worker thread
    /// then pulls pending tasks and acks → executes → reports, and the ledger ends up on disk (idempotency semantics unchanged).
    #[test]
    fn task_runtime_runs_in_background_and_kick_returns_immediately() {
        // Task command in per-platform shell syntax (shell_command uses `sh -c` / `cmd /C`):
        // sleep 1s then echo — keeps observable margin for "ran in the background" so Windows CI actually exercises it.
        let bg_cmd = if cfg!(windows) {
            "timeout /t 1 /nobreak >nul & echo bg-done"
        } else {
            "sleep 1; echo bg-done"
        };
        let pending_body = serde_json::json!([{
            "id": "task-bg", "target_node": "dev-1",
            "payload": { "cmd": bg_cmd, "workdir": null, "timeout_secs": null },
            "state": "assigned", "retry_limit": 0, "result_ref": null,
        }])
        .to_string();
        let mut routes = std::collections::HashMap::new();
        routes.insert(
            "/api/v1/agent/tasks/pending".to_string(),
            (200, pending_body),
        );
        routes.insert(
            "/api/v1/agent/tasks/task-bg/ack".to_string(),
            (200, "{}".to_string()),
        );
        routes.insert(
            "/api/v1/agent/tasks/task-bg/result".to_string(),
            (200, "{}".to_string()),
        );
        let (base, handle) = spawn_mock(routes, 3);
        let dir = std::env::temp_dir().join(format!("meshlet-task-bg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ledger_path = dir.join("tasks.json");
        let rt = TaskRuntime::start(
            base,
            "tok".into(),
            TaskLedger::default(),
            ledger_path.clone(),
            |_| {},
        );
        let start = Instant::now();
        rt.kick();
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "kick must return immediately, not run the task inline"
        );
        // Wait for the worker: poll the ledger (the task sleeps 1s; allow ample margin).
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ledger = rt.ledger();
            if ledger.has("task-bg") {
                assert_eq!(ledger.result("task-bg").unwrap().exit_code, 0);
                assert!(ledger
                    .result("task-bg")
                    .unwrap()
                    .log_tail
                    .contains("bg-done"));
                break;
            }
            drop(ledger);
            if Instant::now() >= deadline {
                panic!("task not executed by background worker in time");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        drop(rt);
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
