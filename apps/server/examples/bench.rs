//! 控制面基准驱动（性能方案条目，2026-10-14）。
//!
//! 进程内直连 Router（`oneshot`），不经 TCP/TLS——度量的是 handler +
//! 序列化 + SQLite 读的完整成本，不含内核网络栈（吞吐数字偏低但可复现，
//! 前后对照有效）。数据面（WireGuard 中继）基准命令见
//! docs/architecture/routing-optimization.md。
//!
//! 用法：
//! ```text
//! cargo run --release -p meshlet-server --example bench -- [--db file|memory] [--secs 10] [--workers 64] [--target all|status|networks|tokens] [--sweep 1,8,64,256] [--footprint]
//! ```
//! `--footprint`：批量建 500 网络 + 500 token，报告 RSS 增量（实体内存占用）。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt; // oneshot

struct BenchApp {
    app: Router,
    cookie: String,
}

fn rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(v) = line.strip_prefix("VmRSS:") {
            return v
                .trim()
                .trim_end_matches(" kB")
                .replace(' ', "")
                .parse()
                .unwrap_or(0);
        }
    }
    0
}

fn cpu_model() -> String {
    let info = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    for line in info.lines() {
        if let Some(v) = line.strip_prefix("model name") {
            return v.trim_start_matches(':').trim().to_string();
        }
    }
    "unknown".into()
}

/// file 模式使用临时文件数据库（贴近生产：磁盘 + pool 行为）；
/// memory 模式使用 `sqlite::memory:`（测试语义，连接池恒 1）。
async fn build(db: &str) -> BenchApp {
    let url = match db {
        "memory" => "sqlite::memory:".to_string(),
        _ => {
            let path =
                std::env::temp_dir().join(format!("meshlet-bench-{}.db", std::process::id()));
            let _ = std::fs::remove_file(&path);
            format!("sqlite:{}?mode=rwc", path.display())
        }
    };
    let pool = meshlet_server::store::connect(&url).await.unwrap();
    let state = Arc::new(meshlet_server::auth::AppState::new(
        meshlet_server::service::SharedState::default(),
        meshlet_server::auth::AuthStore::new(pool.clone()),
        meshlet_server::agent::AgentTokenStore::new(pool.clone()),
        meshlet_server::api_token::ApiTokenStore::new(pool),
        false,
    ));
    let app = meshlet_server::router(state);

    let res = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/bootstrap")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"bench@test.local","password":"bench-password-123"}"#.to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "bootstrap must succeed");
    let cookie = res
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .expect("session cookie")
        .to_string();
    BenchApp { app, cookie }
}

#[derive(Clone, Copy)]
enum Target {
    Status,
    Networks,
    Tokens,
}

impl Target {
    fn name(&self) -> &'static str {
        match self {
            Target::Status => "GET /system/status（公开，无 DB）",
            Target::Networks => "GET /networks（会话校验 = 1 次 DB 读）",
            Target::Tokens => "GET /auth/tokens（会话 + token 列表 = 2 次 DB 读）",
        }
    }

    fn request(&self, cookie: &str) -> Request<Body> {
        let (uri, with_cookie) = match self {
            Target::Status => ("/api/v1/system/status", false),
            Target::Networks => ("/api/v1/networks", true),
            Target::Tokens => ("/api/v1/auth/tokens", true),
        };
        let mut b = Request::builder().method("GET").uri(uri);
        if with_cookie {
            b = b.header("cookie", cookie);
        }
        b.body(Body::empty()).unwrap()
    }
}

struct RunResult {
    total: u64,
    errors: u64,
    latencies_us: Vec<u64>,
}

/// `workers` 个并发任务，各自串行发请求直到时限；返回合并结果。
async fn drive(app: &Router, cookie: &str, target: Target, workers: usize, secs: u64) -> RunResult {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let per_worker = Arc::new(std::sync::Mutex::new(Vec::<u64>::new()));
    let counters = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let errors = Arc::new(std::sync::atomic::AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..workers {
        let app = app.clone();
        let cookie = cookie.to_string();
        let latencies = per_worker.clone();
        let counters = counters.clone();
        let errors = errors.clone();
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let req = target.request(&cookie);
                let t0 = Instant::now();
                let ok = match app.clone().oneshot(req).await {
                    Ok(res) if res.status().is_success() => {
                        // 读掉 body，避免未消费的响应体堆积。
                        res.into_body().collect().await.is_ok()
                    }
                    _ => false,
                };
                if !ok {
                    errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                latencies
                    .lock()
                    .unwrap()
                    .push(t0.elapsed().as_micros() as u64);
                counters.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let mut latencies_us = Vec::new();
    latencies_us.extend(per_worker.lock().unwrap().iter().copied());
    RunResult {
        total: counters.load(std::sync::atomic::Ordering::Relaxed),
        errors: errors.load(std::sync::atomic::Ordering::Relaxed),
        latencies_us,
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn report(target: Target, workers: usize, secs: u64, r: &RunResult) {
    let mut sorted = r.latencies_us.clone();
    sorted.sort_unstable();
    println!(
        "| {} | {workers} | {:.0} | {} | {} | {} | {} | {} |",
        target.name(),
        r.total as f64 / secs as f64,
        percentile(&sorted, 0.50),
        percentile(&sorted, 0.90),
        percentile(&sorted, 0.99),
        sorted.last().copied().unwrap_or(0),
        r.errors,
    );
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let mut db = "file".to_string();
    let mut secs: u64 = 10;
    let mut workers: usize = 64;
    let mut target = "all".to_string();
    let mut sweep: Option<Vec<usize>> = None;
    let mut footprint = false;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--db" => db = args.next().unwrap_or_default(),
            "--secs" => secs = args.next().and_then(|v| v.parse().ok()).unwrap_or(10),
            "--workers" => workers = args.next().and_then(|v| v.parse().ok()).unwrap_or(64),
            "--target" => target = args.next().unwrap_or_else(|| "all".into()),
            "--sweep" => {
                sweep = args.next().map(|v| {
                    v.split(',')
                        .filter_map(|s| s.parse().ok())
                        .collect::<Vec<usize>>()
                });
            }
            "--footprint" => footprint = true,
            _ => {}
        }
    }

    println!("环境：CPU = {}；db = {db}；时长/档 = {secs}s", cpu_model());
    println!("注：进程内 oneshot 驱动，不含 TCP/TLS 栈成本；数字用于前后对照。\n");

    if footprint {
        footprint_run(&db).await;
        return;
    }

    let bench = build(&db).await;
    // 预热 1s（页面缓存、连接建立、首 JIT）。
    drive(&bench.app, &bench.cookie, Target::Networks, workers, 1).await;

    let targets: Vec<Target> = match target.as_str() {
        "status" => vec![Target::Status],
        "networks" => vec![Target::Networks],
        "tokens" => vec![Target::Tokens],
        _ => vec![Target::Status, Target::Networks, Target::Tokens],
    };

    let rss_before = rss_kib();
    let worker_sets = sweep.unwrap_or_else(|| vec![workers]);
    for w in worker_sets {
        println!("| 目标 | 并发 | req/s | p50 µs | p90 µs | p99 µs | max µs | 错误 |");
        println!("|---|---|---|---|---|---|---|---|");
        for t in targets.clone() {
            let r = drive(&bench.app, &bench.cookie, t, w, secs).await;
            report(t, w, secs, &r);
        }
        println!();
    }
    let rss_after = rss_kib();
    println!(
        "RSS：{} KiB → {} KiB（含驱动与运行时）",
        rss_before, rss_after
    );
}

/// 内存占用：批量建 500 网络（内存 MeshState）+ 500 API Token（SQLite），
/// 报告 RSS 增量与均摊值。
async fn footprint_run(db: &str) {
    let bench = build(db).await;
    let warm = drive(&bench.app, &bench.cookie, Target::Networks, 16, 1).await;
    println!("预热请求数：{}", warm.total);
    let rss0 = rss_kib();

    for i in 0..500 {
        // 500 个互不重叠的 /24（10.0.1.x / 10.0.2.x）。
        let body = format!(
            r#"{{"name":"net-{i}","overlay_cidr":"10.{}.{}.0/24"}}"#,
            1 + i / 256,
            i % 256
        );
        let res = bench
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/networks")
                    .header("cookie", &bench.cookie)
                    .header("x-requested-with", "XMLHttpRequest")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }
    let rss_networks = rss_kib();
    for i in 0..500 {
        let res = bench
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/tokens")
                    .header("cookie", &bench.cookie)
                    .header("x-requested-with", "XMLHttpRequest")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"name":"tok-{i}","scopes":"read"}}"#
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CREATED);
    }
    let rss_tokens = rss_kib();

    println!("| 批量操作 | 数量 | RSS 增量 | 均摊 |");
    println!("|---|---|---|---|");
    println!(
        "| 500 网络（内存态 + 各 1 修订） | 500 | {} KiB | {:.1} KiB/网络 |",
        rss_networks - rss0,
        (rss_networks - rss0) as f64 / 500.0
    );
    println!(
        "| 再 500 API Token（SQLite 行） | 500 | {} KiB | {:.1} KiB/token |",
        rss_tokens - rss_networks,
        (rss_tokens - rss_networks) as f64 / 500.0
    );
}
