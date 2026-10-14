# 性能方案与基准

> 外部 API 控制开工单条目「性能方案与基准（吞吐 / 延迟 / 并发连接数 / 内存）」（2026-10-14）。
> 本文覆盖**控制面**（server API + SQLite 持久化）。数据面（WireGuard 中继吞吐与延迟）
> 见 [routing-optimization](routing-optimization.md)。

## 度量方法

- **驱动**：`apps/server/examples/bench.rs`（零新增依赖）。进程内用
  `tower::ServiceExt::oneshot` 直打 `axum::Router`，**不经 TCP/TLS**——度量的是
  handler + JSON 序列化 + SQLite 访问的完整成本，不含内核网络栈，因此**绝对数字
  低于真实 HTTP 部署**；同一驱动下的前后对照有效。
- **模型**：N 个并发任务各自串行发请求跑满时长，统计吞吐、每请求耗时分布
  （p50/p90/p99/max）与错误数。**并发档位 = 同时在飞的请求数**；每个在飞请求在
  处理期间占用一个池连接，故文件库的实际连接数上限 = 池大小（见下）。
- **三个目标**（覆盖三档 DB 成本）：

  | 目标 | DB 成本 |
  |---|---|
  | `GET /system/status` | 公开端点，0 次访问——CPU/调度上限参照 |
  | `GET /networks` | 会话校验 = 1 次读 |
  | `GET /auth/tokens` | 会话校验 + token 列表 = 2 次读 |

- **内存**：`--footprint` 批量建 500 网络 + 500 API Token，以 `/proc/self/status`
  的 VmRSS 增量算均摊。

## 环境

Intel Core i9-10880H @ 2.30GHz；SQLite **文件库**（临时目录，贴近生产的磁盘 +
池行为）；每格 8s；并发档 1 / 16 / 64 / 256；tokio multi_thread 4 worker；
`--release`。

**测量稳定性（重要）**：本机为共享容器，跨会话同一二进制的吞吐可差 2–3 倍
（无 DB 的 `/system/status` 实测 281k–1.75M req/s，差异来自 CPU 调频与邻居噪声）。
因此**基线与优化后在同会话交替测量**，并以区间报告；RSS 同样低信噪（同二进制
19–50 MiB 摆动），内存结论只采用 `--footprint` 的增量均摊值。

## 优化前（基线）

配置：`max_connections(1)`、默认 `journal_mode=delete`、默认 `synchronous=FULL`、
无 `busy_timeout`。瓶颈：**单串行连接**——rollback journal 下读写互斥，所有请求
（含只读端点的会话校验）在一条连接上排队。

| 目标 | 并发 | req/s | p50 µs | p99 µs |
|---|---|---|---|---|
| GET /system/status | 1 / 16 / 64 / 256 | 527k / 281k / 970k / 1757k | 1 / 1 / 1 / 1 | 2 / 6 / 11 / 13 |
| GET /networks | 1 / 16 / 64 / 256 | 4.7k / 2.6k / 6.3k / 6.8k | 87 / 1968 / 10263 / 35798 | 3770 / 86044 / 22229 / 65008 |
| GET /auth/tokens | 1 / 16 / 64 / 256 | 1.2k / 4.0k / 3.1k / 2.9k | 201 / 3316 / 20081 / 88407 | 9123 / 13653 / 33348 / 116670 |

- DB 端点吞吐在并发 ≥16 后**不随并发上升**（2.6k–6.8k 区间平走），p50 从
  87µs 涨到 36ms——典型的单连接排队；无 DB 的 status 端点同时段保持 0.28M–1.76M，
  说明服务本身没有到顶，瓶颈在 DB 访问路径。
- 跨会话基线（早前同机测量）：`/networks` 6.8k–8.2k、`/auth/tokens` 3.1k–4.1k
  （并发 16/64/256），与本次同会话基线同区间。

## 优化（`apps/server/src/store.rs`）

文件库（非 `:memory:`）：

1. `PRAGMA journal_mode = WAL`——读写互不阻塞，读并发才真正并行；
2. `PRAGMA synchronous = NORMAL`——WAL 下提交不同步每帧，fsync 成本从每次
   提交降为检查点粒度（断电风险 = 最多丢最近事务，**不损坏库**，控制面可接受）；
3. `PRAGMA busy_timeout = 5000`——并发写入等待而非立即 `SQLITE_BUSY`；
4. `max_connections = 4`——读并发上限。

`:memory:` 库**恒 1 连接**：每个连接是独立的内存库，多连接 = 多个库（测试语义）。

**写路径不变**：SQLite 单写者，WAL 不并行化写，控制面写吞吐仍由串行事务决定。
副作用：WAL 伴随 `-wal`/`-shm` 文件（检查点回收）；库文件在未检查点时直接拷贝
会拿到旧快照，备份需 `VACUUM INTO`。

## 优化后（同会话两次测量）

| 目标 | 并发 | req/s（两次） | p50 µs（两次） | p99 µs（两次） |
|---|---|---|---|---|
| GET /system/status | 1 / 16 / 64 / 256 | 359–661k / 534k–1.72M / 1.49–1.75M / 799k–1.76M | 1 | 2–13 |
| GET /networks | 1 / 16 / 64 / 256 | 7.7–8.3k / 26.3–31.0k / 31.9–32.4k / 12.5–28.6k | 84–104 / 483–535 / 1911–1940 / 8521–15582 | 391–1504 / 1136–2124 / 3310–3674 / 15704–107932 |
| GET /auth/tokens | 1 / 16 / 64 / 256 | 2.7–4.6k / 13.8–15.4k / 9.7–17.1k / 4.4–17.2k | 140–201 / 968–1027 / 3634–5711 / 14581–44139 | 454–4756 / 2587–4104 / 5944–18570 / 22101–263033 |

- status（无 DB）前后同区间：优化只作用于 DB 绑定路径，CPU 上限不变——符合预期。
- 全部档位错误数 0：`busy_timeout` 下无 `SQLITE_BUSY` 泄漏到响应。

## 前后对照

保守口径：优化后取两次测量中的**较低值** vs 同会话基线。即使按**跨会话基线
区间上沿**（上文）估算，16 并发收益仍 ≥3×。

| 目标 | 并发 | 吞吐 | p50 |
|---|---|---|---|
| GET /networks | 16 | **10×**（2.6k → 26.3k） | 4.1× 缩短 |
| GET /networks | 64 | **5.0×**（6.3k → 31.9k） | 5.4× 缩短 |
| GET /networks | 256 | 1.8×（6.8k → 12.5k；另一轮 4.2×） | 2.3–4.2× 缩短 |
| GET /auth/tokens | 16 | **3.5×**（4.0k → 13.8k） | 3.4× 缩短 |
| GET /auth/tokens | 64 | **3.1×**（3.1k → 9.7k） | 1.8–5.5× 缩短 |
| GET /auth/tokens | 256 | 1.5×（2.9k → 4.4k；另一轮 5.8×） | 2.0–6.1× 缩短 |

## 内存占用（`--footprint`）

| 批量操作 | 数量 | RSS 增量 | 均摊 |
|---|---|---|---|
| 500 网络（内存 MeshState + 各 1 修订） | 500 | 792 KiB | **1.6 KiB/网络** |
| 再 500 API Token（SQLite 行） | 500 | 112 KiB | 0.2 KiB/token |

- 网络条目 1.6 KiB 稳定（两次独立测量 812/792 KiB）；token 条目 RSS 归因噪声大
  （228/112 KiB），但都在亚 KiB 量级。
- 常驻开销：4 连接 + WAL 相对单连接的增量在数 MiB（终态 RSS 19–50 MiB 摆动，
  噪声大于信号，不作为结论）。
- 外推（仅作量级估计）：10k 网络 ≈ +16 MiB。控制面内存主要由网络/设备/修订
  簿记决定，凭证表不占大头。

## 复现命令

```bash
cargo build --release -p meshlet-server --example bench
# 吞吐/延迟（文件库，贴近生产）
./target/release/examples/bench --db file --secs 8 --sweep 1,16,64,256
# 内存均摊
./target/release/examples/bench --db file --footprint
# 纯内存库对照（池恒 1 连接，数字仅供方法对照）
./target/release/examples/bench --db memory --secs 8 --sweep 1,16,64,256
```

基线复现（与优化后同会话交替）：

```bash
git stash push apps/server/src/store.rs        # 还原单连接 + 无 WAL
cargo build --release -p meshlet-server --example bench
./target/release/examples/bench --db file --secs 8 --sweep 1,16,64,256
git stash pop && cargo build --release -p meshlet-server --example bench
```

## 结论

1. 控制面读路径的基线瓶颈是**单串行连接**；4 连接 + WAL 把 `/networks` 吞吐提到
   **~30k req/s（16 并发 10×、64 并发 5×）**、`/auth/tokens` 提到 **~14k req/s
   （16 并发 3.5×）**，p50 延迟从毫秒级降到 **0.5–2 ms**。
2. `/system/status` 前后同区间，确认瓶颈在 DB 路径而非服务本身；无 DB 路径的
   上限（~1M+ req/s）不受影响。
3. **并发远超池大小（256）时收益不稳定**（1.5–6×）：请求在 4 连接上排队，
   连接池成为新瓶颈。控制台与外部集成的真实并发远低于此，**当前不再调池**；
   若外部集成出现持续 >64 并发，先调大 `FILE_DB_MAX_CONNECTIONS` 再测。
4. 写吞吐未优化也未测（SQLite 单写者）；控制面写是低频管理操作。
5. 内存：1.6 KiB/网络 + 亚 KiB/token，常驻增量数 MiB。

## 关联

- 优化实现：`apps/server/src/store.rs`（连接策略与 PRAGMA）
- 驱动：`apps/server/examples/bench.rs`（零新增依赖）
- 数据面瓶颈与验证命令：[routing-optimization](routing-optimization.md)
- 单进程控制平面前提：[ADR-002](../decisions/adr-002-vps-hub-relay.md)
