# R-06：服务发布进展

R-06 仍保持打开。服务转发、Web 发布、授权控制、健康探测和内部服务目录已在当前代码中落地；但 **`meshlet-publish` 尚未接入 agent 运行链路**，因此真实 VPS/真机端到端验收无法闭环（见下节缺口）。

## Implemented

- TCP 和 UDP PortForward 可通过 mesh 发布本地服务，并保留所选传输协议。
- HTTP 和 HTTPS 发布可将外部流量路由到 mesh 服务。
- 授权控制通过 `POST /api/v1/publish/routes/check` 暴露；server 路由在 `apps/server/src/lib.rs:1014` 接入 `meshlet-publish` 服务适配器。
- 健康探测会在流量准入前验证发布目标可达。
- 内部 DNS 服务目录支持分流式服务发现，不覆盖公共 DNS 解析。
- 当前自动化验证结果为：`cargo test -p meshlet-publish` 8 passed；`cargo test -p meshlet-server --test publish_check` 2 passed。

## 真实 VPS 验收记录（2026-10-23）

验收主机 `106.14.216.177`（阿里云 ECS，Ubuntu，内核 7.0.0-34-generic，2 vCPU / 1.6 GiB RAM，`/proc/cpuinfo` 型号串 `Intel(R) Xeon(R) Platinum`）。以下命令与输出均为该主机实测原文，未做任何修饰；本文档不含任何口令、token 或私钥内容。

### 服务端状态快照

```text
$ systemctl is-active meshlet-server
active

$ sha256sum /usr/local/bin/meshlet-server
75327714caf46018e72acb7cfafc60a19b65b7781bcbde5df26825bb780e15ff

$ df -h /
/dev/vda3        40G   21G   17G  55% /

$ docker ps --format "{{.Names}} {{.Status}}"
oddsmaker-demo-control Up 3 days (healthy)
oddsmaker-demo-postgres Up 2 weeks (healthy)
oddsmaker-demo-redis Up 2 weeks (healthy)
```

部署版本证据：本次在 VPS 上用锁定的 1.99.0 工具链出包，旧版 `ce36e81` 二进制 sha256 为 `514e076d7cacc448321087abf7fde4b3a3912115a4c32f653c8b79a3abd454a3`（13705376 字节），新版 `ef97f0d` 为 `75327714caf46018e72acb7cfafc60a19b65b7781bcbde5df26825bb780e15ff`（12734632 字节），以原子 `install` + `mv` 替换后 `systemctl restart`，服务 `active`，journal 记录 `mesh state rebuilt from database networks=1 devices=0 revisions=1`。验收结束时服务端仍在跑 `ef97f0d`（sha256 与上面一致）。

### 控制面基准（真实 VPS，非 CI 机器）

`cargo run --release -p meshlet-server --example bench`，驱动方式为进程内 axum `oneshot`，**不含 TCP/TLS 栈成本**，数字仅用于前后对照。

```text
$ ./target/release/examples/bench --db file --secs 8 --sweep 1,8,32
环境：CPU = : Intel(R) Xeon(R) Platinum；db = file；时长/档 = 8s
注：进程内 oneshot 驱动，不含 TCP/TLS 栈成本；数字用于前后对照。

| 目标 | 并发 | req/s | p50 µs | p90 µs | p99 µs | max µs | 错误 |
|---|---|---|---|---|---|---|---|
| GET /system/status（公开，无 DB） | 1 | 442556 | 1 | 2 | 3 | 5448 | 0 |
| GET /networks（会话校验 = 1 次 DB 读） | 1 | 8611 | 89 | 165 | 460 | 16244 | 0 |
| GET /auth/tokens（会话 + token 列表 = 2 次 DB 读） | 1 | 4445 | 186 | 309 | 806 | 8228 | 0 |

| 目标 | 并发 | req/s | p50 µs | p90 µs | p99 µs | max µs | 错误 |
|---|---|---|---|---|---|---|---|
| GET /system/status（公开，无 DB） | 8 | 485127 | 3 | 3 | 14 | 61457 | 0 |
| GET /networks（会话校验 = 1 次 DB 读） | 8 | 18333 | 358 | 707 | 1619 | 17424 | 0 |
| GET /auth/tokens（会话 + token 列表 = 2 次 DB 读） | 8 | 9015 | 775 | 1296 | 2808 | 32439 | 0 |

| 目标 | 并发 | req/s | p50 µs | p90 µs | p99 µs | max µs | 错误 |
|---|---|---|---|---|---|---|---|
| GET /system/status（公开，无 DB） | 32 | 486822 | 3 | 3 | 14 | 32783 | 0 |
| GET /networks（会话校验 = 1 次 DB 读） | 32 | 18739 | 1569 | 2257 | 4916 | 21028 | 0 |
| GET /auth/tokens（会话 + token 列表 = 2 次 DB 读） | 32 | 8814 | 3222 | 4642 | 11665 | 47047 | 0 |

RSS：11012 KiB → 48492 KiB（含驱动与运行时）
```

内存占用单独跑 `--footprint`（批量建 500 网络 + 500 token）：

```text
| 批量操作 | 数量 | RSS 增量 | 均摊 |
|---|---|---|---|
| 500 网络（内存态 + 各 1 修订） | 500 | 1908 KiB | 3.8 KiB/网络 |
| 再 500 API Token（SQLite 行） | 500 | 132 KiB | 0.3 KiB/token |
```

读法：DB 触达路径受 2 vCPU + SQLite 串行池限制，`/networks` 与 `/auth/tokens` 在 8→32 并发时吞吐基本持平（18333 → 18739、9015 → 8814），p50 延迟随之从 358 µs 涨到 1569 µs，属排队而非退化；三个档位错误数均为 0。外部链路基线为本地→VPS `GET /api/v1/system/status` 10 次采样 min 20.9 ms / max 25.4 ms / 均值约 23.2 ms。

### 授权控制实测（R-06 唯一已接线入口）

`POST /api/v1/publish/routes/check` 在真实实例上逐路径实测：

```text
$ curl -s -X POST http://127.0.0.1:8080/api/v1/publish/routes/check \
    -H 'X-Requested-With: XMLHttpRequest' -H 'content-type: application/json' \
    -d '{"remote":"10.240.4.9:40000","policy":{"allowed_source_cidrs":["10.240.0.0/16"],"allowed_bearer_tokens":[]}}'
{"allowed":true,"reason":"authorized"}

$ curl -s -X POST http://127.0.0.1:8080/api/v1/publish/routes/check \
    -H 'X-Requested-With: XMLHttpRequest' -H 'content-type: application/json' \
    -d '{"remote":"192.168.9.9:40000","auth_header":"Bearer wrong","policy":{"allowed_source_cidrs":["10.240.0.0/16"],"allowed_bearer_tokens":["secret"]}}'
{"allowed":false,"reason":"source or bearer token not authorized"}

$ curl -s -o /dev/null -w '%{http_code}\n' -X POST http://127.0.0.1:8080/api/v1/publish/routes/check
403
```

缺失 CSRF 头 `X-Requested-With: XMLHttpRequest` 返回 403，与 `meshlet_http_requests_total` 中 `publish/routes/check 4xx = 1` 一致。授权判定在打开服务连接之前就位（`crates/meshlet-publish/src/forwarding.rs:66`、`forwarding.rs:115`、`http.rs:165`、`http.rs:191`）。`AuthorizationPolicy::authorize`（`crates/meshlet-publish/src/authorization.rs:45`）为 OR 语义：CIDR 命中即直接放行、不再校验 token；IPv6 来源因 `Ipv4Cidr` 只表达 IPv4 而无法命中 CIDR，只能依赖 Bearer token 放行。

### 2026-10-24：接线缺口已闭合（接线 + 测试，非真机验收）

上方列出的缺口本轮全部在代码里闭合并有测试覆盖。这是控制面接线加 crate/server 集成测试——**尚无任何真实 agent 进程服务过真实发布流量。**

| 面 | 位置 | 测试 |
|---|---|---|
| 控制面 CRUD，四类对象 | `apps/server/src/publish.rs` — `POST/GET /api/v1/networks/{network_id}/publish/{forwards,http-routes,probes,dns-records}` 及 `GET/DELETE /publish/{kind}/{id}` | `apps/server/tests/publish.rs`（10 个用例） |
| Agent 探针健康端点 | `POST /api/v1/agent/publish-health` — 每探针在 `publish_probe_reports` 一条 upsert；为不属于本设备的探针写健康返回 400，未知探针 id 返回 404 | `probe_health_report_is_guarded_by_device_id` |
| DevicePlan 承载发布配置 | `crates/meshlet-network/src/lib.rs` — `publish: Option<PublishPlan>`，并入 `desired_config_hash` | `device_plan_carries_the_publish_segment` |
| Agent 运行发布层 | `apps/agent/src/agent.rs` — `PublishRuntime` 持有专用单 worker tokio 运行时；`tick` 在内核 apply 失败时也先对账发布态，再批量上报缓冲区健康（每批 256，超出丢最旧） | `meshlet-publish` runtime 测试、`apps/agent` 测试 |
| 发布领域建表 | `migrations/012_publish.sql` — 五张表（`publish_forwards`、`publish_http_routes`、`publish_probes`、`publish_dns_records`、`publish_probe_reports`） | `tests/publish.rs`、`tests/migrations.rs`、`tests/backup.rs` |

新测试钉住的口径：四类对象的建-列-查-删往返；端口冲突按 **(设备, 协议, 监听地址)** 判定——同设备同端口 409，同端口不同协议、同网络别的设备同端口均合法；`allowed_bearer_tokens` 任何读路径都不回显原文（只返回计数），也不写 `audit_events`；既无源 CIDR 又无 Bearer token 的发布对象被拒；每设备一个 DNS 套接字（同设备第二后缀 409）；每条发布写入恰好落一行 `audit_events` 与一行 `config_revisions`；重启后全部对象恢复且全局发布序列继续递增（id 不复用）。

写测试时暴露并修掉的两个真缺陷：

- `upsert_probe_reports` 把 6 个值塞进 7 列表的 `INSERT`（SELECT 列表漏了 `p.id`），导致每次探针健康上报都 500。
- `apps/agent` 持有的 `tokio::runtime::Runtime` 在异步上下文被 drop 会 panic。现在改为在独立线程里关闭该运行时，任何调用方都安全。

`tls_termination` 不再是无人读取的字段：`runtime.rs` 读取它并选 `RouteMode::TlsPassThrough`——嗅探 SNI、套用路由授权策略、把 TLS 字节直通后端。**但仍不做 TLS 终止**，无证书、不解密。

### 仍未验收的部分

- **真机端到端未跑**：尚无任何真实 agent 从服务端下发的计划绑定过转发端口、HTTP 监听或 DNS 套接字。转发、DNS、探针路径只在回环 + 高位端口上验证过（`meshlet-publish` runtime 测试）；`0.0.0.0:53` 仍需 root，未在真机上跑过。
- **无控制台 UI** 创建发布对象——CRUD 目前只走 REST API。

## Outstanding

- 运行并归档真实 VPS/真机端到端服务发布验收：真实 agent 从服务端下发的计划绑定转发端口、HTTP 监听与 DNS 套接字，外部流量进出。在此之前 TODO 记录保持待真机验证。
