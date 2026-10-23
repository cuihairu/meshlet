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

### R-06 端到端验收缺口（保持未勾）

真机端到端未闭环，原因是发布链路尚未接入运行时，不是环境限制：

- **无创建 API**：控制面没有任何创建 PortForward / HTTP 路由 / 探针 / DNS 记录的端点，因此也无法在设备上配置一条真实发布项。
- **无进程绑定监听**：`meshlet-publish` 仅被 `apps/server` 依赖；`apps/agent` 不依赖该 crate，`DevicePlan` 也不承载发布配置，因此没有任何进程实际绑定 TCP/UDP 转发端口或 DNS 套接字。
- **探针从未排程**：`HealthStatus` 从未被写入，健康探测逻辑只在 crate 内单测中被驱动。
- **TLS 终止未实现**：`tls_termination: bool` 仅在 `crates/meshlet-publish/src/http.rs:16` 声明、在 `crates/meshlet-publish/tests/http_publishing.rs:29` 设为 `true`，全仓无任何读取点，因此本仓库当前的实际行为是 SNI 嗅探 + 明文字节转发，**不做 TLS 终止**。
- **无 DNS 迁移**：仓库没有为发布领域对象建表。

以上各点在 `apps/agent` 之外 grep 不到任何调用点，属实现缺口而非配置问题。TODO 中的「R-06 服务发布 - 真实 VPS/真机端到端验收」继续保持未勾。

## Outstanding

- 运行并归档真实 VPS/真机端到端服务发布验收。前置条件是把 `meshlet-publish` 接入 agent 运行链路（见上方缺口清单）；在此之前该验收无法完成，TODO 记录保持待真机验证。
