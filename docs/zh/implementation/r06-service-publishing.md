# R-06：服务发布进展

R-06 已端到端接通并在真机上跑通：真实 `meshlet-agent` 从服务端计划绑定转发端口、HTTP 监听与 DNS 套接字，外部流量打通到发布后端。完整真机记录见 [真实 VPS 验收运行（2026-10-24）](#真实-vps-验收运行2026-10-24)；真机上仍未验证的面见 [仍未验收的部分](#仍未验收的部分)。

## Implemented

- TCP 和 UDP PortForward 可通过 mesh 发布本地服务，并保留所选传输协议。
- HTTP 和 HTTPS 发布可将外部流量路由到 mesh 服务。
- 授权控制通过 `POST /api/v1/publish/routes/check` 暴露；server 路由在 `apps/server/src/lib.rs:1014` 接入 `meshlet-publish` 服务适配器。
- 健康探测会在流量准入前验证发布目标可达。
- 内部 DNS 服务目录支持分流式服务发现，不覆盖公共 DNS 解析。
- 当前自动化验证结果为：`cargo test -p meshlet-publish` 35 passed（21 lib、1 dns_catalog、3 forwarding、4 health_probe、6 http_publishing），`cargo test -p meshlet-server` 213 passed（24 个套件，其中 `publish.rs` 11、`publish_check.rs` 2），`cargo clippy --workspace --all-targets -- -D warnings` 干净，`cargo fmt --check` 干净，控制台 17 个用例通过且构建干净。

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

### 2026-10-24：接线缺口已闭合（接线 + 测试）

上方列出的缺口已在此轮全部在代码里闭合并有测试覆盖。本节记录的是接线轮：控制面 CRUD、探针健康端点与 agent 运行时挂钩，加上 crate 与 server 集成测试。它等待的真机运行记录在 [真实 VPS 验收运行](#真实-vps-验收运行2026-10-24)。

| 面 | 位置 | 测试 |
|---|---|---|
| 控制面 CRUD，四类对象 | `apps/server/src/publish.rs` — `POST/GET /api/v1/networks/{network_id}/publish/{forwards,http-routes,probes,dns-records}` 及 `GET/DELETE /publish/{kind}/{id}` | `apps/server/tests/publish.rs`（12 个用例） |
| Agent 探针健康端点 | `POST /api/v1/agent/publish-health` — 每探针在 `publish_probe_reports` 一条 upsert；为不属于本设备的探针写健康返回 400，未知探针 id 返回 404 | `probe_health_report_is_guarded_by_device_id` |
| DevicePlan 承载发布配置 | `crates/meshlet-network/src/lib.rs` — `publish: Option<PublishPlan>`，并入 `desired_config_hash` | `device_plan_carries_the_publish_segment` |
| Agent 运行发布层 | `apps/agent/src/agent.rs` — `PublishRuntime` 持有专用单 worker tokio 运行时；`tick` 在内核 apply 失败时也先对账发布态，再批量上报缓冲区健康（每批 256，超出丢最旧） | `meshlet-publish` runtime 测试、`apps/agent` 测试 |
| 发布领域建表 | `migrations/012_publish.sql` — 五张表（`publish_forwards`、`publish_http_routes`、`publish_probes`、`publish_dns_records`、`publish_probe_reports`） | `tests/publish.rs`、`tests/migrations.rs`、`tests/backup.rs` |

新测试钉住的口径：四类对象的建-列-查-删往返；端口冲突按 **(设备, 协议, 监听地址)** 判定——同设备同端口 409，同端口不同协议、同网络别的设备同端口均合法；`allowed_bearer_tokens` 任何读路径都不回显原文（只返回计数），也不写 `audit_events`；既无源 CIDR 又无 Bearer token 的发布对象被拒；每设备一个 DNS 套接字（同设备第二后缀 409）；每条发布写入恰好落一行 `audit_events` 与一行 `config_revisions`；重启后全部对象恢复且全局发布序列继续递增（id 不复用）。

写测试时暴露并修掉的两个真缺陷：

- `upsert_probe_reports` 把 6 个值塞进 7 列表的 `INSERT`（SELECT 列表漏了 `p.id`），导致每次探针健康上报都 500。
- `apps/agent` 持有的 `tokio::runtime::Runtime` 在异步上下文被 drop 会 panic。现在改为在独立线程里关闭该运行时，任何调用方都安全。

`tls_passthrough` 不再是无人读取的字段：`runtime.rs` 读取它并选 `RouteMode::TlsPassThrough`——嗅探 SNI、套用路由授权策略、把 TLS 字节直通后端。**但仍不做 TLS 终止**，无证书、不解密。

### 字段更名与能力显式拒绝（M1，2026-10-26 落地）

这个字段原叫 `tls_termination`，但实现从来不做这件事。现已在全部位置改名为 `tls_passthrough`：
API 字段、内存模型（`HttpRoute`）、请求与视图结构、控制台类型与文案，以及数据库列
（`migrations/013_publish_tls_passthrough.sql` 原地改列名，取值与语义不变）。请求仍可用旧名：
它作为 serde alias 被接受，存量调用方不断；响应一律只输出新名。新旧两个名字同时出现在
一个请求里会被当作重复字段拒绝。

更名后，原本会被静默忽略的非法组合在创建期改成 409 显式拒绝（与既有「混合终止模式 409」同口径）：

- `tls_passthrough: true` + `allowed_bearer_tokens` → 409。路由器看不到 HTTP 头（TLS 字节对它不透明），
  bearer token 本来永远不会被校验。
- `tls_passthrough: true` + 非 `/` 的 `path_prefix` → 409。SNI 嗅探只按主机名选路、恒以 `/` 匹配，
  路径前缀本来永不参与路由。

要这两项能力就用 plain HTTP 路由，两者在那里都照常可用。真正的 TLS 终止当前不支持：
创建期拒绝才是诚实的答复，而不是用一个暗示支持的名字。

### 控制台发布对象入口（2026-10-24 落地）

创建发布对象此前只能走 REST。网络视图现在多出一个 **Service publishing** 区块（`console/src/App.tsx` 的 `PublishSection`），由 `console/src/api.ts` 里的四个方法驱动，测试见 `console/src/publish.test.tsx`。

抄谁、抄什么，写明来源便于复核：

- **Portainer 服务编辑器里的 "Port publishing"**——行表字段词汇。每条 L4 行读作 `协议 | 发布 host:port → 目标 host:port`，监听与后端拆成独立的 host / port 输入框，与 Portainer 一致；同一套词汇也被 Dokploy 每应用端口表复用，这让熟悉任一产品的人都能读懂转发行。
- **meshlet 自己的主机转发冲突卡片**——失败怎么呈现。被拒的创建渲染成与主机转发编辑器相同的 `Publishing conflict — nothing was published.` 卡片，失败既不是裸错误串，也不会看起来像发布了一半。
- **Portainer 的两步内联删除**——`Delete` 变成 `Confirm delete` + `Cancel` 原地确认，不弹窗；共用同一个 `DeleteButton`，其他发布表也用它。
- **刻意没抄**：Tailscale 应用面板是只读状态面，没有端口发布编辑器，因此除只读健康列之外无可抄。

Bearer token 只出现在创建表单里；所有读视图只保留计数，列表永不一律回显密钥。四个创建表单共用一个设备选择器。

真机浏览器走查：四个表按控制面实况渲染（两条转发、一条路由、三条探针显示 `healthy` / `healthy` / `unreachable`、一条 DNS 记录），`Create` 提交后行出现，`Delete` 需要第二次点击确认，`API errors` 全程为空。从 UI 创建并删除一条路由，agent 侧对应产出 `started=1 stopped=0`，随后 `started=0 stopped=1`。

### 真实 VPS 验收运行（2026-10-24）

主机与上节相同（`ali`，eth0 `172.19.169.82`，公网 `106.14.216.177`）。以下输出均为该主机实测原文，未修饰。设备为 `net-1` 下的 `dev-reg-2`。

```text
$ systemctl is-active meshlet-server
active

$ sha256sum /usr/local/bin/meshlet-server /usr/local/bin/meshlet-agent   # 前 16 位
9adc19a90092bca7  meshlet-server
8025b5e3f2ec831a  meshlet-agent

$ ps -eo pid,args | grep meshlet
2363888 /usr/local/bin/meshlet-server /etc/meshlet/meshlet.toml
2379033 /usr/local/bin/meshlet-agent /etc/meshlet/agent.toml

$ grep -c panicked /root/agent-publish.log
1
```

唯一那条 panic 出自**修复前**的二进制，时间 `2026-10-23T19:02:08Z`。`19:40:54Z` 装上修复版之后该计数再未增加，因此整场验收里它一直停在 1。

#### 缺陷一：SNI 嗅探器对真实 ClientHello 直接 panic

第一次跑 TLS 直通就把发布 worker 打崩了：

```text
thread 'meshlet-publish' (2322840) panicked at crates/meshlet-publish/src/http.rs:238:54:
index out of bounds: the len is 1554 but the index is 7157
```

这一条 trace 背后是三个独立缺陷：

1. `sniff_sni` 直接用下标取字节，没有任何边界检查，截断或畸形的 ClientHello 会 panic 而不是返回 `invalid`。
2. 它从不剥掉 4 字节握手头（type + 3 字节长度），所以即使结构正确的 ClientHello 也解析错——正文偏移差 4。
3. 它把 ClientHello 吃掉了却不回放，后端永远收不到握手。这一条被前两条盖住，直到一个集成测试卡到 `Elapsed`、后端报告 `0`/`N` 字节才浮出来。

修复是引入带边界的 `Cursor`（`take` / `u8` / `u16`，与 `dns.rs` 同一套写法），并确立新的约定：`sniff_sni` 返回 `(sni, 已消费的整段记录字节)`，调用方必须先用 `backend.write_all(&hello)` 回放，再 `copy_bidirectional`。

真机证明触发路径不再 panic——把纯 HTTP 打到 TLS 监听口正是旧崩溃入口：

```text
$ curl -s -m 5 -H 'Host: tls.mesh.internal' http://127.0.0.1:18090/ -w 'status=%{http_code} bytes=%{size_download}
'
status=000 bytes=0
$ grep -c panicked /root/agent-publish.log
1
```

连接被 reset，panic 计数不动。回归覆盖：`http.rs` 内 11 个单测（正常 SNI、跳过未知扩展、拒绝纯 HTTP、非 ClientHello 记录、截断的加密套件块、扩展长度虚报、server_name 列表虚报、名字条目越界、缺 host_name 条目、无任何扩展、记录体截断），加 `tests/http_publishing.rs` 3 个集成测试。

#### 缺陷二：第二个监听口与混合终止模式被静默接受

计划里每台设备只有一个 `http_listener` 和一种 `RouteMode`。第二端口从不绑定，一条 TLS 路由还会把整台设备切成 SNI 嗅探模式。两种失败都无提示，旧二进制甚至接受了与 `18090` 纯 HTTP 路由并存的 `hr-9`（`tls.mesh.internal` 在 `18091`）——结果该路由器 reset 掉每一条纯 HTTP 请求：

```text
$ curl -v -m 5 -H "Host: app.mesh.internal" http://127.0.0.1:18090/
* Request completely sent off
* Recv failure: Connection reset by peer
curl: (56) Recv failure: Connection reset by peer
```

修复是在创建时拒绝（`apps/server/src/publish.rs` 的 `check_http_socket_consistent`，与既有的一设备一 DNS 套接字守卫对称）：

```text
$ # 已有一条纯 HTTP 路由的设备再建 TLS 路由
status=409
{"error":{"code":"conflict","message":"device dev-reg-2 already serves route hr-3 with tls_passthrough=false; one termination mode per device"}}

$ # 同设备第二个监听口
status=409
{"error":{"code":"conflict","message":"device dev-reg-2 already listens for http on 0.0.0.0:18090 (route hr-3); one http listener per device"}}
```

删掉那条陈旧路由后对账干净，幽灵监听口随之消失：

```text
$ curl -s -X DELETE .../publish/http-routes/hr-9 -w 'status=%{http_code}
'
status=204
applied rev 13 applied
reconciled the publish plan started=1 stopped=1 failed=[]
18091 listeners after delete: 0
```

#### 缺陷三：每条探针只跑一次，之后再也不跑

`publish_probe_reports` 里的 `checked_at` 冻结在 `2026-10-23T18:53:07Z` 数小时，而进程一直活着。读调度器找到了原因——`spawn_probe_loop` 在每个 1 秒 tick 上给**全部** schedule 刷新到期表，而不是只刷新本次真正排了的：

```rust
for schedule in &schedules {          // 错：整表每轮刷新
    last_run.insert(schedule.id.clone(), now);
}
```

于是 `duration_since(last_run)` 永远约等于 1 秒，interval 大于 tick 步长的探针再也不会到期。修复为只对真正排出去的 schedule 记录 `last_run`。

补充一句：这也是前面 `checked_at` 冻结的真正根因——worker 并没死，先前那个「worker 不再接收」的判断其实是缺陷二把纯 HTTP 请求 reset 掉了。

连续上报，真机上相隔 35 秒两次快照：

```text
== t0 19:58:51Z ==
pb-5|healthy|2026-10-23T19:58:44Z|2026-10-23T19:58:44Z
pb-6|healthy|2026-10-23T19:58:34Z|2026-10-23T19:58:44Z
pb-7|unreachable|2026-10-23T19:58:44Z|2026-10-23T19:58:44Z
== t+35s 19:59:26Z ==
pb-5|healthy|2026-10-23T19:59:24Z|2026-10-23T19:59:24Z
pb-6|healthy|2026-10-23T19:59:14Z|2026-10-23T19:59:14Z
pb-7|unreachable|2026-10-23T19:59:24Z|2026-10-23T19:59:24Z
```

再过 65 秒：`pb-5`/`pb-7` 到 `20:01:24Z`，`pb-6` 到 `20:01:24Z`（interval 20 秒）。服务端行持续推进，这正是 `publish_probe_reports.checked_at` 的含义。回归测试：`tests/health_probe.rs` 的 `the_probe_loop_re_runs_a_due_schedule`。

#### 已验收面，真机实测

agent 按服务端下发的计划绑定的套接字（`ss -tlnup`）：

```text
udp 0.0.0.0:15353   tcp 0.0.0.0:18090   tcp 0.0.0.0:18083   tcp 0.0.0.0:18080
```

```text
$ curl -s -m 6 http://127.0.0.1:18080/                 # 转发，允许 0.0.0.0/0
L4-FORWARD-BACKEND-OK

$ curl -s -m 6 -o /dev/null -w 'status=%{http_code} bytes=%{size_download}
' http://127.0.0.1:18083/
                                                        # 转发，仅 10.9.9.9/32 可入
status=000 bytes=0                                       # reset，零字节

$ curl -s -m 6 -H 'Host: app.mesh.internal' http://127.0.0.1:18090/
HTTP-ROUTE-BACKEND-OK

$ dig @127.0.0.1 -p 15353 app.mesh.internal +short +time=3 +tries=1
10.240.0.5

$ dig @127.0.0.1 -p 15353 github.com +short +time=3 +tries=1
;; no servers could be reached       # 公共域名不在目录里，也不会被应答
```

TLS 直通——客户端看到的是**后端**证书，因为 agent 不持有任何证书：

```text
$ curl -sk -m 8 --resolve tls.mesh.internal:18090:127.0.0.1 https://tls.mesh.internal:18090/ -w 'status=%{http_code} remote=%{remote_ip}
'
TLS-PASSTHROUGH-BACKEND-OK
status=200 remote=127.0.0.1
$ echo | openssl s_client -connect 127.0.0.1:18090 -servername tls.mesh.internal 2>/dev/null | openssl x509 -noout -subject
subject=CN=tls.mesh.internal

$ curl -sk -m 8 --resolve tls.mesh.internal:18090:172.19.169.82 https://tls.mesh.internal:18090/ -w 'status=%{http_code} remote=%{remote_ip}
'
TLS-PASSTHROUGH-BACKEND-OK
status=200 remote=172.19.169.82
subject=CN=tls.mesh.internal

$ curl -sk -m 8 --resolve other.mesh.internal:18090:172.19.169.82 https://other.mesh.internal:18090/ -o /tmp/n.out -w 'status=%{http_code} bytes=%{size_download}
'
status=000 bytes=0                    # 未知 SNI：reset，后端从未被连接
```

这一项顺带暴露了一个我方脚本缺陷，值得记下：第一版脚本用 `--resolve tls.mesh.internal:18090` 配 `https://tls.mesh.internal/`，而后者默认走 443，于是 curl 根本没解析到主机（`curl: exit 6`，`remote_ip` 为空）。这是脚本 bug，不是产品 bug——`openssl s_client` 在同一端口上早已取回后端证书。把端口写进 URL 后即修正。

对账事件，全部来自 agent 日志：

```text
reconciled the publish plan started=7 stopped=0 failed=[]      # 冷启动：2 转发、1 路由、1 DNS、3 探针
reconciled the publish plan started=1 stopped=1 failed=[]      # 路由纯 HTTP → TLS
reconciled the publish plan started=1 stopped=1 failed=[]      # 路由 TLS → 纯 HTTP 还原
reconciled the publish plan started=0 stopped=1 failed=[]      # 最后一条路由删除，监听口释放
```

#### 外部可达性，从盒子之外的机器实测

```text
$ for p in 22 80 443 8080 18080 18090; do timeout 10 bash -c "echo > /dev/tcp/106.14.216.177/$p" && echo OPEN || echo BLOCKED; done
tcp 22    OPEN
tcp 80    OPEN
tcp 443   OPEN
tcp 8080  OPEN
tcp 18080 BLOCKED
tcp 18090 BLOCKED

$ curl -s -m 8 -o /dev/null -w '%{http_code}
' http://106.14.216.177:8080/api/v1/networks
401
$ curl -s -m 8 -o /dev/null -w '%{http_code}
' http://106.14.216.177:18090/
000
```

控制面可从外部访问，且在鉴权门之后。发布端口从外部**不可达**：云安全组只开 22、80、443、8080，而发布监听落在 15353、18080、18083、18090。所以上面「已验收面」全部是在回环或私网 IP 上验证的。

唯一真正打通的外部路径走的是 80 端口：临时挂一个 nginx vhost 把 `app.mesh.internal` 代理到 `127.0.0.1:18090`，外部用发布域名即可打到发布后端——

```text
$ curl -s -m 8 --resolve app.mesh.internal:80:106.14.216.177 http://app.mesh.internal/
HTTP-ROUTE-BACKEND-OK
```

该 vhost 在验收结束时已按可回退原则删除，所以下一条同样请求现在返回的是 nginx 默认页：

```text
$ curl -s -m 8 --resolve app.mesh.internal:80:106.14.216.177 http://app.mesh.internal/
<!DOCTYPE html><html><head><title>Welcome to nginx!</title>...

$ ls /etc/nginx/sites-enabled/
cockpit.cuihairu.site  coding.cuihairu.site  default  oddsmaker.cuihairu.site  wingman.cuihairu.site

$ nginx -t
nginx: the configuration file /etc/nginx/nginx.conf syntax is ok
```

也就是说：经开放端口、用发布域名把流量引入这一能力已证明可行，但它不属于盒子的常设配置，也未按常设配置验证。

### 仍未验收的部分

- **`0.0.0.0:53` 未绑定过。** DNS 套接字绑定在 `0.0.0.0:15353`，不需要 root；53 需要 root，未做任何 root 绑定尝试，所以内部后缀只在高位端口上验收过。
- **发布端口没有外部入口。** 15353 / 18080 / 18083 / 18090 从任何外部主机都被云安全组挡住，外部实测为 `BLOCKED` / `000`。
- **TLS 没有外部入口。** 443 被 `cockpit.cuihairu.site` 业务 vhost 占用，在 443 上加 nginx stream 直通会与线上业务冲突，18090 又不在安全组放行之列。TLS 直通因此只在回环与私网 IP 上验证。
- **不做 TLS 终止。** 整条链路没有证书、不解密，`tls_passthrough` 的含义是 SNI 直通。
- **发布域名的公网 HTTP 入口未常设。** 只在临时 nginx vhost 存在期间可用，该 vhost 已删除。
- **设备级限制是设计限制，不是静默 bug。** 一台设备一个 HTTP 监听口、一种终止模式，现在在创建期以 409 显式拒绝，而不是静默丢掉第二个值。需要同时发布纯 HTTP 与 TLS 域名的设备需要两个监听口，而当前计划结构表达不了。

## Outstanding

- 让一台设备表达两个 HTTP 监听口（或混合终止模式），使纯 HTTP 与 TLS 域名能并排发布。当前计划只带一个 `http_listener` 与一种 `RouteMode`；409 守卫把这个限制在创建期显性化，而不是静默丢掉第二个值。
- 在 agent 以 root 运行的设备上绑定并接受 `0.0.0.0:53`。目前只在 15353 上完成真机验收。
- 把发布域名接进盒子真实的入口层（80 端口上的 nginx 主机头，或与 `cockpit.cuihairu.site` 共存的 443 stream 直通），使外部流量无需临时 vhost 即可到达发布服务。
- 在云安全组里放行发布端口，或者接受这台盒子上只有 80 与 443 是可用的入口、发布监听只服务局域网对端。
- 真正的 TLS 终止（证书、解密、再加密），若 SNI 直通不再够用。
