# meshlet 连接稳定性提升调研报告（2026-11-13）

> 调研范围：hub 中继面 / p2p 直连面的故障链路通读、C01–C13 能力表缺口盘点、
> ZeroTier / Tailscale / plain WireGuard 生态的多线路容错机制（官方文档核实）、
> 以及落到具体文件的方案清单与落地顺序。**所有外部机制描述均经联网核实**（来源见文末）；
> 所有 meshlet 代码引用给到 file:line。本报告只调研，不含 commit。

## 0. 结论速览

- meshlet 的稳定性短板不是「没有直连」，而是**容错面太薄**：hub 是单 endpoint 单进程单 VPS
  的硬单点；直连切换闸的输入（ICMP 探测）在 Windows 防火墙 / ZT 面骑跨场景下大面积失真；
  一旦 UDP/51820 整体被封，全网络没有任何回退传输。
- 近期 6 连修（`00da12b` 探测默认开 → `c4e5038` 现路径无窗口不切换）已经把「切换闸误动作」
  这一类抖动压下去了；剩下的收益大头按序是：**①切换闸参数与探测口径收尾（S）→
  ②多 hub endpoint 轮换（M）→ ③第二中继 hub（M/L）→ ④MTU/路径诊断强化（M）→
  ⑤STUN/NAT 判断（L）→ ⑥TCP/443 回退（XL）**。ZT 骑跨面先收编（观测上报），不急于排除。
- 「zerotier 是三条线」的说法经核实对应 ZeroTier 的三类容错来源：多 root（PLANET）转发网、
  multipath bond（active-backup 等策略）的物理多链路冗余、以及 UDP 死路时的 TCP/HTTPS relay
  兜底。meshlet 单 hub 架构下，三者分别对应本报告的方案 3（第二中继）、方案 8（弱聚合保活）
  与方案 6（TCP 回退），可借鉴其语义，不必照搬其分布式实现。

## 1. 现有连接链路通读与单点清单

### 1.1 hub 中继面（控制 + 数据）

链路：agent 每 `poll_interval_secs`（默认 30s，`crates/meshlet-config/src/agent.rs:286`）
tick → `server::fetch_plan`（`apps/agent/src/server.rs:21`）→ 本地兜底 `plan_with_hub_endpoint`
（`apps/agent/src/agent/plan_adapter.rs:9`）→ 内核对账应用（`apps/agent/src/agent/reconcile.rs:26-30`，
其中 `enforce_hub_keepalive` 把 hub peer keepalive 钉到 ≥25s，`plan_adapter.rs:28`；
常量 `crates/meshlet-network/src/plan.rs:123`）。tick 失败走指数退避，上限 30s
（`apps/agent/src/agent/mod.rs:57`），网络变化事件（netlink / `NotifyAddrChange`）立即唤醒重试
（`apps/agent/src/net_event.rs:28`，`agent/mod.rs:222-256`）。

**单点/脆弱点（hub 面）：**

| # | 脆弱点 | 证据 |
|---|---|---|
| H1 | `hub_endpoint` 是单值 `Option<String>`，一个 hub IP:port，无备选 | `crates/meshlet-config/src/agent.rs:193`，`apps/agent/src/agent/plan_adapter.rs:9-23` |
| H2 | `server_url` 同样单值：hub 进程挂 = 控制面 + 数据面同时失联，agent 只能退避重试 | `apps/agent/src/agent/mod.rs:66`（`server_url: String`），`apps/agent/src/server.rs:21` |
| H3 | hub peer endpoint 写死后无重解析：`hub_endpoint` 支持 hostname 但只在计划适配时填一次，DNS 变化不触发重新解析 | `plan_adapter.rs:11-20`（仅在 `peer.endpoint.is_none()` 时填） |
| H4 | hub 宕机时 agent 侧无「数据面判死」信号：presence 由 hub 算（`crates/meshlet-domain/src/presence.rs:68-81`，agent 窗口 5min/握手 2min），hub 自己死了没有人为 agent 判死 | `apps/server/src/presence_watch.rs:84-101` 只在 hub 活着时才有意义 |
| H5 | spoke↔spoke 中继依赖 hub 内核转发 + `MLT_wg0` 链（同段 ACCEPT/跨段 DROP），转发面也是 hub 单点（dev 实测：`-A MLT_wg0 -i wg0 -o wg0 -j ACCEPT`；ip_forward 由 unit 打开 `deploy/systemd/meshlet-agent.service:25`、`deploy/systemd/meshlet-server.service.d/dataplane.conf:3`） | hub 实机 iptables（2026-11-13 核查） |
| H6 | hub 观测源地址是候选公网 endpoint 的唯一来源（`apps/server/src/agent.rs:119-137` 的 `direct_observed_ip`），hub 死 = 候选集冻结，直连面跟着瞎 | `apps/server/src/agent.rs:324` |

### 1.2 p2p 直连面

链路（每 30s 一轮，`crates/meshlet-domain/src/p2p/link.rs:11`）：
hub 下发候选 `peer_endpoints_for`（`crates/meshlet-domain/src/p2p/report.rs:117-151`；
候选 = hub 观测公网 IP + agent 自报 RFC1918 列表，`report.rs:74-92`）
→ agent `reconcile_direct`（`apps/agent/src/agent/direct.rs:41`）拉候选
（`server.rs:38`）→ `decide_direct_path`：LAN 命中选 SameLan、否则公网 HolePunch、否则 Relay
（`crates/meshlet-domain/src/p2p/endpoint.rs:95-118`）→ 状态机 `on_probe`
（`link.rs:125-158`：Relay→Promote、pending 3 周期超时 Demote、Direct 握手过期 Demote）
→ `wg set` 下发 `/32` 直连 peer（`apps/agent/src/direct.rs:438-450`，AllowedIPs 只写对端 `/32`，
`crates/meshlet-domain/src/p2p/allowed_ips.rs:23-36`）。

探测与切换的三层闸：

- **SEL-001 探测**：独立线程 5s 一轮，对每 peer 每候选发 ICMP，滑动窗口 20 样本
  （`apps/agent/src/probe.rs:66-84`；`ProbeConfig` 默认 `interval_secs=5, window=20`，
  `crates/meshlet-config/src/agent.rs:276-281`）。传输为平台 `ping -c/-n 1`，超时 1s
  （`crates/meshlet-network/src/probe.rs:261-276`；Windows 接线 `df21f88`）。
- **SEL-002 迟滞切换**：`SwitchGate::evaluate` 要求新路径连续 3 轮得分优于现路径 ≥30% 才切
  （`probe.rs:355-424`；`score = rtt * (1 + 10 * loss_rate)`，`probe.rs:286-303`）。
  现路径无窗口 → 不切换（`c4e5038`，`probe.rs:365-372`）。
- **SEL-003 劣化回退**：`is_degraded` = 丢包率 ≥50% / 末样本超时 / RTT 中位数 ≥800ms 任一命中
  立即 Demote（`probe.rs:458-474`）；回中继后须连续 3 轮健康才放行切回
  （`RecoveryGate`，`probe.rs:479-521`；接线 `apps/agent/src/agent/direct.rs:142-161`）。
  劣化优先级最高，握手新鲜不能否决劣化（`apps/agent/src/direct.rs:370-399`）。
- **握手兜底**：晋升只认 WG 握手证据（≤180s，`link.rs:36`），健康窗口 240s——必须大于 WG
  rekey 节拍（~120–180s，keepalive 不刷新 latest-handshake），否则 promote/demote 每 ~90s 抖动
  （`link.rs:14-24` 真机取证注释）。读数缺失时用 `wg dump` 投影兜底
  （`apps/agent/src/direct.rs:474-483`）。

重启恢复：`{state_dir}/direct.json` 只存 keep set（pubkey+VIP），恢复为 Direct 再由握手收敛
（`apps/agent/src/direct.rs:146-200`）；状态上报进 `direct-peers.json` /
`direct-switch-events.json`（`crates/meshlet-network/src/dial.rs:108-120`）。

**单点/脆弱点（直连面）：**

| # | 脆弱点 | 证据 |
|---|---|---|
| D1 | 探测传输只有 ICMP 一条腿。Windows 默认拦 wg 接口/候选 IP 的 ICMP echo → 窗口全 Lost → `is_degraded` 无基线豁免（正确），但 SEL-002 评分、RTT 标注也全盲，切换闸实际失能 | `probe.rs:255-276`；豁免逻辑 `probe.rs:462-466`；SEL-002 复验实录 `docs/acceptance-evidence/sel-002-realdeath-rerun-2026-11-13.md`（两台 Windows 对端防火墙拦 ICMP，候选窗口全 Lost） |
| D2 | 探测目标与 WG 会话的实际路径**口径不一致**：SEL-001 探候选 IP（underlay），而 WG roaming 后真实路径可能在候选表之外（真机实锤 192.168.5.0/24 面）。现路径无窗口不切换（`c4e5038`）避免了误切，但也意味着 roaming 面**永远没有质量读数**，劣化只能等握手 240s 兜底 | `probe.rs:365-372`；sel-002 复验「服务端候选表不含 192.168.5.x」 |
| D3 | 切换即会话重建：`wg set peer endpoint` 换 endpoint 后 WG 对新路径重新握手，握手年龄瞬间拉满 → 在 240s 窗口内恰逢 SEL-003 有读数就构成「切换→劣化→回中继」极限环（sel-002 第二根因的实际链路）。切换后没有「新路径宽限期」。**勘误（2026-11-14，按深夜 keyed 实测补）**：环内 demote 的实测触发者是 SEL-003 对 ZT 面窗口的瞬态劣化（demote 时握手 age 56–120s ≪240、握手正常 rekey，classify 排除嫌疑——`docs/acceptance-evidence/sel-002-imac-keyed-trace-2026-11-14.txt`）；「年龄拉满」路径（None → DirectPending 90s 超时）在 promote 后 nohs 阶段真实存在但非本轮实测的触发主因。宽限期方案的必要性不变，两类触发都受它保护 | `apps/agent/src/agent/direct.rs:296-353`（切换后立即 `record_endpoint`，无宽限逻辑） |
| D4 | 候选集质量不可控：ZT 面地址（10.147.19.x）混进 RFC1918 上报成为 `lan` 候选，openclaw-win 的直连面骑跨匿名 ZT 成员 10.147.19.17 的中继面（todo.md [P0] spoke-to-spoke 调查记录）。上游劣化时直连跟着抖 | `crates/meshlet-domain/src/p2p/report.rs:77-87`（RFC1918 一律收为 lan 候选，无接口归属/来源标注） |
| D5 | 初始路径选择无评分：`decide_direct_path` 取「地址最小」的确定性选择（`endpoint.rs:104,113`），不看 RTT——LAN 命中即用，公网多候选时可能选中劣化路径再靠切换闸纠偏 | `endpoint.rs:95-118` |
| D6 | pending 超时回退的最坏等待 = 3 周期 × 30s = 90s（探测 5s 不参与 pending 推进），打洞慢时用户感知「拨号中」近两分钟 | `link.rs:12-13` + `on_probe`（`link.rs:139-152`） |
| D7 | 单 hub 下候选的「公网 endpoint」只有 hub 视角的一个观测 IP：多出口设备（多 WAN）或 CGNAT 场景候选根本不存在，直连无从谈起（H6 的直连面投影） | `report.rs:38-53`（observed_endpoint 只有单值） |

### 1.3 控制面 / 观测面

- 心跳携带直连候选与链路状态（`apps/agent/src/agent/heartbeat.rs:25-46`；上报契约
  `crates/meshlet-domain/src/p2p/link.rs:186-233`），hub 只存内存态
  （`apps/server/src/service/operations.rs:611-633`）——**hub 重启即丢全部候选/链路状态**，
  要等所有 agent 各走一轮心跳才恢复（最坏 ~2×poll 周期 + 每设备轮询相位差）。
- presence 判定与时间线日志有 watchdog（`8824997`），但指标面（`apps/server/src/metrics.rs`）
  没有「直连占比 / 切换次数 / 劣化回退次数」这类稳定性 SLO 读数，事故只能靠翻 journal。

## 2. C01–C13 缺口盘点（对照 docs/zh/analysis/personal-networking-comparison.md §4.1）

> 表内「当前」列以 2026-11-13 代码为准，比原文档（写于直连落地前）更新。

| ID | 原表判级 | 现状（代码证据） | 实现代价 | 对应方案 |
|---|---|---|---|---|
| C01 稳定虚拟 IP | 必需/M | ✅ IPAM 已有（`devices.virtual_ipv4`，hub 实测 10.240.0.1/16 分发正常） | — | — |
| C02 自动 UDP 直连 | 推荐/XL | ✅ 已落地：SameLan/HolePunch 决策 + 30s 状态机（§1.2），Linux 32-34s 自愈已验 | — | — |
| C03 同 LAN 直连 | 推荐/L | ⚠️ 部分：候选来自 agent 自报 RFC1918，**没有主动 LAN 发现**（不经 hub 就发现不了新上线的同段 peer，候选相位差最多 2×30s） | S：hub 把心跳里的 lan_addrs 即时广播进下一轮候选即可（已有通道） | 方案 7 附属 |
| C04 公网端点直连 | 推荐/L | ⚠️ 单观测 IP（D7），无 IPv6 候选（`report.rs` 全程 `Ipv4Addr`） | M：多观测（见方案 2/5） | 方案 2、5 |
| C05 STUN 与 NAT 判断 | 条件/L | ❌ 无：公网候选 = hub 单视角观测，对称 NAT 无端口预测 | L：引 stun 客户端 + NAT 类型分类（方案 5） | 方案 5 |
| C06 UDP 中继保底 | 必需/L | ✅ hub 中继即保底（整段路由，直连 `/32` 拆分即回退，`allowed_ips.rs:23-36`）；短板在 hub 自身可用性（H1-H5） | — | 方案 2、3 |
| C07 TCP/HTTPS 回退 | 推荐/XL | ❌ 无任何非 UDP 传输；hub wg 监听仅 UDP/51820（hub 实机 `wg show`） | XL：userspace WG/boringtun over TCP + 计划通道（方案 6） | 方案 6 |
| C08 路径升级与降级 | 推荐/XL | ✅ 主体已落地（direct ↔ relay 双向 + SEL-002 路径间切换）；缺切换宽限期与 roaming 面读数（D2/D3） | S | 方案 1 |
| C09 端口映射 | 条件/M-L | ❌ 未做自动映射；hub 公网端口手动配 | 条件触发再做 | — |
| C10 自有备用中继 | 条件/L | ❌ 单 VPS（H1/H2）；_easytier-comparison.md_ 也标记「单一 hub = SPOF」 | M/L（方案 3） | 方案 3 |
| C11 MTU 与路径诊断 | 必需/M | ⚠️ 半成品：`derive_tunnel_mtu` 推导辅助有了（`plan.rs:125-139`），但**无运行时 PMTU 实测**（无 DF 大包探测），诊断快照无 MTU 维度 | M（方案 4） | 方案 4 |
| C12 多链路聚合 | 暂缓/XL | ❌ 无；不建议做完整聚合，但「双路径弱保活」可作为低成本近似 | XL→可拆 S 弱化版 | 方案 8 |
| C13 速度基准 | 必需/M | ⚠️ API 基准有；无三方可比实测与本报告相关的稳定性 SLO 指标 | S-M | 方案 9 |

## 3. 外部机制调研（官方文档核实）

### 3.1 ZeroTier 的多线路容错（对应「三条线」的说法）

核实到三层机制：

1. **Root（PLANET）转发网 = 中继兜底线**。VL1 语义：「VL1 never gives up. If a direct path
   can't be established, communication can continue through (slower) relaying. Direct
   connection attempts continue forever on a periodic basis.」——中继是永续保底，直连尝试永不
   停止[2]。LEAF 节点走 RELAY 状态时「packets are bouncing through our root servers because a
   direct connection between peers cannot be established」，代价是高延迟与丢包[3]。ZT 官方对
   自托管/受限网络的建议是：策略不允许出网 UDP 时，部署一台 **TCP relay（pylon reflect，
   TCP/443）** 作为兜底，agent 配置 `tcpFallbackRelay` 自动回落，`forceTcpRelay` 可强制[4]。
   NAT 语义：Easy NAT 直连可靠，Symmetric/CGNAT「will be forced through relay servers」[5]。
2. **Multipath bond = 物理多链路冗余线**（企业版特性）。标准策略：`active-backup`（单活，
   `failoverInterval` 可到 1s，`linkSelectMethod` 决定主路径恢复语义：`always/better/failure/
   optimize`）、`broadcast`（全链路复制，故障切换近似零损）、`balance-rr/xor/aware`（分片/哈希）；
   每链路可设 `mode: primary|spare`（warm spare 不承载流量但持续探测）、`failoverTo` 链；
   链路质量用 `lat_max/pdv_max` 加权向量表达，越限即迁流[1]。CLI 可 `bond list/show/rotate`
   观测每路径 lat/pdv/plr/rx_age/tx_age[1]。
3. **NAT 判断与穿透工具箱**：UDP 打洞 + LAN 发现 + 「port prediction for traversal of
   symmetric IPv4 NATs」+ uPnP/NAT-PMP 显式映射[2]。

**对 meshlet 的适用性判定：**
- 「直连尝试永不停止 + 中继永远可用」的**语义** meshlet 已对齐（Relay 保底 + 30s 状态机）；
  ZT 的差异在于中继网本身是冗余的（全球多 root），meshlet 是单 hub —— 这是方案 3 要补的。
- active-backup + failoverInterval + linkSelectMethod 的**参数化语义**正是 meshlet SEL-002/003
  迟滞闸的对照物：ZT 用「探测→判定→切换→恢复语义」四段，meshlet 已有探测/切换/恢复，缺
  「切换后的宽限」（D3）与「spare 链路持续探测」的等价物（方案 8）。
- port prediction / uPnP 属于 C05/C09 范畴，作为方案 5 的延伸，不建议第一优先。

### 3.2 Tailscale：DERP 池 + 多 home DERP

- DERP 双职责：协商直连 + 最后兜底中继；「Most connections between tailnet devices only use
  DERP servers to establish a direct connection」；DERP 中继的流量仍是端到端 WireGuard 密文，
  「A DERP server blindly forwards already-encrypted traffic」[6]。
- 容错结构：**DERP map 由协调服务器下发，每个 region ≥3 台**；客户端按延迟自选 home DERP 并
  上报，协调服务器把选择广播给全网；协调服务器宕机时客户端用**本地缓存的最后已知 DERP map**
  继续连接[6]。降级链路：直连 → peer relay（自建/同网设备中继，优先于 DERP）→ DERP[7]。
- STUN：客户端向**所有** DERP 发 STUN，服务端记下观测到的公网 IP:port，`netcheck` 输出 NAT
  类型与可用性[8]。DERP 本身跑在 **HTTPS/443**，「Any device that can open an HTTPS connection
  to an arbitrary host can build a tunnel using DERP relays」[7]——这就是 UDP 被封场景的答案。
- HA 另一面：subnet router 同前缀多台宣告即主备 failover（路由层冗余，与数据面中继冗余正交）[9]。

**对 meshlet 的适用性判定：**
- 「控制面下发 → 客户端本地缓存 → 控制面死了中继还活着」的语义是方案 2/3 的直接借鉴点：
  meshlet 的 agent 端应该**持久化最后已知 hub endpoint/候选集**，控制面不可达时数据面决策不冻结。
  （当前 `hub_endpoint` 是静态配置，不算缓存失效问题，但**候选集/计划**只存内存，值得做本地快照。）
- DERP = 「HTTPS 传输里跑密文 WG」验证了方案 6（TCP/443 回退）的可行形态：不必兼容 DERP 协议，
  语义对齐即可（meshlet 的对比文档也明确「不能预先承诺 DERP 协议兼容」，见
  _personal-networking-comparison_ §5.2）。
- 多 home DERP（每 region 3 台 + 延迟自选）对单 hub meshlet 过重；可借鉴的只是「**中继池 ≥2**
  + 按延迟选优」这一条，落地即方案 3。

### 3.3 plain WireGuard 生态

- **同 allowed-ips 多 peer**：内核 WG **禁止**两个 peer 拥有重叠的 AllowedIPs——「WireGuard
  prohibits duplicating AllowedIPs networks across peers. If you add 0.0.0.0/0 to the
  AllowedIPs of one peer, it is removed from the AllowedIPs of every other peer」（后配置者赢）；
  想做多路径要么每 peer 精确前缀，要么**每 peer 一个独立接口**再让内核路由层决策[10]。
  ⇒ meshlet 现有的「hub peer 持整段路由 + 直连 peer 只拿 `/32`」正是最长前缀多路径的标准
  plain-WG 形态（`allowed_ips.rs:23-36`），**结构上已经是对的**；要做第二中继（方案 3），
  每个 hub 用不同接口名或用更短前缀区分即可避开重叠限制。
- **rr/netns 方案**：社区共识是没有原生 multipath——`balance-rr` 类行为要靠多接口 + 策略路由
  （或 nftables 级分片）实现，TCP 乱序敏感，实用形态只有 active-backup[10]。boringtun/
  userspace WG 的价值不在多路径而在**传输可编程**（TCP/WS 封装），这是方案 6 的技术底座；
  meshlet 数据面目前全部走内核 WG（`SystemBackend`，`apps/agent/src/agent/mod.rs:53`），
  引 userspace 栈是 XL 改动的根本原因。
- NetBird（同类自托管 WG mesh）的对照：relay 即 TURN/WebSocket 中继，「Plan B」语义，
  可自托管[11]——证明「第二中继」在 WG 生态是常规操作，不是 ZT 专属。

## 4. 方案清单

> 量级：S ≤1 天 / M 1-3 天 / L 3-7 天 / XL >1 周（单人，含测试）。每项给出
> (a) 故障场景 (b) 改动面 (c) 量级 (d) 依赖与风险 (e) 建议优先级。

### 方案 1：切换闸参数与口径收尾（迟滞/窗口/宽限）
- **(a) 故障场景**：单点切换震荡——切换后新路径无读数被 ∞ 评分误判（已修 `c4e5038`，但只挡了
  「无窗口」一种）、切换→握手年龄拉满→SEL-003 误回退的极限环（D3）；degrade_rtt_ms=800 在
  探测超时 1000ms 下的盲带。
- **(b) 改动面**：
  - `crates/meshlet-network/src/probe.rs`：`SwitchGate::evaluate` 后追加**切换宽限**——切换后
    `switch_required × interval` 秒内禁止再次切换、禁止对现路径判劣化（需要给 gate 记
    `last_switch_at`）；`is_degraded` 对「窗口样本 < N」的年轻窗口豁免（同无基线豁免语义）。
  - `crates/meshlet-config/src/agent.rs`（`ProbeConfig`，:236-281）：新增
    `switch_cooldown_secs`（建议默认 = interval×required×2）、`degrade_min_samples`（建议 4）。
  - `apps/agent/src/agent/direct.rs`：`apply_switch_decisions`（:301-353）把冷却期传入 gate；
    切换事件已落 `direct-switch-events.json`（`crates/meshlet-network/src/dial.rs:108-110`），
    直接复用做震荡观测。
- **(c) 量级**：**S**（纯逻辑 + 单测，probe.rs 测试基建齐全）。
- **(d) 依赖与风险**：无外部依赖。风险是宽限过长延迟真故障切换——冷却上限建议 ≤60s；
  `degrade_rtt_ms` 已有配置面，不动语义只补年轻窗豁免，与「降级口径不放松」原则不冲突
  （豁免的是「读数不足」，不是「读数差」）。
- **(e) 优先级**：**P0**。这是 11-13 三连修的收尾，趁热落地。

### 方案 2：多 hub endpoint 轮换（hub_endpoint → 列表 + 本地缓存 + 重解析）
- **(a) 故障场景**：hub 换 IP/迁移、DNS 变更、公网 endpoint 抖动——当前单值配置下 agent 面对旧
  endpoint 只能退避空转（H1/H3）；换网（net_event 已有立即重试）后 hub endpoint 若也换了，
  agent 无从得知。
- **(b) 改动面**：
  - `crates/meshlet-config/src/agent.rs`：`hub_endpoint: Option<String>`（:193）保持兼容，
    新增 `hub_endpoints: Vec<String>`（TOML 数组），解析层归一为非空列表（单值进列表首位）。
  - `apps/agent/src/agent/plan_adapter.rs:9`：`plan_with_hub_endpoint` 改收列表；**失败转移**
    的判定信号来自 WG 内核——hub peer `latest-handshake` 年龄超阈值（复用
    `DIRECT_HEALTH_WINDOW_SECS` 口径或新常量，建议 180s）即认为现 endpoint 死，下一 tick 起
    轮换到列表下一个（对 hub peer 做 `wg set peer endpoint`，roaming 同 SEL-002 的零断线机制）。
  - `apps/agent/src/agent/reconcile.rs`：对账时 hub peer 的 endpoint 生成逻辑同步列表语义。
  - `crates/meshlet-network/src/linux/operations.rs` / `windows/`：`set_hub_endpoint` 类接口
    （可复用 `set_direct_endpoint_sync` 的路径，加 peer 定位为「计划第一个 peer」）。
  - 本地缓存：`{state_dir}/hub-endpoints.json` 存最后已知列表（对齐 DERP「控制面死了中继还
    活着」语义），`crates/meshlet-config/src/agent.rs` 的默认列表 + 本地发现的新 endpoint
    （如 server_url 解析出的 IP）合并。
- **(c) 量级**：**M**（配置 + 适配器 + 轮换状态机 + 双平台接线）。
- **(d) 依赖与风险**：依赖 WG roaming（内核已证可靠：todo.md 端点破坏实验「~15s 内 WG roaming
  自愈」）。风险：hostname endpoint 的解析失败要按「死」处理但要与 DNS 瞬时故障区分——轮换
  判死阈值 ≥3 分钟起。兼容性：单值配置完全不变。
- **(e) 优先级**：**P1**。

### 方案 3：第二中继 hub（backup relay）
- **(a) 故障场景**：hub VPS 宕机/被封端口/被限流——全网瘫（H2/H5），这是「自托管单点」最大
  的可用性风险；`personal-networking-comparison` C10 行早已标记。
- **(b) 改动面**（复用 meshlet 已有「一台机器可自建 server」的事实，`meshlet-ops` 技能记录
  home-pve 就跑着自己的 meshlet-server）：
  - 数据面：备用 hub 起 `meshlet-server`（同二进制，`wg0` 段不同 overlay 或同 overlay 段），
    主 hub 的计划里**不**下发备用 hub peer——备用中继走**第二 wg 接口**（`wg-mlt-backup`），
    规避 plain WG 的 allowed-ips 重叠禁令[10]。agent 侧数据面备 peer 由配置
    `[dataplane] backup_hub_endpoint` + `backup_interface` 声明。
  - `apps/agent/src/agent/mod.rs` tick：主 hub 控制面连续 N tick 失败（复用 backoff 计数，
    `mod.rs:227-256`）→ 激活备用面（起第二接口 + 对备用 hub peer 的 keepalive，keepalive 沿用
    `HUB_KEEPALIVE_SECS`）；主面恢复 → 拆除备用面（回切要迟滞，避免乒乓）。
  - `crates/meshlet-network/src/plan.rs`：`DevicePlan` 增加 optional `backup_hub` 段（备
    endpoint + 网段 + keepalive），由 server 在网络配置里声明（`crates/meshlet-config/src/server.rs`
    加 `[backup_hub]` 段）。
  - 控制面备用：**不做**完整控制面双活（审批/修订是单 DB 语义，双活是 XL）。备用 hub 只承载
    数据面中继 + 「主 hub 失联」的只读判断。断主期间 agent 状态 tray 显式标注 `degraded`。
- **(c) 量级**：**M/L**（数据面 M；若把备用 hub 也纳入 console 管理则 L）。
- **(d) 依赖与风险**：需要第二台公网 VPS（用户已有 dev 一台；备 hub 可以用低配）。风险：
  备 hub 的 wg 私钥/peer 管理是第二套身份，key 分发要走现有 bootstrap 流程；两 hub 的
  overlay 网段规划要避开（如主 10.240.0.0/16、备 10.241.0.0/16），应用层 IP 引用会随切换变化
  ——这是该方案**唯一的**用户体验代价，须在文档写明（ZT 换 root 也有同类语义代价）。
- **(e) 优先级**：**P1**（排在方案 2 后：先让单 hub 的 endpoint 轮换可靠，再加第二台）。

### 方案 4：MTU / 路径诊断强化（C11）
- **(a) 故障场景**：PPPoE/中间盒场景下 1420 默认 MTU 过大 → 大包黑洞、小包通（TCP 握手成功
  但传输卡死），与直连/中继切换无关，现有 13 项诊断抓不到；sel-002 复验的「两探针口径差」
  （SEL-001 探 underlay 候选 vs enrich 探 overlay）也是诊断口径问题。
- **(b) 改动面**：
  - `crates/meshlet-network/src/diag.rs` + `linux/operations.rs`：诊断快照新增
    `path_mtu`——对 hub endpoint 与直连 endpoint 各发一轮 DF 大包阶梯探测
    （1420→1400→1380…，`ping -M do -s <size>` Linux / `ping -f -l <size>` Windows，
    两者已有平台探测基建 `linux.rs::run_ping_rtt` / `windows_probe.rs` 可复用）。
  - `crates/meshlet-network/src/plan.rs:125-139`：`derive_tunnel_mtu` 的结果接入诊断展示，
    并在 `NetworkDiagnostics` 里比对「计划 MTU vs 实测 PMTU」，不一致即告警字段。
  - `apps/agent/src/agent/heartbeat.rs`（`collect_evidence`，:68）：证据里带上 MTU 读数，
    console 设备详情展示。
  - 统一探针口径：把 SEL-001 的探测目标扩为「候选 endpoint + 现役 roaming endpoint」
    （`apps/agent/src/probe.rs::update_candidates` 输入加现路径），消除 D2 的盲区同时
    解决 todo.md 记录的「enrich probe_failed 但 SEL-001 仍 Healthy」口径差。
- **(c) 量级**：**M**。
- **(d) 依赖与风险**：DF 大包探测在部分运营商网会被限速/丢弃 → 读数要标 `unknown` 而非
  `failed`（沿用 `rtt_source` 的四态如实标注模式，`apps/agent/src/direct_rtt.rs`）。
  现路径探测会多一条 ICMP 流（5s 周期 ×1），控制面零负载纪律不变。
- **(e) 优先级**：**P2**。

### 方案 5：STUN / NAT 判断增强（C05、C04）
- **(a) 故障场景**：对称 NAT/CGNAT 下 hub 单视角观测拿不到可打洞 endpoint（D7），直连率低；
  「NAT 类型」不可见导致用户无法自证网络环境（O01 的连接路径可观测缺口）。
- **(b) 改动面**：
  - 引 `stun-client`（纯 Rust，tiny）或手写 RFC5389 最小子集（Binding Request/Response，
    ~200 行）：agent 周期向 **hub 自身的 UDP/51820** 发 STUN（hub 是天然 STUN 服务器——
    观测源地址这件事 hub 本来就在做，`apps/server/src/agent.rs:119-137`；公网 STUN 服务器
    是可选项，默认关、显式开启，符合「外部查询须明示」纪律）。
  - `crates/meshlet-domain/src/p2p/report.rs`：`DirectEndpointReport` 增 `nat_type`、
    `stun_observed: Option<EndpointCandidate>`（STUN 观测的映射 endpoint，与 hub 观测对比
    即可分类：一致=EI/NOCONE，不一致=Symmetric）。
  - `endpoint.rs::decide_direct_path`：对称 NAT 且对端也是对称 NAT → 直接判 Relay（省 90s
    pending 空转，D6 顺带缓解）；端口预测（ZT 手法[2]）列为后续不做承诺。
  - console 设备详情/`direct-peers.json` 展示 nat_type（`crates/meshlet-network/src/dial.rs:55`
    的单条结构加字段）。
- **(c) 量级**：**L**（协议实现 + 契约扩展 + 双端）。
- **(d) 依赖与风险**：依赖 hub UDP 通道（已存在）。风险小：STUN 失败 = 字段缺省，不影响现有
  链路；对称 NAT 判 Relay 可能让部分「其实能通」的路径不再尝试——用配置开关
  `[dataplane.direct_connect] symmetric_relays=true` 默认保守（尝试）。
- **(e) 优先级**：**P2**。

### 方案 6：TCP/443 回退传输（C07）
- **(a) 故障场景**：UDP 整体被封（企业网/运营商 QoS）——当前全网络无解，唯一 workaround 是
  ZT 面骑跨（这正是 D4 现象存在的根因：用户在用 ZT 补 meshlet 的这个洞）。
- **(b) 改动面**（XL，必须拆两期）：
  - **一期（hub 侧终止 TLS，hub 内解密转发）**：hub 起一个 `wss`/TLS-TCP 监听
    （443 或可配端口，与 nginx 共存需 ALPN/路径分流，`docs/analysis/architecture.md` 的
    反代纪律适用）；agent 侧数据面在 UDP 不可达（hub peer 握手年龄超窗 + STUN/探测全灭）
    时切到 userspace WG（`boringtun` 或 `wireguard-rs` 生态 crate）over TCP，把 overlay 流量
    封装进 TLS 流。改动面：新 crate `meshlet-transport`（boringtun 封装 + TCP 帧协议）；
    `apps/agent/src/agent/mod.rs` 数据面选路（内核 WG 为主、userspace-TCP 为备，**同一 overlay
    IP**，切换 = 路由切换不换地址）；hub 侧 `apps/server` 增 TCP relay listener，把 agent 的
    userspace WG 流量对接进 hub 的内核 wg0（hub 充当 userspace↔kernel 桥）。
  - **二期（可选）**：端到端 userspace WG（agent↔agent 直连 over TCP），只有一期证明价值后做。
  - 参照语义：ZT `tcpFallbackRelay` 自动回落 + `forceTcpRelay` 测试开关[4]；Tailscale DERP
    over HTTPS 的「443 必通」定位[7]。**不能只改 WG 监听端口**（对比文档 §4.1 C07 已明确）：
    UDP 封禁环境下 UDP:443 同样被封，必须是真 TCP/TLS。
- **(c) 量级**：**XL**（一期 1-2 周，二期另计）。
- (d) **依赖与风险**：引入 userspace WG 栈 = 数据面新依赖 + 性能损耗（TCP 队头阻塞，对比文档
  §5.2 已预警「套 TCP 的回退可能因有序传输与丢包产生队头阻塞，只作为可用性保底」）；
  hub 侧桥接的会话管理（多 agent 复用一条 TCP）是新状态机。**验收门禁**：只在「UDP 双向不通」
  时激活，UDP 恢复即回切（复用方案 1 的迟滞闸参数）。
- **(e) 优先级**：**P3**（最贵的保底，但也是唯一覆盖「UDP 封禁」场景的项；若 ZT 骑跨收编
  （方案 7）后用户不再需要 ZT，此项降为 P4 由用户按需驱动）。

### 方案 7：ZT 骑跨面收编（先观测、后排除）
- **(a) 故障场景**：10.147.19.x（ZT 网段）地址被当 RFC1918 LAN 候选上报，openclaw-win 的
  「直连」实际骑跨匿名 ZT 成员 10.147.19.17 的中继面（todo.md [P0] 实锤）——ZT 面劣化直接
  变成 meshlet 直连抖动（sel-002 第二轮的 ZT 面瞬态触发 SEL-003 回收就是这一机制）。
- **(b) 改动面**：
  - **收编（先做）**：`crates/meshlet-domain/src/p2p/report.rs:77-87` 的 `endpoint_candidates`
    给每个 lan 候选加**来源标注**（interface name / prefix 生命周期），心跳上报接口名；
    agent 本地 `lan_subnets_sync`（`crates/meshlet-network/src/linux/operations.rs:117`）
    已按接口枚举，把「已知虚拟网段」标记出来（ZT `10.147.0.0/16`、自身 meshlet overlay
    `10.240.0.0/16`、Tailscale `100.64.0.0/10` 等，做成可配黑名单
    `[dataplane.direct_connect] excluded_subnets`，默认含主流 overlay 网段）。
  - **排除（后做，默认关）**：`decide_direct_path`（`endpoint.rs:95-118`）对被排除候选不再
    选为 SameLan；候选仍上报（console 可见「检测到第三方 overlay 面」）。
  - 对已确认的匿名成员 .17：这是 hub/controller 侧治理动作（对账 ZT controller 成员表），
    不在 meshlet 代码面内，作为运维项记录。
- **(c) 量级**：**S**（标注+黑名单）/ **S**（排除开关）。
- (d) **依赖与风险**：黑名单误伤「真 LAN 恰好是 10.147.x」的概率极低但存在——黑名单按网段
  可配即兜底。收编阶段对现有行为零影响。
- **(e) 优先级**：**P1**（与方案 2 并行；它是当前真机抖动的直接相关项）。

### 方案 8：multi-path 同时保活（弱聚合，C12 的低成本近似）
- **(a) 故障场景**：路径切换期间的会话中断窗（切换→重新握手→宽限期，秒级）；ZT multipath
  的 active-backup 语义里有「spare 链路持续探测保证可切」[1]，meshlet 的备份路径切换后从零
  起步，切换时延被拉长。
- **(b) 改动面**：
  - **不做**完整聚合（ZT 的 balance-rr/xor/aware 是企业版特性且 meshlet 用户面收益不足——
    对比文档 C12 判级「暂缓/XL」不变；balance-rr 官方明示不适用 TCP[1]）。
  - 做「**直连路径 keepalive 双活**」：Direct 状态下，现役 endpoint 正常 keepalive（15s，
    `link.rs:27`），**次优候选**（SEL-002 评分第二名）以低频 keepalive（如 60s，仅保 NAT 映射）
    维持一条温备 WG 会话——对次优候选额外下发一个同 pubkey 直连 peer 是被内核 allowed-ips
    禁令阻止的[10]，所以实现为：`wg set peer` 的 **endpoint 常换 + persistent-keepalive 双发
    是不可行的**，正确形态是「温备探测」——probe.rs 已有候选窗口，缺的只是把次优候选的窗口
    健康度作为「切换可行性」输入：`SwitchGate` 切换前检查目标候选窗口非空且非全 Lost
    （现在已隐含，需显式化），并把切换触发从「现路径劣化后才开始探测目标」改为「持续探测
    全部候选」（**已经是**——SEL-001 本来就探全部候选）。所以本方案的真实增量收缩为：
    ①切换目标预检显式化（S）；②对「切换后宽限期」内的旧 endpoint 保留一次性 fallback
    `wg set peer endpoint` 回滚能力（S）。
  - 若未来真要 bundle 级聚合，正确路线是 userspace 数据面（方案 6 的栈复用），列为不做承诺。
- **(c) 量级**：**S**（预检 + 回滚）；完整聚合 **XL 不做**。
- **(d) 依赖与风险**：低；风险在回滚动作与方案 1 宽限期的交互（回滚也要过宽限），实现时
  统一放 `SwitchGate` 内。
- **(e) 优先级**：**P2**（与方案 1 同文件，顺手做 ①；②视 ① 效果）。

### 方案 9：稳定性 SLO 指标与事故留痕（C13/O01 配套）
- **(a) 故障场景**：所有「不稳定」类反馈缺数据支撑——切换次数、劣化回退次数、hub 可达性、
  直连占比都没有时间序列，事故只能靠 journal 人肉还原（本次调研反复借用的
  `docs/acceptance-evidence/*` 就是手工取证产物）。
- **(b) 改动面**：
  - `apps/server/src/metrics.rs`（已有 Prometheus 面）新增：`meshlet_direct_links_total{state}`、
    `meshlet_direct_switch_events_total`（聚合自心跳 `direct_links` + switch 事件上报）、
    `meshlet_agent_control_reachable{device}`（presence_watch 已算，导出即可）。
  - `apps/agent/src/agent/direct.rs`：switch/demote 事件除本地 JSON 外，心跳捎带计数
    （`DirectLinkStatus` 加 `switch_count_1h` 字段，`crates/meshlet-domain/src/p2p/link.rs:186`）。
  - 本地留痕：`direct-switch-events.json` 已是 append 日志（`dial.rs:108-110`），加轮转
    （>1000 条截断）防膨胀。
- **(c) 量级**：**S-M**。
- **(d) 依赖与风险**：无。心跳字段加法是向后兼容（`#[serde(default)]` 模式已普及）。
- **(e) 优先级**：**P0**（没有度量，后面每个方案的「有效没效」都无法验收——meshlet-ops 技能
  的 R-07 soak 门禁也需要这组读数才能开窗）。

### 明确不做（本轮论证后排除）

- **完整 multipath/链路聚合**（C12 原判级维持）：单用户场景收益不足；ZT 把它放企业版也说明
  运维成本；balance-rr 官方明示不适用 TCP[1]。
- **DERP 协议兼容 / 全球中继调度**（O08 原判级维持）：自托管单 hub 无此需求；DERP map
  多 region 的复杂度只对多地域用户有价值[6]。
- **控制面双活（多 server 同 DB）**：修订/审批是单写者语义，双活引入的冲突处理是纯 XL 负担；
  方案 3 的「数据面备用 + 控制面单点」是正确的第一梯队形态。

## 5. 建议落地顺序

| 序 | 方案 | 量级 | 覆盖故障 | 理由 |
|---|---|---|---|---|
| 1 | **方案 9** 稳定性 SLO 指标 | S-M | 全部（度量底座） | 没有读数，后续每项验收都是盲的；R-07 soak 开窗前置 |
| 2 | **方案 1** 切换闸收尾（宽限/冷却/年轻窗豁免） | S | 切换震荡极限环 | 11-13 三连修的直接收尾，热上下文，纯逻辑低风险 |
| 3 | **方案 7** ZT 面收编（候选来源标注 + 可配黑名单） | S | 骑跨面抖动 | 当前真机抖动的直接相关项；收编零风险，排除开关默认关 |
| 4 | **方案 2** 多 hub endpoint 轮换 + 本地缓存 | M | hub 换 IP/DNS 失效/endpoint 抖动 | 单 hub 下最便宜的高可用增量，WG roaming 机制已验证 |
| 5 | **方案 3** 第二中继 hub | M/L | hub 宕机（全网瘫） | 数据面高可用的正解；依赖方案 2 的轮换语义先稳 |
| 6 | **方案 4** MTU/路径诊断强化 + 探针口径统一 | M | 大包黑洞 / 诊断盲区 | C11 必需项收尾；顺手消 D2 探针口径差 |
| 7 | **方案 5** STUN/NAT 判断 | L | 对称 NAT 直连率 / pending 空转 | C05 依赖项；在前 6 项稳定后再扩协议面 |
| 8 | **方案 8** 切换目标预检 + 回滚 | S | 切换中断窗 | 与方案 1 同文件，可并入第 2 步 |
| 9 | **方案 6** TCP/443 回退（一期：hub 桥接） | XL | UDP 被封 | 最贵保底；方案 7 收编 + 用户诉求再启动 |

验收口径建议：第 1-2 项落地后，以「7 天内 direct_switch_events ≤ 阈值 + 直连占比 ≥ 基线 +
zero hub_relay 意外回退」作为 R-07 soak 开窗的前置判据（衔接 meshlet-ops 技能的 soak 纪律）。

## Sources

[1] https://docs.zerotier.com/multipath — ZeroTier Docs: Multipath
[2] https://docs.zerotier.com/protocol — ZeroTier Docs: The Protocol
[3] https://docs.zerotier.com/faq/relaying — ZeroTier Docs: High Latency and Relaying Issues
[4] https://docs.zerotier.com/relay — ZeroTier Docs: TCP Relay
[5] https://docs.zerotier.com/enterprise-deployment — ZeroTier Docs: Enterprise Deployment Guide
[6] https://tailscale.com/docs/reference/derp-servers — Tailscale Docs: DERP servers
[7] https://tailscale.com/docs/reference/connection-types — Tailscale Docs: Connection types
[8] https://tailscale.com/docs/reference/stun-protocol — Tailscale Docs: What is STUN?
[9] https://tailscale.com/kb/1115/subnet-failover — Tailscale KB: Set up high availability
[10] https://lists.zx2c4.com/pipermail/wireguard/2018-December/003704.html — WireGuard mailing list: Behaviour of multiple Allowed-IPs 0.0.0.0/0
[11] https://docs.netbird.io/about-netbird/how-netbird-works — NetBird Docs: How NetBird Works
