# 个人组网功能调研：Meshlet、ZeroTier 与 Tailscale

调研日期：2026-10-17。目标是筛选个人自托管所需的能力，不追求复制商业产品。本文结合厂商官方文档与本仓静态核对，未对三者做同环境测速或成功率实验；功能存在不代表任意平台、套餐或自托管形态都支持。

本文是调研与建议，尚未成为 Accepted ADR。现有代码缺口见 [架构与 TODO 审查](architecture-review-2026-10-17.md)。商业套餐、预览功能和客户端行为可能变化，实施时需固定版本复核；不以免费额度、价格或营销性能数字决定架构。

## 1. 面向个人的结论

Meshlet 当前主要是可自托管的 WireGuard hub 组网与配置管理，ZeroTier 更接近可编程虚拟以太网，Tailscale 更接近带自动连接与身份策略的三层设备网络。个人版应重点借鉴连接恢复、路径可见性、简单授权和服务入口，不复制整个企业产品体系。[ZeroTier 协议][Z1]、[Tailscale 连接类型][T1]

“ZeroTier 更快、Tailscale 成功率更高”可以作为实验假设，不能作为普遍结论。两者都有直连与回退；实际差异可能来自直连比例、中继位置、UDP 限制、物理线路、端点性能、MTU 和软件版本。本次没有可比较的实测数字。[ZeroTier 带宽说明][Z2]、[Tailscale 性能建议][T3]

个人版建议保留一个管理员、少量网络与设备、自有 VPS、显式访问策略。设备数量按实际清单验收，不预设企业规模；DNS、P2P 和回退能力按使用需要逐步加入。

## 2. 架构差异

| 维度 | Meshlet 当前 | ZeroTier | Tailscale | 对个人版的影响 |
|---|---|---|---|---|
| 网络抽象 | IPv4 L3 Overlay + LAN/Alias | L2 虚拟以太网，支持其上的 IP 网络 [协议][Z1] | L3 IP 组网 [连接][T1] | 无广播/旧游戏需求时保留 L3 |
| 常规业务路径 | A → 自有 VPS → B | 尝试建立 P2P，不能直连则中继 [连接][Z3] | 直连、Peer Relay、DERP [连接][T1] | Meshlet 当前所有跨设备流量受 VPS 路径约束 |
| 加密与中继信任 | A↔hub、hub↔B 分段 WireGuard；hub 解密再转发 | 端点间加密，中继不读取业务载荷 [安全][Z4] | 端点间 WireGuard 加密，含中继路径 [连接][T1] | Meshlet 信任 VPS；不能宣传中继不可见明文 |
| 控制与转发部署 | 逻辑分离，生产执行仍在 server 进程内 | controller 与 root/relay 职责不同 [控制器][Z5] | 协调服务与业务转发分离 [故障边界][T4] | 不必拆微服务，但应明确特权执行边界 |
| 自托管 | 自有 server、DB、hub；部署闭环待补 | controller 可自建；不等于替换所有 root 基础设施 [控制器][Z5] | 官方客户端可接自定义控制器；Headscale 为独立项目 [自定义控制器][T5]、[Headscale][H1] | 先区分“自建控制面”和“完全自主转发” |
| 多网络 | 控制面有记录，单实例 hub 资源未隔离 | 客户端可加入多个网络 [多网络][Z6] | 支持管理多个 tailnet；常规客户端切换账号不等于同时接入 [tailnet][T6]、[切换][T7] | 先做网络内分组，再按需推进一机多网 |
| 平台 | Linux 真后端；Windows 完整隧道未接入 | 主流桌面/移动平台，有功能差异 [平台][Z7] | 主流桌面/移动平台，有功能差异 [安装][T8] | 编译/CI 通过不能代表平台网络功能可用 |
| 服务访问 | 当前靠 IP 和路由 | 网络 + 外部应用或代理 [Pylon][Z8] | Serve、Services、Funnel 分别面向不同用途 [Serve][T9]、[Services][T10]、[Funnel][T11] | 可用 Nginx 和四层转发实现个人服务入口 |

两种“中继”尤其不能混淆：Meshlet 当前 hub 是被信任的路由终点；转发端点间密文的 relay 则不终止端点间 WireGuard 隧道。若以后要求 VPS 不可读取转发载荷，需要单独设计端点间密钥分发与密文转发，而非只换 UI 名称。

## 3. 速度与成功率应分别衡量

### 3.1 为何可能感觉 ZeroTier 更快

优先记录实际路径。如果 ZeroTier 直连，而 Tailscale 在 DERP 中继，结果反映的是路径差异，不能据此判断 ZeroTier 协议吞吐一定更高。若两者都直连，再比较 CPU、端点实现、链路、MTU 和测试方向；内核实现也不能单凭名称判定一定更快。[ZeroTier 中继诊断][Z3]、[Tailscale 性能][T3]

Meshlet 中继 RTT 可粗略理解为 A↔VPS 与 VPS↔B 两段路径时延的合成，吞吐受两段链路及 VPS 转发能力限制。这是架构推导，不能替代测量。增加 HTTP 代理只能改变服务路由，不能消除底层绕路。

### 3.2 为何可能感觉 Tailscale 更容易连上

Tailscale 用 DERP 协助协商和保底，再争取升级到直连；当前还提供同 tailnet 的 Peer Relay。Peer Relay 使用可达 UDP 端口，解决不了所有“UDP 完全禁用”的场景；DERP 的 HTTPS 路径才是此类环境中的重要回退。[连接流程][T1]、[DERP][T2]、[Peer Relay][T12]

ZeroTier 也有 UDP P2P、root 中继、周期性直连尝试和 TCP 回退，不能写成“没有保底”。官方提供自建 TCP relay 指南，同时提示其性能限制。[连接][Z1]、[TCP relay][Z9]

Meshlet 目前只有到 VPS 的 WireGuard UDP 路径。HTTPS 控制 API 可达不能证明隧道可达；开放 UDP 443 也不能代替 HTTPS/TCP 回退。STUN 发现公网映射不等于能穿透所有 NAT。[STUN][T13]

### 3.3 成功率口径

| 指标 | 定义 | 避免的误判 |
|---|---|---|
| 控制面成功率 | 注册/拉计划成功次数 ÷ 尝试次数 | 管理 API 可达不算业务可用 |
| 业务连接成功率 | 在固定截止时间内完成指定协议请求的次数 ÷ 尝试次数 | ping 通不代表 HTTP/数据库可用 |
| 直连成功率 | 成功建立直接数据路径次数 ÷ 尝试次数 | 中继成功不能计入直连 |
| 首次可用时间 | 发起连接到第一次业务请求成功 | 不只统计握手时间 |
| 升级时间 | 保底可用到切成直连所需时间 | 首包中继不表示一直在中继 |
| 恢复时间 | Wi-Fi/热点切换或休眠恢复到业务重新成功 | 心跳恢复不等于业务恢复 |
| 持续可用性 | 固定时长传输中的中断次数/时长 | 一次成功不代表稳定 |

HTTPS 能出站也不保证任何回退协议都能通过：代理认证、TLS 检查、域名阻断和仅允许特定 HTTP 行为都会产生边界。不能承诺“100% 连通”。

## 4. 功能对比与个人版取舍

编号用于与 TODO/后续设计交叉引用。每表分别比较同一层能力，避免把控制面管理和数据面转发当成同一功能。

取舍：**必需**＝已明确需求或可靠性基础；**推荐**＝个人常用且收益高；**条件**＝特定设备/网络出现后再做；**暂缓**＝本期不承担。

难度是本仓增量工程判断，不是工期承诺：S＝局部配置/UI；M＝跨模块但可复用后端；L＝涉及网络生命周期/跨平台；XL＝新增传输、移动平台或信任模型。推荐栏的“原型”不等于承诺正式实现。

### 4.1 连接、路径与性能（C01–C13）

| ID / 能力 | ZeroTier | Tailscale | Meshlet 当前 | 取舍 / 难度与实现方向 |
|---|---|---|---|---|
| C01 稳定虚拟 IP | 网络内分配 [网络][Z10] | 节点地址 [DNS][T14] | 已有 IPv4 IPAM | 必需 / M：保持地址稳定与冲突校验 |
| C02 自动 UDP 直连 | 支持 [协议][Z1] | 支持 [连接][T1] | 无，全部经 hub | 推荐 / XL：先做可验证原型，保留保底 |
| C03 同 LAN 直连 | 有 LAN 发现 [协议][Z1] | 候选端点与路径选择 [穿透][T15] | 仍绕 VPS | 推荐 / L：先验证已知 LAN 端点，仍校验身份与权限 |
| C04 公网 IPv4/IPv6 端点直连 | 支持 [协议][Z1] | 支持 [穿透][T15] | 配置仅有 hub 入口 | 推荐 / L：优先可达端点，降低复杂穿透需求 |
| C05 STUN 与 NAT 判断 | 有穿透/映射机制 [协议][Z1] | STUN/连接诊断 [STUN][T13] | 无 | 条件 / L：作为 C02 依赖，不宣称 STUN 万能 |
| C06 UDP 中继保底 | root 中继 [中继][Z3] | Peer Relay/其他连接形态 [Peer Relay][T12] | 自有 hub 分段隧道 | 必需 / L：先修可靠性，区分路由 hub 与密文 relay |
| C07 UDP 被禁时 HTTPS/TCP 回退 | TCP relay [回退][Z9] | DERP [DERP][T2] | 无 | 推荐 / XL：P1 原型；不能只修改 WG 监听端口 |
| C08 路径升级与降级 | 继续尝试直连 [协议][Z1] | 自动切换并重试 [连接][T1] | 单路径 | 推荐 / XL：跟随 C02/C07，设置退避与切换稳定性 |
| C09 手动端口映射/自动映射 | 支持映射辅助 [协议][Z1] | NAT-PMP/PCP 等辅助 [改进][T16] | 可手配 hub 公网端口 | 条件 / M–L：先手动说明，自动映射可选开启 |
| C10 单个自有备用中继 | 自建 TCP relay；Moons 已不推荐 [回退][Z9]、[roots][Z11] | 可自建 DERP/Peer Relay [DERP][T2] | 单 VPS | 条件 / L：先故障诊断与手动恢复，不建全球调度 |
| C11 MTU 与路径诊断 | 提供配置和排障 [客户端][Z12] | 性能与连接排障 [性能][T3] | 有 MTU 配置/探测概要 | 必需 / M：真实路径读数和大包业务验收 |
| C12 多链路聚合/智能选路 | Multipath [多路径][Z13] | 路由与连接选择，不能等同链路聚合 [路由][T17] | 无 | 暂缓 / XL：个人常规设备收益不足 |
| C13 速度优化与基准 | 受物理网络/路径影响 [带宽][Z2] | 有 offload/实现优化 [性能][T3] | API 基准与网络测试；无三方可比实测 | 必需 / M：先测速定位，再决定底层优化 |

### 4.2 网络、分组与路由（N01–N10）

| ID / 能力 | ZeroTier | Tailscale | Meshlet 当前 | 取舍 / 难度与实现方向 |
|---|---|---|---|---|
| N01 多个隔离网络 | 多网络 [加入][Z6] | 多 tailnet 管理 [多网][T6] | 控制面有，生产隔离有 AR-01 缺口 | 必需 / L：先完成单实例隔离 |
| N02 一机同时加入多网 | 客户端可多网；平台有差异 [加入][Z6] | 常规账号切换仅一个活动账号 [切换][T7] | 单 Device 直接归属单网络 | 条件 / L：一机多网模型预留，按实际需求实现 |
| N03 网络内设备组/标签 | tags 与规则 [规则][Z14] | tags/用户组与 grants [标签][T18]、[授权][T19] | 无独立设备组 | 必需 / M：设备可多组，先静态分组 |
| N04 异地 LAN 访问 | 物理网路由 [路由][Z15] | subnet router [子网][T20] | 已有 Direct LAN，AR-05 待补 | 必需 / M：四种返回路径单独验收 |
| N05 不能安装客户端的设备 | 网关/桥接/代理 [物理集成][Z16] | subnet router [子网][T20] | 可经 Linux LAN 网关 | 必需 / M：优先复用网关，不给每种 IoT 写客户端 |
| N06 重叠 LAN 网段 | 普通地址冲突不能自动确定站点，需额外规划 [路由][Z15] | 4via6 映射到独立 IPv6 地址 [4via6][T21] | IPv4 等长 Alias | 必需 / M：保留 Alias；不因竞品支持 4via6 就换模型 |
| N07 IPv6 Overlay | 支持 IPv6 配置 [出口][Z17] | 支持 IPv6 路由/4via6 [4via6][T21] | 仅 IPv4 | 条件 / L：和 IPv6 底层端点分别规划 |
| N08 全局互联网出口 | 可配置网关与默认路由 [出口][Z17] | Exit node [出口][T22] | v1 排除 | 暂缓 / L：明确有回家上网需求时新 ADR |
| N09 二层桥接/广播/组播 | 有相关能力，移动端受限 [物理集成][Z16] | 不提供通用 L2 网络 [定位][T23] | v1 排除 | 暂缓 / XL：发现需求先考虑应用层发现代理 |
| N10 网关 HA/动态路由 | 系统路由/多路径可组合，非本仓同等承诺 [多路径][Z13] | subnet router HA [HA][T24] | 单网关模型 | 条件 / L–XL：先单点可恢复，不做 BGP/OSPF 平台 |

ZeroTier New Central 的 **Network Groups** 是组织网络的管理层级，不等于 Meshlet 要增加的“网络内设备组”；Tailscale 的用户组、设备 tags 与多个 tailnet 也不是同一个概念。[ZeroTier 层级][Z10]、[Tailscale 标签][T18]

### 4.3 服务入口、名称与应用（S01–S12）

| ID / 能力 | ZeroTier | Tailscale | Meshlet 当前 | 取舍 / 难度与实现方向 |
|---|---|---|---|---|
| S01 内网 TCP 端口转发 | 可组合系统 NAT/代理，Pylon 为代理工具 [Pylon][Z8] | Serve 有 TCP 转发 [Serve][T9] | 无独立规则模型 | 必需 / M：先 Linux，来源与回程明确 |
| S02 内网 UDP 端口转发 | 可组合系统 NAT [路由][Z15] | 基础网络可承载 UDP；不等同 Serve 直接支持 UDP [Services 限制][T10] | 无独立规则模型 | 必需 / M–L：独立超时、源地址与清理验收 |
| S03 HTTP 域名/路径分流 | 通常叠加 Nginx 等应用，未据此认定内置网关 | Serve/Services 有应用端点 [Serve][T9]、[Services][T10] | 无 | 必需 / M：Nginx 受管配置，先 Host + 路径前缀 |
| S04 HTTPS 证书与续期 | 由上层 Web 服务解决 | Serve 使用 tailnet HTTPS 能力 [Serve][T9] | 安装指南含控制台 HTTPS 反代，非用户服务证书管理 | 推荐 / M–L：先用户证书，再评估 ACME；和控制台证书分开 |
| S05 公网发布内网服务 | 可用公网 VPS + 代理组合 | Funnel [Funnel][T11] | 无产品化入口 | 条件 / M–L：自有 VPS 显式授权，不建全球 Funnel |
| S06 设备名称自动解析 | managed DNS，可配 DNS 服务 [DNS][Z18] | MagicDNS [DNS][T14] | 无内建 DNS | 推荐 / M：先受管 DNS 记录和解析回滚，不自研通用 DNS 平台 |
| S07 Split DNS/自定义域 | DNS 配置 [DNS][Z18] | tailnet DNS 配置 [DNS 管理][T25] | 无 | 条件 / M–L：不能覆盖用户已有解析配置 |
| S08 服务目录/书签 | 网络管理不是应用目录 | Services 与 endpoint collection [Services][T10]、[端点][T26] | 无 | 推荐 / S–M：手工登记名称/协议/地址，默认不主动扫描 |
| S09 服务 VIP/多后端调度 | 可由上层服务实现 | Services 抽象/VIP [Services][T10] | 无 | 条件 / L：先单后端，不复制完整服务发现 |
| S10 专用 SSH 登录系统 | 可运行普通 SSH | Tailscale SSH 管理认证授权 [SSH][T27] | 可承载普通 SSH，无专用功能 | 暂缓 / L：先普通 OpenSSH + 网络权限 |
| S11 文件投送/共享盘 | 可运行文件服务 | Taildrop / Taildrive [投送][T28]、[共享盘][T29] | 无 | 暂缓 / L：复用 SFTP/SMB/现有同步工具 |
| S12 SOCKS/无 TUN 应用接入 | Pylon [代理][Z8] | userspace networking [用户态][T30] | 无 | 条件 / L：容器或无管理员权限需求出现后再做 |

S01 与 Tailscale Serve 不是完全相同的产品语义：Serve 主要发布本机服务，Meshlet 需求是指定入口设备 A 转到设备 B。S03 的 HTTP 代理也不能替代 SSH/数据库/游戏 UDP 的转发；TLS 透传不能按加密 URL 路由，参见 [Nginx HTTP](https://nginx.org/en/docs/http/ngx_http_proxy_module.html) 与 [TLS preread](https://nginx.org/en/docs/stream/ngx_stream_ssl_preread_module.html)。

### 4.4 身份与权限（A01–A10）

| ID / 能力 | ZeroTier | Tailscale | Meshlet 当前 | 取舍 / 难度与实现方向 |
|---|---|---|---|---|
| A01 设备加入与批准 | 私有网络授权 [控制器][Z5] | 设备批准 [设备批准][T31] | 自举码 → 待批准；也有邀请 | 必需 / M：保留简单流程 |
| A02 自动化注册凭据 | controller/API 配合 [控制器][Z5] | auth keys [认证密钥][T32] | 自举码、一次性邀请 | 必需 / M：撤销/有效期/限次语义清楚 |
| A03 设备撤销 | 取消授权 [控制器][Z5] | 设备管理与批准 [设备批准][T31] | 凭据撤销与新修订已有 | 必需 / L：补实际数据面失效时限及确认 |
| A04 组到端口的授权 | 分布式 flow rules [规则][Z14] | ACL/grants [授权][T19] | 未有精细策略，隧道转发较宽 | 必需 / L：先最小允许模型与默认行为 |
| A05 策略测试/生效可见 | 规则在端点执行 [规则][Z14] | Services 可做访问策略测试 [Services][T10] | 有修订状态，无端点版本 ACK | 必需 / M–L：允许和拒绝都验收；对账见 AR-02 |
| A06 密钥生命周期 | 节点身份与 controller 密钥管理 [协议][Z1] | auth/node key 生命周期 [认证密钥][T32] | 本地 WG 私钥；缺完整轮换 API | 推荐 / L：先手动安全轮换与恢复，避免远程失联 |
| A07 控制器不可擅自加节点 | controller 为信任核心 [协议][Z1] | Tailnet Lock 节点签名 [锁定][T33] | 信任自有控制面与 hub | 条件 / XL：个人先保护控制面，不复制签名授权体系 |
| A08 临时访客/跨网共享 | 可另建网络和规则 [网络][Z10] | 节点共享 [共享][T34] | 无访客服务授权 | 条件 / M–L：先单服务、限时、可撤销，不开放整网 |
| A09 企业 SSO/设备姿态 | 有企业集成 [企业部署][Z19] | identity/device posture [姿态][T35] | 本地管理员 | 暂缓 / XL：个人版不建 IdP/MDM/SCIM |
| A10 API 最小权限与审计 | Central/本地 API [API][Z20] | API 与日志能力 [日志][T36] | read/write Token、会话和审计 | 必需 / M：网络级作用域按实际多网管理需要扩展 |

ZeroTier 官方 New Central 文档把模板规则与自定义规则按套餐区分；不能把协议规则能力直接描述为免费托管版全部可用。自建 controller 也不能自动获得托管控制台所有能力。[规则套餐说明][Z14]

### 4.5 平台与日常使用（P01–P08）

| ID / 能力 | ZeroTier / Tailscale | Meshlet 当前 | 取舍 / 难度与实现方向 |
|---|---|---|---|
| P01 Linux 常驻/ARM 主机 | 两者有 Linux，ZeroTier 列出多架构 [ZT 平台][Z7]、[TS 安装][T8] | Linux 后端与 unit，正式部署权限待补 | 必需 / M：按实际 x86_64/ARM64 设备验证 |
| P02 Windows 完整客户端 | 两者有客户端 [ZT 平台][Z7]、[TS 安装][T8] | 路由原语部分验证；系统后端仍 Unsupported | 必需 / L：隧道服务、提权、开机恢复、卸载清理 |
| P03 macOS | 两者有客户端 [ZT 平台][Z7]、[TS 安装][T8] | 无后端 | 条件 / L：有 Mac 再优先实现，先选系统接入方式 |
| P04 Android | 两者有客户端 [ZT 平台][Z7]、[TS 安装][T8] | 无后端 | 推荐 / XL：若手机是常用端，提高优先级；VPN/后台与 UI 单独项目 |
| P05 iOS/iPadOS | 两者有客户端 [ZT 平台][Z7]、[TS 安装][T8] | 无后端 | 条件 / XL：VPN 扩展、签名、分发和后台行为先原型 |
| P06 NAS/路由器 | 按厂商/平台适配，不能泛称全支持 [ZT 平台][Z7]、[TS 安装][T8] | 通用 Linux 与 LAN 网关可复用 | 推荐 / M–L：先网关与安装文档，再专用包 |
| P07 系统托盘/状态/通知 | 桌面客户端具备 UI，平台各异 [ZT 配置][Z12]、[TS 安装][T8] | Linux D-Bus 实现已入仓，真实桌面待验收 | 推荐 / M：沿用现有工作，不能挤占核心网络修复 |
| P08 自动更新/升级回退 | 有安装/更新渠道 [ZT 平台][Z7]、[TS 安装][T8] | 构建/安装说明，未有完整更新闭环 | 推荐 / M–L：先手动可靠升级与配置兼容，自动更新后置 |

手机支持会显著增加工作量。若必须在所有手机上可用且尽快获得成熟穿透，复用现成客户端的路线必须与继续自研作成本对照，而不是把移动端算作一个普通网络后端。

补充：常规组网使用虚拟网卡不等于需要每次手动启动 VPN，也不意味着改变全局出口。用户态代理可覆盖受限场景，但无法直接替代宿主所有应用的透明网络接入。ZeroTier/Tailscale/NetBird/EasyTier 的网卡与代理模式核对，以及 Meshlet 的模块边界建议，见 [模块化与库复用提案](../architecture/modularity-and-library-design.md)。

### 4.6 运维、集成与明确不做（O01–O08）

| ID / 能力 | ZeroTier / Tailscale | Meshlet 当前 | 取舍 / 难度与实现方向 |
|---|---|---|---|
| O01 连接路径与失败原因 | ZT peers；TS status/ping/netcheck [ZT 排障][Z3]、[TS 连接][T1] | 13 项诊断，尚无 P2P 路径 | 必需 / M：显示 hub/直连/回退、端点、更新时间 |
| O02 重启/断网/漂移恢复 | 现成客户端生命周期；TS 有协调服务故障边界 [TS 故障][T4] | Agent 对账已有；hub AR-03 待补 | 必需 / L：缓存、撤销边界与冷启动分别验收 |
| O03 备份/迁移 | 自托管需备份自身状态；不假定 SaaS 可导出完整恢复 | SQLite 一致性备份已有，内核恢复待补 | 必需 / M：DB、配置、hub 密钥分别备份与验收 |
| O04 日志/轻量流量统计 | ZT observability；TS logs [ZT API][Z20]、[TS 日志][T36] | 审计/Prometheus 指标已有 | 推荐 / M：先设备级计数和错误，不建设全量流量仓库 |
| O05 API/Webhook | 两者有集成能力 [ZT webhook][Z21]、[TS webhook][T37] | API 已有，未有 Webhook | API 必需、Webhook 条件 / M：事件少量重试即可 |
| O06 IaC/Kubernetes/企业自动化 | 两者有相关生态 [ZT API][Z20]、[TS 功能][T38] | 无 | 暂缓 / L–XL：个人不复制 Operator/Terraform 生态 |
| O07 企业目录/PAM/会话录像/AI 网关 | TS 产品覆盖相关领域 [功能][T38]；不据此推断 ZT 同等功能 | 无 | 暂缓 / XL：超出私人网络产品边界 |
| O08 全球公共中继/多租户计费 | 商业基础设施与管理体系 | 无 | 暂缓 / XL：保留自有一台或少量 VPS |

## 5. 可开发不等于应该一次开发

### 5.1 建议路线与验收门槛

| 阶段 | 范围 | 交付门槛 |
|---|---|---|
| R0 可靠基础 | AR-01…AR-06、真实数据面门禁 | 单实例双网隔离、hub 重启恢复、设备 ACK、失败恢复、Direct SNAT、正式 unit 可部署 |
| R1 个人可日用 | N03/A04 分组授权、P02 Windows、O01/C13 诊断基准 | 同组/跨组允许与拒绝；两台实际设备开机/休眠后可恢复；记录真实路径与业务成功率 |
| R1 连接原型 | C03/C04 简单直连、C07 受限网络回退；C02/C05 可行性 | 固定拓扑证明收益和失败边界，决定用户态与内核数据面的关系，再写 ADR |
| R2 服务与连接增强 | S01/S02/S03、S04/S06；按原型结果推进 C02/C07/C08 | 服务映射与网络权限一致；Nginx 校验/reload/恢复可见；回退不中断基本可用性 |
| R3 按需扩展 | N02 一机多网、移动端、自有备用中继、访客 | 以实际设备与场景排期，不因竞品有功能就全部加入 |

若用户当前最痛的是受限网络连不上，C07 的正式实现应排在服务美化之前；若最痛的是同地 NAS 传输绕远，先做 C03/C04。没有测量前，不把“调优 Rust/换加密算法”列为优先项。

### 5.2 两个需要原型的架构变化

**简单直连也需要权限闭环。** 当前客户端只有 hub 一个 Peer；增加直连必须分发目标 Peer 公钥/端点、改变 AllowedIPs 和路由，并处理同一目标在直连与 hub 路径间的归属、回退及撤销。不能简单给两个 Peer 配同一目的前缀并期望内核自动做路径择优。上线前必须让直连端点执行访问策略，防止绕过 hub 的组间限制。

**HTTPS 回退需要传输适配。** 内核 WireGuard 使用 UDP，不能将 Endpoint 改为 HTTPS URL。候选包括复用已有可审查实现、用户态 WireGuard 传输适配或本地 UDP 到受控隧道的桥接；均需验证身份授权、MTU、背压、断线恢复和性能。套 TCP 的回退可能因有序传输与丢包产生队头阻塞，只作为可用性保底。C07 原型应比较它们，不能预先承诺 DERP 协议兼容或端到端信任性质。

这些属于待设计方案；本次只确认研究方向，不引入新依赖或自研密码协议。

### 5.3 自研与复用路线对照

| 路线 | 个人使用收益 | 主要代价 / 适用条件 |
|---|---|---|
| 继续 Meshlet | 控制体验、Alias、分组和 A→B 服务转发可按需求设计 | 自己承担穿透、回退、Windows/移动端与升级维护 |
| Headscale + Tailscale 客户端 + Nginx | 借助现成客户端和自托管控制器，减少客户端工作 [Headscale][H1]、[自定义控制器][T5] | Headscale 仅实现目标范围内能力，不保证所有 TS SaaS 功能；兼容版本、DNS/DERP 和服务编排需验证 |
| 自建 ZeroTier controller + 代理 | 复用客户端及多网/L2 机制 [controller][Z5] | controller 与根发现/relay 不同；不能把自建 controller 或旧 Moons 教程当成完全独立基础设施 |
| 使用托管组网 + 自有服务配置 | 最少自建连接组件，聚焦个人服务 | 控制依赖外部服务；和“完全自托管”目标不同，按用户接受程度选择 |

**调研发现：ZeroTier 官方 Private Root Servers 页面已将 private moons 标为不推荐部署，并提示可靠性风险。** 页面仍保留历史配置教程，不能因此推荐新建 Moon 作为个人版加速方案。[官方说明][Z11]

继续自研有价值的前提，是自定义控制/服务编排本身就是目标。如果只想尽快获得成熟跨平台连接，应先用小规模复用原型比较维护成本。本文不据此切换 Meshlet 技术路线。

## 6. 三方对照实验设计（尚未执行）

### 6.1 固定条件

使用相同 A/B 设备、同一网络和相近时间窗口，记录 OS、CPU、软件版本、MTU、物理上/下行、VPS 位置与带宽、源地址保留方式。每次只启用一套组网，避免三套客户端路由/DNS 互相干扰。每组先确认实际业务路径；原始与优化参数分开记录。

分别报告真实产品体验和同路径对照：自动选路反映日用体验；强制或确认相同类型的直连/中继才用于比较实现开销。没有官方支持的强制方式时记录观察到的路径，不伪造同条件。各产品不能使用同一中继位置时，明确说明线路因素未受控。

### 6.2 拓扑与故障矩阵

| 场景 | 目的 | 应记录 |
|---|---|---|
| 同一 LAN | 验证避免 VPS 绕行 | 实际端点、RTT、吞吐、CPU |
| 两端公网或可达 IPv6 | 比较简单直连 | 实际 v4/v6 路径、防火墙条件 |
| 家宽 ↔ 家宽 / 家宽 ↔ 手机热点 | 常见 NAT 与网络切换 | 业务成功率、直连率、首连和恢复时间 |
| 双 CGNAT / 双重 NAT / 已知难 NAT | 验证保底 | 未穿透原因、中继类型；不能只按运营商名称判 NAT 类型 |
| 禁止 UDP，允许到测试入口的 HTTPS | 验证 TCP/HTTPS 回退 | 控制成功与业务成功分别记录 |
| 限丢包/高 RTT | 比较回退性能退化 | TCP 吞吐、UDP 丢包、RTT p95/p99 |
| 休眠/重启/断网/更换出口 IP | 生命周期恢复 | 无人工干预的恢复时间 |
| 管理进程停止 / hub 或 relay 停止 | 区分控制与数据依赖 | 既有连接、新连接、撤销传播的边界 |
| 双 Network / 重叠 LAN / 组间拒绝 | 功能与授权正确性 | 目标站点标识、越权负向断言 |

故障注入仅在隔离实验环境执行。已有 netns 测试可复用，但普通 CI 与真实运营商 NAT 的覆盖范围分别登记。

### 6.3 指标与命令模板

以下工具需预先安装并确保端口可达；`<peer-ip>` 是本次测试系统中目标虚拟 IP。接收端先运行 `iperf3 -s`，HTTP 目标放置固定测试资源。

```bash
ping -c 100 <peer-ip>
iperf3 -c <peer-ip> -t 30
iperf3 -c <peer-ip> -t 30 -R
iperf3 -c <peer-ip> -t 30 -P 4
iperf3 -c <peer-ip> -u -b 10M -t 30
curl --max-time 10 -o /dev/null -sS -w '%{http_code} %{time_connect} %{time_starttransfer} %{time_total}\n' http://<peer-ip>:8080/health
tailscale status
tailscale ping <peer-ip>
tailscale netcheck
zerotier-cli peers
zerotier-cli listnetworks
wg show
```

路径诊断命令来自 [Tailscale 连接文档][T1] 与 [ZeroTier 排障文档][Z3]；`wg show` 只能显示当前 WireGuard Peer/握手等证据，不能单凭它证明完整业务成功。

建议每拓扑至少 30 次独立建连尝试，每次预先固定业务截止时间，例如 10 秒；持续吞吐至少重复 5 轮。记录全部尝试，不因未连上就移出分母。样本只支持这些设备和线路下的结论，不称为全球成功率。

结果模板：

| 日期/版本 | 场景 | 产品 | 实际路径/relay 位置 | 成功/尝试 | 首次可用 p50/p95 | RTT p50/p95 | 单流/多流/反向 Mbps | UDP 丢包 | CPU/内存 | 恢复时间 | 备注 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 待测 | 待测 | Meshlet / ZeroTier / Tailscale | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 待测 | 不填估算值 |

当前 `docs/architecture/performance.md` 是控制 API 的进程内基准，不经 TCP/TLS，更不是数据面吞吐实验。它对控制面优化有价值，不能用于声称比 ZeroTier/Tailscale 更快。

## 7. 官方来源与复核方式

表内短链接均指向本次查阅的官方文档或项目自身文档。索引用于覆盖功能目录；详细行为以对应功能页为依据。“未查到同等内置功能”只说明本次核验范围，不断言第三方或未来版本绝对不能实现。来源更新后应重新核验套餐、平台和限制，尤其 Peer Relay、Services、Moons 与多 tailnet 行为。

[Z1]: https://docs.zerotier.com/protocol/
[Z2]: https://docs.zerotier.com/faq/bandwidth/
[Z3]: https://docs.zerotier.com/faq/relaying/
[Z4]: https://docs.zerotier.com/faq/canweseeyourtraffic/
[Z5]: https://docs.zerotier.com/controller/
[Z6]: https://docs.zerotier.com/start/
[Z7]: https://docs.zerotier.com/compatibility/
[Z8]: https://docs.zerotier.com/proxy/
[Z9]: https://docs.zerotier.com/relay/
[Z10]: https://docs.zerotier.com/networks/
[Z11]: https://docs.zerotier.com/roots/
[Z12]: https://docs.zerotier.com/config/
[Z13]: https://docs.zerotier.com/multipath/
[Z14]: https://docs.zerotier.com/rules/
[Z15]: https://docs.zerotier.com/route-between-phys-and-virt/
[Z16]: https://docs.zerotier.com/integrating-physical-networks/
[Z17]: https://docs.zerotier.com/exitnode/
[Z18]: https://docs.zerotier.com/dns-management/
[Z19]: https://docs.zerotier.com/enterprise-deployment/
[Z20]: https://docs.zerotier.com/api/
[Z21]: https://docs.zerotier.com/webhooks/
[T1]: https://tailscale.com/docs/reference/connection-types
[T2]: https://tailscale.com/docs/reference/derp-servers
[T3]: https://tailscale.com/docs/reference/best-practices/performance
[T4]: https://tailscale.com/docs/reference/coordination-server-down
[T5]: https://tailscale.com/docs/how-to/set-up-custom-control-server
[T6]: https://tailscale.com/docs/features/multiple-tailnets
[T7]: https://tailscale.com/kb/1225/fast-user-switching
[T8]: https://tailscale.com/docs/install
[T9]: https://tailscale.com/docs/features/tailscale-serve
[T10]: https://tailscale.com/docs/features/tailscale-services
[T11]: https://tailscale.com/docs/features/tailscale-funnel
[T12]: https://tailscale.com/docs/features/peer-relay
[T13]: https://tailscale.com/docs/reference/stun-protocol
[T14]: https://tailscale.com/docs/features/magicdns
[T15]: https://tailscale.com/blog/how-nat-traversal-works
[T16]: https://tailscale.com/blog/nat-traversal-improvements-pt-1/
[T17]: https://tailscale.com/docs/features/route-selection
[T18]: https://tailscale.com/docs/features/tags
[T19]: https://tailscale.com/docs/features/access-control/grants
[T20]: https://tailscale.com/docs/features/subnet-routers
[T21]: https://tailscale.com/docs/features/subnet-routers/4via6-subnets
[T22]: https://tailscale.com/docs/features/exit-nodes
[T23]: https://tailscale.com/docs/concepts/what-is-tailscale
[T24]: https://tailscale.com/docs/how-to/set-up-high-availability
[T25]: https://tailscale.com/docs/reference/dns-in-tailscale
[T26]: https://tailscale.com/docs/features/services
[T27]: https://tailscale.com/docs/features/tailscale-ssh
[T28]: https://tailscale.com/docs/features/taildrop
[T29]: https://tailscale.com/docs/features/taildrive
[T30]: https://tailscale.com/docs/concepts/userspace-networking
[T31]: https://tailscale.com/docs/features/access-control/device-management/device-approval
[T32]: https://tailscale.com/docs/features/access-control/auth-keys
[T33]: https://tailscale.com/docs/features/tailnet-lock
[T34]: https://tailscale.com/docs/features/sharing
[T35]: https://tailscale.com/docs/features/device-posture
[T36]: https://tailscale.com/docs/features/logging
[T37]: https://tailscale.com/docs/features/webhooks
[T38]: https://tailscale.com/docs/features
[H1]: https://docs.headscale.org/
