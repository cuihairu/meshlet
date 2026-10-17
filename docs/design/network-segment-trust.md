# 网段即信任组：Network 内分段与跨段授权设计

日期：2026-10-17。状态：设计提案（未实现，不是 Accepted ADR；落地前需 ADR 与验收）。

用户意图（2026-10-16）：「meshlet 是不是可以分配网段呢？这样一类网段的是可以相互信任的，这样就分组了」。本文把它落成一个模型：**Segment（网段）是 Network 内部的地址子前缀，也是默认信任边界**。同一网段内成员默认互信；跨网段默认不可达，必须由显式授权（Grant）放行。

本文是静态核对既有实现后写的增量设计，不重写既有路由模型：LAN Route / Alias / 网关 / IPAM 实体全部保留，分段只增加「地址归属」和「hub 转发点的来源校验」两件事。

## 1. 范围

本文覆盖：

1. Segment 的创建、CIDR 选择、与既有 IP 分配的关系；
2. 同段互信与跨段默认拒绝的密码学/内核执行点；
3. 段与 LAN Route / Alias 发布可见性的联动；
4. 成员移出、授权撤销、整段隔离的语义与时效；
5. Windows 客户端在该模型中的位置。

非目标（明确不做）：

- 不做网络层之外的服务/端口级 ACL。「A 段只能访问 B 段某台设备的 5432 端口」属于 PN-02（设备/服务端口策略），本文只到「段对段网络层可达」。
- 不做 P2P 直连拓扑（ADR-002 已定 v1 为 VPS hub 中继，P2P 留 v2）。段策略只需要在 hub 一个点执行。
- 不做多 Network 合并；段是 Network **内部**概念。跨 Network 仍按现状默认隔离，不在本期打通。
- 不做成员设备自行建段/发授权；段与授权的写操作只属于控制台用户与管理 API。

## 2. 现状核验

以下结论均对仓内核验（2026-10-17 工作树）。**既有实现中没有 Segment / Group 实体**：分组的唯一既有单位是 `Network` 本身；同 Network 内 Overlay 全互通，跨 Network 完全隔离。

### 2.1 地址与网络实体

| 事实 | 位置 |
|---|---|
| `Network` 持有不可变 `overlay_cidr`（默认 `10.240.0.0/16`，ADR-004） | `crates/meshlet-domain/src/entities.rs:47`；`docs/decisions/adr-004-overlay-ipam.md` |
| `Ipam`：Network 级扁平顺序池，hub 保留第一可用地址，客户端顺序分配、全局唯一、耗尽报错、不回卷复用 | `crates/meshlet-domain/src/ipam.rs:21`（`allocate` 在 `:53`） |
| `Device`：`network_id` + `virtual_ipv4` + `public_key` + `platform` + `status`；无任何分组字段 | `crates/meshlet-domain/src/entities.rs:92` |
| `DeviceStatus = Pending | Active | Revoked`；Pending 申请不占地址、不进期望配置 | `crates/meshlet-domain/src/entities.rs:79`；`crates/meshlet-domain/src/entities.rs:123` |
| `DeviceRegistry::add` 拒绝同 Network 内重复虚拟 IP 与重复名 | `crates/meshlet-domain/src/entities.rs:468` |
| 注册批准时由 Network 级 IPAM `allocate()` 分配地址 | `apps/server/src/service.rs:1007`（分配在 `:1030`） |
| `LanRoute`：Network 级，`gateway_device_id` + `destination_cidr` + `route_mode(Direct/Alias)` + `return_path_mode` | `crates/meshlet-domain/src/entities.rs:215`、`:235`；表 `migrations/001_init.sql:57` |
| `AliasMapping`：与 Alias 模式路由 1:1，等长前缀 | `crates/meshlet-domain/src/entities.rs:280`；表 `migrations/001_init.sql:68` |

### 2.2 身份与授权现状

- 设备身份是每设备一把 WireGuard 静态公钥（`Device.public_key`），经邀请入会或自举注册+中心审批进入；私钥不离开设备（ADR-010；`apps/server/src/device_plan.rs:14`）。仓内**没有 CA、没有组密钥、没有每段 PSK**——文档层面查无按组组织密钥的机制。
- 控制台用户与设备身份是两套体系：用户登录 Argon2id + session（`crates/meshlet-domain/src/auth.rs:91`）；设备靠 agent token / 自举码（`migrations/003_agent_tokens.sql`、`migrations/008_device_registrations.sql`）。
- 既有的「授权」只有两级：
  1. **Network 成员资格**：非成员的公钥不在 hub peer 列表中，密码学上不可达（真实内核证据见 `crates/meshlet-network/tests/wg_forwarding.rs`，未授权 C 无 peer、ping 失败）。
  2. **路由发布状态**：只有 `Applied` 的 LanRoute/Alias 进入计划（`crates/meshlet-domain/src/peer_routes.rs:31`）。
- Network 内部 Overlay **默认全互通**：客户端到 hub 的 AllowedIPs 直接给整个 Overlay CIDR（`crates/meshlet-domain/src/peer_routes.rs:101`，`client_hub_peer_allowed_ips` 首行即 `vec![overlay_cidr]`）。这正是本设计要收窄的点。

### 2.3 计划编译与执行点（本设计改动的接缝）

| 环节 | 现状 | 位置 |
|---|---|---|
| 期望配置确定性哈希 | 输入 overlay/hub/设备/路由/Alias，无前缀授权维度；格式标签 `meshlet-desired-v3` | `crates/meshlet-domain/src/config_state.rs:35` |
| hub 侧计划 | 每 Active 设备一个 peer（/32 + 其发布前缀）；路由按 Direct/Alias 选真实段或 Alias 段经网关 | `apps/server/src/revision.rs:208`（`hub_plan`）；peer 推导 `crates/meshlet-domain/src/peer_routes.rs:136` |
| 设备侧计划 | 到 hub 单 peer，AllowedIPs = 整个 Overlay + 他人已发布 LAN/Alias；自己发布的不回灌 | `apps/server/src/device_plan.rs:53`（`build_device_plan`）；`crates/meshlet-domain/src/peer_routes.rs:101` |
| 计划对象 | `DevicePlan { tunnel, routes, nat_rules, hub_address, desired_config_hash }`，agent 只消费结构化对象 | `crates/meshlet-network/src/lib.rs:95` |
| hub/agent Linux 执行 | peer 对账：计划外 peer 立即移除；路由 `ip route replace`；NAT 按 owner 注释增删 | `crates/meshlet-network/src/linux.rs:190`（`reconcile_peers`）、`:429`（`apply_routes_sync`） |
| hub 现有 FORWARD 策略 | 仅两条 `-i wg0` / `-o wg0` ACCEPT（注释 `meshlet tunnel`），**无来源/目的维度的区分** | `crates/meshlet-network/src/linux.rs:443` |
| 外来路由冲突 | 目的前缀已指向其他接口时 fail-closed 拒绝 | `crates/meshlet-network/src/linux.rs:483` |
| Windows | 只有 netsh 路由**计划层**（任意平台可编译单测），执行层 `#[cfg(windows)]` 未实测；非 Linux 的 `SystemBackend` 是显式 Unsupported 占位；ADR-008 定 Windows v1 仅 Overlay 客户端，不做网关/NAT | `crates/meshlet-network/src/windows_routes.rs:37`；`crates/meshlet-network/src/lib.rs:40`；`docs/decisions/adr-008-windows-network-backend.md` |

另：端口转发提案（网关专题 §4）出现过 `allowed_sources`（设备/组）字样，但没有 group 实体与 API（`docs/architecture/gateways-conflicts-and-port-forwarding.md` §4）。本设计落地后，该字段的「组」主语即 Segment，不再另造分组概念。

## 3. 网段分配

### 3.1 模型

- `Segment` 隶属于一个 Network，持有一个 CIDR，该 CIDR 必须是 Network `overlay_cidr` 的真子集（或相等，见默认段）；同一 Network 内各 Segment CIDR 不得重叠（复用 `Ipv4Cidr::overlaps`，`crates/meshlet-domain/src/cidr.rs:75`）。
- 一个设备同一时刻**只属于一个 Segment**。设备的 `virtual_ipv4` 必须落在所属段 CIDR 内。
- 不要求段 CIDR 拼接后等于整个 Overlay：允许存在未分配的间隙地址，间隙地址不属于任何段，因而不被任何 FORWARD 规则覆盖（默认拒绝，见 §4）。
- LAN Route / Alias 不新增归属字段：其可见性由**发布网关设备所属的段**推导（见 §5）。

概念结构（设计态，非实现代码）：

```text
Segment          { id, network_id, name, cidr, status: Active|Quarantined, created_at }
Device 增加字段   { segment_id: SegmentId }                       // 设备唯一所属段
SegmentGrant     { id, network_id, source_segment_id, destination_segment_id,
                    status: Pending|Applied|Revoked, created_at, revoked_at }
```

### 3.2 默认段：存量网络零行为分叉

- 创建 Network 时自动创建一个 `default` 段，CIDR = 该 Network 的 `overlay_cidr` 整体。
- 不分段的网络只有这一个段：所有成员同段 ⇒ 同段互信，其数据面行为与今天完全等价（`-i/-o wg0 ACCEPT` 被「同段 ACCEPT」一条规则取代，放行集合相同）。
- 要分段时，用户显式新建更窄的段；新段与 default 段 CIDR 重叠，因此**启用分段的前提是 default 段先被收窄或删除**。为避免「改一个不可变对象的 CIDR」，规则定为：
  - default 段与用户段地位相同，**CIDR 创建后同样不可变**（沿用 Network/ADR-004 纪律）；
  - 用户想分段时，删除 default 段（要求其内已无 Active 设备），再创建多个窄段；
  - 因此「把一个已经在用的整网拆成多段」需要先把设备迁出，见 §6.3。这是有意的保守选择：地址位置即信任身份，不允许在成员无感知时改变边界。
- hub 地址（Overlay 第一可用地址）落在 default 段或某个业务段内时，规则约定：**hub /32 对所有段恒可达**（MTU 探测与计划拉取的既有行为，`DevicePlan.hub_address`，`crates/meshlet-network/src/lib.rs:95`），段策略规则显式放行到 hub /32，hub 不被视为可被普通成员访问的业务主机。

### 3.3 谁能创建、怎么选 CIDR

- 创建/删除段、发/撤授权：控制台登录用户（`WriteUser`，`apps/server/src/auth.rs:428`）与具备写权限的管理 API token；设备端任何接口不能建段或授权。
- v1 CIDR 由用户显式指定，服务端校验；不做自动切分（自动切分的前缀长度与扩容预期无法由服务端猜测，且段不可变，切错代价高）。
- 校验项（任一不过即拒绝，409 点名冲突对象，沿用路由冲突的错误口径）：
  1. 是 Overlay 的真子集（default 段例外，允许相等）；
  2. 与同 Network 其他段不重叠；
  3. 可用地址数 ≥ 2（hub 之外至少容纳一个成员；复用 `Ipv4Cidr::usable_addresses`）；
  4. 段 CIDR 不得与本 Network 已发布的 Alias 前缀重叠（Alias 前缀是隧道可见地址，与 Overlay 成员地址共用 cryptkey 路由空间；现有检查 `crates/meshlet-domain/src/conflict.rs:58` 同口径扩展到段）。
- 段内地址分配：把现有 `Ipam` 原样嵌套一层——Network 级 IPAM 负责**段 CIDR 的占用登记**（段 CIDR 视为已保留区间），每个段持有一个池为段 CIDR 的 `Ipam` 实例负责成员地址分配。因为段 CIDR 互不重叠，现有「IP 不重复」验收（`DeviceRegistry::add`，`entities.rs:468`）天然保持，不需要新的唯一性机制。
- 批准注册（`service.rs:1007`）增加必填语义：**批准时指定目标段**，地址从该段的 IPAM 分配；邀请入会同理。不允许先批准进网络再「补充分组」——无段成员在模型中不存在（控制台可把 default 段作为预选默认值）。

## 4. 信任边界模型

### 4.1 一句话不变量

> 从隧道收到的流量，hub 只在「源段 == 目的段」或「存在 Applied 的 source→destination 段授权」时转发；其余一律丢弃。

v1 所有成员流量都经 hub（ADR-002），因此**只需要在 hub 一个点执行策略**，成员设备自身不承担段判定。

### 4.2 双层执行（纵深防御，缺一不可）

**第一层：WireGuard AllowedIPs 收窄（cryptkey 路由）。**

- 设备侧计划中到 hub peer 的 AllowedIPs，从今天的「整个 Overlay + 他人全部 LAN/Alias」改为：
  - hub 自身 /32；
  - 本段 CIDR（同段全部成员）；
  - 每条 Applied 授权指向的**目的段 CIDR**；
  - 同段成员发布的、以及被授权目的段成员发布的 LAN/Alias 已发布前缀（可见性规则见 §5）。
- 改动点是 `client_hub_peer_allowed_ips`（`crates/meshlet-domain/src/peer_routes.rs:101`）的输入与集合构造；它今天无条件 `vec![overlay_cidr]`，改为由「本段 + 授权目的段」集合替代。`normalize` 排序去重（同文件 `:65`）保持不变。
- hub 侧每设备 peer 的 AllowedIPs（`hub_peer_allowed_ips`，`peer_routes.rs:76`）**不变**：它表达「该设备能从隧道发上来的源/目的地」，仍为设备 /32 + 它作为网关发布的 LAN/Alias，与信任授权无关。

**第二层：hub FORWARD 段策略（内核默认拒绝）。**

- 取代今天无差别的 `-i/-o wg0 ACCEPT`（`linux.rs:443`）。在受管 FORWARD 链位置按固定顺序安装（owner 注释保证可精确回滚，沿用 NAT 注释纪律，`crates/meshlet-network/src/linux.rs:36`）：
  1. 隔离规则（最高优先，§6.2）：`-s <quarantined 段> -j DROP`、`-d <quarantined 段> -j DROP`；
  2. 同段规则（每段一条）：`-s <segA> -d <segA> -j ACCEPT`；
  3. 授权规则（每 Applied Grant 一条）：`-s <segA> -d <segB> -j ACCEPT`（单向；反向需要另一条 Grant）；
  4. 到 hub /32 的隧道放行（保持既有探测/控制面行为）；
  5. 末尾受控默认拒绝：`-i wg0 -j DROP` 与 `-o wg0 -j DROP`（注释 `meshlet segment default-deny`）。
- 规则只匹配隧道转发路径，不动主机本地流量，不动非受管接口（与现有外来路由 fail-closed 纪律一致，`linux.rs:483`）。
- 两层各自挡住不同的失效模式：旧 agent 持有更宽 AllowedIPs 时，hub DROP 兜底；FORWARD 规则缺失/被外部清空时，cryptkey 路由使 hub 无法把包解密给错误的对端 peer。**「允许」与「拒绝」都必须有内核证据**（对应 PN-02 的验收口径）。

### 4.3 为什么不引入按段密钥/WireGuard PSK

- WireGuard 没有组密钥语义：每端独立静态公钥，可达性由中心编排的 peer 集合与 AllowedIPs 决定。「同段」在密码学上的含义不是共享秘密，而是「中心为同段成员互相编排了可达性、并在 hub 放行」。
- WireGuard 的可选 PSK 是**点对点**参数（抗量子附加层），不是段凭证；引入按段 PSK 会让成员变动时全段换钥，与「移出即失权」的简单模型相悖。v1 不引入。设备公钥与入段批准沿用既有注册/审批流（`migrations/008_device_registrations.sql`），段成员关系由期望配置哈希背书（§5.3），agent 只信任经既有鉴权拉到的计划——不需要新的证书体系。

## 5. 路由联动

### 5.1 LAN Route / Alias 的可见性随段走

- 一条已发布 LAN 路由（网关 G 属于段 B，目标 `192.168.10.0/24`）的可见集合 = 段 B 自身 ∪ 所有持有「source → B」Applied 授权的段。**路由本身不再新增授权字段**，授权主语统一为段，避免「设备可达性」与「网段可达性」两套模型并行。
- Alias 前缀同理：段 B 的网关发布的 Alias 前缀，只进入 B 自身及被授权段的计划。
- 这替换今天「同 Network 内任何 Active 设备都能看到全部 Applied 路由」的口径（`device_plan.rs:74` 起的路由循环、`peer_routes.rs:101` 的全量收集）。

### 5.2 计划编译的具体接缝

| 编译产物 | 现状输入 | 增加输入 |
|---|---|---|
| 设备 AllowedIPs（`client_hub_peer_allowed_ips`） | overlay + 全部他人路由/Alias | 本设备段、Applied Grant 集合；按「网关所属段」过滤路由/Alias |
| 设备路由表（`build_device_plan` 中 `routes` 循环，`device_plan.rs:74`） | 全部他人 Applied 路由 | 同一可见性过滤；不可见路由不生成 `RouteConfig`，也不进 AllowedIPs |
| hub peer AllowedIPs（`hub_peer_allowed_ips`） | /32 + 本设备发布前缀 | 不变 |
| hub 转发路由（`hub_plan`，`revision.rs:208`） | Direct 真实段/Alias 段经网关 | 不变（hub 必须能把已授权流量送到网关；是否允许由 FORWARD 策略决定，不由路由表决定） |
| hub FORWARD 规则 | 无（两条全放行） | **新增**：隔离/同段/授权/default-deny 规则集，随修订重放 |
| 网关侧 NAT（`nat.rs`） | Alias 映射推导 | 不变（NAT 只在授权流量到达网关后才有机会命中） |

网关失效、主备、重叠 Direct 拒绝等既有语义（网关专题 §2.3、RG-01）不受影响：段策略只决定「流量能否到网关」，不改变「到了之后怎么转发」。

### 5.3 期望配置与修订

- `desired_config_hash` 的输入增加两类内容并升级格式标签（`v3 → v4`，`crates/meshlet-domain/src/config_state.rs:42`）：
  - 设备行追加 `segment=<id>`；
  - 追加排序后的授权行 `grant <src-seg> -> <dst-seg>`（只计 Applied）；
  - 段 CIDR 集合行 `segment <id>=<cidr>`。
- 段/授权/成员归属的任何变更 = 该 Network 一个新 ConfigRevision（ADR-009 状态机不变），hub 计划与设备计划共用同一哈希口径；agent 仍是「哈希不变不重放」。失败修订的回滚只移除 Meshlet owner 的规则与 peer，段表数据保留（回滚的是数据面，不是关系本身——与今天路由/Alias 的口径一致）。

## 6. 撤销与隔离

### 6.1 移出成员与撤销授权

- **设备移出段**（改派到另一个段或挂起）：
  - 成员地址必须落在目的段内，因此「换段」= 在目的段分配新地址、重放该设备隧道地址与全部相关 AllowedIPs/FORWARD 集。设备 id、公钥、agent 凭证不变（与注册批准时「凭证原样沿用」同一纪律，`docs/guide/external-caller.md` 登记的口径）。
  - 在新修订 Applied 前，先在 hub 收紧：从旧段同段/授权规则的源集合中消失是规则重放的必然结果；为保证「立即失去旧段权限」，移出操作的 hub 计划先于设备侧计划应用（服务端编排顺序：hub 修订 Applied 后再放行设备新计划），最坏窗口等于一次 hub 重放时长，而不是等设备下次轮询。
- **撤销 Grant**：删除一条授权 = 新修订；hub FORWARD 对应规则移除 + 相关源段设备下一轮计划收窄 AllowedIPs。FORWARD 移除在 hub 即时生效；对端 AllowedIPs 收窄在下个轮询周期补齐（第二层兜底，期间默认拒绝已经恢复）。
- **设备 Revoke**（既有语义）：peer 对账立即移除（`linux.rs:190`），其发布路由/Alias 级联删除（既有行为）；段模型不改变这条路径，只额外要求 FORWARD 规则集重放。

### 6.2 整段隔离（应急）

- Segment 增加 `Quarantined` 状态。隔离动作**只动 hub 数据面、不动成员关系**：
  - 在 FORWARD 最前面插 `-s <seg> -j DROP` 与 `-d <seg> -j DROP`（owner 注释 `meshlet segment <id> quarantine`）；
  - 该段 peer 保留（成员与 hub 的隧道、计划拉取不断，便于取证与恢复），但任何跨成员转发被丢弃；该段网关发布的 LAN/Alias 因流量无法到达网关而对外不可达。
- 解除隔离 = 删除两条 DROP，回到同段/授权规则；不产生成员地址或授权关系的变化。
- 隔离也要记修订与审计事件（`audit_events`，`migrations/001_init.sql:90`），控制台展示「隔离中」覆盖该段所有在线状态。

### 6.3 删除段

- 仅允许删除无 Active 设备、无 Applied 路由/Alias 网关、无 Applied Grant 的段；否则 409 点名残留对象。
- 段删除后其 CIDR 回到 Network 未分配间隙，可被新段重新使用（地址复用发生在段级，与设备级 `Ipam` 不回卷不冲突：段删除是管理员显式动作）。

## 7. 与 Windows 的关系

结论：**段模型在 Windows 上同样成立，且不依赖 Windows 端做任何策略动作**，但 Windows 在 v1 不能承担段网关职责。

- 策略执行点全在 Linux hub：FORWARD 段策略与 peer 编排对流量来源不区分平台。一台 Windows 设备属于段 A，它发出的流量在 hub 上与 Linux 设备走同一条 `-s 10.x.A.0/dd` 匹配路径。
- Windows 客户端侧唯一相关的是 AllowedIPs——而它由官方 WireGuard for Windows 隧道配置直接生效（ADR-008 的既定路线：优先隧道自身 AllowedIPs 生成的路由，`netsh`/API 补充）。计划收窄到「本段 + 授权段」后，Windows 端无需新增过滤组件；`windows_routes.rs` 的计划层（`crates/meshlet-network/src/windows_routes.rs:37`）也只需按收窄后的 `RouteConfig` 集合工作，无新增命令种类。
- 边界：ADR-008 定 Windows v1 仅 Overlay 客户端，不做 LAN 网关与 Alias NAT。因此一个「成员全是 Windows」的段可以正常做 Overlay 同段互通与被跨段授权访问，但**不能发布 LAN 路由**；PN-03（Windows 完整 Overlay 客户端，隧道服务/提权/开机恢复）完成前，Windows 甚至还没有完整数据面。段设计不要求 PN-03 先行，PN-03 落地时按本文 AllowedIPs 口径实现即天然在段内。
- Windows 上不安装、也不需要安装本地段防火墙规则；若未来出现 P2P 直连（v2），端点执行才成为问题——那是 PN-02 的前置项，本文的 hub 单点模型不预付这笔复杂度。

## 8. 实施契约草案（供后续 ADR 细化，本轮不实现）

- 迁移（下一个 migration 编号）：
  - `segments(id, network_id, name, cidr, status, created_at)`；
  - `segment_grants(id, network_id, source_segment_id, destination_segment_id, status, created_at, revoked_at)`；
  - `devices` 加 `segment_id REFERENCES segments(id)`；
  - 存量网络回填：每个已有 Network 建一条 `default` 段（CIDR = overlay），全部存量 Active 设备挂入。
- API（沿用现有 `/api/v1/networks/{id}/...` 层级与修订回执风格）：
  - `GET/POST /networks/{id}/segments`、`DELETE /segments/{seg_id}`；
  - `POST /segments/{seg_id}/quarantine`、`DELETE /segments/{seg_id}/quarantine`；
  - `GET/POST /networks/{id}/segment-grants`、`DELETE /segment-grants/{grant_id}`；
  - 设备批准/入会请求增加 `segment_id`；设备改派 `POST /devices/{id}/segment`（语义为 §6.1 的换地址重放）。
- 冲突检查扩展点：`conflict.rs` 的 `check_network`（`crates/meshlet-domain/src/conflict.rs:182`）增加段间重叠、段/Alias 重叠、段/Overlay 包含关系三类，沿用 `ConflictKind` 严重度分类。
- 后端执行扩展点：`NetworkBackend` trait（`crates/meshlet-network/src/lib.rs:173`）增加一个 `apply_segment_policy(rules)` 之类的受控方法（规则由域层纯函数渲染，参数化 argv，与 `nat.rs` 同纪律），`NetworkSnapshot` 增加段规则计数用于漂移对账（AR-03）。

## 9. 与既有待办条目的衔接

| 条目 | 关系 |
|---|---|
| RG-01（不同目标网段走指定网关；网关失效不串站） | 正交且复用：段策略决定「谁能到网关」，网关选择仍由 `LanRoute.gateway_device_id` 决定。无新路由模型 |
| RG-02（重复站点用独立 Alias；收敛真实/Alias 前缀口径） | 段可见性过滤是 RG-02 前缀口径收敛的**额外调用方**：AllowedIPs/路由集合在既有真实/Alias 口径之上再按段过滤，不改变 Direct/Alias 的选择规则 |
| RG-03（Overlay/Alias/Direct/本地及多网络冲突域完整检查） | 段 CIDR 纳入同一冲突域：段/Alias、段/Overlay 检查进 `check_network`；跨 Network 仍互不可见，段不打通网络边界 |
| PN-01（Device/成员/设备组/能力模型） | **Segment 即 PN-01 中「网络内分组」的答案**。建议 PN-01 的分组部分与本设计合并为一个 ADR；「一机多网」仍留在 PN-10，不被本文拉入 |
| PN-02（组到设备/服务端口最小策略） | 分层关系：本文是网络层「段对段」粗粒度默认拒绝；PN-02 在其上做设备/端口细粒度策略。PN-02 的端点执行前置问题只在 v2 P2P 时出现；hub 模型下细粒度策略同样在 hub FORWARD 落点即可 |
| PN-03（Windows 完整 Overlay 客户端） | 见 §7：不阻塞本设计，实现时遵循收窄后的 AllowedIPs 口径即可 |
| AR-01（单实例多 Network 互不干扰） | 段规则按 Network 的受管接口与 owner 注释归属，资源归属模型直接复用；段表也是 per-Network |
| AR-02（计划/ACK/修订哈希） | 哈希升 v4、段与授权变更进修订链；hub 与设备两侧 ACK 分别要求 |
| 网关专题 §4 端口转发 `allowed_sources` | 其「组」主语采用 Segment；host-forward 的 `/32` Route+Alias 原子模型不变，仅来源集合受段可见性约束 |

## 10. 验收条件（内核证据，非配置截图）

1. 同段可达、跨段默认拒绝：两段各两个 Active 设备的真实 netns 矩阵——同段双向 ping 成功；跨段四组全部失败，且 hub `iptables -S FORWARD` 可见对应 ACCEPT 缺失与末尾 default-deny 规则（扩展 `crates/meshlet-network/tests/wg_forwarding.rs` 同形态）。
2. 显式授权单向生效：Grant A→B Applied 后 A 可访问 B、B 仍不可访问 A；`wg show <if> allowed-ips` 中 A 的 peer 只含本段 + B 段，B 不含 A 段。
3. 路由随段可见：段 B 网关发布 LAN 路由后，A 段设备计划在授权前不含该前缀（`build_device_plan` 单测 + 真实路由表），授权后出现，撤权后下一轮消失且 hub DROP 即时恢复。
4. 移出即失权：设备换段重放期间，旧段地址在 hub `wg show` peer 与 FORWARD 源集合中均消失后才算完成；旧段成员对其旧 /32 的 ping 失败为完成判据。
5. 整段隔离：置 Quarantined 后该段入/出转发全部失败、成员隧道仍在（`wg show` handshare 可继续）、解除后恢复，全程无成员/授权数据变化。
6. 存量兼容：迁移回填后单 default 段网络的内核规则放行集合与迁移前 `-i/-o wg0 ACCEPT` 等价（构造性证明 + 既有 `wg_forwarding.rs` 四项断言不回归）。
7. Windows 计划层：Windows 设备计划的 AllowedIPs/路由集合在 Linux 侧单测可断言（`windows_routes.rs` 既有模式），不把 Windows 实测作为本设计验收门槛。

## 11. 风险与未决

- ** hub 规则规模**：FORWARD 规则数随「段数 + 授权数」线性增长，个人规模（十段、数十授权）无压力；不预先做 ipset/nftset 聚合，规模到了再在同一计划层替换渲染。
- **换段即换 IP 的体验**：设备段间迁移必然改变其 Overlay 地址（地址位置即边界），对记住了旧 IP 的使用方不友好。缓解：PN-09 名称解析落地后以名称访问；本文不为它破坏「CIDR 即边界」的直接性。
- **default 段拆分需先清空**：对「已在用网络中途分组」要求先迁成员，这是保守约束；若实际场景强烈需要，另开「段 CIDR 预留 + 成员原地迁移」的设计，不与本文混做。
- **同段互信仍是全端口**：网络层同段 ACCEPT 不等同于应用层安全；勒索软件横向移动场景需要 PN-02 的端点级策略，文档与控制台文案需明示「同段 = 网络可达，不等于服务免鉴权」。
