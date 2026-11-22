# 节点与网络唯一身份（ZeroTier 式稳定 ID）

状态：提案（仅设计，本文档不包含任何实现代码）。日期：2026-11-07。

## 1. 问题与现状

ZeroTier 给每个节点一个永久的短地址（40 bit、10 位十六进制、由节点公钥推导），
给每个网络一个自描述的 16 位 ID（控制器的 40 bit 地址 + 24 bit 网络号），节点
`zerotier-cli join <nwid>` 即可加入、由控制器授权成员资格。Meshlet 目前两者都
没有可引用形态：

**节点身份现状。** 领域层把 `DeviceId` 定义为不透明字符串新类型
（`crates/meshlet-domain/src/entities.rs:27`），取值是服务端序列号而非设备的
固有属性：邀请路径分配 `dev-{count+1}`（`apps/server/src/service.rs:1502`），
自举路径分配 `dev-reg-{seq}`（`apps/server/src/service.rs:1309`），批准时把
`dev-reg-N` 原样带入永久设备行（`apps/server/src/service.rs:1372`，`id:
registration.id.clone()`）——两种格式并存，且换库重建后都不延续。事实上的节点
身份是 WireGuard 公钥：`devices.public_key`（`migrations/001_init.sql:28`），
进入期望配置哈希行 `device name=… vip=… pubkey=…`
（`crates/meshlet-domain/src/config_state.rs:57`），是直连链路的对账键
（`crates/meshlet-network/src/dial.rs:27-28`，agent 按 `public_key` 对账候选），
并在本地面板整串展示 44 字符（`apps/tray-host/src/panel.rs:907`）。电话报障时
没人能口述一串 44 字符 base64。

**网络身份现状。** `NetworkId` 新类型存在
（`crates/meshlet-domain/src/entities.rs:26`），但取值是 `net-{count+1}`，按
创建顺序分配（`apps/server/src/service.rs:1088`），纯属内部记账：agent 从头到
尾见不到它。agent 的网络归属是间接建立的——`agent.toml` 里的 `server_url` +
`bootstrap_token`（`crates/meshlet-config/src/lib.rs:303-318`），自举码行把设备
绑到一个网络（`crates/meshlet-domain/src/entities.rs:148-157`，
`bootstrap_tokens.network_id`）。注册响应里虽然返回 `network_id`
（`apps/agent/src/server.rs:63-72`），agent 只打日志
（`apps/agent/src/bootstrap.rs:108-113`），不落账本。`{state_dir}/applied.json`
的字段里有 `tunnel_address` 与
`local_public_key`（`apps/agent/src/reconcile.rs:20-50`），但没有任何网络或节点
标识。

**加入流程现状。** 凭证解析顺序：配置 `device_token` → 已存
`{state_dir}/device_token` → 持 `bootstrap_token` 自注册
（`apps/agent/src/bootstrap.rs:9-12,35-71`）。注册把本机公钥 POST 到
`/api/v1/device-registrations`，落 Pending `DeviceRegistration`
（`crates/meshlet-domain/src/entities.rs:129-142`），由人在控制台批准
（ADR-011）。不存在「凭 ID 加入」：拿不到某个 hub 控制台签发的 token 就无法把
新 agent 指到它的网络，网络本身也没有带校验、可转抄的标识符。

**为什么现在要做。** 在飞的 SSH 分发席按设备名生成 `ssh_config`/主机别名；设备
名可改、改名后别名失锚。稳定的短节点 ID 给别名一个免改名的锚点；可引用的网络
ID 把「把这台机器加进我的网」变成一条可复制的字符串。

## 2. 目标与非目标

目标：

1. 由 WireGuard 公钥派生的永久、可人读节点 ID，hub 与 agent 各自推导结果一致。
2. 带校验位、自描述归属 hub 的网络 ID。
3. 存量部署零数据面行为变化的平滑迁移。
4. 在飞的 alias/`ssh_config` 分发落地后可解析节点 ID。

非目标（本期）：

- agent 侧多网络共存：一个 agent 仍只加入一个网络。
- 凭 ID 发现 hub：网络 ID 本期不替代 `server_url`；没有把 ID 解析到 hub 地址的
  注册表/DHT。
- 密钥轮换：换钥仍是一次重新注册事件（与现状相同），因此节点 ID 随之改变。记
  录在案，不在本期解决。

## 3. 节点 ID（8 字符、40 bit）

**定义。** `node_id = base32_crockford( SHA-256("meshlet-node-v1" ||
wireguard_public_key_bytes) )[0..8]`——对 base64 解码后的 32 字节公钥做域分隔 SHA-256，
取前 8 个 Crockford base32 字符 = 40 bit。线上小写；Crockford 解码容忍 `i→1`、`l→1`、`o→0` 转抄错。

**性质。**

- *密钥存续期内永久*：由 agent 首启生成且重启不变的密钥推导
  （`apps/agent/src/bootstrap.rs:87-99`，已有密钥文件复用，「重装不换钥匙」）。
  限定词如实：ID 恰在与密钥存续且不轮换的期间内永久；丢失私钥文件的重装即新身
  份（与现状相同）。hub 与 agent 各自从既有材料即可计算，展示无需往返。
- *与密钥双向绑定*：持公钥者可重算 ID；仅持 ID 推不出任何东西（40 bit 截断，
  原像不可行），也不能借此冒充——WireGuard 认证仍用完整公钥。
- *碰撞预算*：生日概率 `1 − e^{−n(n−1)/2^41}`：100 节点约 4.5e-7 %，1000 节点
  约 4.5e-5 %，10000 节点约 0.0045 %。hub 的 UNIQUE 约束是权威；对本产品个人
  舰队的定位（ADR-014）碰撞可忽略，且确定性推导使恢复期回填幂等。

**分层——保留既有主键。** `devices.id`（`dev-N`/`dev-reg-N`）继续作为存储与外
键层；节点 ID 作为展示/寻址层新增：迁移加 `devices.node_id TEXT` + UNIQUE 索
引，服务启动时从 `public_key` 回填（Rust 计算而非 SQL——对 base64 密钥做
SHA-256）。理由：所有对设备的存储引用（`device_keys.device_id`、
`lan_routes.gateway_device_id`、任务、计划）都已以 `dev-N` 为键，换键无收益、
只给恢复路径加风险。这也与 ZeroTier 自身的分层一致：40
bit 地址是对端句柄，控制器另存更丰富的成员记录。

**呈现面。**

- `direct-peers.json` 的 `DirectPeerView`
  （`crates/meshlet-network/src/dial.rs:61-81`）增可选 `node_id`：新字段在读写两
  侧结构上都用 `#[serde(default)]`，新旧混布的每个方向都容忍缺字段——既有先例
  是 `name` 字段对旧服务端缺省为空（「旧服务端缺省为空」，`dial.rs:63`）。
- CLI `peer dial <node>` 解析（`apps/cli/src/main.rs:296`
  `resolve_dial_target`——名称精确 / overlay IP / 公钥前缀）在同一函数内增加节
  点 ID 前缀匹配。
- 面板与控制台以 8 字符节点 ID 取代或并列 44 字符公钥
  （`apps/tray-host/src/panel.rs:907`）。
- 期望配置哈希不动（`crates/meshlet-domain/src/config_state.rs:36-57`，
  版本串 `meshlet-desired-v4` 在 `config_state.rs:44-45`）：节点 ID 不是期望状态的一部分，加入它不得升哈希版本、
  不得触发全网重应用。

## 4. 网络 ID（16 字符、自描述）

**定义。** `nwid = base32[8 字符 hub 节点 id][6 字符网络号][2 字符校验]` =
16 个小写 Crockford base32 字符，规范形态无分隔符；UI 可分组为
`xxxxxxxx-xxxxxx-xx`。与 ZeroTier 完全一致，前 40 bit 是控制器（hub）自己的节
点 ID——由 hub 公钥推导，服务端本就能拿到（
`apps/server/src/device_plan.rs:61-63` `hub_public_key`）——所以 ID 无需查表即
指明归属 hub。中间 30 bit 是 `create_network`
（`apps/server/src/service.rs:1067`）创建时分配的每 hub 随机网络号。末 10 bit
是对前 14 字符 ASCII 字节的 CRC-10 校验（poly `0x233`、init `0`、不反射、无
xorout——ATM CRC-10），以 2 个 Crockford base32 字符编码：高 5 位在前、低 5 位
在后，线上小写。CRC 保证检出任一单字符错误与长度 ≤ 10 的任意位突发；更长突发
不在穷尽保证之列。实现必须附带固定测试向量——例如前 14 字符 `abcd2345abcd23`
的 CRC 为 `0x307`，完整 ID 即 `abcd2345-abcd23-r7`——保证所有生产者与消费者逐
字节一致，再发起任何网络调用。

**分层。** 同节点 ID：`net-N` 留作内部主键（`migrations/001_init.sql:14-21`）；
nwid 以 `networks.nwid TEXT UNIQUE` 新增，创建时分配、启动时回填（确定性：hub
节点 id + 按既有行 `created_at` 排序派生网络号，跨重启稳定）。既有 API 路由
`/api/v1/networks/{id}` 不变；nwid 以增量字段出现在视图里。

**凭 ID 加入（目标形态）。** `agent.toml` 在 `bootstrap_token` 旁新增可选
`network_id`（`crates/meshlet-config/src/lib.rs:303-318`）。agent 本地校验校验
位后走与今天完全相同的流程（`apps/agent/src/bootstrap.rs:35-71`）；注册请求携
带 `network_id`，hub 拒绝两种请求：nwid 解析不到自己网络之一的，以及 nwid 与
所持自举码绑定的网络（`bootstrap_tokens.network_id`）不一致的——否则 A 网络的
token 可以在同一 hub 上声称加入 B 网络。本期 nwid 是*本地校验
与可引用*层——`server_url` 仍是实际传输地址。以 ID→hub 发现取代 `server_url`
明确列为后续工作（§8）。

**授权。** 默认不变：加入的设备仍落 Pending `DeviceRegistration`、需控制台批
准（ADR-011）——这正是 ZeroTier「私有网络」的对应物，比 ZeroTier 默认放行的
公共网络模式更严格。实验网络可按需给 `BootstrapToken`
（`crates/meshlet-domain/src/entities.rs:148-157`，行内已有 `max_uses`，放按
token 策略位正合适）加 opt-in 的 `auto_authorize`。批准即授权闸门；仅知 nwid
得不到任何权限。

**多网络边界。** hub 侧本就支持一个部署多网络（hub 状态持有
`networks: HashMap<String, Network>`，`apps/server/src/service.rs:487`；每个设备行带 `network_id`，
`crates/meshlet-domain/src/entities.rs:96`）。不存在的是 agent 侧共存：一个
agent 进程管一个 overlay 接口、一份账本、一个 `applied.json`。agent 多网络意
味着多隧道、按网络分账本、路由策略与面板 UI——那是独立的一期（§8），不混入
ID 工作。本期落地 ID 的*格式与签发*，让未来多加入消费稳定 ID 而不是 later 破
坏性改名。

## 5. 迁移路径（存量部署）

阶段 A——签发，零行为变化：

1. 迁移 `018_identity_ids.sql`：`ALTER TABLE devices ADD COLUMN node_id TEXT`；
   `ALTER TABLE networks ADD COLUMN nwid TEXT`；两者加 UNIQUE 索引（可空列，迁
   移本身天然向后安全）。
2. 服务端恢复路径启动回填（`apps/server/src/persist.rs` 把行载入领域状态）：
   按每台设备的 `public_key` 算节点 ID，按 hub 密钥 + `created_at` 顺序算
   nwid：仅对 NULL 行回填，按稳定行序 `(created_at, id)`（秒级时间戳可能并列，
   以 id 决胜）。已分配的 nwid 随即**持久化并永久权威**——恢复时保留存储列，绝
   不对变化后的行集重新推导；只有仍为 NULL 的行（刚升级的旧行）才推导。新网络
   随机号与既有号碰撞时，hub 在插入前内存内重抽（hub 可见全部行）。
3. API 增量：设备/网络/注册视图增 `node_id`/`nwid` 字段。
   RegisterDeviceResponse 本就返回 `network_id`
   （`apps/agent/src/server.rs:63-72`），并列增 `nwid`。比 hub 新或旧的 agent
   都忽略未知 JSON 字段。
4. agent 账本：hub 上报后 agent 把可选 `network_id` 写入 `applied.json`；旧
   hub 下缺省。WG 配置零变化——计划、peer、AllowedIPs、哈希版本全部不动。（该
   账本字段属于阶段 A 交付物，已列入下方验收表。）

阶段 B——呈现面：CLI/面板/控制台展示节点 ID；`resolve_dial_target` 支持节点
ID 前缀；alias/`ssh_config` 分发席（在飞）输出 `Host <name>` 加
`# node-id: xxxxxxxx` 锚注释，改名后别名可凭锚点重解析。这是在飞工作受益点：
现在无需改动，落地时获得稳定挂靠键。

阶段 C——凭 ID 加入：`network_id` 配置项 + 本地校验位 + hub 侧 nwid 核验 +
可选 `auto_authorize`。bootstrap token 仍是入会凭证——nwid 寻址，token 认证。

每期独立可发；A 不改变任何数据面行为与既有 API 调用语义（仅增量 JSON 字段），
B 只动展示/解析，C 新增默认关闭的输入路径。降级如实声明：代码里设备/网络有多
条插入路径（`apps/server/src/persist.rs:125`、`persist.rs:440-453`、
`persist.rs:625-630`）；旧二进制跑在新 schema 上会继续向新列写 NULL（SQLite 的
UNIQUE 索引允许多个 NULL，不会坏——这些行只是暂无 ID，升级后的二进制下次启动
回填补上）。降级不删列，只是忽略。「独立可回滚」仅在这个意义上成立，不是字节
级状态往返。

## 6. 协议/存储改动清单

| 领域 | 改动 | 兼容性 |
| --- | --- | --- |
| 领域层（`meshlet-domain`） | 新纯函数 `node_id(pubkey)`、`nwid_assign(hub_node_id, number)`、`nwid_verify(str)`；阶段 A 不新增实体字段 | 纯增量 |
| 迁移 | `018_identity_ids.sql`：两个可空列 + UNIQUE 索引 | 增量 |
| 服务端持久化 | 启动回填两列；写入时带上（`apps/server/src/persist.rs:125-143` `insert_device_tx`） | 旧库新二进制：回填；新库旧二进制：忽略列 |
| 服务端 API | 设备/网络/注册视图与 `RegisterDeviceResponse` 增量 JSON 字段 | 双向容忍未知字段 |
| agent 账本 | `applied.json` 可选 `network_id`（`apps/agent/src/reconcile.rs:23` 结构 `AgentState`）；serde default | 旧 agent 不写 |
| agent 发布 | `direct-peers.json` `DirectPeerView` 可选 `node_id`（`crates/meshlet-network/src/dial.rs:62-70`） | 读取端本就缺省容忍 |
| CLI | `resolve_dial_target`（`apps/cli/src/main.rs:296`）增节点 ID 前缀匹配 | 纯增量 |
| 面板/控制台 | 展示替换或并列（`apps/tray-host/src/panel.rs:907`） | 外观级 |
| `direct.rs` keep set | 不动——`direct.json` 持久化的是每对端公钥（`apps/agent/src/direct.rs:86-92,143-150`），本设计不触碰 | — |
| 期望配置哈希 | 不动、不升版本（`config_state.rs:44-45`） | 无全网重应用 |

## 7. 风险与边界

- **碰撞。** 节点 ID 40 bit，数字见 §3；UNIQUE 索引是权威。须区分两种情形：同
  一公钥重复注册走既有去重路径（幂等）；*不同*公钥截断成相同 8 字符会在插入时
  以 UNIQUE 违例大声失败，由操作员按文档化的扩展规则处置：受冲突行的存储
  `node_id` 扩展为同一摘要的前 10 个字符（UNIQUE 索引加在存储值上；8 字符仍是
  展示默认形态；命中歧义的查询以控制台展示的完整存储 ID 决断）。绝不静默错路。网络号每 hub 30 bit 随机，插入前内存查重。40 bit hub id
  本身跨 hub 有非零生日概率（1000 hub 约 4.5e-5 %）——可接受，且只有多 hub 共享
  ID 后才相关，但如实写明而非否认。
- **ID 泄露面。** 节点 ID 是 40 bit 密钥截断：写进报障泄露不了可用信息。nwid
  不是秘密（ZeroTier 的也不是）：加入仍需自举码（只存摘要，
  `crates/meshlet-domain/src/entities.rs:144-146`）与控制台批准。阶段 C 的
  `auto_authorize` 必须保持按 token opt-in，以既有 `max_uses` 限爆炸半径，默认
  关闭。
- **与 `bootstrap_token` 的关系。** 互补而非竞争：token 认证首次接触
  （ADR-010/011，静态只存哈希），nwid 寻址网络并使指令可转抄（「在 hub X 上凭
  nwid `abcd2345-abcd23-r7` 加入」）。阶段 C 把两者接进同一配置块；A/B 两期不弱
  化 token 路径的任何环节。
- **密钥轮换。** 新钥 ⇒ 新节点 ID。可接受：轮换本就是重新注册事件（新的
  Pending 注册、新的批准）；本文档如实记录，而不假装 ID 比密钥活得久。
- **hub 重建/搬迁。** 顺序型内部 id（`net-N`、`dev-N`）依赖创建顺序，而节点 ID
  依赖内容：重建的 hub 从 `public_key` 行重算出完全相同的节点 ID。nwid 则以持
  久化列为权威——保住了数据库就保住了全部 nwid；只有 NULL 行（刚升级的旧行）
  才按 §5 回填规则推导。这一点优于现状——现状重建 hub 会铸出新的序号。
- **在飞席位。** direct.rs 状态机与 SSH 分发两席不受本设计影响；§5 阶段 B 指明
  唯一集成点（别名锚注释），落地顺序为：身份阶段 A → 分发席消费 ID。

## 8. 分期与验收

| 阶段 | 交付 | 验收 |
| --- | --- | --- |
| A | 迁移 018 + 回填 + API 增量字段 + agent 账本 `network_id` | 存量部署升级后 WG/计划零变化、既有 API 语义不变；恢复产生相同 ID；`desired_config_hash` 不变 |
| B | CLI/面板展示 + 拨号解析 + 别名锚点 | `meshlet peer dial <8 字符前缀>` 可解析；面板显示节点 ID；ssh_config 带锚点 |
| C | `network_id` 配置 + 校验位 + hub 侧核验 + opt-in `auto_authorize` | 校验位损坏的 nwid 在任何网络调用前被本地拒绝；他 hub 的 nwid 被服务端拒绝；不带新字段时默认流程不变 |
