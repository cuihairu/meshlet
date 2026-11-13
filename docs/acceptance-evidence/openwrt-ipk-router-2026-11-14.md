# OpenWrt .ipk 打包 + LuCI 真机验收（2026-11-14）

## 交付物

- `packaging/openwrt/`：UCI 配置、双 procd init（UCI→TOML 渲染）、LuCI controller/cbi/status、CONTROL、app-meta json、`build-ipk.sh`（三包：`meshlet` / `luci-app-meshlet` / `app-meta-meshlet`，tar.gz 容器形制，照 custos 先例）
- `scripts/package-openwrt.sh`：nightly 包装（滚动资产名 `meshlet-nightly-openwrt-<arch>.ipk` / `-luci-app.ipk` / `-app-meta.ipk`）
- `assets/icons/meshlet.png`：128×128 RGBA，由 `logo-teal.svg` 渲染
- `.github/workflows/nightly.yml`：build 矩阵加 ipk 打包步、checks 加 sh/bash 语法 + shellcheck + `luac5.1 -p` 门禁、publish 资产清单与 SHA256SUMS 加 `meshlet-nightly-openwrt-*.ipk`
- `README.md` / `README.zh.md`：OpenWrt 安装节（双语）

## 本机门禁

- musl 静态构建：x86_64 直编 EXIT 0；aarch64 经 `cross` EXIT 0
- `shellcheck` build-ipk.sh / package-openwrt.sh 通过（后者 shebang 由 sh 改 bash，`set -euo pipefail` 是 bash 语法）
- `luac -p` controller/cbi 通过
- .ipk 结构：三成员 `./debian-binary` / `./control.tar.gz` / `./data.tar.gz`；control 字段齐全（License Apache-2.0，Section net）；postinst/prerm 0755；conffiles 三条；data 归档带目录条目（见下）
- aarch64 包本机结构检查通过；**无 aarch64 真机，opkg 全链路仅 x86_64 实测**（如实标注）

## 真机验收（192.168.5.11，iStoreOS 24.10.8 x86_64）

### 安装链（发现 2 个真 bug，均已修复回归）

1. `opkg install meshlet → luci-app → app-meta` 0.1.0-1：luci-app 配置报 `wfopen: view/meshlet/status.htm: No such file or directory`。**根因：opkg 解包器不为 file-only 成员创建缺失父目录**（custos 的 controller/model 叶子目录当时恰好已存在才侥幸装上）。修复：data.tar.gz 改为整树归档（带目录条目），postinst 同步补 `mkdir -p` 叶子目录。0.1.0-2 升级安装干净通过（同时即升级路径证据）。
2. agent 首启 TOML 解析失败：`unknown field listen_port, expected ... direct_connect`。**根因：agent 配置里直连监听端口在 `[dataplane.direct_connect]` 子表，不在 `[dataplane]` 平层**（server 侧平层合法，两边 schema 不同）。修复 agent init 渲染为独立子表后 agent 正常运行。

### 控制面 + 数据面全链路

- UCI→TOML 渲染正确（bind 18080 实际生效）；hub 密钥首启 `wg genkey` 自动生成（0600）
- bootstrap 建首管理员 → 建 net-1 → 发 read token → 发设备自举码（全程 curl 实测）
- read-scope Bearer 查 networks/devices 成功（即 LuCI 状态页数据路径）
- agent 自举注册 dev-reg-1 → pending → 批准 → VIP 10.240.0.2
- apply rev2 因 hub 数据面未开而 Failed（`dataplane_not_configured` 语义正确）；开 `server.dataplane=1` 后 rev2 已 Failed 不可重 apply（`illegal transition: Failed -> Applied` 状态机拒绝）→ rollback rev2 → labels 变更不出新 revision → **apply rev1 成功**
- 数据面打通：hub `meshlet` 接口 51820，agent 侧 peer（allowed-ips 10.240.0.0/16，keepalive 25s），hub→agent VIP ping 3/3 丢包 0%，均值 0.117 ms；agent 日志 `applied the desired device plan ... reason=KernelDrift`

### 升级路径（0.1.0-2 → 0.1.0-4）

- `resolve_conffiles: Existing conffile /etc/config/meshlet is different ... /etc/config/meshlet-opkg`：用户配置保留、新默认旁路，符合预期
- prerm 停双角色 → postinst 自动拉回（server/agent 均 running）——postinst 由此新增「已启用角色升级后自动 start」
- bind/api_token/enabled 全部保留；wg 接口密钥持久不换

### LuCI

- postinst 清 indexcache 生效；controller/cbi 在路由器 Lua 5.1 `loadfile` 解析通过
- `luci.template.parser.parse()`（LuCI 渲染时的真编译步）对 `meshlet/status.htm` TEMPLATE_PARSE_OK，custos 已知良好模板作对照组同绿
- 路由存在性：`/admin/services/meshlet` 与 `/status` 均 403（sysauth，非 404）；重启 uhttpd 后仍 403，路由存活
- **诚实边界：LuCI 页面 HTTP 渲染未走通（无 web 登录凭据，无法建会话）；模板编译与路由注册已验证，浏览器端渲染留待人工确认**

### 资源占用（server 角色可选性的实测依据）

- meshlet-server RSS ~10.7 MB（数据面开启）；agent RSS ~6.4 MB（x86_64，1.6 GB 内存路由器）
- Installed-Size：主包 ~35 MB（三二进制）

## 收尾状态

路由器已还原安全态：双角色 disabled、bind 回 8080、api_token/bootstrap_token 删除、运行时状态（DB/密钥/token/注册）全清、测试 wg 接口删除、opkg 旁路文件删除。三包保留安装（disabled）。测试期生成的管理员口令与 token 已随 DB 一并销毁。

## 遗留

- LuCI 浏览器端人工点验（有凭据后 1 分钟事）
- aarch64 真机 opkg 链路
- iStore 上架（后续项）
