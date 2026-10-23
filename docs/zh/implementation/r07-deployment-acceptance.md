# R-07：正式部署与长期运行验收

2026-10-24 的验收运行，环境是本地 Proxmox VE 9.2.4 宿主机（`pve-manager/9.2.4`，内核 7.0.14-4-pve，1.82 TiB LVM thin 池）：hub 容器 192.168.5.150（`wg0` 10.240.0.1/16，监听 :51820），三台设备容器 192.168.5.151/.152/.153（10.240.0.2/3/4）。实验台时钟为 UTC，故时间戳记作 `2026-10-23T22:xxZ`。被测二进制为本轮本地构建（agent `sha256/16 2114bd9e16de2045`、server `92318893987ae2e0`）；下方「空白容器安装」用的是**已发布的** nightly 资产。控制台口令与所有 token 每次现生成，从不出现在日志里。

## 空白容器安装

第三台容器直接从原版 `debian-12-standard_12.12-1` 模板创建，无任何预装：2 核、1 GiB 内存、非特权、`nesting=1`、10 GiB thin 根盘、一条 veth 接管理网桥。`install.sh` 直接从已发布的 release 拉取后管道执行。

有两处文档是错的，都是这次安装发现的：

- README 的一行式是 `curl -fsSL … | sudo bash -s -- agent`。原版 Debian 12 容器**既没有 `curl` 也没有 `sudo`**：结果就是 `curl: command not found`、`sudo: command not found`、退出码 127，机器上什么都没留下。容器里有 `wget`，所以 `wget -qO- … | bash -s -- agent …` 可用。README 现在写明前置条件（`apt-get update && apt-get install -y curl sudo`）与 wget 形式。
- install.sh 的 apt 行往容器里装了 **107 MB 的内核镜像**（`linux-image-6.12.113+deb12-rt-amd64` 连带 `initramfs-tools`、`linux-base`、`klibc-utils`，17 个新包，"Need to get 111 MB of archives"），来自 `wireguard-tools` 的 Recommends 链。容器与宿主共享内核，这镜像纯属浪费，还多花了两分多钟下载（755 kB/s）。`scripts/install.sh` 现改为 `--no-install-recommends`；`for tool in …` 检查仍会在真缺工具时报错。

wget 形式随后跑通：依赖装齐（wireguard-tools 1.0.20210914-1+b1、iptables 1.8.9-2、iproute2 6.1.0-3、iputils-ping、ca-certificates、curl），压缩包下载并校验，服务落到如下状态——`active`；单元加固 `User=meshlet-agent`、`Group=meshlet-agent`、`AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`、`CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW`、`ProtectSystem=strict`、`ReadWritePaths=/var/lib/meshlet-agent`、`ExecStartPre=+sysctl -w net.ipv4.ip_forward=1`；`/etc/meshlet/agent.toml`、`/etc/meshlet/agent.key`、`/var/lib/meshlet-agent/device_token` 均为 `0600 meshlet-agent:meshlet-agent`；`agent.toml` 写入 `device_name = "pve-dev-3"`、`hub_endpoint = "192.168.5.150:51820"`、`poll_interval_secs = 30`，bootstrap token 留在容器配置内（日志已脱敏）。

发布资产完整性在刚装好的容器上直接核对：下载的 `meshlet-linux-x86_64.tar.gz` 哈希 `39852830b3d38e7e16a0ddcf706f0a0812329427b5fe0891056d85ce7f0c3fcd`，与已发布 `SHA256SUMS` 完全一致（`sha256sum -c` → `OK`）。压缩包内含 `install.sh`、`meshlet-agent`、`meshlet-cli`、`console/`、`systemd/`、`BUILD_INFO`。

已发布的 nightly agent 哈希为 `4845343087249b66`，即修复前的构建——验收用的二进制更新，这也是下面「升级与回滚」一节存在的理由。

## 三台真实设备

注册走的是真实 bootstrap 路径：`POST /networks/{net-1}/bootstrap-tokens` 带 `max_uses=1` 返回 token `bt-2`，恰好用一次。设备自注册为 `dev-reg-3`（名 `pve-dev-3`，平台 `linux`），agent 日志 `self-registered: waiting for approval in the control center`，随后 `registration pending approval: heartbeat sent, plan withheld`。批准返回 `virtual_ipv4 10.240.0.4`、`revision_id 4`、`apply_status pending`；随后 `POST …/config-revisions/4/apply`（200，`applied` 22:52:40Z），apply 后的首个 tick 以 `reason=NoLocalLedger` 应用计划。其间 503 `dataplane_not_configured` 在日志里带着 `retry_in_secs=2`，是指数退避的起点。

hub 侧随后有三个带 `/32` allowed-ips 的 peer 且握手新鲜，诊断读作 `3/3 device(s) with a handshake inside the 120s window`。三台设备的内核证据完全一致：`{"tunnel_mtu":1420,"nat_rules_present":false,"nat_snat_rules_present":false,"mtu_probe_payload":1392}`。库里的 token 记账：`bt-1` 用了 2/5（共享），`bt-2` 用了 1/1（已耗尽），只存摘要——没有任何原文入库。

## 备份与恢复

`POST /api/v1/system/backup` 产出 385024 字节工件，回报 `networks=1 devices=2 routes=0 invites=0 revisions=3`。该工件是**明文 SQLite 数据库**，`0600 meshlet:meshlet`，位于 `750` 目录内。这是刻意的口径，见[备份恢复](/zh/architecture/backup-restore.md)：文件不加密，等同于数据库本体，出机前一律 `0600`；hub 的 WireGuard 密钥在 `/etc/meshlet/hub.key`（`0600`，45 字节），**不在库内**，所以恢复数据库并不会恢复传输密钥，必须另有独立密钥备份。

文档给的顺序实测通过且本轮修好了：停服务、`meshlet-server restore <backup> <config>`、再启动。恢复回报 `networks=1 devices=2 routes=0 invites=0 revisions=3` 与 `system.restore recorded`；恢复出的 `meshlet.db` 是 `0600 meshlet:meshlet`——本轮修复前，root 执行的恢复会把文件变成 `root:root`，非特权服务随即 crash-loop（`unable to open database file`）。修复后服务 `active` 且 `NRestarts=0`、`{"status":"ok"}`。业务状态全部存活（设备、修订、bootstrap token），`system.restore` 审计行带源路径；恢复前的会话 cookie 仍能通过鉴权（`GET /auth/me` 200），因为会话随库一起备份；hub 从恢复的记录里重建了两个 peer；`restore-tmp` 暂存文件无残留。

负例：同一备份请求缺 `x-requested-with` 时拒绝，`403 {"error":{"code":"forbidden","message":"mutating console requests must set X-Requested-With"}}`。

**服务器运行中做恢复并不安全，本轮已证实机理。** 在服务运行中执行恢复会把新文件 rename 到 `meshlet.db`，而服务进程仍握着旧 inode：服务保持 `active`，但此后每一次写入——包括一次返回 HTTP 201 的 bootstrap token 铸造——都落到了已脱链的 inode 上，从不出现在磁盘库中；重启服务后才重新采用恢复出的文件。文档给的操作顺序是先停服务，这个顺序必须保留。

## 密钥轮换与密钥丢失

hub 密钥是服务器唯一持有的传输秘密；设备密钥留在设备上（ADR-010），设备侧轮换就是上方已走过的重新入网流程。

独立密钥备份：轮换**之前**把 hub 密钥（`0600 meshlet:meshlet`，45 字节）复制到 `/root/meshlet-key-backup/hub.key.20261023T225729Z`，目录 `700`。轮换即 `wg genkey` 写入同一路径、重设权限、重启服务：hub 公钥从 `S7HIikdT8Xvkb78fDOi5HlP6f5RAC7m0QcCkw6R9XQs=` 变为 `mUEmAMp/yLpIgquw1px7OVLcVkS1sWzbFr0D6+ie7Vg=`。

设备侧零接触：**重启后 45 秒，三台容器已经全部 peer 到新 hub 公钥且握手新鲜（25–40 秒前）**。服务器在每台设备的期望计划里下发 hub 公钥，agent 在下一个 30 秒 tick 自行更新 peer，日志 `applied the desired device plan … reason=DesiredConfigChanged`。未做任何设备侧操作。诊断读作 `3/3 device(s) with a handshake inside the 120s window`，到三个 overlay 地址的 ping 零丢包。

密钥丢失与既定口径：删掉 `hub.key` 后重启，服务**没有**停下——保持 `active`、控制面照常应答，同时记 `{"level":"ERROR","message":"hub recovery failed","network_id":"net-1","error":"read private_key_file /etc/meshlet/hub.key: No such file or directory (os error 2)"}`。也就是隧道侧已死而控制台还能用，安静得足以让人漏掉这一行。从独立备份恢复密钥并重启后隧道即恢复，设备侧零动作（三次 ping 零丢包）。注意这个备份实际恢复的是什么：它存的是**轮换前**的密钥 `S7HIikdT8Xvkb78fDOi5HlP6f5RAC7m0QcCkw6R9XQs=`，所以恢复它等于**撤销**了轮换，设备也跟随回到旧密钥——一次成功的轮换应当被当成一次需要备份的变更，而不是一项既成事实。

一处如实记录的缺口：密钥丢失不会让服务变不健康，只看 `systemctl` 的部署发现不了。

## 升级与回滚

在本席位上回滚到**已发布的旧 tag** 目前做不到：release 页只有一个滚动 `nightly`（2026-10-17），因为 nightly 构建被本轮修掉的工具链错配打断，从未发布过带日期的 release。因此升级与回滚的证据在新容器上按以下口径执行：**同一角色重跑即为原地升级**（配置、私钥与状态目录均保留），**回滚走文档化的离线/分阶段安装**（`MESHLET_INSTALL_ARCHIVE` + `MESHLET_INSTALL_SHA256SUMS`）指向上一版压缩包。

## 性能基线

进程内 handler 基线（文件库与内存库、并发 1/16/64/256、内存占用）见[性能](/zh/architecture/performance.md)；那是内部驱动器、不含 TCP/TLS，不构成容量承诺。针对 hub 容器上**正在运行的**服务、走真实 socket 的结果：

| 路径 | 形态 | 结果 |
|---|---|---|
| `GET /system/status`（公开，不碰库） | 200 串行 | 126 req/s |
| `GET /system/status` | 8 并发 × 100 | 261 req/s |
| `GET /networks`（会话 + 1 次库读） | 100 串行 | 130 req/s |
| `POST /system/backup`（会话 + `VACUUM INTO`） | 20 串行 | 63 req/s |

每轮都 fork 一个全新的 `curl` 进程，所以这些是受客户端进程启动约束的下限，不是服务上限；backup 路径主要由每次真实的 `VACUUM INTO` 决定（累计 23 份工件）。这台机器上的服务离能承受的负载还很远。

## 本轮发现并修复的缺陷

- agent 的 MTU 对账把「未配置」当「不动接口」，导致停在更高 MTU 的接口永不收敛。现按显式值同等强制，并与同一默认值读回比对；证据见 [R-04](/zh/implementation/r04-linux-agent-e2e.md)。
- root 执行的恢复把库留给 root 所有，导致非特权服务 crash-loop；现恢复原归属（被替换的文件优先，其次数据目录），并清理残留的 `-wal`/`-shm`。
- install.sh 的 apt 行往容器里塞 100+ MB 内核镜像；现改为 `--no-install-recommends`。
- README 一行式假定存在 `curl` 与 `sudo`，原版最小 Debian 容器两者皆无；现已补前置条件。
- nightly 工作流的构建步骤钉了 `stable`，而 `rust-toolchain.toml` 钉 1.99.0，自钉工具链起每次构建都因 E0463 失败；工作流现改用钉定版本。这也是 release 页仍停在 2026-10-17、且没有任何带日期 release 的原因。

## 未验收的部分

- Windows 客户端：本席位无 Windows 真机，R-05 保持未勾。仅 `x86_64-pc-windows-msvc` 的 check/clippy 为绿，仅此而已。
- 长期稳定性浸泡：本轮是数小时量级，不是数周。没有多日的持续流量观察。
- LAN 路由、别名映射、NAT 与网关 agent 仅以「缺席」形式（诊断里的 `not_applicable`/`unavailable`）验证，未在真实网关上做正向验证。
- hub 的 MTU 跟随已 apply 的修订，设备 MTU 跟随实时配置，所以改 MTU 后 hub 停在 1420、设备已到 1480，直到新修订立账并 apply；记录见 [R-04](/zh/implementation/r04-linux-agent-e2e.md)。
