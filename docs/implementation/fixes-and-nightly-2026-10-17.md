# P0 修复与 nightly 实施记录（2026-10-17）

本页记录本轮工作区的实现与验证范围。历史结论仍保存在 [历史记录](history-2026-10-17.md)，本页不表示所有产品 TODO 已完成。

## 实现

| 范围 | 当前行为 | 代码与测试 |
|---|---|---|
| 修订一致性 | 只应用当前版本；旧 Pending/Applied 不能应用当前快照；重复旧 RolledBack 不改变新资源状态；Applying / RollbackPending 意图先于内核操作落库；落库失败不保留暂定成功状态 | `revision.rs`、`config_state.rs`；`revisions.rs` |
| 设备确认 | hub 成功、设备 ACK 与业务健康分开；版本和实际计划哈希必须匹配，资源等相关设备确认才 Applied | `convergence.rs`；`agent_plan.rs` |
| 多 Network | 独立接口和 UDP 端口；拒绝共享路由域的前缀歧义；hub filter 链拒绝跨网转发 | `revision.rs`、`linux.rs`；`single_instance.rs` |
| hub 恢复 | SQLite 保存公共成功计划，启动及每 30 秒检查内核并修复；恢复错误进入修订详情 | `convergence.rs`、`persist.rs`；`single_instance.rs` |
| 回滚 | 重放上一份成功计划并读回，恢复路由/Alias；首次失败只清理本网络，不扫描删除全机 NAT | `revision.rs`、`persist.rs`；`single_instance.rs` |
| NAT | DNAT-only 不要求 SNAT 地址；多个 LAN 逐规则解析；Direct controlled_snat 已进入计划；生产规则限定来源与入口 | `device_plan.rs`、`nat.rs`、`linux.rs`；真实内核测试 |
| agent 漂移 | 读回实际接口地址、UP/MTU、Peer/AllowedIPs、路由下一跳和逐条 NAT；局部 SNAT 丢失、关闭转发均重放 | `agent.rs`、`reconcile.rs`；`single_instance.rs` |
| 首次管理员 | 进程互斥 + SQLite 条件插入，只创建一个首任管理员和会话 | `auth.rs`；并发 bootstrap 回归 |
| 服务权限 | agent 直接继承 capabilities，不经 sudo；hub 用显式 drop-in，允许 Netlink，root pre-start 启用转发 | `deploy/systemd/`；隔离 netns 中实际非 root 服务验证 |
| 备份升级 | v8 备份在临时库升级到 v9、重建和校验后再换名；迁移失败不改活动库 | `persist.rs`；`backup.rs` |

设备计划的 `desired_config_hash` 现在是完整设备计划的 SHA-256，包含版本、MTU、hub 公钥和 NAT，区别于网络修订簿记哈希。服务端只存公共成功计划，私钥仍留在本机文件。

## 每日构建和安装

- `Nightly build` 每天 19:17 UTC（北京时间次日 03:17）运行，也支持手动触发。
- 发布依赖格式、Clippy、workspace 测试、控制台/文档构建和严格真实内核门禁。
- Linux x86_64 与 ARM64 使用 musl 静态构建，归档包含 server、agent、CLI、控制台、systemd 单元、安装脚本、LICENSE 和 BUILD_INFO。
- 同时发布滚动 `nightly` 和带日期的不可变预发布版本，提供 SHA256SUMS；`source_dirty` 标记本地工作区构建，CI 发布基于检出的提交。
- 安装脚本校验归档，创建专用用户、配置与密钥，安装并启动服务；重复执行保留已有配置、凭据和数据库。
- 中英文 README 已给服务端、agent、升级、版本定位和诊断教程。

工作流在默认分支首次成功运行后才会生成下载资产；首次成功发布前下载 URL 不会有资产。ARM64 runner 标签依据 [GitHub 官方 runner 文档](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)。

## 验证证据与边界

- `single_instance.rs`：一个服务端、同一 hub netns 同时管理两个网络。验证各自互通、恶意客户端添加跨网 AllowedIPs/路由仍拒绝、重应用不破坏另一网络、删除 hub 接口后由正式恢复协调器从数据库恢复、旧库无 journal 时重建成功计划、失败应用回滚、两 LAN 的独立 SNAT、仅 DNAT、局部 NAT 丢失和关闭转发后的恢复。
- `dual_site_end_to_end.rs`：保留双站点相同真实网段经不同 Alias 访问的真实 HTTP + agent 路径；历史双实例拓扑不再当作单实例隔离证据。
- `agent_plan.rs`：精确 ACK、等待、失败、旧版本/错误哈希拒绝，状态更新不改变候选计划哈希。
- `revisions.rs` / `auth_console.rs`：旧修订拒绝、幂等、并发首次引导单胜。
- `backup.rs`：v8 备份升级、迁移失败保护活动库。首次 Windows CI 暴露迁移错误路径中连接池异步释放导致清理文件失败；`store::connect` 现显式等待关闭连接池后返回迁移错误，Windows 回归结果以最新 CI 为准。
- `scripts/verify-systemd.py` 使用正式 server unit 与 drop-in，以 uid 65534 在独立 netns 实际运行，读取 0600 私钥、创建 WireGuard、配置转发/防火墙并持久化成功状态；测试后服务、命名空间和目录已清理。这不替代空 VPS 的公网安装走查。
- 本地 x86_64 musl release 构建和归档检查已完成；控制台、VitePress、ShellCheck、actionlint、Clippy 已通过。最终 `MESHLET_REQUIRE_DATAPLANE=1 cargo test --locked --workspace -- --test-threads=1` 通过：381 passed / 0 failed / 0 ignored，0 SKIP。

尚未完成：默认分支上的真实 nightly 发布、ARM64 实际构建、空 VPS 下载与安装、Windows / 手机数据面验收，以及当前执行清单中的后续 PN / MOD 功能。业务可达性未探测时仍显示 `not_probed`。
