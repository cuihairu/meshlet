# ADR-008 复审：数据面切 wireguard-nt 嵌入式绑定——PoC 判定

日期：2026-11-21。性质：对 [ADR-008](/decisions/adr-008-windows-network-backend)
的复审推进（承 [v1 gate](/decisions/2026-11-09-adr-008-windows-v1-gate)）。
触发：用户令 2026-11-21「赶紧推进 切到 wireguard-nt」；依据
[userspace-wireguard-analysis.md](/design/userspace-wireguard-analysis.md)
（1bcb538）。结论：**现模型（wireguard.exe 隧道服务）的两个结构性缺陷
已在真机实锤；目标模型（wireguard-nt 一网络一 adapter）双 adapter PoC
真机 8/8 PASS——方向可行，进入 backend 接线批；现网三台仍跑服务模型，
部署切换等用户点头。**

证据全录：[wgnt-step12-2026-11-21](/acceptance-evidence/wgnt-step12-2026-11-21)。

## 现模型缺陷实锤（此前为分析推测，现为真机证据）

- **§1.2 服务单例互踩**（imac 2026-11-21）：同名 conf 经
  `installtunnelservice` 后装快照整体顶掉运行时——4-peer 运行时表蒸发、
  假 peer 注入、handshake 从零、PathName 无校验换目录。服务承载=最后
  一次 install 的 conf 快照，direct peers（`wg set` 运行时态）不在其内。
- **§2.5 51820 撞绑**（imac 同日，事故副产品）：不同名第二隧道实例实占
  UDP 51820 → 原服务 STOPPED（WIN32_EXIT_CODE 32）——比分析预设的
  「同名才撞」更广，端口是机器级资源。openclaw 侧 wg-newapi 并存可用
  反证共存前提=名字不同且端口不撞。
- 机制补充（真机实测）：对已存在同名服务 install 被静默拒（exit=0，
  GUI 框不可见）——agent install_plan 先 uninstall 再 install 的语义
  实证正确；SSH 会话令牌 install 被静默拒，须 SYSTEM 分离执行。

## 目标模型 PoC 判定（8/8 PASS，imac 提权）

单进程双 adapter（wg-mlt-a/wg-mlt-b，wireguard-nt crate
`Adapter::create`）四条验收断言全过：①`sc query
WireGuardTunnel$wg-mlt-a`→1060（不经 Windows 服务，§1.2 根因不存在）
②netstat 51821/51822 两端口共存（每 adapter 独立 listen_port）③A 的
peer 表在 B 配置后不变 ④两 overlay 双向通包（handshake+rx_bytes+ping
TTL）。增设：get_config 读回一致；`listen_port: None` 落 OS 随机 62642
（实证 None 不可规划，计划层 `nt_listen_port` None 拒的设计依据成立）。
退出 Drop→CloseAdapter 清理零残留。

**实证口径**：PoC 与 main 骨架（65af1e6）用同一 crates.io crate
`wireguard-nt = "0.5.0"`（`load_from_path`/`Adapter`/`SetInterface`/
`SetPeer`）——不是手写 FFI；staged dll 为官方 wireguard-nt 1.1 amd64
（driver version 65537），binding 0.5.0 × dll 1.1 组合真机可行。

## 前提修正（PoC 产生的新事实，接线批必须吸收）

1. **官方 WireGuard for Windows 安装不含 wireguard.dll**（只有
   wg.exe/wireguard.exe，tunnel 服务静态链在 exe 内）——dll 必须随
   meshlet 分发（打包 wireguard-nt 1.1 amd64 dll 进 MSI/zip，
   SHA256 b1b85e07…校验），不能依赖用户已装的 WireGuard。
2. agent 进程内直接持有 adapter（crate API），**无 wireguard.exe 服务
   中介**——v1 gate 遗留的 elevation 模型问题（D1 的 (a) runas 点提权
   vs (b) 服务承载）在 nt 模型下重述为：agent 进程需提权调 adapter
   API，服务模型的大量 sc/wireguard.exe 编排面消失；reboot recovery
   语义变化（adapter 随进程消失，无服务自启面）——接线批设计点。
3. 多网络端口规划：per-network 显式 listen_port 是硬前提（None 实证
   落 OS 随机），需要 server 侧端口分配或本机确定性分配策略——接线批
   设计点。

## 未完成（backend 接线批范围，勿在本复审外预支）

- `windows_wireguard_nt.rs` cfg(windows) 执行层（计划层已就绪：406 行
  中性结构+9 单测，65af1e6）。
- 数据面 backend 切换：windows_tunnel.rs（1105 行服务模型）→ nt
  adapter 模型；与 install_plan/reconcile/自愈轮的对接。
- dll 分发打包 + 安装链路（MSI/zip/deploy 三形态）。
- 切换的回滚路径与现网灰度（三台现网 imac/openclaw/cuihaitao 仍跑
  服务模型；**部署切换等用户点头**，与 PoC 同口径）。
- ADR-008 七项验收面对 nt 模型重跑（installation/repeated apply/
  partial failure/uninstall/route cleanup/reboot recovery——reboot 面
  语义变化最大）。
