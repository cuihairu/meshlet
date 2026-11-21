# wireguard-nt `private_key: None` 驱动语义锚定 PoC（2026-11-21）

任务书 meshlet-wireguard-nt-switch 禁区条款：`SetInterface.private_key: None`
的驱动语义（保留 vs 清空）执行层落地后、backend 分派前必须真机锚定。
执行层已落 main（e373277），本 PoC 在 imac 真机提权完成锚定。

机器：imac（192.168.5.117，Windows，生产隧道 wg-meshlet / VIP
10.240.0.7）。窗口 2026-11-21 14:39–14:44 (+08)。PoC 用独立 adapter
`wg-mlt-anchor` + 独立端口 51823，**零接触生产隧道**（生产仍
WireGuardTunnel$wg-meshlet 服务模型 RUNNING）。

PoC exe：`wg-nt-anchor`（独立构建，非仓库内依赖——wireguard-nt 0.5.0
同 crate 组合；exe SHA256 前 16 位 FEAB53DB3E939201 最终版，初版
E6B63AFD…）。执行方式：schtasks SYSTEM 分离（任务 MeshletWgNtAnchor，
同 wgnt-step3 PoC 先例）；dll 官方 wireguard-nt 1.1 amd64（SHA256
b1b85e07…，与 ADR-008 同物料）。

## 锚定方法（单 adapter 三段 set_config，确定性密钥）

- **A 基线**：`set_config(private_key=Some(K1))` + `up()` → `get_config()`
  回读，期望=clamp(K1)（RFC 7748 X25519 scalar clamping）；
- **B 锚定**：`set_config(private_key=None)` → 回读，判据=与 A 回读
  **逐字节一致**（驱动保留现有私钥）；若=全零即「驱动清空」（契约
  不成立）；
- **C 对照**：`set_config(private_key=Some(K2))` → 回读=clamp(K2)
  （读回链路对 Some 敏感，排除「回读恒旧值」伪 PASS）；
- **D 边界**：`sc query WireGuardTunnel$wg-mlt-anchor` → 1060（不经
  Windows 服务）。

K1=[0x07;32]、K2=[0x11;32]（确定性字节，非密钥学用途，只验证驱动
字节保留行为）。

## 实录（C:\Users\cui\wgnt\wgnt-anchor-stdout.txt，2026-11-21T14:42:51+08）

```
dll = C:\Users\cui\wgnt\wireguard.dll
adapter = wg-mlt-anchor port = 51823 (explicit)
wireguard.dll loaded, driver version = 65537
[PASS] assertA-baseline-some-key-writes - set Some(K1) -> readback 00070707 (expect clamped 07070707 = 00070707 - rfc7748)
[PASS] assertB-none-key-preserves - set None -> readback 00070707 (clamped K1=00070707 zeroed=false verdict=PRESERVED (crate flag semantics hold))
[PASS] assertC-control-k2-reads-back - set Some(K2) -> readback 10111111 (expect clamped 11111111 = 10111111 - rfc7748)
[PASS] assertD-no-tunnel-service - sc query WireGuardTunnel$wg-mlt-anchor exit=Some(1060) (expect 1060)

=== summary: 4/4 PASS ===
adapter cleanup on exit (Drop -> WireGuardCloseAdapter)...
```

driver 包裹 exit=0（初版 exit=1：A/C 断言误写为逐字节==原字节，未计
clamping——B 的核心锚定已成立，修正后复跑 4/4 PASS）。

## 判定

1. **`None` → 驱动保留现有私钥（不清空）**：B 回读 `00070707` 与 A 回读
   **逐字节一致**，非全零非随机——与 crate `set_config` 源码按位 flag
   语义（`None` → `HAS_PRIVATE_KEY` 位不设 → 驱动不动私钥）**真机互证**。
   todo 禁区条款满足；执行层 `nt_apply_spec` 的 `None → None` 透传契约
   成立，backend 分派可依赖幂等重应用语义。
2. **RFC 7748 clamping 新事实**：驱动存储私钥时做 scalar clamping
   （`k[0] &= 248`；K1 首字节 07→00、K2 首字节 11→10，`&248` 精确吻合；
   31 字节位不在 hex 前缀窗口）。读回私钥是 clamped 字节，**非原字节**
   ——诊断面比较密钥时必须 clamp 后再比（本批执行层读回面后续接线注意；
   `wg` 同构，非驱动异常）。
3. **C 对照成立**：读回对 Some 敏感（clamp(K1)=00070707… ≠
   clamp(K2)=10111111…），B 的「一致」非恒值伪影。
4. **D 边界**：无 WireGuardTunnel$ 服务（1060）——服务单例根因不存在，
   Step 3 PoC 断言①同源复核。
5. **零残留**：Drop → WireGuardCloseAdapter，`Get-NetAdapter` 无
   wg-mlt-anchor；机上实验文件与 schtasks 任务全清。

## 生产终态（14:4x 取证）

```
STATE : 4 RUNNING
live peers: 3 (hub vLkJ… + b6txQ61… + FSaf/1S…)
ping hub: 8ms / 8ms
no wg-mlt-anchor adapters
```

qaa2 不在 peer 表（上批 11:4x 终态 4 peers 含 qaa2）——本 PoC **零接触
生产隧道**（独立名+独立端口），该变化按服务端计划由 agent 自愈轮
reconcile 管理（hub 8ms 通、隧道 RUNNING、自愈轮 ~30s 周期补齐计划内
direct peers），非本实验所致。实验残留全清（含上批遗漏的
wgnt-step1-out.txt 一并删除）。

## 过程备注

- 首跑发现 clamping 后，A/C 断言修正为 clamp 期望复跑；B 锚定首跑与
  复跑结论一致（PRESERVED），判定不依赖修正（修正只影响 A/C 自检）。
- 端口 51823 独立于生产 51820 与 wgnt-step3 PoC 的 51821/51822。
