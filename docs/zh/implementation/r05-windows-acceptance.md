# R-05：Windows 数据面真机验收记录

本页**只转录已记录的真实证据**：R-05 Windows 数据面子项（路由、防火墙、
服务、卸载清理）于 2026-10-25/26 在中文 Windows Server 2022 真机上验收的
记录。本页不含任何新测的数值或结论。R-05 父项保持未勾：三项真机缺项仍在，
见[仍未验收](#仍未验收)。

来源：`TODO.md` R-05 数据面子项（2026-10-25/26 记录）与
`crates/meshlet-network/src/windows_*.rs` 模块头注。

## 机器与工具链（照记录转录）

- 真机：中文 Windows Server 2022（本机），2026-10-25 与 2026-10-26 两轮。
- 工具链：GNU，`stable-x86_64-pc-windows-gnu` —— 全 workspace `cargo test`
  与 `cargo clippy --workspace --all-targets -- -D warnings` 均 exit 0。
- CI：`.github/workflows/ci.yml` 矩阵 `os: [ubuntu-latest, windows-latest]`
  在 windows-latest 上原生跑 `cargo test --workspace`，`clippy -D warnings`
  同样原生跑。

## 本地化根因与修复

netsh / sc.exe 的**重定向输出是活动代码页编码，不是 UTF-8**。真机字节：
netsh 删除不存在路由返回 `D5 D2 B2 BB B5 BD D4 AA CB D8 A1 A3`（
「找不到元素。」的 GBK 编码）。执行层此前用 `String::from_utf8_lossy`
解码，中文全部丢失为 U+FFFD，本地化幂等删除文案的匹配全部失效——由
`windows_netsh` 真机集成测试抓到。

记录的修复：新增 `windows_console` —— UTF-8 优先（合法 UTF-8 原样通过），
非 UTF-8 用 `MultiByteToWideChar(CP_ACP)` 解码（windows-sys 已有依赖，加
`Win32_Globalization`）。纪律：绝不 panic、绝不返回空文本伪装成功（§10.3）。

## 分类器匹配的真机报文（原文）

| 面 | 报文（zh-CN，CP936 解码后） | 分类 |
|---|---|---|
| 路由缺失 | `找不到元素。` | 路由删除幂等成功 |
| sc 服务不存在 | `指定的服务未安装。`（退出码 1060） | 服务 stop/delete 幂等成功 |
| sc 服务从未启动 | `服务尚未启动。`（退出码 1062） | 服务 stop 幂等成功 |
| 防火墙规则缺失 | `没有与指定标准相匹配的规则。` | 规则删除幂等成功 |
| 需要提升 | `请求的操作需要提升(作为管理员运行)。` | `InsufficientPrivileges` |
| 拒绝访问 | `拒绝访问。` | `InsufficientPrivileges` |

真机新发现：从未启动的服务 `sc stop` 返回 1062「服务尚未启动。」——Stop
的目标状态是「已停止」，未运行即已达成；记为幂等成功（退出码 1060/1062
与文案匹配双通道）。

## 各模块验证状态（照模块头注转录）

- **`windows_routes`** —— 执行层真机验证 2026-10-16（CI runner，en-US）
  与 2026-10-26（中文 Windows Server）：add / show 读回 / delete / 幂等
  re-delete 全链路走通。
- **`windows_firewall`** —— 执行层真机验证 2026-10-26：add / show 读回 /
  delete / 幂等 re-delete。
- **`windows_service`** —— 执行层真机验证 2026-10-26：create / stop（含
  从未启动的 1062 幂等）/ delete / re-delete（1060 幂等）。
- **`windows_cleanup`** —— 只有计划层；执行复用三个已验证的 exec 薄封装。
  卸载链重入集成测试 `windows_cleanup_e2e` 2026-10-26 真机闭环：服务
  create→stop→delete→re-delete、防火墙 add→show→delete→re-delete、空态
  `CleanupPlan` 全步幂等。
- **`windows_elevation`** —— 计划层（受管 `.exe` 路径校验、`runas` 命令行
  转义、错误码/文案 → `InsufficientPrivileges`）全平台编译 + 单测（66
  通过）；`#[cfg(windows)]` 执行层（ShellExecuteW `runas` + TokenElevation
  查询）已过 `x86_64-pc-windows-msvc` clippy/check。**从未在真机 Windows
  上实测** —— 不得接为 `SystemBackend`。
- **`windows_tunnel`**（2026-10-27）—— WireGuardNT 计划层（conf 渲染、
  安装/卸载 argv、幂等 re-apply、失败分类）+ `#[cfg(windows)]` 执行层原语
  落地；文件级 `tests/windows_tunnel.rs` 由 CI windows-latest 真跑。真机
  隧道生命周期仍缺（见下）。
- **`windows_console`** —— 共享解码器；真机 GBK 字节固定为测试常量。

## 测试证据（照记录转录，验收快照）

- `meshlet-network`：**75 单测 + 3 真机集成**全绿（2026-10-25/26 快照；
  此后 crate 随隧道计划层继续增长）。
- `stable-x86_64-pc-windows-gnu` 上全 workspace `cargo test` 与 clippy：
  exit 0。
- CI windows-latest 原生跑 `cargo test --workspace`。
- `windows_netsh` 原失败用例（幂等 re-delete）在 CP936 修复后转绿。

## 仍未验收

以下三项保持 BLOCKED，也是 R-05 不勾的原因。**win-worker 已永久停用；
补齐需要用户手动提供可重启的 Windows 真机。**

1. **WireGuardNT 隧道全生命周期** —— 安装 WireGuardNT 驱动后在真机跑
   install → start → stop → uninstall。
2. **提权执行层真机运行** —— `windows_elevation` 执行路径从未在真机
   Windows 上执行过。
3. **开机恢复重启验证** —— 重启并确认隧道/路由/防火墙状态恢复。
4. **#52 `SystemBackend` 接线决策** —— 有意等 1–3 验收后再定；在此之前
   Windows 保持 [unsupported] 显式占位，任何数据面操作绝不假装生效
   （§10.3、§12.2）。
