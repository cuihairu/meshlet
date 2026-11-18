# tray-app 单实例防护验收证据（2026-11-19）

任务单 meshlet-tray-singleton（用户亲报 2026-11-18：「meshlet 本地居然可以运行多个 tray」）。

## 根因

`apps/tray-app/src-tauri/src/main.rs` 的 tauri Builder 未接单实例插件，Cargo.toml 无
`tauri-plugin-single-instance` 依赖：每次启动都是全新进程——新托盘图标+新窗口+各自
轮询 agent（状态面互相覆盖、菜单操作打到随机实例）。

## 修复（commit 待补：本证据随收口 commit 落库）

- `Cargo.toml`：`tauri-plugin-single-instance = "2"`（解析为 2.5.5），`[dev-dependencies]`
  加 `tauri = { version = "2", features = ["test"] }`（契约测试用 MockRuntime，平台无关）。
- `main.rs`：插件**第一个注册**（官方要求，deep-link 场景对注册顺序敏感）：

  ```rust
  .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
      second_instance_focus(app);
  }))
  ```

  回调体独立为 `second_instance_focus<R: Runtime>`（泛型以便 mock 测试走同一调用链），
  行为=`windows::open_settings_window`（既有 settings 窗 reveal：unminimize→show→focus；
  不存在则补建同 label 窗）。
- `windows.rs`：`reveal_window` / `open_settings_window` / `build_settings_window` 泛型化
  `<R: tauri::Runtime>`（调用点不变，Wry 推断）。
- 兼容现状：MSI（apps/cli/wix/main.wxs）只装 `meshlet-tray-host.exe`（apps/tray-host），
  **tray-app 不在 MSI 分发面**，MSI 升级对本修复无直接影响；wxs 仅有 MajorUpgrade、无任何
  停进程逻辑（taskkill/CloseApplication 零命中）——升级前 taskkill 旧实例检查项已记 todo。

## 门禁（全绿）

- `cargo test -p meshlet-tray`：**25 passed**（原 23 + 新 2 契约测试）
- `cargo clippy -p meshlet-tray --all-targets -- -D warnings`：净（宿主腿）
- `cargo clippy -p meshlet-tray --target x86_64-pc-windows-gnu --all-targets -- -D warnings`：
  净（windows-gnu 交叉腿，tray-app 双腿纪律）
- `cargo clippy --workspace --all-targets -- -D warnings`：0 error；`cargo fmt --all -- --check`：净

## 契约测试（MockRuntime，平台无关）

1. `second_instance_focus_reuses_existing_settings_window`：settings 窗已存在时回调走
   reveal 分支复用既有窗——`webview_windows()` 仍唯一且 label=settings（不新开第二扇窗）。
   注：MockRuntime 的 `is_visible()` 恒 `Ok(true)`（tauri-2.12.5 mock_runtime.rs:788），
   show/focus 腿在 mock 上不可观测，显示效果由全部打开路径共用的 reveal_window 兜底
   （该函数的 unminimize→show→focus 顺序有 tray-host 真机行为佐证，见 windows.rs 注释）。
2. `second_instance_focus_builds_settings_window_when_missing`：settings 窗缺失时回调补建
   同 label 窗（第二实例唤起的始终是同一个 label，不落孤儿窗口）。

## 端到端双开实测（本机 Linux，Xvfb :77 + dbus-run-session 真进程）

```
first_alive=yes          # 实例 1（release build target/release/meshlet-tray）存活
second_exit=0            # 实例 2 启动→通知实例 1→自身退出（exit 0）
first_still_alive=yes    # 实例 1 持续存活，锁未误释放
```

实例 1 日志无 error/panic（仅无头环境 libEGL DRI3 噪音）。这是单实例插件生效的进程级
完整证明：第二实例不再产生第二个托盘进程。

## 边界（如实）

- **托盘图标数的视觉面待用户亲验**（任务书原文口径）：Xvfb 无 StatusNotifier 托盘宿主、
  Windows 真机 SSH 属 session 0（tray-host 先例：NIM_ADD=0 托盘不可见，须 console 登录），
  两面都无法由 agent 截到托盘区截图；用户在任一有桌面的环境双开 `meshlet-tray` 应只见
  一个托盘图标、第二次启动唤起已有设置窗。
- 回调「显示并前置」的用户可见效果在无窗口管理器的 Xvfb 里不可截证，契约测试钉住调用
  链与窗口复用关系；真机视觉效果随用户亲验一并确认。
