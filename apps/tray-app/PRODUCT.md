# Product

<!-- impeccable:product-schema 1 -->

## Platform

adaptive

> 桌面双平台：Windows 托盘 + macOS 菜单栏，形态按各自系统惯例分别设计（用户 2026-11-03 确认）。
> 非移动端；本项目的 ios.md / android.md 参考不适用，不加载。

## Users

个人多机 / HomeLab 自建组网的机主：自己拥有并管理自己的 VPS 与节点，需要跨地域访问自己的服务、让自己的机器互相可达。属于「自己管自己的基础设施」的使用者，不是被运维的普通终端用户。

## Product Purpose

meshlet agent 的托盘常驻面，让用户**不必打开设置窗**就能完成两件事：

1. 一眼知道当前网络的在线 / 掉线状态（用户指定表达方式：**图标颜色**）；
2. 一步到达常用页（诊断、路由表、对等节点）。

成功 = 扫一眼托盘即可判断网络是否正常；失败 = 必须打开设置窗才知道连没连上。

## Positioning

基于自有 VPS 的自托管私人虚拟网络 —— Rust + WireGuard（README 原文）。托盘面承载的是「我自己的网络，我一眼要知道它活着」，而非面向被管理终端用户的上网工具。

## Operating Context

- 应用形态：Tauri 托盘应用，`apps/tray-app/`（Rust 壳 `src-tauri/` + webview 设置窗 `index.html`）。
- 托盘现状：菜单**只有 2 项** —— `打开设置` / `退出`（`apps/tray-app/src-tauri/src/main.rs:307-309`）。
- 图标机制现状：`main.rs:365` 已有 `tray.set_icon(...)` 运行时换图标能力；2026-11-03 图标方案已替换为四态（用户批准）：`icons/icon-online.png`（青实心六边形+中心孔）、`icon-degraded.png`（铜削角）、`icon-offline.png`（灰空心环）、`icon-error.png`（红挖空感叹号）、`icon.png`/`icon.ico`（默认铜色实心）。
- 设置窗现状：`index.html` 591 行，4 个分区 —— Connection（连接信息 / Hub 配置 / Peers）、诊断（Route table / Interfaces / WireGuard peers）、命令、常规（autostart）。
- 发布：nightly 每日构建产出 Windows agent+CLI zip 与 `install.ps1`；README 明示 **托盘宿主真机验收仍待完成（R-05）**。
- 平台可得性：本机为 Linux headless，**无法截取真实 Windows 托盘与 macOS 菜单栏的现状图**；Windows 实机 `openclaw` 当前离线（No route to host）；macOS 无可用实机。

## Capabilities and Constraints

已确认的托盘能力（用户 2026-11-03）：

1. **图标颜色表达在线 / 掉线状态**——环境态、常驻、零操作成本；
2. **菜单做常用页直达**——诊断、路由表、对等节点的快捷入口；
3. Windows 托盘与 macOS 菜单栏**都要出原型，且形态按各自系统惯例分别设计**（不是同一套外观硬套）；
4. 设置窗既有 4 区功能面保持不变（本轮只做托盘展示的重设计，不改产品功能）。

技术约束：

- 托盘菜单由 **OS 原生渲染**（Tauri `Menu`/`MenuItem`），视觉自由度限于：图标本身、菜单项结构与分组、文案、分隔线、（Windows 支持的）菜单项图标；**不能像网页那样自由排版**。要得到富视觉状态面板，需要另行引入自定义弹出窗口——这是尚未决定的产品事实，记为 open decision。
- 状态表达的派生要求（从「靠图标颜色判断」直接推出，非用户原话）：图标须**在深浅两种系统背景上都可读**，且**不能只依赖颜色**（色盲可用性 + Windows 深浅任务栏），需要形状 / 徽标冗余。

Open decisions（不代为决定）：

- 是否引入自定义弹出面板（而非纯原生菜单）承载更丰富的状态与图表；
- 状态语义的具体档位数（除在线 / 掉线外是否需要「连接中」「异常」）。

## Brand Commitments

- Logo 资产归用户所有，**不得自行替换或生成代餐**（`logo.svg`、`logo-copper.svg`、`logo-teal.svg`）。
- 已知品牌配色线索：README 徽章载明 `logo-B amber copper #C97B2E`；图标资源现存 copper / teal / gray 三色。配色决策留给 new-work，此处仅记录既有资产事实。

## Evidence on Hand

- 托盘四态图标的整体预览图已归档到 `docs/public/tray-icon-preview.png`（自 `apps/tray-app/ICON_PREVIEW.png` 迁入，2026-11-03 托盘重设计落地）。
- 仓内截图 `docs/public/toggles/*.png` 与 `docs/.vitepress/dist/**` 是 **console 界面**的开关截图，**与托盘无关**。
- **缺失且未来工作不得编造**：托盘菜单与设置窗的现状实拍图（见 Operating Context 的平台可得性）——原型阶段的「前图」只能基于源码结构描述，必须在交付时明确标注这一点。

## Product Principles

1. 状态优先于操作：环境态放图标，交互态放菜单，两者分工而非并列（避免出现第二个「状态权威位」）。
2. 一步可达：托盘的一切入口以「单击一次」为上限，详情才进设置窗。
3. 形态服从系统：Windows 与 macOS 各按其系统惯例，不强行统一外观。
4. 资产不动：logo 与既有图标资源由用户提供，设计只做编排与状态扩展。
5. 诚实标注不可得证据：拿不到实拍图就明说，不用臆造的「现状图」充当对比基线。

## Accessibility & Inclusion

- 状态判定不得只依赖颜色，需要形状 / 徽标冗余（色盲与深浅任务栏场景）。
- 图标须在系统深色与浅色任务栏 / 菜单栏背景下都保持可辨。
