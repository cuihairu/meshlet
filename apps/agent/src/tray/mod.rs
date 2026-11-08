//! 运行时系统托盘状态展示（用户 2026-10-16：「运行时需要显示对应的 icon 的吧」「系统托盘
//! icon 最好能体现状态变化」）。
//!
//! ## 纪律一：不新造状态名
//!
//! [`TrayState`] 的四态**逐一对应仓内已有枚举**，映射依据写在每个变体上：
//!
//! | 用户原话 | 托盘态 | 仓内已有枚举 |
//! |---|---|---|
//! | 在线直连 | [`TrayState::Online`] | [`meshlet_domain::presence::PresenceState::Online`] ＋ [`crate::reconcile::Reason::UpToDate`] |
//! | 中继中 | 同上 | v1 是 VPS 中心中继（ADR-002），**仓内没有「直连 / 中继」二值信号**，P2P 直连明确留 v2——所以「在线直连」与「中继中」在 v1 是**同一个真实状态**，本模块用一态表达，不伪造第二个 |
//! | 已断开 | [`TrayState::Offline`] | `PresenceState::Offline`（控制通道与隧道均无新鲜证据） |
//! | 隧道异常 | [`TrayState::TunnelDrift`] | [`crate::reconcile::Reason::KernelDrift`] ＋ [`meshlet_domain::entities::ApplyStatus::Failed`] |
//!
//! 中间还有一态 [`TrayState::TunnelOnly`] ← `PresenceState::TunnelOnly`（握手新鲜但
//! agent 上报过期）——这是仓内**真实存在**的三态之一，agent 侧对位是「本地能读到握手
//! 但心跳上报失败」，见 [`TrayState::derive`]。
//!
//! ## 纪律二/三：非静态、文本等价物、不靠颜色
//!
//! 状态变化即换图（[`TraySink::publish_with`] 内容相同则不重写，不同才落盘）；每态有
//! `tooltip`（整句说明）与 `accessible_name`（无障碍短名）。四态的**轮廓互不相同**
//! （2026-11 托盘重设计，用户批准的四态方案，设计源
//! [apps/tray-app/src-tauri/icons](../../tray-app/src-tauri/icons/)，commit `e9d67d4`）：
//! 六边形螺母 / 右缘削角螺母 / 空心六边环 / 挖空感叹号六边形——颜色只是第二通道，
//! [`tray_state_silhouettes_are_pairwise_distinct`] 用像素探针钉死这一条。
//!
//! ## 纪律四：headless / CI 必须 no-op
//!
//! [`EnvProbe::from_env`] 读出桌面会话环境，[`EnvProbe::has_desktop_session`] 为 false
//! （CI、无头 VPS）时 [`TraySink::publish_with`] 直接返回
//! [`TrayWrite::Skipped`]——不写任何文件、不 panic、不让 agent 起不来。桌面探测是**注入**
//! 的纯数据，测试不需要动进程环境变量。
//!
//! ## 素材与依赖纪律
//!
//! 图标是**简单自绘形状**，几何与色值逐项对齐已过审的四态 PNG 设计（32px 主图
//! `icon-{online,degraded,offline,error}.png` 的六边形语形＋`gen_icons.py` 的
//! 16px 可读性微调：offline 内孔放大、feather 收紧到 0.5px），不使用品牌 logo 代餐：
//! 仓内 [logo.svg](../../../logo.svg) 的主形是分层透镜多边形（`viewBox="0 0 1024 1024"`），
//! 细节在 16px 下会糊。状态信息由形状＋颜色双通道表达，渲染在 16/24px **原生 1:1**
//! 进行（不经过缩放，避免 gen_icons.py 记录的「32px 缩到 16px 内孔被抗锯齿残渣
//! 填塞」缺陷）。
//!
//! 不引入 GUI / 托盘 crate（`tray-icon`/`tao`/`winit` 全无）：托盘宿主由桌面壳按
//! [TraySink] 写出的 PNG 自行接入（面板插件、`notify-send` 脚本等）。PNG 用内置编码器
//! （stored deflate 块）生成，零新增依赖；[`png_roundtrip_decodes_the_same_pixels`]
//! 用「解码自己写出的流」验证输出可被通用解压器还原。
//!
//! ## 模块划分（LAY-017）
//!
//! - [`state`]：四态状态机（映射、文本等价物）——纯语义，无渲染；
//! - [`icon`]：图标渲染（轮廓几何＋调色板＋尺寸）；
//! - [`png`]：PNG 编码（stored deflate 块，零依赖编解码器）；
//! - [`env`]：桌面会话探测（注入式纯数据）；
//! - [`sink`]：托盘产物落盘（status.json + icon PNG，幂等发布）。

pub mod env;
pub mod icon;
pub mod png;
pub mod sink;
pub mod state;

pub use env::EnvProbe;
pub use icon::IconSize;
pub use png::png_encode;
pub use sink::{TraySink, TrayStatus, TrayWrite};
pub use state::TrayState;
