# meshlet console 界面审核 · 2026-10-31（impeccable 技能）

> 对象：`console/`（React 19 + Vite 8 + antd v6，按功能域重构后：网络/准入/设备/诊断 4 路由域 + 登录 + 空/加载态，桌面与窄屏两档）。
> 方法：impeccable 的 audit/critique playbook（a11y / 性能 / 主题 / 响应式 / 实现完整性 + Nielsen 10 启发式 + Design Specificity 判定）。真实渲染截图，非静态走查。
> 边界：不动 logo 与品牌绿 accent；不 bump version；vitest 全绿门禁。
> 截图目录：逐页证据见 `2026-10-31-ui-audit-impeccable/shots/`；4 个已修问题的 before/after 同视图成对截图见 `shots-before/` 与 `shots-after/`（文件名按问题编号对齐）。

## 整体印象（critique，不留情面）

这套 console 是**一款有产品判断力的运维工具，不是装饰性仪表盘**。它的骨架是对的：深色瑞士极简、全宽 fluid 布局、状态点必须说明来源（presence_source）、诊断页"不可用 ≠ 通过"的诚实标注、冲突卡片给出恢复路径、设备表 `direct_links ?? []` 的版本错位容忍——这些是好产品的本能，不是 UI 模板堆出来的。品牌绿 accent 用在正确的地方（导航激活、按钮、焦点、冲突虚线框）。

但它有**一批明确的工艺漏洞**，按"运维人员出事时会怎么抓狂"排序：

1. **一个缺失 API 字段就能让设备页白屏**。`d.direct_links.length` 没有防御——旧服务器（Oct 20 二进制）省略该字段，整张表崩成空白页。管理后台在故障排查时最不能白屏。
2. **焦点环不可见**——最基础的键盘可达性 affordance 被 antd cssinjs 的 `colorPrimaryBg` 盖掉了，键盘用户几乎看不见自己在哪。这不是"待优化"，是"基本功能缺失"。
3. **浅色主题两处真实 WCAG AA 失败**：状态标签 2.2:1、激活导航 2.78:1、主按钮 3.32:1。品牌绿 accent 让这些对比度问题容易被"看起来还行"糊弄过去，但 AA 是硬线。
4. **窄屏把宽表挤成字堆**。"device-reg-1"折成三行、时间戳折成两行——390px 下表格直接不可读。
5. **首屏体验**：4 个路由域里 3 个在没手动选网络时是死胡同空态，用户第一反应是"坏了？"。网络选择不持久化、不自动选第一个。
6. **标题层级从 h3 起跳**，没有页面级标题——屏幕阅读器用户拿不到文档结构。
7. 小但真实的：一处硬编码英文破坏 i18n、冲突卡片左侧 4px 强调边（检测器 AI-slop tell）、登录页无品牌标识、品牌绿浅色对比度（边界约束未修，需决策）。

一句话：**底子好，但距离"打磨完成"还差一轮 a11y + 窄屏 + 首屏的硬功夫。** 下面按严重度列。

## 审核方法

- 本地环境：systemd `meshlet-server :8080` + vite dev `:5173`（`/api` 代理到 :8080），本地 admin bootstrap（凭证见 `~/.hermes/cache/scratch/mlt-reset.sh`，勿外传/不入库）。
- 截图：Playwright 1.63.0（chromium r1243），强制暗/亮双主题，26 张 PNG 全量，13 张精选 JPEG 入 `2026-10-31-ui-audit-impeccable/shots/`。before/after 对在独立 worktree（`30d530c^` 修复前代码，dev server :5175）重渲染，同视图、同视口、同主题。
- 版本错位：运行中 systemd 二进制（Oct 20）早于 `direct_links` 字段（当前源码总是下发）——这个时间差暴露了真实崩溃。
- DESIGN.md / PRODUCT.md：**仓内缺失**（impeccable 要求对照，此处记录为"无"）。i18n 以 `src/i18n/en.ts` / `zh.ts` 为事实源。组件规则 `src/App.css`，token `src/theme.css`。

## 问题清单（按严重度排序）

### P1

#### 1. 设备页 `direct_links` 缺失即崩溃 — **已修**
- **现象**：旧服务器省略 `direct_links`（而非返回 `[]`），`DevicesSection.tsx` 直接读 `d.direct_links.length` → `TypeError: Cannot read properties of undefined (reading 'length')`，整页 React 渲染崩溃成空白。
- **截图**：before 白屏 `shots-before/issue-01-before.jpg`；after 设备表完整渲染（Direct links 列显示 "all relay via hub" 回退）`shots-after/issue-01-after.jpg`；逐页证据 `2026-10-31-ui-audit-impeccable/shots/dark-devices-desktop.jpg`。
- **定位**：`console/src/pages/devices/DevicesSection.tsx:113-116`（原 :114）。
- **修复**：`const links = d.direct_links ?? []` —— 版本错位容忍，列回退为 "all relay via hub" 或链接标签。

#### 2. 窄屏（≤720px）宽表被挤压、文字折成字堆 — **已修**
- **现象**：antd 在 ~390px 挤压列、单元格换行成高堆叠；"device-reg-1" 折三行、"Max uses" 折两行、时间戳折两行，不可读。诊断表/准入表/注册令牌表均受影响。
- **截图**：before `shots-before/issue-02-before.jpg`（折行字堆）；after `shots-after/issue-02-after.jpg`（自然宽度 + 横向滚动）；逐页证据 `2026-10-31-ui-audit-impeccable/shots/dark-access-narrow.jpg`、`2026-10-31-ui-audit-impeccable/shots/dark-diagnostics-narrow.jpg`。
- **定位**：`console/src/App.css:335-345`（`@media (max-width: 720px)` 响应式块）。
- **修复**：`.ant-table-content { overflow-x: auto }` + `.ant-table-content > table { min-width: max-content }` —— 表格保持自然宽度，内容包装横向滚动，绝不挤压列。

#### 3. 浅色主题状态标签对比度不达标（WCAG AA 失败）— **已修**
- **现象**：antd 默认 `success` 文本 `#52c41a` 在浅填充上约 2.2:1、`warning` `#d48806` 约 2.8:1，低于 4.5:1。`active`/`pending` 等状态标签在浅主题难读。
- **截图**：before 亮绿标签 `shots-before/issue-03-before.jpg`（对比 `#52c41a`）；after 深绿 `#15803d` 标签 `shots-after/issue-03-after.jpg`（4.79:1）；逐页证据 `2026-10-31-ui-audit-impeccable/shots/light-devices-desktop.jpg`、`2026-10-31-ui-audit-impeccable/shots/light-networks-desktop.jpg`。
- **定位**：`console/src/theme/antd-theme.ts:37-40`（light token 块）。
- **修复**：固定 AA 合规文本+填充对——`colorSuccess:#15803d`/`colorSuccessBg:#f0fdf4`（4.79:1）、`colorWarning:#b45309`/`colorWarningBg:#fffbeb`（4.84:1）。antd 把填充作为种子色 tint 派生，故文本+填充须同时设定。暗色主题（~9.2:1 / ~9.6:1）与品牌主色未动。

#### 4. 焦点环近不可见（WCAG 2.4.7 / 2.4.11）— **已修**
- **现象**：antd 的 cssinjs 样式在 `App.css` 之后注入，其 `:focus-visible` 环（以 `colorPrimaryBg` 绘制——暗色 `#18492a`、浅色淡绿）盖过 app 规则，在两种背景上都近乎不可见。键盘用户无法定位焦点。
- **截图**：before 暗绿近不可见环 `shots-before/issue-04-before.jpg`；after 亮绿 accent 环 `shots-after/issue-04-after.jpg`（"Run checks" 按钮上对比）；逐页证据 `2026-10-31-ui-audit-impeccable/shots/dark-access-narrow.jpg`、`2026-10-31-ui-audit-impeccable/shots/dark-diagnostics-narrow.jpg`。
- **定位**：`console/src/App.css:47-51`（`:focus-visible`）。
- **修复**：`:focus-visible { outline: 2px solid var(--accent) !important; }` —— `!important` 胜出 antd 注入样式；焦点环保持设计一部分、从不移除。

#### 5. 浅色主题激活导航文字对比不足（品牌约束，待决）— **未修**
- **现象**：浅主题下侧导航激活项 `color: var(--accent)`（`#16a34a`）画在绿色 tint 背景上约 2.78:1，低于 4.5:1。
- **定位**：`console/src/App.css:143-147`（`.sidenav a.active`）。
- **修复建议**：浅主题下用更深绿（如 `#14532d`）作激活文字，背景 tint 不变；只改文字色、不动 `--accent` token。品牌绿约束内，需用户拍板。
- **截图**：`2026-10-31-ui-audit-impeccable/shots/light-networks-desktop.jpg`。

#### 6. 浅色主按钮白字对比不足（品牌约束，待决）— **未修**
- **现象**：`#16a34a` 底 + 白字约 3.32:1，低于 4.5:1。登录/创建操作主按钮受影响。
- **定位**：`console/src/theme/antd-theme.ts:26`（`colorPrimary`）。
- **修复建议**：浅主题主按钮底色调深至 `#15803d`（≈4.5:1）或加粗字重。品牌绿约束内，需用户拍板。
- **截图**：`2026-10-31-ui-audit-impeccable/shots/light-networks-desktop.jpg`（"Create network" 按钮）、`2026-10-31-ui-audit-impeccable/shots/login-dark-desktop.jpg`。

### P2

#### 7. 标题层级从 h3 起跳，无 h1/h2 — **已修**
- **修复 commit**：`2356fa3`（每路由页加 `<h1>` 页面标题，区块升为 `<h2>`，子块 h3/h4 连贯）。
- **现象**：各路由页区块标题直接是 `<h3>`，无页面级 `<h1>`/`<h2>`；屏幕阅读器拿不到文档结构。
- **定位**：`console/src/pages/devices/DevicesSection.tsx:181`（`<h3>`），`access`/`diagnostics`/`networks` 各区块同。
- **修复建议**：每路由页加 `<h1>`（路由标题），区块用 `<h2>`，子块保留 h3；层级连贯。

#### 8. `NoNetworkSelected` 硬编码英文，未走 i18n — **已修**
- **修复 commit**：`1df7169`（文案提取至 `i18n/en.ts` `shell.noNetworkSelected` + `zh.ts` 对应键，组件走 `useLanguage().t`）。
- **现象**：死胡同空态文案 "Select a network in the top bar." 硬编码；中文环境显示英文。
- **定位**：`console/src/components/NoNetworkSelected.tsx`。
- **修复建议**：提取到 `i18n/en.ts` + `zh.ts`。

#### 9. 登录页无品牌标识 — **已修**
- **修复 commit**：`1f2fbc3`（认证卡上方加 `.brand` 字标 `.auth-brand`，居中排版）。
- **现象**：未登录时 topbar（含品牌）隐藏，登录卡仅 "Sign in"，无品牌字标；首印象弱。
- **定位**：`console/src/App.tsx`（auth 状态隐藏 topbar）。
- **修复建议**：认证卡上方加品牌字标（复用 `.brand` 标记）。

#### 10. 网络选择不持久化、不自动选首个 — **已修**
- **修复 commit**：`6863f08`（`NetworkProvider` 用 `meshlet-network` localStorage 持久化；加载时无有效选中则自动选第一个；删除网络回退首个）。
- **现象**：4 域中 3 个在没手动选网络时落空态死胡同；刷新即丢。
- **定位**：`console/src/App.tsx`（network selection state，`theme/network-picker`）。
- **修复建议**：选中网络 localStorage 持久化 + 加载时自动选第一个。

#### 11. 设备 Name 列换行 — **已修**
- **修复 commit**：`5313ef6`（Name 列 `width:180` + `.cell-ellipsis` 单行省略，完整值 title 悬停）。
- **现象**：`gateway-1` 折成两行，列过窄。
- **定位**：`console/src/pages/devices/DevicesSection.tsx:58`（`colName` 列）。
- **修复建议**：列设 `width` + ellipsis（或 min-width）。

#### 12. antd theme 与 theme.css 双 token 源 — **已修**
- **修复 commit**：`c300722`（单一事实源 `theme/tokens.ts`；`ThemeProvider` 注入 CSS 变量，`antdThemeConfig` 读同一模块，`theme.css` 仅留结构刻度）。
- **现象**：`console/src/theme/antd-theme.ts` 重复 `theme.css` 的 token 值，单一事实源被打破；改一处漏另一处。
- **定位**：`console/src/theme/antd-theme.ts` vs `console/src/theme.css`。
- **修复建议**：单一来源（TS 模块导出 token → CSS 变量注入，或构建时生成）。

### P3

#### 13. `.conflict` 卡片左侧 4px 强调边（AI-slop tell）— **已修**
- **修复 commit**：`9511c16`（去掉 `border-left: 4px`，统一 1px 边框，加 `⚠` 图标表达严重度）。
- **现象**：`border-left: 4px solid var(--danger-strong)` 是检测器的 "side-tab accent border" 信号，AI 设计模板痕迹。
- **定位**：`console/src/App.css:266`。
- **修复建议**：统一 1px 边框 + 图标表达严重度。
- **截图**：`2026-10-31-ui-audit-impeccable/shots/dark-networks-homelab-detail.jpg`（冲突卡片）。

#### 14. 移动端触控目标偏小 — **已修**
- **修复 commit**：`6276cda`（720px 断点下 antd 按钮/输入/选择/表格操作行 `min-height:44px`，行内 padding 放大）。
- **现象**：触控目标约 32px（低于 44px 最佳；过 WCAG 2.5.8 24px 下限）；移动端操作热区不足。
- **定位**：`console/src/App.css`（表格/表单控件），窄屏放大按钮/行内操作区。
- **修复建议**：窄屏下放大 tap 目标。
- **截图**：`2026-10-31-ui-audit-impeccable/shots/dark-access-narrow.jpg`。

## 已修四联表（问题 | before | after | commit）

| # | 问题 | before | after | commit |
|---|------|--------|-------|--------|
| 1 | 设备页 `direct_links` 崩溃 | `shots-before/issue-01-before.jpg` | `shots-after/issue-01-after.jpg` | `30d530c` |
| 2 | 窄屏表格挤压 | `shots-before/issue-02-before.jpg` | `shots-after/issue-02-after.jpg` | `30d530c` |
| 3 | 浅色状态标签对比度 | `shots-before/issue-03-before.jpg` | `shots-after/issue-03-after.jpg` | `30d530c` |
| 4 | 焦点环不可见 | `shots-before/issue-04-before.jpg` | `shots-after/issue-04-after.jpg` | `30d530c` |

> before/after 在独立 worktree（修复前代码 `30d530c^`）同视图重渲染：同页面、同视口、同主题；4 个修复全部带成对的同视图截图。修复前截图在 `docs/review/shots-before/`，修复后在 `docs/review/shots-after/`。

## 待修清单

- **P1 品牌约束（待决，2）**：#5 激活导航文字对比（App.css:143）、#6 主按钮文字对比（antd-theme.ts:26）。本轮禁止改动，留用户决策。
- **P2（6，已修）**：#7 标题层级 `2356fa3`、#8 i18n 硬编码 `1df7169`、#9 登录品牌 `1f2fbc3`、#10 网络持久化 `6863f08`、#11 Name 列换行 `5313ef6`、#12 双 token 源 `c300722`。
- **P3（2，已修）**：#13 侧边框 AI-slop tell `9511c16`、#14 触控目标偏小 `6276cda`。

## impeccable 审计评分（修复后状态）

### 五维健康度（0–4）

| 维度 | 分 | 说明 |
|------|----|------|
| Accessibility | 3 | 键盘可达（焦点环修复后可见）、语义标签、i18n 大体完整；但缺页面标题层级、浅主题导航/按钮文字对比 2 项 AA 失败、触控目标偏小。 |
| Performance | 3 | 全宽 fluid、无多余包装、antd v6；无懒加载/虚拟滚动，大表长列表待优化。 |
| Theming | 3 | 暗/浅双主题 token 一致、`prefers-reduced-motion` 尊重、OS 偏好跟随；但 antd token 与 theme.css 双源。 |
| Responsive | 3 | 720/1024 断点堆叠合理、侧导航变横条；但宽表需横向滚动、触控目标偏小。 |
| Implementation Integrity | 3 | 版本错位容忍已加、状态诚实（presence 来源/诊断"不可用≠通过"）；但白屏崩溃暴露防御不足、1 处硬编码。 |

**合计 15/20（Good）**

### Nielsen 10 启发式（修复后）

| 启发式 | 分 | 说明 |
|--------|----|------|
| Visibility of system status | 4 | 状态点带来源、诊断层标注、加载/空态齐全。 |
| Match with real world | 4 | 运维语义（presence、revision、segment grants、conflict 恢复路径）。 |
| User control & freedom | 4 | 撤销/拒绝/取消、冲突卡片给出恢复路径。 |
| Consistency & standards | 3 | antd 规范一致；但标题层级不一致（全 h3）。 |
| Error prevention | 3 | 冲突卡片防误操作；但缺失字段即崩溃（错误预防不足）。 |
| Recognition rather than recall | 3 | 表格/表单降低记忆负担；但网络选择不持久化、首屏死胡同。 |
| Flexibility & efficiency | 3 | 快捷键/批量待优化。 |
| Aesthetic & minimalist design | 4 | 瑞士极简、无多余装饰（冲突卡侧边框除外）。 |
| Help users recognize errors | 4 | 冲突卡片明确说明发生了什么、怎么做。 |
| Help & documentation | 2 | 无内置帮助/引导。 |

**合计 33/40（Good）**

### Design Specificity

**高。** 明显为 meshlet 而作：presence 语义（"绿点必须说明来源"，archive §12.2）、诊断"不可用 ≠ 通过"的诚实性、版本修订生命周期、segment grants、conflict 恢复路径（§8.3）、gateway-kernel 证据列。这些不是模板能生成的领域细节。

### 检测器

1 个 warning（`.conflict` 侧边框 accent border，即 #13）。无其他模板化设计信号。

## 运行备注

- vitest 门禁：4 files / 18 tests pass（修复后状态）。
- 截图生成脚本：`/home/cui/.cache/persona-ui-shots/mlt-audit-shot.mjs`（全量 26 张）与 `mlt-pairs.mjs`（4 问题 before/after 对，参数化 base-url + out-dir）。
- 修复前重渲染：`git worktree add /tmp/mlt-before 30d530c^`，node_modules 软链，dev server :5175。
- 凭证：本地 admin bootstrap（`meshlet-admin-2026`），来自 `~/.hermes/cache/scratch/mlt-reset.sh`，**勿外传、不入库**。
- 本日同日落地的后端 Windows 防火墙接线（`514cb51`）是后端改动、非 UI，不在本次审计范围。
