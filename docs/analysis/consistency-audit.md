# 全仓一致性审计（docs ↔ code ↔ tests）

> 范围：把文档（`docs/**`、`README*.md`、根 `TODO.md`）里对**代码的引用**与实际仓库做机械比对，产出差异清单。
> 方法：脚本抽取（非人工通读），结果可复现。
> 日期：2026-10-16。结论：**一致，发现 2 处真实漂移并已修复**（见 §2）。

## 1. 审计方法与覆盖

| 检查 | 对象 | 方式 | 结果 |
|---|---|---|---|
| C1 源文件引用 | 文档中反引号包住的源码路径（`apps/…rs`、`crates/…rs`、`migrations/…sql` 等） | 抽取后与文件系统比对 | 真实缺失 **0**（抽取器把跨多段路径截断的 4 例为工具假阳性，见 §3） |
| C2 行号引用 | `file.rs:NN` 形式 | 抽取后校验行号在文件范围内 | **0** 越界 |
| C3 API 路径 | 文档中的 `/api/v1/…` | 与 `apps/server/src` 中出现的 `/api/v1/…` 字面量比对 | 契约文档与实现**一致**；存档中的未实现端点见 §3 |
| C4 侧栏链接 | `docs/.vitepress/config.mts` 的 `link:` | 解析为 `docs/` 下 `.md` | **0** 悬空 |
| C5 字段/标识符名 | 文档中的实体字段名与内部错误变体名 | 与实体定义、DB 列、错误枚举比对 | **2 处漂移**（§2，已修复） |

## 2. 差异清单（真实，已修复）

| # | 位置 | 差异 | 处置 |
|---|---|---|---|
| D1 | `docs/architecture/domain-model.md:40` | 文档写 `overlay_ipv4_cidr`，实际字段是 `overlay_cidr`（`crates/meshlet-domain/src/entities.rs:50` 的 `Network.overlay_cidr`；`migrations/001_init.sql:17` 列名 `overlay_cidr`） | 文档改为 `overlay_cidr`（存档 §6 原名 `overlay_ipv4_cidr`，实现沿用更短的 `overlay_cidr`） |
| D2 | `docs/architecture/diagnostics.md:59-60` | ① 路由占位符写 `{id}`，实际注册为 `{network_id}`（`apps/server/src/lib.rs`）；② `404 not_found（diagnostics_not_run，…）` 把内部变体名 `ServiceError::DiagnosticsNotRun` 与 HTTP `code` 混在一处，易误读为 JSON 错误码 | ① 占位符改为 `{network_id}`；② 改为 `404`（`code: "not_found"`，内部变体 `ServiceError::DiagnosticsNotRun`），与 `ErrorCode` 的 snake_case 序列化口径一致 |

两处均为**文档侧笔误**，不涉及代码行为变更。

## 3. 判定为非差异（有据）

| 现象 | 判定依据 |
|---|---|
| 存档 §13 中的 `GET/PATCH/DELETE /api/v1/networks/{network_id}`、`…/devices/{device_id}`、`…/rotate-key`、`…/status` 未在实现中注册 | 这些出现在 [存档 §13](/review/chatgpt-2026-10-13)（外部意见），**不是本仓契约**；本仓契约 [API 契约](../architecture/api-contract.md) 与实现一致。存档中未采纳的设计不算漂移 |
| 文档中 `nf_conntrack` / `nf_conntrack_max` | 内核 sysctl 名（`docs/architecture/routing-optimization.md`），非代码标识符 |
| 存档 §14.3 的 agent 状态 `applying_config` | 外部设计状态名，`docs/analysis/agent-platform.md` 已标 **【待核】**（登记的外部意见状态，非实现现状） |
| C1 抽取出的 4 例「缺失路径」（`console/`、`src/windows_routes.rs`、`tests/revisions.rs`、`tests/windows_netsh.rs`） | 抽取器对跨多段反引号内容的截断产物；真实文件均存在（`console/src/…`、`crates/meshlet-network/src/windows_routes.rs`、`apps/server/tests/revisions.rs`、`crates/meshlet-network/tests/windows_netsh.rs`） |
| `TODO.md` 中的简写 crate 路径（`domain/src/peer_routes.rs`、`api-types/src/lib.rs`、`config/src/lib.rs`） | 指代真实文件（`crates/meshlet-domain/…` 等），但非字面路径；属账本书写习惯，不影响可追溯性（仓内已能用简写定位） |

## 4. 结论与建议

- 文档与代码在本次审计范围内**一致**；发现的两处笔误已就地修复。
- 未做人工通读式校对（风格、措辞、论证），本审计只覆盖**可机械判定的引用一致性**。
- 后续若改动实体字段名或路由占位符，建议同步跑本审计的抽取脚本（§1 的 C1–C5）再提交。
