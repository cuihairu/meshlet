# roam 计数口径提案：beats-inf（死面逃逸）是否计入 roam（2026-11-19）

巡检单 meshlet-roam-kejing-1119。回填窗23 判定单
（fliploop-fix-window23-verdict-2026-11-19.md）留下的口径新题。
**本文档原为提案；口径已于 2026-11-22 拍板定为口径 B**（见文末
「已拍板」节），基线与闸字面已按 B 重述。

## 实现层事实（crates 真读，非拍脑袋）

1. **事件产生与落盘**（`crates/meshlet-network/src/dial.rs:95` SwitchEvent +
   `apps/agent/src/agent/direct.rs:447/487/545`）：切换事件两类——
   - `kind=mode_flip`：直连模式翻转（demote/promote/exhausted/verified）；
   - `kind` 缺省：SEL-002 迟滞闸端点漫游（`probe.rs` SwitchGate
     `evaluate()` 产生，`record_endpoint` 落盘）——roam 口径的对象。
2. **无结构化 score/current 字段**：事件 JSON 只有 `reason` 文本
   （`probe.rs:495`：`"score {best_score:.1} beats current
   {current_score:.1} by >= …"`）。**beats-inf 与 beats-数值靠 reason
   文本即可区分**（`beats current inf` vs `beats current <数值>`），
   无需改落盘格式（红线遵守）。
3. **`beats current inf` 的精确语义**（`probe.rs:295` score()）：
   现役面探测窗口**非空但 rtt_ms()=None（窗口内全 Lost）→ 返回
   f64::INFINITY**。窗口为空（无基线）时 score()=None，evaluate 的
   `and_then(score)?` 直接不切换——**「无基线」永不产生切换事件**。
   所以 beats-inf ≠ 无基线，而是**「有基线的死面逃逸」**：现役面 RTT
   基线全 Lost（面真死），闸把会话逃到活候选面（方案 8 预检保证目标
   面至少一拍 RTT 成功）。
4. `beats current <数值>` = 现役面活但候选面按 RTT×丢包惩罚更优
   ≥margin 连续 3 采样——**两活面间的择优切换**（含劣化面逃逸）。

## 基线勘误（随复算发现，勘误不改既有单据）

窗23 判定单写「基线 18 条全 in-gate beats-数值」**不准确**：复算基线窗
（2026-11-15T08:57:32Z→11-16T09:11:32Z 含端）18 条 roam 构成=
**10 条 beats-数值（QmAF 3 + b6tx 7）+ 8 条 beats-inf（QmAF 8）**。
0dd4af4 原文「18/18 全为判据内触发」仍成立（beats-inf 同样走
`best_score < current_score` + margin + 连续 3 采样判据，inf 恒被
严格更优击败），但「全 beats-数值」系窗23 判定单表述错误，此处勘误。
既有判定单与 raw 按红线不改。

## 两口径定义与四列对比（真跑复算）

**口径 A（现状）**：无 kind 端点切换全数计入 roam。
**口径 B（提案）**：beats-inf=死面逃逸不计 roam、单列 beats-inf 计数
（死面逃逸率=面质量观测列，不进验收闸惩罚项）。

| 列 | 基线（24.23h） | 窗23（24h） | 口径 |
|---|---|---|---|
| roam | **18**（数值 10 + inf 8） | **75**（数值 8 + inf 67） | A（现状全数） |
| roam | **10**（QmAF 3 + b6tx 7，全 beats-数值） | **8**（全 b6tx） | B（剔 beats-inf） |
| beats-inf 单列 | （并入 roam）8，全 QmAF | （并入 roam）67，全 QmAF | B 的观测列 |
| flip/peer | 214 / 612 / 150 = 976 | 227 / 441 / 294 = 962 | 两口径同 |
| rollback | 0 | 0 | 两口径同 |
| 环数（defB） | wd n=76 / median 1.88 | JMrE 68/1.07、QmAF 23/6.39、b6tx 97/3.35 | 两口径同 |

（方法自洽注记沿用窗23 判定单：基线 flip 975 vs 锁定 976 差 1 条=文件
2.5 天轮转漂移；roam 18 精确复现。）

## 对 L157 验收闸的影响

- 闸字面现为「SEL-002 roam 18→≤17」，隐含口径 A（基线 18=全数计入）。
- **口径 A**：窗23 roam=75，闸 FAIL（现状判定已如此，勿需改动）。
  但 75 里的 67 条是「面死了→闸正确逃逸」的计数——闸干对了活却被扣分。
- **口径 B**：基线随之重述 18→10，闸字面需改为「roam 10→≤9」（或按
  用户意愿另行定标）；窗23 roam=8 < 9 **PASS**，另单列 beats-inf
  8→67（imac 面失联期的死面逃逸放大，归面质量列不归闸）。
  代价：基线数字被口径切换重写（18→10），须用户明示接受。

## 推荐与理由

**推荐口径 B**（剔 beats-inf 出 roam、单列观测）：
1. 语义正交：roam 原语义=两活面间择优漫游（判据=RTT 分数比较）；
   beats-inf=现役面基线全死的逃逸，比较对象一侧是 ∞，分数比较无意义
   （任何活面都"击败"死面），两者混在一条计数里使指标失去可解释性。
2. 激励方向正确：把「正确逃逸」计为惩罚项会反向激励调参（抑制逃逸=
   留在死面=ping 三态横跳回归）；死面逃逸应当被观测（逃逸频发=面质量
   差的信号，正是窗23 imac 面失联的如实呈现）而非被闸惩罚。
3. 历史兼容：基线 18 条里本就有 8 条 beats-inf，口径 B 对基线同样成立
   （不是为窗23 量身定做的口径裁剪——两窗同一把尺）。

**反方向（维持 A）的理由也如实列出**：A 的唯一优势是口径零改动
（基线 18 与闸字面不变），适合「验收闸冻结、指标只增不改」的纪律偏好。

## 待用户拍板

- [x] **已拍板（2026-11-22，巡检单 meshlet-1122-2225 回填）：口径 B**——
      roam 剔 beats-inf=基线重述 18→10、闸改「roam 10→≤9」，窗23 roam=8
      PASS；beats-inf 单列 8→67 归面质量观测。
- 拍板后由后续单执行：todo 闸字面更新（若 B）+ 判定单口径注记追加
  （不改既有单据原文）。

## 已拍板（2026-11-22）落地注记

口径 B 生效，后续窗对账一律 B 口径（roam=无 `kind` 端点切换剔 reason 含
`current inf`；beats-inf 单列观测列不进闸）。**注意闸字面随口径重述为
「roam 10→≤9」后，基线重述不等于历史判定翻转**：

- 窗23（2026-11-16）：B=8 < 9 → 由 FAIL 转 **PASS**（kejing 提案原文）。
- 整定批最终窗（2026-11-20 OC 24h，tuning-window-final-2026-11-20.md）：
  B=14 > 9 → **仍 FAIL**（该单「B=14 达标」系按旧闸 ≤17 评，重述后不
  达标；其 59 条 beats-inf（A 口径主体）归面质量观测列，指向 imac 侧
  死面逃逸治理——治理另立，不在本口径单内）。

闸字面更新与判定单口径注记已同批落（todo 整定批行 + 判定单文末追加节）。
