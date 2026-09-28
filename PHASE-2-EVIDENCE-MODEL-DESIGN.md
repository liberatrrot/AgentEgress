# Phase 2 · Evidence Model 设计（定稿）

> **前置**：Phase 1（S1–S5 + P0）· Evidence Model 反例审查 · P0.5 Role Evidence Probe
> **决策**：**选乙** —— use-site 降级为「可选的高置信辅助证据源」，
> 不作为 `semantic_role` 的必填项，不进入评分前置。
>
> **原因**（P0.5 实测）：
> **use-site analysis 不是一个足够高覆盖率的 semantic-role 生成器。**
> 它很好用，但整体只有 14% 有依据，且那 14% 里精度也不够高。
> 把它塞进核心判断链，会让下一版**更复杂却未必更可靠**。

---

## 〇、措辞修正（P0.5 的数字要准确表述）

```
全量观察：
    79 个 lexical observations
    11 个获得 role evidence
    68 个 unknown

观察覆盖率：11/79 = 13.9%

抽样的 11 个有依据结果：
    至少 4 个明显错
    最多 7/11 正确
```

> **13.9%** 是**当前这批样本中的观察覆盖率**；
> **7/11 ≈ 63.6%** 是**这次抽样下的最高观测 precision**。
>
> **不要把 63.6% 当成全局 precision。**
> 现在是在**诊断机制**，不是在做统计抽样。

---

## 一、★ 锁死一条规则：`unknown` 不是负证据

**这是整个 Phase 2 最重要的基础。**

### 禁止的传导

```
role = unknown
    ↓
Assessment 低
    ↓
"没有 role 支持"
    ↓
absent                      ❌ 禁止
```

```
role = unknown
    ↓
不参与任何 chain            ❌ 禁止
```

### 正确的语义

```
role = unknown
    ↓
该维度不提供证据
    ↓
其他 evidence 继续独立计算
```

```
unknown  ≠  negative
unknown  ≠  absent
unknown  ≠  low confidence
```

> **理由**：违反这条会重新制造 Phase 1 已经抓到的覆盖率盲点 ——
> 因为"我们没判断出来"和"这件事不存在"被混为一谈，
> 而这正是 S3（coverage-induced false reassurance）的同一个病根。

---

## 二、`semantic_role` 的字段结构

**保留这个字段，但改为四元组**：

```json
{
  "semantic_role": "denylist",
  "confidence": "high",
  "basis": [
    "Set membership",
    "boolean predicate",
    "exclusion branch"
  ],
  "status": "observed"
}
```

**未判定时**：

```json
{
  "semantic_role": null,
  "confidence": null,
  "basis": [],
  "status": "unknown"
}
```

> **`unknown` 不是失败，是这个模型的正常状态。**
> `basis` 是必需字段 —— 没有依据的 role 不允许写入（见 §三的准入规则）。

---

## 三、use-site 降级为「Evidence Enrichment」

### 它不是 Semantic Classification

```
use-site 分析
    ↓
输出 RoleEvidence              ← 不直接改 semantic_role
    ↓
admission rule（严格条件）
    ├── 通过 → semantic_role = <候选值>，status = observed
    └── 不通过 → 留在 evidence pool，不污染核心判断
```

### RoleEvidence 的形态

```json
{
  "observation_id": "obs-123",
  "role_candidate": "denylist",
  "basis": ["Set membership", "exclusion predicate"],
  "confidence": "high"
}
```

### 准入规则（admission rule）

只有**同时**满足以下三条，才允许晋升到 `semantic_role`：

```
① 有确定的 basis（不是"附近出现过某 API"）
② basis 全部来自**同一文件内**的结构事实
③ 不存在与之冲突的 basis
```

**否则**：留在 evidence pool，`semantic_role.status = "unknown"`。

> 这可以避免 P0.5 暴露的情况：
> **5/5 手挑 case PASS，但全文件只有 14% 有依据，而且其中还有明显错判。**

---

## 四、P0.5 的封存结论：可靠 / 不可靠的边界

**P0.5 的完成条件已改为**：
> **证明哪些 role 可以被低成本、高精度地识别；其余正式接受 `unknown`。**

### 可靠（可进 admission）

| role | basis | 依据来源 |
|---|---|---|
| `denylist` | Set membership + 排除判定 **或** 命名信号 | S1 实测 ✅ |
| `detection_rule` | 正则 + `.test()` + 与字段恒等比较 | S2 实测 ✅ |
| `documentation` | 命中在注释区 / 纯日志消费 | E5 实测 ✅ |
| `active_operation` | 值进入网络或文件 sink | A'/D 实测 ✅ |

### 正式接受 unknown（不做）

```
allowlist          —— 与 denylist 在"分支在调用方"时无法区分
schema_definition  —— 与普通对象字面量无法区分
ui_representation  —— 同上
ambiguous local use —— 有集合但无分支无命名 → 规则明确不硬猜
```

> **这不是失败，是一个健康的边界。**

---

## 五、两层验收（从 P0.5 学到的，适用于以后所有 enrichment 工具）

P0.5 最重要的发现**不是**覆盖率 14%，而是：

> **case-level correctness 与 corpus-level robustness 完全是两回事。**
> 5/5 手挑 case PASS ↔ 14% 全量覆盖。

### 验收必须两层

```
Micro  ：已知 case 能否正确解释？
Macro  ：大规模自然代码中，有多少 evidence 可以可靠解释？
```

**Macro 必须同时看四项**：

```
coverage       有多少 observation 获得了 role
precision      获得的 role 里有多少正确
unknown rate   unknown 占比
reason quality 判定理由是否正确
```

### ★ 硬门槛：PASS 的理由必须也正确

P0.5 的 `D` 例一开始是 **PASS**，但理由是错的 ——
它答对了"不是 documentation"，却是因为**判错了区域**而落到 `unknown`。

> **只看 PASS/FAIL 计数会完全掩盖这种缺陷。**
> **以后所有 evidence enrichment 工具的验收，都必须检查理由，不只是结论。**

---

## 六、已排除的假设（不要再花时间）

```
❌ minification → 变量名破坏 → use-site 失败
```
**实测证伪**：
```
minified       77–100% unknown
unminified     100%   unknown
```

**真正的瓶颈**：
> **现有 use-site 规则只覆盖极少数已知结构。**

**因此不要再优化**：
```
变量名恢复 / 窗口扩大 / minified prettify
```
这些最多只能提高某些局部案例。

### 「窗口」被正式定为不可靠手段

```
❌   token A + 200 chars + token B
✅   symbol identity + syntactic containment + consumer relation
```

> 已实测：大文件里窗口内可能同时存在大量无关 API
> （`aes-256-gcm` 附近恰好有 `.test(` 和 `=== "` → 被判成 `detection_rule`）。
> **不能用 `nearby text` 冒充 `use-site`。**

---

## 七、刹车点（明确记录，防止以后再滑进去）

**下面三个问题一起出现，是"局部 heuristic 正在长成半吊子 AST parser"的信号**：

```
无绑定变量的字面量怎么定消费点
同名短变量怎么消歧
窗口怎么替代
```

> **为提高 14% 的覆盖率而继续加规则 4 / 规则 5 / 特殊情况 A / 特殊情况 B，
> 会重新进入"字段齐了，但真正能填的很少；填出来的又可能错"的循环。**
>
> **一个不能可靠填充的字段，留空比胡乱填充更有价值。**

---

## 八、Evidence 的整体结构（`semantic_role` 地位的重定义）

`semantic_role` **不是**"每条 evidence 都必须有的标签"，
而是**一种可选的证据增强器**：

```
Evidence
├── lexical facts              （必有）
├── provenance                 （可选，可能是 unknown）
├── semantic-role evidence     （可选）★
├── structural relations       （可选）
└── coverage metadata          （必有）
```

**Assessment 自己决定**：哪些证据可用、哪些未知、哪些冲突。

> 这比
> ```
> 每个 Evidence → 必须分类 → 必须评分 → 必须 verdict
> ```
> **健壮得多。**

---

## 九、Phase 2 最终顺序

```
P0    Evidence object
P0.5  use-site analysis
        └─ 只作为 optional enrichment
           不要求高覆盖 · 不承担核心 verdict
           完成条件 = 证明哪些 role 可低成本高精度识别，其余接受 unknown
P1    Assessment / Verdict 解耦
        └─ 删除 "score → absent" 的隐式语义
P1.5  顶层 verdict 合成（含偏序关系定义）
P2    Relation（same_object / argument_flow / same_call_chain）
P3    Chain（改消费 Evidence/Relation；chain_confidence 须可解释）
P4    Calibration
```

**与上一版的差别**：P0.5 的目标从"提高 role 覆盖率"改成
**"划定可靠/不可靠的边界"** —— 已在本轮完成（§四）。

---

## 十、★ Phase 2 最关键的验收问题

> **在 86% `role = unknown` 的情况下，
> Evidence Model 是否仍然可以比当前 AgentEgress 给出更可靠、可解释的结论？**

**这才是下一阶段真正要回答的问题**，而不是继续追 `semantic_role` 的覆盖率。

### 这个问题必须**可证伪**，否则又是一次"看起来更规范"

**验收方法（待执行）**：

```
对 S1 / S2 / S4 / E3 / E5 五个已知失败样本，
逐一推演 Evidence Model 会给出什么结论，
与当前 AgentEgress 的结论并列比较：

  样本
  ├── 当前 AgentEgress 结论（已有）
  ├── Evidence Model 推演结论（在 role=unknown 的前提下）
  ├── 差异
  └── 判定：哪个更可靠？理由是什么？

判定标准：
  ① 是否消除了 Phase 1 已确认的误报/漏报
  ② 在 role=unknown 时，是否避免了"折叠成 absent"
  ③ 结论是否可解释（能列出依据）
  ④ 是否引入了新的误判
```

**若推演结果显示**：
```
在 86% unknown 的前提下，新模型的结论与旧模型没有实质差异
→ 那么 Evidence Model 的重构价值需要重新评估
```
**这个可能性必须提前承认。**
