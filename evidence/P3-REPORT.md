# P3 · Chain 层报告

> **Out of scope（写在顶部，防 scope creep）**
> ```
> B1 discovery · B2 normalization · B3 calibration
> ```
> 这三类是**单能力 evidence → assessment** 的问题，与链无关。
> **P3 不会让 S4 的三个 B 类消失。**

---

## 一、七条硬规则（assert 强制前六条）

```
1. 不消费 possible / likely / confirmed
2. 没有 admitted relation → 不得成为 supported chain
3. confidence 必须由显式 reason-pattern 导出（不是计数）
4. 不允许连续 score / 隐式 threshold
5. ★ no candidate ≠ chain absent   （not evaluated ≠ negative）
6. missing_relation 必须区分三子类
7. P3 不解决 B1/B2/B3
```

### 关于规则 3 的落实

`confidence` 是 **reason-pattern 的命名**，不是分数：

```
strong   = source + sink evidence 齐全 + ≥1 admitted relation + 无反证
moderate = source + sink evidence 齐全 + relation 存在但非必需级 + 无反证
weak     = 证据或关系不完整（可评估）
unknown  = 覆盖阻断 / 不适用 / 无法评估
```

`derive_confidence()` 用**布尔谓词**判定，**任何 `len(reasons) >= N` 形式的计数都在断言里被禁止**
（P1 的 `hi >= 2` 教训）。

### 关于规则 5

```
applicable=False → not_applicable（evaluated=False）
不产出 'absent' —— 那会被读成「评估过且不存在」
```

> 这是 `unknown ≠ negative` 的第三次出现：
> ```
> not evaluated ≠ negative
> unknown       ≠ negative
> no relation   ≠ no structure
> ```

---

## 二、验收：8 / 8（判据是「state + blocker 正确」）

| # | 案例 | state | confidence | blocker |
|---|---|---|---|---|
| P3-1 | 完整 evidence + `same_object` | **supported** | strong | — |
| P3-2 | 完整 evidence + `argument_flow` | **supported** | strong | — |
| P3-3 | evidence 齐全、无 relation | insufficient | weak | `missing_relation_structurally_expected` |
| P3-4 | relation 存在、source 缺 | insufficient | weak | `missing_source_evidence` |
| P3-5 | relation 存在、sink 缺 | insufficient | weak | `missing_sink_evidence` |
| P3-6 | supporting + contradicting | **contradicted** | weak | `contradicting_evidence` |
| P3-7 | coverage blocked | **blocked_by_coverage** | unknown | `coverage_blocked` |
| P3-8 | ★ E3 离散阈值案例 | **supported** | strong | — |

**硬规则断言 1/2/3/4/5/6 全部 PASS。**

### ★ P3-8 是本轮最重要的一个 PASS

```
E3 旧模型：
    object_storage_upload = possible (0.29)
    → 组合链被 discrete 断裂截断 → 0 条链

E3 新 chain：
    source_evidence_present:envelope_encryption
    sink_evidence_present:object_storage_upload      ← 旧模型里只有 possible
    admitted_relation:same_object
    → state = supported, confidence = strong
```

> **离散阈值断裂被真正修掉了。** 这正是 P3 最大的明确收益。

---

## 三、证据回放 + `chain_blocker_distribution`

### 版本 A · 片段版（4 条候选链）

| blocker | 计数 |
|---|---|
| `missing_sink_evidence` | **3 / 4** |
| `missing_source_evidence` | **2 / 4** |
| `missing_relation_structurally_expected` | 1 / 4 |
| 其余 | 0 / 4 |

⚠ **这个分布不可用**：S1/S2 的片段太短（Observation=0），
两份都判 `missing_source/sink_evidence`，分布被样本选取严重扭曲。

### 版本 B · 完整文件版（8 条候选链，S1 的 host/main + S3 的 main）

| blocker | 计数 |
|---|---|
| **`relation_unknown_due_to_analysis`** | **8 / 8  (100%)** |
| `missing_sink_evidence` | 1 / 8 |
| 其余 | 0 / 8 |

### ★ 这个分布对「要不要加 `same_call_chain`」的判读

```
relation 类型不足导致（missing_relation_structurally_expected）：0 / 8
无法判定结构（relation_unknown_due_to_analysis）：              8 / 8
evidence 缺失：                                                1 / 8
```

> **结论：`same_call_chain` 不是瓶颈 —— 但理由和第一版完全不同。**
>
> 真正的情况是：**在完整文件上，`same_object` / `argument_flow`
> 一个都没建成，而"代码里到底有没有结构"这件事，自动分析判不出来**
> （所以归到 `relation_unknown_due_to_analysis`）。
>
> **所以正确的结论是「无法判定」，不是「缺 relation 类型」。**
> 要得到真正的 `structurally_expected` 计数，**必须人工标注**
> 哪些链环节之间确实存在结构 —— 这部分无法自动化。

**第一版曾报出「8/8 支持加 `same_call_chain`」，那是启发式产物，已在 §四③ 说明并修正。**

---

## 四、★ 三处必须诚实记录的问题

### ① E4 的 blocker 与我预期不同

**我上一条消息预期**：E4 应该是 `missing_source_evidence`（`obscureSeal` 0 命中）。

**实测**：
```
source_evidence_present:envelope_encryption    ← 竟然有！
sink_evidence_absent:object_storage_upload     ← 缺
blocker = missing_sink_evidence
```

**原因（已查证）**：E4 样本的**注释块里写了 `createCipheriv`**
（我自己写的「全流程不使用 createCipheriv / fetch … 等标准名」这句说明），
于是 `envelope_encryption` 反而有了 evidence。

> **我上一条的预期是错的，实测数据推翻了它。**
> 这恰好又一次展示了 **注释污染（E5 同类问题）** 如何扭曲结论 ——
> 连"哪个环节缺证据"这种基本判断都会被它带偏。

### ② ⚠ S1 / S2 片段版的 Observation = 0

```
S1 · ZCode      Observation = 0
S2 · WorkBuddy  Observation = 0
```

**原因**：片段版只取了单个函数，片段里**没有强模式命中**
→ 0 Observation → 两份都判 `missing_source/sink_evidence`。

> **片段版的 blocker 分布不能推广。**

### ③ ★★ 完整文件版第一版的 8/8 是**无效结论**（最重要的教训）

**第一版做法**：
```python
anchor[k] = v[0].citation.get("offset")      # 每能力只取第一个证据当锚点
rel = relate(text, anchor[src], anchor[snk]) # 拿这两个锚点建关系
```

在 2.5 MB 文件里，两个能力各自的"第一个证据"几乎必然相距很远 ——
`same_object`（同一 object literal）和 `argument_flow`（返回值→实参）**根本不可能成立**。

**于是得到**：
```
missing_relation_structurally_expected   8 / 8   100%
判读：relation 类型不足是主要瓶颈 → 支持加 same_call_chain
```

**我一开始以为"改成全证据两两配对"就能修好。改完结果没变（仍 8/8）** —— 
说明 `missing_relation` 本身是真实的，**问题在它的子类归错了**。

**真正的原因**：
```python
elif candidate.required_relations:                # ← 只要候选"声明"了需要关系
    blockers.append("missing_relation_structurally_expected")   # 就归为「有结构但类型不支持」
```

**这个判据根本没有验证"代码里到底有没有结构"** ——
它测的是**候选的声明**，不是**代码的事实**。

> **所以那个 8/8 是我自己的启发式产物，不是实测。**
> **如果据此去加 `same_call_chain`，就是被一个假信号推着做决策。**

**修法**：三个子类的判据改为**由调用方显式声明**，实现不猜：
```python
ChainCandidate(..., structural_expectation="expected" | "none" | "unknown")
#   expected  人工确认过代码里有结构 → 找不到报 structurally_expected
#   none      本来就没结构           → 报 no_structure
#   unknown   无法自动判定（默认）    → 报 relation_unknown_due_to_analysis
```

**修正后的完整文件回放**：
```
relation_unknown_due_to_analysis   8 / 8   100%
missing_sink_evidence              1 / 8    12%

判读：relation 类型不足导致 0/8
     → **same_call_chain 不是瓶颈**（真正的问题是"判不了"，不是"缺类型"）
```

> **这才是诚实的结论**：在当前自动化水平下，
> `missing_relation` 全部落在"**无法判定**"，
> **不能据此支持加 `same_call_chain`**。
>
> 要得到真正的 `structurally_expected` 计数，需要**人工标注**
> 哪些链环节之间确实存在结构 —— 这是无法自动化的部分。

---

## 五、下一步建议

### 短期

1. **在完整文件上重跑 blocker 分布**（用 Phase 1 的解包样本），
   让"`same_call_chain` 是否必要"这个结论有更大分母
2. **进 P4（Calibration）** —— P0–P3 的数据模型已稳定

### 关于 `same_call_chain`

**当前证据不支持现在做。** 判据是：
```
missing_relation_structurally_expected  1/4
missing_relation_no_structure           0/4
```
**relation 类型不是瓶颈。** 等完整文件上的分布出来再定。

### 明确不做

```
❌ 继续加 relation type（数据不支持）
❌ 用 P3 去修 E5 / S4 的 B1-B3（out of scope）
❌ 在 chain 里引入任何连续分数
```

---

## 附：可复跑资产

```
evidence/chain.py         ChainCandidate / ChainAssessment / 七条硬规则 / 断言
evidence/chain_eval.py    evaluate / derive_confidence / blocker_distribution
evidence/test_chain.py    8 个验收案例
evidence/replay_p3.py     S1 / S2 / E3 / E4 回放 + 分布
```
