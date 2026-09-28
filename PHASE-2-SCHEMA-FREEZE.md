# Phase 2 · Schema 冻结（v1）

> **状态**：本文件是 Phase 2 的**规范**。实现必须遵守，不得自行偏离。
> **前置**：Phase 1（S1–S5 + P0）· Evidence Model 反例审查 · P0.5（已封存）
> **冻结日期**：2026-09-28
>
> **解除 Phase 1 冻结的前提**：本文件的**五条不变量**成立且被实现遵守。

---

# 第一部分 · 五条不变量

**这五条是硬约束。任何实现如果违反其中一条，设计即视为失败 —— 不论结论看起来多好。**

## I1 · `unknown` 永远不能自动变成 `negative`

```
unknown ≠ negative
unknown ≠ absent
unknown ≠ low confidence
```

**禁止**：
```
field = unknown  →  Assessment 低  →  "没有支持"  →  absent
field = unknown  →  不参与任何 chain
```

**正确**：
```
field = unknown  →  该维度不提供证据  →  其他 evidence 继续独立计算
```

## I2 · ★ `unknown` 也永远不等于 `safe`（本轮新增）

**这条是我上一版漏掉的，也是最容易被顶层合成破坏的一条。**

反例（必须禁止）：
```
workspace  = unknown
credential = unknown
upload     = supported
→ overall = medium          ← 用户会读成"风险不高"
```

**要求**：`unknown` 必须进入最终报告的**未决项集合**，
而不是仅仅作为某个 Evidence 字段里的 `null`。

```
Verdict 必须显式携带 unresolved 集合；
"有未决项"必须影响顶层呈现，不允许被"最高 supported"掩盖。
```

**这是一条硬不变量，不是 UI 约定。**

## I3 · `semantic_role` 永远不是 Evidence 的必填前提

**schema 层面**：`semantic_role` 与 `role_evidence` **必须可选**。

反模式（必须禁止）：
```
Evidence
  └── semantic_role      ← 必须存在
```
因为虽然嘴上说"unknown 是正常状态"，**schema 却在暗示"每条 evidence 应该有 role"** ——
这会把 P0.5 重新变成隐形前置条件。

**而 P0.5 已实测**：严格准入下 `coverage ≈ 0`（0/5 admitted）。
所以"必需"是不可能的。

## I4 · `Relation` 必须有结构依据，不能退化成窗口

**禁止**：
```
token A + 同一行/同一区域 + token B   →  命名为 same_object
```

**要求**：至少给出**语法包含证据**。

```
same_object:       同一 object literal 的 property 之间
argument_flow:     created = foo() → bar(created.x)
same_call_chain:   同一 class / 同一命名空间下的方法串联
```

> 依据：P0.5 已实测**窗口不可靠** ——
> 大文件里 ±220 字符内什么 API 都有（`aes-256-gcm` 因附近恰好有 `.test(` 
> 和 `=== "` 被判成 `detection_rule`）。
> **这条必须成为下一阶段的 invariant，不只是"注意"。**

## I5 · Chain / Verdict 不得隐藏第二套连续分数阈值

**禁止**：
```
Chain = sum(evidence) → hidden threshold
chain_confidence = 连续分数 → 再切一档
```

否则 E3 的离散断裂只是**从 Capability 搬到了 Chain**。

**要求**：Chain 必须是**可检查的显式集合**：

```json
{
  "chain": "workspace_to_object_storage",
  "confidence": "strong",
  "reasons": [
    "workspace_source",
    "encryption_evidence",
    "object_storage_sink",
    "same_object_relation"
  ]
}
```

`confidence` 是**分档枚举**（`strong` / `moderate` / `weak` / `insufficient`），
每个档次必须能对应到 `reasons` 的具体构成 —— **不允许存在"内部打分"**。

---

# 第二部分 · 五个硬问题的答复

## Q1 · `unknown` 的语义 —— 已升级为 I2

除了三条不等式，新增 **`unknown ≠ safe`**，
并要求 `unknown` 进入最终报告的**未决项集合**（硬不变量，非 UI 约定）。

## Q2 · P0 Evidence object —— 已升级为 I3

`semantic_role` / `role_evidence` 在 schema 上**可选**：

```
Observation
  ├─ lexical_facts       （必有）
  ├─ location            （必有）
  ├─ provenance          （必有，允许 unknown）
  ├─ raw_context         （必有）
  └─ pattern             （必有）

Evidence
  ├─ observation_ref     （必有）
  ├─ specificity         （必有）
  ├─ polarity            （必有）
  ├─ semantic_role?      （可选）★
  └─ role_evidence?      （可选）★
```

## Q3 · Relation 防"伪结构化" —— 已升级为 I4

## Q4 · Chain 的无断裂要在 schema 层解决 —— 已升级为 I5

## Q5 · 顶层 Verdict 需要第四态

**我上一版提的三元组不够** —— 少了"存在明确反驳证据"这个维度。

**S1 的 denylist 就是典型**：
```
credential evidence
+  同一证据存在 denylist interpretation
≠  "credential evidence = unknown"
=  存在明确的反驳证据
```

**因此 Verdict 四态（已由 `polarity` 支撑）**：

```
supported              有支持证据，无反证
contradicted           存在明确反驳证据
insufficient           有证据但不足以定级（≠ 没证据）
blocked_by_coverage    技术性覆盖缺口导致无法判断（≠ 没找到）
```

配合 I2，顶层输出形如：

```
{
  "verdict": "supported",
  "unresolved": ["workspace_snapshot", "credential_access"],   ← 未决项集合（必有）
  "coverage": { ... }
}
```

---

# 第三部分 · 各阶段 Schema

## P0 · Observation / Evidence

### Observation（扫描器看到的最原始事实）

```json
{
  "id": "obs-000123",
  "file": "out/host/index.js",
  "offset": 123456,
  "line": null,
  "text": "createCipheriv(...)",
  "pattern_id": "crypto_node_cipher",
  "region": "code",
  "file_class": "production",
  "source_kind": "lexical"
}
```

**Observation 不判断**：是不是真的加密 / 是否用于用户数据 / 是否属于应用自身。

### Evidence（对 Observation 的解释，仍不产生风险等级）

```json
{
  "id": "ev-000123",
  "observations": ["obs-000123"],
  "capability_candidate": "encryption",
  "specificity": "high",
  "polarity": "supporting",
  "semantic_role": null,          ← 可选（I3）
  "role_evidence": null,          ← 可选（I3）
  "provenance": {
    "kind": "application",
    "confidence": "medium"
  },
  "coverage": "observed"
}
```

**允许的值**：
```
specificity : high | medium | low
polarity    : supporting | contradicting | neutral | unknown
provenance.kind : application | bundled_dependency | external_dependency
                | generated | test | documentation | unknown
coverage    : observed | not_observed | observed_insufficient
            | observed_supportive | confirmed_capability
            | unknown_due_to_coverage
```

## P0.5 · RoleEvidence（optional enrichment，已封存）

```json
{
  "observation_id": "obs-123",
  "role_candidate": "denylist",
  "basis": ["Set membership", "exclusion predicate"],
  "confidence": "high"
}
```

**规则**：
- **不直接写 `semantic_role`**
- 通过 `admission rule` 才晋升；否则留在 evidence pool
- **允许 coverage = 0** —— 实测确实 ≈ 0，这是**正常状态**

```
ADMISSIBLE_ROLES = {denylist, detection_rule, documentation, active_operation}
正式接受 unknown = {allowlist, schema_definition, ui_representation, ambiguous_local_use}
```

## P1 · Assessment（从 Evidence 中彻底移出评分）

```json
{
  "capability": "object_storage_upload",
  "evidence_state": "observed_supportive",
  "confidence": "medium",
  "impact": "high",
  "business_context": "unknown"
}
```

**三个独立维度必须分开**（S2 的问题证明这一点）：
```
impact            能力本身影响多大（low/medium/high/critical）
confidence        我们有多确定它真存在（low/medium/high）
business_context  有没有明确合法业务解释（none/weak/strong/unknown）
```

**旧的 `norm` 不再是 Evidence 的属性** —— 它属于 Assessment。

## P1.5 · Verdict 合成

**四态**（见 Q5）+ **未决项集合**（I2）：

```
supported | contradicted | insufficient | blocked_by_coverage
```

**合成规则必须处理**：
```
① 任一 capability 为 contradicted  → 进入顶层"被反驳"清单，不静默
② 任一 capability 为 unknown       → 进入 unresolved 集合，不静默
③ blocked_by_coverage 与 not_observed 必须区分
④ 顶层不允许只给一个词
```

## P2 · Relation

```json
{
  "id": "rel-003",
  "type": "argument_flow",
  "from": "ev-create-media",
  "to": "ev-upload-cos",
  "argument": "created.cos_credential",
  "confidence": "high",
  "structural_basis": {
    "source": "return_value",
    "target": "argument",
    "containment": "call_argument_of"
  }
}
```

**`structural_basis` 是必填**（I4）—— 没有它就不允许生成 Relation。

```
type: same_object | argument_flow | same_call_chain
     （按需扩展 return_value / property_flow / import_relation）
```

## P3 · Chain

```json
{
  "chain": "workspace_to_object_storage",
  "confidence": "strong",
  "evidence": ["ev-001", "ev-007", "ev-012"],
  "relations": ["rel-003"],
  "reasons": [
    "workspace_source",
    "encryption_evidence",
    "object_storage_sink",
    "same_object_relation"
  ]
}
```

**消费 Evidence + Relation 的直接表示，不消费已离散化的 capability level**（I5）。

## P4 · Calibration

**最后处理**。在 P0–P3 的数据模型稳定之前，**不动权重与阈值**。

---

# 第四部分 · ★ 实现隔离原则（关键）

**不要马上改旧的 56 个 pattern。**

```
第一版实现：
    旧 detector（56 pattern 原样）
        ↓
    适配层（把旧命中转成 Observation/Evidence）
        ↓
    新 Evidence
        ↓
    新 Assessment
```

**而不是**：
```
新 Evidence + 新 pattern + 新 role + 新 relation + 新 threshold   ← 禁止
```

**理由**：否则出问题时无法区分
```
是检测器变了，还是证据模型变了
```

**这与 Phase 1 冻结基线是同一个思想 —— 隔离变量。**

**下一阶段要验证的命题是**：
> **Evidence Model 能否比旧模型更可靠**，
> **而不是**重新提高检测 coverage。

---

# 第五部分 · 解除冻结的检查表

四条不变量（+ I2 共五条）落实到实现后，才解除冻结：

```
[ ] I1  unknown 不自动变 negative        —— 在 Assessment 里断言
[ ] I2  unknown ≠ safe                   —— Verdict 必须携带 unresolved 集合
[ ] I3  semantic_role 非必填              —— schema 验证该字段可为 null
[ ] I4  Relation 必须有 structural_basis  —— 无 basis 则拒绝生成
[ ] I5  Chain 无隐藏连续阈值              —— confidence 是枚举，可回溯到 reasons
```

**验证方式**：用 S1 / S2 / S4 / E3 / E5 五个样本重跑，
对比 `PHASE-2-VALIDATION-WALKTHROUGH.md` 的推演结论是否一致。

---

# 附：当前所处位置

```
Phase 1  ✅ 完成（S1–S5 + P0，冻结基线全程未改代码）
         └─ 产出：架构决策 + 14 种语义形态 + 7 类必然失效机制

P0.5     ✅ 完成并封存（严格准入 coverage ≈ 0）
         └─ 产出：可靠/不可靠边界 + 两条重要否证

Phase 2  🔒 Schema 已冻结，待实现
         ├─ 待做：I1–I5 的断言
         ├─ 待做：适配层（隔离旧 detector）
         └─ 验收：五样本重跑，对比推演结论
```
