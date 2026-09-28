# Phase 2 · Consistency Gate 报告

> **目的**：不是"把几个测试跑一遍"，而是检查
> **同一份事实经过 P0 → P1 → P2 → P3 后，语义有没有发生不允许的漂移。**
>
> **为什么在 P4 之前做**：P4 要重新定义"证据如何汇总成结论"。
> 如果 P0–P3 内部还有语义冲突，P4 会把冲突**正常化**为一个看起来漂亮的 calibration 结果。

---

## 总判定：**全部通过 → 可以进入 P4**

| Gate | 内容 | 结果 |
|---|---|---|
| **G1** | 六条核心不变量 | ✅ 12 / 12 |
| **G2** | 状态代数无歧义 | ✅ 9 / 9 |
| **G3** | S1/S2/S4/E3/E4/E5 回放 | ✅ 全部 |
| **G4** | 层间禁止反向造证据 | ✅ 4 / 4 |
| **G5** | 所有结论都有可验证理由 | ✅ 4 / 4 |
| **G6** | confidence / chain 无隐藏阈值 | ✅ 4 / 4 |
| **G7** | P3 无越权改变 capability 结论 | ✅ 4 / 4 |

**贯穿纪律**：
> **PASS 的理由必须正确。FAIL 的理由也必须正确。**
> 「8/8」不是结论；「8/8 + 为什么 8/8」才是结论。

---

## 一、G1 六条不变量（I6 已正式编号）

```
I1  unknown ≠ negative
I2  unknown ≠ safe
I3  semantic_role ≠ required
I4  no structural proof → no relation
I5  no hidden threshold
I6  ★ no candidate → no chain evaluation
```

**I6 与前三者同层**，因为它也是同一个原则：
```
not evaluated  ≠  negative
unknown        ≠  negative
no relation    ≠  no structure
```

**检查方式**：源码级 + 运行时断言（不是"跑一遍看绿不绿"）。

---

## 二、G2 状态代数（P4 前最关键项）

### 层归属已显式化（`state_algebra.py`）

```
observation   9 个（计数口径：read / prefilter_rejected / skipped_* / …）
evidence      3 个（observed / not_observed / unknown_due_to_coverage）
assessment    6 个（not_observed / observed_insufficient / observed_supportive
                    / confirmed_capability / contradicted / blocked_by_coverage）
verdict       4 个（supported / contradicted / insufficient / blocked_by_coverage）
chain         4 个（同上）
```

### 四态机械可区分（用三个布尔量唯一映射）

```
blocked_by_coverage  ←  coverage_gap = True
contradicted         ←  有反向证据
not_observed         ←  无 support 且无 coverage gap
insufficient         ←  有 support 但不足以更高结论

穷尽 2^3 = 8 种输入组合 → 全部有唯一输出，且四态都可触达
```

**"没机会看" / "看到反证" / "没看到" / "看到但不够" —— 四者互斥且穷尽。**

### 六组禁止合并的状态对（已显式记录）

```
not_observed         ≠ insufficient            「没看到」≠「看到但不够」
not_observed         ≠ contradicted            「没看到」≠「看到反证」
insufficient         ≠ contradicted            「证据不够」≠「存在反证」
blocked_by_coverage  ≠ not_observed            「没机会看」≠「没看到」
unknown              ≠ not_observed            「判不了」≠「没看到」
unknown              ≠ negative                I1/I6 的根源
```

---

## 三、G3 历史样本回放

**检查的是「能否表达」，不是「判得准不准」** ——
role 层已封存（严格准入 coverage ≈ 0），所以"语义判不准"是**已知边界，不是回归**。

| 样本 | 关键性质 | 结果 |
|---|---|---|
| **S1** | credential 证据**未丢成 unknown**；polarity / semantic_role 字段**可表达反驳** | ✅ |
| **S2** | UI/SDK/detection 证据存在，`semantic_role` 全为 `None`（未硬猜）| ✅ |
| **S4** | 空文本无 `absent`；有证据能判到高于 `not_observed` | ✅ |
| **E3** | `possible` + valid relation → **chain = supported / strong**（不再被截断）| ✅ |
| **E4** | Relation = present · Capability = not_observed · Chain ≠ supported | ✅ |
| **E5** | 仍是 Known limitation（注释污染保留，**未假装已解决**）| ✅ |

### ★ S1 检查的口径说明

你要求"S1 必须仍能表示 credential evidence + contradicting denylist evidence"。
**当前 role 层封存，所以 `denylist` 不会被标为 `contradicting`。**

**本 Gate 检查的是**：
```
a) 证据存在（未丢失）           ✅ by_cap=['credential_access']
b) polarity 字段结构上可表达反驳  ✅ 字段存在（当前值 unknown，属已知边界）
c) semantic_role 可为 None（I3）  ✅
```

> **即：管道没堵，只是这一段的填充能力被封存了。**
> 这是「能表达」与「判得对」的区别 —— 后者不在本 Gate 范围。

---

## 四、G4 层间单向性（本轮新增的硬规则）

信息流必须是单向的：

```
Observation → Evidence → Assessment → Relation → Chain → Verdict
```

**任何上层都不能反向创造下层事实。**

| 检查 | 方式 | 结果 |
|---|---|---|
| 无反向 import | 静态分析模块依赖方向 | ✅ |
| `relation.py` 不 import adapter/assess/chain | 静态 | ✅ |
| `chain_eval` 只读 evidence | 静态 + 运行时 | ✅ |
| Chain 评估不改变 evidence 集合 | 运行时前后对比 | ✅ |

**你要求的例子已实测**：
```
obscureSeal → shipSealed
    → relation = argument_flow   ✅
    → 不产生 encryption capability ✅
```

---

## 五、G5 / G6 / G7

### G5 理由验收

```
· 提取到 reason 白名单 17 条
· 非 not_observed 的能力 4/4 都有 reasons
· 断言失败信息包含具体原因（不是裸断言）
· Chain confidence 返回可读的触发原因
```

### G6 无隐藏阈值

```
· derive_confidence 以多分支布尔谓词判定（if 分支 ≥ 3）
· 无 len(reasons)/n_reasons/score/norm 形式的阈值
· confidence 是枚举而非连续值
· 4 组抽样全部可回溯到具名 facts
```

### G7 P3 无越权

```
· E5 / E3 / S4-B3 三个样本：加 Chain 评估前后 capability 结论**完全一致**
· P3 文档明确声明 out of scope 含 B1/B2/B3
```

> **P3 越"局部"，架构越健康。** 如果 P3 一动，Discovery / Normalization
> 的结果全变了，那说明层间耦合太强。

---

## 六、★ 过程中抓到的三个问题（两个是检查写错，一个是真 bug）

| # | 现象 | 真相 | 性质 |
|---|---|---|---|
| 1 | G1 报 `"absent"` 出现在 assess 中 | 它出现在**断言**和**错误消息**里，不是输出路径 | **检查写得太粗** |
| 2 | G6 报 `derive_confidence` 不存在 | 我从 `chain_eval.py` 找，它定义在 `chain.py` | **找错文件** |
| 3 | G3 的 E4 报 relation 建不出来 | **但单独 debug 明明能建** | **真 bug** |

### 问题 3 的真因：`id()` 缓存复用

```python
_REGION_CACHE = {}
def region_at(text, pos):
    key = id(text)          # ← 不安全
```

**Python 的对象 `id()` 在对象被 GC 后会被复用。**
前一个文本被回收后，新文本可能拿到相同 id →
`region_at` 返回**另一个文件的 regions** → relation 凭空建不出来。

**现象特征**：**单独 debug 能建出 relation，批量回放里同一段代码判为 None。**

**修法**：键改成 `(id(text), len(text))`，并限制缓存条数。
**同一 bug 在 `tests/p05/probe.py` 里也有，一并修了。**

> 这是本轮**唯一的功能性修复**，而且它只在"批量跑多个文本"时才暴露 ——
> **单文件测试永远抓不到它。** G3 这种跨样本回放的价值正在这里。

---

## 七、Gate 之后的状态

```
P0    Evidence object      ✅
P0.5  Role enrichment      ✅ 封存（optional，coverage≈0）
P1    Assessment           ✅
P1.5  Verdict              ✅（四态 + unresolved）
P2    Relation             ✅
P3    Chain                ✅
────  Consistency Gate     ✅ 全部通过
P4    Calibration          ⏳ 可开始
```

**可以进入 P4。**

---

## 附：可复跑资产

```
evidence/state_algebra.py      状态层归属 + 四态机械区分 + 禁止合并对
evidence/consistency_gate.py   G1/G2/G4/G5/G6/G7
evidence/replay_gate.py        G3（历史样本回放）
```
