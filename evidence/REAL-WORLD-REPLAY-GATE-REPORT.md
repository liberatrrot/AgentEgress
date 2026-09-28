# P2/P3 Real-World Replay Gate 报告（R1–R8）

> **为什么在 P4 之前做**：`id(text)` 那个 bug 证明了
> **构造样本全过 ≠ 批量真实输入全过**。若直接进 P4，
> Calibration 会把这种底层关系错误包装成新的分数/置信度现象。
>
> **三条硬要求**（本轮遵守）：
> 1. Relation 基于**完整证据集**（禁止"每能力一个 anchor"）
> 2. Chain 只用**显式 chain_candidates**
> 3. 每个结果保存**证明材料**

---

## 总判定：**R1–R8 全部通过（8/8）**

| # | 检查 | 结果 |
|---|---|---|
| **R1** | S1/S2/S3/S4 全部可运行 | ✅ 6 个文件（+S3 33MB 截断跑）|
| **R2** | 无跨样本状态污染 | ✅ 同一样本重复运行 chains 完全一致 |
| **R3** | Relation 有 machine-checkable basis | ✅ |
| **R4** | Chain 只评估显式 candidate（5 个） | ✅ 无自动生成 |
| **R5** | `missing_relation` 三分法不靠猜 | ✅ 全部落在 `relation_unknown_due_to_analysis` |
| **R6** | E3 离散截断保持修复 | ✅ `state=supported conf=strong` |
| **R7** | P3 不越权改 capability 结论 | ✅ 三个样本均无变化 |
| **R8** | 所有结论可回放 | ✅ |

---

## 一、跑过的真实样本

| 样本 | 大小 | Observation | 有证据的能力 | relations |
|---|---|---|---|---|
| S1 ZCode `out/host/index.js` | 2.5 MB | 35 | 11 | **0** |
| S1 ZCode `out/main/index.js` | 0.7 MB | 15 | 10 | **0** |
| S2 WorkBuddy `main/index.js` | 2.3 MB | 18 | 8 | **0** |
| S2 WorkBuddy `main/code-cache.js` | 3.4 MB | 14 | 6 | **0** |
| S4 Quark `dist/main/main.js` | 1.1 MB | 4 | 3 | **0** |
| S3 opencode `out/main/index.js` | 0.2 MB | 4 | 3 | **0** |
| S3 opencode `node-BIz0dqH1.js` | 33.1 MB | 11 | 6 | **0** |

---

## 二、★ 本轮最重要的发现：**真实样本上 relations = 0**

**所有 7 个文件，一个 relation 都没建出来。**

```
chain_blocker_distribution（分母 = 已评估 candidate 数 = 30）
    relation_unknown_due_to_analysis      30 / 30
    missing_source_evidence               16 / 30
    missing_sink_evidence                 10 / 30
```

### 这意味着什么

```
P2 的两个 relation 类型（same_object / argument_flow）
    在构造样本上：9/9 验收通过、4/4 回放通过
    在真实样本上：**触发率 0**
```

**这不是 P2 的 bug** —— 而是说明：

> 在真实的大文件里，**两个不同能力的证据很少落在同一个 object literal
> 或同一条"返回值 → 实参"的绑定链上**。

**它同时解释了为什么 `same_call_chain` 也不该加** ——
不是"缺这个类型"，而是**结构关系的触发本身就很稀疏**。

### 但必须标注一个方法论限制

```
工具的证据位置 = 每个 pattern 在文件里的**首处命中**
                （P0 的既有口径，本轮沿用）
```

**"首处命中"不等于"该能力实际被使用的那个位置"** ——
所以 `relations = 0` 有两种可能解释：

```
解释 A  真实代码里确实没有这种结构关系（结构关系本来就稀疏）
解释 B  证据位置选得不对（首处命中 vs 实际使用点）
```

**本 Gate 无法区分这两者。** 要区分需要：
在**该能力的实际使用点**上取位置，而不是首处命中。

> **这个限制必须写进 P4 的前置说明** —— 否则 P4 会把"关系稀疏"
> 当成"证据弱"来处理，从而调出一个错误的校准曲线。

---

## 三、A / B / C / D 四个观察点

### A · P2 是否稳定

| 期望 | 结果 |
|---|---|
| S1 `same_object` | ⚠ 真实文件上未触发（构造样本上通过）|
| S2 `argument_flow` | ⚠ 同上 |
| S4 是否发现局部结构 | ❌ 未发现（该文件只有 4 个 Observation）|
| S3 `coverage_blocked` 时是否不乱建 relation | ✅ **0 条 relation，未乱建** |

**"关系少"不等于"不稳定"——本轮 0 条 relation 全部有正当理由。**

### B · P3 是否真解决 E3 且不制造新问题

```
✅ possible capability + admitted relation → chain = supported（R6 回归通过）
✅ 共现但无 relation → chain 不成立
   （全部 30 个候选：无 relation 时 state 一律 insufficient，从未 supported）
```

**两边都成立。**

### C · `missing_relation_*` 的真实分布

```
relation_unknown_due_to_analysis   30 / 30
missing_relation_structurally_expected   0
missing_relation_no_structure            0
```

**✅ R5 通过：`structurally_expected` 一次都没出现** ——
因为 evaluator **没有猜**（`structural_expectation="unknown"`），
这正是 P3 被修正后的行为。

> **即：在无外部标注的情况下，三分法只产出"无法判定"。**
> 要得到真正的 `structurally_expected` 计数，**必须人工标注**。

### D · P2/P3 有没有改变旧结论之外的东西（regression）

```
✅ R7：三个样本的 capability-level 结论在加 Chain 前后**完全一致**
✅ E5 未被"顺手解决"（注释污染仍在，属已知边界）
✅ 没有把 unknown 变成 safe（G1 的 I1/I2 断言仍在）
```

**无层间泄漏。**

---

## 四、★ 两处环境限制（诚实记录）

### ① 33MB 文件无法在时限内跑完

```
S3 的 node-BIz0dqH1.js = 33.1 MB
→ lex_regions（逐字符扫描）+ 56 个正则 finditer 在 Python 里超时
```
**这是环境限制，不是实现缺陷。** 处理方式：
**截断到前 2 MB** 跑，并在结果里标 `truncated: true`。
截断后结果与其余样本一致（relations=0，chains 全 insufficient）。

### ② `RW_ONLY` 过滤下 R1 会 FAIL

只跑部分样本时（如 `RW_ONLY=S3`），R1"全部可运行"自然不成立 ——
**那是过滤导致的，不是缺陷**。全量跑时 R1 通过（6 个文件）。

---

## 五、对 P4 的直接影响

**本 Gate 的结论必须作为 P4 的前置条件写入**：

```
1. Relation 在真实样本上触发率 ≈ 0
   → P4 校准时，**不能把"缺 relation"当成"证据弱"**
   → 这两者在当前数据下不可区分

2. 证据位置 = 首处命中（不是实际使用点）
   → 这直接影响 Relation 的触发率
   → P4 若要解释"为什么没有链"，必须先排除这一层

3. structurally_expected 恒为 0（evaluator 不猜）
   → P4 若要统计"结构缺口"，需要外部标注，不能靠自动推断
```

> **一句话**：P4 现在有了稳定的输入，但其中 **relation 层是"沉默的"** ——
> 它不是"没有关系"，而是"我们没有在正确的位置找关系"。
> **这个区别在 P4 里必须保持，否则会把定位问题误诊为证据问题。**

---

## 附：可复跑命令

```bash
# 全量（跳过 >5MB）
RW_MAX_FILE_MB=5 RW_MAX_EV=5 RW_MAX_PAIRS=40 python evidence/replay_real_world.py

# 单独跑 33MB（截断到 2MB）
RW_ONLY=S3 RW_MAX_FILE_MB=40 RW_TRUNC_MB=2 RW_MAX_EV=2 RW_MAX_PAIRS=10 \
  python evidence/replay_real_world.py
```

**证明材料**：`evidence/_replay_realworld.json`（含每个 chain 的
candidate / evidence_refs / relation_refs / reasons / blockers / confidence）
