# P2 · Relation 层报告

> **第一版严格限定**（按老大要求）：
> ```
> 实现  P2.1 same_object
>       P2.2 argument_flow
> 不做  same_call_chain（语义弱，易被误解成"A 的数据到了 C"）
>       复杂 alias / 跨函数 / 跨文件 / 控制流合流 / 循环传播
> ```
> **未改动 `agentegress.py`**（隔离原则保持）。

---

## 一、核心不变量（I4 的落实）

```
No proof      →  No relation
Weak proof    →  weak structural evidence
Strong proof  →  relation admitted
```

**禁止** `maybe related → relation = true`。

**`structural_basis` 必须是可机器复核的结构事实**（不是自述字符串）：

| 类型 | 必需的 basis 字段 |
|---|---|
| `same_object` | `container_start` / `container_end` / `property_source` / `property_target` |
| `argument_flow` | `binding_ident` / `binding_pos` / `return_call` / `return_call_span` / `argument_span` |

`assert_relation_invariants()` 会在运行时强制检查 —— 缺字段直接抛异常。

---

## 二、验收：9 / 9 PASS（Precision-first）

### 正例

| 样本 | 结果 | basis |
|---|---|---|
| **P-1** S1 ZCode 真实结构 | ✅ `same_object` | `container span=[120,333)` `property url ↔ maxBytes` |
| **P-2** 返回值 → 绑定 → 实参 | ✅ `argument_flow` | `binding=artifact` `return_call=makeArtifact` `args='(artifact, sink'` |

### 近负例（必须拒绝）

| 样本 | 结果 |
|---|---|
| N-1 两个 object 挨着但不是同一个 | ✅ 无关系 |
| N-2 绑定存在，但上传用了**别的**参数 | ✅ 无关系 |
| N-3 同一属性内部（非跨属性） | ✅ 无关系 |

### 诱骗例（lexical trap，必须拒绝）

| 样本 | 结果 |
|---|---|
| T-1 两个 token 都在块注释里 | ✅ 无关系 |
| T-2 同现在字符串里 | ✅ 无关系 |
| T-3 同一对象的同一个字符串值里 | ✅ 无关系 |
| T-4 绑定出现在字符串里 | ✅ 无关系 |

> **诱骗例防线**：`same_object` / `argument_flow` 都先检查两个位置是否落在
> `string` / `line_comment` / `block_comment` / 正则字面量内 —— 是则直接拒绝。
> 这是 Phase 1 反复发现的 lexical trap 在 P2 层的对应防护。

---

## 三、证据回放：4 / 4 结构关系重建

| 样本 | 期望 | 实际 |
|---|---|---|
| S1 ZCode | `same_object` | ✅ |
| S2 WorkBuddy | `argument_flow` | ✅ |
| E3 加密产物字段 → 上传参数 | `same_object` | ✅ |
| **★ E4 非标准加密 → 上传** | `argument_flow` | ✅ |

**I4 不变量：4 条 relation 全部有可机器复核 basis** ✅

### ★ E4 的结论

```
structural_basis:
    kind               return_binding_to_argument
    binding_ident      sealed
    return_call        obscureSeal          ← 非标准实现
    return_call_span   [1296, 1326]
    argument_span      [1384, 1491]

capability 状态（来自 adapter，不是 relation）:
    obscureSeal / shipSealed **没有产生任何 capability**  ✅
```

> **这证明了两件事**：
> ① **结构关系能建立** —— 即使 `obscureSeal` 完全不含标准词，
>    只要 `const sealed = obscureSeal(...)` + `shipSealed({payload: sealed.sealedBlob})`
>    这个结构成立，Relation 层就能识别；
> ② **Relation 不会因此发明 capability** —— `obscureSeal` / `shipSealed`
>    在 adapter 层依然是 `not_observed`。
>
> **这正是分层要守住的边界**：
> ```
> Discovery → Evidence → Relation
> 而不是 Relation → 自动宣布 capability
> ```

### ⚠ E4 样本里的一处杂质（诚实记录）

该样本的 capability 状态**不是"全 not_observed"**：
```
bulk_archive          observed_insufficient   （来自 walk_tree）
envelope_encryption   observed_supportive     （来自 ...）
```

**原因**：E4 的**注释块里写了 `createCipheriv`**（我自己写的
「全流程不使用 createCipheriv / fetch / … 等标准名」这句说明），
被 `cipheriv` 模式以 `w=9` 命中，`region=line_comment`。

**这是 E5 的同一类问题（注释/字符串里的命中被当证据）**，
**与 Relation 层无关**——它是 `semantic_role` 缺失导致的 known limitation。
已按约定**不在 P2 处理**。

---

## 四、实现过程中撞到的三个坑（全部是"定位"类问题）

**这三个都不是算法错误，而是"位置定错"** —— 值得单独记，因为它们是同一类。

| # | 现象 | 根因 | 修法 |
|---|---|---|---|
| 1 | P-2 `argument_flow` 判否 | 只**往前**找 `(`，找到了外层函数 `sync(...)` 的括号 | 两侧各找候选，取**最内层** |
| 2 | E4 `argument_flow` 判否 | 只**往后**找 `(`，但 `shipSealed({ payload: sealed.sealedBlob })` 的括号在**前面** | 同上 |
| 3 | 测试定位到注释 | `text.find()` 落在注释里的同样文字上 | 测试加 `loc_code()`：跳过非 `code` 区 |

**坑 1 和坑 2 是同一个函数在两种调用形态下的相反失败**：
```
形态 A：up(      )        → 括号在"位置"之后
形态 B：fn({ x: up })     → 括号在"位置"之前
```
**只往一个方向找，必然在某一种形态上失败。**

**坑 3 值得单独说**：三次 FAIL 里有两次其实是**测试定位错了**，
而不是实现错了 —— 甚至有一次实现**正确地拒绝了注释里的假关系**，
但被记成了 FAIL。

> **教训**：验收脚本自身的定位逻辑也要被审查。
> 这与 P0.5 学到的「PASS 的理由必须也正确」是同一件事的另一面 ——
> **FAIL 的原因也必须查清，否则会去修一个没坏的东西。**

---

## 五、P2 的边界（当前明确不做的）

```
❌ same_call_chain   —— 等第一轮结果决定是否值得
❌ 复杂 alias
❌ 跨函数 / 跨文件
❌ 控制流合流 / 循环传播
❌ Relation → capability 的自动推导（分层边界，永不做）
```

**下一步判断依据**：
> 如果 S1/S2/E3/E4 的结构关系都能稳定重建（**已达成：4/4**），
> 再决定是否加 `same_call_chain`；
> 如果连这两个最小关系都很难稳定建立，那说明"轻量结构层"的成本
> 已接近其收益边界。

**当前结论：两个最小关系稳定成立，可以进入 P3（Chain）或补做 `same_call_chain`。**

---

## 六、P3 的前置约束（已写进 schema，实现时遵守）

```
Chain = evidence set + relations + explicit reasons

❌ Chain = sum(evidence) → hidden threshold
❌ chain_confidence = 连续分数 → 再切一档
```

`chain_confidence` 必须是**分档枚举**（`strong` / `moderate` / `weak` / `insufficient`），
且每个档次都要能对应到 `reasons` 的具体构成 ——
**不允许存在"内部打分"**。

---

## 附：可复跑资产

```
evidence/relation.py        P2.1 same_object + P2.2 argument_flow
evidence/test_relation.py   9 个验收样本（正例 / 近负例 / 诱骗例）
evidence/replay_p2.py       S1 / S2 / E3 / E4 证据回放
```
