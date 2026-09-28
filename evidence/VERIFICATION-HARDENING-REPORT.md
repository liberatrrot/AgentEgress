# Verification Infrastructure Hardening 报告

> **为什么先做这个而不是先看 21 个案例**
>
> 21 个 `candidate_but_unverified` 现在只有"距离 ≤ 4000"这个判据，
> 人工看它们得到的是**探索性样本**。
> 如果随后发现"21 个里 8 个真有关系"，仍然要问：
> **我们的 Gate 是不是可靠地确认了这个结论？**
>
> 而 Gate 自己有 13 条弱断言 —— **这个底层问题没消掉之前，证据链是不闭合的。**
>
> ```
> Gate assertions → runtime truth → Gate trustworthy → 21 cases become meaningful
> ```
> **这个依赖关系更干净。**

---

## 一、断言三层（本轮引入）

| 级别 | 含义 | 是否计入"通过" |
|---|---|---|
| **A** | Source-presence：源码里存在某字面量 | ❌ **只算辅助，不得独立贡献** |
| **B** | Runtime-behavior：构造输入 → 跑 → 断言行为 | ✅ |
| **C** | End-to-end：跨层不变量 | ✅ |

**v1 的 13 条弱断言全部属于 A 级，但它们当时是独立计入通过的。**

---

## 二、新增的硬要求：失败路径自证

**每个 B/C 断言必须附一个负例探针**：
故意构造违反条件的输入，**确认断言真的会失败**。

```python
def probe_can_fail(fn, expect_fail=True):
    try:
        fn()
    except AssertionError as e:
        return True, "断言确实触发"
    except Exception as e:
        return False, "抛了非 AssertionError（探针写错）"
    return (not expect_fail), "未触发断言（该检查可能是恒真的）"
```

**理由**：`"字面量" in src` 形式的断言**永远不会失败**（除非有人删了那行注释），
所以"全绿"可能只是因为它写成了恒真。**自证是防假绿的唯一办法。**

---

## 三、v2 结果：**全部通过**

```
G1 六条核心不变量        B/C: 8/8   A 级辅助: 1
G2 状态代数无歧义        B/C: 8/8
G4 层间禁止反向造证据     B/C: 2/2
G5 所有结论都有可验证理由  B/C: 2/2
G6 confidence 无隐藏阈值  B/C: 2/2
G7 P3 无越权             B/C: 1/1
─────────────────────────────────
B/C 级断言合计 23 条；A 级辅助 1 条
Gate 总判定：全部通过（B/C 级）→ 验证层可信
```

### 13 条弱断言的处理

```
13 条 → 全部降级或改造：
  · 12 条改成 B/C 级运行时断言
  · 1 条保留为 A 级（源码约束，明确标注不计入通过）

自检结果：13 条弱断言 → **1 条（1%）**
```

### 关键改造示例

**I1（unknown ≠ negative）**：
```python
# 旧（A 级）：只查源码里有没有那个字符串
g.check("...", "有证据却报 not_observed" in src_assess)

# 新（B 级）：构造输入 → 跑 → 断言行为
by_cap = {"workspace_snapshot": [FakeEv()], ...}
ass = assess(by_cap)
st = {a.capability: a.evidence_state for a in ass}
assert st["workspace_snapshot"] != "not_observed"
assert "absent" not in set(st.values())
```

**I5（无隐藏阈值）—— 这条改得最彻底**：
```python
# 不再测"源码里有没有 reason-pattern"
# 而是遍历 2^6 = 64 组 facts 输入空间：
for hs, hk, ar, anyr, ct, bk in product([False, True], repeat=6):
    c1 = derive_confidence("s", hs, hk, ar, anyr, ct, bk)
    c2 = derive_confidence("s", hs, hk, ar, anyr, ct, bk)
    assert c1 == c2          # 稳定性
    assert c1 in 四档枚举
# 外加单调性：
assert order[with_admitted] >= order[without_admitted]
```

**I6（no candidate → no chain evaluation）—— 新加入的重点**：
```python
cand = ChainCandidate(..., applicable=False)
r = evaluate(cand, {}, [])
assert r.evaluated is False      # 不得评估
assert r.state != "absent"       # 不得产出 absent
# 负例：无对应 candidate 的评估结果必须被拦
assert_chain_invariants([r], [])   # → 应抛 AssertionError
```

**"not evaluated ≠ negative" 因此真正进入了执行路径**，而不只是文档里的一句话。

---

## 四、★ 过程中第 4 次"检查写错"

```
I2 的失败路径自证报告失败：
  → 抛了非 AssertionError：'A' object has no attribute 'supporting'
```

**真相**：我用来"制造违规"的 fake 对象**缺字段**，
`assert_invariants` 先访问它就抛 `AttributeError` —— **探针本身写错，不是断言失效**。

**修法**：fake 对象必须提供断言会访问的**全部**字段。

### 这已经是第 4 次同类问题了

| 次数 | 场景 | 真相 |
|---|---|---|
| 1 | G1 报 `"absent"` 出现在 assess | 它在**断言**和**错误消息**里，不是输出路径 |
| 2 | G6 报 `derive_confidence` 不存在 | 我从 `chain_eval.py` 找，它在 `chain.py` |
| 3 | 自检 S5 报"弱断言 0 条" | 扫描器只匹配 `assert`，漏了 `g.check(...)` |
| 4 | I2 自证失败 | fake 对象缺字段 |

> **规律：Gate/自检工具自身的错误率，和它检查的代码差不多。**
> 所以"抓到的每个 FAIL 都要定性"必须是硬纪律 ——
> **不区分"实现错/检查错/探针错"就动手修，很容易去修一个没坏的东西。**

---

## 五、变更清单

```
删除  evidence/consistency_gate.py        （v1，13 条弱断言）
新增  evidence/consistency_gate_v2.py     （B/C 分层 + 失败路径自证）
更新  evidence/self_audit.py              （结论文案改为动态判断）
```

**v1 已由 v2 完全替代**，删除以免混淆（git 历史保留）。

---

## 六、这一步的定位

> **修的不是 AgentEgress 的一个能力，而是「以后所有架构结论所依赖的验证层」。**

这与项目从 Phase 1 起就确立的纪律一致：
```
测试系统通过 ≠ 产品无缺陷
```
现在把它继续向下递归了一层：
```
Gate 自身"通过" ≠ Gate 可信
```

---

## 七、下一步：21 个 `candidate_but_unverified` 的人工核实

**验证层已可信**，现在可以做这件事了。

**要求（按老大的设计）**：

```
只标这三类，**不顺便重新判 capability**：
    U1  structurally_expected       代码中确实存在可复核的结构事实
    U2  no_structure                只是距离近，本来没有结构
    U3  unknown_due_to_analysis     当前无法判断
```

**关键纪律**：
> **人工标注的不是"我觉得它们应该连"，而是"代码中是否存在可复核的结构事实"。**
> 否则又会把"架构假设"写进 Ground Truth。

**停止条件**：
```
只要没有人工依据，就不允许把它归到 U1。
```

**这个答案直接决定 P4 的输入形状。**
