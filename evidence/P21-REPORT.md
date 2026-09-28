# P2.1 · Evidence Locator Refinement 报告

> **要回答的问题**：
> **`relation=0` 到底是事实，还是我们的证据定位策略造成的测量假象？**
>
> **范围严格限定**：只改善「从哪条已有证据开始找 Relation」。
> ❌ 不做 actual use-site analysis（会滑向半个 AST）
> ❌ 不增加 capability discovery
> ❌ 不引入 semantic-role enrichment

---

## 一、R-L1 ~ R-L6：**6 / 6 全部通过**

| # | 标准 | 结果 |
|---|---|---|
| **R-L1** | 所有 Evidence 保留完整 citation 集合 | ✅ 44 条证据拥有 >1 个位置 |
| **R-L2** | `primary_citation` 不决定 relation evaluation | ✅ 无 `checked_pairs=0` 的 verified |
| **R-L3** | 候选生成有 bounded complexity | ✅ 上限 200 对 / 窗口 4000，超标 0 次 |
| **R-L4** | 每个 search 都能说明四态 | ✅ 三态都出现过 |
| **R-L5** | 回放不改变既有事实 | ✅ capability 结论零变化 |
| **R-L6** | 未引入 semantic-role enrichment | ✅ `locator.py` 不提 role |

### 实现方式（为什么不改 `build()`）

```
primary_citation   首处命中（展示用，保持原样）
all_citations      全部命中位置（relation 搜索用，按需展开）
```

**按需展开**而不是改 `build()` —— 这样 R-L5（回放不改变既有事实）自然成立。

---

## 二、★ 核心问题的答案：**部分是定位偏差**

```
搜索 133 次（分母）
    relation_verified                1   ← 不再是 0
    candidate_found_but_unverified  21
    no_candidate                   111
    search_blocked                   0

建出的 relation 总数 = 3
```

### 结论：**定位策略确实是原因之一，但不是全部**

**证据**：S1 的 `out/main/index.js`（0.7 MB）用完整 citation 集合后，
真的建出了 3 条 relation：

```
✓ browser_state_access ↔ credential_access : argument_flow
✓ browser_state_access ↔ credential_access : same_object
✓ browser_state_access ↔ credential_access : same_object
```

**而 S1 的 `out/host/index.js`（2.5 MB）仍然 0 条 verified。**

> 说明：
> ```
> 小文件   → 完整 citation 集合能建出关系（定位偏差是主因）
> 大文件   → 仍然建不出（距离太远，或确实没有局部结构）
> ```

**所以 P4 的前置条件要更新**：
```
旧：relation 层在真实样本上"沉默"，不能把"缺 relation"当"证据弱"
新：relation 层在小文件上可用、在大文件上仍稀疏
    → 校准时必须区分"文件规模"，不能用一个全局阈值
```

---

## 三、⚠ 21 次 `candidate_found_but_unverified` 的含义（诚实说明）

这是本轮最容易被过度解读的数据。

```
候选搜索中有 21 次：邻域内**存在配对证据**，但 same_object / argument_flow 都未通过
```

**它可能是**：
```
解释 A   关系确实存在，只是当前两类关系类型不足以表达
         → 支持增加 same_call_chain / property_flow 等
解释 B   只是"距离近"，本来就没有结构关系
         → 不支持增加
```

**本 Gate 无法区分。** 因为 `candidate_found_but_unverified` 的判据是
「两处证据距离 ≤ 4000 字符」，而**距离近 ≠ 有结构关系**。

> **要判断是否"类型不够"，必须人工检查这 21 个案例。**
> **在此之前不能据它增加 relation 类型。**

---

## 四、S1 host（2.5MB）的 8 次 unverified 案例

```
~ bulk_archive              ↔ envelope_encryption
~ bulk_archive              ↔ object_storage_upload
~ envelope_encryption       ↔ global_config_collection
~ envelope_encryption       ↔ workspace_snapshot          ← 与 S1 的真实结构相关
~ global_config_collection  ↔ telemetry_egress
~ global_config_collection  ↔ workspace_snapshot
~ object_storage_upload     ↔ upload_credential_api
~ upload_credential_api     ↔ workspace_snapshot
```

**`envelope_encryption ↔ workspace_snapshot` 与 S1 的真实链路最相关** ——
但 P3 的 `workspace_encrypt_upload` 候选链需要的其实是
`workspace ↔ encryption ↔ object_storage` 三段，这里只有两段的部分配对。

**要确认它是否真的存在结构，需要人工看这 4 个位置附近的代码。**
**这是下一步的事，不是本轮。**

---

## 五、★ 对 `same_call_chain` 的结论修正

```
P3 之后的结论：不是瓶颈（relation 类型不足 0/8）
P2.1 之后的结论：**证据不足，无法判定**
```

**理由**：
```
· verified 只有 1/133 → 不能说明"类型够了"
· unverified 有 21/133 → 但"距离近 ≠ 有关系"，也不能说明"类型不够"
```

**所以：`same_call_chain` 现在既不能加也不能否定。**
判据是**人工检查那 21 个 unverified 案例** —— 看其中有多少
「确实存在可观察的结构，只是没有对应类型」。

---

## 六、⚠ 定时自检的发现（与本轮独立，但必须记录）

按要求做了一次自检（`self_audit.py`）：

```
S1 assert 可达性                无恒真断言
S2 被实现带偏的期望              未发现
S3 模块级可变共享状态            无（除常量表）
S4 报告数字自洽性                未发现
S5 断言强度                      ★ 77 条断言中 13 条是弱断言（17%）
S6 报告里未验证的表述            无
```

### S5 的 13 条弱断言全部在 `consistency_gate.py`

```python
g.check("I1 有证据却报 not_observed 会被断言拦住",
        "有证据却报 not_observed" in src_assess)      # ← 只证明字面量存在
```

**这类断言只能证明"源码里写了这句话"，不能证明"这段逻辑真的会触发"。**
**它们恰好是"看起来通过但可能是假绿"的高发区。**

> **Gate 自己也要被 Gate。**

**处理方式（待办）**：把 I1/I2/I5/I6 这四条**最关键**的检查
补上**运行时行为断言**（构造输入 → 跑 → 断言抛异常），
而不是只查源码里有没有某个字符串。

**为什么本轮没做**：P2.1 是优先级更高的（它回答更根本的问题）。
**但这条不能一直挂着。**

---

## 七、P4 的前置条件（更新版）

```
1. relation 层：小文件可用、大文件稀疏
   → 校准不能用一个全局阈值，必须区分文件规模

2. 21 次 unverified 未人工核实
   → 不能据此增加 relation 类型
   → 也不能据此认为"关系稀疏"

3. consistency_gate.py 有 13 条弱断言待补
   → 在此之前，Gate 的"通过"要打折扣看
```

**建议**：进 P4 之前先做一件事 ——
**人工检查那 21 个 unverified 案例**（约 30 分钟），
确定"类型不够"还是"本来没关系"。**这个答案直接决定 P4 的输入形状。**

---

## 附：可复跑

```bash
LC_MAX_FILE_MB=5 python evidence/test_locator.py
python evidence/self_audit.py
```

**新增**：`evidence/locator.py` / `test_locator.py` / `self_audit.py`
