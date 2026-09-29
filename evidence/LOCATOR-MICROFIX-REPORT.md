# Locator micro-fix 报告（P2.1 补丁）

> **裁定（老大定的）**：
> 做一次**受控的 locator 修复**，然后立刻进 P4。
> 不直接跳，也不继续无限扩展 21 案例审计。

---

## 一、问题定性：不是「窗口太小」，是「坐标系统错配」

**这是本次修复最重要的认识。**

```
candidate_pairs 用 **pattern 命中位置** 当关系端点
relation 的端点却是 **结构坐标**：
    argument_flow 两端 = 「变量绑定位置」+「实参引用位置」
    same_object   两端 = 「对象属性值位置」
```

**实测证据（E3 构造样本）**：

```
pattern 命中：  createCipheriv @265        fetch( @734
结构坐标：      const artifact = makeArtifact @830    uploadPutObject(artifact,…) @877

relate(@265, @734)   = False   ← 用命中位置必然失败
argument_flow(@830, @877) = True   ← 用结构坐标就成立
```

> **所以即使能力配对正确，用错坐标就永远建不出关系。**
> 这不是"窗口不够大"，是**拿错了坐标系**。

**这解释了为什么 `candidate_but_unverified` 里全是 U2 ——
那些配对不是"结构不存在"，而是"用错了坐标去找"。**

---

## 二、micro-fix 的三条设计约束

```
✅ 只改 candidate locator / candidate generation
❌ 不改 relation 类型定义
❌ 不改权重 / 阈值 / verdict / 打分
❌ 不引入 semantic-role enrichment
```

### 实现

```
structural_anchors(text, pos)
    在命中位置附近采集结构坐标：变量绑定位置 + 调用位置
    ★ 按**离命中位置的距离**排序，取最近的 N 个
    ★ `pos` 本身始终保留 → 新集合是旧集合的**超集**，不丢原有能力

search_relation(..., lazy_expand=True)
    第一轮：pattern 命中位置（保持历史行为）
    第二轮（懒扩展）：仅当第一轮**一个都没建出**时，才展开结构坐标重试
```

### 两次调参（都是实测驱动的）

| 版本 | 候选对增长 | 问题 |
|---|---|---|
| 全量展开 | **129.5×** | 噪声失控（端点 1→13） |
| 懒扩展（无上限） | 129.5× | 懒扩展对"第一轮就失败"的案例无效 |
| **+ 每侧最多 3 个锚点** | **8.1×** ✓ | 合格 |

---

## 三、Stop Condition：**全部满足**

| 条件 | 结果 |
|---|---|
| **U12 漏召回已修复** | ✅ 修复前 `verified=0` → 修复后 `verified=1` |
| **候选噪声未明显扩大** | ✅ **8.1×** ≤ 10× |
| **未出现超出既有 schema 的新关系类型** | ✅ 超出：无 |
| **未改动 relation 类型 / 权重 / verdict / 打分** | ✅ |

**→ 可以进入 P4。**

### U12 修复后建出的 relation 是真实的

```json
{
  "type": "argument_flow",
  "structural_basis": {
    "kind": "return_binding_to_argument",
    "binding_ident": "body",
    "binding_pos": 305,
    "return_call": "Buffer.concat",
    "return_call_span": [331, 364],
    "argument_ref_pos": 771,
    "argument_span": [739, 787]
  }
}
```

**语义核对**：`body = Buffer.concat([iv, c.update(plain), c.final()])`（**加密后的数据**）
→ `fetch(req.url, { body })`（**上传**）

**这正是 E3 想验证的「加密产物 → 上传」链路的真实一段。** ✓

---

## 四、回归检查：无影响

```
Gate v2（Consistency Gate）  全部通过（B/C 级 23 条）
自检（self_audit）           弱断言 1 条（1%）
P2 验收（test_relation）      9 / 9 PASS
```

---

## 五、★ 过程中三次「检查写错」——第 5、6、7 次同类

| # | 现象 | 真相 |
|---|---|---|
| **5** | 候选噪声报 129.5× | 验证脚本**直接调 `candidate_pairs(expand=True)`**，绕过了 `search_relation` 里的懒扩展 → 噪声被全量暴露 |
| **6** | 报"新增类型 `argument_flow`" | 判定用**集合差**（∅→{argument_flow} 被当成新增）→ 应为"**是否超出既有 schema**" |
| **7** | U12 回归报 FAIL | 回归测试用 `text.find("fetch(")` 而非**案例记录里的实际 offset** → 假失败 |

> **累计第 5、6、7 次同类问题**（前 4 次见 Verification Hardening 报告）。
>
> **规律再次成立：验证脚本自身的错误率，和被验证的代码差不多。**
> "每个 FAIL 都要定性（实现错 / 检查错 / 探针错）"这条纪律，
> 在本轮又救了一次 —— 第 7 次如果不查，我会去"修"一个已经修好的功能。

---

## 六、修正一处表述（老大指出的）

**原表述**：
> Q3 > 0，但无重复模式 → 不足以推动新增 relation 类型。

**修正为**：
> **发现一个 schema gap（`call_edge` 现有 schema 无法表达），
> 但当前证据不足以证明它具有足够普遍性或业务价值，
> 因此暂不扩展 relation type。**

**为什么要改**：前者容易被读成"不存在 schema 缺陷"。
后者保留了这个事实 —— **以后再出现 `call_edge`，可以直接归并，
而不是重新争论"第一次是不是误判"。**

---

## 七、状态

```
Phase 1 verdict integrity       ✅（Shadow Audit 确认 A 类）
region bug impact               ✅ 已隔离
structural audit                ✅ enough for decision
locator recall issue            ✅ micro-fix 完成 + stop condition 全满足
relation schema expansion       ⏸ deferred（已记录 schema gap: call_edge）
P4 calibration                  ▶️ 可以开始
```

### ★ P4 的数据集标注要求

```
本轮这些 13 个案例的旧结果 **不是干净标尺** ——
它们是在"坐标系统错配"的 locator 下产生的。

P4 的 calibration dataset 必须明确标成：
    clean / post-locator-fix
而不是把历史结果直接当 Ground Truth。
```

---

## 附：可复跑

```bash
python evidence/test_locator_fix.py      # micro-fix 三项验证
python evidence/consistency_gate_v2.py   # 无回归
python evidence/test_relation.py         # P2 验收 9/9
```
