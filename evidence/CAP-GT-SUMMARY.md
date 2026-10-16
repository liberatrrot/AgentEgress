# P4-CAP-GT v1 · 盲标汇总报告（25/25）

> ⚠ **先说结论的边界**：
> **25 个样本全部标完，不代表 capability GT 已足以支持可靠的性能结论。**
> 见第五节「样本池不平衡」——**negative 只有 2 个**。

---

## 一、两轮盲标方法的区别（必须区分）

```
第 1 轮（S1/S2，8 个）  detector-output-blind
    · 物理隔离 detector（未 import agentegress/locator/relation/assess/…）
    · 但**未隔离预期标签**：样本名（b1-real-user-data / d0-standard）
      与注释（// D0 标准 API：全部直调）会泄露预期

第 2–3 轮（S3–S6，17 个）  detector-output-blind **+ 预期标签 blind**
    · 不透明 ID（CASE-XXXX）
    · **剥离注释后再展示**
    · 隐藏文件名 / 路径 / stratum
    · 映射存 _blind_key.json，标注结束前不展示
```

**报告里必须准确区分这两者**，不能混为一谈。

**第 1 轮已冻结，未返工**：
```
发现样本分层错误 ≠ 发现已填的 GT 标签错误
前者修正样本池，后者才要重审标注 —— 本轮只发生了前者。
```

---

## 二、样本覆盖

```
完成 25 / 25

S1 明确 positive              5
S2 明确 negative              3
S3 access 有 egress 无         4
S4 egress 有但无结构联系        4
S5 legitimate / SDK 边界       4
S6 结构复杂 / 需跨层            5
```

---

## 三、四维标签分布

| 维度 | =1 | =0 | 未标 |
|---|---|---|---|
| access | **21** | 4 | 0 |
| handling | **22** | 3 | 0 |
| egress | **19** | 6 | 0 |
| reachability | **19** | 6 | 0 |

### capability_class 分布

| class | 数量 |
|---|---|
| `full_chain_present` | **18** |
| `access_and_handling_only` | 2 |
| `absent` | **2** |
| `handling_only` | 1 |
| `access_only` | 1 |
| `handling_and_egress_present` | 1 |

### confidence 分布

```
high      24
medium     1   （CAP-08，40KB minified 未逐行读完 → insufficient_context）
```

---

## 四、★ 映射表扩展两处（原表无法覆盖）

盲标发现原 `capability_class` 映射表有缺口，**不硬塞进已有类别**：

```
CAP-17  handling_only
        access=0（treescan 定义但无调用点）· handling=1 · egress=0 · reach=0
        原表 "0 - - -" 只能映射到 absent —— 但 handling 确实存在

CAP-24  handling_and_egress_present
        access=0（数据由调用方提供）· handling=1 · egress=1 · reach=1
        原表无 "0 1 1 1" 这一行
```

**前者是"能力只有一半"，后者是"数据来源在本文件外"** ——
两者都不能塌缩成 `absent`。

---

## 五、⚠ 样本池不平衡（最重要的限制）

```
full_chain_present  18  (72%)
negative（absent）   2  ( 8%)
```

**老大此前已预警**：
> 如果 negative 样本只有少数几个，即使所有验证脚本通过，
> **针对 negative 类的误报率估计仍可能很不稳定。**

**当前状态就是如此。** 因此：

```
· 现在**不能**基于这 25 个样本给出 capability 层的误报率估计
· 现在**不能**据此判断 detector 在 negative 上的表现
· 这 25 个样本足以做 **FN 侧的探索**，但**不足以做 FP 侧评估**
```

**根因**：`negative` 样本池本身就稀缺 ——
盲标时已发现两个原本归入 S2 的样本（d0-standard / e1-discovery）
**实际都是 positive**，S2 因此只剩 3 个，其中 1 个还是 medium。

**不凑数**：宁可承认不平衡，也不把归类错误的样本留在 negative 组里。

---

## 六、上下文不足项与未解决问题

| case | 限制 |
|---|---|
| **CAP-08** | 40KB minified 未逐行读完 → `medium` + `insufficient_context`；**不得升级为 high** |
| **CAP-10** | **必须读依赖模块 `lib/vault.js` 才能判定**；单文件视角会误判为 insufficient_context |
| **CAP-17** | 只判定**本文件范围**；导出函数被外部使用后的能力不在范围 |
| **CAP-24** | 本文件**无数据获取动作**（plain 为参数）；数据来源需看调用方 |

**未解决**：
```
· detector 结果尚未加载（盲标期间全程未接触）
· 解盲后的误差评估（FN/FP/boundary）待做
· negative 样本不足 → 需扩充或明确声明不做 FP 估计
```

---

## 七、完成条件核对

| 条件 | 状态 |
|---|---|
| 已完成标注的样本都有可复核的证据 | ✅ 每条都带 evidence（代码位置 + 片段） |
| 不确定的样本被保留为不确定 | ✅ CAP-08 保持 medium；CAP-17/24 标 scope_limitation |
| 每个维度的正负例数量可审计 | ✅ 见第三节（**不平衡已暴露，未掩盖**） |
| 标注结束前没有接触 detector 结果 | ✅ 全程未加载 detector（有断言保证） |
| 解盲后能分别识别标签错误/样本偏差/detector 错误 | ⏳ 待解盲后执行 |

---

## 八、下一步

```
1  扩充 negative 样本（当前 2 个，不足以做 FP 估计）
2  然后才解盲，比较 detector 输出
3  ERROR_CLASS 归因（只有 calibration / verification 允许进调参讨论）
```

**在此之前不得查看 detector 预测结果** —— 冻结后才统一解盲。
