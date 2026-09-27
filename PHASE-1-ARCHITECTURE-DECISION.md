# PHASE 1 · 架构决策

> **产出时间**：2026-09-27
> **依据**：S1–S5 真实样本 + P0 正交边界实验，全部在 **冻结基线** 上完成
> （commit `f561272`，`agentegress.py` sha256 `48B914A0...F2EC7`，全程未改一行代码）
>
> **Phase 1 的结束标准**（不是"挖完所有 bug"）：
> **我们是否已经知道现有架构在哪些机制层面必然失效，以及下一阶段要解决哪个瓶颈。**

---

## 证据总览

| 阶段 | 样本 | 性质 | 关键产出 |
|---|---|---|---|
| S1 | ZCode 293 MB | 真实软件 | semantic-role confusion（2 形态）· evidence dilution · evidence aggregation（understate）|
| S2 | WorkBuddy 302 MB | 真实软件 | library-source contamination · semantic-role（+3 形态）· understate 复现 |
| S3 | opencode 137 MB | 真实软件（开源）| coverage accounting · coverage-induced false reassurance · semantic-role（+7 形态）|
| S4 | 夸克网盘 258 MB | 真实软件（不同领域）| **首次出现漏报**：B1/B2/B3 三机制 |
| S5 | 6 个构造项目 | 正交机制实验 | **structural 补不了 lexical**（E4）· 等级离散化截断（E3）· scoring 双向出错（E5）|
| P0 | 21 个构造项目 | 边界测量 | discovery 边界比预期宽 · **semantic precision 严重不足** · invariance 成立 |

---

# 问题 1 · Discovery 的真实边界在哪里？

## 结论（有实测支撑）

```
边界位置：只有「代码里一个标准词都没有」时才真正失效。

d0 标准 API          likely    ✅
d1 自造 wrapper      likely    ✅   ← 内部仍调标准 API
d2 wrapper+部分直调   likely    ✅
d3 完全自定义 primitive absent  ❌   ← 唯一的失效点
d4 字符串拼接 API 名   possible  ⚠   降级但可见
d5 动态属性调用       possible  ⚠   降级但可见
d6 注册表/配置驱动     possible  ⚠   降级但可见
d7 间接 import/alias  likely    ✅
d8 库封装层          likely    ✅
```

**这修正了 S5 给人的印象**：E1/E4 之所以零命中，是因为构造时**连 `'aes-256-gcm'`
这类算法名都换掉了**。真实世界的混淆很少这么彻底。

## 但真正确认的边界不是"能不能看见"，而是"看见了也不能分辨"

**P0 的 B 组（same spelling / different behavior）**：

| 样本 | 真实语义 | 工具判定 |
|---|---|---|
| b1 | **真加密用户数据并外发** | likely（命中 4）|
| b2 | 只在测试代码里加密 | **likely（命中 4）** |
| b3 | 加密后**写本地文件，不联网** | **likely（命中 4）** |
| b4 | SDK 风格通用工具函数 | possible（命中 3）|

> **b1（真外发）与 b2/b3（完全不外发）判得一模一样。**

**所以 Discovery 的边界分两段：**

```
Recall 边界    : 相当宽（只有零标准词才失效）—— 不是主要瓶颈
Precision 边界 : 极窄 —— 只要用了标准 API，就一律当作「有该能力」
```

**Precision 问题更严重**，因为：
- discovery 失效只发生在极端写法上
- precision 失效发生在**日常代码**里（本地缓存加密、测试 fixture、SDK 工具函数到处都是）

## 边界外的真实事故（S4 佐证）

S4 的三个 B 类漏报说明"看见 ≠ 判对"：
```
工作区全量快照   0 命中            → B1 Discovery
信封加密        1 命中但 absent     → B2 Normalization
遥测上报        48 命中但 absent    → B3 Calibration
```

---

# 问题 2 · Semantic role 是否值得独立成为 evidence layer？

## 结论：值得，但它已经收集够了，**该进入修复而不是继续 discovery**

**证据**：`semantic-role confusion` 在 **5/5 个样本**中出现，
`direction` 全部是 `wrong-semantics`，**累计 14 种表现、1 个根因**：

```
S1  denylist（new Set）· CSP allowlist
S2  detector rule · SDK 数据结构 · UI props
S3  语法高亮模板 · 点文件清单 · key 一词多义 · BSL 语言模板 ·
    FormData API · 合法 FS 遍历 · DOM 遍历
S4  ARMS 探针排除规则 · mock 伪造响应头 · XML DOM API
P0（隐含）  同一 API 名在「外发 / 本地 / 测试」三种语义下不可分
```

**根因（已精确化）**：

> `lexical evidence without provenance / syntactic role / execution-context
> information is insufficient to infer capability semantics.`

**但继续找第 15 种形态已无边际价值。** 下一步该问的是：

> **「加入最小的 syntactic role / provenance 信息后，误报率能下降多少？」**

## 最小的 evidence role 分类（设计草案）

现有工具只输出「这个字符串出现了」。需要补的是**角色**：

```
Evidence role
├── declaration        声明（类型/接口/schema）
├── allowlist          允许列表
├── denylist           排除列表
├── detector_rule      检测规则
├── ui_display         UI 展示
├── test_only          仅测试
├── local_operation    本地操作（无出站）
├── active_operation   真实执行
└── unknown
```

**判据来源（不需要 AST）**，从便宜到贵：
1. **作用域位置**：是否在 `if (...)` 的 guard 子句里？
2. **数据结构形态**：是否在 `Set(...)` / 数组字面量 / 对象键里？
3. **文件路径**：`test/` `spec/` `__tests__/` → `test_only`
4. **是否存在配对的出站调用**（见问题 3）
5. **命名信号**：`NEVER_` / `deny` / `allow` / `skip`（已在 v0.2.6 做了 `NEGATIVE_CONTEXT`）

> **注意**：这一层**必须在 discovery 成功之后**才有输入（S5/E4 已证）。

---

# 问题 3 · Structural evidence 最小需要什么表达能力？

## 先纠正一个我之前说错的地方

S5 的 E4 证明了 **structural 不能替代 discovery**，
但 **不能**推出"structural 没价值"。两者关系是**硬依赖 + 顺序**，不是替代：

```
Layer 0 lexical discovery   ← 必须先行（E1/E4）
   ↓
Layer 1 semantic role       ← 当前严重不足
   ↓
Layer 2 structural relation ← 当前完全无法表达（这才是问题）
   ↓
Layer 3 reachability        ← 尚未证明必须
```

## 最小表达能力（三件事就够，不需要 AST/CFG）

**依据**：S1 与 S2 各自给出了一个真实的结构关系，**类型不同**：

| 来源 | 关系类型 | 代码 |
|---|---|---|
| S1 ZCode | `same-object`（同一对象字面量内的字段引用）| `maxBytes: t.encryptedArtifact.encryptedSizeBytes` |
| S2 WorkBuddy | `argument-flow`（返回值 → 实参）| `uploadToCos(created.cos_credential, ...)` |

**所以最小集是：**

```
1. same-object        同一对象字面量内的字段互引
2. argument-flow      某调用的返回值，作为另一调用的实参
3. same-call-chain    同一 class / 同一命名空间下的方法串联
```

**判据只需词法 + 括号配平**，例：
```
收集所有 `ident.field` 的 (ident, field) 对；
若 ident 的赋值来自调用的返回值，且 field 出现在另一调用的实参里 → argument-flow
```

> **这不需要 AST，更不需要 CFG。** 只需要"别名/赋值追踪 + 括号配对"。

## 但 E3 揭示了一个必须先修的阻断

**S5 的 E3（结构关系与 S1 同型，工具却 0 组合证据）**：

```
evidence existence  ──┬── possible (0.29)  →  「没有组合链」
                      └── likely   (0.30)  →  「阻断级组合链」
```

> **结构证据一旦进入组合引擎，会被上游的等级离散化提前截断。**

**所以在实现 Layer 2 之前，必须先拆掉这个离散化断裂** —— 否则
结构证据即使被表达出来，也会在 `possible → likely` 的边界上被吃掉。

---

# 问题 4 · Calibration / aggregation 应如何与 detection 解耦？

## 现状：它们耦合在一起，而且在两个方向都会错

**S4 与 E5 构成一组镜像**：

```
S4 遥测:   48 命中 → score  1.48 → absent   （压没）
E5 文档:    3 命中 → score 12.72 → likely   （报高）
```

**同一个 scoring 层，两个方向都错。**

**你的表述比我原来的更精确**：

> 当前 `scoring aggregation` 混合了「证据强度 / 证据数量 / 证据来源 / 类别权重」，
> 它们**没有统一的可解释语义**。

「更多 evidence ≠ 更强 verdict」本身不是 bug（安全评分本就该考虑 evidence quality）。
**真正的问题是：没有可解释、稳定、跨证据类型一致的质量维度。**

## 另外三个已定位的 calibration 缺陷

| 缺陷 | 证据 |
|---|---|
| **等级离散化截断** | E3：`0.29` 与 `0.30` 之间事实现象几乎没变，结论从"无"跳到"阻断级" |
| **尺度依赖** | E3/E0：组合链要求各环节达 `likely`，而可达证据量随样本规模变化 → 小样本永远凑不齐组合 |
| **归一化与覆盖冲突** | 补模式库会静默降级已有发现（权重和变大 → norm 变小，v0.2.5 已记录）|

## 解耦方向（设计草案，不实施）

```
detection      →  产出带「角色 + 来源 + 结构」标注的证据项（不再只有分数）
aggregation    →  按证据类别独立聚合（不混加）
calibration    →  显式输出「结论 + 置信度 + 覆盖率」，而不是单一等级
verdict        →  三态（有 / 无 / 证据不足），不再用连续分数硬切离散等级
```

> **关键**：`verdict` 需要第三态 **`证据不足`**。
> 现在 `possible → absent` 的跌落把"证据弱"和"证据无"混为一谈，
> 这正是 S4 的 B2/B3 与 E3 的共同病根。

---

# 问题 5 · 下一阶段走哪条？

## 候选

```
A. 更好的行为级 discovery       （解决 Recall 边界）
B. evidence model 重构          （解决 Precision + 角色 + 槽位）
C. 轻量结构解析                 （解决 same-object / argument-flow）
D. 完整静态数据流               （AST / CFG / reachability）
```

## 证据给出的排序

**S5 已证明：`data-flow` 不能替代 discovery。**
**但它还没有证明：`data-flow` 值不值得做。这两句话必须严格分开。**

按证据强度（Phase 1 实测）：

| 优先级 | 方向 | 依据 | 是否被证明必要 |
|---|---|---|---|
| **1** | **B. evidence model 重构** | P0-B：真外发与本地加密**无法区分**；S1/S2：结构关系**没有槽位**；S1–S5：14 种语义角色形态 | ✅ **最强** |
| **2** | **A. 行为级 discovery** | P0-D：边界比预期宽（只有零标准词失效）→ 收益有限但明确 | ⚠ 收益中等 |
| **3** | **C. 轻量结构解析** | S1/S2 给出两种真实关系；**但 E3 证明需先修离散化** | ⚠ 有价值，有前置条件 |
| **4** | **D. 完整静态数据流** | **无样本证明必须** —— 还没有"知道结构关系但仍需跨函数控制流"的案例 | ❌ **未证明必要** |

## 我的判断

> **下一阶段是 B（evidence model 重构），而不是 D。**
>
> 理由：Phase 1 收集到的所有问题 —— 14 种语义角色、真外发不可分、
> 结构关系无槽位、等级离散化截断、scoring 双向出错 ——
> **全部指向同一件事：证据的表示太贫乏。**
>
> 而 D 要解决的是"跨函数可达路径"，**Phase 1 没有任何样本证明这一层是必需的**。

**A 与 C 是 B 的自然延伸**：
- B 做对了，A 的 precision 部分自动改善（有角色可判"这个加密作用于什么"）
- B 做对了，C 才有地方放结构关系（有槽位可填）

## 明确不做的

```
❌ 继续收集 semantic-role 第 15 种形态      （边际价值已耗尽）
❌ 直接上 AST / CFG / data-flow            （未被任何样本证明必要）
❌ 宽化 pattern 白名单                      （P0-D 证明不是主要瓶颈）
❌ 调阈值                                   （E5 证明阈值高低都不是病根）
```

---

# Phase 1 收尾声明

**Phase 1 的目标已达成**：

> 我们**已经知道**现有架构在哪些机制层面必然失效，以及下一阶段要解决哪个瓶颈。

```
必然失效的机制（有实测证据）：
  · lexical token 无稳定语义角色              （5/5 样本，14 种形态）
  · 同一 API 名在不同行为下不可分              （P0-B，最严重）
  · 结构关系无表达槽位                        （S1/S2 两种真实关系）
  · 等级离散化截断结构证据                    （E3）
  · scoring 在两个方向都出错                  （S4 vs E5）
  · 完全自造实现零命中                        （D3；但边界比预期宽）
  · 技术性覆盖缺口造成假性安抚                 （S3）

瓶颈归属：
  Layer 0 Discovery        —— 不是主要瓶颈（边界宽）
  Layer 1 Semantic role    —— 严重不足
  Layer 2 Structural       —— 完全无表达能力
  Layer 3 Reachability     —— 未证明必要
  横切  Evidence model     —— ★ 所有问题的共同病根
```

**冻结可以解除，但下一阶段不应从"改代码"开始**：
先做 `evidence model` 的设计（数据结构 + 角色分类 + 三态 verdict），
**再**决定是否以及如何回到 Layer 2。

---

## 附：Phase 1 的可复跑资产

```
tests/dogfood/unpack.py        独立 asar 解包器（不 import agentegress）
tests/dogfood/look.py          上下文取景器（人工分析用）
tests/dogfood/make_s5.py       S5 六个正交样本生成
tests/dogfood/run_s5.py        S5 批量执行 + 矩阵
tests/dogfood/make_p0.py       P0 21 个边界样本生成
tests/dogfood/run_p0.py        P0 批量执行 + 四层记录
tests/dogfood/s5-orthogonal/   S5 样本本体
tests/dogfood/p0-boundary/     P0 样本本体
DOGFOODING-BASELINE.md         冻结记录
DOGFOODING-RESULTS.md          S1–S5 + P0 全部观察结果
```
