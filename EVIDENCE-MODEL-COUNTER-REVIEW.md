# Evidence Model · 反例审查（Counter-Review）

> **审查对象**：`Evidence Model Design`（Observation → Evidence → Relation → Assessment → Verdict）
> **审查方式**：拿 S1 / S2 / S4 / E3 / E5 五个**已知失败样本**逐一回放
> **审查标准**：不是"模型里有没有对应字段"，而是
> **「填充这个字段需要什么信息，而那个信息在这一层拿不拿得到」**
>
> 字段存在 ≠ 字段能被填上。**下面每一条都先给判定，再给理由。**

---

## 审查方法说明

对每个历史问题问四个问题：

```
① 新模型里哪个字段/层负责它？
② 填充该字段需要什么**新增信息**？
③ 那个信息**在当前（或本 Phase 2 计划内）拿得到吗**？
④ 判定：真正解决 / 部分解决 / 只是改名 / 新模型反而表达不了
```

**判定口径**：
- **真正解决** = 有确定的填充算法，且不依赖未实现的能力
- **部分解决** = 有算法但覆盖率有限，或需要人工兜底
- **只是改名** = 字段有了，但填充算法与旧实现等价（等于没变）
- **表达不了** = 模型里没有合适的位置，或与其他字段冲突

---

# 回放 1 · S1 ZCode

## 1.1 `new Set([".env","id_rsa","id_ed25519"])` 被判 `credential_access`

| | |
|---|---|
| 新模型槽位 | `Evidence.semantic_role = "denylist"` + `polarity = "contradicting"` |
| 填充需要 | 认出「`new Set([...])` 出现在文件名过滤位置」= **需要父节点/调用点信息** |
| 信息可得性 | ⚠ **部分可得**。纯文本也能做到弱版本：<br>· 命中点是否在 `Set(` / `[` 字面量内<br>· 附近是否有 `has(` / `includes(` / `filter(` / `skip` / `continue`<br>· 是否出现在 `if (...)` 的 guard 里 |
| 判定 | **部分解决** —— 比现在的 `NEGATIVE_CONTEXT`（纯词表）强，因为可以看**结构位置**。<br>但**仍然是启发式**：S3 的 `ssh-config` 语言模板也是「字符串列表」，<br>却既不是 denylist 也不是 allowlist，而是 **schema/声明**。 |

> **要害**：`denylist` 与 `declaration` 的区别**不在词，而在"这个集合被用来做什么"**。
> 判"被用来做什么"需要**看它的消费者**（谁调用 `has()`、在什么分支里）。
> **这已经越过了"词法 + 括号配对"的边界，进入了轻量的使用点分析。**
>
> → **这是对 P0 设计的一个额外要求**，模型文档里没有明说。

## 1.2 `encryptedArtifact.encryptedSizeBytes → objectUpload.maxBytes` 被降格为 `same_file`

| | |
|---|---|
| 新模型槽位 | `Relation.type = "same_object"`（confidence high）|
| 填充需要 | 解析**同一个对象字面量**的字段列表，并确认 `maxBytes` 的值表达式引用了 `encryptedArtifact.encryptedSizeBytes` |
| 信息可得性 | ✅ **完全可得**。只需括号/花括号配对 + 标识符提取，**不需要 AST** |
| 判定 | ✅ **真正解决**。这是新模型最扎实的一格。 |

## 1.3 ARMS 遥测端点（`log.aliyuncs.com/rum/...`）混入 `object_storage_upload` 证据

| | |
|---|---|
| 新模型槽位 | `Evidence.specificity = "low"` + `Capability Candidate` 只收 high/medium |
| 填充需要 | 判断 `aliyuncs.com` 这个 token 的**判别力** |
| 信息可得性 | ✅ **可得，但需要一张"判别力表"** —— 而这张表**本身就要人工维护**，<br>且会随服务商变化而过时（阿里云同时承载 RUM/APM/OSS）|
| 判定 | ⚠ **部分解决**。`specificity` 把问题**显式化**了（比现在闷在分数里好），<br>但**没有消除维护成本**——只是把"调权重"换成了"填判别力表"。 |

> **要点**：这条**不是"只是改名"**，因为显式化之后可以**按 capability 分别设门槛**，
> 而现在是所有模式共享一套分数。**但它也不是"解决"，因为依赖人工知识。**

## 1.4 S1 小结

| 问题 | 判定 |
|---|---|
| denylist 误判 | **部分解决**（且暴露了模型未说明的额外要求：使用点分析）|
| 结构关系被降格 | ✅ **真正解决** |
| 遥测混入 | ⚠ **部分解决**（显式化但未消除维护成本）|

---

# 回放 2 · S2 WorkBuddy

## 2.1 `"read" === Q.action && /\.ssh\/|id_rsa/` 被判「读取凭据」

| | |
|---|---|
| 新模型槽位 | `semantic_role = "detection_rule"` |
| 填充需要 | 认出「这个正则/字符串在一个**判定表达式**里，且判定对象是**别的进程的行为**」 |
| 信息可得性 | ⚠ **很难**。文本里能看到 `"read" === action`，但**要判断"这个 action 是谁的"**<br>需要追踪 `Q` 的来源 —— **这是数据流问题** |
| 判定 | ⚠ **部分解决（弱）**。<br>可做的弱版本：命中点附近出现 `<ident>.action`、`===`、`test(` → 提高 `detection_rule` 先验。<br>但**无法区分**"检测别人读取"与"自己读取并比较"。 |

> **要害**：`detection_rule` 与 `active_operation` 的区分，
> 有时**只差一个变量的来源**（`Q.files` 是自己扫的还是别人报的）。
> **这是 Phase 1 没有证明必要、但这个模型会自然导向的问题。**
>
> → **模型在这里隐含地需要 Layer 3（可达性/来源）**，
> 而 `PHASE-1-ARCHITECTURE-DECISION.md` 明确说 Layer 3 未被证明必要。
> **这是一个模型内部的不一致点，需要显式承认。**

## 2.2 `archiver` 库源码被判为应用能力

| | |
|---|---|
| 新模型槽位 | `provenance.kind = "bundled_dependency"` |
| 填充需要 | 判断"这段代码来自第三方库" —— 而**路径已经不可靠**（bundle 后是 `/main/module-base.js`）|
| 信息可得性 | ❌ **当前不可得**。<br>可用的弱信号：<br>· 文件里是否有 `webpack` 模块编号 / `__esm` / `defineProperty(exports`<br>· 是否有 `/*! ... */` 版权 banner<br>· 是否有 `package.json` 同名依赖声明<br>· 同一文件内是否大量出现某库特有的 API 名 |
| 判定 | ⚠ **部分解决（需要新的探测手段）**。<br>模型给了**正确的位置**，但**填充算法不存在**——<br>而且它**不能靠现有 56 个 pattern 解决**，需要引入"bundle 产物特征"这一类新检测。 |

> **这是审查里发现的第一处"模型正确但实现路径未定义"的地方。**
> 需要明确：`provenance` 的第一版**允许长期为 `unknown`**，
> 并在 Verdict 里体现（`provenance=unknown` → confidence 上限降低）。

## 2.3 `RepoConfigCard({ snapshotStatus, repoConfig })` 被判「快照采集」

| | |
|---|---|
| 新模型槽位 | `semantic_role = "ui_representation"` |
| 填充需要 | 认出"这是一组 **JSX/对象属性**，且属于 UI 组件" |
| 信息可得性 | ✅ **可得**。信号：<br>· 命中点在同一对象的**键位置**（`{ snapshotStatus, ... }`）<br>· 存在 `jsx` / `createElement` / `Component` / `props` 邻近<br>· 文件在 `renderer/` 且含 `React`/`createRoot` |
| 判定 | ✅ **真正解决**（有确定的启发式，误判率可控）。 |

## 2.4 S2 小结

| 问题 | 判定 |
|---|---|
| detection_rule 误判 | ⚠ **部分解决（弱）**，且**隐含需要 Layer 3** —— 模型未承认 |
| 库源码污染 | ⚠ 位置正确、**填充算法缺失**，且需新检测类别 |
| UI props 误判 | ✅ **真正解决** |

---

# 回放 3 · S4 夸克网盘（B1/B2/B3）

## 3.1 B1 · 工作区快照 0 命中

| | |
|---|---|
| 新模型槽位 | `Observation` 为空 → `Verdict = not_observed` |
| 填充需要 | 无（就是没看见）|
| 判定 | ✅ **解决**（正确表达为 `not_observed`，且 `coverage=observed` 时可以说"确实没观察到"）|

## 3.2 B2 · 加密 1 命中但 `absent`

| | |
|---|---|
| 新模型槽位 | `evidence_state = "observed_insufficient"` |
| 填充需要 | 无新增信息 —— **只是不再把"证据弱"折叠成"没有"** |
| 判定 | ✅ **真正解决**。这正是模型 §2.3 要修的东西。 |

## 3.3 B3 · 遥测 48 命中但 `absent`

| | |
|---|---|
| 新模型槽位 | `evidence_state = "observed_supportive"` + `Assessment` 给 confidence |
| 填充需要 | 无新增信息（48 条 Observation 已经在了）|
| 判定 | ✅ **真正解决**。 |

## 3.4 ⚠ 但 S4 暴露一个模型没覆盖的组合

S4 同时存在：

```
工作区快照  = not_observed（B1）
加密        = observed_insufficient（B2）
遥测        = observed_supportive（B3）
```

**三者混在同一个 verdict 里怎么呈现？**

旧模型：`已确认 2 / 疑似 0 / 弱信号 2` —— 已经有点说不清。

新模型：如果没有明确规定"**顶层 verdict 如何从多个 capability 的不同 state 合成**"，
就会退回到同样是拍脑袋。

| 判定 | ⚠ **模型缺一节：verdict 合成规则** |
|---|---|

> 建议补：顶层不要只给一个词，而是
> **「最高 capability state + 覆盖状态 + 存在未决项数」**三元组。

---

# 回放 4 · E3（结构关系存在，组合链不成立）

## 4.1 原始问题

```js
artifact.encryptedSizeBytes → req.contentLength     // 与 S1 同型
```
但 `object_storage_upload` 只有 `possible` → **0 组合证据**。

```
possible 0.29  →  「没有组合链」
likely   0.30  →  「阻断级组合链」
```

## 4.2 新模型的解法（§16）

> **Chain 直接消费 Evidence + Relation，而不是消费已离散化的 capability level。**

| | |
|---|---|
| 判定 | ✅ **设计上正确解决** —— 因为 `Relation` 独立于 `capability.level` 存在，<br>链的成立不再被 `possible→likely` 截断。 |

## 4.3 ⚠ 但引入了一个新的判定问题

链条成立现在由 `chain_confidence` 决定。**那 `chain_confidence` 怎么算？**

如果它内部还是要某个类似 `norm` 的东西，**离散化断裂只是从 capability 移到了 chain**。

| 判定 | ⚠ **风险：把问题搬家而不是消除** |
|---|---|

> **缓解要求**：`chain_confidence` 必须**显式列出它消费了哪些证据与关系**
> （即"可解释"），且**不允许**再出现一个隐式阈值把 `0.29/0.30` 切成两态。
> 建议用**分档枚举**（`weak/moderate/strong`）+ **列出理由**，而不是连续分数。

---

# 回放 5 · E5（纯注释/日志被判 `likely`）

## 5.1 原始问题

```js
const DOC = `telemetry: ... x-oss-signature: ... aliyuncs.com: ...`;   // 文档字符串
function log(msg) { /* telemetry telemetry telemetry */ }
```
→ 报 `object_storage_upload = likely` + 2 个 `possible`。

## 5.2 新模型槽位

- `Observation.region`（本来就有：`string` / `comment`）
- `Evidence.polarity = "neutral"`（注释/文档中的提及）
- `Evidence.specificity = "low"`（这些 token 判别力低）

| | |
|---|---|
| 填充需要 | 无新增信息（region 已在）|
| 判定 | ⚠ **部分解决** |

## 5.3 为什么只是部分

**E5 的 A 面**（`object_storage_upload` **是**由**字符串区**的 DOC 造成的）：

```
Observation.region = "string"      ← 文档字符串也是 string
```

**`region=string` 与"真的 URL 字面量"无法区分。** 需要额外的 `role` 判断：

```
DOC 里的 "aliyuncs.com"     → documentation 角色
真正 fetch('https://...')   → active_operation 角色
```

而判 `documentation` 需要**认出这是一个模板字符串赋给了 `DOC` 常量且从未被用于请求** ——
**又是使用点分析**（与 1.1 同一个要求）。

| 判定 | ⚠ **部分解决**，且**与 1.1 依赖同一个缺失能力** |
|---|---|

> **这是本轮审查最重要的模式发现** ——见下方"三处收敛"。

---

# 审查结论

## A. 真正解决的（4 项）

```
✅ 结构关系被降格为 same_file            → Relation.same_object
✅ B2 normalization（1 命中 → absent）    → evidence_state = observed_insufficient
✅ B3 calibration（48 命中 → absent）     → evidence_state = observed_supportive
✅ E3 等级离散化截断                      → Chain 改消费 Evidence/Relation
   └ ⚠ 但需防止问题搬到 chain_confidence
✅ UI props 误判                          → semantic_role = ui_representation
✅ B1 discovery（0 命中）                 → not_observed
```

## B. 部分解决的（5 项）

```
⚠ denylist / detection_rule / schema 的区分   —— 依赖「使用点分析」，模型未声明
⚠ 遥测混入（specificity）                      —— 显式化了，但依赖人工判别力表
⚠ 库源码污染（provenance）                     —— 位置正确，填充算法缺失
⚠ E5 文档字符串                                —— 与 denylist 同一缺失能力
⚠ detection_rule vs active_operation           —— 隐含需要 Layer 3
```

## C. 新模型反而没覆盖的（1 项，需要补）

```
❌ 顶层 verdict 如何从「多个 capability 的不同 evidence_state」合成
   （S4 同时有 not_observed / observed_insufficient / observed_supportive）
```

## D. ★ 三处收敛：同一个缺失能力

**这是本次审查最有价值的发现** ——以下三个问题表面无关，
但**都要求同一件现在没有的东西**：

| 问题 | 表面需求 | 共同需要 |
|---|---|---|
| denylist 判定（S1）| 知道集合被用来"排除" | **看它的使用点** |
| detection_rule 判定（S2）| 知道 action 是谁的 | **看变量来源** |
| documentation 判定（E5）| 知道 `DOC` 有没有被用于请求 | **看使用点** |

> 三者都指向：**「这个符号/字面量被谁消费了」**
>
> 这**不是** Layer 2（结构关系），也**不是** Layer 3（完整可达性）——
> 它是**一个很窄的中间层：使用点/消费者分析（use-site analysis）**。
>
> **模型文档里没有这一层**，但它的所有 `semantic_role` 判定都**隐含依赖**它。

**这直接修正了 PHASE-1 的层级图**：

```
Layer 0    lexical discovery
Layer 1a   semantic role          ← 需要下面这层才能填
Layer 1b   use-site / consumer    ← ★ 新发现，被模型隐含要求
Layer 2    structural relation
Layer 3    reachability
```

> 而 `1b` 的**成本远低于 Layer 3**：
> 只需"在一个文件内，追踪这个标识符/字面量出现在哪些调用/分支里"，
> **不需要跨函数、不需要 CFG**。

## E. 一句总结

> **模型在"表达层"是对的，在"填充层"缺了一层。**
>
> 具体说：新增的 `semantic_role` 是这个模型最有价值的字段，
> 但它的填充能力**全部依赖一个模型没有命名的层 —— 使用点分析**。
> 如果不把这层显式加进去，Phase 2 会实现出一堆**字段齐全但大部分填 `unknown`** 的结构，
> **看起来比现在更规范，判得并不更准**。

---

# 对 Phase 2 实现顺序的修正建议

原顺序（§19）：

```
P0 Evidence object → P1 Assessment/Verdict 分离 → P2 Relation →
P3 Chain → P4 calibration
```

**建议插入一层**：

```
P0   Evidence object（含 role / polarity / provenance 字段）
P0.5 ★ use-site / consumer analysis        ← 新增，是 P0 能填值的前提
P1   Assessment 与 Verdict 分离
P1.5 ★ 顶层 verdict 合成规则                ← 新增，S4 暴露的缺口
P2   Relation（same_object / argument_flow / same_call_chain）
P3   Chain（改消费 Evidence/Relation，且 chain_confidence 要可解释）
P4   calibration
```

**理由**：`semantic_role` 是模型的枢纽字段，而它的填充依赖 `P0.5`。
**如果 `P0.5` 不做，`P0` 产出的 Evidence 里 `role` 会大面积是 `unknown`**，
那后面的 `Assessment` 就没有比现在更多的信息可用。
