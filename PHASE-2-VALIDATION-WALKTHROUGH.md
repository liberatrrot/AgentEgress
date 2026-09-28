# Phase 2 关键验收：86% unknown 下，新模型是否真的更可靠？

> **被验收的问题（老大定的）**：
> **在 86% `role = unknown` 的情况下，Evidence Model 是否仍然可以
> 比当前 AgentEgress 给出更可靠、可解释的结论？**
>
> **方法**：纸面推演。逐样本把当前结论与「按 Evidence Model 规则推演的结论」并列比较。
>
> **⚠ 声明**：这是**推演，不是实现**。`agentegress.py` 未改动（冻结仍有效）。
> 推演依据是 `_s1_tool.json` / `_s2_tool.json` / `_s4_tool.json` 里的**原始证据**，
> 加上 Phase 2 设计规则（`PHASE-2-EVIDENCE-MODEL-DESIGN.md`）。

---

## 判定标准（四条）

```
① 是否消除了 Phase 1 已确认的误报/漏报
② 在 role=unknown 时，是否避免了"折叠成 absent"
③ 结论是否可解释（能列出依据）
④ 是否引入了新的误判
```

---

# 推演 1 · S1 ZCode

## 当前 AgentEgress

```
CRITICAL · 确认存在高危外传能力 · 已确认 7 / 疑似 5
[阻断级] 工作区采集 + 加密 + 对象存储直传
[阻断级] 凭据文件读取 + 外传通道
[CONFIRMED] 凭据文件访问 3模式/5文件/15命中
```

## Evidence Model 推演

**证据重判**（依据 P0.5 已实测的 4 类可靠 role）：

| 当前能力 | 原始证据 | 推演的 role | status | 效果 |
|---|---|---|---|---|
| `credential_access` | `bct = new Set([..., "id_rsa", ...])` + `bct.has(r)` + `a(_ct,"looksLikeSecretPath")` | **`denylist`** | observed | **polarity = contradicting** |
| `object_storage_upload` | `buildOssFormFields` 被调用包裹 | `active_operation` | observed | supporting |
| `envelope_encryption` | `createCipheriv(...)` 被调用包裹 | `active_operation` | observed | supporting |
| `workspace_snapshot` | 同 `bct`（同一排除集合）| **`denylist`** | observed | **contradicting** |

**链条推演**：

```
[工作区采集]  →  polarity = contradicting      ┐
[加密]        →  supporting                    ├→ 链不成立（首环为反驳证据）
[对象存储直传] →  supporting                    ┘

[凭据文件读取] →  polarity = contradicting     ┐
[外传通道]     →  supporting                    ┘→ 链不成立
```

**推演结论**：

```
capability: object_storage_upload   →  supported（证据充分）
capability: envelope_encryption     →  supported
capability: credential_access       →  contradicted（被 denylist 反证）
capability: workspace_snapshot      →  contradicted
chain:      （无阻断级链）

顶层 verdict:
    最高 state  = supported
    coverage    = observed
    未决项      = 3（受 denylist 影响的项）
```

## 判定

| 标准 | 结果 |
|---|---|
| ① 消除已知误报 | ✅ **消除了「凭据读取」误报**（人工 Ground Truth 确认 `.ssh/` 0 处）|
| ② unknown 不折叠 | ✅ `bct` 未落入 unknown（走 ② 路径 + 命名信号）|
| ③ 可解释 | ✅ 每条都能列出 basis |
| ④ 新误判 | ⚠ 需注意：`denylist` 的 admission 依赖 `looksLikeSecretPath` 这一**命名信号**，<br>若该信号消失则退回 unknown（**至少不会误报**）|

**→ 比当前结论更可靠。** 当前工具把「排除名单」读成了「读取凭据」，新模型把它变成**反驳证据**。

---

# 推演 2 · S2 WorkBuddy

## 当前 AgentEgress

```
CRITICAL · 确认存在高危外传能力
[CONFIRMED] 凭据文件访问 4模式/17文件/59命中
[CONFIRMED] 批量打包 5模式/27文件/87命中
[LIKELY] 工作区全量快照 3模式/4文件/17命中
```

## Evidence Model 推演

| 当前能力 | 原始证据 | 推演 | 效果 |
|---|---|---|---|
| `credential_access` | `"read"===Q.action && /\.ssh\|id_rsa\|.../` | **`detection_rule`** | **contradicting** ✅ |
| `bulk_archive` | `archiver` 库源码（`module-base.js`）+ 遥测 gzip + **1 条真实 `tar.create`** | provenance = **unknown**（bundle 后路径不可靠）<br>role = unknown | **不提供证据，但也不否认**（保留为 `observed_insufficient`）|
| `workspace_snapshot` | `RepoConfigCard({ snapshotStatus })` | `ui_representation` → **正式接受 unknown** | 不提供证据；**不判 absent** |

**推演结论**：

```
credential_access  →  contradicted（被 detection_rule 反证）
bulk_archive       →  observed_insufficient（有真实证据但也有库污染，provenance 无法判定）
workspace_snapshot →  unknown（该维度不提供证据，其他维度独立计算）

最高 state = observed_insufficient
```

## 判定

| 标准 | 结果 |
|---|---|
| ① 消除误报 | ✅ 凭据误报消除 |
| ② unknown 不折叠 | ✅ `provenance=unknown` **没有**导致 `bulk_archive` 被判 absent |
| ③ 可解释 | ⚠ **部分**：`bulk_archive` 只能解释为"混有库证据，无法区分"，说不出更细的 |
| ④ 新误判 | ⚠ **风险**：`workspace_snapshot` 判定为 unknown 后**不再出现在结论里**，<br>而 S2 的 Ground Truth 里工作区快照**确实可能是真的**（需人工确认）|

**→ 比当前结论更可靠，但有一个新的不对称**：
> 当前工具**误报**（把 UI props 当成采集）；
> 新模型**不报**（unknown 不提供证据）。
> **从"错误的肯定"变成"沉默"** —— 按 §一 的纪律这是正确的，
> 但**必须让读者知道"这里有一项我们没判断"**，否则又变成另一种 coverage blind spot。

**→ 需要在顶层 verdict 里显式输出「未决项数」（§九 已设计）。**

---

# 推演 3 · S4 夸克网盘（★ 改进最大）

## 当前 AgentEgress

```
确认存在高危外传能力 · 已确认 2 / 疑似 0 / 弱信号 2
未检出: 信封加密、遥测上报          ← 三个 B 类漏报
```

## Evidence Model 推演

| 能力 | 当前 | 推演 | 效果 |
|---|---|---|---|
| `envelope_encryption` | **absent**（1 命中）| **`observed_insufficient`** | ✅ **不再折叠成"没有"** |
| `telemetry_egress` | **absent**（48 命中！）| **`observed_supportive`** | ✅ **大幅纠正** |
| `workspace_snapshot` | **absent**（0 命中）| `not_observed`（coverage 正常）| 正确 |

**推演结论**：

```
envelope_encryption → observed_insufficient（1 命中，证据不足以定级）
telemetry_egress    → observed_supportive（48 命中）
workspace_snapshot  → not_observed
```

## 判定

| 标准 | 结果 |
|---|---|
| ① 消除漏报 | ✅ **三个 B 类全部纠正**（B2/B3 变 `observed_*`；B1 保持 not_observed 但理由明确）|
| ② unknown 不折叠 | ✅ **这是最直接的收益** |
| ③ 可解释 | ✅ 能说出"有 N 处命中但未达阈值" |
| ④ 新误判 | 无明显新增 |

**→ 这是五个样本里改进最显著的一个。**
**而且这个改进完全不依赖 `semantic_role`** —— 它来自 §一（unknown ≠ negative）
与 §2.3（三态 evidence_state）。

---

# 推演 4 · E3 结构关系

## 当前

```
envelope_encryption    likely    3 命中
object_storage_upload  possible  2 命中
组合证据: 无                    ← 被 possible→likely 的离散断裂截断
```

## 推演

```
Relation:
    same_object:  artifact.encryptedSizeBytes → req.contentLength
                  （只需括号配对 + 标识符提取，判定 high confidence）

Chain 推演:
    Chain 直接消费 Evidence + Relation，不经过 capability.level 离散化
    → workspace evidence + encryption evidence + upload evidence + structural relation
    → chain_confidence = moderate/strong（可解释：列出了 4 项依据）
```

## 判定

| 标准 | 结果 |
|---|---|
| ① 消除缺陷 | ✅ 结构证据不再被 `possible` 截断 |
| ② — | — |
| ③ 可解释 | ✅ 链条能列出参与的证据与关系 |
| ④ 新误判 | ⚠ **风险已记录**：若 `chain_confidence` 内部又是连续分数 + 隐式阈值，<br>**离散化只是从 capability 搬到了 chain**。<br>设计已约束为「分档枚举 + 列出理由」（§九 P3）|

**→ 解决了，但带一个必须守住的约束。**

---

# 推演 5 · E5 纯注释

## 当前

```
object_storage_upload  likely    3 命中   ← 误报
workspace_snapshot     possible  1 命中
telemetry_egress       possible  2 命中
```
（代码里**只有文档字符串和日志**，没有任何实际能力）

## 推演

```
Observation.region = string（模板字符串）
role = documentation（可靠类）
  basis: ["命中在字符串常量区", "所在语句仅被日志消费"]
polarity = contradicting
→ 不产生 supporting evidence

推演结论：三个 capability 全部 not_observed（或 unknown）
```

## 判定

| 标准 | 结果 |
|---|---|
| ① 消除误报 | ✅ |
| ② — | — |
| ③ 可解释 | ✅ |
| ④ 新误判 | 无 |

**→ 解决。**

---

# 汇总

| 样本 | 当前问题 | 推演后 | ①消除 ②不折叠 ③可解释 ④新误判 |
|---|---|---|---|
| **S1** | 凭据读取误报 | 变成**反驳证据** | ✅ ✅ ✅ ⚠(依赖命名信号) |
| **S2** | 凭据/UI/库污染 | 凭据消除；库与 UI 转 unknown | ✅ ✅ ⚠(库解释弱) ⚠(沉默需显式标注) |
| **S4** | 三个漏报 | **B2/B3 变 `observed_*`** | ✅ ✅ ✅ ✅ |
| **E3** | 离散化截断 | 链条成立 | ✅ — ✅ ⚠(需守约束) |
| **E5** | 注释误报 | 反驳证据 | ✅ — ✅ ✅ |

## ★ 核心发现

**五项改进中，最大的两项（S4 的三态、E3 的 Relation 独立）完全不依赖 `semantic_role`。**

```
S4 的改进 ← §一 unknown ≠ negative  +  三态 evidence_state
E3 的改进 ← Relation 独立于 capability.level
S1/S2/E5 的改进 ← P0.5 那 4 类可靠 role（恰好覆盖了最大的误报来源）
```

> **这解释了为什么 14% 的覆盖率够用**：
> **P0.5 的 14%，恰好落在 Phase 1 里误报最集中的那几族上**
>（名单类 `denylist`、检测规则类 `detection_rule`、文档类 `documentation`）。

## 但必须承认三个风险

```
① S2 的「沉默」风险
   当前把 UI props 误报为采集；新模型变成 unknown（不提供证据）
   → 从"错误的肯定"变成"沉默"
   → **必须在顶层 verdict 显式输出「未决项数」**，否则是另一种 coverage blind spot

② provenance 的解释力仍然弱
   bulk_archive 只能解释为"混有库证据，无法区分"
   → provenance 的填充算法仍缺失（反例审查已记录）

③ chain_confidence 的搬家风险
   若它内部仍是连续分数 + 隐式阈值，离散化只是从 capability 移到 chain
   → 约束：必须分档枚举 + 列出理由
```

## 结论

> **回答验收问题：是的，在 86% `role = unknown` 的前提下，
> Evidence Model 仍然能给出更可靠、更可解释的结论。**
>
> **但可靠性提升的主要来源不是 `semantic_role`，而是：**
> ```
> ① unknown ≠ negative（三态 evidence_state）
> ② Relation 独立于离散化等级
> ③ 四类可靠 role 恰好覆盖最大误报族
> ```
>
> **这个结论有一个前提必须写明**：以上是**纸面推演**。
> 真正的验证要在 P0/P1 实现之后，用同一批样本重跑并对比。

## 与「新模型没有实质差异」的对照

预先承认那个可能性（设计文档 §十）：

```
若推演结果显示「在 86% unknown 前提下，新模型结论与旧模型没有实质差异」
→ 那么 Evidence Model 的重构价值需要重新评估
```

**本推演的结果是：五个样本全部出现实质差异，且方向一致（减少误报、消除漏报）。**
**所以这个可能性没有成立 —— 但它是靠推演排除的，不是靠实现。**
