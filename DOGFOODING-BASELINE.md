# DOGFOODING BASELINE —— 冻结记录

> **开始时间**：2026-09-25
> **规则**：dogfooding 期间**不改代码**。发现问题只记录，不边扫边改。
>
> 理由（来自老大的判断）：
>
> ```
> 样本 A → 发现问题 → 改规则
> 样本 B → 发现另一个问题 → 再改
> 样本 C → 结果变了
> ```
> 最后无法判断：**是工具本来就有问题，还是我在测试期间改变了工具。**

---

## 冻结内容

| 项 | 值 |
|---|---|
| **commit** | `f561272` |
| **agentegress.py sha256** | `48B914A0B577F3C8EAC6306AFAB0DFF1B18B3B5E38EE40B8F352BCB2BF0F2EC7` |
| 版本号 | 0.2.2（`VERSION` 常量尚未随迭代递增——已记为待办） |
| 代码行数 | 3631 行（代码 2952 / 注释 306 / 空行 380） |

### 规则与权重（全部冻结）

| 项 | 值 |
|---|---|
| 能力类别 | 12 |
| 模式总数 | **56** |
| 预筛关键词 | 170 |
| 等级阈值 | confirmed `norm≥0.55 & patterns≥3 & files≥2`｜likely `0.30/2/1`｜possible `0.12/1/1` |
| 区域权重 | code 1.00 / string 0.85 / 注释 0.15 |
| 文件类别权重 | production 1.00 / config 0.90 / types 0.30 / test 0.25 / docs 0.15 / **vendor 0.10** / generated 0.10 / other 0.60 |
| vendor 强证据系数 | 门槛 `w≥8` → `0.80`（其余仍 0.10） |
| 负向上下文 | 因子 `0.15`，窗口 `±120` 字符 |
| 组合证据 | 6 条，成立条件「各环节 ≥ likely」 |
| `MAX_HEADER` | 32 MB |
| 单文件上限 | 8 MB |
| 指纹库 | 8 个工具 |

**dogfooding 期间以上任何一项被修改 → 本轮结果作废，必须重跑。**

---

## Gate 状态（措辞已按老大要求修正）

```
Release-prep Gate：通过
  ⚠ 已知缺口 1 项（xfail，不阻止进入 dogfooding）：
      · oss_export：object_storage_upload 在「用户主动导出 + 用户自配桶」场景判 likely
  语义：通过 = 可以安全进入 dogfooding 并知道如何记录未知；
        不等于质量已验收。
```

> **「测试系统通过」≠「产品能力无缺陷」。** 这两件事在本文件里必须分开记录。

---

## 本阶段的目标（不是 F1）

> **发现"以前设计时没有想到的失败模式"。**

比精确率、召回率更重要的是 **Novel failure mode**。

**结束条件**：连续若干个**结构明显不同**的真实样本，不再出现新的失败模式。
不是"跑够 10 个软件"。

**观察指标**：`Novel failure modes / sample` —— 这个比值开始下降，就是该收尾的信号。

---

## 样本清单（Phase 1）

| # | 样本 | 类型 | 路径 |
|---|---|---|---|
| S1 | ZCode | 真实客户端（有事件背景，高风险） | `refs/ZCode\resources\app.asar` |
| S2 | WorkBuddy | 真实客户端（本机主力工具） | `<WORKBUDDY_HOME>\resources\app.asar` |
| S3 | Kimi Work | 真实客户端（双 asar） | `<KIMI_WORK_HOME>\resources\app.asar` + `gateway.asar` |
| S4 | Cursor | 真实客户端（未装 asar？需确认） | `%LOCALAPPDATA%\Programs\cursor\resources\app.asar` |
| S5 | tmp_attack 构造样本 | 人工构造（红队留的） | `tests/review/samples/` |

---

## 三遍观察法（老大定的）

### 第一遍 · 完全不看 AgentEgress，建立 Ground Truth

对每个样本回答 9 个问题，每项 `YES / NO / UNKNOWN`：

```
1. 是否存在工作区读取？
2. 是否存在敏感文件读取？
3. 是否存在归档？
4. 是否存在加密？
5. 是否存在外部网络 sink？
6. 是否存在对象存储？
7. 是否存在自动触发？
8. 是否存在明确的数据关联证据？
9. 是否存在明显的合法业务解释？
```

**不要先写"它是不是恶意"。**
**不要**把「安全意图」与「恶意/非恶意」混在一起——`oss_export` 已经踩过这个坑。

### 第二遍 · 跑 AgentEgress，做差分

分类**不止** TP/FP/FN，多一类：

| 类 | 含义 |
|---|---|
| **A 检测正确** | 人工 YES ↔ 工具 confirmed |
| **B 检测漏报** | 人工 YES ↔ 工具 absent |
| **C 检测误报** | 人工 NO ↔ 工具 likely |
| **D 解释错** | 证据存在、事实正确，但**语义赋予错了**（`oss_export` 属此类）|

**D 类对 AgentEgress 尤其重要**——它检测到了真实技术事实，但给事实赋予了错误含义。

### 第三遍 · 专门攻击"不一致"

出现分歧时**不立即修**，先按 8 类归因：

```
representation failure          表示层
prefilter failure               预筛
pattern failure                 模式
evidence aggregation failure    证据聚合
provenance failure              来源追踪
context failure                 上下文
semantic interpretation failure 语义解释
reporting failure               报告
```

---

## Phase 1 的唯一产出

`DOGFOODING-RESULTS.md`，每个样本记录：

```
样本
├── Ground Truth
├── AgentEgress Output
├── Disagreements
├── Failure Class
├── Reproducible?
└── Action
      ├── Fix
      ├── Known Gap
      ├── Won't Fix
      └── Need More Evidence
```

**第一轮不改代码。** 等跑完再决定下一阶段走静态数据流，还是维持轻量侦察器——
**这一点不预判。**

---

## 纪律（必须遵守）

遇到分歧时，第一反应**不是**"我要加一个负向上下文"，而是：

> **"这里到底缺的是上下文、来源、可达性，还是目的地归属？"**

否则会掉进这个循环：

```
漏报/误报 → 新规则 → 新例外 → 规则更多 → 维护复杂度上升 → 新误报
```

**不要为了让工具"看起来更准"而修。**
