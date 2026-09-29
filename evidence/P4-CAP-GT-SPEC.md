# P4-CAP-GT v1 · Capability Ground Truth 规范

> **前置修正（比"标多少"更重要）**：
> **Capability GT 必须与现有 detection output 解耦。**
> 否则会形成循环校准：
> ```
> 工具说"有能力" → 人根据工具提示找证据 → GT 认为"有能力" → 再拿 GT 校准工具
> ```
>
> **另一条纪律**：
> **结构层的结果（2 个 FN 都来自 call_edge）不得外推成 capability 层也只有一个 gap。**
> ```
> 结构 relation 漏掉 ≠ capability verdict 必然漏掉
> 反过来也成立
> ```

---

## 一、GT 定义：四个独立事实（先冻结，再抽样）

Capability GT 不回答"这东西可疑吗"，
而回答一个机械问题：

> **在给定代码与执行上下文下，这段代码实际具备什么能力，
> 以及该能力是否形成可达链路。**

### 四个维度

| 维度 | 问题 | 取值 |
|---|---|---|
| **A. data_access** | 是否能取得目标数据？ | 0 / 1 |
| **B. data_handling** | 是否对目标数据进行了读取 / 聚合 / 编码 / 加密 / 打包？ | 0 / 1 |
| **C. egress** | 是否存在把该数据送出**本地信任边界**的实际路径？ | 0 / 1 |
| **D. reachable_chain** | A → B → C 是否在当前代码中存在足够证据形成**可执行链路**？ | 0 / 1 |

### 为什么不直接标 `malicious = yes/no`

```
四个维度分开标之后，才能回答：
    工具到底漏的是 access、handling、egress，还是 linkage？

而不是只知道"这里有个 FN"。
```

**由四维事实产生 capability class**（映射规则见第三节），
**而不是让 capability class 反过来去猜四维**。

---

## 二、第一批规模：24 个（6 strata × 4）

**目的不是统计代表性，而是 calibration discovery。**

| Stratum | 要测试什么 | 数量 |
|---|---|---|
| **S1** | 明确 capability-positive | 4 |
| **S2** | 明确 capability-negative | 4 |
| **S3** | data access 有、egress 无 | 4 |
| **S4** | egress 有、但与目标数据无结构联系 | 4 |
| **S5** | ★ legitimate upload / telemetry / APM 等边界 | 4 |
| **S6** | 结构复杂、需跨函数/跨模块才能确认 | 4 |

### ★ 为什么 S5 特别重要

**已经实际遇到**：
```
"危险能力存在"  ≠  "这是可疑 exfiltration"
```

`uploadToCos` 就是典型：**它真实具备网络上传能力，
但不能因为"存在上传"就自动成为 malicious / exfil verdict。**

**所以 capability calibration 第一阶段故意不讨论 maliciousness。**

---

## 三、Capability Class 映射（由四维事实产生）

```
access  handling  egress  reachable   →   capability_class
   1        1        1        1       →   full_chain_present
   1        1        1        0       →   capability_present_but_unlinked
   1        1        0        -       →   access_and_handling_only
   1        0        0        -       →   access_only
   0        -        -        -       →   absent
```

**注意**：`reachable_chain = 0` 时**不等于 capability absent** ——
它等于**"能力存在但链路未被证实"**。

> 这与 `unknown ≠ negative` 同源：
> ```
> 未证实链路  ≠  没有能力
> ```

---

## 四、★ 盲标流程（必须有，否则 GT 被 detector 污染）

```
Case
  ↓
取独立代码 / 上下文      ← **只读代码**
  ↓
Human GT annotation
  ↓
**冻结 GT**
  ↓
加载 candidate / evidence
  ↓
运行现有 capability logic
  ↓
比较
```

### 标注者在 GT 阶段**不能看到**

```
现有 relation
score
confidence
verdict
candidate_pairs
tool finding
```

**至少第一版必须这样。** 否则 GT 本身会被 detector 污染。

**对 AI 标注者的额外自律**：
第 5–7 次"检查写错"的教训说明，**看到的第一个数字会锚定判断**。
所以标注阶段**只读代码片段**，不运行任何 detector。

---

## 五、每个 GT 的最小记录

```yaml
case_id: CAP-01

data_asset:
  type:            # credential / user_content / workspace / telemetry / config
  sensitivity:     # high / medium / low / none

access:
  present: 0|1
  evidence: "..."          # 代码位置 + 片段（可复核）

handling:
  present: 0|1
  operations: [encrypt, pack, ...]

egress:
  present: 0|1
  destination: "..."       # 域 / 服务 / 本地
  mechanism: "..."         # http / spawn / file-write / ...

reachability:
  present: 0|1
  chain: "..."             # A→B→C 的具体证据

capability_class: ...      # 由四维产生（见第三节）

context:
  legitimate_context: "..."   # 有明确合法解释吗
  ambiguity: "..."

gt_confidence: high|medium|low

blocking_gap: none | missing_relation | missing_evidence | insufficient_context
```

### ★ 为什么必须保留 `blocking_gap`

**因为已经有经验了**：
```
"工具没建出来" 不能直接等于  "能力不存在"
```

`blocking_gap` 记录的是**"若是工具判错，最可能是哪一层的锅"** ——
但它**在 GT 阶段就标注**（基于代码本身的可分析性），
**不是事后归因**。

---

## 六、三种错误必须分开（P4 不能只算 overall accuracy）

```
FN              真实 capability 有  →  工具没识别
FP              真实 capability 没有 →  工具识别出来
Boundary error  能力确实存在，但工具把"能力"进一步解释成"可疑行为"   ★ 最重要
```

**Boundary error 的典型样本**：
```
legitimate upload · telemetry · APM · crash reporting · knowledge-base upload
```
这些可能都是 `egress = 1`，但
```
malicious / exfiltration = **不由此事实自动推出**
```

> **绝不能让 capability calibration 悄悄变成 intent calibration。**

---

## 七、★ ERROR_CLASS：强制分类（只有两类允许进调参讨论）

```
ERROR_CLASS =
    implementation       检测代码本身错
  | locator              候选/端点定位错
  | relation_schema      关系类型无法表达
  | evidence             证据未产生（采集问题）
  | capability_model     能力判定模型错
  | calibration          权重/阈值问题
  | verification         验证脚本 / 解读错
```

> **只有 `calibration` 和 `verification` 才允许进入「调参讨论」。**
> 其余五类都必须先用**非调参**手段处理。

**理由**：locator micro-fix 那轮已经证明 ——
**schema gap、locator gap、verification gap、calibration gap 是四种完全不同的问题。**
把它们混在一起，就会出现"参数其实没问题，是验证器解释错了"这类误判。

---

## 八、24 个之后**不要**马上调权重

先得到：

```
GT capability
    ↓
fixed evidence
    ↓
current capability output
    ↓
confusion matrix
```

**然后分类**：

| 情形 | 含义 | 处置 |
|---|---|---|
| **Case A** | FN 集中在同一 relation gap | 优先考虑 **coverage / schema / evidence path**，**不是调权重** |
| **Case B** | GT evidence 相同，但 score 常压不过阈值 | **才**进入 weight / threshold calibration |
| **Case C** | GT 说 capability present，但 evidence 本身不完整 | 归 **evidence acquisition problem**，不是 calibration problem |

---

## 九、★ Stop Condition（第一轮）

24 个案例满足以下五条即停，**不因看到单个 FN 就继续扩样本**：

```
① 所有 4 个 GT dimensions 都完成标注
② 至少存在明确 positive / negative / boundary
③ GT 与 detector output 可一一对应
④ 每个 FN / FP 都完成 root-cause 分类
⑤ 未发现新的、无法解释的 capability taxonomy
```

**然后才决定**：
```
A. 调 capability weights
B. 补 evidence path
C. 扩 GT 到 40~60
```

---

## 十、执行顺序

```
P4-CAP-GT v1
    ↓
冻结 capability taxonomy（本文件第一、三节）
    ↓
抽 24 个分层样本（6 strata × 4）
    ↓
盲标 4-dimensional GT
    ↓
跑 fixed detector（实现已冻结，见 P4-CALIBRATION-CHARTER.md）
    ↓
建立 FN / FP / boundary confusion matrix
    ↓
ERROR_CLASS root-cause 分类
    ↓
再决定是否值得 calibration
```

**这样不会解冻已冻结的 locator / relation 实现。**
