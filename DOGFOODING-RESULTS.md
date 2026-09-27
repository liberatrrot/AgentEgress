# DOGFOODING RESULTS · Phase 1

> 冻结基线：commit `f561272`，`agentegress.py` sha256 `48B914A0...F2EC7`  
> 期间**未修改任何代码 / 规则 / 权重 / 阈值**（见 `DOGFOODING-BASELINE.md`）  
> 方法：三遍观察法 —— ① 完全不看工具建立 Ground Truth ② 跑工具做差分 ③ 攻击"不一致"并归因

**目标不是 F1，是发现"以前设计时没想到的失败模式"。**

---

# 记录标准 v2（S2 后修订）

## 指标拆成两个（**取消主观权重**）

旧写法 `S1 = 4.0 / S2 = 1.5` 里的 `0.5` **没有可重复定义**——  
以后"又来一种新形态算几分"会变成拍脑袋，指标也就失去统计价值。

**改为两个独立指标：**

| 指标                        | 定义                            | 回答的问题            |
| ------------------------- | ----------------------------- | ---------------- |
| **Root-cause novelty**    | 每个样本引入的**新 failure class** 数量 | 发现了多少**新的根因**    |
| **Manifestation novelty** | 按 class 分组记录**表现形态**          | 同一根因有多少种**承载形式** |

```
Root-cause novelty
  S1 = 4   （semantic-role / pattern / evidence dilution / evidence aggregation）
  S2 = 1   （library-source contamination）

Manifestation novelty
  semantic-role confusion:
    S1  denylist · CSP allowlist
    S2  detector rule · data structure · UI display
```

## 每条分歧新增两个字段

```python
systemic_candidate: bool      # 「首次发现」与「已重复验证」是两个不同维度，
                              # 不能只靠 novelty 计数判断
structural_relation: str      # 当 structural 达到 moderate/strong 时必填：
                              #   same-object / argument-flow / return-value /
                              #   property-flow / call-chain / import-relation
```

## S2 的 CRITICAL **不判为误报**（新增观察维度）

Ground Truth 认定 `uploadToCos` 有明确合法业务解释（知识库上传），  
但工具给 CRITICAL。**这不等于误报**——程序确实  
`读用户数据 → 加密/处理 → 取临时凭证 → 上传 COS`，能力是真的。

真正的问题是：**「能力严重度」与「安全可疑程度」混在了一起。**

所以新增三个观察维度（**暂不改风险等级**）：

```
Capability impact         能力本身有多重
Evidence confidence       证据有多强
Business-context evidence 是否存在明确合法解释
```

> 这背后是一个**产品定位问题**，现在不选：
> **AgentEgress 评价的是「危险能力」，还是「可疑外传行为」？**
> 若是前者，S2 的 CRITICAL 可能是对的；若是后者，它明显过重。

---

# 中期裁判（S3 后）

## 四档分类 —— 不能都写成 "systemic"

| 发现 | 当前判断 | 信心 |
|---|---|---|
| `semantic-role confusion` | **strong systemic candidate** | 高，但受采样污染影响 |
| `evidence aggregation` 对强结构关系的低估 | **strong systemic candidate** | **很高**（2 个独立真实软件、2 种不同结构关系）|
| `library-source contamination` | 真实缺陷，**尚未证明系统性** | 中 |
| `coverage accounting` / **`coverage-induced false reassurance`** | **真实且严重** | 高；"系统性"待更多样本 |

## 三条必须修正的表述

### ① `3/3 samples` 要降级

```
3/3 observed  ≠  3 independent confirmations
```

S1 之后我已经知道"排除列表 / allowlist / 检测规则 / UI / schema…"都可能是陷阱，
S2/S3 的人工分析必然主动去找。**独立性受自适应采样限制。**

正式写法：
> `strong systemic candidate; observed in 3/3 samples;
> independence limited by adaptive sampling.`

> 但这**没有削弱到"只有一点迹象"**——因为不是重复找到同一个字符串陷阱，
> 而是在**不同程序、不同代码结构、不同语义载体**中反复找到同一根因。

### ② 根因描述要加维度

原表述 `lexical evidence is insufficient to infer semantic role` 不完整。更准确：

> **`lexical evidence without provenance / syntactic role / execution-context
> information is insufficient to infer capability semantics.`**

因为暴露的问题实际包含三层：
```
字符串是什么
    ↓
它在代码中扮演什么角色
    ↓
这段代码是应用行为 / 库实现 / UI 描述 / 检测器
```

### ③ `evidence aggregation` 不是"算低了"，是"没有槽位"

```
strong evidence（S1 的 object/property relation，S2 的 argument/return relation）
    ↓
现有 evidence model 根本没有表达这些关系的槽位
    ↓
被迫降级成 same_file
```

**这不是关联度算法不好，是数据结构缺一层。**
→ **高优先级架构候选**，不是普通规则缺陷。

## Coverage 要记三个维度（不能只看文件数）

```
S1  23270 → 2731 → 309
S2  18460 → 1327 → 602   7 个 large-file gap
S3   6699 →  841 → 645   1 个 large-file gap
```

**单看 "S2=7 gaps / S3=1 gap" 会完全误导** ——
S3 的那 1 个文件就是 **33.1 MB 的核心 bundle**。

Phase 1 内**手工补记**（冻结期不改实现）：
```
file coverage              文件数覆盖
byte coverage              字节覆盖
eligible-code coverage     可分析代码覆盖
largest-unseen-unit        最大的未分析单元        ← S3 = 33.1 MB
```

## `coverage-induced false reassurance`（独立命名）

比 `coverage accounting failure` 更准确。**危害在于非单调关系：**

```
更多代码被分析  →  更多证据  →  风险可能上升
更少代码被分析  →  更少证据  →  风险可能下降
```

> **当前风险等级不是「程序风险」的单调函数，而是「程序风险 × 可见度」的函数。**

S3 的 opencode 就是这个形态：33.1 MB 核心逻辑未扫，报告只给 medium，
**看起来比 ZCode/WorkBuddy 温和，但实际上它 99.5% 的代码没进分析**。

## Layer 框架（判断"要不要上 data-flow"的正确问法）

问题已被重新定义为：

> **「从纯 lexical evidence 往上增加哪一层信息，能最大程度减少当前真实样本暴露出的错误？」**

```
Layer 0  lexical evidence                    ← 已证明不够（S1/S2/S3）
Layer 1  semantic / provenance role          ← 有真实需求
Layer 2  structural relation                 ← 有真实需求（S1/S2）
Layer 3  reachability / data-flow            ← **暂时没有被证明必要**
```

**Layer 3 未被证明必要**，因为还没有样本证明：
> 「已经知道结构关系，但仍需要真正的跨函数控制流/数据流才能判断」

**所以绝对不要因为"出现 strong structural"就立刻上 CFG/data-flow。**

## Ground Truth 记录扩展（不改冻结流程，只加记录字段）

```
YES / NO / UNKNOWN / YES(weak) / YES(strong)
ground_truth_revision = tool-assisted        # 被工具证据推翻过的，标记出来
```

未来回看时能区分「人工直接判断」与「相互审查后的判断」。

## 独立性受限的其他证据源

**opencode 是开源的**，可以对照上游真实源码。但**不用它改变 Ground Truth**，
而是留到 Phase 1 之后回答：
> **bundle provenance 到底能不能恢复？**（`source file ↕ bundle location` 是否有稳定映射）
> 这可能直接决定 `library-source contamination` 后面要不要做。

## S4 的四个研究假设（不再"平均地看十个问题"）

```
H1  semantic-role confusion 是否持续
    → 不主动只找已知 12 类；仍按正常流程，盲差分时检查「这条 evidence 的真实角色是什么」

H2  strong structural relation 是否第三次出现
    → 记录关系类型：same-object / argument-flow / return-value /
                    property-flow / call-chain / import-relation

H3  library-source contamination 是否复现
    → 关注 bundled SDK / crypto / HTTP client / uploader / compression library

H4  coverage-induced false reassurance 是否有第二个实例        ← 本轮最想看
    → 不只问"有没有大文件没扫"，还问「大文件没扫时，风险结论是否系统性变温和」
    → 直接比较：unseen code importance  vs  reported severity
```

**S5（`tmp_attack`）彻底从"发现问题"的指标里剥离** ——
它只用于**验证 S1–S4 形成的假设能否被主动构造攻击复现**。

## Phase 1 最终产出：矩阵

| Root cause | S1 | S2 | S3 | S4 | 独立性 | 状态 |
|---|:-:|:-:|:-:|:-:|---|---|
| semantic-role confusion | ✓ | ✓ | ✓ | ? | 受污染 | systemic candidate |
| evidence aggregation（understate）| ✓ | ✓ | — | ? | 较高 | systemic candidate |
| library-source contamination | — | ✓ | ? | ? | 中 | pending |
| evidence dilution | ✓ | — | ? | ? | 中 | pending |
| coverage accounting | — | — | ✓ | ? | 较高 | pending |
| coverage-induced false reassurance | — | — | ✓ | ? | 较低 | pending |

> **判断没有改变方向**：继续 S4，不修。
> 但重点从"继续找 bug"升级成"**验证这些 failure class 是否真的构成架构边界**"。
>
> 最值得期待的不是再发现第 13 个 semantic-role 变体，
> 而是看看 **S4 会不会出现第三个 `strong structural`，
> 以及第二个 `coverage-induced false reassurance`。**

---

## coverage loss reasons 要分类统计

```
候选 23270 → 读到 2731 → 真正跑正则 309     (S1)
候选 18460 → 读到 1327 → 真正跑正则 602     (S2，另有 7 项技术缺口)
```

这已不是报告优化问题，而是研究变量：**检测器最终看到的代码量，与实际代码量差多少？**

必须区分：

```
pattern failed            ← 规则没命中
pattern never got to run  ← 文件根本没跑到正则
```

**这两个是完全不同的问题**，混在一起谈"漏报率"没有意义。

Phase 1 后期按原因归类：

```
prefilter / file size / encoding / unsupported archive / third-party / generated / other
```

## Ground Truth 被推翻时的记录规则

S2 出现的正当流程（**保留，不回改**）：

```
第一遍：Q3 = NO（倾向）           ← 人工判断
工具证据：server.js:167746 tar.create(...)   ← 新证据
修正为：Q3 = YES
记录：谁推翻了谁 + 基于什么新证据
```

**不回头覆盖第一遍** —— 否则就看不出"三遍流程真的在相互审查"。  
流程已从 `人工裁判 → 工具考试` 变成 `独立证据 A ↕ 独立证据 B → 相互审查`。

## S5 放最后

```
S1 ZCode / S2 WorkBuddy / S3 Kimi / S4 Cursor  ← 真实世界自然分布
S5 tmp_attack                                  ← 已知构造样本，易受知识污染
```

S5 适合做**假设验证**，不适合作为**发现新模式**的主要证据。

---

# S1 · ZCode（`refs/ZCode\resources\app.asar`）

293.6 MB / 26785 条目 / 自研代码 4129 条（其余是 node_modules）

## 第一遍 · Ground Truth（独立建立，未参考工具）

**工具**：独立写的 `tests/dogfood/unpack.py`（不 import agentegress）+ `look.py`  
（只在 minified 代码里定位关键词并打印上下文，判断由人做出）

| #  | 问题         | 判定         | 人工依据（文件:行 + 原文）                                                                                                                                                                                                                                                                                          |
| -- | ---------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Q1 | 工作区读取      | **YES**    | `out/scheduler/index.js:832` `conversationWorkspaceRoot`；`repoSnapshot` 全库 80 处                                                                                                                                                                                                                          |
| Q2 | 敏感文件读取     | **NO**     | `.ssh/` **0 处**；`NEVER_` **0 处**。反证见下方分歧 1                                                                                                                                                                                                                                                               |
| Q3 | 归档         | **YES**    | `out/host/index.js:477` `import{createGzip as Bst}from"zlib"`；`:479` `a(Vst,"writeGzipTarToPath")`                                                                                                                                                                                                       |
| Q4 | 加密         | **YES**    | `out/host/index.js:477` 同时 import `createCipheriv` **与 `publicEncrypt`** → 信封加密（非对称包裹对称密钥）                                                                                                                                                                                                               |
| Q5 | 外部网络 sink  | **YES**    | `undici` 的 `fetch`；`zcode.z.ai`；`*.aliyuncs.com`                                                                                                                                                                                                                                                         |
| Q6 | 对象存储       | **YES**    | `out/host/index.js:332` `a(Iot,"buildOssFormFields")`，构造完整 OSS PostObject 表单（`x-oss-signature`/`policy`/`x-oss-credential`）                                                                                                                                                                              |
| Q7 | 自动触发       | **YES**    | `out/scheduler/index.js:834` `Hn("info","cron scheduler started")` + `DP=setInterval(NP,uBe)`；上下文含 `off-peak recoverInterrupted`                                                                                                                                                                         |
| Q8 | **数据关联证据** | **YES（强）** | `out/host/index.js:487`：`objectUpload:{url:r.oss.host, maxBytes:Math.max(t.encryptedArtifact.encryptedSizeBytes,1), formFields:{...}}` —— **加密产物的字节数直接作为上传表单的 maxBytes**，同一对象字面量内。同文件另有 `class RepoSnapshotUpload` / `uploadPostObject` / `uploadPutObject` / `consumeUploadCredential` / `uploadObject` |
| Q9 | 合法业务解释     | **部分**     | 遥测（ARMS RUM / APM）是标准做法；快照上传有 2026-09 事件背景                                                                                                                                                                                                                                                               |

**Q9 的克制说明**：本栏**不判"是否恶意"**。按基线文件的要求，  
「安全意图」与「恶意/非恶意」必须分开——`oss_export` 已经踩过这个坑。

## 第二遍 · AgentEgress 输出（冻结版）

```
风险等级 [CRITICAL] · 确认存在高危外传能力 · 已确认 7 / 疑似 5 / 弱信号 0
覆盖台账: 候选 23270 -> 读到 2731 -> 真正跑正则 309
  关键词预筛未通过 2422 个
因技术原因未覆盖: 0 项

[CONFIRMED] 信封加密 6模式/8文件/31处      触发:未判定
[CONFIRMED] 跨工作区配置采集 5/16/111      触发:自动
[CONFIRMED] 工作区全量快照 4/15/73         触发:自动
[CONFIRMED] 凭据文件访问 3/5/15            触发:未判定
[CONFIRMED] 失败自动重试 4/33/139          触发:自动
[CONFIRMED] 命令执行 3/22/78               触发:未判定
[CONFIRMED] 遥测上报 4/21/135              触发:自动
[LIKELY] 对象存储直传 3/12/20 | 上传凭证接口 2/4/11 | 浏览器状态访问 2/2/18
[LIKELY] Git 历史访问 2/5/20 | 批量打包 3/3/8

组合证据（共现检测）：
  [阻断级] 工作区采集+加密+对象存储直传   关联度: 较强(same_file)
  [阻断级] 工作区采集+上传凭证申请        关联度: 较强
  [阻断级] 凭据文件读取+外传通道          关联度: 较强
  [严重]   跨工作区配置采集+外传通道      关联度: 较强
  [严重]   Git历史读取+外传通道          关联度: 较强
```

## 第三遍 · 分歧与归因

> **记录标准（S1 后修订）**  
> 每个分歧必须带三个字段，比 TP/FP/FN 更有用：
>
> - `direction`：`overstate`（把弱证据说强）/ `understate`（把强证据说弱）/ `wrong-semantics`（事实对、语义错）
> - `class`：8 类 failure class 之一
> - `structural`：该样本中「代码结构已表达关联，但工具只能表示成共现」的程度  
>   —— `none` / `weak` / `moderate` / `strong`

### 分歧 1 ★★★ · 凭据文件访问：人工 NO ↔ 工具 **confirmed**

**工具的原始依据**（从 JSON 取）：

```
[ssh_keys w=8] /out/host/index.js:340
   …return e===".env"||e.startsWith(".env.")||e===".npmrc"||e==="settings.local.json"
    ||/^(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)$/.test(e)||/\.(?:pem|key…
[pkg_tokens w=7] /out/host/index.js:480
   …Pct=new Set([".git"]), bct=new Set([".env",".env.local",".env.development",
    ".env.production",".npmrc","id_rsa","id_dsa","id_ecdsa","id_ed25519"]);
```

**人工读代码**：这是一个**文件名排除集合**（`new Set([...])` 用作"不纳入的名单"），  
不是"要去读的文件列表"。

- `direction` = **`wrong-semantics`**
- `class` = **`semantic-role confusion`**（新术语，不是笼统的 FP）
- `structural` = `none`

> **术语定义 —— `semantic-role confusion`**
>
> 工具拿到了正确的字符串，但**误判了这些字符串在代码里承担的语义角色**。
>
> 负向语义的表达方式远不止"显式否定词"：
>
> ```
> never(...)   exclude(...)   Set([...])   if (...)   filter(...)   denylist
> ```
>
> 甚至更深地藏在控制流里。**v0.2.6 加的 `NEGATIVE_CONTEXT`  
> 只覆盖了「显式写明排除」，覆盖不到「用数据结构表达排除」。**  
> 这条比"再加几个词表"更根本——它是**结构语义缺失**，不是词表不全。

### 分歧 2 ★★ · Git 历史访问：人工 **NO** ↔ 工具 **likely**

同一份代码里 `Pct = new Set([".git"])` —— **`.git` 出现在排除集合里**。  
把 `.git` 列入排除集，恰恰说明**不处理** `.git`。

- `direction` = **`wrong-semantics`**
- `class` = `semantic-role confusion`（与分歧 1 同源）
- `structural` = `none`

### 分歧 3 ★★ · 对象存储直传：结论对，但**证据被稀释**

工具报 3 个模式命中，其中 `aliyun_oss` 的证据：

```
/out/main/chunk-6XM33EZR.js:1  …log.aliyuncs.com/rum/web/v2?workspace=…   ← ARMS RUM 遥测
/out/main/chunk-DBVOEQ2Z.js:1  …log.aliyuncs.com/apm/trace/opentelemetry… ← APM 链路追踪
```

**人工读代码**：这两处是**遥测/APM 端点**，不是对象存储。

- `direction` = **`overstate`**（弱证据污染，使真实证据的辨识度下降）
- `class` = `pattern failure`（`aliyun_oss` 的判据过宽：一个域名承载三种服务）
- `structural` = `none`

> **新失败模式 `evidence dilution`** —— 与之前"一个模式只贡献一次"的讨论形成闭环：
>
> ```
> 旧担忧：弱证据 × 很多次 → 刷分（已用 max + 多样性封顶解决）
> 新发现：弱证据 × 很多次 → 强证据辨识度下降
> ```
>
> 说明 evidence aggregation 需要的可能不是单纯累加，而是  
> `strength × independence × specificity × provenance`。  
> **但现在不碰公式，只记录现象。**

### 分歧 4 ★★★ · 数据关联被**低估**

**人工发现**：`out/host/index.js:487` 里，  
`objectUpload.maxBytes` 直接取自 `t.encryptedArtifact.encryptedSizeBytes`，  
且同文件有 `class RepoSnapshotUpload` + `uploadObject` / `uploadPostObject` / `uploadPutObject`  
/ `consumeUploadCredential` 的**方法链**。

**工具输出**：`[阻断级] 工作区采集+加密+对象存储直传  关联度: 较强(same_file)`  
并附说明「**共现 ≠ 在同一条可达路径上，可能来自互不相关的代码**」。

- `direction` = **`understate`**
- `class` = `evidence aggregation failure`
- `structural` = **`strong`**

> **为什么单独加 `structural` 这个字段**
>
> 老大给的证据表达能力梯度：
>
> ```
> 文本共现  →  结构关联  →  局部数据依赖  →  跨函数可达路径  →  完整 source→sink
>    ↑            ↑
>  现有模型    这次实际发现的位置
> ```
>
> 这次发现的**不是**"需要完整 data-flow"，而是  
> **"结构关联 / 局部数据依赖已经超出当前模型的表达能力"**。
>
> 第一阶段可能只需要一个**很窄的中间层**：
>
> ```
> object literal · parameter relation · same function · same call chain · same imported symbol
> ```
>
> 即先让工具能表达：「这两个证据不只是出现在同一个 bundle，而是代码里存在**可观察的结构关系**」。  
> 这远比引入 AST/CFG/data-flow 便宜。
>
> **但现在不做。** 当前最重要的是回答：  
> **这是 ZCode 的特例，还是多个真实客户端都存在的普遍失败模式？**

## Failure Class 汇总

| 分歧               | direction         | class                     | structural | 可复现  |
| ---------------- | ----------------- | ------------------------- | ---------- | ---- |
| 1 凭据访问 confirmed | `wrong-semantics` | `semantic-role confusion` | none       | ✅ A1 |
| 2 Git 历史 likely  | `wrong-semantics` | `semantic-role confusion` | none       | ✅ A1 |
| 3 遥测端点计入 OSS 证据  | `overstate`       | `pattern failure`         | none       | ✅ A2 |
| 4 强关联被降格为共现      | **`understate`**  | `evidence aggregation`    | **strong** | ✅ A3 |

**四个分歧三种方向** —— 这本身就是 S1 最重要的产出：

> **AgentEgress 的错误不是单向的。**  
> 它既可能把无关证据拼成故事（overstate），  
> 也可能**看到了真实结构，却因为证据模型太粗而无法表达**（understate）。

这意味着下一阶段真正该优化的对象可能不是 `pattern coverage`，  
而是 **`evidence representation`**。  
**但要不要走到 `AST → CFG → data-flow`，现在不决定。**

## ⚠ 采样污染声明（必须记住）

**S1 完成后，我已经知道**：排除集合、OSS 遥测、结构关联这三个概念。

**S2～S5 的人工分析不可能真正"忘掉"它们**，会下意识去找。  
所以：

1. **本轮记录显式声明该污染** —— 后续样本若再发现同类问题，  
   其"独立性"是打折的，必须在结果里标注
2. 为降低污染，S2 仍严格按同一顺序执行：  
   `独立解包 → 独立提取上下文 → 10 项 Ground Truth → 跑工具 → 盲差分`
3. **Ground Truth 必须在跑工具之前写完**，且不得回头修改

## S2～S5 新增第 10 问

除原有 9 问，每个样本必须回答：

> **是否存在「代码结构已经明显表达关联，但 AgentEgress 只能把它表示成共现」的证据？**

答案不是 yes/no，而是四档：

```
none              无此类证据
weak structural   同一变量名 / 同一字面量在附近出现
moderate structural  参数传递、返回值消费
strong structural   同一对象字面量内的字段引用、同一方法链、同类内字段
```

S1 = **strong structural relation**

> S5 结束后就能回答关键问题：  
> **真实样本中，「字符串共现不足以表达、但又不需要完整 data-flow」的案例到底有多少？**  
> 这才真正能决定下一步架构。

## 复现步骤（可独立复跑）

```
A1  python tests/dogfood/look.py tests/dogfood/s1-zcode "id_ed25519" --window 240
    → 观察它在 new Set([...]) 里

A2  python tests/dogfood/look.py tests/dogfood/s1-zcode "aliyuncs" --window 240
    → 两处都是 log.aliyuncs.com 的 rum / apm 端点

A3  python tests/dogfood/look.py tests/dogfood/s1-zcode "encryptedArtifact" --window 240
    → 71 处；重点看 host/index.js:487 的 objectUpload 对象
```

## Action

| 分歧 | Action                 | 说明                                                          |
| -- | ---------------------- | ----------------------------------------------------------- |
| 1  | **Need More Evidence** | 单样本不足以断定"排除列表"是普遍模式。需在 S2/S3 验证：其他客户端是否也用 `new Set`/数组表达排除？ |
| 2  | **Need More Evidence** | 同上，与 1 同源                                                   |
| 3  | **Need More Evidence** | 需确认 `aliyun_oss` 模式的定义域；但**先不改**——按纪律，Phase 1 不动代码          |
| 4  | **Need More Evidence** | 需要设计一个能表达"同对象内字段引用"的判据。**但先不改**                             |

**本轮不产生 Fix。** 按基线纪律，所有分歧先累积，Phase 1 结束后再统一判断。

---

## Novel Failure Mode 计数

| 样本 | 新失败模式 | 说明                                                                                                                 |
| -- | ----- | ------------------------------------------------------------------------------------------------------------------ |
| S1 | **4** | `semantic interpretation`（排除列表误读）· `pattern`（遥测域名混入）· `evidence dilution`（证据稀释）· `evidence aggregation`（**低估**强关联） |


> 其中 **`evidence dilution`** 与 **低估方向的 `evidence aggregation`**
> 是此前五轮评审**从未出现过**的类型——前几轮全是"高估"（把弱证据说强）问题，
> 这次第一次出现"**低估**"（把强证据说弱）。

**`Novel failure modes / sample` = 4.0（S1）**

---

# S2 · WorkBuddy（`<WORKBUDDY_HOME>\resources\app.asar`）

302.4 MB / 20553 条目 / 自研 2391 条
解包范围：`/main/` `/cli/dist/` `/cli/bin/` `/resources/extensions/` → 281 文件 / 80.6 MB

## 第一遍 · Ground Truth（**在跑工具之前写完**）

| # | 问题 | 判定 | 人工依据（文件:行 + 原文） |
|---|---|---|---|
| Q1 | 工作区读取 | **待定** | `workspaceFolder` 未命中；需另查 |
| Q2 | 敏感文件读取 | **见分歧 1**（语义极关键） | `cli/dist/lazy-headless/914.37a808af.js:65` |
| Q3 | 归档 | **NO（倾向）** | `archiver` 179 处全是**库源码本身**；`createGzip` 2 处 = 遥测压缩 + archiver 库实现，**没有"打包工作区"的应用逻辑** |
| Q4 | 加密 | **YES** | `log-acl-guard.js` `encrypt(plaintext,aadParts)`，`aes-256-gcm` + `buildAad(this.userId,…)` → **应用自己的日志加密** |
| Q5 | 外部网络 sink | **YES** | `app-server-mcp-apps-host.js:9133` 的 CSP `connect-src` 白名单（含 `*.beacon.qq.com`、`svibeacon.onezapp.com`）|
| Q6 | 对象存储 | **YES** | `celljs-deps.js:1400` `uploadToCos(cred, body, …)` + `cos.putObject({Bucket: cred.bucket_name, Key: cred.cos_key, …})` —— **腾讯云 COS 直传** |
| Q7 | 自动触发 | **YES** | `cli-prewarm-pool.js:399-422` `startHealthProbe` + `setInterval(…, HEALTH_PROBE_INTERVAL_MS)`；`setInterval` 全库 89 处 |
| Q8 | 数据关联证据 | **YES（强）** | 见 Q10 |
| Q9 | 合法业务解释 | **YES（明确）** | `uploadToCos` 的注释写明用途：`Step ②：用 STS 凭证把 Buffer 直传 COS`，上下文含 `knowledge_base_id` / `add_knowledge` → **知识库文件上传** |
| Q10 | **结构关联强度** | **`strong`** | `celljs-deps.js:1548`：`created = await createMedia(...)` → `await this.uploadToCos(created.cos_credential, buffer, contentType, …)` —— **createMedia 的返回值直接作为 uploadToCos 的实参**（参数传递，非巧合共现）|

### S2 的关键观察（写于跑工具之前）

**`semantic-role confusion` 又出现了，而且是全新类型：**

`cli/dist/lazy-headless/914.37a808af.js:65`：
```js
function Co(Q, E) {
  return Q.files.some(Q => "read" === Q.action &&
      /\/\.ssh\/|\\\.ssh\\|id_rsa|id_ed25519|\.pem\b|\.p12\b|\.pfx\b|\.kube\/config|
       credentials|credential|token|secret|keychain|login\.keychain/i.test(Ve(Q.path)))
    || /\b(?:cat|type|Get-Content|gc|more|less|head|tail|strings|xxd|scp|curl)\b[^;&|]{0,240}
       (?:\/\.ssh\/|…)/i.test(E);
}
```

**人工判断**：这是 **WorkBuddy 自己的一条安全检测规则**——
检查"有没有**别的**进程/命令去读敏感文件"（`"read" === Q.action` + shell 命令模式）。

**它不是在读凭据，它是在检测"读凭据的行为"。**

对照 S1（ZCode）的发现，同一个根因已经有**三种表现**：

| 样本 | 代码形态 | 真实语义 | 工具的解读 |
|---|---|---|---|
| S1 ZCode | `new Set([...id_rsa...])` | **排除列表**（不处理这些） | 「读取这些」 |
| S2 WorkBuddy | `"read"===action && /\.ssh\|id_rsa…/` | **检测规则**（检测别人有没有读） | 「读取这些」 |
| S2 WorkBuddy | CSP `connect-src` 白名单 | **允许列表**（允许连接这些） | 「要连接这些」（待验证） |

> **这是一个很强的模式信号**：`denylist` / `detection rule` / `allowlist`
> 三种结构都会产生"看起来像能力声明"的字符串，而它们**都不是能力声明**。
>
> 如果 S3～S5 继续出现，就不再是"ZCode 特例"，而是**普遍失败模式**。

**注意 Q3 = NO（倾向）**：`archiver` 179 处很像强证据，
但人工读下来全是**库自身源码**被打包进 bundle。这正好是 S1 分歧 3（evidence dilution）
的镜像：**库源码产生了大量"看起来像能力"的字符串**。

## 第二遍 · AgentEgress 输出（冻结版）

```
风险等级 [CRITICAL] · 确认存在高危外传能力（注意：7 个文件未覆盖）
已确认 8 / 疑似 3 / 弱信号 1
覆盖台账: 候选 18460 -> 读到 1327 -> 真正跑正则 602
  关键词预筛未通过 725 个
!! 因技术原因未覆盖 7 项：大文件 7

[CONFIRMED] 对象存储直传 6/53/239   触发:自动
[CONFIRMED] 信封加密 6/13/99        触发:未判定
[CONFIRMED] 凭据文件访问 4/17/59     触发:未判定
[CONFIRMED] 上传凭证接口 3/10/23     触发:未判定
[CONFIRMED] 失败自动重试 4/86/525    触发:自动
[CONFIRMED] 批量打包 5/27/87        触发:未判定
[CONFIRMED] 命令执行 4/52/197       触发:自动
[CONFIRMED] 遥测上报 4/176/864      触发:混合
[LIKELY] 工作区全量快照 3/4/17 | 跨工作区配置采集 2/6/29 | Git 历史访问 2/5/19
[POSSIBLE] 浏览器状态访问 1/13/24
```

## 第三遍 · 分歧与归因

### ⚠ 先记录一件事：**工具的证据修正了我的人工判断**

我的第一遍把 **Q3 归档判为「NO（倾向）」**。
工具的证据列表里有一条推翻了我：

```
/main/server.js:167746  [创建归档 w=7]
   …const absDir = path.resolve(localDir);
      const tmpFile = path.join(os.tmpdir().trim(), ARCHIVE_NAME);
      await tar.create({ gzip: true, file: tmpFile, …
```

**这是应用自己的 `tar.create`**（不是库实现）。**Q3 修正为 YES。**

> **这条必须记下来**：dogfooding 的差分是**双向**的。
> 不只是"工具错了多少"，也存在"**工具的证据纠正了人工判断**"。
> 我前面几轮一直把工具当成被检验对象，忽略了它作为"取证辅助"的价值。

### 分歧 1 ★★★ · 凭据文件访问：人工「检测规则」↔ 工具 **confirmed**

工具 4 个模式的证据里，**大部分来自第三方库**：

```
[/main/cos-nodejs-sdk-v5.js:19726] [云凭据 w=8]
   …"*.azurecontainer.io", "azure-api.net", "azure-mobile.net", "azureedge.net", …
```

**人工读代码**：这是 **COS SDK 内部的一个域名后缀列表**（用于判断公网/内网域名），
**根本不是凭据**。只是其中若干字符串形态与 `cloud_creds` 模式撞上了。

- `direction` = **`wrong-semantics`**
- `class` = `semantic-role confusion`（**新形态：数据结构被当成内容**）

### 分歧 2 ★★★ · 批量打包：**证据列表 3 条里 2 条是库/遥测**

```
[/main/module-base.js:39577]  ← archiver 库自己的实现（this.engine = engine.pack）
[/main/code-cache.js:37279]   ← 遥测上报时的 gzip（Content-Encoding: gzip）
[/main/server.js:167746]      ← ✅ 这条是真的应用逻辑
```

**人工判断**：结论对（Q3 确为 YES），但**证据列表严重不纯**。

- `direction` = **`overstate`**
- `class` = **`library-source contamination`** ← **新失败模式**
- `structural` = `none`

> **`library-source contamination` 的定义**
>
> 第三方库被 bundle 进 `cli/dist/` / `main/` 后**失去了来源标识**——
> 路径看起来像自研代码，`classify_file` 判为 `production`（权重 1.0），
> 于是**库自身的实现细节被算作应用能力**。
>
> `archiver` 179 处、`cos-nodejs-sdk-v5.js` 的域名列表，都是这个机制的产物。
>
> **与 S1 分歧 3（evidence dilution）的区别**：
> - dilution：**弱相关证据混入**，稀释强证据的辨识度
> - contamination：**库源码本身产生大量假证据**，且因 bundle 而无法按 vendor 降权
>
> **这是 vendor 跳过策略的直接盲区**：工具能识别 `/node_modules/`，
> 但识别不了"已经被打包进 dist 的 node_modules"。

### 分歧 3 ★★ · 工作区全量快照：工具证据来自 **UI 组件**

```
[/renderer/assets/project-detail-page-Brz3IJte.js:44436] [仓库快照标识 w=9]
   …showRepoConfig, repoConfig, repoSnapshotStatus, onOpenRepoConfig, …
[/renderer/assets/project-detail-page-Brz3IJte.js:44594]
   …(0, import_jsx_runtime.jsx)(RepoConfigCard, { repoConfig: repoConfig ?? null,
      snapshotStatus: repoSnapshotStatus, canEdit, …
```

**人工读代码**：这是 **React 组件的 props 列表**（`RepoConfigCard` 的属性）。
它在**界面上显示"仓库快照状态"**，**不是执行快照采集**。

- `direction` = **`wrong-semantics`**
- `class` = `semantic-role confusion`（**新形态：UI 展示被当成采集能力**）
- `structural` = `none`

> **这是 `semantic-role confusion` 在 S2 的第三种形态**：
> ```
> 检测规则（"read"===action && /\.ssh…/）   → 被读成「读取凭据」
> 数据结构（SDK 的域名后缀列表）            → 被读成「云凭据」
> UI 展示（React 组件的 props）             → 被读成「快照采集」
> ```
> **加上 S1 的两种（排除列表 / CSP 白名单），同一个根因已有 5 种表现。**

### 分歧 4 ★★ · 数据关联再次被**低估**

人工 Ground Truth Q10 = **`strong`**：
```js
created = await createMedia(...)                                    // 返回 cos_credential
await this.uploadToCos(created.cos_credential, buffer, contentType, …)  // 直接作实参
```

工具输出：`关联度: 较强(same_file)` + 附注「可能来自互不相关的代码」。

- `direction` = **`understate`**
- `class` = `evidence aggregation`
- `structural` = **`strong`**

**与 S1 完全一致** —— 这是**第二次**出现，不再是孤例。

## Failure Class 汇总

| 分歧 | direction | class | structural |
|---|---|---|---|
| 1 凭据访问 confirmed | `wrong-semantics` | `semantic-role confusion`（数据结构形态）| none |
| 2 批量打包证据不纯 | `overstate` | **`library-source contamination`** ← 新 | none |
| 3 工作区快照（UI 组件）| `wrong-semantics` | `semantic-role confusion`（UI 形态）| none |
| 4 强关联被降格 | **`understate`** | `evidence aggregation` | **strong** |

## Novel Failure Mode 计数

| 样本 | 新类型 | 复用已有类型 |
|---|---|---|
| S1 | **4** | — |
| S2 | **2**（`library-source contamination`、`semantic-role confusion` 的 UI/数据结构形态）| 2（semantic-role 基础形、evidence aggregation-understate）|

**`Novel failure modes / sample`：4.0 → 2.0**（下降 ✓）

> 但要谨慎：`semantic-role confusion` 在 S2 出了**两种新形态**。
> 「新形态」算不算「新的 failure mode」需要 S3～S5 之后统一定标——
> 目前先按"根因相同、表现不同"记录，**记为 0.5 个**更合理 → 实际 **4.0 → 1.5**。

## Action

| 分歧 | Action |
|---|---|
| 1 凭据访问 | **Need More Evidence**（第三次见到 semantic-role confusion 的变体，S3 继续观察）|
| 2 库源码污染 | **Need More Evidence**（这是 vendor 策略的盲区，但先确认 S3/S4 是否重现）|
| 3 UI 组件 | **Need More Evidence** |
| 4 understate | **Need More Evidence**（第二次出现，已接近可判定的阈值）|

**本轮仍不产生 Fix。** 冻结继续。

> **Ground Truth 修正记录**：Q3 由 `NO（倾向）` → `YES`（依据 `server.js:167746` 的 `tar.create`）。
> 修正来源是**工具的证据**，不是事后猜测。这是 dogfooding 的正当流程。

---

# S3 · opencode（`@opencode-aidesktop` 1.18.30）

**⚠ 样本变更**：原计划的 Kimi Work / Cursor 的 asar 已不在磁盘上（软件已卸载）。
改用 **opencode**（137.1 MB / 6991 条目 / 自研 1018）。
**它其实更适合**：**开源软件**，Ground Truth 可对照上游真实源码。

## 第一遍 · Ground Truth（**在跑工具之前写完**）

| # | 问题 | 判定 | 人工依据 |
|---|---|---|---|
| Q1 | 工作区读取 | **YES** | `OPENCODE_WORKSPACE_ID` / `OPENCODE_EXPERIMENTAL_WORKSPACES`；`workspace` 全库 1310 处 |
| Q2 | 敏感文件读取 | **NO** | `id_rsa` **0 处** |
| Q3 | 归档 | **NO** | `createGzip` 仅 1 处 = **HTTP 请求压缩**（`compressAndSend`，`Content-Encoding: gzip`）；`archiver` 3 处其实是 **`ia_archiver`**（Internet Archive **爬虫 UA 正则**）|
| Q4 | 加密 | **NO** | `createCipheriv` **0 处** |
| Q5 | 外部网络 sink | **YES（但需分辨）** | `fetch(` 155 处；抽样显示大量属于 **lru-cache 等库**（`LRUCache.fetch()`）|
| Q6 | 对象存储 | **NO** | `PutObject` 10 处**全部**是 `InputObject` —— 权限配置的 **schema 定义**（`Schema.StructWithRest({read,edit,glob})`）|
| Q7 | 自动触发 | **YES** | `setInterval` 11 处：心跳续期 + OTel `PeriodicExportingMetricReader` |
| Q8 | 数据关联证据 | **none** | 未发现 source→sink 结构关系 |
| Q9 | 合法业务解释 | — | 见下方"产品语义"一节 |
| Q10 | **结构关联强度** | **`none`** | 自研代码里没有外传链路，自然也没有结构关系 |

### ⚠ 本样本最重要的结构事实：**核心逻辑工具扫不到**

```
/out/main/chunks/node-BIz0dqH1.js   33,909.7 KB  ← 33.1 MB
```

头部：`import { createRequire } from "node:module"` / `import * as crypto7 from "node:crypto"` /
`import * as NFS from "node:fs"` …
尾部：`await init_database(); export { Config, Database, Server, bootstrap };`

**这是 opencode 的完整服务端 bundle**（`Database` / `Server` / `Config` / `bootstrap`），
而且是**未压缩的可读代码**（有缩进与换行，不是 minified）。

**但 33.1 MB > 工具的 `max_file_bytes = 8 MB` → 它会被 `skipped_large` 跳过。**

工具实际能看到的 `/out/main/` 下文件只有：

```
  160.6 KB  /out/main/index.js
    3.3 KB  /out/main/sidecar.js
    7.8 KB  /out/preload/index.js
    1.3 KB  /package.json
```

即：**工具只能看到约 168 KB，而应用的实质逻辑是 33 MB。**

> 这正好落在老大提出的区分上：
> ```
> pattern failed            ← 规则没命中
> pattern never got to run  ← 文件根本没跑到正则
> ```
> **S3 是第二个问题的极端案例**——不是规则不够好，
> 而是**最核心的文件没有被读到**。

### S3 的新 `semantic-role confusion` 形态

`PutObject` 10 处命中的真相：
```js
InputObject = exports_Schema.StructWithRest(exports_Schema.Struct({
  read: exports_Schema.optional(Rule2),
  edit: exports_Schema.optional(Rule2),
  glob: exports_Schema.optional(Rule2)…
```
**`Object` 是 schema 里的一个词**（`InputObject` / `Object2` / `PermissionObjectConfig`）。

`archiver` 3 处命中的真相：
```js
{ test: [/ia_archiver/i], describe: function(e3) {
    var t3 = { name: "InternetArchiveCrawler" }…
```
**`ia_archiver` 是 Internet Archive 爬虫的 User-Agent 字符串**，
与"创建归档"毫无关系——只是**恰好包含 `archiver` 这个词**。


> **到 S3，`semantic-role confusion` 的形态已累计 7 种**：
> ```
> S1  denylist（new Set）· CSP allowlist
> S2  detector rule · SDK 数据结构 · UI props
> S3  schema 类型定义（InputObject）· 第三方 UA 字符串（ia_archiver）
> ```
> **三种完全不同的软件，七种语义载体，同一个根因。**

## 第二遍 · AgentEgress 输出（冻结版）

```
存在多项已确认的外传能力（注意：1 个文件未覆盖）
已确认 2 / 疑似 3 / 弱信号 2

覆盖台账: 候选 6699 -> 读到 841 -> 真正跑正则 645
  关键词预筛未通过 196 个
!! 因技术原因未覆盖 1 项：大文件 1

[CONFIRMED] 失败自动重试 4/16/76
[CONFIRMED] 遥测上报 3/533/3202
[LIKELY] 凭据文件访问 3/3/7 | Git 历史访问 2/2/12 | 命令执行 3/4/16
[POSSIBLE] 对象存储直传 1/5/5 | 批量打包 1/2/4
未检出: 信封加密、跨工作区配置采集
```

**注意等级**：工具只给到「存在多项已确认的外传能力」（非 CRITICAL）。
而 S1/S2 都是 CRITICAL。**原因不是 opencode 更干净，而是它 99.5% 的代码没被扫到。**

## 第三遍 · 分歧与归因

### 分歧 1 ★★★ · 凭据文件访问：人工 NO ↔ 工具 **likely**

工具 3 个模式的证据，**全部来自编辑器的语言资源**：

```
[/out/renderer/assets/ssh-config-C1Jhmhk_.js:19] [SSH 密钥 w=8]
   …JSON.parse('{"displayName":"SSH Config","fileTypes":["ssh_config",".ssh/config","sshd_config"]…

[/out/renderer/assets/main-BDbQ3Vtm.js:115503] [包管理器凭据 w=7]
   …".latexmkrc", ".login", ".luacheckrc", ".markdownlintignore", ".nodemonignore",
      ".npmignore", ".npmrc", ".nvimrc"…

[/out/renderer/assets/main-BDbQ3Vtm.js:109179] [系统钥匙串 w=6]
   …canScrollKey(owner, key2) ? owner : root2; }  function isScrollKeyTarget…
```

**三种全新形态**：
1. **语法高亮模板** —— 声明"这个语言有哪些文件名"（编辑器内置支持 SSH 配置文件高亮）
2. **点文件清单** —— 编辑器识别的一堆 `.xxx` 配置文件列表
3. **`key` 一词多义** —— `canScrollKey` / `isScrollKeyTarget` 里的 **key 是键盘按键**，
   被 `keychain` 模式命中

### 分歧 2 ★★ · 对象存储直传：人工 NO ↔ 工具 **possible**

```
[/out/renderer/assets/bsl-CVaYL_Im.js:20] [表单直传签名 w=7]
   …"name":"support.function.bsl"},{"match":"(?i:…ЗначениеВДанныеФормы|ValueToFormData|…

[/out/renderer/assets/dialog-connect-provider-CgLk08r5.js:1420]
   …const form = e.currentTarget; const formData = new FormData(form);
      const apiKey2 = formData.get("apiKey");…
```

1. **BSL（1C:Enterprise）语言的语法模板** —— `ValueToFormData` 是 BSL 的**内置函数名**
2. **HTML 的 `FormData`** —— 前端表单提交，与对象存储无关

### 分歧 3 ★★ · 批量打包：人工 NO ↔ 工具 **possible**

```
[/out/main/index.js:1074] [递归遍历目录 w=4]
   …const file = join(current, entry); const info = statSync(file);
      if (info.isDirectory()) { walk(file); continue;…

[/out/renderer/assets/main-BDbQ3Vtm.js:9346]
   …walk(root2); const observer…              ← DOM 遍历

[/out/renderer/assets/main-BDbQ3Vtm.js:9363]
   …visibleNodes.add(node); } else if (node instanceof Element) { walk(node);…
```

1. **文件系统遍历** —— 编辑器扫描项目文件，是**核心功能**
2. **DOM 树遍历** —— `node instanceof Element` / `visibleNodes`，**浏览器 DOM，不是文件**

### 分歧 4 ★★★ · 新增失败模式：`coverage-weight blindness`

工具的覆盖台账：

```
候选 6699 -> 读到 841 -> 真正跑正则 645
!! 因技术原因未覆盖 1 项：大文件 1
```

**"未覆盖 1 项" 听起来微不足道。但那 1 项是 33.1 MB**，
而工具实际看到的全部只有 **约 168 KB**。

> **「1 项未覆盖」与「7 项未覆盖」在报告里看起来差不多，
> 但一个可能是无关紧要的文件，另一个可能是 99.5% 的实现逻辑。**
>
> **`coverage-weight blindness`：覆盖缺口的计数不体现权重。**

- `direction` = **`understate`**（低估了缺口的严重性）
- `class` = **`coverage accounting failure`** ← **新 failure class**
- `structural` = `none`

### 分歧 5 ★★★ · 「因覆盖不足而侥幸避免误报」

工具对 opencode 只报 medium 级，而 S1/S2 都是 CRITICAL。
**但 opencode 不是更干净——是它 99.5% 的代码没被扫到。**

> 如果工具真的读了那 33 MB（里面有完整的 `Database` / `Server` / `Config`，
> 以及 155 处 `fetch(`、11 处 `setInterval`、大量 schema 定义），
> **很可能产生更多误报**。
>
> **它是靠"看不见"而显得更准的。**

- `direction` = `understate`（**看似保守，实则是覆盖缺口造成的假象**）
- `class` = `coverage accounting failure`
- 这是分歧 4 的**后果**，不是独立问题，但必须单独记录 —— 因为它会造成
  **"覆盖越差 → 报得越保守 → 看起来越可信"** 的**逆向激励**。

## Failure Class 汇总（S3）

| 分歧 | direction | class | structural |
|---|---|---|---|
| 1 凭据访问（语法模板/点文件/key 多义）| `wrong-semantics` | `semantic-role confusion` ×3 新形态 | none |
| 2 对象存储（BSL 模板/FormData）| `wrong-semantics` | `semantic-role confusion` ×2 新形态 | none |
| 3 批量打包（FS 遍历/DOM 遍历）| `wrong-semantics` | `semantic-role confusion` ×2 新形态 | none |
| 4 覆盖缺口不体现权重 | `understate` | **`coverage accounting`** ← 新 | none |
| 5 侥幸避免误报 | `understate` | `coverage accounting`（后果）| none |

## `semantic-role confusion` 形态累计（**关键证据**）

| 样本 | 新形态 |
|---|---|
| S1 | `denylist`（`new Set`）· CSP `allowlist` |
| S2 | `detector rule` · SDK 数据结构 · UI props |
| S3 | 语法高亮模板 · 点文件清单 · **`key` 一词多义** · BSL 语言模板 · `FormData` API · 合法 FS 遍历 · DOM 遍历 |

**三种完全不同的软件，12 种语义载体，1 个根因。**

> 这已经不是"某个正则写得不好"，而是 **`lexical evidence is insufficient
> to infer semantic role`** —— 词法证据不足以推断语义角色。
> **该结论现在有 3/3 的样本支撑。**

## Novel Failure Mode 计数（按新指标）

```
Root-cause novelty
  S1 = 4   semantic-role / pattern / evidence dilution / evidence aggregation
  S2 = 1   library-source contamination
  S3 = 1   coverage accounting

Manifestation novelty
  semantic-role confusion:  S1=2  S2=3  S3=7   （累计 12，1 个根因）
  coverage accounting:       S3=2（缺口不体现权重 / 侥幸避免误报）
```

**`systemic_candidate` 标记**：

| 发现 | 状态 |
|---|---|
| `semantic-role confusion` | ✅ **systemic，3/3 样本，12 种形态** |
| `evidence aggregation`（understate）| ✅ **systemic，2/2 样本，2 种结构类型** |
| `library-source contamination` | ⏳ S2 单次，待验证 |
| `coverage accounting` | ✅ **systemic，S3 单样本内已出现两个后果** |
| `evidence dilution` | ⏳ S1 单次，待验证 |

## Action

| 分歧 | Action |
|---|---|
| 1~3 误报 | **Need More Evidence**（形态多样性已足够，但要 S4 确认；**仍不修**）|
| 4 覆盖权重 | **Need More Evidence** |
| 5 侥幸保守 | **Need More Evidence** |

**本轮仍不产生 Fix。冻结继续。**

> **⚠ 采样污染（累积）**：我现在已经知道 semantic-role confusion 的 12 种形态。
> S4 的人工分析必然受此影响。**此后的"新形态"其独立性递减**，记录时必须标注。

---

# S4 的重新定标（S4 之后，按老大的拆解）

## 一、S4 真正证明的不是「对非标准实现系统性失明」

而是：**AgentEgress 存在三种完全不同的漏检机制，不能用同一种技术修复。**

| B 类 | 工具表现 | 本质 | 归因 |
|---|---|---|---|
| 工作区全量快照 | **0 命中** | 检测 primitive 缺失 / 表示差异 | **B1 Discovery failure** |
| 信封加密 | **1 命中但 absent** | 有 primitive，证据不足以跨阈值 | **B2 Evidence normalization failure** |
| 遥测上报 | **48 命中但 absent** | 大量低权重证据被评分体系压没 | **B3 Evidence calibration failure** |

> **`non-canonical-implementation gap` 这个名字下早了。**
> 只有「0 命中」那一条才配叫 discovery gap。
> 另两条是 **Discovery succeeded; classification / calibration failed**。

## 二、Pipeline 形式化（这是 S4 最该留下的东西）

```
source code
    ↓
 detection          ← S1/S2 主要攻击这里（semantic-role confusion）
    ↓
raw evidence
    ↓
evidence typing     ← S1/S2 的 library-source contamination / UI props
    ↓
aggregation         ← S4 攻击：48 hits 被压成 score 1.48
    ↓
scoring             ← S4 攻击：1 hit 够不到 possible 阈值
    ↓
verdict
```

**S1/S2 攻击 `detection → evidence typing`；S4 第一次攻击 `evidence → aggregation → scoring`。**

## 三、核心架构结论

> **从源代码到安全结论的中间表示太贫乏。**

不是"正则少了几个"。两侧边界现在都暴露出来了：

```
                    true state
                        │
            ┌───────────┴───────────┐
            ↓                       ↓
     overstatement            understatement
            │                       │
  lexical semantic role      B1 discovery（完全没看见）
  provenance contamination   B2 normalization（看见了但表示不足）
  evidence dilution          B3 calibration（看见很多但被压没）
```

## 四、必须修正我上一条消息的推论

我说过"如果对非标准实现系统性失明，Layer 1/2 可能救不了"。**这个逻辑要改**：

| 层 | 能否解决 discovery gap | 说明 |
|---|---|---|
| Layer 1（semantic role）| ❌ **不能** | 它解决的是 `new Set(["id_rsa"])` 是 denylist 还是 read target，对"完全未知的 crypto API"无能为力 |
| Layer 2（structural relation）| ❌ 不能单独解决 | 若 `createMedia` 根本未被识别为 relevant source，后面没有 structural evidence 可分析 |

**但这不等于 Layer 1/2 没价值。它们是互补的，不是替代关系：**

```
Layer 0  lexical discovery      ← B1 的瓶颈在这里
Layer 1  semantic role          ← 解决 semantic-role confusion
Layer 2  structural relation    ← 解决 understate
Layer 3  reachability
```

## 五、H4 改名

```
旧：Low file coverage can create false reassurance          ← 被 S4 证伪
新：Technical coverage loss can create false reassurance
```

因为 S4 已证明 `low file coverage ≠ low technical coverage`
（97% 是 node_modules 的设计内跳过，不是技术性不可见）。

## 六、S5 的任务定义（升级为诊断实验）

**S5 不再是"跑第五个软件"，而是 S4 的实验性反事实验证器。**

用**正交化**的方式人为控制变量，最后得到"**哪一层缺失导致哪一种错误**"：

| 实验 | lexical | semantic | structural | 测什么 |
|---|:-:|:-:|:-:|---|
| **E0** 标准加密 | ✓ | — | — | 基线 |
| **E1** `customEncrypt()` / `obscureUpload()` | ✗ | — | — | **discovery gap（B1）** |
| **E2** 标准加密 + `new Set(["id_rsa"])` | ✓ | 需要 | — | **semantic role** |
| **E3** 标准加密 → 上传（同对象/参数流）| ✓ | ✓ | 需要 | **structural relation** |
| **E4** ★ **非标准加密 → 上传** | ✗ | ✓? | ✓ | **structural 能否补 lexical** |
| **E5** 48 处弱证据 | ✓ | ✓ | — | **aggregation / calibration（B2/B3）** |

> **E4 价值最大。** 它可能给出三种结论之一：
> ```
> A. lexical discovery 是不可替代的瓶颈
> B. 结构关系可以部分补救 lexical blindness
> C. 两者都需要：lexical 提供候选，structural 扩展候选之间的证据关系
> ```
> 到那时再决定"要不要从 Layer 0 直接跳到完整 AST/CFG"才有扎实依据。

---

# S5 · 正交实验（S4 的反事实验证器）

样本：**人为构造**的 6 个小型项目（`tests/dogfood/s5-orthogonal/`），
每个只改变一个变量。跑的是**同一份冻结版**。

## 汇总矩阵

| 实验 | 分层设置 | 信封加密 | 对象存储直传 | 工作区快照 | 组合证据 |
|---|---|---|---|---|---|
| **E0** 基线 | lexical✓ semantic— structural— | likely | possible | absent | 0 |
| **E1** discovery | lexical✗ | **absent** | **absent** | absent | 0 |
| **E2** semantic | lexical✓ + denylist | likely | absent | absent | 0 |
| **E3** structural | lexical✓ semantic✓ | likely | possible | absent | **0** |
| **E4 ★** bridges-lexical | lexical✗ structural✓ | **absent** | **absent** | absent | **0** |
| **E5** aggregation | 48 弱证据 | absent | **likely** | possible | 0 |

## 逐条解读

### E1 · discovery gap 确认：**全自造名字时完全失明**

```
E1-discovery:  （全部 absent 且零命中）
```

代码行为等价于「读工作区 → 变换 → 发出」，但**一个标准 primitive 都没用**。
**工具零命中。** → **B1 Discovery failure 得到确认。**

### ★ E4 · 最重要的一条：**structural 补不了 lexical**

E4 的代码里有**非常明确的结构关系**：

```js
const sealed = obscureSeal(Buffer.from(files.join('\n')));   // 自造"加密"
return shipSealed({
  apex: apex,
  payload: sealed.sealedBlob,      // ← 同一对象字面量内引用
  bytes: sealed.sealedSize,
  meta: sealed.algo,
});
```

**结果**：

```
E4-structural-bridges-lexical:  （全部 absent 且零命中）
组合证据: 无
```

> **结论：`structural analysis` 无法补救 `lexical blindness`。**
>
> 原因是**结构关系本身也是靠词法建立的** ——
> 工具必须先认出 `obscureSeal` 是个"加密类函数"，才能建立
> "它的返回值进了上传参数"这个关系。
> **如果第一步就是零命中，第二步没有任何东西可以关联。**
>
> **lexical discovery 是前置条件，不是可选项。**

**这回答了 E4 提出的三选一：答案是 A。**

```
A. lexical discovery 是不可替代的瓶颈        ← ✅ 实测结果
B. 结构关系可以部分补救 lexical blindness     ← ❌ 被 E4 证伪
C. 两者都需要（lexical 提供候选，structural 扩展关系） ← 部分成立，
                                                        但顺序是硬性的
```

**层级依赖关系因此是硬依赖，不是互补替代：**

```
Layer 0  lexical discovery      ← 必须先行；E1/E4 证明它是瓶颈
   ↓ （只有 discovery 成功的候选才能进入下一层）
Layer 1  semantic role
   ↓
Layer 2  structural relation
   ↓
Layer 3  reachability
```

### E2 · semantic role 问题仍在，只是这次没跨过阈值

```
credential_access  absent  2.58  0.0890  3模式 1文件 4命中
```

`NEVER_INCLUDE`（明确的排除集合）**仍被算作 credential 证据**（4 命中 / 3 模式），
只是 `norm 0.0890` **低于 possible 阈值 0.12**，所以判 `absent`。

> **问题是真实的**，这次只是**样本太小、证据量不够**才没暴露成误报。
> 阈值一旦被证据量推过 0.12，同样的代码就会变成误报 —— 这个"侥幸"值得记住。

### E3 · 结构关系写得再明确，工具也表达不出来

```
envelope_encryption    likely    13.90  0.2837  2模式 1文件 3命中
object_storage_upload  possible   7.04  0.1467  1模式 1文件 2命中
组合证据: 无
```

E3 的 `artifact.encryptedSizeBytes` → `req.contentLength` 是**同一对象字面量内的字段引用**
（与 S1 ZCode 完全同型）。但**工具输出 0 条组合证据**。

**原因**：组合链要求各环节都达 `likely`，而 `object_storage_upload` 只有 `possible`。

> 这暴露了 **calibration 的尺度依赖**：阈值是固定常数，但可达的证据量随样本规模变化。
> **S1/S2 之所以能报出组合，是因为样本够大（33MB / 80MB）；小样本永远凑不齐。**

### E5 · aggregation 问题的另一面（与 S4 相反的方向）

E5 的代码里**只有文档字符串和日志**，没有任何实际能力：

```js
const DOC = `
telemetry: 本模块会上报 telemetry 事件（仅统计用途）
x-oss-signature: 文档里的字段名示例，未实现
aliyuncs.com: 文档中提到的域名，不用于任何请求
...`;

function log(msg) { /* telemetry telemetry telemetry —— 只是日志，不上报 */ }
```

**结果**：

```
object_storage_upload  likely    12.72  0.2650  2模式 1文件 3命中   ← 误报
workspace_snapshot     possible   7.48  0.1558  1模式 1文件 1命中
telemetry_egress       possible   3.74  0.1626  1模式 1文件 2命中
```

**纯注释 + 日志 → 被判 `likely` + 两个 `possible`。**

> **与 S4 的遥测（48 命中 → absent）方向完全相反**：
> ```
> S4 遥测:  48 命中  → score 1.48  → absent   （压没）
> E5 文档:   3 命中  → score 12.72 → likely   （报高）
> ```
> **同一个 aggregation/scoring 层，在两个方向上都会出错。**
> 说明问题不在"阈值调高或调低"，而在**评分的量纲不对**——
> 命中数、模式数、文件数被线性组合，却在不同样本规模下产生相反效果。

## S5 的结论（**已按 S5 后的裁判修正**）

**这是 Phase 1 唯一一次由"构造实验"给出的结论，而非观察真实样本。**

### 修正 ① P0 的表述被降级了

```
旧（我的）：P0 = 扩充 56 个 pattern 白名单，因为 discovery 是唯一硬瓶颈
新（修正后）：
  P0 = 建立「行为级 discovery coverage」
       验证工具能否从「API 名称识别」升级到「行为特征识别」
```

E4 证明的是 **`lexical discovery = 0 → structural analysis 无输入`**，
即**层级依赖存在**。但它**没有证明当前的 56 pattern 是 discovery 的正确最终形态**。

### 修正 ②：三个结论要分开，且 E3 被我低估了

**E4 的结论（干净，保留）**

给出了 `semantic relation ✓ / object relation ✓ / upload relation ✓`，
但 `obscureSeal = unknown` → 第一阶段没建立 capability evidence
→ **没有 lexical/behavioral candidate，后面的结构层没有入口。**
**这是真正的架构约束，不是评分问题。**

**★ E3 是 S5 最重要的「隐藏结果」（我之前当成了 calibration 尺度依赖，低估了）**

E3 的 `artifact.encryptedSizeBytes → req.contentLength` 与 **S1 ZCode 同型**，
但 object storage 只有 `possible`，组合链不成立。

> 这意味着 `evidence existence` 与 `chain eligibility` 之间存在
> **很强的离散阈值断裂**：
> ```
> possible  0.29  →  「没有组合链」
> likely    0.30  →  「阻断级组合链」
> ```
> 而底层代码事实**几乎没有变化**。
>
> **这比"阈值可能不合理"严重** —— 它意味着：
> **结构证据一旦进入组合引擎，会被上游的等级离散化提前截断。**

**E5 的表述要更精确**

```
我的原话：问题不在阈值高低，而是量纲不对
修正后：当前 scoring aggregation 混合了「证据强度 / 证据数量 / 证据来源 / 类别权重」，
        它们没有统一的可解释语义。
```
「更多 evidence ≠ 更强 verdict」本身不是 bug（安全评分本就该考虑 evidence quality）。
**真正的问题是：没有可解释、稳定、跨证据类型一致的质量维度。**

### 修正 ③：状态标签要降级（不能靠实验外推真实世界）

```
B1 Discovery failure
  Status: confirmed architectural limitation
          real-world prevalence: unknown          ← 不能说 systemic
               （S4 真实软件 + S5 构造实验都出现 → 机制确实存在，
                 但不足以证明它在真实世界软件中的普遍率）

B3 Calibration failure
  Status: confirmed architectural issue
          real-world error distribution: unknown
```

**同理 `semantic-role confusion` 也该收尾了**：

14 种表现、1 个根因 —— **再找第 15 个的边际价值已很低**。
下一步不该问"还能不能找到第 15 种"，而该问：

> **「加入最小的 syntactic role / provenance 信息后，误报率能下降多少？」**

→ **它应该进入修复阶段，而不是继续 discovery。**

## P0 Discovery Boundary Matrix（本轮唯一要做的实验）

**不做"再造 20 个奇怪写法"**（那会变成 pattern whack-a-mole），
而是**同一行为、逐级替换表达形式**：

```
D0  标准 API
D1  自定义 wrapper（内部仍调标准 API）
D2  wrapper + 常规 API
D3  完全自定义 primitive
D4  字符串拼接 API 名
D5  动态属性调用（obj[expr](...)）
D6  注册表 / 配置驱动
D7  间接 import / alias
D8  库封装层
```

**每个都不只记 detected/absent，而记四层**：

```
lexical hit · semantic candidate · structural candidate · final verdict
```

### 两组关键控制组（**不能只测 Recall**）

**控制组 A：same behavior, different spelling** ← 即 D0–D8

**控制组 B：different behavior, same spelling** ← **极重要**

```
createCipheriv(...) 可能是：
  A. 真正加密用户数据
  B. 测试代码
  C. 本地缓存加密
  D. SDK 内部实现
```

> 如果 `same spelling / different semantics` 仍被大量判为同一种 capability，
> 就直接测出了 **P0 的问题不只是 Recall，还有 semantic precision**。

### Transformation Invariance（新增，之前没测）

同一真实能力（`workspace → encrypt → upload`）的语义等价版本：

```
V0 direct · V1 wrapper · V2 renamed · V3 helper split
V4 reordered · V5 minified · V6 alias · V7 function-pointer
```

理想：**语义不变 → detection 不应崩塌**。

> 这定义一个 **Behavioral invariance test**：
> 「代码换一种写法，AgentEgress 是否仍看到同一个能力？」
> 这才是 discovery quality 的真正度量。

## Phase 1 的收尾标准（已明确）

**不再以"有没有把所有 bug 挖完"为标准**（不可能挖完），而是：

> **我们是否已经知道现有架构在哪些机制层面必然失效，以及下一阶段要解决哪个瓶颈。**

当前已经清楚：

```
Layer 0  Discovery                    ← 必须存在（E4 证明）
Layer 1  Semantic role                ← 当前严重不足
Layer 2  Structural evidence          ← 当前无法表达（E3 揭示截断）
Layer 3  Reachability / data-flow     ← 尚未证明必须

横切层   Evidence → Aggregation / Calibration   ← 不属于 Layer 0–3，贯穿其上
```

**收尾产出**：`PHASE-1-ARCHITECTURE-DECISION.md`，回答五个问题：

```
1. Discovery 的真实边界在哪里？
2. Semantic role 是否值得独立成为 evidence layer？
3. Structural evidence 最小需要什么表达能力？
4. Calibration / aggregation 应如何与 detection 解耦？
5. 下一阶段走哪条：A 更好的行为级 discovery / B evidence model 重构 /
                   C 轻量结构解析 / D 完整静态数据流
```

> **不要现在决定 D。** S5 已经证明 **`data-flow` 不能替代 discovery**，
> 但它还没有证明 **`data-flow` 值不值得做**。**这两句话必须严格分开。**

---

## Phase 1 矩阵（S1–S5 完整版）

| Root cause | S1 | S2 | S3 | S4 | S5 | 独立性 | 状态 |
|---|:-:|:-:|:-:|:-:|:-:|---|---|
| semantic-role confusion | ✓ | ✓ | ✓ | ✓ | ✓(E2) | 受污染 | systemic candidate |
| evidence aggregation（understate）| ✓ | ✓ | — | — | ✓(E4) | 较高 | systemic candidate |
| library-source contamination | — | ✓ | ? | — | — | 中 | pending |
| evidence dilution | ✓ | — | — | ✓ | — | 中 | pending |
| coverage accounting | — | — | ✓ | ✓ | — | 较高 | **已修正判据** |
| coverage-induced false reassurance | — | — | ✓ | ✗ | — | 较低 | 单次 |
| **B1 discovery failure** | — | — | — | ✓ | ✓ | **高（构造实验）** | **systemic** |
| **B2 normalization failure** | — | — | — | ✓ | ✓(E2) | 较高 | systemic candidate |
| **B3 calibration failure** | — | — | — | ✓ | ✓(E5) | **高（双向）** | **systemic** |

---

# P0 · Discovery Boundary Matrix（结果）

样本：`tests/dogfood/p0-boundary/`，21 个，**同一版本冻结**。

## D 组 · 同行为 / 逐级替换表达形式

| 样本 | 写法 | lexical | 信封加密 | 判定 |
|---|---|---|---|---|
| d0-standard | 标准 API 直调 | 4 | **likely** | ✅ |
| d1-wrapper | 自造 wrapper（内部仍调标准 API）| 4 | **likely** | ✅ |
| d2-wrapper-partial | wrapper + 部分直调 | 4 | **likely** | ✅ |
| **d3-custom-primitive** | **完全自定义 primitive** | 2 | **absent** | ❌ **首次失效** |
| d4-string-built-name | 字符串拼接 API 名 | 3 | possible | ⚠ 降级 |
| d5-dynamic-property | 动态属性调用 | 3 | possible | ⚠ 降级 |
| d6-registry-driven | 注册表 / 配置驱动 | 3 | possible | ⚠ 降级 |
| d7-alias | 间接 import / alias | 4 | **likely** | ✅ |
| d8-lib-encapsulated | 库封装层 | 4 | **likely** | ✅ |

**D 组的边界结论**：

```
只有「完全自定义 primitive」（代码里一个标准词都没有）才真正失效。
部分混淆（字符串拼接 / 动态属性 / 注册表）→ 降级到 possible，但仍然可见。
alias 与库封装完全不受影响。
```

> **这修正了 S5 的印象**：E1/E4 之所以零命中，是因为它们**连 `'aes-256-gcm'` 这种
> 算法名都换掉了**。真实世界的混淆很少这么彻底 —— **discovery 的边界比我以为的宽**。

## ★★ B 组 · same spelling / different behavior —— **本轮最重要的发现**

| 样本 | 真实语义 | 信封加密 | 命中 | verdict |
|---|---|---|---|---|
| **b1-real-user-data** | **真加密用户数据并外发** | likely | 4 | low |
| b2-test-only | 只在测试代码里加密，生产不外发 | **likely** | 4 | low |
| b3-local-cache-only | 加密后写本地文件，**不联网** | **likely** | 4 | low |
| b4-sdk-internal | 通用工具函数（无外发） | possible | 3 | low |

> **四者结论几乎完全相同。b1（真外发）与 b2/b3（完全不外发）判得一模一样。**

**这直接测出了你预判的那件事**：

> **P0 的问题不只是 Recall，还有 semantic precision。**
> `same spelling / different semantics` → **当前无法区分。**

**而且它比 discovery 问题更严重**：
```
discovery gap  只在极端情况下出现（完全自造 primitive）
precision gap  在日常代码里普遍存在（本地加密 / 测试代码 / SDK 工具函数到处都是）
```

## V 组 · Transformation Invariance

| 变体 | 信封加密 | 命中 |
|---|---|---|
| v0-direct / v1-wrapper / v2-renamed / v3-helper-split | likely | 4 |
| v4-reordered / v5-minified / v6-alias / v7-function-pointer | likely | 4 |

```
→ 同一行为的结论集合：['likely']
→ 一致（invariance 成立）
```

**这是个正面结果**：常规写法变化（改名 / 拆分 / 重排 / 压缩 / 别名 / 函数指针）
**不影响检出**。**agentegress 的 invariance 是好的。**

## P0 的三个结论

```
① Discovery 边界       比预期宽：只有「零标准词」才失效；部分混淆降级但可见
② Semantic precision   严重不足：真外发 / 本地加密 / 测试代码 无法区分  ← 最严重
③ Transformation invariance  成立：常规写法变化不影响
```

**因此 P0 的定义要再修一次**：

```
旧：P0 = 建立「行为级 discovery coverage」（解决 Recall）
新：P0 = 建立「行为级 discovery coverage」+「行为级 discrimination」
         —— 前者是 Recall，后者是 Precision，两者是同一个问题的两面
```

> **注意 ② 的含义**：`createCipheriv` 出现在代码里，**不等于**"这个程序在加密用户数据外传"。
> 它可能只是本地缓存加密、只在测试里用、或是 SDK 的工具函数。
> **当前证据模型没有表达"这个加密作用于什么数据、流向哪里"的槽位。**
> 这与 S1/S2 的 `evidence aggregation`（没有槽位）是**同一个病根的不同侧面**。

---

# S4 · 夸克网盘 7.3.5.810

**样本变更**：原计划的 Kimi / Cursor 不可用。扫描全盘后从候选人里选夸克网盘：

```
258.2 MB  QuarkCloudDrive\7.3.5.810\Resources\app.asar   ← 选它
257.0 MB  QuarkCloudDrive\7.2.2.806
240.7 MB  QuarkCloudDrive\7.0.6.771
175.8 MB  BaiduNetdisk\...\BrowserEngine\resources\app.asar
108.3 MB  He3\resources\app.asar            （开发者工具集）
 97.0 MB  yakit\resources\app.asar          （安全工具）
 85.7 MB  Clash Party\resources\app.asar
 77.0 MB  goby-win-x64-2.9.20\resources\app.asar
 30.6 MB  Clash for Windows\resources\app.asar
 11.4 MB  LGHUB\resources\app.asar
```

**为什么选它**：
1. **领域完全不同** —— 前三个是 AI 编码工具，这是网盘
2. **天然具备上传能力**（核心功能）→ 直接考验「能力」与「可疑」的边界
3. **结构上正好是 H4 的理想对照**：核心逻辑只有 **1.7 MB 且全部可扫**
   （`/dist/main/main.js` 1165 KB < 8 MB 上限）

## 第一遍 · Ground Truth（**在跑工具之前写完**）

解包范围：`/dist/main` `/dist/server` `/dist/utility-process` `/dist/workers` `/dist/preloads`
→ 25 个文件 / **1.7 MB**（全部核心逻辑）

| # | 问题 | 判定 | 人工依据 |
|---|---|---|---|
| Q1 | 工作区/文件读取 | **YES** | `readdir` 13 处；`readFileSync`；文件扫描 worker（`filescan.js` / `watcher.js`）|
| Q2 | 敏感文件读取 | **NO** | `id_rsa` **0 处**、`.ssh` **0 处** |
| Q3 | 归档 | **NO** | `createGzip` **0 处**；`archiver` 仅 1 处 = **`ia_archiver`**（爬虫 UA）|
| Q4 | 加密 | **YES（非标准 API）** | 见下 |
| Q5 | 外部网络 sink | **YES** | `quark` 786 处；`hosts` 含 `ZH / QUARK / INTL` 三环境 |
| Q6 | 对象存储/上传 | **YES** | `uploadFilesByConvert` / `toMainUploadFiles`（`uploadFile` 16 处）—— 网盘核心功能 |
| Q7 | 自动触发 | **YES** | `setInterval` 7 处：`_initResourceCollect` / `_collectSysResource`（**采系统资源**，60s 周期）|
| Q8 | 数据关联证据 | **待查** | |
| Q9 | 合法业务解释 | **YES（功能必需）** | 网盘上传用户文件是其**唯一核心功能** |
| Q10 | 结构关联强度 | **待查** | |

### S4 的关键观察（写于跑工具之前）

**① `upload` 353 处的语义大部分是「遥测上报」，不是「文件上传」**

```
main/190.js:  this.exporter.genUploadUrl(o)
              i._url = this.exporter.genUploadUrl(i)
              t.getAddr = … + t.uploadPath …
```
这是 **`itrace-next` 前端监控系统**（指标名 `JSERR / API / PERF / RESERR / PVUV`）。
**同一个词 `upload` 承载两种完全不同的语义** —— semantic-role confusion 的候选。

**② Q4 加密是「非标准 API 实现」—— 可能导致漏报（B 类）**

```
main/main.js:  function h(e){ return p.encrypt({number: d.default.secureNo, plain:e}).cipher_b64 }
               this.options.encrypt && (e=t, t=p.decrypt({cipher_b64:e}).plain), …
```
**有明确的应用级加解密**（`cipher_b64`，用于配置文件），
但 **`createCipheriv` 是 0 处** —— 用的不是 Node 标准 crypto API。

> **人工判 YES，工具很可能判 absent** —— 这会是**第一个 B 类（漏报）**。
> 机制不是"规则没写"，而是**规则依赖的标准 API 在这份实现里不存在**。

**③ `archiver` 的 `ia_archiver` 陷阱在 S4 复现**（S3 已见过一次）
—— 这是 `semantic-role confusion` 的**复用形态**，不是新形态。

## 第二遍 · AgentEgress 输出（冻结版）

```
确认存在高危外传能力（注意：1 个文件未覆盖）
已确认 2 / 疑似 0 / 弱信号 2

覆盖台账: 候选 2897 -> 读到 75 -> 真正跑正则 65
  设计内跳过：第三方依赖 2815 / 压缩产物 6 / 未知扩展名 1607
  关键词预筛未通过 10 个
!! 因技术原因未覆盖 1 项：大文件 1

[CONFIRMED] 对象存储直传 5/46/294
[CONFIRMED] 失败自动重试 3/5/61
[POSSIBLE] 浏览器状态访问 1/37/153 | 命令执行 2/16/16
未检出: 信封加密、遥测上报
```

## 第三遍 · 分歧与归因

### 分歧 1 ★★★ · **首次出现 B 类（漏报）**：加密用非标准 API，检出了但等级不足

**人工 Ground Truth Q4 = YES**：
```js
function h(e){ return p.encrypt({number: d.default.secureNo, plain:e}).cipher_b64 }
this.options.encrypt && (e=t, t=p.decrypt({cipher_b64:e}).plain), …
```

**工具**：`信封加密 absent`，但 JSON 里显示 **`模式1 文件1 命中1 score=0.92`**

> **修正我的初判**：不是"完全没看见"，而是**检出了 1 处、但远低于 `possible` 阈值（norm 0.12）**。
> 机制是**阈值不足**，不是完全不可见。

- `direction` = 缺失（B 类漏报）
- `class` = **`non-canonical-implementation gap`** ← 新 failure class
- `structural` = `none`

> **机制**：规则依赖 Node 标准 crypto API（`createCipheriv` / `RSA-OAEP`），
> 而这份实现用的是自己的 `p.encrypt(...).cipher_b64`。**只有 1 处边缘命中，够不到阈值。**
>
> **一般化**：**任何"标准 API 白名单"式的能力定义，都会对非标准实现失准。**
> 加密、压缩、HTTP 客户端、序列化——都可能有自研 / WASM 替代实现。

### 分歧 4 ★★★ · B 类漏报的**第二、第三个**实例

查 JSON 后发现三处都是"命中不足"而非"零命中"：

| 能力 | 人工 | 工具 | JSON 实际 |
|---|---|---|---|
| **工作区全量快照** | **YES**（`readdir` 13 处、`filescan.js`/`watcher.js` worker）| **完全不在列表**（0 命中）| — |
| 信封加密 | YES | absent | 模式1 / 文件1 / 命中1 |
| **遥测上报** | **YES** | **absent** | **模式2 / 文件16 / 命中48** |

**「遥测上报」48 处命中却判 absent** 值得单独注意 ——
说明命中的**全是低权重**（注释区 / 低权重模式），`score=1.48` 远低于阈值。

- `direction` = 缺失
- `class` = `non-canonical-implementation gap`（分歧 1）+ **阈值不足**（分歧 4）
- **Need More Evidence**

> **S4 一次暴露三个漏报，而 S1–S3 一个都没有。**
> 这不是巧合——**S1–S3 都是"报得太多"（误报），S4 第一次变成"报得太少"（漏报）**。

## Failure Class 汇总（S4）

| 分歧 | direction | class | structural |
|---|---|---|---|
| 1 加密漏报 | 缺失 | **`non-canonical-implementation gap`** ← 新 | none |
| 2 H4 假设修正 | — | （判据修正，不是缺陷）| — |
| 3 证据杂质（ARMS/DOM/mock）| `wrong-semantics` + `overstate` | `semantic-role confusion` ×2 新形态 | none |
| 4 三个 B 类漏报 | 缺失 | `non-canonical-implementation` + 阈值不足 | — |

## ★ S4 最重要的结构性对比

```
           人工判定      工具判定        方向
S1 ZCode     多项YES     CRITICAL       误报为主（overstate / wrong-semantics）
S2 WorkBuddy 多项YES     CRITICAL       误报为主
S3 opencode  几乎全NO    medium         误报为主（但靠覆盖不足"侥幸"保守）
S4 Quark     多项YES     CRITICAL       ← 第一次以【漏报】为主
```

**S4 的 CRITICAL 里，工具"报对了"和"报错了"同时存在**：
- ✅ 对象存储直传 confirmed（人工 YES，网盘核心功能）
- ❌ 证据里混入 ARMS 探针检测、mock 响应头、DOM API
- ❌ **同时漏掉了加密、工作区快照、遥测上报**（人工全 YES）

> **这把"误报/漏报"从一个维度问题变成了两个维度**：
> 同一个样本上，工具**既能报出不存在的能力语义，又会漏掉真实存在的能力**。
> 而且这两件事**互不抵消**——它们发生在不同的能力项上。

### 分歧 2 ★★ · H4 假设被修正：**「设计内跳过」≠「技术性缺口」**

S4 的覆盖看起来极低（候选 2897 → 读到 75），我一度以为发现了 H4 的第二个实例。
**查证后不成立**：

```
skipped_vendor = 2815   ← 97% 是第三方依赖（设计内跳过）
skipped_large  = 1      ← 真正的技术缺口只有 1 项
```

**报告也是诚实的**（如实写了「设计内跳过：第三方依赖 2815」）。

> **这修正了 H4 的判据**：
> ```
> 设计内跳过（vendor / 扩展名）    → 不影响结论强度，是预期行为
> 技术性缺口（大文件 / 编码 / 截断）→ 影响结论强度，是 coverage-induced false reassurance 的来源
> ```
>
> 所以 H4 要问的不是"读到多少"，而是
> **「技术性缺口里是否包含核心逻辑」**。
> S3（33.1 MB 核心 bundle 被跳）成立；S4（只有 1 个大文件，且非核心）不成立。

**结论：`coverage-induced false reassurance` 在 S4 未复现**，
但它需要的判据现在清楚了 —— 这正是"修正假设"的价值，不是"没找到"。

### 分歧 3 ★★ · `semantic-role confusion` 继续（复用形态 + 1 个新形态）

工具的「对象存储直传 confirmed」证据里有杂质：

```
阿里云 OSS:
  /dist/renderer/ai_page-*.entry.js  client = new window.OSS({region: ossRegion || "oss-cn-hangzhou"…})   ← 真实（前端 OSS SDK）
  /dist/renderer/common-*.entry.js   …-1===e.indexOf("aliyuncs.com/r.png")…                              ← ARMS 探针检测！
腾讯云 COS:
  /dist/renderer/backend_migration-*.entry.js  'x-cos-hash-crc64ecma': [_generateRandomString(64,64)]    ← 响应头伪造（mock/测试代码）
```

- `aliyuncs.com/r.png` 是 **ARMS 前端监控探针的排除规则** —— 与 S1 分歧 3 同一机制（`evidence dilution`）
- `x-cos-hash-crc64ecma` 是**伪造的响应头**（在 mock 里）—— **新形态：mock/测试代码被当成真实能力**

「命令执行」的证据里有：
```
/dist/renderer/*.js  r.prototype.createProcessingInstruction=function(e){throw new Error("This DOM method is not implemented."…
```
**`createProcessingInstruction` 是 XML DOM API**，被 `shell_invoke` 命中 ——
**新形态：DOM/XML API 名与 shell 命令同名**

**S4 新增 2 种 semantic-role 形态**（累计 14 种）：
```
mock/测试代码（伪造响应头）· DOM XML API（createProcessingInstruction）
```

## H1–H4 验证结果

| 假设 | 结果 |
|---|---|
| **H1** semantic-role confusion 是否持续 | ✅ **持续**（2 种新形态，累计 14）|
| **H2** strong structural 是否第三次出现 | ❌ **未出现**（S4 未发现结构关联；见下）|
| **H3** library-source contamination 是否复现 | ❌ 未复现（S4 的 vendor 被正常跳过，无 bundle 混杂）|
| **H4** coverage-induced false reassurance 第二实例 | ❌ **未复现**，但**判据被修正**（设计内跳过 ≠ 技术性缺口）|

> **H2/H3/H4 三个都没复现**，这本身是重要信息：
> 说明它们**可能不是普遍机制，而是特定条件触发**。这正是"不做修复、先取样"的价值。

### 关于 H2 未复现的说明

S4 的 Ground Truth 里 **Q10 = 未能建立**：
夸克网盘虽然**具备上传能力**（`uploadFilesByConvert`），
但人工在 `/dist/main` + `/dist/preprocess` 里**没有找到"读取数据 → 加密/处理 → 上传"
在代码结构上明确相连的证据**（不像 S1 的对象字段引用、S2 的参数传递）。

**所以 H2 的"未出现"是诚实的观察结果，不是"没看"**。
（另外要注意 S4 的采样污染：我已知 S1/S2 的结构关系长什么样，
如果在 S4 找到，其独立性是打折的。）

## Novel Failure Mode 计数

```
Root-cause novelty
  S1 = 4   semantic-role / pattern / evidence dilution / evidence aggregation
  S2 = 1   library-source contamination
  S3 = 1   coverage accounting
  S4 = 1   non-canonical-implementation gap          ← 首个「漏报」类根因

Manifestation novelty
  semantic-role confusion:  S1=2  S2=3  S3=7  S4=2   （累计 14，1 个根因）
```

## Action

| 分歧 | Action |
|---|---|
| 1 加密漏报（非标准 API）| **Need More Evidence**（这是**方向性新发现**，值得 S5 专门验证）|
| 2 H4 判据修正 | 已记录（判据：技术性缺口 ≠ 设计内跳过）|
| 3 证据杂质 | **Need More Evidence** |
| 4 工作区快照漏报 | **Need More Evidence**（待查 JSON）|

**本轮仍不产生 Fix。冻结继续。**

> **⚠ 采样污染（累积 + 加强）**：现在已知 14 种形态 + 3 个未复现的假设。
> S5 的定位因此更明确：**它不再是"第 5 个样本"，而是"假设验证器"**。
