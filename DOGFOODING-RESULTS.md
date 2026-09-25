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

| 指标 | 定义 | 回答的问题 |
|---|---|---|
| **Root-cause novelty** | 每个样本引入的**新 failure class** 数量 | 发现了多少**新的根因** |
| **Manifestation novelty** | 按 class 分组记录**表现形态** | 同一根因有多少种**承载形式** |

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

| # | 问题 | 判定 | 人工依据（文件:行 + 原文） |
|---|---|---|---|
| Q1 | 工作区读取 | **YES** | `out/scheduler/index.js:832` `conversationWorkspaceRoot`；`repoSnapshot` 全库 80 处 |
| Q2 | 敏感文件读取 | **NO** | `.ssh/` **0 处**；`NEVER_` **0 处**。反证见下方分歧 1 |
| Q3 | 归档 | **YES** | `out/host/index.js:477` `import{createGzip as Bst}from"zlib"`；`:479` `a(Vst,"writeGzipTarToPath")` |
| Q4 | 加密 | **YES** | `out/host/index.js:477` 同时 import `createCipheriv` **与 `publicEncrypt`** → 信封加密（非对称包裹对称密钥） |
| Q5 | 外部网络 sink | **YES** | `undici` 的 `fetch`；`zcode.z.ai`；`*.aliyuncs.com` |
| Q6 | 对象存储 | **YES** | `out/host/index.js:332` `a(Iot,"buildOssFormFields")`，构造完整 OSS PostObject 表单（`x-oss-signature`/`policy`/`x-oss-credential`） |
| Q7 | 自动触发 | **YES** | `out/scheduler/index.js:834` `Hn("info","cron scheduler started")` + `DP=setInterval(NP,uBe)`；上下文含 `off-peak recoverInterrupted` |
| Q8 | **数据关联证据** | **YES（强）** | `out/host/index.js:487`：`objectUpload:{url:r.oss.host, maxBytes:Math.max(t.encryptedArtifact.encryptedSizeBytes,1), formFields:{...}}` —— **加密产物的字节数直接作为上传表单的 maxBytes**，同一对象字面量内。同文件另有 `class RepoSnapshotUpload` / `uploadPostObject` / `uploadPutObject` / `consumeUploadCredential` / `uploadObject` |
| Q9 | 合法业务解释 | **部分** | 遥测（ARMS RUM / APM）是标准做法；快照上传有 2026-09 事件背景 |

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
> ```
> never(...)   exclude(...)   Set([...])   if (...)   filter(...)   denylist
> ```
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
> ```
> 旧担忧：弱证据 × 很多次 → 刷分（已用 max + 多样性封顶解决）
> 新发现：弱证据 × 很多次 → 强证据辨识度下降
> ```
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
> ```
> 文本共现  →  结构关联  →  局部数据依赖  →  跨函数可达路径  →  完整 source→sink
>    ↑            ↑
>  现有模型    这次实际发现的位置
> ```
> 这次发现的**不是**"需要完整 data-flow"，而是
> **"结构关联 / 局部数据依赖已经超出当前模型的表达能力"**。
>
> 第一阶段可能只需要一个**很窄的中间层**：
> ```
> object literal · parameter relation · same function · same call chain · same imported symbol
> ```
> 即先让工具能表达：「这两个证据不只是出现在同一个 bundle，而是代码里存在**可观察的结构关系**」。
> 这远比引入 AST/CFG/data-flow 便宜。
>
> **但现在不做。** 当前最重要的是回答：
> **这是 ZCode 的特例，还是多个真实客户端都存在的普遍失败模式？**

## Failure Class 汇总

| 分歧 | direction | class | structural | 可复现 |
|---|---|---|---|---|
| 1 凭据访问 confirmed | `wrong-semantics` | `semantic-role confusion` | none | ✅ A1 |
| 2 Git 历史 likely | `wrong-semantics` | `semantic-role confusion` | none | ✅ A1 |
| 3 遥测端点计入 OSS 证据 | `overstate` | `pattern failure` | none | ✅ A2 |
| 4 强关联被降格为共现 | **`understate`** | `evidence aggregation` | **strong** | ✅ A3 |

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

| 分歧 | Action | 说明 |
|---|---|---|
| 1 | **Need More Evidence** | 单样本不足以断定"排除列表"是普遍模式。需在 S2/S3 验证：其他客户端是否也用 `new Set`/数组表达排除？ |
| 2 | **Need More Evidence** | 同上，与 1 同源 |
| 3 | **Need More Evidence** | 需确认 `aliyun_oss` 模式的定义域；但**先不改**——按纪律，Phase 1 不动代码 |
| 4 | **Need More Evidence** | 需要设计一个能表达"同对象内字段引用"的判据。**但先不改** |

**本轮不产生 Fix。** 按基线纪律，所有分歧先累积，Phase 1 结束后再统一判断。

---

## Novel Failure Mode 计数

| 样本 | 新失败模式 | 说明 |
|---|---|---|
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
> S4 的人工分析必然受此影响。**此后的"新形态"其独立性递减**，记录时必须标注。 —— 后续样本应观察该值是否下降。
