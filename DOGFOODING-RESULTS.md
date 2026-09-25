# DOGFOODING RESULTS · Phase 1

> 冻结基线：commit `f561272`，`agentegress.py` sha256 `48B914A0...F2EC7`
> 期间**未修改任何代码 / 规则 / 权重 / 阈值**（见 `DOGFOODING-BASELINE.md`）
> 方法：三遍观察法 —— ① 完全不看工具建立 Ground Truth ② 跑工具做差分 ③ 攻击"不一致"并归因

**目标不是 F1，是发现"以前设计时没想到的失败模式"。**

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
> 修正来源是**工具的证据**，不是事后猜测。这是 dogfooding 的正当流程。| —— 后续样本应观察该值是否下降。
