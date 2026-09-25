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

**人工读代码**：这是一个**文件名排除集合**（`new Set([...])` 被用作"不纳入的名单"），
不是"要去读的文件列表"。变量名 `Pct` / `bct`（minified）无法确认用途，
但 **`new Set` 的构造 + 紧邻 `.git`** 指向"过滤/排除"语义。

**归因**：`semantic interpretation failure` + `context failure`
—— 工具看到了正确的字符串，但**把「排除名单」读成了「读取目标」**。

**这是 C 类（误报），且与本轮之前修掉的 `oss_export` / `NEVER_BACKUP` 同一根源。**

> **重要**：我在 v0.2.6 加了 `NEGATIVE_CONTEXT`（±120 字符内的 never/exclude/排除/禁止…），
> 但**这个案例没有触发它**——因为代码里没有这些英文/中文词，
> 只有 `new Set([...])` 这种**结构性线索**。
> **说明负向上下文只覆盖了"显式写明排除"的情形，覆盖不到"用数据结构表达排除"。**

### 分歧 2 ★★ · Git 历史访问：人工 **NO** ↔ 工具 **likely**

同一份代码里 `Pct = new Set([".git"])` —— **`.git` 出现在排除集合里**。

**人工判断**：把 `.git` 列入排除集，恰恰说明**不处理** `.git`。

**归因**：同分歧 1（`semantic interpretation failure`）。

### 分歧 3 ★★ · 对象存储直传：结论对，但**证据不纯**

工具报 3 个模式命中，其中 `aliyun_oss` 的证据：

```
/out/main/chunk-6XM33EZR.js:1  …log.aliyuncs.com/rum/web/v2?workspace=…&service_id=…   ← ARMS RUM 遥测
/out/main/chunk-DBVOEQ2Z.js:1  …log.aliyuncs.com/apm/trace/opentelemetry…             ← APM 链路追踪
```

**人工读代码**：这两处是**遥测/APM 端点**，不是对象存储。

**归因**：`pattern failure` —— `aliyun_oss` 模式的判据过宽（`aliyuncs.com` 一个域名
同时承载 RUM / APM / OSS 三种服务）。

**结论仍然正确**（真 OSS 证据在 `host/index.js:332` 确实存在），
但**"3 个模式命中"这个计数被稀释了**——按阈值它本应是更强的证据。

> **新的失败模式**：`evidence dilution` —— 弱相关的命中混在强证据里，
> 使「模式数 / 命中数」这两个驱动等级的指标失真。

### 分歧 4 ★★★ · 数据关联被**低估**（D 类反向）

**人工发现**：`out/host/index.js:487` 里，
`objectUpload.maxBytes` 直接取自 `t.encryptedArtifact.encryptedSizeBytes`，
且同文件有 `class RepoSnapshotUpload` + `uploadObject` / `uploadPostObject` / `uploadPutObject`
/ `consumeUploadCredential` 的**方法链**。

**这是代码级的数据关联**，不是巧合共现。

**工具输出**：`[阻断级] 工作区采集+加密+对象存储直传  关联度: 较强(same_file)`
并附说明「**共现 ≠ 在同一条可达路径上，可能来自互不相关的代码**」。

**归因**：`evidence aggregation failure`（**低估**方向）
—— 工具把**已经观察到的最强证据**（同一对象字面量内的字段引用）
统一降格为「同文件共现」。

> **这是本轮最重要的发现。**
> 之前所有讨论都假设工具的问题是"把共现说成链"（**高估**）。
> 但真实样本显示：工具**只有"共现"这一种表达能力**，
> 所以当真正存在强关联时，它**反而无法表达，只能降级陈述**。
> 这解释了为什么 `same_file` 在 ZCode 上 5/5 全中——
> 它根本不是"关联度"，而是"这个目标被 bundle 过"的同义反复。

## Failure Class 汇总（按基线的 8 类）

| 分歧 | 分类 | 可复现 |
|---|---|---|
| 1 凭据访问 confirmed | `semantic interpretation failure` + `context failure` | ✅ 见 A1 |
| 2 Git 历史 likely | `semantic interpretation failure` | ✅ 见 A1 |
| 3 遥测端点计入 OSS 证据 | `pattern failure` | ✅ 见 A2 |
| 4 强关联被降格为共现 | `evidence aggregation failure`（低估） | ✅ 见 A3 |

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

**`Novel failure modes / sample` = 4.0（S1）** —— 后续样本应观察该值是否下降。
