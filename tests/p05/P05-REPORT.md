# P0.5 · Role Evidence Probe 报告

> **问题（老大定的）**：
> **在不引入 AST/CFG 的情况下，local consumer / use-site 信息
> 能把多少 `semantic_role = unknown` 变成有可靠依据的角色？**
>
> **性质**：小型、可否证的**分析实验**。不是"语义分析器"。
> **未改动 `agentegress.py`**（冻结基线保持一致）。

---

## 一、范围（严格限定）

**只做**：
```
same file · local symbol · direct consumer · simple branch/use context
```

**明确不做**（防 scope 爆炸）：
```
跨函数完整追踪 / 跨文件追踪 / CFG / 完整 AST /
alias analysis / data-flow engine / 运行时执行
```

实现：`tests/p05/probe.py`（约 300 行纯文本分析，**零依赖**）

---

## 二、验收结果：5 / 5 PASS

样本全部取自 **S1 / S2 / E5 的真实代码**（非构造）。

| Case | 来源 | 期望 | 实际 | conf | 依据 |
|---|---|---|---|---|---|
| **A** | S1 ZCode `_ct` 函数 | `denylist` | **denylist** ✅ | medium | 集合 + 成员判断（分支在调用方）+ **函数名 `looksLikeSecretPath`** |
| **A'** | 对照组：真读取密钥并外发 | `active_operation` | **active_operation** ✅ | medium | 字符串进入了网络/文件 sink |
| **B** | S2 WorkBuddy `Co` 函数 | `detection_rule` | **detection_rule** ✅ | medium | 正则 `.test()` + 与动作字段比较 |
| **C** | E5 文档字符串 | `documentation` | **documentation** ✅ | medium | 字符串 + 仅被日志消费 |
| **D** | 反例：E5-like 串进了 `request.body` | NOT documentation | **active_operation** ✅ | medium | 字符串进入了网络/文件 sink |

**role 分布**：`active_operation 2 / denylist 1 / detection_rule 1 / documentation 1`
**unknown：0 例**

> **A 与 A' 放在一起是有意的**：同一个 token（`id_rsa`），
> 一个是「排除名单」、一个是「真的读取外发」，**probe 给出了相反的 role**。
> 这正是 Phase 1 里工具做不到的事。

---

## 三、第一轮暴露的三个真实缺陷（已修）

**这三个缺陷不是设计问题，是实现细节，但每一个都会造成整类误判。**

| # | 缺陷 | 后果 | 修法 |
|---|---|---|---|
| 1 | `region_at` 用「当前行内是否有未闭合引号」 | **跨行模板字符串完全判错** → C 例 FAIL、D 例"侥幸 PASS"（结论对理由错）| 改为整文件扫描区域（O(n)，单文件可接受）|
| 2 | `identity_cmp` 只匹配 `=== "` | **漏掉 `"read" === Q.action`（字符串在左）** → B 例 FAIL | 改为双向匹配 |
| 3 | 消费者窗口前向只有 60 字符 | S2 的判定条件在 token **前面**被截掉 | 前向扩到 220 字符 |

> **第 1 条值得单独记**：`D` 例在第一版是 **PASS**，但理由是错的 ——
> 它答对了"不是 documentation"，却是因为**判错了区域**而落到 `unknown`。
> **如果只看 PASS/FAIL 计数，这个缺陷会被完全掩盖。**
> 所以验收必须看**理由**，不只是结论。

---

## 四、P0.5 要求的三个产出

### ① 哪些 role 可以靠 local consumer analysis 稳定识别

**4 类，均有明确的本地判据**：

| role | 判据 | 实测 |
|---|---|---|
| `documentation` | 区域 = 注释 / 字符串，且消费者只含日志类 | ✅ C |
| `active_operation` | 值进入网络或文件 sink | ✅ A'、D |
| `detection_rule` | 正则 + `.test()` + 与某字段做恒等比较 | ✅ B |
| `denylist` | 集合字面量 + 成员判断 +（排除分支 **或** 命名信号）| ✅ A |

**这四类覆盖了 Phase 1 误报的绝大部分**（S1/S2/S3 的 14 种形态里，
最大两族就是「排除/允许名单」和「检测规则」）。

### ② 哪些 role 即使看 consumer 仍然无法判断

```
· allowlist vs denylist  —— 当分支在调用方、且无命名信号时（A 例就是这种情况）
· ui_representation vs 配置对象 —— 都是对象字面量，消费方式相同
· schema_definition      —— 与普通对象字面量无法区分
· 「集合 + 成员判断」但无分支无命名 → 规则明确返回 unknown（不硬猜）
```

### ③ ★ 哪些情况开始需要跨函数信息（**最重要**）

**A 例就是分界线，而且它是一个"侥幸成功"**：

```js
bct = new Set([".env", ..., "id_rsa", "id_ed25519"]);   // 本地能看见

function _ct(e) {
  ...
  return bct.has(r) || r.endsWith(".pem") || r.includes("token");
  //     ↑ 成员判断在本地可见
  //       但「这个判断的结论被用来排除还是保留」在**调用方**
}
a(_ct, "looksLikeSecretPath");      // ← A 例靠这个函数名判出 denylist
```

**判定分支在调用方 → 本地信息不足 → 需要跨函数。**

**本次之所以成功，是因为 minified 代码保留了可读函数名 `looksLikeSecretPath`。**

> **如果代码更彻底地混淆（没有 `a(fn, "name")` 这种保留命名），A 例会 FAIL。**
>
> **这就是 Layer 3 的候选边界** —— 不是"感觉需要跨函数分析"，
> 而是**实测到的一个具体缺口**：`分支语义在调用方时，本地信号可能完全缺失`。

---

## 五、KPI 讨论（按老大的纪律）

**要求的 KPI**：
```
role coverage ↑   **且**   role precision 不下降
```
**不是** `unknown ↓`。

本次实测：

```
旧模型（无 role 概念）：
    隐含把所有 lexical 命中当 active_operation
    → coverage 100%，precision 极低（S1–S5 已实测 14 种误判）

本次 probe（5 例）：
    4 类不同 role，0 个 unknown，全部与人工判断一致
```

### ⚠ 扩大测量推翻了手挑 case 的结论

在 **完整文件** 上跑（79 条 lexical 命中）：

| 目标 | 大小 | unknown |
|---|---|---|
| S1-ZCode `out/host/index.js` | 2.5 MB (min) | **77%** |
| S1-ZCode `out/main/index.js` | 0.7 MB (min) | **80%** |
| S3-opencode `out/main/index.js` | 0.2 MB (min) | **100%** |
| **S3-opencode `node-BIz0dqH1.js`** | **32.9 MB（未压缩）** | **100%** |

```
总体：unknown 68 / 79 = 86%
      有依据 11 / 79 = 14%
```

**从 100%（5 个手挑 case）掉到 14%（79 条真实命中）→ 手挑 case 严重过拟合。**

### 我一开始判错了原因，对照实验纠正了它

**我的假设**：minified 让变量名压成 `e`/`t`，`find_uses` 失去区分度。

**加未压缩对照后证伪**：33 MB 的**未压缩** bundle **同样是 100% unknown**。

**真正的原因：三级规则的覆盖面太窄。**

```
① 被已知 API 直接包裹        —— 大多数命中不在这个形态
② 属于有绑定变量的集合容器    —— 大多数命中不在 Set/Array 里
③ 在注释 / 字符串里           —— 大多数命中在 code 区
→ 三级都不成立 → unknown
```

> **大多数 lexical 命中，本身就没有可识别的本地消费结构。**
> 这跟"信息在不在本地"无关，也跟"是否 minified"无关。

### 而且这 14% 里精度也不高

抽样 11 条"有依据"的判定，**至少 4 条明显错误**：

```
[documentation] aes-256-gcm       ← 错：它是加密算法名，不是文档
[documentation] createCipheriv    ← 错
[detection_rule] aes-256-gcm      ← 错
[detection_rule] retryCount       ← 错
```

→ **precision ≤ 64%**（11 条里最多 7 条可能对）

### KPI 实测结果

```
role coverage  : 14%  （远低于手挑 case 的 100%）
role precision : ≤ 64%
```

**两者都不理想。而且这正是你警告的形态 —— 但我这次是反过来的：
不是"unknown 被错误自信取代"，而是"少量有依据的判定里还混着错"。**

---

## 六、结论

> **local consumer analysis 在当前实现下，覆盖 14%、精度 ≤ 64%。**
> **它离"能填上 `semantic_role`"还很远。**

**但有一个成功案例值得保留** ——

**A 例（S1 的 denylist）是真正跑通的**：
```js
bct = new Set([".env", ..., "id_rsa", "id_ed25519"]);
function _ct(e) { ... return bct.has(r) || ... }
a(_ct, "looksLikeSecretPath");           // ← 决定性信号
```
→ `denylist`（confidence **medium**），依据是「集合 + 成员判断 + 函数名」。

**说明特定形态下可行，只是覆盖面窄。**

### 三个产出（回答 P0.5 的定义问题）

**① 可稳定识别**（有精确依据时）：
```
documentation      —— 注释区 / 纯日志消费
active_operation   —— 进入网络或文件 sink
denylist           —— 集合 + 成员判断 +（排除分支 或 命名信号）
detection_rule     —— 正则 + .test() + 与字段恒等比较
```
这四类正好覆盖 Phase 1 里**最大的两族误报**（名单类、检测规则类）。

**② 仍然无法判断**：
```
allowlist vs denylist（分支在调用方、无命名信号）
ui_representation vs 配置对象
schema_definition
「有集合但无分支无命名」→ 规则明确返回 unknown（不硬猜）
```

**③ ★ 需要跨函数信息**：
**A 例就是分界线，而且它是一次"侥幸成功"**：
```
_ct 返回 boolean，排除分支在调用方 → 本地看不到
A 例之所以成，靠的是 minified 代码保留了可读函数名 looksLikeSecretPath
→ 若代码更彻底混淆，A 会 FAIL
```
**这就是 Layer 3 的候选边界 —— 实测出来的，不是猜的。**

---

## 七、下一步（我的建议）

现在的证据指向一个**明确的二选一**：

### 路线甲：继续做 use-site（选项 1 的加强版）

**但必须先解决"精确使用点"问题**，否则永远停在 14%/64%。

难点：
```
· 无绑定变量的字面量（正则里的 token、裸字符串）怎么定消费点？
· 大文件里同名短变量的歧义怎么消？
· 「窗口」这个手段已被证明不可靠，需要换成什么？
```

**如果这三条没有便宜解法，那 use-site 就不该继续做。**

### 路线乙：接受"大部分命中注定 unknown"，把力气花在别处

**因为 Phase 1 的核心问题不是"unknown 太多"，而是"把错误的当正确"。**

```
18% 的高置信 role（即使 precision 只有 60%）如果能稳定产出，
就足以消掉 S1/S2 里最大的两族误报（denylist / detection_rule）
—— 而剩下的 86% 保持 unknown，本来就不该被当成结论。
```

**这条路更便宜，也更符合"宁可 unknown，不要错误自信"的纪律。**

**我倾向路线乙**，但这是**要你定的**：
毕竟它等于承认"semantic_role 只能部分填充"，
而这会直接影响 `Evidence object` 的设计（`role` 字段大部分时候是 `unknown`，
那么 `Assessment` 就不能太依赖它）。

