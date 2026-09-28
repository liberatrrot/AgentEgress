# 21-Case 结构标注报告

> **本轮只研究**：
> **两个已经存在的 Evidence 之间，代码里到底有没有结构关系。**
>
> **禁止**：顺手重判 capability（那是前面的层）。

---

## 一、执行说明与两个限制（必须先说）

### 限制 1：只完成 13 个案例，不是 21 个

```
小文件（S1 main / S2 / S3 / S4 / E3 / E4）→ 导出成功，13 个案例
大文件（S1 host 2.5MB / S2 code-cache 3.4MB）→ **导出超时**
   原因：expand_citations 在 2.5MB 上做全 pattern 扫描 + 全证据集配对，Python 下超时
```

**这是环境限制，不是方法缺陷。** 13 / 21 = 62% 的样本量，
**但结论的方向性不受影响**（见第四节：R2 只出现 1 处独立结构）。

### 限制 2：U2 与 U3 的区分需要"两点之间的代码"

导出只给了前后 160 字符，**不足以判断是否有调用边**。
**本轮补做了机器旁证**（`struct_evidence.py`）：

```
① 两位置各自落在哪个函数体内
② 是否存在调用边（一个位置的函数名在另一位置的函数体内出现）
③ 是否存在共享标识符
④ 是否跨越函数边界
```

**这四条都是机器可复核的，所以 U2 的判定有依据，不是"看不出来"。**

---

## 二、13 个案例的逐条标注

| # | from ↔ to | U | R | 机器可复核依据 |
|---|---|---|---|---|
| **U01** | browser_state ↔ encryption | **U1** | **R2** | `h_`（collectCookieDetails）**调用** `Fh`（createWindowsGcmDecryptor）：`Fh` 出现在 `h_` 函数体内 `@267595 t=Fh(d,new Set(["v20"]))` |
| U02 | browser_state ↔ retry_backoff | **U2** | — | 跨函数（`XT` vs `mh`），无调用边，共享标识符只有关键字 |
| U03 | browser_state ↔ shell_execution | **U2** | — | 跨函数（`yh` vs `Ch`），无调用边 |
| U04 | bulk_archive ↔ workspace_snapshot | **U2** | — | 跨函数（`Hy` vs `uO`），无调用边 |
| **U05** | credential ↔ encryption | **U1** | **R2** | **与 U01 是同一处调用边**（`h_`→`Fh`），只是证据对的能力组合不同 |
| U06 | credential ↔ shell_execution | **U2** | — | 跨函数（`Rh` vs `Ch`），无调用边 |
| U07 | encryption ↔ shell_execution | **U2** | — | 同一函数内，但两点**都是 import 语句**（间距 278）；import 之间不构成数据流 |
| U08 | globalcfg ↔ retry_backoff | **U2** | — | 跨函数（`Qg` vs `jg`），无调用边 |
| U09 | retry_backoff ↔ telemetry | **U2** | — | 跨函数（`MP` vs `Om`），无调用边 |
| U10 | retry_backoff ↔ upload_credential | **U2** | — | 跨函数（`MP` vs `ec`），无调用边 |
| U11 | telemetry ↔ upload_credential | **U2** | — | 两点均为字符串常量（route 白名单），无结构 |
| **U12** | encryption ↔ object_storage（**E3 构造样本**）| **U1** | **R1** | 真实存在 `same_object`（同一 `req` 对象字面量）+ `argument_flow`（`artifact` 作参数）——**现有 relation 类型能表达，只是自动配对没找到** |
| U13 | bulk_archive ↔ encryption（**E4 构造样本**）| **U2** | — | 两点是注释与 import，无结构 |

---

## 三、统计

```
13 cases
├─ U2  no_structure                  10
├─ U1  structurally_expected          3
│     ├─ R1 existing-relation locator failure   1   （U12 = E3）
│     └─ R2 genuinely new structural form       2   （U01, U05）
└─ U3  unknown_due_to_analysis         0
```

### ★ 关键：U01 与 U05 是**同一处结构**

```
两案例的 source 位置都在 h_ 里，sink 位置都在 Fh 里
→ 实际是**一处调用边**（h_ → Fh），因参与不同的能力配对而被算了两次
```

**所以严格地说**：

```
R2 的独立结构数 = **1**（不是 2）
```

**这个 1 处结构长这样**：

```js
async function h_(e) {                       // = collectCookieDetails
  ...
  t = Fh(d, new Set(["v20"]))                // ← 调用 Fh
  ...
}
function Fh(e, t) {                          // = createWindowsGcmDecryptor
  return { decrypt: (r, n, o) => {
             ...
             u = Lh("aes-256-gcm", e, c)     // ← envelope_encryption 的证据
             ...
  }}
}
```

**缺失的结构表达是**：**`call_edge`（函数 A 调用函数 B）**

**现有 `same_object` / `argument_flow` 都无法表达它** ——
它不是对象字段关系，也不是返回值→实参关系，而是**调用图上的边**。

---

## 四、结论与对架构的意义

### 对 `same_call_chain` 的判断

```
R2 的独立结构数 = 1
重复模式       = 否（只有一处，且两个案例指向同一点）
```

**按老大定的门槛**：
> **只有 Q3 > 0 并且存在重复模式，才有资格认真讨论新 Relation。**

```
Q1  21（本轮 13）个 candidate 中，有多少是真结构？        3（U1）
Q2  真结构里，有多少只是 locator 没找到？                 1（U12 = R1）
Q3  剩下多少才是现有 Relation 类型真的无法表达？           1 处（U01/U05 = R2）
```

**Q3 = 1，但无重复模式** → **不足以推动新增 Relation 类型。**

### 但有一个重要的副产品

**`U12`（E3）被标为 R1 这件事本身有价值**：

```
E3 的 same_object + argument_flow **是真实存在的**，
而且现有 relation 类型**能表达**它 —— 只是自动配对（candidate_pairs）没找到。

→ 说明 P2.1 的 locator 仍有改进空间：
   用"距离窗口"筛候选，会漏掉"结构关系存在但位置不在窗口内"的情况。
```

**这比"新增 relation 类型"更便宜，而且有实测支持。**

### 对 P4 的输入说明

```
1. relation 层：小文件可用、大文件稀疏（不变）
2. ★ 本轮的 13 个案例里，10 个是 U2（proximity 噪声）
   → P2.1 的 candidate_but_unverified 主要确实是"距离够近"而非"结构需求"
3. R2 只有 1 处独立结构 → **不支持立刻新增 relation 类型**
4. region 权重扰动（已隔离，见 Shadow Audit）
```

---

## 五、诚实的空白

```
· 8 个大文件案例未导出（性能限制）→ 若其中出现 R2 的**新结构类型**，
  结论可能改变
· U3 = 0 部分是因为"机器旁证能给出确定答案"，
  不排除某些 U2 在更完整的分析下会变成 U1
· 未与真实 AST parser 对照 → "两个 lexer 都不是正确答案"（见 Shadow Audit）
```

**建议**：若要收尾这个议题，最小成本的做法是
**先改善 locator 的候选生成**（解 U12 那类 R1），
而不是新增 relation 类型。
