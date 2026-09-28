# Shadow Impact Audit 报告

> **要回答的问题**：
> **这个 bug 是「历史实现有缺陷但结论没受影响」，
> 还是「Phase 1 的部分结论实际上建立在错误的 region 分类上」？**
>
> **纪律**：保持历史基线不变。
> ```
> A = 原 Phase 1 实现
> B = **只替换 region lexer**，其余代码/pattern/threshold/权重全部不动
> ```
> **不修 Phase 1，本轮只做评估。**

---

## 判定：**A 类 —— Phase 1 现有 verdict 基本稳健**

```
region 误分类      ：有（S1 host 66.3% 的 hit 分类发生了变化）
证据权重变化        ：有（净 delta 最大的 capability 达 -105.0）
★ capability verdict：**全不变（0 项）**
Ground Truth 对应    ：全不变（verdict 就是 GT 对照的对象）
benchmark           ：全部通过，与历史一致
```

> **→ 该 bug 可严格隔离为「未改变 Phase 1 verdict 的潜在证据污染」。
> 修复进入下一 baseline，不覆盖历史结果。**

---

## 一、逐 hit 的 region 变化（第 1 层）

### S1 ZCode `out/host/index.js`（2.5 MB，受影响最大）

```
命中总数 719
region 分类变化 477 / 719（66.3%）

变化类型：
    string        → code            345    权重 0.85 → 1.00
    string        → line_comment    112    权重 0.85 → 0.15   ← 反方向
    line_comment  → string            6    权重 0.15 → 0.85
    code          → string            5    权重 1.00 → 0.85
    line_comment  → code              5    权重 0.15 → 1.00
    code          → line_comment      4    权重 1.00 → 0.15
```

**注意 112 处 `string → line_comment` 是反方向的** ——
说明修复版 lexer 也不是完美的（有些位置它判得更差）。

**净效果才是关键**，而不是单向统计。

### 其余样本

| 样本 | 命中 | 分类变化 | verdict 变化 |
|---|---|---|---|
| S1 main（0.7MB）| 352 | 94（26.7%）| **0** |
| S2 main（2.3MB）| 491 | **0（0.0%）** | **0** |
| S3 main（0.2MB）| 22 | 6（27.3%）| **0** |
| S4 main（1.1MB）| 10 | 2（20.0%）| **0** |

**S2 main 完全没受影响**（0 变化）——说明不同文件的 minified 风格差异很大。

---

## 二、evidence contribution diff（第 2 层）

按能力的权重净变化（`Δ = new_contribution - old_contribution`）：

```
global_config_collection    520 hits     -105.0    ← 权重降低最多
upload_credential_api        39 hits      +46.6
shell_execution             295 hits      +39.6
retry_backoff               190 hits      +21.0
envelope_encryption          25 hits      +16.2
telemetry_egress            271 hits      +10.5
workspace_snapshot           95 hits       -6.6
credential_access            18 hits       +2.4
object_storage_upload        51 hits       -1.5
bulk_archive                  5 hits       +1.0
```

**有正有负 —— 不是单向的高估或低估。**

> 这比"region bug 让所有证据被降权"更复杂：
> 有些能力的证据确实一直被低估（`upload_credential_api` +46.6），
> 有些则被高估（`global_config_collection` -105.0）。

---

## 三、★ 为什么 verdict 全不变（第 3 层，最关键）

**全部 5 个样本、所有 capability、verdict 零变化。**

**原因**：**阈值余量吸收了区域权重的扰动。**

```
GRADE_THRESHOLDS:
    confirmed  norm ≥ 0.55 且 patterns ≥ 3 且 files ≥ 2
    likely     norm ≥ 0.30 且 patterns ≥ 2 且 files ≥ 1
    possible   norm ≥ 0.12 且 patterns ≥ 1 且 files ≥ 1
```

单个 hit 的权重从 0.85 变到 1.00（或反向），**不足以让一个 capability 的整体 norm 跨过 0.12 / 0.30 / 0.55 的台阶** ——
因为 norm 是**归一化后**的比值，分子分母同向变化。

> **这是一个重要观察**：region 权重的作用被归一化 + 阈值台阶**双重稀释**了。
> 它意味着这个 bug 的**实际杀伤力远小于它的视觉冲击力**（78% 文件被判错 vs verdict 零变化）。

---

## 四、与"发现 bug ≠ 找到根因"同一条纪律

**上一轮我在 P2 层刚刚被自己否证过一次**：

```
发现 region bug → 以为找到 relation=0 的根因 → 修复 → relation 仍然 0
```

**本轮在 P0 层，我刻意没有再犯同样的错**：

```
lexer 有真 bug（已证）
    ↓
它确实改变了大量 hit 的 region 分类（已证）
    ↓
它确实改变了 evidence contribution（已证）
    ↓
**但它没有改变任何 verdict（已证）**
```

**这四条必须各自实测，不能靠"看起来严重"推断。**

---

## 五、对后续工作的影响

### 对 Phase 1 结论

```
✅ 现有 verdict 稳健，不需要回退或重做
✅ benchmark（F1=1.000 / 5 例 / 56 模式）与历史一致
✅ 基于 Phase 1 的架构决策（PHASE-1-ARCHITECTURE-DECISION.md）不需要修改
⚠ 但 evidence weighting 存在潜在系统性污染 —— 应记录在案
```

### 对 P4

```
本 bug **不阻塞 P4**。
但 P4 的输入说明里应加一条：
    "region 权重的作用被归一化与阈值台阶双重稀释；
     历史 evidence weighting 存在未量化的扰动。"
```

### 修复建议（不覆盖历史）

```
· evidence 层（P2/P2.1）：已修 ✓
· agentegress 层（P0）  ：修复应进入**下一 baseline**，
                          不改动历史结果，也不重跑 Phase 1
· 若将来重开 Phase 1 式评估，应以修复后的 lexer 作为新基线
```

---

## 六、遗留观察（未在本轮展开）

**112 处 `string → line_comment`（反方向）值得单独看** ——
说明修复版 lexer 在某些模式上**比原版判得更差**。

**可能的成因**：
```
· 正则识别吞掉了本该是字符串的内容
· 或者原版把某些真实字符串误判成 code，而新版判成注释
```

**这不影响本轮判定**（verdict 不变），但说明
**两个 lexer 都不是"正确答案"** ——
真正的正确性需要与真实 AST parser 对照才有定论。

**建议**：记录为后续议题，不在本轮处理。

---

## 附：可复跑

```bash
SA_MAX_FILE_MB=3 python evidence/shadow_audit.py
python tests/verify.py          # 确认 benchmark 基线未变
```

**结果明细**：`evidence/_shadow_audit.json`
