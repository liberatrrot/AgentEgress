# P4 · Calibration Charter（冻结声明 + 四条约束）

> **本文件是 P4 的规范。** 开始 P4 之前先冻结实现，不允许边做 calibration 边改检测器。

---

## 〇、进入 P4 的前置状态

```
Phase 1 verdict integrity    ✅（Shadow Impact Audit 确认 A 类）
region bug impact            ✅ 已隔离（evidence 层已修；P0 层修复进下一 baseline）
structural audit             ✅ decision-sufficient
locator recall issue         ✅ fixed + regression verified（stop condition 全满足）
relation schema expansion    ⏸ deferred；schema gap 已记录（call_edge）
P4 calibration               ▶ START
```

### ★ 样本覆盖状态（不要把两件事混为一谈）

```
clean / post-locator-fix / audited  = 13
pending / unaudited                 = 8
```

> **「工具链干净」是 13 个案例的状态标签，
> 不等于「P4 有完整的 clean calibration dataset」。**
>
> 8 个大文件（S1 host 2.5MB / S2 code-cache 3.4MB 等）因导出超时**未审计** ——
> **明确留作未审计集，不得当作 negative evidence。**

---

## 一、Freeze implementation（从本文件提交起生效）

```
region lexer             frozen
candidate locator        frozen
relation schema          frozen
weights                  frozen
thresholds               frozen
verdict logic            frozen
```

**P4 只研究 calibration，不允许在 P4 期间修改上述任何一项。**

若确需修改，必须：
```
① 停止 P4
② 单独提交一次回归验证（证明既有结论不变）
③ 更新本 Charter 的冻结清单
④ 重新开始 P4
```

**理由**：`locator` 的教训 —— 边做边改会让"工具链误差"与"校准误差"混在一起，
无法归因。

---

## 二、Calibration 的 Ground Truth 来源

### 可用的 reference cases（13 个）

```
post-locator-fix, structurally audited reference cases

U1 = 已确认结构   （3 个：U01 / U05 / U12）
U2 = 已确认无结构  （10 个）
U3 = 当前未发现   （0 个）
```

### ★ 关于 `U3 = 0` 的表述纪律

```
❌ 不允许写成："U3 不存在。"
✅ 只能写成："在当前 13 个已审计案例和当前旁证能力下，未观察到 U3。"
```

**理由**：13 / 21 的覆盖率下，`U3 = 0` 是**观察结果**，不是**普遍结论**。
（且 `struct_evidence.py` 的旁证能力本身有边界 —— 它只能查调用边/共享标识符/函数边界。）

---

## 三、`call_edge` 的处理：schema-gap observation，不是 calibration 类别

```
schema gap observation:
    call_edge  observed = 1 independent instance   （U01/U05 是同一处结构）
decision:
    **P4 不做 schema expansion**
```

### 为什么必须在 Charter 里写明

**如果 P4 偷偷把 `call_edge` 纳入新类别，calibration 就会再次改变被校准对象** ——
那就不是校准，是同时改了输入和输出。

**记录方式**：
```
在 P4 的输入说明里作为 **known schema gap** 列出，
但**不进入 calibration 的类别体系**。
以后再出现 call_edge，可直接归并为"已知 gap 的第 N 次观察"。
```

---

## 四、★ 必须区分「校准参数」与「样本判断」

**这是 P4 最容易踩的坑。**

### 禁止的顺序

```
这个案例看起来应该是 U1
    → 调权重
    → 模型终于判 U1
    → 所以权重正确          ← ❌ 这是"为了让历史案例看起来正确而调参"
```

### 允许的顺序

```
结构 Ground Truth          （已冻结，来自 13 个审计案例）
    ↓
固定候选 / 证据            （frozen locator + frozen evidence）
    ↓
观察当前评分输出
    ↓
测 calibration error      （当前输出与 GT 的偏差有多大、在哪些类别上）
    ↓
才讨论参数是否需要调整
```

**判据**：
```
调参前必须能回答：
    这个偏差是**系统性的**（某一类样本普遍偏）还是**个案性的**？
    若是个案性 → 不能调参（那是过拟合）
    若是系统性 → 记录偏差模式，再决定是否调、调什么
```

---

## 五、Verification Layer（P4 期的正式组成部分）

**这一轮实测出了 7 次"检查写错"**（第 1–4 次见 Verification Hardening，第 5–7 次见 Locator micro-fix）。

**它不是尴尬的小插曲，而是 P4 本身应该监控的实验风险。**

### 三者必须独立定性

```
implementation bug     检测/评分代码本身错
test bug               验证脚本错（假绿 / 假失败）
interpretation bug     结果被错误解读（如"U3=0"被读成"U3 不存在"）
```

### P4 期纪律

```
每一个异常结果，先归类再处理：
    ① 是 implementation 错？  → 修实现（但先解冻，见第一节）
    ② 是 test 错？            → 修验证脚本
    ③ 是 interpretation 错？  → 修表述，不改代码

禁止：不分类就直接调参。
```

**理由（本轮实证）**：
```
若第 7 次不查证 → 会去"修"一个已经修好的功能
若第 5 次不查证 → 会基于虚高的噪声数据判定"locator 不可用"
若第 6 次不查证 → 会把存量类型误判为"新类型"，进而错误地认为需要扩展 schema
```

---

## 六、P4 的验收判据

```
C1  冻结清单未被修改（可机器验证：git diff 检查）
C2  calibration 输入明确标注：
        audited reference cases = 13
        unaudited              = 8（不作为 negative evidence）
C3  U3 = 0 的表述符合纪律（"未观察到"而非"不存在"）
C4  call_edge 仅作为 schema-gap observation，未进入 calibration 类别
C5  调参前后必须给出"系统性偏差 vs 个案偏差"的分析
C6  所有异常结果都有 implementation / test / interpretation 的归类
```

**C1–C6 全部满足，P4 才算完成。**

---

## 七、本 Charter 的元信息

```
前身：Phase 2 Consistency Gate（G1–G7）· Real-World Gate（R1–R8）
      Verification Hardening · Shadow Impact Audit · Locator micro-fix
立此文件的教训：
    · 边改边测 → 无法归因（locator 的教训）
    · 验证器自身会错（7 次实测）
    · 发现 bug ≠ 找到根因（P2 层自我否证）
    · 样本覆盖 ≠ 工具链状态（本文件第〇节）
```
