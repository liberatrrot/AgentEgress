# U-Case 准备阶段 · 意外发现的一个真 bug

> **本轮的原始任务是 21 个案例的人工标注。**
> 在导出案例证据时（为了"不只凭印象标注"），**发现了一个更基础的 bug**，
> 必须先处理 —— 否则导出的案例位置本身就是错的。

---

## 一、发现：`lex_regions` 不处理正则字面量

### 现象

导出案例时，看到大量 source/sink 的 `region` 是 `string`，
但我看代码片段，`createGzip`、`createCipheriv` 明明在 `import{...}from"zlib"` 里（代码区）。

### 实测数据（S1 ZCode `out/host/index.js`，2.5 MB）

```
修复前：  code 12.6%  ·  string 78.2%  ·  line_comment 9.2%
```

**78.2% 的文件被判成字符串** —— 这是明显错误。

### 根因（两层）

**① 未闭合引号会一路吞到下一个同种引号**

JS 的 `'` / `"` 字符串**不能跨行**（只有模板字符串可以），
原实现没检查换行 → 一个孤立引号能吞掉几十万字符。

**② ★ 完全不处理正则字面量（主因）**

实测最长的几个 `line_comment` 段：

```
长度 54314  @1454018 : '//i.test(t))return t;let r=q2e(t);...'
长度 51412  @1824567 : '//.test(e)?e:`http://${e}`;...'
长度 22800  @2478316 : '//127.0.0.1:${Z.port}...'
```

**这些 `//` 全部来自正则字面量的尾部**（如 `/^https?:\/\//i`）。

`lex_regions` 不识别正则 → 把正则里的 `//` 当成**行注释起点** →
而 minified 代码"一行"有几十万字符 → **整行沦陷为注释**。

### 修复

在 `lex_regions` 中加入正则字面量识别（JS 里 `/` 的歧义用标准判据解决）：

```python
def _regex_allowed(text, i):
    """前一个非空白字符 ∈ ( , = : [ ! & | ? { } ; + - * % ~ ^ < > → 可以是正则"""
```

### 修复效果

```
修复前：  code 12.6%  ·  string 78.2%  ·  line_comment 9.2%
修复后：  code 57.3%  ·  string 36.4%  ·  line_comment 4.6%  ·  regex 1.7%

已知代码位置的判定：
    createGzip     @2216337  → code  ✓（修复前是 line_comment）
    createCipheriv @876208   → code  ✓（修复前是 string）
    publicEncrypt  @2215903  → code  ✓（修复前是 line_comment）
    readFileSync   @20690    → code  ✓
```

---

## 二、★ 但它**不是** `relation=0` 的主因

**我原本以为找到了根因，实测否证了。**

```
S1 host（2.5MB，region 修复前后对比）：
    修复前  verified=0  unverified=8  no_candidate=47
    修复后  verified=0  unverified=5  no_candidate=50
    → **verified 仍然 0**

S1 main（0.7MB，本来就不受正则 bug 影响）：
    修复前  verified=1  unverified=11  no_candidate=33
    修复后  verified=1  unverified=11  no_candidate=33
    → **完全没变化**
```

> **结论：region 判定确实有严重缺陷，修好它是必要的；
> 但 `relation=0` 的真正原因仍然是原来那个 ——
> 在真实大文件里，不同能力的证据确实不在同一个 object literal
> 或同一条"返回值→实参"绑定链上。**

**这是一个必须诚实记录的自我否证。**

---

## 三、⚠ `agentegress.py` 有同一个 bug（P0 层，未修）

```
agentegress:  code 27.1%  ·  string 65.7%  ·  line_comment 7.2%
```

**同样不处理正则字面量。**

### 为什么不在本轮修

```
evidence/* 是 Phase 2 的新层（P2/P2.1）
agentegress.py 是 P0 —— **Phase 1 的全部结论都建立在它之上**
```

**改它会改变**：
```
· REGION_FACTOR 的权重分配（code 1.0 / string 0.85 / 注释 0.15）
  → 代码被判成注释 → 权重从 1.0 掉到 0.15 → **真实证据被严重降权**
· prefilter 的行为
· 进而 Phase 1 的所有区域分级结论
```

**这必须作为一个独立议题评估**，不能顺手改。

**但它可能影响很大** —— 如果 S1 里 78% 的代码被判成注释，
那么**大量真实证据的权重可能一直是错的**。

---

## 四、修正后的 P4 前置条件

```
1. relation 层：小文件可用、大文件稀疏（不变）
2. 21 个案例待人工标注（不变）
3. ★ 新增：lex_regions 的 region 判定在 minified 代码上不可靠
   → evidence 层已修
   → **P0 层（agentegress）未修，影响面待评估**
4. consistency_gate 的断言分层已完成（B/C 23 条 + 失败路径自证）
```

---

## 五、下一步

**原本要做的事（21 个案例标注）现在可以做了** ——
而且**必须用修复后的 region 重新导出**（位置可能变化）。

**顺序**：
```
① 用修复后的 region 重新导出 21 个案例
② 人工标注 U1 / U2 / U3（只标结构事实，不重判 capability）
③ 统计 Q1/Q2/Q3
④ U1 再拆：existing-relation locator failure vs genuinely new structural form
```

**另需单独安排**：
```
⑤ 评估 agentegress.py 的 region bug 影响面（可能改变 Phase 1 的部分结论）
```
