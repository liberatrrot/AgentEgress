# -*- coding: utf-8 -*-
"""Phase 2 · P2 Relation（第一版）

**严格限定**：
    实现  P2.1 same_object
          P2.2 argument_flow
    不做  same_call_chain（语义弱，易被误解成"A 的数据到了 C"）
          复杂 alias / 跨函数 / 跨文件 / 控制流合流 / 循环传播

**核心不变量（与 unknown ≠ negative 一脉相承）**：
    No proof      →  No relation
    Weak proof    →  weak structural evidence
    Strong proof  →  relation admitted

即：**没有可机器复核的结构证明，就不生成关系。**
禁止 `maybe related → relation = true`。

**structural_basis 必须是可机器验证的结构事实**（I4）：
    不允许 structural_basis = "same object" 这种自述字符串。
    必须是 span（起止偏移）等可独立复核的坐标。
"""

import re


# ================================================================ 基础：区域与括号

def _regex_allowed(text, i):
    """判断位置 i 处的 '/' 能否开始一个正则字面量。

    JS 里 `/` 有歧义：除号 vs 正则起始。经典判据是看**前一个非空白字符**：
      `( , = : [ ! & | ? { } ; + - * % ~ ^ < >` 之后  → 可以是正则
      标识符 / 数字 / `)` / `]` 之后                    → 是除号

    【实测发现的第二个严重 bug】
    原实现完全不处理正则字面量 → 正则内部的 `//`（如 `/https?:\\/\\//i` 的结尾）
    被当成**行注释起点** → 而 minified 代码"一行"有几十万字符
    → **整行沦陷为注释**。

    实测后果（S1 ZCode out/host/index.js）：最长的 line_comment 段达 54314 字符，
    起点正是 `//i.test(t))` —— 即正则 `/^.../i` 的尾部。
    """
    j = i - 1
    while j >= 0 and text[j] in " \t\r\n":
        j -= 1
    if j < 0:
        return True
    return text[j] in "(,=:[!&|?{};+-*%~^<>"


def _scan_regex(text, i):
    """从 '/' 开始扫正则字面量，返回结束位置（含 flags）或 -1（不是正则）。"""
    j = i + 1
    n = len(text)
    in_class = False
    while j < n:
        c = text[j]
        if c == "\\":
            j += 2
            continue
        if c == "\n":
            return -1                 # 正则不能跨行
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            j += 1
            # 吃掉 flags
            while j < n and text[j].isalpha():
                j += 1
            return j
        j += 1
    return -1


def lex_regions(text):
    """返回 [(start, end, kind)]，kind ∈ code / string / line_comment / block_comment。

    【实测发现的两个严重 bug，均已修】
    ① 未闭合引号会一路吞到下一个同种引号 ——
       JS 的 `'`/`"` 不能跨行，原实现没检查换行。
    ② **完全不处理正则字面量** —— 正则里的 `//` 被当成行注释起点，
       在 minified 代码（一行几十万字符）上会让**整行沦陷**。

    修复前（S1 ZCode out/host/index.js）：code 12.6% / string 78.2%
    修复后需重新实测。

    ⚠ **注意**：`agentegress.py` 里有另一个 `lex_regions` 实现，
    经检查存在同类问题（code 27.1% / string 65.7%）。
    但那是 P0 层，改动会影响 Phase 1 的全部结论，**不在本层修**。
    """
    segs = []
    i, n = 0, len(text)
    plain_start = 0
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            if plain_start < i:
                segs.append((plain_start, i, "code"))
            j = text.find("\n", i)
            j = n if j < 0 else j
            segs.append((i, j, "line_comment"))
            i, plain_start = j, j
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            if plain_start < i:
                segs.append((plain_start, i, "code"))
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            segs.append((i, j, "block_comment"))
            i, plain_start = j, j
            continue
        # ★ 正则字面量（必须在 `//` 判断之后、字符串之前处理）
        if c == "/" and _regex_allowed(text, i):
            end = _scan_regex(text, i)
            if end > 0:
                if plain_start < i:
                    segs.append((plain_start, i, "code"))
                segs.append((i, end, "regex"))
                i, plain_start = end, end
                continue
        if c in "\"'`":
            q = c
            j = i + 1
            closed = False
            while j < n:
                ch = text[j]
                if ch == "\\":
                    j += 2
                    continue
                if ch == "\n" and q != "`":
                    break
                if ch == q:
                    j += 1
                    closed = True
                    break
                j += 1
            if closed:
                if plain_start < i:
                    segs.append((plain_start, i, "code"))
                segs.append((i, j, "string"))
                i, plain_start = j, j
            else:
                i += 1
            continue
        i += 1
    if plain_start < n:
        segs.append((plain_start, n, "code"))
    return segs


_REGION_CACHE = {}

# 【实测踩坑】第一版用 `id(text)` 单独作缓存键。
# Python 的对象 id 在对象被 GC 后**会被复用** ——
# 前一个文本被回收后，新文本可能拿到相同 id，
# 于是 region_at 返回**另一个文件的 regions**，导致 relation 凭空建不出来。
# 现象：单独 debug 能建出 relation，但在批量回放里同一段代码判为 None。
# 修法：键改成 (id, len)，并限制缓存条数。
_REGION_CACHE_MAX = 4


def region_at(text, pos):
    key = (id(text), len(text))
    segs = _REGION_CACHE.get(key)
    if segs is None:
        segs = lex_regions(text)
        if len(_REGION_CACHE) >= _REGION_CACHE_MAX:
            _REGION_CACHE.clear()
        _REGION_CACHE[key] = segs
    for s, e, k in segs:
        if s <= pos < e:
            return k
    return "code"


def match_bracket(text, open_pos):
    """从开括号位置返回配对闭括号位置。纯字符扫描。"""
    pairs = {"(": ")", "[": "]", "{": "}"}
    ch = text[open_pos]
    if ch not in pairs:
        return -1
    close = pairs[ch]
    depth = 0
    i, n = open_pos, len(text)
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == ch:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def find_regex_literal_span(text, pos):
    """若 pos 落在某个正则字面量内，返回它的 (start, end)。用于排除诱骗例。"""
    # 向前找最近的 /，判断它像不像正则起始
    i = pos
    while i > 0 and i > pos - 400:
        if text[i] == "/":
            prev = text[i - 1] if i > 0 else ""
            if prev in "=(,:[!&|?{; \n\t" or i == 0:
                j = match_regex_end(text, i)
                if j > pos:
                    return (i, j)
        i -= 1
    return None


def match_regex_end(text, start):
    """从 start（'/' 的位置）找正则字面量的结束 '/'。"""
    i, n = start + 1, len(text)
    in_class = False
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            in_class = True
        elif c == "]":
            in_class = False
        elif c == "/" and not in_class:
            return i + 1
        elif c == "\n":
            return start        # 跨行 → 不是正则
        i += 1
    return start


# ================================================================ 对象字面量

# 有助于判定 `{` 是对象字面量而非代码块的前导记号
_OBJ_LEAD = re.compile(
    r"(?:=|\(|,|:|\breturn\b|\bawait\b|\byield\b|=>|\[|\?\?|\|\||&&|\bnew\b)\s*$")


def find_object_literal(text, pos):
    """找**包含 pos 的最内层对象字面量**的 span。

    判定 `{` 是对象字面量而非代码块：看它前面的非空白字符。
      `= { ... }`  `({ ... })`  `, { ... }`  `: { ... }`  `return { ... }`  → 对象
      `) { ... }`  `else { ... }`  `try { ... }`  `do { ... }`               → 块

    返回 (open_pos, close_pos) 或 None。
    """
    # 从 pos 往前找候选 `{`
    i = pos
    while i > 0:
        if text[i] == "{":
            close = match_bracket(text, i)
            if close >= pos:                      # 确实包含 pos
                head = text[max(0, i - 40):i]
                if _OBJ_LEAD.search(head):
                    return (i, close)
                # 前导不像对象字面量 → 继续往外找（可能是内层块）
        i -= 1
    return None


def toplevel_properties(text, obj_span):
    """列出对象字面量的顶层属性 (name, name_pos, value_pos, value_end)。

    只在 depth==1 时记录，避免把嵌套对象的属性也算进来。
    """
    start, end = obj_span
    if start < 0 or end <= start:
        return []
    props = []
    depth = 0
    i = start
    n = min(end, len(text))
    key_start = -1
    while i < n:
        c = text[i]
        reg = region_at(text, i)
        if reg in ("string", "line_comment", "block_comment"):
            if c in "{[(":
                pass
            i += 1
            continue
        if c in "{[(":
            depth += 1
            if depth == 1 and c == "{":
                key_start = i + 1
        elif c in "}])":
            depth -= 1
        elif c == ":" and depth == 1:
            # 形如  key : value
            seg = text[key_start:i] if key_start >= 0 else ""
            m = re.search(r"([A-Za-z_$][\w$]*)\s*$", seg)
            name = m.group(1) if m else None
            name_pos = (key_start + m.start(1)) if m else -1
            # value 从 ':' 之后开始
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            # value 结束：到下一个 depth==1 的 ',' 或对象结束
            k = j
            d2 = 0
            while k < n:
                cc = text[k]
                if cc in "{[(":
                    d2 += 1
                elif cc in "}])":
                    if d2 == 0:
                        break
                    d2 -= 1
                elif cc == "," and d2 == 0:
                    break
                k += 1
            if name:
                props.append({"name": name, "name_pos": name_pos,
                              "value_pos": j, "value_end": k})
        elif c == "," and depth == 1:
            key_start = i + 1
        i += 1
    return props


# ================================================================ P2.1 same_object

def same_object(text, pos_a, pos_b, label_a=None, label_b=None):
    """判断两处是否处于**同一个对象字面量**内（且分属不同属性）。

    返回可机器复核的 basis，或 None（无证明 → 无关系）。

    basis 含：container_start / container_end / property_a / property_b
    —— 任何第三方都能用这两个 span 独立复核。
    """
    if pos_a is None or pos_b is None:
        return None
    if pos_a == pos_b:
        return None

    # 诱骗例防线：任一位置落在字符串/注释/正则里 → 拒绝
    for p in (pos_a, pos_b):
        r = region_at(text, p)
        if r not in ("code", ""):
            return None
        if find_regex_literal_span(text, p):
            return None

    oa = find_object_literal(text, pos_a)
    ob = find_object_literal(text, pos_b)
    if not oa or not ob:
        return None
    # 必须是**同一个**对象字面量
    if oa != ob:
        return None

    props = toplevel_properties(text, oa)
    if len(props) < 2:
        return None

    def owner(p):
        for pr in props:
            if pr["value_pos"] <= p < pr["value_end"]:
                return pr["name"]
        return None

    pa, pb = owner(pos_a), owner(pos_b)
    if not pa or not pb or pa == pb:
        # 同一属性内 → 不构成"两个 property 之间的关系"
        return None

    return {
        "type": "same_object",
        "source": label_a or text[pos_a:pos_a + 40],
        "target": label_b or text[pos_b:pos_b + 40],
        "confidence": "high",
        "structural_basis": {
            "kind": "object_literal",
            "container_start": oa[0],
            "container_end": oa[1],
            "property_source": pa,
            "property_target": pb,
            "source_offset": pos_a,
            "target_offset": pos_b,
        },
    }


# ================================================================ P2.2 argument_flow

_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?([A-Za-z_$][\w$.]*)\s*\(")


def find_bindings(text):
    """找 `const X = await foo(` / `X = foo(` 形式的绑定。

    返回 [{ident, bind_pos, call_name, call_open, call_close}]
    —— 只保留**返回调用**这一种最窄形态。
    """
    out = []
    for m in _ASSIGN_RE.finditer(text):
        if region_at(text, m.start()) != "code":
            continue
        open_pos = m.end() - 1
        close = match_bracket(text, open_pos)
        if close < 0:
            continue
        out.append({
            "ident": m.group(1),
            "bind_pos": m.start(),
            "call_name": m.group(2),
            "call_open": open_pos,
            "call_close": close,
        })
    return out


def argument_flow(text, create_pos, upload_pos, label=None):
    """判断是否存在最窄的 argument_flow：

        const created = await createMedia(...)      ← 返回调用绑定到 created
        uploadToCos(created.cos_credential, ...)    ← created 出现在实参里

    必须在**同一文件**且能找到**明确绑定**。

    返回可机器复核的 basis，或 None。
    """
    if create_pos is None or upload_pos is None:
        return None
    if create_pos >= upload_pos:
        return None          # 顺序不合理：上传调用在返回调用之前

    # 诱骗例防线
    for p in (create_pos, upload_pos):
        if region_at(text, p) != "code":
            return None

    # ① 找一个绑定，其**整条赋值语句**覆盖 create_pos
    #
    # 【实测踩坑】第一版用 `call_open <= create_pos <= call_close` 判断，
    # 但调用方传进来的 create_pos 往往是**函数名的位置**（如 `makeArtifact` 的起始），
    # 而 call_open 是 `(` 的位置 —— 于是 55 < 67 直接判否。
    # 正确做法：用整条赋值语句的范围 [bind_pos, call_close]。
    binding = None
    for b in find_bindings(text):
        if b["bind_pos"] <= create_pos <= b["call_close"]:
            binding = b
            break
    if not binding:
        return None

    # ② 上传调用必须**在绑定之后**
    if upload_pos <= binding["call_close"]:
        return None

    # ③ 找包含 upload_pos 的最内层调用括号
    #
    # 【实测踩坑 · 两次】
    #   第一版只**往前**找 '('：
    #       传进来的 upload_pos 是函数名开头（如 `uploadPutObject`），
    #       往前找到的是外层函数 `sync(...)` 的括号 → P-2 FAIL。
    #   第二版只**往后**找 '('：
    #       但 `shipSealed({ payload: sealed.sealedBlob })` 这种写法里，
    #       upload_pos 在**实参对象内部**，调用括号在它**前面** → E4 FAIL。
    #
    #   正确做法：两侧各找最近的候选，取**最内层**那个（open 位置更大者）。
    cands = []
    i = upload_pos
    while i > 0:
        if text[i] == "(":
            c = match_bracket(text, i)
            if c >= upload_pos:
                cands.append((i, c))
                break
        i -= 1
    j = upload_pos
    n = len(text)
    while j < n:
        if text[j] == "(":
            c = match_bracket(text, j)
            if c > upload_pos:
                cands.append((j, c))
                break
        j += 1
    if not cands:
        return None
    up_open, up_close = max(cands, key=lambda x: x[0])   # 最内层

    args = text[up_open + 1:up_close]
    ident = binding["ident"]
    # 必须出现 `ident` 或 `ident.prop`（作为独立标识符）
    ref = re.search(r"(?<![\w$])" + re.escape(ident) + r"(?:\.\w+)*",
                    args)
    if not ref:
        return None

    # ④ 实参里那次引用，是否与 upload_pos 位置一致（避免"别的参数里恰好提到同名变量"）
    ref_abs = up_open + 1 + ref.start()
    if not (upload_pos <= ref_abs < upload_pos + 200 or
            abs(ref_abs - upload_pos) < 200):
        return None

    return {
        "type": "argument_flow",
        "source": binding["call_name"],
        "target": text[up_open + 1:up_close][:60],
        "confidence": "high",
        "structural_basis": {
            "kind": "return_binding_to_argument",
            "binding_ident": ident,
            "binding_pos": binding["bind_pos"],
            "return_call": binding["call_name"],
            "return_call_span": [binding["call_open"], binding["call_close"]],
            "argument_ref_pos": ref_abs,
            "argument_span": [up_open, up_close],
        },
    }


# ================================================================ 统一入口

def relate(text, a, b, label_a=None, label_b=None):
    """对两个位置尝试建立关系。**没有证明就不返回任何关系。**

    顺序：先试 same_object（结构更近），再试 argument_flow。
    """
    r = same_object(text, a, b, label_a, label_b)
    if r:
        return r
    r = argument_flow(text, a, b, label_a)
    if r:
        return r
    return None


def assert_relation_invariants(relations):
    """P2 不变量断言：每条 relation 必须带可机器复核的 basis。

    I4 的落实点：禁止 structural_basis 是自述字符串。
    """
    for r in relations:
        assert "structural_basis" in r, "I4 违反：relation 缺少 structural_basis"
        b = r["structural_basis"]
        assert isinstance(b, dict), \
            "I4 违反：structural_basis 必须是结构化事实，不是字符串"
        assert "kind" in b, "I4 违反：structural_basis 缺少 kind"
        assert r["type"] in ("same_object", "argument_flow"), \
            "未知 relation 类型：%s" % r["type"]
        # 每种类型必须有对应的可复核坐标
        if r["type"] == "same_object":
            assert "container_start" in b and "container_end" in b, \
                "I4 违反：same_object 必须给出 object literal 的 span"
            assert b["container_start"] < b["container_end"], \
                "I4 违反：span 不合法"
            assert "property_source" in b and "property_target" in b, \
                "I4 违反：same_object 必须指出分属哪两个 property"
        if r["type"] == "argument_flow":
            assert "binding_pos" in b and "argument_span" in b, \
                "I4 违反：argument_flow 必须给出绑定位置与实参 span"
            assert "binding_ident" in b, \
                "I4 违反：argument_flow 必须指出绑定标识符"
    return True
