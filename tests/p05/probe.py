# -*- coding: utf-8 -*-
"""P0.5 · Role Evidence Probe

目标（老大的原话）：
    在不引入 AST/CFG 的情况下，local consumer / use-site 信息
    能把多少 semantic_role = unknown 变成有可靠依据的角色？

**明确不做**（禁止 scope 爆炸）：
    跨函数完整追踪 / 跨文件追踪 / CFG / 完整 AST /
    alias analysis / data-flow engine / 运行时执行

**只做**：
    same file · local symbol · direct consumer · simple branch/use context

回答三个问题：
    Q1 它被当成什么东西使用？      → 容器类型
    Q2 它的消费者是什么？          → 使用点 + 分支语义
    Q3 它最终有没有进入真正的行为？ → 拒绝 documentation 的关键
"""

import re


# ---------------------------------------------------------------- 区域检测
#
# 【实测缺陷】第一版用「当前行内是否有未闭合引号」判断 in_str，
# 跨行模板字符串（E5 的 `const DOC = \`...\``）会完全判错。
# 改为对整文件扫一遍区域（O(n)，单文件可接受）。
# **独立实现，不依赖被检验工具的 lex_regions。**

def lex_regions(text):
    """返回 [(start, end, kind)]，kind ∈ code / string / line_comment / block_comment。"""
    segs = []
    i = 0
    n = len(text)
    plain_start = 0
    while i < n:
        c = text[i]
        # 行注释
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            if plain_start < i:
                segs.append((plain_start, i, "code"))
            j = text.find("\n", i)
            j = n if j < 0 else j
            segs.append((i, j, "line_comment"))
            i = j
            plain_start = i
            continue
        # 块注释
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            if plain_start < i:
                segs.append((plain_start, i, "code"))
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            segs.append((i, j, "block_comment"))
            i = j
            plain_start = i
            continue
        # 字符串（含跨行模板字符串）
        if c in "\"'`":
            if plain_start < i:
                segs.append((plain_start, i, "code"))
            q = c
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == q:
                    j += 1
                    break
                j += 1
            segs.append((i, j, "string"))
            i = j
            plain_start = i
            continue
        i += 1
    if plain_start < n:
        segs.append((plain_start, n, "code"))
    return segs


_REGION_CACHE = {}


def region_at(text, pos):
    key = id(text)
    segs = _REGION_CACHE.get(key)
    if segs is None:
        segs = lex_regions(text)
        _REGION_CACHE[key] = segs
    for s, e, k in segs:
        if s <= pos < e:
            return k
    return "code"


def find_enclosing_call(text, pos, max_back=240):
    """找**包围** pos 的最内层调用名：形如 `name( ... pos ... )`。

    【为什么需要】
    第一版用「±220 字符窗口内是否出现某 API 名」判断消费者。
    在大 minified 文件里窗口内什么 API 都有 → 误判极高。
    实测：`aes-256-gcm` 被判成 detection_rule（因为附近恰好有 .test( 和 === "），
    而它的**真正消费者**是 `createCipheriv('aes-256-gcm', ...)`。

    这个方法只回答一件事：**是哪个调用在直接用这个值**。
    """
    # 从 pos 往前找最近的、能包住 pos 的开括号
    seg_start = max(0, pos - max_back)
    seg = text[seg_start:pos]
    for m in reversed(list(re.finditer(r"[\(\[\{]", seg))):
        open_pos = seg_start + m.start()
        close_pos = _match_bracket(text, open_pos)
        if close_pos >= pos:
            head = text[max(0, open_pos - 60):open_pos]
            nm = re.search(r"([A-Za-z_$][\w$.]*)\s*$", head)
            return nm.group(1) if nm else None
    return None


# 调用名 → role 提示（高判别力的标准 API）
CALL_ROLE = [
    (r"(?:createCipheriv|createDecipheriv|publicEncrypt|privateDecrypt|"
     r"createHash|randomBytes)", "active_operation"),
    (r"(?:readFileSync|readFile|createReadStream)", "active_operation"),
    (r"(?:fetch|request|axios|putObject|postObject|upload)", "active_operation"),
    (r"(?:writeFileSync|writeFile|createWriteStream)", "active_operation"),
    (r"(?:console\.log|print|logger)", "documentation"),
]


def role_from_enclosing_call(text, pos):
    """若 token 被某个已知 API 调用直接包裹，用它判 role。"""
    name = find_enclosing_call(text, pos)
    if not name:
        return None
    for pat, role in CALL_ROLE:
        if re.search(pat, name):
            return role, name
    return None


# ---------------------------------------------------------------- 基础工具

def _match_bracket(text, open_pos):
    """从 open_pos 处的开括号出发，返回配对闭括号的位置。纯字符扫描。"""
    pairs = {"(": ")", "[": "]", "{": "}"}
    ch = text[open_pos]
    if ch not in pairs:
        return -1
    close = pairs[ch]
    depth = 0
    i = open_pos
    n = len(text)
    in_str = None
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
        elif c in "\"'`":
            in_str = c
        elif c == ch:
            depth += 1
        elif c == close:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def find_container(text, pos):
    """向外找最近的容器字面量：Set( / [ / { 。

    返回 (kind, open_pos, close_pos, head) 或 None。
    head 用于区分 `new Set(` 与普通 `(`。
    """
    # 先看是不是在 Set(...) / Array.from(...) 这类调用里
    depth = 0
    i = pos
    while i > 0:
        c = text[i]
        if c in ")]}":
            depth += 1
        elif c in "([{":
            if depth == 0:
                # 看这个开括号前面是什么
                head = text[max(0, i - 40):i]
                if c == "(":
                    m = re.search(r"(\w+(?:\.\w+)*)\s*$", head)
                    if m:
                        name = m.group(1)
                        if name.endswith("Set") or name.endswith("Map"):
                            return ("Set", i, _match_bracket(text, i), name)
                        if name in ("Array", "Array.from", "from"):
                            return ("Array", i, _match_bracket(text, i), name)
                        return ("call", i, _match_bracket(text, i), name)
                elif c == "[":
                    return ("Array", i, _match_bracket(text, i), "[")
                elif c == "{":
                    # 判断是对象字面量还是块
                    return ("Object", i, _match_bracket(text, i), "{")
                return None
            depth -= 1
        i -= 1
    return None


def find_binding(text, container_open):
    """找容器被绑定到哪个变量：const X = new Set([...]) / X = [...] 。"""
    head = text[max(0, container_open - 200):container_open]
    # 去掉开括号本身前的调用名
    m = re.search(r"(?:const|let|var)\s+(\w+)\s*=\s*[\w.]*\s*$", head)
    if m:
        return m.group(1)
    m = re.search(r"(\w+)\s*=\s*[\w.]*\s*$", head)
    if m:
        return m.group(1)
    # 数组/对象直接作为参数的情况
    return None


def find_uses(text, var, exclude_range=None):
    """同一文件内，变量的所有直接使用点。"""
    if not var:
        return []
    out = []
    for m in re.finditer(r"(?<![\w$])" + re.escape(var) + r"(?![\w$])", text):
        if exclude_range and exclude_range[0] <= m.start() <= exclude_range[1]:
            continue
        out.append(m.start())
    return out


# ---------------------------------------------------------------- 消费者分类

# 消费者形态（按判别力从高到低）
CONSUMER_PATTERNS = [
    ("membership",   r"\.(?:has|includes|indexOf|find|some|every)\s*\("),
    ("regex_test",   r"\.(?:test|match|exec)\s*\("),
    ("filter",       r"\.(?:filter|reject|exclude|without)\s*\("),
    ("iteration",    r"\bfor\s*\(.*\bof\b"),
    # 【实测缺陷】第一版只匹配 `=== "`，漏掉了 `"read" === Q.action` 这种
    # 字符串在左侧的写法（S2 的真实样本正是这种）。改为双向匹配。
    ("identity_cmp", r"(?:[=!]==?\s*[\"'`]|[\"'`]\s*[=!]==?)"),
    ("logging",      r"\b(?:console\.log|print|logger|process\.stdout\.write|log)\s*\("),
    ("network_sink", r"\b(?:fetch|request|axios|http\.request|https\.request|"
                     r"putObject|postObject|SendMessage|send)\s*\("),
    ("file_write",   r"\b(?:writeFile|writeFileSync|createWriteStream|appendFile)\s*\("),
    ("body_use",     r"\b(?:body|payload|data|content)\s*:"),
]

# 排除 / 保留分支信号
NEGATIVE_BRANCH = re.compile(
    r"\b(?:continue|break|return\s+(?:false|null|void|;)|throw|delete|unlink|rm)\b|"
    r"(?:skip|deny|exclude|never|ignore|forbid|block)\w*", re.I)
POSITIVE_BRANCH = re.compile(
    r"\b(?:push|add|include|keep|accept|allow)\w*", re.I)


def classify_consumers(text, uses, window=260, back=220):
    """对每个使用点取窗口，判定消费者形态与分支语义。

    【实测缺陷】第一版前向窗口只有 60 字符。
    S2 的真实样本里 `"read"===Q.action && /...id_rsa.../` 的判定条件
    在 token **前面**，被截掉了 → B 例 FAIL。
    改为向两侧都取足够窗口。
    """
    found = []
    for p in uses:
        lo, hi = max(0, p - back), min(len(text), p + window)
        seg = text[lo:hi]
        kinds = [name for name, pat in CONSUMER_PATTERNS if re.search(pat, seg)]
        neg = bool(NEGATIVE_BRANCH.search(seg))
        pos_b = bool(POSITIVE_BRANCH.search(seg))
        found.append({"pos": p, "kinds": kinds, "neg_branch": neg,
                      "pos_branch": pos_b})
    return found


# ---- 函数名信号：minified 代码里函数名常被 `a(fn, "name")` 显式保留 ----
# 早期样本里出现过这种写法；该模式仍需支持（打包工具常用它保留函数名）
FUNC_NAME_RE = re.compile(
    r"""(?:a|__name|Object\.defineProperty)\s*\(\s*(\w+)\s*,\s*["'](\w+)["']""")

NAME_SIGNALS = [
    # (名称片段正则, 提示的 role, 权重说明)
    (r"looks?like(secret|cred|sensitive)|is(secret|sensitive|cred)", "denylist", "high"),
    (r"(should|must)(skip|exclude|ignore|deny)|excluded|denied", "denylist", "high"),
    (r"(allow|accept|include|permit)ed?", "allowlist", "medium"),
    (r"detect|violat|suspect|attack|malicious|forbidden", "detection_rule", "high"),
    (r"(read|write|access)only|viewer|display|render", "ui_representation", "medium"),
    (r"is(cipher|encrypt|compress|upload)", "active_operation", "high"),
]


def find_func_name_signals(text, uses, radius=3000):
    """在使用点附近找 `a(fn, "name")` 形态的函数名，返回命中的 role 提示。"""
    hits = []
    for p in uses:
        lo, hi = max(0, p - radius), min(len(text), p + radius)
        seg = text[lo:hi]
        for m in FUNC_NAME_RE.finditer(seg):
            fname = m.group(2)
            for pat, role, conf in NAME_SIGNALS:
                if re.search(pat, fname, re.I):
                    hits.append({"role": role, "func": fname, "confidence": conf})
    return hits


# ---------------------------------------------------------------- role 推断

def infer_role(container, var, consumers, token_in_string, in_comment,
               name_signals=None):
    """把 (容器, 消费者, 分支语义, 函数名信号) 映射到 semantic_role。

    只输出**有依据**的角色；依据不足一律 unknown。
    这是核心纪律：宁可 unknown，不要错误自信。
    """
    name_signals = name_signals or []
    kinds = set()
    for c in consumers:
        kinds.update(c["kinds"])
    any_neg = any(c["neg_branch"] for c in consumers)
    any_pos = any(c["pos_branch"] for c in consumers)
    has_sink = bool(kinds & {"network_sink", "file_write"})
    only_log = bool(kinds) and kinds <= {"logging"}

    # --- 注释区：直接 documentation ---
    if in_comment:
        return "documentation", "high", "命中在注释区"

    # --- ★ 函数名信号优先用于补足"分支语义不明"的情况 ---
    #   依据：minified 代码里 `a(fn, "name")` 保留了可读函数名
    ns_role = None
    if name_signals:
        # 取加权最高的信号
        order = {"high": 3, "medium": 2, "low": 1}
        best = max(name_signals, key=lambda x: order.get(x["confidence"], 0))
        ns_role = best

    # --- 集合 + 成员判断 + 排除分支 → denylist ---
    if container in ("Set", "Array") and "membership" in kinds and any_neg:
        return "denylist", "high", "集合 + 成员判断 + 排除分支"

    # --- ★ 集合 + 成员判断 + 无明确分支，但函数名指向 denylist → denylist(medium) ---
    if (container in ("Set", "Array") and "membership" in kinds
            and ns_role and ns_role["role"] == "denylist"):
        return ("denylist", "medium",
                "集合 + 成员判断（分支在调用方）+ 函数名 %r" % ns_role["func"])

    # --- 集合 + 成员判断 + 保留分支 → allowlist ---
    if container in ("Set", "Array") and "membership" in kinds and any_pos:
        return "allowlist", "medium", "集合 + 成员判断 + 保留分支"

    # --- 集合 + 成员判断（无分支、无名称信号）→ 不硬猜 ---
    if container in ("Set", "Array") and "membership" in kinds:
        return "unknown", "low", "集合 + 成员判断，但分支语义与命名均不明"

    # --- 正则 + .test() + 与动作字段比较 → detection_rule ---
    if "regex_test" in kinds and "identity_cmp" in kinds:
        return "detection_rule", "medium", "正则 .test() + 与动作字段比较"

    # --- ★ 正则 + 名称指向 detection → detection_rule(medium) ---
    if ("regex_test" in kinds and ns_role
            and ns_role["role"] == "detection_rule"):
        return ("detection_rule", "medium",
                "正则 .test() + 函数名 %r" % ns_role["func"])

    # --- 字符串 + 只有日志消费 → documentation ---
    if token_in_string and only_log:
        return "documentation", "medium", "字符串 + 仅被日志消费"

    # --- ★ 关键反例：字符串 + 进入网络/文件 sink → 拒绝 documentation ---
    if token_in_string and has_sink:
        return "active_operation", "medium", "字符串进入了网络/文件 sink"

    # --- 字符串 + 出现在 body/payload 字段 → 偏 active ---
    if token_in_string and "body_use" in kinds:
        return "unknown", "low", "字符串被用作请求体字段，用途待定"

    # --- 对象属性键位置（UI 组件 props 等）→ 不硬猜 ---
    if container == "Object" and not has_sink:
        return "unknown", "low", "对象字面量内，无法区分 UI props 与配置"

    return "unknown", "none", "无足够消费点信息"


# ---------------------------------------------------------------- 探针入口

def probe(text, token, occurrence=0):
    """对 text 中第 occurrence 次出现的 token 做 role 探针。

    **三级优先，逐级降信**：
      ① 精确：token 被已知 API 调用直接包裹           （如 createCipheriv('aes-256-gcm')）
      ② 精确：token 属于某个有绑定变量的集合/容器      （用变量的真实使用点）
      ③ 区域：token 在字符串/注释里                    （日志 vs sink）
      → 三级都不成立时返回 unknown，**不用窗口硬猜**

    【实测教训】第一版对每一处命中都用 ±220 字符窗口找消费者。
    在 minified 大文件里窗口内什么 API 都有 → `aes-256-gcm` 被判成
    detection_rule（附近恰好有 .test( 和 === "）。**unknown 被错误自信取代。**
    """
    positions = [m.start() for m in re.finditer(re.escape(token), text)]
    if not positions:
        return {"role": "unknown", "confidence": "none",
                "reason": "token 未出现", "container": None, "var": None,
                "consumer_kinds": [], "region": None, "name_signals": []}
    pos = positions[min(occurrence, len(positions) - 1)]
    rkind = region_at(text, pos)

    def mk(role, conf, reason, **kw):
        d = {"role": role, "confidence": conf, "reason": reason,
             "container": None, "var": None, "consumer_kinds": [],
             "region": rkind, "name_signals": []}
        d.update(kw)
        return d

    # ---------- ① 被已知 API 调用直接包裹（最精确） ----------
    rc = role_from_enclosing_call(text, pos)
    if rc:
        role, name = rc
        return mk(role, "high", "被 %s(...) 直接包裹" % name)

    # ---------- ② 属于有绑定变量的集合/容器（精确） ----------
    container = find_container(text, pos)
    ckind = container[0] if container else None
    var = find_binding(text, container[1]) if container else None
    if var:
        uses = find_uses(text, var)
        consumers = classify_consumers(text, uses)
        signals = find_func_name_signals(text, uses)
        role, conf, reason = infer_role(ckind, var, consumers, False,
                                        rkind in ("line_comment", "block_comment"),
                                        name_signals=signals)
        return mk(role, conf, reason,
                  container=ckind, var=var,
                  consumer_kinds=sorted({k for c in consumers for k in c["kinds"]}),
                  name_signals=signals[:4])

    # ---------- ③ 区域 + 日志/数据流（字符串、注释） ----------
    if rkind in ("line_comment", "block_comment"):
        return mk("documentation", "high", "命中在注释区")

    if rkind == "string":
        # 看这个字符串字面量**所在的容器**里有没有 sink / 日志
        # （不用大窗口；只看该字符串字面量本身所在的语句片段）
        seg_open = text.rfind("\n", 0, pos)
        seg_close = text.find("\n", pos)
        seg = text[max(0, seg_open):(len(text) if seg_close < 0 else seg_close)]
        # 跨行字符串：向前后各扩 400 字符（但仍要求 sink 出现在**同一容器**上下文）
        ctx = text[max(0, pos - 400):min(len(text), pos + 400)]
        has_sink = bool(re.search(
            r"\b(?:fetch|request|axios|putObject|postObject|upload|"
            r"writeFile|writeFileSync|createWriteStream)\s*\(", ctx))
        only_log = bool(re.search(
            r"\b(?:console\.log|print|logger|process\.stdout\.write)\s*\(", seg))
        # 模板字符串赋给常量、且该常量只被日志消费 → documentation
        if only_log:
            return mk("documentation", "medium", "字符串所在语句只被日志消费")
        if has_sink:
            return mk("active_operation", "low",
                      "字符串附近出现网络/文件 sink（弱证据，需人工复核）")

    # ---------- 无足够依据：不硬猜 ----------
    return mk("unknown", "low", "无精确消费点，且不做窗口猜测")
