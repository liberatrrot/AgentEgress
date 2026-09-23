#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A1 反例搜索：PATTERN_KEYWORDS 不变式
   不变式：pattern.re 匹配  ⇒  该 pattern 的 kws 至少有一个出现在文本里
   违反 = 预筛会跳过含该证据的文件 = 该类证据永久漏检。

方法：从正则语法树枚举可生成的字符串（每个分支分别枚举），对每个候选用
re.search 实跑一遍；若「能匹配」且「候选串里不含任何关键词」→ 找到反例。
"""
import sys, re, itertools
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as A
from re import _parser as sre_parse

CAP = 400        # 单 pattern 候选串上限
CAT = {
    "CATEGORY_DIGIT": "0", "CATEGORY_NOT_DIGIT": "a",
    "CATEGORY_SPACE": " ", "CATEGORY_NOT_SPACE": "a",
    "CATEGORY_WORD": "a",  "CATEGORY_NOT_WORD": "-",
    "CATEGORY_LINEBREAK": "\n", "CATEGORY_NOT_LINEBREAK": "a",
}

def gen_tokens(tokens):
    """把 token 列表生成候选串列表（笛卡尔积，带上限）。"""
    opts_per_token = [gen_one(op, av) for op, av in tokens]
    out = []
    for combo in itertools.product(*opts_per_token):
        out.append("".join(combo))
        if len(out) >= CAP:
            break
    return out or [""]

def gen_one(op, av):
    n = str(op)
    if n == "LITERAL":
        return [chr(av)]
    if n == "NOT_LITERAL":
        return ["X"]                       # 任意不等于该字符的字
    if n == "ANY":
        return ["a"]
    if n == "IN":
        items = list(av)
        negate = any(str(io) == "NEGATE" for io, _ in items)
        if negate:
            return ["X"]
        cands = []
        for io, ia in items:
            iname = str(io)
            if iname == "LITERAL":
                cands.append(chr(ia))
            elif iname == "CATEGORY":
                cands.append(CAT.get(str(ia), "a"))
            elif iname == "RANGE":
                cands.append(chr(ia[0]))
        return cands[:6] or ["a"]
    if n == "CATEGORY":
        return [CAT.get(str(av), "a")]
    if n == "SUBPATTERN":
        return gen_tokens(list(av[3]))
    if n == "BRANCH":
        out = []
        for b in av[1]:
            out.extend(gen_tokens(list(b)))
        return out[:CAP] or [""]
    if n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
        mn, mx, child = av
        base = gen_tokens(list(child))
        reps = [""] if mn == 0 else []
        reps += [(base[0] * k) for k in range(mn, mn + 2)]
        reps += base[:2]
        return reps
    if n in ("AT", "ASSERT", "ASSERT_NOT", "GROUPREF",
             "GROUPREF_EXISTS", "ATOMIC_GROUP", "SUCCESS", "FAILURE"):
        return [""]
    # 未知 opcode：留空，靠后续 re.search 兜底
    return [""]

print("=" * 80)
print("%-22s %-40s %s" % ("pattern id", "regex", "结果"))
print("=" * 80)

violations = []
unparsed = []
for cap in A.CAPABILITY_DEFS:
    for p in cap["patterns"]:
        pid, rx = p["id"], p["re"]
        kws = [k.lower() for k in A.PATTERN_KEYWORDS.get(pid, [])]
        rgx = re.compile(rx, re.I)
        try:
            tree = list(sre_parse.parse(rx, re.I))
        except Exception as e:
            unparsed.append((pid, rx, str(e))); continue
        cands = gen_tokens(tree)
        bad = None
        matched_any = False
        for c in cands:
            m = rgx.search(c)
            if not m:
                continue
            matched_any = True
            text = c.lower()
            if not any(k in text for k in kws):
                bad = c
                break
        if bad is not None:
            violations.append((pid, rx, bad, kws))
        elif not matched_any:
            unparsed.append((pid, rx, "生成器未产出可匹配串"))

print("=" * 80)
print("反例命中（不变式被违反）：%d" % len(violations))
print("=" * 80)
for pid, rx, bad, kws in violations:
    print("!! %-22s re=%s" % (pid, rx))
    print("   反例文本 : %r   （re.search 命中，但不含任何 kws）" % bad)
    print("   声明 kws : %s" % kws)
    print()

print("=" * 80)
print("未能自动覆盖（需人工看）：%d" % len(unparsed))
for pid, rx, why in unparsed:
    print("   ? %-22s %-45s %s" % (pid, rx, why))
