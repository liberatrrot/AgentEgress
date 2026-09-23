#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A1 严格版 v3：展开有限歧义 -> 逐变体求必现字面量 -> 要求全部变体被 kw 覆盖。"""
import sys, re, itertools
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as A
from re import _parser as sre_parse

CAP = 300
VAR = "VAR"

def expand(tokens):
    """把 token 列表展开成若干『无有限歧义』的 token 列表变体。"""
    outs = [[]]
    for op, av in tokens:
        n = str(op)
        opts = exp1(n, av)
        new = []
        for base in outs:
            for o in opts:
                if len(new) >= CAP:
                    break
                new.append(base + o)
        outs = new
        if len(outs) >= CAP:
            outs = outs[:CAP]
    return outs

def exp1(n, av):
    if n == "LITERAL":
        return [[("L", chr(av))]]
    if n == "SUBPATTERN":
        return expand(list(av[3]))
    if n == "BRANCH":
        out = []
        for b in av[1]:
            out.extend(expand(list(b)))
        return out[:CAP]
    if n == "IN":
        items = list(av)
        if any(str(io) == "NEGATE" for io, _ in items):
            return [[("V","")]]
        lits = [chr(ia) for io, ia in items if str(io) == "LITERAL"]
        if lits and len(lits) == len(items) and len(lits) <= 6:
            return [[("L", c)] for c in lits]
        return [[("V","")]]
    if n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
        mn, mx, child = av
        sub = exp1(str(child[0][0]), child[0][1]) if len(child) == 1 else expand(list(child))
        if mx == mn:                      # 定长
            if mn == 0:
                return [[]]
            res = [[]]
            for _ in range(mn):
                res = [a + b for a in res for b in sub][:CAP]
            return res or [[]]
        if mx is not None and mx <= 2:    # 0..1 / 0..2
            variants = [[]]
            for k in range(1, mx + 1):
                acc = [[]]
                for _ in range(k):
                    acc = [a + b for a in acc for b in sub][:CAP]
                variants.extend(acc)
            return variants[:CAP]
        # 无界
        res = [[]]
        for _ in range(mn):
            res = [a + b for a in res for b in sub][:CAP]
        return [r + [("V","")] for r in res][:CAP]
    if n == "AT" or n == "ASSERT":
        return [[]]
    return [[("V","")]]

def expand_one(sub):
    return sub

def forced(v):
    """变体 -> 必现连续字面量片段（VAR 截断）。"""
    out, cur = [], ""
    for op, val in v:
        if op == "L":
            cur += val
        else:
            if cur: out.append(cur); cur = ""
    if cur: out.append(cur)
    return out

print("=" * 80)
flags = []
for cap in A.CAPABILITY_DEFS:
    for p in cap["patterns"]:
        pid, rx = p["id"], p["re"]
        kws = [k.lower() for k in A.PATTERN_KEYWORDS.get(pid, [])]
        tree = list(sre_parse.parse(rx, re.I))
        variants = expand(tree)
        bad = []
        for v in variants:
            F = forced(v)
            if not any(any(k in f.lower() for k in kws) for f in F):
                bad.append(F)
        if bad:
            flags.append((pid, rx, kws, len(variants), bad[:3]))

print("未被覆盖的变体数 > 0 的 pattern：%d" % len(flags))
print("=" * 80)
for pid, rx, kws, nv, bad in flags:
    print("! %-20s re=%s   (%d 变体)" % (pid, rx, nv))
    print("    未覆盖变体的必现片段示例: %s" % bad)
    print("    声明 kws: %s" % kws)
    print()
