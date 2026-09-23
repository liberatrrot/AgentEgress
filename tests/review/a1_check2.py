#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A1 严格版：分支级「必现字面量」覆盖检查 + id 重复检查。

判据：把正则按顶层 `|` 拆成若干分支；对每个分支算出「任何匹配都必然包含的
连续字面量片段集合」F。若某分支存在 F 中任一片段包含某个 kw，则该分支的所有
匹配都必然含 kw（因为 匹配 ⊇ 片段 ⊇ kw）。若某分支 F 中没有任何片段覆盖
任何 kw，则该分支可疑 —— 存在匹配不含任何 kw 的可能。
"""
import sys, re
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as A
from re import _parser as sre_parse
from collections import Counter

CAT = {"CATEGORY_DIGIT":"0","CATEGORY_NOT_DIGIT":"a","CATEGORY_SPACE":" ",
       "CATEGORY_NOT_SPACE":"a","CATEGORY_WORD":"a","CATEGORY_NOT_WORD":"-",
       "CATEGORY_LINEBREAK":"\n","CATEGORY_NOT_LINEBREAK":"a"}

def forced(tokens):
    """返回该 token 序列中『必然出现的连续字面量片段』集合。"""
    out = []
    cur = ""
    for op, av in tokens:
        n = str(op)
        if n == "LITERAL":
            cur += chr(av)
        elif n == "SUBPATTERN":
            inner = forced(list(av[3]))
            if len(inner) == 1 and cur:
                cur += inner[0]
                continue
            if cur: out.append(cur); cur = ""
            out += inner
        elif n == "BRANCH":
            sets = [forced(list(b)) for b in av[1]]
            common = set(sets[0])
            for s in sets[1:]:
                common &= set(s)
            if cur and len(common) == 1:
                cur += next(iter(common)); continue
            if cur: out.append(cur); cur = ""
            out += sorted(common)
        elif n in ("MAX_REPEAT","MIN_REPEAT","POSSESSIVE_REPEAT"):
            mn, mx, child = av
            if mn >= 1:
                inner = forced(list(child))
                if len(inner) == 1 and cur:
                    cur += inner[0]; continue
                if cur: out.append(cur); cur = ""
                out += inner
            else:
                if cur: out.append(cur); cur = ""
        elif n == "IN":
            items = list(av)
            neg = any(str(io) == "NEGATE" for io, _ in items)
            if not neg:
                lits = [chr(ia) for io, ia in items if str(io) == "LITERAL"]
                if len(lits) == 1:
                    cur += lits[0]
                    continue
            if cur: out.append(cur); cur = ""
        elif n == "AT":
            continue
        else:  # ANY / CATEGORY / ASSERT / GROUPREF / ...
            if cur: out.append(cur); cur = ""
    if cur: out.append(cur)
    return [x for x in out if x]

# ---- id 重复检查
ids = [p["id"] for c in A.CAPABILITY_DEFS for p in c["patterns"]]
dupes = [k for k, v in Counter(ids).items() if v > 1]
extra = [k for k in A.PATTERN_KEYWORDS if k not in set(ids)]
print("pattern 总数: %d ; PATTERN_KEYWORDS 条目数: %d" % (len(ids), len(A.PATTERN_KEYWORDS)))
print("重复 id: %s" % (dupes or "无"))
print("PATTERN_KEYWORDS 里的多余键: %s" % (extra or "无"))
print("=" * 80)

flags = []
for cap in A.CAPABILITY_DEFS:
    for p in cap["patterns"]:
        pid, rx = p["id"], p["re"]
        kws = [k.lower() for k in A.PATTERN_KEYWORDS.get(pid, [])]
        tree = list(sre_parse.parse(rx, re.I))
        # 顶层按 BRANCH 展开
        branches = [tree]
        if len(tree) == 1 and str(tree[0][0]) == "BRANCH":
            branches = [list(b) for b in tree[0][1][1]]
        for bi, b in enumerate(branches):
            F = forced(b)
            covered = any(any(k in f.lower() for k in kws) for f in F)
            if not covered:
                flags.append((pid, rx, bi, F, kws))

print("可疑分支 %d 个：" % len(flags))
for pid, rx, bi, F, kws in flags:
    print("! %-20s 分支#%d  re=%s" % (pid, bi, rx))
    print("    必现片段: %s" % F)
    print("    声明 kws : %s" % kws)
    print()
