# -*- coding: utf-8 -*-
"""A1：证伪预筛表不变式。

不变式（源码声明）：某个 pattern 的正则匹配 ⇒ 该 pattern 的 kws 至少有一个出现在文本里。

内置自检 _check_keyword_consistency 只为一个正则生成【一条】最小匹配串。
本脚本改为枚举正则语法树上【所有分支 × 所有可选重复次数】的展开，
对每条展开同时验证：(1) 正则确实匹配它 (2) 预筛过滤器放行它。
只要有一条展开不被放行，不变式即被证伪。
"""
import sys
import itertools

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402
from re import _parser as _rp  # noqa: E402

LIMIT = 4          # 每条子表达式最多保留的候选串数
MAX_DEPTH = 12


def _expand_range(a):
    lo, hi = a
    if hi - lo > 128:
        return {lo, hi}
    return set(range(lo, hi + 1))


def in_class_candidates(av):
    """IN 类：只产生【确实属于该类】的代表字符，否则会造出正则不匹配的假违例。

    对取反类（\\W / [^,;]）必须知道整个类的成员集合，只拿一个代表字符是不够的。
    """
    import string
    negate = any(str(op) == "NEGATE" for op, _a in av)
    members, excluded = set(), set()
    for op, a in av:
        n = str(op)
        if n == "LITERAL" and isinstance(a, int):
            members.add(a)
            excluded.add(a)
        elif n == "RANGE":
            excluded |= _expand_range(a)
            members.add(a[0])
        elif n == "CATEGORY":
            cat = str(a)
            if "WORD" in cat:
                excluded |= set(string.ascii_letters + string.digits + "_")
            elif "SPACE" in cat:
                excluded |= set(" \t\n\r\f\v")
            elif "DIGIT" in cat:
                excluded |= set(string.digits)
            elif "LINEBREAK" in cat:
                excluded |= set("\n\r")
            else:
                members.add(ord("a"))
    if negate:
        pool = "!@#$%^&*-+=~`|:;,.?/\\\"'<>[]{}()"
        out = [c for c in pool if ord(c) not in excluded]
        return out[:3] or ["#"]
    out = [chr(c) for c in sorted(members)]
    return out[:3] or ["a"]


def walk(sub, depth=0):
    """返回该子树所有（有界的）展开候选。"""
    if depth > MAX_DEPTH:
        return [""]
    try:
        items = list(sub)
    except TypeError:
        return [""]

    parts = []
    for op, av in items:
        n = str(op)
        if n == "LITERAL":
            cands = [chr(av)]
        elif n == "NOT_LITERAL":
            cands = ["a", "Z"]
        elif n == "IN":
            cands = in_class_candidates(av)
        elif n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
            lo = int(av[0])
            body = walk(av[2], depth + 1)[:LIMIT]
            if lo == 0:
                reps = [0, 1]
            else:
                reps = [lo, lo + 1]
            cands = []
            for r in reps:
                for combo in itertools.islice(itertools.product(body, repeat=r), LIMIT):
                    cands.append("".join(combo))
            cands = list(dict.fromkeys(cands))[:LIMIT + 1]
        elif n == "SUBPATTERN":
            cands = walk(av[3], depth + 1)[:LIMIT]
        elif n == "BRANCH":
            cands = []
            for b in av[1]:
                cands.extend(walk(b, depth + 1))
            cands = list(dict.fromkeys(cands))[:LIMIT]
        elif n == "ANY":
            cands = ["a", "1"]
        elif n == "CATEGORY":
            cands = ["a", "5", " "]
        elif n == "AT":
            cands = [""]
        else:
            cands = [""]
        parts.append(cands or [""])

    out = []
    for combo in itertools.islice(itertools.product(*parts), LIMIT * 4):
        out.append("".join(combo))
    return list(dict.fromkeys(out)) or [""]


def main():
    total_expansions = 0
    violations = []
    nonmatching = []
    empty = []

    for cap in ae._COMPILED_CAPS:
        for pat in cap["patterns"]:
            pat_str = pat["re"].pattern
            exps = walk(_rp.parse(pat_str, 0))
            exps = list(dict.fromkeys(e for e in exps if e))
            if not exps:
                empty.append(pat["id"])
                continue
            for s in exps:
                total_expansions += 1
                if pat["re"].search(s) is None:
                    nonmatching.append((pat["id"], pat_str, s))
                    continue
                if ae._KW_FILTER.search(s) is None:
                    violations.append((pat["id"], pat_str, s))

    print("枚举出的展开总数:", total_expansions)
    print("展开后正则不匹配（生成器不可靠）:", len(nonmatching))
    for pid, pat_str, s in nonmatching[:40]:
        print("   NONMATCH %-16s re=%-46r sample=%r" % (pid, pat_str, s))
    print("不变式违例（正则匹配但预筛挡掉）:", len(violations))
    for pid, pat_str, s in violations[:60]:
        print("   VIOLATION %-16s re=%-46r sample=%r" % (pid, pat_str, s))
    print("无法生成展开:", empty)
    print("内置自检的 unverifiable:", ae._KEYWORD_CONSISTENCY)
    return 1 if (violations or nonmatching) else 0


if __name__ == "__main__":
    sys.exit(main())
