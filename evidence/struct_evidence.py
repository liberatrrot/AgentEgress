# -*- coding: utf-8 -*-
"""结构事实检查器 —— 为 21-case 标注提供**机器可复核的旁证**

**它不是判定器。** 判定（U1/U2/U3 + R1/R2）由人做。
它只回答四个可以用代码验证的问题：

    ① 两位置各自落在哪个函数体内？
    ② 是否存在调用边？（一个位置的函数名/标识符，在另一位置的区域内出现）
    ③ 是否存在共享标识符？（两位置都引用同一变量）
    ④ 两位置之间是否跨越了函数边界？（在 minified 代码里常代表"无关"）

**为什么需要它**：`candidate_pairs` 只用"距离 ≤ 4000"筛选，
选出的多是"同一业务模块内相邻的函数"。
人工只看片段无法区分"真的没有结构"和"看不清"。
"""
import io
import os
import re
import sys
import json

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

# 函数起点：`function name(` / `name=function` / `a(fn,"name")` 显式命名
FN_DEF = re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(")
FN_NAMED = re.compile(r"a\(\s*([A-Za-z_$][\w$]*)\s*,\s*[\"']([^\"']+)[\"']\s*\)")
# 标识符
IDENT = re.compile(r"[A-Za-z_$][\w$]{0,30}")


def enclosing_fn(text, pos, back=6000):
    """返回包含 pos 的最近函数定义（名字 + 起点）。"""
    seg = text[max(0, pos - back):pos]
    m = None
    for mm in FN_DEF.finditer(seg):
        m = mm
    if not m:
        return None, -1
    return m.group(1), max(0, pos - back) + m.start()


def named_at(text, pos, span=400):
    """该位置附近是否有 `a(fn,"readableName")` 的显式命名。"""
    seg = text[max(0, pos - span):pos + span]
    out = []
    for mm in FN_NAMED.finditer(seg):
        out.append((mm.group(1), mm.group(2)))
    return out


def idents_near(text, pos, radius=300, limit=40):
    seg = text[max(0, pos - radius):pos + radius]
    ids = {m.group(0) for m in IDENT.finditer(seg)}
    # 过滤过短的
    return {i for i in ids if len(i) > 1}


def analyze(text, off_a, off_b):
    """对一对位置做结构旁证检查。"""
    lo, hi = min(off_a, off_b), max(off_a, off_b)
    fa, sa = enclosing_fn(text, off_a)
    fb, sb = enclosing_fn(text, off_b)
    na = named_at(text, off_a)
    nb = named_at(text, off_b)

    # ① 各自的函数体范围
    def fn_span(text, fname, start):
        if start < 0:
            return None
        s = text.find("(", start)
        if s < 0:
            return None
        depth, i, n = 0, s, len(text)
        while i < n:
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return (start, i + 1)
            elif c == "(" and depth == 0:
                pass
            i += 1
        return None

    spa = fn_span(text, fa, sa)
    spb = fn_span(text, fb, sb)

    # ② 调用边：a 的函数名（及显式命名）是否出现在 b 的函数体内
    def appears_in(name, span):
        if not name or not span:
            return False
        seg = text[span[0]:span[1]]
        return bool(re.search(r"(?<![\w$])" + re.escape(name) + r"(?![\w$])", seg))

    names_a = ([fa] if fa else []) + [x[1] for x in na]
    names_b = ([fb] if fb else []) + [x[1] for x in nb]
    call_a_in_b = [n for n in names_a if n and appears_in(n, spb)]
    call_b_in_a = [n for n in names_b if n and appears_in(n, spa)]

    # ③ 共享标识符
    ia = idents_near(text, off_a)
    ib = idents_near(text, off_b)
    shared = sorted(ia & ib)[:15]

    return {
        "fn_a": fa, "fn_b": fb,
        "named_a": na[:4], "named_b": nb[:4],
        "fn_span_a": spa, "fn_span_b": spb,
        "crosses_fn_boundary": bool(fa and fb and fa != fb),
        "call_a_in_b": call_a_in_b,
        "call_b_in_a": call_b_in_a,
        "shared_idents": shared,
        "distance": hi - lo,
    }


def main():
    cases_path = os.path.join(_HERE, "_u_cases.json")
    if not os.path.exists(cases_path):
        print("缺 _u_cases.json —— 请先跑 export_cases.py")
        return
    cases = json.load(open(cases_path, encoding="utf-8"))
    print("=" * 104)
    print("结构事实旁证（供标注参考，**不含判定**）")
    print("=" * 104)

    for i, c in enumerate(cases, 1):
        p = os.path.join(DOGFOOD, *c["file"].split("/"))
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8", errors="ignore").read()
        r = analyze(text, c["source"]["offset"], c["sink"]["offset"])
        print("\n[U%02d] %s ↔ %s   (距离 %d)" % (
            i, c["from_cap"], c["to_cap"], r["distance"]))
        print("    source 函数 = %s %s" % (r["fn_a"] or "—",
                                          [x[1] for x in r["named_a"]] or ""))
        print("    sink   函数 = %s %s" % (r["fn_b"] or "—",
                                          [x[1] for x in r["named_b"]] or ""))
        print("    ★ 跨越函数边界 = %s" % r["crosses_fn_boundary"])
        print("    ★ 调用边：a→b %s   b→a %s" % (
            r["call_a_in_b"] or "无", r["call_b_in_a"] or "无"))
        print("    ★ 共享标识符 = %s" % (r["shared_idents"][:8] or "无"))
        verdict = ("**no call edge, different functions → 倾向 U2**"
                   if r["crosses_fn_boundary"] and not r["call_a_in_b"]
                   and not r["call_b_in_a"] and not r["shared_idents"]
                   else "**需人工判断**")
        print("    旁证结论: %s" % verdict)


if __name__ == "__main__":
    main()
