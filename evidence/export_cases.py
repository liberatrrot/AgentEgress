# -*- coding: utf-8 -*-
"""导出 21 个 candidate_but_unverified 的完整证据，供人工标注。

**只导出，不判定。** 判定由人工做（U1/U2/U3）。

每个案例给出：
    from_cap / to_cap
    source: file + offset + region + 代码片段（前后各 160 字符）
    sink  : 同上
    两点之间的距离

**禁止**在导出里出现"建议"、"可能相关"之类的判断 ——
本脚本只负责把代码端到人面前。
"""
import io
import os
import sys
import json

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import agentegress as ae                                        # noqa: E402
from adapter import build                                       # noqa: E402
from locator import expand_citations, candidate_pairs           # noqa: E402
from relation import relate, region_at, same_object, argument_flow  # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

MAX_FILE_MB = float(os.environ.get("EX_MAX_FILE_MB", "5"))
WINDOW = int(os.environ.get("EX_WINDOW", "4000"))
ONLY = os.environ.get("EX_ONLY", "")      # 只跑文件名含该串的文件（分批用）
TRUNC_MB = float(os.environ.get("EX_TRUNC_MB", "0"))

FILES = [
    ("S1 ZCode",     "s1-zcode/out/host/index.js"),
    ("S1 ZCode",     "s1-zcode/out/main/index.js"),
    ("S2 WorkBuddy", "s2-workbuddy/main/index.js"),
    ("S4 Quark",     "s4-quark/dist/main/main.js"),
    ("E3", "s5-orthogonal/e3-structural/src/index.js"),
    ("E4", "s5-orthogonal/e4-structural-bridges-lexical/src/index.js"),
]


def pattern_res_for(cap_id):
    for c in ae._COMPILED_CAPS:
        if c["id"] == cap_id:
            return [p["re"] for p in c["patterns"]]
    return []


def snippet(text, pos, back=160, fwd=160):
    lo = max(0, pos - back)
    hi = min(len(text), pos + fwd)
    s = text[lo:hi].replace("\n", "\\n")
    return ("…" if lo > 0 else "") + s + ("…" if hi < len(text) else "")


def main():
    cases = []
    for tag, rel in FILES:
        if ONLY and ONLY not in rel:
            continue
        p = os.path.join(DOGFOOD, *rel.split("/"))
        if not os.path.exists(p):
            continue
        if os.path.getsize(p) / 1048576.0 > MAX_FILE_MB:
            continue
        text = open(p, encoding="utf-8", errors="ignore").read()
        if TRUNC_MB and len(text) > TRUNC_MB * 1048576:
            text = text[:int(TRUNC_MB * 1048576)]
        _obs, by_cap = build(text, os.path.basename(p))

        # 展开全部 citation
        expanded = {}
        for cap, evs in by_cap.items():
            pats = pattern_res_for(cap)
            allc = []
            for e in evs:
                cs = [e.citation.get("offset")] if e.citation else []
                for re_ in pats:
                    cs += expand_citations(text, e, pattern_re=re_)
                allc.append(sorted(set(c for c in cs if c is not None)))
            expanded[cap] = allc

        caps = sorted(by_cap)
        for i in range(len(caps)):
            for j in range(i + 1, len(caps)):
                a_cap, b_cap = caps[i], caps[j]
                pa_list = [c for cs in expanded[a_cap] for c in cs]
                pb_list = [c for cs in expanded[b_cap] for c in cs]
                pairs, _tr = candidate_pairs(text, pa_list, pb_list, WINDOW)
                if not pairs:
                    continue
                # 该对是否有 verified
                verified = [p_ for p_ in pairs
                            if relate(text, p_[0], p_[1], a_cap, b_cap)]
                if verified:
                    continue        # 已验证的不属于本清单
                # 取距离最近的一对作为代表
                pairs.sort(key=lambda x: abs(x[0] - x[1]))
                pa, pb = pairs[0]
                cases.append({
                    "file": rel,
                    "tag": tag,
                    "from_cap": a_cap,
                    "to_cap": b_cap,
                    "n_pairs_in_window": len(pairs),
                    "closest_distance": abs(pa - pb),
                    "source": {"offset": pa, "region": region_at(text, pa),
                               "snippet": snippet(text, pa)},
                    "sink": {"offset": pb, "region": region_at(text, pb),
                             "snippet": snippet(text, pb)},
                })

    # ---- 输出 ----
    print("=" * 110)
    print("candidate_but_unverified 全量导出（供人工标注）")
    print("=" * 110)
    print("共 %d 个案例。**本清单不含任何判定** —— label 需人工填。" % len(cases))
    print("""
标签定义：
  U1 structurally_expected    代码中存在可复核结构事实，当前 Relation 层应能表达却没表达
  U2 no_structure             距离近但不存在可证明的结构关系
  U3 unknown_due_to_analysis  可能有关，但当前证据/定位/分析能力不足以判定

结构证据白名单（只有这些能支撑 U1）：
  变量赋值 · 参数传递 · 返回值 · 对象属性 · 同一对象 · 嵌套调用 · 函数调用边 · import/binding
**相邻 / 同一文件 / 同一函数附近 / 命名相似 / 业务上相关 / 同时出现 —— 都不能单独成为结构证据。**
""")

    for k, c in enumerate(cases, 1):
        print("─" * 110)
        print("[U%02d] %s  ·  %s" % (k, c["tag"], c["file"]))
        print("  from_cap = %s" % c["from_cap"])
        print("  to_cap   = %s" % c["to_cap"])
        print("  窗口内证据对数 = %d   最近距离 = %d" % (
            c["n_pairs_in_window"], c["closest_distance"]))
        print("  source @%d [%s]" % (c["source"]["offset"], c["source"]["region"]))
        print("      %s" % c["source"]["snippet"])
        print("  sink   @%d [%s]" % (c["sink"]["offset"], c["sink"]["region"]))
        print("      %s" % c["sink"]["snippet"])
        print("  label = ____    structural_proof = ____    why = ____")

    with open(os.path.join(_HERE, "_u_cases.json"), "w", encoding="utf-8") as f:
        json.dump(cases, f, ensure_ascii=False, indent=2)
    print("\n" + "=" * 110)
    print("已保存 %d 个案例到 _u_cases.json" % len(cases))


if __name__ == "__main__":
    main()
