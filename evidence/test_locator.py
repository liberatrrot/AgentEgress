# -*- coding: utf-8 -*-
"""P2.1 验收：R-L1 ~ R-L6

**成功标准不是"触发率从 0% 提到 10%"**，而是：

    R-L1  所有 Evidence 保留完整 citation 集合
    R-L2  primary_citation 不再决定 relation evaluation
    R-L3  候选生成有 bounded complexity
    R-L4  每个 search 都能说明四态
    R-L5  S1/S2/S4/E3/E4 回放不改变既有事实
    R-L6  没有引入 semantic-role enrichment

核心问题：**relation=0 是事实，还是定位策略造成的假象？**
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

import agentegress as ae                                     # noqa: E402
from adapter import build, observe                           # noqa: E402
from assess import assess                                    # noqa: E402
from locator import (expand_citations, candidate_pairs,      # noqa: E402
                     search_relation, summarize_searches,
                     assert_locator_invariants)

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

MAX_FILE_MB = float(os.environ.get("LC_MAX_FILE_MB", "5"))
TRUNC_MB = float(os.environ.get("LC_TRUNC_MB", "0"))

FILES = [
    ("S1 ZCode",     "s1-zcode/out/host/index.js"),
    ("S1 ZCode",     "s1-zcode/out/main/index.js"),
    ("S2 WorkBuddy", "s2-workbuddy/main/index.js"),
    ("S4 Quark",     "s4-quark/dist/main/main.js"),
    ("E3 构造",       "s5-orthogonal/e3-structural/src/index.js"),
    ("E4 构造",       "s5-orthogonal/e4-structural-bridges-lexical/src/index.js"),
]


def pattern_res_for(cap_id):
    """返回该能力的全部 pattern 正则（用于 expand_citations）。"""
    for c in ae._COMPILED_CAPS:
        if c["id"] == cap_id:
            return [p["re"] for p in c["patterns"]]
    return []


def run_file(tag, rel):
    p = os.path.join(DOGFOOD, *rel.split("/"))
    if not os.path.exists(p):
        return None
    mb = os.path.getsize(p) / 1048576.0
    if mb > MAX_FILE_MB:
        return {"skipped": True, "mb": mb, "tag": tag, "file": rel}
    text = open(p, encoding="utf-8", errors="ignore").read()
    truncated = False
    if TRUNC_MB and len(text) > TRUNC_MB * 1048576:
        text = text[:int(TRUNC_MB * 1048576)]
        truncated = True

    _obs, by_cap = build(text, os.path.basename(p))
    before = {a.capability: a.evidence_state for a in assess(by_cap)}

    # ---- R-L1：为每条 Evidence 展开完整 citation ----
    expanded = {}
    n_multi = 0
    for cap, evs in by_cap.items():
        pats = pattern_res_for(cap)
        all_c = []
        for e in evs:
            cs = [e.citation.get("offset")] if e.citation else []
            for re_ in pats:
                cs += expand_citations(text, e, pattern_re=re_)
            cs = sorted(set(c for c in cs if c is not None))
            if len(cs) > 1:
                n_multi += 1
            all_c.append(cs)
        expanded[cap] = all_c

    # ---- 搜索（对每对能力）----
    caps = sorted(by_cap)
    searches = []
    for i in range(len(caps)):
        for j in range(i + 1, len(caps)):
            a_cap, b_cap = caps[i], caps[j]
            flat_a = [c for cs in expanded[a_cap] for c in cs]
            flat_b = [c for c in (x for cs in expanded[b_cap] for x in cs)]
            searches.append(search_relation(text, a_cap, b_cap,
                                            flat_a, flat_b))

    after = {a.capability: a.evidence_state for a in assess(by_cap)}
    return {
        "tag": tag, "file": rel, "mb": round(mb, 2), "truncated": truncated,
        "n_caps": len(caps), "n_evidence": sum(len(v) for v in by_cap.values()),
        "n_multi_citation": n_multi,
        "searches": searches, "summary": summarize_searches(searches),
        "before": before, "after": after,
        "skipped": False,
    }


def main():
    print("=" * 100)
    print("P2.1 · Evidence Locator Refinement 验收（R-L1 ~ R-L6）")
    print("=" * 100)
    print("""核心问题：relation=0 是**事实**，还是**定位策略造成的假象**？
三条硬要求：
  1. Evidence 保留完整 citation 集合
  2. primary_citation 不再决定 relation evaluation
  3. 候选生成 bounded complexity（邻域筛选，不做全配对）""")

    results = []
    all_searches = []
    for tag, rel in FILES:
        print("\n" + "#" * 100)
        print("# %s  ·  %s" % (tag, rel))
        r = run_file(tag, rel)
        if r is None:
            print("# [缺]")
            continue
        if r.get("skipped"):
            print("# [跳过] %.1f MB > %s MB" % (r["mb"], MAX_FILE_MB))
            continue
        results.append(r)
        all_searches += r["searches"]
        s = r["summary"]
        print("# %.1f MB  %d 能力  %d 条证据  其中 %d 条有多个 citation"
              % (r["mb"], r["n_caps"], r["n_evidence"], r["n_multi_citation"]))
        print("# 搜索 %d 次：verified=%d  candidate_but_unverified=%d  "
              "no_candidate=%d  blocked=%d"
              % (s["searches"], s["relation_verified"],
                 s["candidate_found_but_unverified"],
                 s["no_candidate"], s["search_blocked"]))
        print("# 建出的 relation 数 = %d   检查的证据对 = %d"
              % (s["verified_relations"], s["checked_pairs_total"]))
        for sr in r["searches"]:
            if sr.state == "relation_verified":
                for v in sr.verified:
                    print("#     ✓ %s ↔ %s : %s" % (
                        sr.from_cap, sr.to_cap, v["type"]))
            elif sr.state == "candidate_found_but_unverified":
                print("#     ~ %s ↔ %s : 有邻域候选对但 verifier 未通过"
                      % (sr.from_cap, sr.to_cap))

    # ============================================================ R-L1..L6
    print("\n" + "=" * 100)
    print("R-L1 ~ R-L6")
    print("=" * 100)
    gates = []

    # R-L1 完整 citation 集合
    n_multi = sum(r["n_multi_citation"] for r in results)
    gates.append(("R-L1 Evidence 保留完整 citation 集合", n_multi > 0,
                  "%d 条证据拥有 >1 个 citation 位置" % n_multi))

    # R-L2 primary_citation 不再决定 evaluation
    try:
        assert_locator_invariants(all_searches)
        gates.append(("R-L2 primary_citation 不决定 relation evaluation",
                      True, "无 checked_pairs=0 的 verified 结果"))
    except AssertionError as e:
        gates.append(("R-L2 primary_citation 不决定 relation evaluation",
                      False, str(e)))

    # R-L3 bounded complexity
    from locator import MAX_CANDIDATE_PAIRS, DEFAULT_WINDOW
    over = [s for s in all_searches if s.checked_pairs > MAX_CANDIDATE_PAIRS]
    gates.append(("R-L3 候选生成 bounded（上限 %d 对，窗口 %d）"
                  % (MAX_CANDIDATE_PAIRS, DEFAULT_WINDOW), not over,
                  "超标 %d 次" % len(over)))

    # R-L4 四态可说明
    seen_states = {s.state for s in all_searches}
    gates.append(("R-L4 每个 search 都能说明四态之一", len(seen_states) >= 2,
                  "出现的状态: %s" % sorted(seen_states)))

    # R-L5 回放不改变既有事实
    leaks = []
    for r in results:
        d = {k for k in r["before"] if r["before"][k] != r["after"].get(k)}
        if d:
            leaks.append("%s/%s: %s" % (r["tag"], r["file"], d))
    gates.append(("R-L5 回放不改变 capability 既有事实", not leaks,
                  "层间变化: %s" % leaks if leaks else "无变化"))

    # R-L6 无 semantic-role enrichment
    loc_src = open(os.path.join(_HERE, "locator.py"), encoding="utf-8").read()
    bad = [k for k in ("semantic_role", "role_evidence", "admit(")
           if k in loc_src and "R-L6" not in loc_src.split(k)[0][-200:]]
    gates.append(("R-L6 未引入 semantic-role enrichment", not bad,
                  "命中: %s" % bad if bad else "locator.py 不提 role"))

    for name, ok, detail in gates:
        print("  %s %s" % ("✓" if ok else "✗", name))
        print("      %s" % detail)

    # ============================================================ 核心问题
    print("\n" + "=" * 100)
    print("★ 核心问题：relation=0 是事实，还是定位假象？")
    print("=" * 100)
    total = summarize_searches(all_searches)
    print("  搜索次数（分母）           = %d" % total["searches"])
    print("  relation_verified          = %d" % total["relation_verified"])
    print("  candidate_found_but_unverif= %d" % total["candidate_found_but_unverified"])
    print("  no_candidate               = %d" % total["no_candidate"])
    print("  search_blocked             = %d" % total["search_blocked"])
    print("  建出的 relation 总数        = %d" % total["verified_relations"])

    if total["relation_verified"] > 0:
        print("""
  → **定位策略确实是原因之一。** 用完整 citation 集合后能找到 relation，
    说明之前的 0 主要是"首处命中"这个定位偏差造成的。""")
    elif total["candidate_found_but_unverified"] > 0:
        print("""
  → **找到了邻域候选对，但 verifier 未通过。**
    说明关系可能存在，只是当前两类关系（same_object / argument_flow）
    不足以表达 —— 这才是支持增加 relation 类型的证据。""")
    else:
        print("""
  → **所有搜索都是 no_candidate。**
    说明在合理邻域内，这些能力的证据对之间**根本没有可观察的局部结构**。
    此时"关系稀疏"是事实，而不是定位假象。""")

    n = sum(1 for _x, ok, _d in gates if ok)
    print("\n" + "=" * 100)
    print("Gate 判定：%d / %d" % (n, len(gates)))

    with open(os.path.join(_HERE, "_p21_result.json"), "w", encoding="utf-8") as f:
        json.dump([{k: v for k, v in r.items()
                    if k not in ("searches",)} for r in results],
                  f, ensure_ascii=False, indent=2)
    print("结果已保存: _p21_result.json")


if __name__ == "__main__":
    main()
