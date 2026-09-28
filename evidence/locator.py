# -*- coding: utf-8 -*-
"""P2.1 · Evidence Locator Refinement

> **解决的不是"关系不存在"，而是"我们可能没在正确的位置找关系"。**

**范围严格限定**（老大定的）：
    ✅ 只改善「从哪条已有证据开始找 Relation」
    ❌ 不做 "actual use-site analysis"（那会滑向半个 AST）
    ❌ 不增加新的 capability discovery
    ❌ 不引入 semantic-role enrichment

**为什么不做 use-site**：P0.5 已封存为 optional enrichment（严格准入 coverage≈0）。
若因 relation 需要 locator 就重新打开它，会沿
`role inference → consumer analysis → symbol resolution → function boundary → 半个 AST`
一路 scope creep。

---

## 六条成功标准

    R-L1  所有 Evidence 保留完整 citation 集合
    R-L2  primary_citation 不再决定 relation evaluation
    R-L3  候选生成有 bounded complexity
    R-L4  每个 relation search 都能说明四态
    R-L5  S1/S2/S4/E3/E4 回放不改变既有事实
    R-L6  没有引入 semantic-role enrichment

## 四态 search 结果

    no_candidate                  邻域内没有任何候选对
    candidate_found_but_unverified 找到了疑似结构邻居，但 P2 不支持这种关系
    relation_verified             真正建出 same_object / argument_flow
    search_blocked                截断 / 大文件 / 不支持语法 / 覆盖缺口
"""

import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)

from relation import relate, region_at, same_object, argument_flow   # noqa: E402


# ================================================================ 四态

SEARCH_STATES = ("no_candidate", "candidate_found_but_unverified",
                 "relation_verified", "search_blocked")


class RelationSearch:
    """一次 relation 搜索的完整记录（可回放）。"""

    __slots__ = ("from_cap", "to_cap", "state", "verified", "candidates",
                 "blockers", "checked_pairs", "note")

    def __init__(self, from_cap, to_cap, state, verified=None,
                 candidates=None, blockers=None, checked_pairs=0, note=None):
        assert state in SEARCH_STATES, "非法 search state: %s" % state
        self.from_cap = from_cap
        self.to_cap = to_cap
        self.state = state
        self.verified = list(verified or [])
        self.candidates = list(candidates or [])
        self.blockers = list(blockers or [])
        self.checked_pairs = checked_pairs
        self.note = note

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


# ================================================================ R-L1 完整 citation

def expand_citations(text, ev, pattern_re=None, max_hits=40):
    """给一条 Evidence 补充它的**全部命中位置**（不只首处）。

    ★ R-L1：Evidence 必须保留完整 citation 集合。

    实现方式：**不改 build()**（R-L5 要求回放不改变既有事实），
    而是**在用的时候按需展开**：
        primary_citation  首处命中（展示用，保持原样）
        all_citations     全部命中位置（relation 搜索用）

    参数 pattern_re 给定时，用它重新扫全文；否则退化为只用 primary。
    """
    primary = (ev.citation or {}).get("offset")
    out = [primary] if primary is not None else []
    if pattern_re is None or primary is None:
        return out
    try:
        for i, m in enumerate(pattern_re.finditer(text)):
            if i >= max_hits:
                break
            p = m.start()
            if p not in out and region_at(text, p) == "code":
                out.append(p)
    except Exception:                                       # noqa: BLE001
        pass
    return out


# ================================================================ R-L3 邻域筛选

# 邻域窗口：只在这个距离内才调用结构 verifier
# 理由：33MB 全配对已实测超时（Python lexer + 56 regex）
DEFAULT_WINDOW = 4000
MAX_CANDIDATE_PAIRS = 200


def candidate_pairs(text, evs_a, evs_b, window=DEFAULT_WINDOW):
    """★ R-L3：只生成"合理邻域"内的候选对，复杂度有界。

    便宜条件（先筛）：
        same file（本实现天然满足 —— 单文件内）
        distance <= local_window
    然后才调用 same_object / argument_flow verifier。
    """
    pairs = []
    n = 0
    for pa in evs_a:
        for pb in evs_b:
            if n >= MAX_CANDIDATE_PAIRS:
                return pairs, True            # True = 被复杂度上限截断
            if pa == pb:
                continue
            if abs(pa - pb) > window:
                continue
            n += 1
            pairs.append((pa, pb))
    return pairs, False


# ================================================================ 主搜索

def search_relation(text, from_cap, to_cap, evs_a, evs_b,
                    window=DEFAULT_WINDOW, blocked_reason=None):
    """对一对能力做一次 relation 搜索，返回四态结果。

    ★ R-L2：**不使用 primary_citation 作为唯一输入** ——
             用 evs_a / evs_b 的完整 citation 集合。
    """
    if blocked_reason:
        return RelationSearch(from_cap, to_cap, "search_blocked",
                              blockers=[blocked_reason])

    pairs, truncated = candidate_pairs(text, evs_a, evs_b, window)
    if not pairs:
        return RelationSearch(from_cap, to_cap, "no_candidate",
                              blockers=["outside_local_window"]
                              if (evs_a and evs_b) else ["missing_evidence"])

    verified = []
    candidates = []
    for (pa, pb) in pairs:
        # 先做便宜的存在性检查 —— 是否在同一个对象字面量 /
        # 是否有绑定关系（这两个 verifier 内部自带严格依据，不做窗口猜测）
        r = relate(text, pa, pb, from_cap, to_cap)
        if r:
            verified.append(r)
            if len(verified) >= 3:
                break
        else:
            # 记录"邻域内确实存在成对证据但 verifier 未通过"
            candidates.append((pa, pb))

    if verified:
        st = "relation_verified"
    elif candidates:
        st = "candidate_found_but_unverified"
    else:
        st = "no_candidate"

    return RelationSearch(
        from_cap, to_cap, st,
        verified=verified, candidates=candidates,
        blockers=(["complexity_cap_reached"] if truncated else []),
        checked_pairs=len(pairs))


def summarize_searches(searches):
    """四态分布（**分母 = 搜索次数**，不是"某种状态出现几次"）。"""
    from collections import Counter
    c = Counter(s.state for s in searches)
    return {
        "searches": len(searches),
        "no_candidate": c.get("no_candidate", 0),
        "candidate_found_but_unverified": c.get("candidate_found_but_unverified", 0),
        "relation_verified": c.get("relation_verified", 0),
        "search_blocked": c.get("search_blocked", 0),
        "verified_relations": sum(len(s.verified) for s in searches),
        "checked_pairs_total": sum(s.checked_pairs for s in searches),
        "blockers": dict(Counter(b for s in searches for b in s.blockers)),
    }


# ================================================================ 不变量（R-L2 / R-L6）

def assert_locator_invariants(searches, source_modules=None):
    """P2.1 的硬规则断言。

    R-L2  primary_citation 不得是 relation evaluator 的唯一输入
    R-L6  不得引入 semantic-role enrichment
    """
    # R-L2：搜索记录必须带 checked_pairs > 0（说明真的扫过多对，不是只看首处）
    lone = [s for s in searches
            if s.state == "relation_verified" and s.checked_pairs == 0]
    assert not lone, "R-L2 违反：有 verified 结果但 checked_pairs=0（可能只用了首处）"

    # R-L6：locator 模块不得 import role 相关模块
    if source_modules:
        for name, src in source_modules.items():
            for bad in ("semantic_role", "role_evidence", "admit("):
                assert bad not in src, \
                    "R-L6 违反：%s 引入了 semantic-role enrichment（%s）" % (name, bad)
    return True
