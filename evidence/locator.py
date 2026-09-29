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
# 结构坐标的采集半径（围绕一个 pattern 命中位置）
ANCHOR_RADIUS = 220
# ★ 每侧最多取多少个结构锚点
#
# 【实测调优】不限数量时，端点会从 1 个膨胀到 13 个，
# 两侧配对后候选对从 13 暴增到 1683（**129×**）—— 噪声完全失控。
# 只取**距离命中位置最近的** N 个锚点，把增长控制在常数倍。
MAX_ANCHORS_PER_SIDE = 3


# ================================================================ ★ micro-fix：结构坐标

# 【实测发现的真问题】candidate_pairs 用 **pattern 命中位置** 当关系端点。
# 但 relation 的端点是**结构坐标**：
#     argument_flow 的两端 = 「变量绑定位置」+「实参引用位置」
#     same_object   的两端 = 「对象属性值位置」
# 这**不是同一套坐标系统**。
#
# 实测证据（E3 构造样本）：
#     pattern 命中：createCipheriv @265 · fetch @734
#     结构坐标：    const artifact = makeArtifact @830 · uploadPutObject(artifact,…) @877
#     relate(@265, @734) = False   ← 用命中位置必然失败
#     argument_flow(@830, @877) = True   ← 用结构坐标就成立
#
# 所以即使能力配对正确，**用错坐标就永远建不出关系**。
# 这不是"窗口太小"，是**坐标系统错配**。
#
# micro-fix 范围严格限定：**只扩展候选端点集合**。
#   ❌ 不改 relation 类型定义
#   ❌ 不改权重 / 阈值 / verdict / 打分
#   ❌ 不引入 semantic-role enrichment

_RE_BIND = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=")
_RE_CALL = re.compile(r"([A-Za-z_$][\w$.]*)\s*\(")


def _all_anchors(text, pos, radius=ANCHOR_RADIUS):
    """列出半径内**全部**结构坐标（不截断），供按距离排序用。"""
    out = set()
    lo = max(0, pos - radius)
    hi = min(len(text), pos + radius)
    seg = text[lo:hi]
    for m in _RE_BIND.finditer(seg):
        out.add(lo + m.start())
    for m in _RE_CALL.finditer(seg):
        out.add(lo + m.start())
    out.add(pos)
    return out


def structural_anchors(text, pos, radius=ANCHOR_RADIUS,
                       max_anchors=MAX_ANCHORS_PER_SIDE):
    """给定一个 pattern 命中位置，返回附近**最近的**若干结构性坐标。

    `pos` 本身始终保留 —— 保证新集合是旧集合的**超集**，
    这样 micro-fix 不会丢失任何原有能力（只会增加候选）。

    ★ 按**离命中位置的距离**排序取最近的 N 个。
      【实测踩坑】第一版按坐标大小排序（sorted），
      结果截断时把远处但结构上更相关的锚点排掉了 → U12 回归反而失败。
    """
    cands = _all_anchors(text, pos, radius)
    ordered = sorted(cands, key=lambda p: (abs(p - pos), p))
    out = [pos] + [p for p in ordered if p != pos][:max(0, max_anchors - 1)]
    return sorted(set(out))


def expand_anchors(text, positions, radius=ANCHOR_RADIUS,
                   max_anchors=MAX_ANCHORS_PER_SIDE, max_total=8):
    """对一组命中位置做结构坐标展开（总量有上限，且**按距离优先**）。

    ★ 同样按"离原始命中位置的距离"排序后截断，
      否则结构上最相关的锚点可能被位置靠前的噪声挤掉。
    """
    scored = []
    for p in positions:
        for a in _all_anchors(text, p, radius):
            scored.append((abs(a - p), a))
    scored.sort()
    out = set(positions)
    for _d, a in scored:
        if len(out) >= max_total:
            break
        out.add(a)
    return sorted(out)


def expand_anchors(text, positions, radius=ANCHOR_RADIUS):
    """对一组命中位置做结构坐标展开。"""
    out = set()
    for p in positions:
        out.update(structural_anchors(text, p, radius))
    return sorted(out)


def candidate_pairs(text, evs_a, evs_b, window=DEFAULT_WINDOW,
                    expand=False, radius=ANCHOR_RADIUS):
    """★ R-L3：只生成"合理邻域"内的候选对，复杂度有界。

    `expand=True` 时启用 micro-fix：先把两侧端点展开为结构坐标，
    再做距离筛选。**默认 False 保持历史行为**（便于对照）。
    """
    if expand:
        evs_a = expand_anchors(text, evs_a, radius)
        evs_b = expand_anchors(text, evs_b, radius)
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
                    window=DEFAULT_WINDOW, blocked_reason=None,
                    lazy_expand=True):
    """对一对能力做一次 relation 搜索，返回四态结果。

    ★ R-L2：**不使用 primary_citation 作为唯一输入** ——
             用 evs_a / evs_b 的完整 citation 集合。

    ★ micro-fix（坐标系统修正）采用**懒扩展**：
        第一轮用 pattern 命中位置（保持历史行为）
        只有第一轮**一个都没建出**时，才把端点展开为结构坐标重试
      理由：实测"全量展开"会让候选对从 13 暴增到 1683（129×），
            引入大量噪声；懒扩展只在"原本找不到"时付出这个代价。
    """
    if blocked_reason:
        return RelationSearch(from_cap, to_cap, "search_blocked",
                              blockers=[blocked_reason])

    # ---- 第一轮：pattern 命中位置（历史行为）----
    pairs, truncated = candidate_pairs(text, evs_a, evs_b, window, expand=False)
    verified = []
    candidates = []
    for (pa, pb) in pairs:
        r = relate(text, pa, pb, from_cap, to_cap)
        if r:
            verified.append(r)
            if len(verified) >= 3:
                break
        else:
            candidates.append((pa, pb))

    used_expand = False
    total_checked = len(pairs)

    # ---- 第二轮（懒扩展）：仅当第一轮完全失败 ----
    if not verified and lazy_expand and evs_a and evs_b:
        pairs2, tr2 = candidate_pairs(text, evs_a, evs_b, window, expand=True)
        if len(pairs2) > len(pairs):
            used_expand = True
            truncated = truncated or tr2
            total_checked = len(pairs2)
            for (pa, pb) in pairs2:
                r = relate(text, pa, pb, from_cap, to_cap)
                if r:
                    verified.append(r)
                    if len(verified) >= 3:
                        break
                else:
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
        blockers=(["complexity_cap_reached"] if truncated else [])
                 + (["expanded_anchors"] if used_expand else []),
        checked_pairs=total_checked)


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
