# -*- coding: utf-8 -*-
"""Phase 2 · 状态代数（G2 的规范件）

**目的**：在 P4 之前，把散落在四层的状态显式化并证明其可机械区分。

没有这张表，P4 一定会重新制造"拍脑袋"。

**四层状态**（规范）：
    Observation state   扫描器看到什么
    Evidence state      单个证据的覆盖情况
    Assessment state    单个能力的状态（由 Evidence 聚合）
    Verdict state       顶层结论
    Chain state         链的结论
"""

# ================================================================ 层归属（G2）

STATE_LAYERS = {
    "observation": [
        # 这些是**计数口径**，不是判定状态
        "candidates",
        "read",              # 真的读到了字节
        "prefilter_rejected",  # 读到但没跑正则
        "skipped_vendor",
        "skipped_ext",
        "skipped_other",
        "skipped_large",
        "read_errors",
        "truncated",
    ],
    "evidence": [
        # 单个 Evidence 的覆盖情况（schema.COVERAGE）
        "observed",
        "not_observed",
        "unknown_due_to_coverage",
    ],
    "assessment": [
        # 单个能力的状态（assess.Assessment.evidence_state）
        "not_observed",
        "observed_insufficient",
        "observed_supportive",
        "confirmed_capability",
        "contradicted",
        "blocked_by_coverage",
    ],
    "verdict": [
        # 顶层（assess.synthesize）
        "supported",
        "contradicted",
        "insufficient",
        "blocked_by_coverage",
    ],
    "chain": [
        # 链（chain.CHAIN_STATE）
        "supported",
        "insufficient",
        "contradicted",
        "blocked_by_coverage",
    ],
}

# ================================================================ 四态机械区分（G2 核心）

# 老大要求：这四个状态必须能**机械地区分**，否则 P4 不该开始。
#
# 区分依据只用三个布尔量：
#     has_contradicting   是否存在明确反向证据
#     has_supporting      是否存在支持性证据
#     coverage_gap        是否存在技术性覆盖缺口

STATE_DISCRIMINATION = [
    # (状态,            has_contradicting, has_supporting, coverage_gap, 含义)
    ("blocked_by_coverage", False, None, True,
     "没有机会充分观察（技术性缺口）"),
    ("contradicted",        True,  None, False,
     "存在明确反向证据"),
    ("not_observed",        False, False, False,
     "没有观察到"),
    ("insufficient",        False, True,  False,
     "有支持性证据，但不足以达到更高结论"),
]


def discriminate(has_contradicting, has_supporting, coverage_gap):
    """给定三个布尔量，返回唯一的状态。

    **机械可区分** = 任意输入组合都能唯一映射，且无歧义。
    这是 G2 的核心断言对象。
    """
    if coverage_gap:
        return "blocked_by_coverage"
    if has_contradicting:
        return "contradicted"
    if has_supporting:
        return "insufficient"
    return "not_observed"


def assert_discrimination_total():
    """穷尽 2^3 输入组合，确认每个组合都有唯一状态，且四态都被覆盖。

    **这也检查"互斥且穷尽"**：
      · 穷尽   —— 8 种组合都有输出
      · 互斥   —— 每种组合只映射一个状态
      · 覆盖   —— 四个被要求的状态都能被触达
    """
    seen = {}
    for hc in (False, True):
        for hs in (False, True):
            for cg in (False, True):
                st = discriminate(hc, hs, cg)
                seen[(hc, hs, cg)] = st
                assert st in ("blocked_by_coverage", "contradicted",
                              "not_observed", "insufficient"), \
                    "G2 违反：(%s,%s,%s) 映射出未知状态 %s" % (hc, hs, cg, st)
    reached = set(seen.values())
    missing = {"blocked_by_coverage", "contradicted",
               "not_observed", "insufficient"} - reached
    assert not missing, "G2 违反：以下状态不可达 %s" % missing
    return seen


# ================================================================ 禁止的状态对（G2 附加）

# 明确**不允许合并**的状态对 —— 合并它们就是"把不同的事实混为一谈"
FORBIDDEN_COLLAPSES = [
    ("not_observed", "insufficient",
     "「没看到」≠「看到了但不够」"),
    ("not_observed", "contradicted",
     "「没看到」≠「看到了反证」"),
    ("insufficient", "contradicted",
     "「证据不够」≠「存在反证」"),
    ("blocked_by_coverage", "not_observed",
     "「没机会看」≠「没看到」"),
    ("unknown", "not_observed",
     "「判不了」≠「没看到」"),
    ("unknown", "negative",
     "「判不了」≠「不存在」（I1/I6 的根源）"),
]
