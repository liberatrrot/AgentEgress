# -*- coding: utf-8 -*-
"""Phase 2 · Assessment 与 Verdict

落实 I1 与 I2：
    I1  unknown 永远不能自动变成 negative
    I2  unknown 也永远不等于 safe —— Verdict 必须携带 unresolved 集合
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from schema import Assessment, VERDICT           # noqa: E402


# ---------------------------------------------------------------- 能力清单

# 从旧 detector 读（不改它）
def _all_capabilities():
    import agentegress as ae
    return [(c["id"], c.get("name", c["id"]), c.get("risk", "medium"))
            for c in ae._COMPILED_CAPS]


# ---------------------------------------------------------------- Assessment

def assess(evidence_by_cap, coverage_info=None, roles=None):
    """把 Evidence 聚合成 Assessment。

    **I5 的落实**：不引入隐藏的连续分数阈值。
    每个档位都必须能回溯到一组**具名 reasons**；`reasons` 与档位一一对应。

    **I1 的落实**：无证据 → not_observed；证据弱 → observed_insufficient。
    绝不把这两者折成 "absent" 或任何会被读成 negative 的状态。
    """
    coverage_info = coverage_info or {}
    out = []
    for cap_id, cap_name, cap_risk in _all_capabilities():
        evs = evidence_by_cap.get(cap_id, [])
        supporting = [e.id for e in evs if e.polarity in ("supporting", "unknown")]
        contradicting = [e.id for e in evs if e.polarity == "contradicting"]

        # ---- 只用 Evidence 自身信息，不引入任何新分数 ----
        n_high = sum(1 for e in evs if e.specificity == "high")
        n_med = sum(1 for e in evs if e.specificity == "medium")
        n_obs = len({e.citation.get("offset") for e in evs if e.citation})

        # ---- ★ I5：档位由**具名 reasons** 决定，可回溯 ----
        reasons = []
        if contradicting and not supporting:
            reasons.append("contradicting_evidence_only")
        if n_high:
            reasons.append("high_specificity_evidence")
        if n_med:
            reasons.append("medium_specificity_evidence")
        if n_obs >= 2:
            reasons.append("multiple_observations")
        if not evs:
            reasons.append("no_observation")
        elif not (n_high or n_med):
            # 【实测踩坑】缺这条时，observed_insufficient 会没有理由，
            # 被 I5 断言抓住 —— 断言起作用了。
            reasons.append("low_specificity_evidence_only")

        if "contradicting_evidence_only" in reasons:
            cov, conf = "observed", "medium"
        elif not evs:
            cov, conf = "not_observed", "low"
        elif "high_specificity_evidence" in reasons and "multiple_observations" in reasons:
            cov, conf = "confirmed_capability", "high"
        elif ("high_specificity_evidence" in reasons
              or "medium_specificity_evidence" in reasons):
            cov, conf = "observed_supportive", "medium"
        else:
            # ★ I1：有证据但不足以定级 —— 绝不写 absent
            cov, conf = "observed_insufficient", "low"

        # ---- 覆盖缺口（S3 的教训：技术性缺口必须单独成态）----
        if coverage_info.get("technical_gap_for", {}).get(cap_id):
            cov = "unknown_due_to_coverage"
            conf = "low"
            reasons = ["technical_coverage_gap"]

        out.append(Assessment(
            capability=cap_id,
            coverage=cov,
            supporting=supporting,
            contradicting=contradicting,
            confidence=conf,
            impact=cap_risk,
            business_context="unknown",
            reasons=reasons,          # ← 可回溯（I5）
        ))
    return out


# ---------------------------------------------------------------- Verdict

def synthesize(assessments, coverage_info=None):
    """顶层合成。

    **I2 的落实**：
      · unresolved 集合是**必填输出**，不是可选
      · 顶层绝不允许只给一个词
      · unknown / insufficient / blocked 必须与 not_observed 区分
    """
    coverage_info = coverage_info or {}

    supported, contradicted, insufficient = [], [], []
    blocked, not_observed = [], []
    unresolved = []            # ★ I2：未决项集合，必有

    for a in assessments:
        st = a.evidence_state
        if st == "contradicted":
            contradicted.append(a.capability)
            unresolved.append(a.capability)
        elif st == "blocked_by_coverage":
            blocked.append(a.capability)
            unresolved.append(a.capability)
        elif st in ("supported", "observed_supportive"):
            supported.append(a.capability)
        elif st == "observed_insufficient":
            insufficient.append(a.capability)
            unresolved.append(a.capability)      # ★ 证据不足也是"未决"
        elif st == "not_observed":
            not_observed.append(a.capability)

    # ---- 顶层状态 ----
    if contradicted:
        top = "contradicted"
    elif blocked:
        top = "blocked_by_coverage"
    elif supported:
        top = "supported"
    elif insufficient:
        top = "insufficient"
    else:
        top = "insufficient"      # 什么都没观察到，也是"证据不足"，不是"安全"

    assert top in VERDICT, "非法 verdict"

    return {
        "verdict": top,
        # ★ I2：以下三项是**必有**输出，缺一不可
        "unresolved": unresolved,
        "unresolved_count": len(unresolved),
        "coverage": {
            "technical_gap": coverage_info.get("technical_gap", 0),
            "largest_unseen_unit": coverage_info.get("largest_unseen_unit"),
            "state": ("blocked" if blocked else "ok"),
        },
        # 明细
        "supported": supported,
        "contradicted": contradicted,
        "insufficient_evidence": insufficient,
        "blocked_by_coverage": blocked,
        "not_observed": not_observed,
        "reasons": ["顶层状态由 %d 项 supported / %d contradicted / "
                    "%d insufficient / %d blocked / %d not_observed 合成"
                    % (len(supported), len(contradicted), len(insufficient),
                       len(blocked), len(not_observed))],
    }


# ---------------------------------------------------------------- 不变量断言

def assert_invariants(assessments, verdict):
    """I1 / I2 / I3 / I5 的运行时断言。任何一条违反 → 抛异常。

    这是"不变量落实到实现"的检查点，对应 PHASE-2-SCHEMA-FREEZE.md 第五部分。
    """
    # I1：不存在被折成 negative 的状态
    for a in assessments:
        st = a.evidence_state
        assert st != "absent", \
            "I1 违反：%s 被折成 absent" % a.capability
        # 有证据却报 not_observed，说明折叠发生了
        if a.supporting:
            assert st != "not_observed", \
                "I1 违反：%s 有证据却报 not_observed" % a.capability

    # I2：未决项集合必须存在且与实际一致
    assert "unresolved" in verdict, "I2 违反：缺少 unresolved 集合"
    assert "unresolved_count" in verdict, "I2 违反：缺少 unresolved_count"
    assert verdict["unresolved_count"] == len(verdict["unresolved"]), \
        "I2 违反：unresolved_count 与实际不符"

    # I2：unknown / insufficient / blocked / contradicted 必须进入 unresolved
    for a in assessments:
        st = a.evidence_state
        if st in ("observed_insufficient", "blocked_by_coverage", "contradicted"):
            assert a.capability in verdict["unresolved"], \
                "I2 违反：%s（%s）未进入 unresolved" % (a.capability, st)

    # I3：semantic_role 允许为 None —— schema 层已保证
    #     （Evidence.semantic_role 默认 None；此处不做强制）

    # ★ I5：档位必须能回溯到具名 reasons
    #     禁止出现"无理由的高档位" —— 那就是隐藏的连续阈值
    STRENGTH_REASONS = ("high_specificity_evidence",
                        "medium_specificity_evidence")
    for a in assessments:
        if a.coverage in ("confirmed_capability", "observed_supportive"):
            assert any(r in STRENGTH_REASONS for r in a.reasons), \
                "I5 违反：%s 档位=%s 但无 strength reason（说明存在隐藏阈值）" \
                % (a.capability, a.coverage)
        if a.coverage == "observed_insufficient":
            assert not any(r in STRENGTH_REASONS for r in a.reasons), \
                "I5 违反：%s 有 strength reason 却落到 insufficient（档位与理由不符）" \
                % a.capability
        # reasons 不得为空（除 not_observed 外）
        if a.coverage != "not_observed":
            assert a.reasons, "I5 违反：%s 的档位 %s 没有列出任何理由" \
                % (a.capability, a.coverage)

    return True
