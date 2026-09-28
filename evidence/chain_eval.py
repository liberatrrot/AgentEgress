# -*- coding: utf-8 -*-
"""Phase 2 · P3 Chain Evaluator

**输入**：chain_candidates + Evidence + Relations + Coverage
**输出**：ChainAssessment（state + confidence + reasons + blockers）

**不做**：
    · 不消费 possible / likely / confirmed（硬规则 1）
    · 不自己去找 Relation（关系由调用方传入 —— 保持分层）
    · 不用任何连续分数或隐式阈值（硬规则 4）
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from chain import (ChainCandidate, ChainAssessment, not_applicable,   # noqa: E402
                   derive_confidence)


def _capability_ids_with_evidence(evidence_by_cap):
    return {k for k, v in evidence_by_cap.items() if v}


def _relation_types(relations, admitted_only=True):
    out = set()
    for r in relations:
        if admitted_only and not r.get("structural_basis"):
            continue
        out.add(r.get("type"))
    return out


def evaluate(candidate, evidence_by_cap, relations,
             coverage_info=None, contradicting_caps=None):
    """评估一条候选链。

    **硬规则 2**：没有 admitted relation → 不可能是 supported。
    **硬规则 5**：candidate.applicable=False → 返回 not_applicable（不评估）。
    """
    coverage_info = coverage_info or {}
    contradicting_caps = set(contradicting_caps or [])

    # ---- 硬规则 5：没评估就是没评估 ----
    if not candidate.applicable:
        return not_applicable(candidate)

    with_ev = _capability_ids_with_evidence(evidence_by_cap)
    rel_types = _relation_types(relations, admitted_only=True)
    all_rel_types = _relation_types(relations, admitted_only=False)

    req = candidate.required_evidence
    if len(req) < 2:
        return not_applicable(candidate)
    source_cap, sink_cap = req[0], req[-1]
    middle_caps = req[1:-1]

    has_source = source_cap in with_ev
    has_sink = sink_cap in with_ev
    missing_middle = [c for c in middle_caps if c not in with_ev]

    has_admitted_relation = bool(rel_types & set(candidate.required_relations))
    has_any_relation = bool(all_rel_types & (
        set(candidate.required_relations) | set(candidate.optional_relations)))

    coverage_blocked = bool(
        coverage_info.get("technical_gap_for", {}).get(source_cap)
        or coverage_info.get("technical_gap_for", {}).get(sink_cap))
    cov_state = "blocked" if coverage_blocked else "ok"

    has_contradiction = bool(
        (contradicting_caps & set(req)) or
        any(e.get("polarity") == "contradicting"
            for v in evidence_by_cap.values() for e in v
            if getattr(e, "polarity", None) == "contradicting"))

    # ---- blockers（七类 taxonomy）----
    blockers = []
    reasons = []

    if not has_source:
        blockers.append("missing_source_evidence")
        reasons.append("source_evidence_absent:%s" % source_cap)
    else:
        reasons.append("source_evidence_present:%s" % source_cap)

    if not has_sink:
        blockers.append("missing_sink_evidence")
        reasons.append("sink_evidence_absent:%s" % sink_cap)
    else:
        reasons.append("sink_evidence_present:%s" % sink_cap)

    for c in missing_middle:
        reasons.append("middle_evidence_absent:%s" % c)

    # ★ 硬规则 6：missing_relation 必须分子类
    #
    # 【实测教训】第一版的判据是「candidate 声明了 required_relations
    # 就归 structurally_expected」—— 那只是**候选的声明**，
    # 并没有验证代码里到底有没有结构。
    # 结果在完整文件上得到 8/8 的"relation 类型不足"结论，
    # **那是启发式的产物，不是实测**。
    # 现在改为由调用方显式声明 structural_expectation。
    if not has_admitted_relation:
        exp = getattr(candidate, "structural_expectation", "unknown")
        if coverage_blocked:
            blockers.append("relation_unknown_due_to_analysis")
            reasons.append("relation_undecidable:coverage")
        elif exp == "expected":
            blockers.append("missing_relation_structurally_expected")
            reasons.append("relation_expected_but_absent:%s"
                           % ",".join(candidate.required_relations))
        elif exp == "none":
            blockers.append("missing_relation_no_structure")
            reasons.append("no_structural_relation_expected")
        else:
            blockers.append("relation_unknown_due_to_analysis")
            reasons.append("relation_undecidable:structural_expectation_not_determined")

    if coverage_blocked:
        blockers.append("coverage_blocked")
    if has_contradiction:
        blockers.append("contradicting_evidence")
        reasons.append("contradicting_evidence_present")

    if has_admitted_relation:
        reasons.append("admitted_relation:%s"
                       % ",".join(sorted(rel_types & set(candidate.required_relations))))
    elif has_any_relation:
        reasons.append("weak_relation:%s" % ",".join(sorted(all_rel_types)))

    # ---- state（硬规则 2：无 relation 不得 supported）----
    if coverage_blocked:
        state = "blocked_by_coverage"
    elif has_contradiction:
        state = "contradicted"
    elif (has_source and has_sink and has_admitted_relation
          and not missing_middle):
        state = "supported"
    else:
        state = "insufficient"

    # 硬规则 2 的双保险
    if state == "supported" and not has_admitted_relation:
        state = "insufficient"

    conf, _why = derive_confidence(
        state=state, has_source=has_source, has_sink=has_sink,
        has_admitted_relation=has_admitted_relation,
        has_any_relation=has_any_relation,
        has_contradiction=has_contradiction,
        coverage_blocked=coverage_blocked)

    return ChainAssessment(
        chain_type=candidate.chain_type,
        scope=candidate.scope,
        state=state,
        confidence=conf,
        reasons=reasons,
        blockers=blockers,
        evidence_refs=[c for c in req if c in with_ev],
        relation_refs=[r.get("type") for r in relations
                       if r.get("structural_basis")
                       and r.get("type") in candidate.required_relations],
        coverage_state=cov_state,
    )


def evaluate_all(candidates, evidence_by_cap, relations,
                 coverage_info=None, contradicting_caps=None):
    return [evaluate(c, evidence_by_cap, relations,
                     coverage_info, contradicting_caps)
            for c in candidates]


def blocker_distribution(assessments):
    """统计 blocker 分布。

    **分母是"已评估的候选链数"** —— 没有 candidate 就不进统计。
    否则会出现"某种 blocker 出现 3 次"这种没有分母的数字。
    """
    from collections import Counter
    evaluated = [a for a in assessments if a.evaluated]
    dist = Counter()
    for a in evaluated:
        for b in a.blockers:
            dist[b] += 1
    return {
        "candidate_count": len(assessments),
        "evaluated_count": len(evaluated),
        "not_applicable_count": len(assessments) - len(evaluated),
        "blocker_counts": dict(dist),
    }
