# -*- coding: utf-8 -*-
"""Phase 2 · P3 Chain（Schema + 不变量）

> **Out of scope（明确写在顶部，防 scope creep）**：
> B1 / B2 / B3 —— 即 discovery / normalization / calibration 这类
> **单能力 evidence → assessment** 的失败。
> P3 只解决「多个已存在的 Evidence 如何形成结构性链」，
> **不解决 non-canonical discovery / weak normalization / low-specificity calibration。**
> 所以 P3 不会让 S4 的三个 B 类消失。

**七条硬规则**（本模块用断言强制前六条，第七条是 scope 声明）：

    1. 不消费 possible / likely / confirmed
    2. 没有 admitted relation → 不得成为 supported chain
    3. confidence 必须由显式 reason-pattern 导出（不是计数）
    4. 不允许连续 score / 隐式 threshold
    5. ★ no candidate ≠ chain absent   （not evaluated ≠ negative）
    6. missing_relation 必须区分三子类
    7. P3 不解决 B1/B2/B3
"""


# ================================================================ 枚举

# chain 状态（与 P1 的 verdict 四态对齐）
CHAIN_STATE = ("supported", "insufficient", "contradicted", "blocked_by_coverage")

# chain 强度 —— 只是 reason-pattern 的**命名**，不是分数
CHAIN_CONFIDENCE = ("strong", "moderate", "weak", "unknown")

# chain 作用范围（防止 same_call_chain 被误解成完整 data-flow）
CHAIN_SCOPE = ("local", "intra_function", "inter_function", "inter_file")

# ★ blocker taxonomy（七类，missing_relation 拆三子类）
BLOCKERS = (
    "missing_source_evidence",
    "missing_sink_evidence",
    "missing_relation_structurally_expected",   # 有结构，只是类型没实现 → 支持加 relation type
    "missing_relation_no_structure",            # 本来就没结构 → 不支持加
    "relation_unknown_due_to_analysis",         # coverage / 语法 / 歧义导致判不了
    "coverage_blocked",
    "contradicting_evidence",
)

# ★ 明确不使用 missing_capability_evidence
#    理由：它会把三个阶段重新混在一起。
#    Evidence 有没有 / Relation 有没有 / Coverage 有没有阻断 —— 这才是 P3 关心的。
#    Capability mapping 是 P1 的事。
FORBIDDEN_BLOCKER_NAMES = ("missing_capability_evidence",)


# ================================================================ ChainCandidate

class ChainCandidate:
    """一条**待评估的链假设**。

    ★ 硬规则 5 的载体：没有 candidate 就不评估，
    因此不会产出 `absent` —— 因为那会被读成"评估过且不存在"。

    `applicable=False` 表示"这个样本不适用这条链"
    （例如纯本地工具样本里根本没有 sink），
    此时应报 `not_applicable`，而不是 `absent`。
    """

    __slots__ = ("chain_type", "required_evidence", "required_relations",
                 "optional_relations", "scope", "applicable",
                 "structural_expectation", "note")

    def __init__(self, chain_type, required_evidence,
                 required_relations=(), optional_relations=(),
                 scope="intra_function", applicable=True,
                 structural_expectation="unknown", note=None):
        self.chain_type = chain_type
        self.required_evidence = list(required_evidence)
        self.required_relations = list(required_relations)
        self.optional_relations = list(optional_relations)
        assert scope in CHAIN_SCOPE, "非法 scope: %s" % scope
        self.scope = scope
        self.applicable = applicable
        # ★ 三个子类的判据必须由**调用方显式声明**，不能由实现猜测。
        #
        #   "expected"  已知代码里存在结构（人工确认过）→ 找不到就报 structurally_expected
        #   "none"      本来就没有结构                    → 报 no_structure
        #   "unknown"   无法自动判定（默认）              → 报 relation_unknown_due_to_analysis
        #
        # 【实测教训】第一版实现里，只要 candidate 声明了 required_relations
        # 就一律归到 structurally_expected —— 结果在完整文件上得到 8/8 的
        # "relation 类型不足" 结论。**那是启发式的产物，不是实测。**
        assert structural_expectation in ("expected", "none", "unknown"), \
            "非法 structural_expectation: %s" % structural_expectation
        self.structural_expectation = structural_expectation
        self.note = note

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


# ================================================================ ChainAssessment

class ChainAssessment:
    """一条候选链的评估结果。

    注意 `state` 与 `confidence` 是**两个维度**：
        state      由 blockers / 反证决定（能不能成立）
        confidence 由 reason-pattern 决定（成立得多扎实）
    """

    __slots__ = ("chain_type", "scope", "state", "confidence",
                 "reasons", "blockers", "evidence_refs", "relation_refs",
                 "coverage_state", "evaluated")

    def __init__(self, chain_type, scope, state, confidence,
                 reasons, blockers, evidence_refs, relation_refs,
                 coverage_state="ok", evaluated=True):
        assert state in CHAIN_STATE, "非法 state: %s" % state
        assert confidence in CHAIN_CONFIDENCE, "非法 confidence: %s" % confidence
        for b in blockers:
            assert b in BLOCKERS, "非法 blocker: %s" % b
            assert b not in FORBIDDEN_BLOCKER_NAMES, \
                "禁用 blocker 名：%s（会把 Evidence/Relation/Capability 三阶段混在一起）" % b
        assert isinstance(reasons, (list, tuple))
        self.chain_type = chain_type
        self.scope = scope
        self.state = state
        self.confidence = confidence
        self.reasons = list(reasons)
        self.blockers = list(blockers)
        self.evidence_refs = list(evidence_refs)
        self.relation_refs = list(relation_refs)
        self.coverage_state = coverage_state
        self.evaluated = evaluated

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


def not_applicable(cand):
    """★ 硬规则 5 的产物：没评估就是没评估，不是 absent。

    `not_applicable` 与 `insufficient` 的区别：
        not_applicable  这个样本不适用这条链（不评估）
        insufficient    评估了，但证据/关系不足
    """
    return ChainAssessment(
        chain_type=cand.chain_type, scope=cand.scope,
        state="insufficient", confidence="unknown",
        reasons=["candidate_not_applicable"],
        blockers=[],
        evidence_refs=[], relation_refs=[],
        coverage_state="ok", evaluated=False)


# ================================================================ ★ 硬规则 3

# confidence 是 **reason-pattern 的命名**，不是"理由数量 → 等级"。
# 下面每一条都是**谓词**，实现必须按其判定，不允许用 len() 计数。

CONFIDENCE_PREDICATES = {
    # 三个必需环节 + ≥1 条 admitted relation + 无反证
    "strong": {
        "desc": "source + sink evidence 齐全，且有 admitted structural relation，无反证",
        "requires": ["has_source", "has_sink", "has_admitted_relation"],
        "excludes": ["has_contradiction", "coverage_blocked"],
    },
    # 环节齐全 + 有 relation 但 relation 只是 optional 级（结构支持较弱）
    "moderate": {
        "desc": "source + sink evidence 齐全，relation 存在但非必需级支持，无反证",
        "requires": ["has_source", "has_sink", "has_any_relation"],
        "excludes": ["has_contradiction", "coverage_blocked"],
    },
    # 环节不全，或关系缺失
    "weak": {
        "desc": "证据或关系不完整（但可评估）",
        "requires": [],
        "excludes": ["coverage_blocked"],
    },
    # 无法评估
    "unknown": {
        "desc": "覆盖阻断 / 不适用 / 无法评估",
        "requires": [],
        "excludes": [],
    },
}


def derive_confidence(state, has_source, has_sink,
                      has_admitted_relation, has_any_relation,
                      has_contradiction, coverage_blocked):
    """★ 由 reason-pattern 推导 confidence（硬规则 3）。

    **绝对不用 len(reasons) 之类计数。**
    返回 (confidence, 触发的谓词名)。
    """
    if coverage_blocked:
        return "unknown", "coverage_blocked"
    if has_contradiction:
        return "weak", "has_contradiction"
    if has_source and has_sink and has_admitted_relation:
        return "strong", "source+sink+admitted_relation"
    if has_source and has_sink and has_any_relation:
        return "moderate", "source+sink+any_relation"
    return "weak", "incomplete_evidence_or_relation"


# ================================================================ 不变量断言

def assert_chain_invariants(assessments, candidates):
    """P3 硬规则的运行时断言。

    规则 1 / 2 / 3 / 4 / 5 / 6 在这里强制。
    """
    cand_types = {c.chain_type for c in candidates}

    for a in assessments:
        # 规则 5：评估结果必须对应一个真实存在的 candidate
        assert a.chain_type in cand_types, \
            "规则 5 违反：%s 没有对应的 ChainCandidate（no candidate → no evaluation）" \
            % a.chain_type

        # 规则 2：没有 admitted relation → 不得是 supported
        if a.state == "supported":
            assert a.relation_refs, \
                "规则 2 违反：%s 成为 supported 但没有 relation_refs" % a.chain_type
            assert "missing_relation_structurally_expected" not in a.blockers, \
                "规则 2 违反：%s 缺 relation 却仍 supported" % a.chain_type
            assert "missing_relation_no_structure" not in a.blockers, \
                "规则 2 违反：%s 缺 relation 却仍 supported" % a.chain_type

        # 规则 3：confidence 必须是枚举，且 supported 不得是 weak
        assert a.confidence in CHAIN_CONFIDENCE, \
            "规则 3 违反：%s confidence=%s 非枚举" % (a.chain_type, a.confidence)
        if a.state == "supported":
            assert a.confidence in ("strong", "moderate"), \
                "规则 3 违反：%s 是 supported 但 confidence=%s" \
                % (a.chain_type, a.confidence)

        # 规则 4：禁止任何连续分数痕迹
        for k in ("score", "confidence_score", "norm", "probability"):
            assert not hasattr(a, k), \
                "规则 4 违反：%s 出现连续分数字段 %s" % (a.chain_type, k)

        # 规则 6：missing_relation 必须用三子类，不能用总类
        for b in a.blockers:
            assert b != "missing_relation", \
                "规则 6 违反：%s 使用了总类 missing_relation（必须分子类）" \
                % a.chain_type

        # 非 supported 必须有 blocker 或 reason 解释
        if a.state != "supported" and a.evaluated:
            assert a.blockers or a.reasons, \
                "%s 非 supported 但没有任何 blocker / reason" % a.chain_type

    return True
