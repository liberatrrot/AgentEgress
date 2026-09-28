# -*- coding: utf-8 -*-
"""Phase 2 · Evidence Model —— 数据结构与不变量

**本模块不修改 agentegress 的任何检测逻辑。**
它只定义新的证据表示，并由 adapter 把旧 detector 的输出接进来。

对应规范：PHASE-2-SCHEMA-FREEZE.md
五条不变量（I1–I5）见下，每条都在代码里有对应的断言点。
"""


# ================================================================ 枚举

SPECIFICITY = ("high", "medium", "low")

POLARITY = ("supporting", "contradicting", "neutral", "unknown")

PROVENANCE_KIND = ("application", "bundled_dependency", "external_dependency",
                   "generated", "test", "documentation", "unknown")

# I1: unknown 不是 negative —— 这里的关键是 observed_* 与 absent 分开
COVERAGE = ("observed", "not_observed", "observed_insufficient",
            "observed_supportive", "confirmed_capability",
            "unknown_due_to_coverage")

CONFIDENCE = ("high", "medium", "low")

# Q5: 顶层 Verdict 四态
VERDICT = ("supported", "contradicted", "insufficient", "blocked_by_coverage")

RELATION_TYPE = ("same_object", "argument_flow", "same_call_chain",
                 "return_value", "property_flow", "import_relation")

CHAIN_CONFIDENCE = ("strong", "moderate", "weak", "insufficient")


# ================================================================ Observation

class Observation:
    """扫描器看到的最原始事实。不判断任何语义。"""

    __slots__ = ("id", "file", "offset", "line", "text", "pattern_id",
                 "region", "file_class", "source_kind")

    def __init__(self, id, file, offset, text, pattern_id,
                 region="code", file_class="production",
                 line=None, source_kind="lexical"):
        self.id = id
        self.file = file
        self.offset = offset
        self.line = line
        self.text = text
        self.pattern_id = pattern_id
        self.region = region
        self.file_class = file_class
        self.source_kind = source_kind

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


# ================================================================ Evidence

class Provenance:
    __slots__ = ("kind", "package", "version", "confidence")

    def __init__(self, kind="unknown", package=None, version=None,
                 confidence="low"):
        assert kind in PROVENANCE_KIND, "非法 provenance.kind: %s" % kind
        self.kind = kind
        self.package = package
        self.version = version
        self.confidence = confidence

    def to_dict(self):
        return {k: getattr(self, k) for k in self.__slots__}


class Evidence:
    """对 Observation 的解释。**不产生风险等级。**

    I3 落实点：
        semantic_role 与 role_evidence 都是**可选**（默认 None）。
        schema 不允许暗示"每条 evidence 应该有 role"。
    """

    __slots__ = ("id", "observations", "capability_candidate", "specificity",
                 "polarity", "semantic_role", "role_evidence", "provenance",
                 "coverage", "citation")

    def __init__(self, id, observations, capability_candidate,
                 specificity="low", polarity="unknown",
                 semantic_role=None,            # ← 可选（I3）
                 role_evidence=None,            # ← 可选（I3）
                 provenance=None, coverage="observed", citation=None):
        assert specificity in SPECIFICITY, "非法 specificity"
        assert polarity in POLARITY, "非法 polarity"
        assert coverage in COVERAGE, "非法 coverage"
        assert isinstance(observations, (list, tuple))
        self.id = id
        self.observations = list(observations)
        self.capability_candidate = capability_candidate
        self.specificity = specificity
        self.polarity = polarity
        self.semantic_role = semantic_role
        self.role_evidence = role_evidence
        self.provenance = provenance or Provenance()
        self.coverage = coverage
        self.citation = citation

    def to_dict(self):
        d = {k: getattr(self, k) for k in self.__slots__}
        d["provenance"] = self.provenance.to_dict()
        return d


# ================================================================ Assessment

class Assessment:
    """评分层。**旧的 norm 属于这里，不再是 Evidence 的属性。**

    三个独立维度必须分开（S2 证明）：
        impact / confidence / business_context
    """

    __slots__ = ("capability", "coverage", "supporting", "contradicting",
                 "confidence", "impact", "business_context", "reasons")

    def __init__(self, capability, coverage="not_observed",
                 supporting=None, contradicting=None,
                 confidence="low", impact="unknown",
                 business_context="unknown", reasons=None):
        assert coverage in COVERAGE, "非法 coverage"
        self.capability = capability
        self.coverage = coverage
        self.supporting = list(supporting or [])
        self.contradicting = list(contradicting or [])
        self.confidence = confidence
        self.impact = impact
        self.business_context = business_context
        self.reasons = list(reasons or [])

    # ---- I1 的断言点 ----
    @property
    def evidence_state(self):
        """把 coverage + 证据情况映射成状态。**绝不把 unknown 折成 absent。**

        I1: unknown 不是 negative
            没有证据 → not_observed（不是"无能力"）
            有证据但弱 → observed_insufficient（不是 absent）
            有证据且够 → observed_supportive / confirmed_capability
        """
        # 有明确反证 → 仍不叫 absent，而是给出 contradicting 计数
        if self.coverage == "unknown_due_to_coverage":
            return "blocked_by_coverage"
        if self.coverage == "not_observed" and not self.supporting:
            return "not_observed"
        if self.contradicting and not self.supporting:
            return "contradicted"
        if self.supporting and self.coverage in ("observed_supportive",
                                                 "confirmed_capability"):
            return "supported" if self.coverage == "confirmed_capability" \
                else "observed_supportive"
        if self.supporting:
            return "observed_insufficient"
        return self.coverage
