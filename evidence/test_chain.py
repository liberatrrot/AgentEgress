# -*- coding: utf-8 -*-
"""P3 Chain 验收：8 个最小案例

**验收判据不是「8/8 都成功形成 Chain」**，而是：

    8/8 都得到正确、可解释的 Chain 状态和 blocker

因为 P3 的目标不是"让更多东西形成链"，而是：
    正确知道什么时候应该形成、什么时候不应该形成、为什么不形成。
"""
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from chain import (ChainCandidate, assert_chain_invariants,   # noqa: E402
                   CHAIN_STATE, CHAIN_CONFIDENCE)
from chain_eval import evaluate, evaluate_all, blocker_distribution  # noqa: E402
from adapter import build                                     # noqa: E402
from relation import relate, region_at                        # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")


class FakeEv:
    """最小 Evidence 替身（evaluator 只用到 polarity）。"""
    def __init__(self, polarity="unknown"):
        self.polarity = polarity


def loc_code(text, needle):
    i = -1
    while True:
        i = text.find(needle, i + 1)
        if i < 0:
            return -1
        if region_at(text, i) == "code":
            return i


# ================================================================ 候选链模板

CAND_WS2OBJ = ChainCandidate(
    chain_type="workspace_to_object_storage",
    required_evidence=["workspace_snapshot", "envelope_encryption",
                       "object_storage_upload"],
    required_relations=["same_object"],
    scope="intra_function",
    # ★ 三个子类必须由调用方显式声明（实现不猜）
    #   本案例是「人工确认过这些环节在同一函数内、本该有 same_object」，
    #   所以声明为 expected → 找不到时报 missing_relation_structurally_expected
    structural_expectation="expected",
)

CAND_ENC2UP = ChainCandidate(
    chain_type="encryption_to_upload",
    required_evidence=["envelope_encryption", "object_storage_upload"],
    required_relations=["same_object", "argument_flow"],
    scope="intra_function",
    structural_expectation="expected",
)

CAND_NOT_APPLICABLE = ChainCandidate(
    chain_type="browser_state_to_upload",
    required_evidence=["browser_state_access", "object_storage_upload"],
    required_relations=["same_object"],
    applicable=False,          # ★ 硬规则 5
    note="该样本不适用",
)


# ================================================================ 8 个案例

def case_1():
    """P3-1 完整 evidence + same_object → supported / strong"""
    text = """
async function f(oss, t) {
  return { ok: true,
    objectUpload: {
      url: oss.host,
      maxBytes: t.encryptedArtifact.encryptedSizeBytes,
    }
  };
}
"""
    a = loc_code(text, "oss.host")
    b = loc_code(text, "t.encryptedArtifact.encryptedSizeBytes")
    rel = relate(text, a, b, "oss.host", "encryptedArtifact.encryptedSizeBytes")
    ev = {"workspace_snapshot": [FakeEv()], "envelope_encryption": [FakeEv()],
          "object_storage_upload": [FakeEv()]}
    return CAND_WS2OBJ, ev, [rel] if rel else []


def case_2():
    """P3-2 完整 evidence + argument_flow → supported / strong"""
    text = """
async function sync(plain, sink) {
  const artifact = makeArtifact(plain);
  return uploadPutObject(artifact, sink);
}
"""
    a = loc_code(text, "= makeArtifact(")
    b = loc_code(text, "uploadPutObject(artifact")
    rel = relate(text, a, b)
    # enc2up 链：用 argument_flow
    cand = ChainCandidate(
        chain_type="encryption_to_upload",
        required_evidence=["envelope_encryption", "object_storage_upload"],
        required_relations=["argument_flow"], scope="intra_function")
    ev = {"envelope_encryption": [FakeEv()], "object_storage_upload": [FakeEv()]}
    return cand, ev, [rel] if rel else []


def case_3():
    """P3-3 evidence 齐全但无 relation → insufficient + missing_relation_structurally_expected"""
    ev = {"workspace_snapshot": [FakeEv()], "envelope_encryption": [FakeEv()],
          "object_storage_upload": [FakeEv()]}
    return CAND_WS2OBJ, ev, []        # 关键：没有关系


def case_4():
    """P3-4 relation 存在但 source evidence 缺失 → missing_source_evidence（E4 的形态）"""
    text = """
const sealed = obscureSeal(data);
return shipSealed({ payload: sealed.sealedBlob });
"""
    a = loc_code(text, "= obscureSeal(")
    b = loc_code(text, "shipSealed({ payload: sealed.sealedBlob")
    rel = relate(text, a, b)
    cand = ChainCandidate(
        chain_type="encryption_to_upload",
        required_evidence=["envelope_encryption", "object_storage_upload"],
        required_relations=["argument_flow"], scope="intra_function")
    # ★ obscureSeal 完全没有 evidence（0 命中）
    ev = {"object_storage_upload": [FakeEv()]}
    return cand, ev, [rel] if rel else []


def case_5():
    """P3-5 relation 存在但 sink evidence 缺失 → missing_sink_evidence"""
    text = """
const sealed = obscureSeal(data);
return shipSealed({ payload: sealed.sealedBlob });
"""
    a = loc_code(text, "= obscureSeal(")
    b = loc_code(text, "shipSealed({ payload: sealed.sealedBlob")
    rel = relate(text, a, b)
    cand = ChainCandidate(
        chain_type="encryption_to_upload",
        required_evidence=["envelope_encryption", "object_storage_upload"],
        required_relations=["argument_flow"], scope="intra_function")
    ev = {"envelope_encryption": [FakeEv()]}       # sink 缺
    return cand, ev, [rel] if rel else []


def case_6():
    """P3-6 supporting + contradicting evidence → contradicted"""
    text = """
async function f(oss, t) {
  return { objectUpload: {
      url: oss.host,
      maxBytes: t.encryptedArtifact.encryptedSizeBytes } };
}
"""
    a = loc_code(text, "oss.host")
    b = loc_code(text, "t.encryptedArtifact.encryptedSizeBytes")
    rel = relate(text, a, b)
    cand = ChainCandidate(
        chain_type="credential_to_upload",
        required_evidence=["credential_access", "object_storage_upload"],
        required_relations=["same_object"], scope="intra_function")
    ev = {"credential_access": [FakeEv("contradicting")],
          "object_storage_upload": [FakeEv("supporting")]}
    return cand, ev, [rel] if rel else [], {"credential_access"}


def case_7():
    """P3-7 coverage_blocked → blocked_by_coverage"""
    ev = {"workspace_snapshot": [FakeEv()], "envelope_encryption": [FakeEv()],
          "object_storage_upload": [FakeEv()]}
    cov = {"technical_gap_for": {"object_storage_upload": True},
           "technical_gap": 1, "largest_unseen_unit": {"bytes": 33100000}}
    return CAND_WS2OBJ, ev, [], None, cov


def case_8():
    """P3-8 ★ E3 离散阈值案例 —— 证明不再被上游 possible→likely 截断"""
    p = os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural", "src", "index.js")
    text = open(p, encoding="utf-8").read()
    a = loc_code(text, "sink.url")
    b = loc_code(text, "artifact.encryptedSizeBytes")
    rel = relate(text, a, b, "sink.url", "artifact.encryptedSizeBytes")
    obs, by_cap = build(text, os.path.basename(p))
    cand = ChainCandidate(
        chain_type="encryption_to_upload",
        required_evidence=["envelope_encryption", "object_storage_upload"],
        required_relations=["same_object"], scope="intra_function")
    return cand, by_cap, [rel] if rel else []


CASES = [
    ("P3-1  完整 evidence + same_object", case_1, "supported",
     ["strong"], []),
    ("P3-2  完整 evidence + argument_flow", case_2, "supported",
     ["strong", "moderate"], []),
    ("P3-3  evidence 齐全、无 relation", case_3, "insufficient",
     ["weak", "unknown"], ["missing_relation_structurally_expected"]),
    ("P3-4  ★ relation 存在、source evidence 缺（E4 形态）", case_4,
     "insufficient", ["weak", "unknown"], ["missing_source_evidence"]),
    ("P3-5  relation 存在、sink evidence 缺", case_5, "insufficient",
     ["weak", "unknown"], ["missing_sink_evidence"]),
    ("P3-6  supporting + contradicting", case_6, "contradicted",
     ["weak"], ["contradicting_evidence"]),
    ("P3-7  coverage_blocked", case_7, "blocked_by_coverage",
     ["unknown"], ["coverage_blocked"]),
    ("P3-8  ★ E3 离散阈值案例", case_8, "supported",
     ["strong", "moderate"], []),
]


def main():
    print("=" * 100)
    print("P3 Chain 验收（判据：state + blocker 正确，不是 8/8 成链）")
    print("=" * 100)

    assessments, candidates = [], []
    results = []

    for item in CASES:
        title, fn, exp_state, exp_conf, exp_blockers = item
        out = fn()
        cand = out[0]
        ev = out[1]
        rels = out[2] or []
        contra = out[3] if len(out) > 3 else None
        cov = out[4] if len(out) > 4 else None

        a = evaluate(cand, ev, rels, cov, contra)
        candidates.append(cand)
        assessments.append(a)

        state_ok = (a.state == exp_state)
        conf_ok = (a.confidence in exp_conf)
        blk_ok = all(b in a.blockers for b in exp_blockers)
        ok = state_ok and conf_ok and blk_ok
        results.append(ok)

        print("\n" + "-" * 100)
        print("%s" % title)
        print("-" * 100)
        print("  期望 state=%-20s conf=%-22s blockers=%s" % (
            exp_state, "/".join(exp_conf), exp_blockers or "—"))
        print("  实际 state=%-20s conf=%-22s" % (a.state, a.confidence))
        print("        blockers=%s" % (a.blockers or "—"))
        for r in a.reasons:
            print("        · %s" % r)
        print("        evidence_refs=%s  relation_refs=%s" % (
            a.evidence_refs, a.relation_refs))
        print("  [%s]%s%s%s" % (
            "PASS" if ok else "FAIL",
            "" if state_ok else " state 不符",
            "" if conf_ok else " conf 不符",
            "" if blk_ok else " blocker 不符"))

    # ---- 硬规则 ----
    print("\n" + "=" * 100)
    print("硬规则断言")
    print("=" * 100)
    try:
        assert_chain_invariants(assessments, candidates)
        print("  规则 1/2/3/4/5/6 → PASS")
    except AssertionError as e:
        print("  → FAIL: %s" % e)

    # ---- 硬规则 5 专项 ----
    print("\n" + "=" * 100)
    print("规则 5 专项：no candidate → no chain evaluation")
    print("=" * 100)
    na = evaluate(CAND_NOT_APPLICABLE, {}, [])
    print("  applicable=False 的候选 → evaluated=%s  reasons=%s" % (
        na.evaluated, na.reasons))
    print("  （不产出 'absent' —— 因为那会被读成「评估过且不存在」）")

    # ---- blocker 分布 ----
    print("\n" + "=" * 100)
    print("chain_blocker_distribution（分母 = 已评估的候选链数）")
    print("=" * 100)
    d = blocker_distribution(assessments)
    print("  candidate_count      = %d" % d["candidate_count"])
    print("  evaluated_count      = %d" % d["evaluated_count"])
    print("  not_applicable_count = %d" % d["not_applicable_count"])
    print("  blocker_counts:")
    for k, v in sorted(d["blocker_counts"].items(), key=lambda x: -x[1]):
        print("     %-42s %d" % (k, v))

    print("\n" + "=" * 100)
    n = sum(results)
    print("结果：%d / %d 的 state + blocker 正确" % (n, len(results)))
    print("=" * 100)
    print("""
注意：P3 的目标不是"让更多东西形成链"，
而是**正确知道什么时候应该形成、什么时候不应该形成、为什么不形成**。

Out of scope（P3 不解决）：
    B1 discovery · B2 normalization · B3 calibration
    这三类是**单能力 evidence → assessment** 的问题，与链无关。""")


if __name__ == "__main__":
    main()
