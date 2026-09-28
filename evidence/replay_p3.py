# -*- coding: utf-8 -*-
"""P3 证据回放：S1 / S2 / E3 / E4 + chain_blocker_distribution

**关键点**：
  · 每条候选链必须**先声明**它的 required_evidence / required_relations
    —— 否则 blocker 分布没有分母。
  · 分母是「已评估的候选链数」，不是「某种 blocker 出现几次」。
"""
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from chain import ChainCandidate, assert_chain_invariants     # noqa: E402
from chain_eval import evaluate, blocker_distribution         # noqa: E402
from adapter import build                                     # noqa: E402
from relation import relate, region_at                        # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")


def loc_code(text, needle):
    i = -1
    while True:
        i = text.find(needle, i + 1)
        if i < 0:
            return -1
        if region_at(text, i) == "code":
            return i


# ================================================================ 样本

S1 = """
async function snapshotUpload(oss, t) {
  return { ok: true, snapshotId: n,
    objectKey: oss.path,
    objectUpload: {
      method: "POST",
      url: oss.host,
      maxBytes: Math.max(t.encryptedArtifact.encryptedSizeBytes, 1),
      formFields: { key: oss.path, policy: oss.policy }
    }
  };
}
"""

S2 = """
async function importFiles(params) {
  const created = await createMedia({ kbId: params.kbId, fileExt: ext });
  if (!created?.media_id || !created?.cos_credential) throw new Error("empty");
  await this.uploadToCos(created.cos_credential, buffer, contentType, cb);
}
"""

E3 = open(os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural",
                       "src", "index.js"), encoding="utf-8").read()
E4 = open(os.path.join(DOGFOOD, "s5-orthogonal",
                       "e4-structural-bridges-lexical",
                       "src", "index.js"), encoding="utf-8").read()


# ================================================================ 回放定义
#
# ★ 每条候选链都**显式声明**它需要什么 —— 这是 blocker 分布的分母来源。
#
# relation 用的 needle 在「__REL__」里给出（源/目标位置）。

REPLAYS = [
    {
        "tag": "S1 · ZCode",
        "note": "真实结构（out/host/index.js:487）",
        "text": S1,
        "cands": [ChainCandidate(
            chain_type="workspace_to_object_storage",
            required_evidence=["workspace_snapshot", "envelope_encryption",
                               "object_storage_upload"],
            required_relations=["same_object"], scope="intra_function")],
        "rel": ("oss.host", "t.encryptedArtifact.encryptedSizeBytes"),
    },
    {
        "tag": "S2 · WorkBuddy",
        "note": "⚠ 等价构造（真实绑定语句未完整取到）",
        "text": S2,
        "cands": [ChainCandidate(
            chain_type="credential_to_upload",
            required_evidence=["upload_credential_api", "object_storage_upload"],
            required_relations=["argument_flow"], scope="intra_function")],
        "rel": ("= createMedia(", "uploadToCos(created.cos_credential"),
    },
    {
        "tag": "E3 · 加密产物→上传",
        "note": "P0/S5 构造样本（★ E3 离散阈值案例）",
        "text": E3,
        "cands": [ChainCandidate(
            chain_type="encryption_to_upload",
            required_evidence=["envelope_encryption", "object_storage_upload"],
            required_relations=["same_object"], scope="intra_function")],
        "rel": ("sink.url", "artifact.encryptedSizeBytes"),
    },
    {
        "tag": "★ E4 · 非标准加密→上传",
        "note": "S5 构造：obscureSeal 完全不含标准词",
        "text": E4,
        "cands": [ChainCandidate(
            chain_type="encryption_to_upload",
            required_evidence=["envelope_encryption", "object_storage_upload"],
            required_relations=["argument_flow"], scope="intra_function")],
        "rel": ("= obscureSeal(", "sealed.sealedBlob"),
    },
]


def main():
    print("=" * 100)
    print("P3 证据回放（S1 / S2 / E3 / E4）")
    print("=" * 100)

    all_ass, all_cand = [], []
    for r in REPLAYS:
        text = r["text"]
        print("\n" + "#" * 100)
        print("# %s    （%s）" % (r["tag"], r["note"]))
        print("#")

        # ---- adapter：拿 evidence ----
        obs, by_cap = build(text, "sample.js")
        # ---- relation：拿 relations ----
        a_n, b_n = r["rel"]
        a, b = loc_code(text, a_n), loc_code(text, b_n)
        rel = relate(text, a, b, a_n, b_n)
        rels = [rel] if rel else []

        print("# Observation = %d   有 evidence 的能力项 = %d" % (len(obs), len(by_cap)))
        print("# relations = %s" % (["%s" % x["type"] for x in rels] or "—"))

        for cand in r["cands"]:
            aa = evaluate(cand, by_cap, rels)
            all_ass.append(aa)
            all_cand.append(cand)
            print("#")
            print("# candidate = %s" % cand.chain_type)
            print("#   required_evidence  = %s" % cand.required_evidence)
            print("#   required_relations = %s" % cand.required_relations)
            print("#   → state      = %s" % aa.state)
            print("#     confidence = %s" % aa.confidence)
            print("#     blockers   = %s" % (aa.blockers or "—"))
            for rs in aa.reasons:
                print("#        · %s" % rs)

    # ---- 硬规则 ----
    print("\n" + "=" * 100)
    print("硬规则断言")
    print("=" * 100)
    try:
        assert_chain_invariants(all_ass, all_cand)
        print("  规则 1/2/3/4/5/6 → PASS")
    except AssertionError as e:
        print("  → FAIL: %s" % e)

    # ---- blocker 分布（带分母）----
    print("\n" + "=" * 100)
    print("chain_blocker_distribution")
    print("=" * 100)
    d = blocker_distribution(all_ass)
    print("  分母（已评估候选链数） = %d" % d["evaluated_count"])
    print("  未评估（not applicable） = %d" % d["not_applicable_count"])
    print()
    for k, v in sorted(d["blocker_counts"].items(), key=lambda x: -x[1]):
        print("     %-42s %d / %d" % (k, v, d["evaluated_count"]))

    print("""
判读（这是 same_call_chain 是否值得做的依据）：
  · 若大量卡在 missing_relation_structurally_expected
        → 代码里有结构，只是 Relation 类型没实现 → **支持加 same_call_chain**
  · 若大多卡在 missing_source_evidence / coverage_blocked / relation_unknown
        → 不是 Relation 类型的问题 → **加更多 relation type 没有价值**
  · missing_relation_no_structure 计数高
        → 说明这些链假设本身不成立 → 同样不支持加 relation type""")

    print("\n" + "=" * 100)
    print("逐样本汇总")
    print("=" * 100)
    print("  %-28s %-14s %-10s %s" % ("样本", "state", "conf", "blockers"))
    for (r, aa) in zip(REPLAYS, all_ass):
        print("  %-28s %-14s %-10s %s" % (
            r["tag"][:28], aa.state, aa.confidence,
            ",".join(aa.blockers) or "—"))


if __name__ == "__main__":
    main()
