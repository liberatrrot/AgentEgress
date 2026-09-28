# -*- coding: utf-8 -*-
"""P3 回放（完整文件版）—— 让 blocker 分布有更大的分母。

片段版（replay_p3.py）的问题：
    S1/S2 片段太短 → Observation=0 → 两份都判 missing_source/sink_evidence
    分布受片段影响，不能推广。

本脚本在 Phase 1 解包的**完整文件**上跑。
"""
import io
import os
import sys
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from chain import ChainCandidate, assert_chain_invariants      # noqa: E402
from chain_eval import evaluate, blocker_distribution          # noqa: E402
from adapter import build                                      # noqa: E402
from relation import relate                                    # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

FILES = [
    ("S1-ZCode/out/host/index.js",
     os.path.join(DOGFOOD, "s1-zcode", "out", "host", "index.js")),
    ("S1-ZCode/out/main/index.js",
     os.path.join(DOGFOOD, "s1-zcode", "out", "main", "index.js")),
    ("S3-opencode/out/main/index.js",
     os.path.join(DOGFOOD, "s3-opencode", "out", "main", "index.js")),
]

# 通用链定义（能力对 → 需要的关系类型）
CHAIN_DEFS = [
    ("workspace_to_object_storage",
     ["workspace_snapshot", "envelope_encryption", "object_storage_upload"],
     ["same_object"]),
    ("workspace_to_upload",
     ["workspace_snapshot", "object_storage_upload"],
     ["same_object"]),
    ("encryption_to_upload",
     ["envelope_encryption", "object_storage_upload"],
     ["same_object", "argument_flow"]),
    ("credential_to_upload",
     ["credential_access", "object_storage_upload"],
     ["same_object", "argument_flow"]),
    ("telemetry_to_upload",
     ["telemetry_egress", "object_storage_upload"],
     ["same_object"]),
    ("globalcfg_to_upload",
     ["global_config_collection", "object_storage_upload"],
     ["same_object"]),
    ("retry_to_upload",
     ["retry_backoff", "object_storage_upload"],
     ["same_object"]),
]


def main():
    print("=" * 100)
    print("P3 回放（完整文件）")
    print("=" * 100)

    all_ass, all_cand = [], []
    per_file = []

    for tag, path in FILES:
        if not os.path.exists(path):
            print("\n[缺] %s" % path)
            continue
        text = open(path, encoding="utf-8", errors="ignore").read()
        print("\n" + "#" * 100)
        print("# %s   (%.1f MB)" % (tag, len(text) / 1048576))

        obs, by_cap = build(text, os.path.basename(path))
        with_ev = {k: len(v) for k, v in by_cap.items()}
        print("# Observation = %d   有 evidence 的能力项 = %d" % (len(obs), len(with_ev)))
        for k, v in sorted(with_ev.items(), key=lambda x: -x[1]):
            print("#     %-26s %d 条" % (k, v))

        # 每个能力取**第一个证据的偏移**，作为该能力在图中的锚点
        anchor = {}
        for k, v in by_cap.items():
            if v and v[0].citation:
                anchor[k] = v[0].citation.get("offset")

        # ★ 修正：对两个能力的**全部证据位置**两两尝试建关系
        #
        # 【第一版的错误】每个能力只取"第一个证据"当锚点，
        # 在 2.5MB 文件里两个锚点几乎必然相距很远，
        # same_object / argument_flow 都不可能成立
        # → 于是 8/8 全判 missing_relation。
        # 那测的是「锚点选得对不对」，不是「relation 类型够不够」。
        positions = {}
        for k, v in by_cap.items():
            positions[k] = [e.citation.get("offset") for e in v
                            if e.citation and e.citation.get("offset") is not None]

        n_cand = 0
        for ctype, caps, rels in CHAIN_DEFS:
            present = [c for c in caps if c in with_ev]
            if len(present) < 2:
                continue              # 连两个环节都没有 → 这条链对这个文件不适用
            cand = ChainCandidate(chain_type=ctype, required_evidence=caps,
                                  required_relations=rels,
                                  scope="intra_function")

            # 逐个环节尝试：相邻两个环节之间找关系（链是逐段的）
            found_rels = []
            for i in range(len(caps) - 1):
                a_cap, b_cap = caps[i], caps[i + 1]
                pa = positions.get(a_cap, [])
                pb = positions.get(b_cap, [])
                for p1 in pa:
                    for p2 in pb:
                        r = relate(text, p1, p2, a_cap, b_cap)
                        if r:
                            found_rels.append(r)
                            break
                    if found_rels and found_rels[-1]["type"]:
                        break

            a = evaluate(cand, by_cap, found_rels)
            all_ass.append(a)
            all_cand.append(cand)
            n_cand += 1
            print("#   %-30s → %-14s %-8s %s" % (
                ctype, a.state, a.confidence,
                ",".join(a.blockers) or "—"))
        per_file.append((tag, n_cand))

    # ---- 硬规则 ----
    print("\n" + "=" * 100)
    print("硬规则断言")
    print("=" * 100)
    try:
        assert_chain_invariants(all_ass, all_cand)
        print("  规则 1/2/3/4/5/6 → PASS（%d 条评估）" % len(all_ass))
    except AssertionError as e:
        print("  → FAIL: %s" % e)

    # ---- 分布 ----
    print("\n" + "=" * 100)
    print("chain_blocker_distribution（完整文件）")
    print("=" * 100)
    d = blocker_distribution(all_ass)
    print("  candidate_count      = %d" % d["candidate_count"])
    print("  evaluated_count      = %d  ← 分母" % d["evaluated_count"])
    print()
    for k, v in sorted(d["blocker_counts"].items(), key=lambda x: -x[1]):
        pct = 100.0 * v / max(1, d["evaluated_count"])
        print("     %-42s %2d / %-2d  %5.0f%%" % (k, v, d["evaluated_count"], pct))

    rel_blocked = d["blocker_counts"].get("missing_relation_structurally_expected", 0)
    ev_blocked = (d["blocker_counts"].get("missing_source_evidence", 0)
                  + d["blocker_counts"].get("missing_sink_evidence", 0))
    print("\n  判读：")
    print("    relation 类型不足导致：%d / %d" % (rel_blocked, d["evaluated_count"]))
    print("    evidence 缺失导致：    %d / %d" % (ev_blocked, d["evaluated_count"]))
    if rel_blocked <= ev_blocked:
        print("    → **same_call_chain 不是瓶颈**（evidence 层才是）")
    else:
        print("    → relation 类型不足是主要瓶颈，**支持加 same_call_chain**")

    # ---- state 汇总 ----
    print("\n" + "=" * 100)
    print("state 汇总")
    print("=" * 100)
    st = Counter(a.state for a in all_ass)
    for k, v in st.most_common():
        print("  %-22s %d" % (k, v))


if __name__ == "__main__":
    main()
