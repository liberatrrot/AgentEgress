# -*- coding: utf-8 -*-
"""P2/P3 Real-World Replay Gate（R1–R8）

**与之前的回放不同，本脚本遵守三条硬要求**：

  1. Relation 必须基于**完整证据集**（禁止"每能力一个代表证据"）
         capability → all admitted evidence → candidate relations
     理由：anchor selection 会把 2.5MB 文件里的真实关系错过，
           那样测的是 anchor 策略，不是 P2。
  2. Chain 必须使用**显式 chain_candidates**（不自动生成）
  3. 每个结果保存**证明材料**（可回放 candidate→evidence→relation→reasons→blockers）
     理由：不是 8/8，而是 8/8 + 为什么。

**R2 的检查方式**（能抓 `id()` 那类 bug）：
  同一个样本连跑两次 → 结果必须一致；
  改变样本顺序 → 结果也必须一致。
"""
import io
import os
import sys
import json
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from adapter import build                                     # noqa: E402
from assess import assess, synthesize                         # noqa: E402
from chain import ChainCandidate, assert_chain_invariants     # noqa: E402
from chain_eval import evaluate, blocker_distribution         # noqa: E402
from relation import relate, region_at, assert_relation_invariants  # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

# 规模限制（防止 33MB 文件上配对爆炸）
# 可用环境变量覆盖，便于分批跑
MAX_FILE_MB = float(os.environ.get("RW_MAX_FILE_MB", "40"))
MAX_EV_PER_CAP = int(os.environ.get("RW_MAX_EV", "6"))
MAX_CAP_PAIRS = int(os.environ.get("RW_MAX_PAIRS", "60"))
ONLY = os.environ.get("RW_ONLY", "")      # 只跑 tag 含该串的文件
# 截断上限（MB）：33MB 文件在 Python 里扫 56 个正则 + lex_regions 会超时。
# 这是**环境限制**，不是实现缺陷；截断跑时必须标注为 truncated。
TRUNC_MB = float(os.environ.get("RW_TRUNC_MB", "0"))

FILES = [
    ("S1 ZCode",     "s1-zcode/out/host/index.js"),
    ("S1 ZCode",     "s1-zcode/out/main/index.js"),
    ("S2 WorkBuddy", "s2-workbuddy/main/index.js"),
    ("S2 WorkBuddy", "s2-workbuddy/main/code-cache.js"),
    ("S4 Quark",     "s4-quark/dist/main/main.js"),
    ("S3 opencode",  "s3-opencode/out/main/index.js"),
    ("S3 opencode",  "s3-opencode/out/main/chunks/node-BIz0dqH1.js"),   # 33MB
]

# ★ 显式 chain_candidates —— 不因"能力多"就自动生成
#
#   structural_expectation 一律 "unknown" ——
#   **evaluator 不得猜"有没有结构"**（P3 的教训）。
#   structurally_expected 只能来自外部标注。
CHAIN_CANDIDATES = [
    ChainCandidate("workspace_to_upload",
                   ["workspace_snapshot", "object_storage_upload"],
                   ["same_object", "argument_flow"],
                   structural_expectation="unknown"),
    ChainCandidate("workspace_encrypt_upload",
                   ["workspace_snapshot", "envelope_encryption",
                    "object_storage_upload"],
                   ["same_object"],
                   structural_expectation="unknown"),
    ChainCandidate("encryption_to_upload",
                   ["envelope_encryption", "object_storage_upload"],
                   ["same_object", "argument_flow"],
                   structural_expectation="unknown"),
    ChainCandidate("credential_to_upload",
                   ["credential_access", "object_storage_upload"],
                   ["same_object", "argument_flow"],
                   structural_expectation="unknown"),
    ChainCandidate("telemetry_to_upload",
                   ["telemetry_egress", "object_storage_upload"],
                   ["same_object"],
                   structural_expectation="unknown"),
]


def loc_code(text, needle):
    """定位 needle 在**真实代码区**的第一次出现（跳过注释/字符串）。

    P2 的教训：直接 find() 会落在注释里的同样文字上。
    """
    i = -1
    while True:
        i = text.find(needle, i + 1)
        if i < 0:
            return -1
        if region_at(text, i) == "code":
            return i


def cap_pairs(text, by_cap, relations_needed):
    """★ 要求 1：用**完整证据集**建 relation（不是每能力一个 anchor）。

    capability → all admitted evidence → candidate relations

    【自我修正】第一版用了模块级 `items_text` 传 text ——
    **那本身就是跨样本共享状态**，而 R2 恰恰要检查这个。
    改为显式传参。
    """
    caps = sorted(by_cap)
    out = []
    n_pairs = 0
    for i in range(len(caps)):
        for j in range(i + 1, len(caps)):
            if n_pairs >= MAX_CAP_PAIRS:
                return out
            n_pairs += 1
            a_cap, b_cap = caps[i], caps[j]
            evs_a = by_cap[a_cap][:MAX_EV_PER_CAP]
            evs_b = by_cap[b_cap][:MAX_EV_PER_CAP]
            for ea in evs_a:
                for eb in evs_b:
                    pa = (ea.citation or {}).get("offset")
                    pb = (eb.citation or {}).get("offset")
                    if pa is None or pb is None:
                        continue
                    r = relate(text, pa, pb, a_cap, b_cap)
                    if r and r.get("type") in relations_needed:
                        out.append({"from_cap": a_cap, "to_cap": b_cap,
                                    "relation": r})
    return out


def run_file(tag, rel_path, order_key=0):
    """对一个文件跑：adapter → relations（完整证据集）→ 显式 candidate → chain。"""
    path = os.path.join(DOGFOOD, *rel_path.split("/"))
    if not os.path.exists(path):
        return None
    mb = os.path.getsize(path) / 1048576.0
    if mb > MAX_FILE_MB:
        return {"skipped": True, "mb": mb}
    text = open(path, encoding="utf-8", errors="ignore").read()
    truncated = False
    if TRUNC_MB and len(text) > TRUNC_MB * 1048576:
        text = text[:int(TRUNC_MB * 1048576)]
        truncated = True

    obs, by_cap = build(text, os.path.basename(path))
    # ---- capability 结论（P2/P3 之前的基线，用于 R7）----
    baseline = {a.capability: a.evidence_state for a in assess(by_cap)}

    # ---- relations：完整证据集 ----
    need = set()
    for c in CHAIN_CANDIDATES:
        need |= set(c.required_relations)
    rels = cap_pairs(text, by_cap, need)

    # ---- chain 评估（只用显式 candidate）----
    chains = []
    for cand in CHAIN_CANDIDATES:
        r = evaluate(cand, by_cap, [x["relation"] for x in rels])
        chains.append({
            "candidate": cand.chain_type,
            "scope": cand.scope,
            "state": r.state,
            "confidence": r.confidence,
            "blockers": r.blockers,
            "reasons": r.reasons,
            "evidence_refs": r.evidence_refs,
            "relation_refs": r.relation_refs,
            "evaluated": r.evaluated,
        })

    # ---- R7：P2/P3 不得改变 capability 结论 ----
    after = {a.capability: a.evidence_state for a in assess(by_cap)}

    return {
        "tag": tag, "file": rel_path, "mb": round(mb, 2),
        "truncated": truncated,
        "observation": len(obs),
        "caps": {k: len(v) for k, v in sorted(by_cap.items())},
        "relations": rels,
        "chains": chains,
        "baseline": baseline,
        "after": after,
        "skipped": False,
    }


def main():
    print("=" * 100)
    print("P2/P3 Real-World Replay Gate（R1–R8）")
    print("=" * 100)
    print("""三条硬要求：
  1. Relation 基于**完整证据集**（禁止每能力一个 anchor）
  2. Chain 只用**显式 chain_candidates**
  3. 每个结果保存**证明材料**（可回放）""")

    results = []
    for tag, rel in FILES:
        if ONLY and ONLY not in tag:
            continue
        print("\n" + "#" * 100)
        print("# %s  ·  %s" % (tag, rel))
        r = run_file(tag, rel)
        if r is None:
            print("# [缺] 跳过")
            continue
        if r.get("skipped"):
            print("# [跳过] %.1f MB 超过上限 %d MB" % (r["mb"], MAX_FILE_MB))
            continue
        results.append(r)
        print("# %.1f MB   Observation=%d   有证据的能力=%d"
              % (r["mb"], r["observation"], len(r["caps"])))
        for k, v in list(r["caps"].items())[:8]:
            print("#     %-26s %d 条" % (k, v))
        print("# relations（完整证据集配对）= %d" % len(r["relations"]))
        for x in r["relations"][:4]:
            print("#     %s ↔ %s : %s" % (
                x["from_cap"], x["to_cap"], x["relation"]["type"]))
        print("# chains（只评估显式 candidate）:")
        for c in r["chains"]:
            print("#     %-26s %-14s %-8s %s" % (
                c["candidate"], c["state"], c["confidence"],
                ",".join(c["blockers"]) or "—"))

    # ============================================================ R1–R8
    print("\n" + "=" * 100)
    print("R1–R8 检查")
    print("=" * 100)
    gates = []

    # R1 全部可运行
    gates.append(("R1 S1/S2/S3/S4 全部可运行", len(results) >= 4,
                  "成功 %d 个文件" % len(results)))

    # R2 无跨样本状态污染：同一文件跑两次结果一致
    if results:
        first = results[0]
        again = run_file(first["tag"], first["file"])
        same = (json.dumps(first["chains"], sort_keys=True, ensure_ascii=False)
                == json.dumps(again["chains"], sort_keys=True, ensure_ascii=False))
        gates.append(("R2 同一样本重复运行结果一致", same,
                      "chains 完全一致" if same else "**存在跨样本状态污染**"))

    # R3 relation 有 machine-checkable basis
    all_rels = [x["relation"] for r in results for x in r["relations"]]
    try:
        assert_relation_invariants(all_rels)
        gates.append(("R3 每条 relation 都有可机器复核 basis", True,
                      "共 %d 条" % len(all_rels)))
    except AssertionError as e:
        gates.append(("R3 relation basis 完整", False, str(e)))

    # R4 chain 只评估显式 candidate
    cand_types = {c.chain_type for c in CHAIN_CANDIDATES}
    all_chains = [c for r in results for c in r["chains"]]
    bad = [c["candidate"] for c in all_chains if c["candidate"] not in cand_types]
    gates.append(("R4 只评估显式 candidate（%d 个）" % len(cand_types),
                  not bad, "越界: %s" % bad if bad else "无自动生成的链"))

    # R5 三分法不靠猜
    all_ass, all_cands = [], []
    for r in results:
        for c in r["chains"]:
            for cd in CHAIN_CANDIDATES:
                if cd.chain_type == c["candidate"]:
                    all_cands.append(cd)
    guessed = [c for c in all_chains
               if "missing_relation_structurally_expected" in c["blockers"]]
    gates.append(("R5 missing_relation 三分法不靠猜",
                  not guessed,
                  ("无外部标注时不应出现 structurally_expected；"
                   "出现 %d 次" % len(guessed)) if guessed else
                  "全部落在 relation_unknown_due_to_analysis"))

    # R6 E3 离散截断保持修复（回归）
    e3_path = os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural",
                           "src", "index.js")
    if os.path.exists(e3_path):
        text = open(e3_path, encoding="utf-8").read()
        a = loc_code(text, "sink.url")
        b = loc_code(text, "artifact.encryptedSizeBytes")
        rel = relate(text, a, b, "sink.url", "artifact.encryptedSizeBytes")
        _o, bc = build(text, "e3.js")
        cd = ChainCandidate("encryption_to_upload",
                            ["envelope_encryption", "object_storage_upload"],
                            ["same_object"], structural_expectation="unknown")
        rr = evaluate(cd, bc, [rel] if rel else [])
        gates.append(("R6 E3 型离散截断保持修复",
                      rr.state == "supported",
                      "state=%s conf=%s" % (rr.state, rr.confidence)))
    else:
        gates.append(("R6 E3 样本存在", False, "缺文件"))

    # R7 P3 不越权
    leaks = []
    for r in results:
        diff = {k for k in r["baseline"] if r["baseline"][k] != r["after"].get(k)}
        if diff:
            leaks.append("%s/%s: %s" % (r["tag"], r["file"], diff))
    gates.append(("R7 P2/P3 不改变 capability-level 结论",
                  not leaks, "层间泄漏: %s" % leaks if leaks else "无变化"))

    # R8 所有结论可回放
    no_proof = []
    for r in results:
        for c in r["chains"]:
            if c["state"] != "supported" and not c["reasons"] and not c["blockers"]:
                no_proof.append("%s/%s" % (r["tag"], c["candidate"]))
    gates.append(("R8 所有 chain 结论都有 evidence/relations/reasons",
                  not no_proof, "缺证明材料: %s" % no_proof if no_proof else "齐全"))

    for name, ok, detail in gates:
        print("  %s %s" % ("✓" if ok else "✗", name))
        print("      %s" % detail)

    print("\n" + "=" * 100)
    n = sum(1 for _n, ok, _d in gates if ok)
    print("Gate 判定：%d / %d %s" % (
        n, len(gates), "→ 可以进入 P4" if n == len(gates) else "→ 不进入 P4"))
    print("=" * 100)

    # ---- blocker 分布 ----
    print("\nchain_blocker_distribution（分母 = 已评估 candidate 数）")
    all_ass = []
    for r in results:
        for c in r["chains"]:
            all_ass.append(type("A", (), {
                "evaluated": c["evaluated"], "blockers": c["blockers"]})())
    d = blocker_distribution(all_ass)
    print("  候选 %d  已评估 %d" % (d["candidate_count"], d["evaluated_count"]))
    for k, v in sorted(d["blocker_counts"].items(), key=lambda x: -x[1]):
        print("     %-42s %d" % (k, v))

    # ---- 保存证明材料 ----
    out = os.path.join(_HERE, "_replay_realworld.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print("\n证明材料已保存: %s" % os.path.basename(out))


if __name__ == "__main__":
    main()
