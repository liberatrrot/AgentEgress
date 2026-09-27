# -*- coding: utf-8 -*-
"""S5：6 个正交实验的批量执行与结果收集。

输出一张表，把「哪一层缺失 → 哪一种错误」摆出来。
"""
import io
import os
import sys
import json

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import agentegress as ae  # noqa: E402

ROOT = str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "dogfood" / "s5-orthogonal")

CASES = [
    ("E0-baseline",                        "lexical✓ semantic— structural—", "标准加密+标准上传"),
    ("E1-discovery",                       "lexical✗ semantic— structural—", "全自造名字，无标准关键词"),
    ("E2-semantic",                        "lexical✓ semantic需要 structural—", "标准加密 + denylist"),
    ("E3-structural",                      "lexical✓ semantic✓ structural需要", "加密产物字段 → 上传参数"),
    ("E4-structural-bridges-lexical",      "lexical✗ semantic? structural✓", "非标准加密 → 上传（★最有价值）"),
    ("E5-aggregation",                     "lexical✓ semantic✓ structural—", "大量弱证据，无真实链路"),
]

WATCH = ("envelope_encryption", "object_storage_upload", "workspace_snapshot",
         "credential_access", "bulk_archive", "telemetry_egress")


def run_case(name):
    d = os.path.join(ROOT, name)
    if not os.path.isdir(d):
        return None
    acc = ae.CapabilityAccumulator()
    hits, meta = ae.audit_path(d, acc=acc)
    caps = ae.aggregate_from_buckets(acc)
    chains = ae.detect_chains(caps, acc=acc)
    lv = {c["id"]: c for c in caps}
    return {
        "name": name,
        "meta": {k: meta.get(k) for k in ("files_scanned", "files_analyzed",
                                          "prefilter_rejected", "candidates")},
        "caps": {
            cid: {
                "level": lv.get(cid, {}).get("level", "absent"),
                "score": round(lv.get(cid, {}).get("score", 0.0), 2),
                "norm": round(lv.get(cid, {}).get("norm", 0.0), 4),
                "patterns": len(lv.get(cid, {}).get("patterns", [])),
                "files": lv.get(cid, {}).get("file_count", 0),
                "hits": lv.get(cid, {}).get("hit_total", 0),
            } for cid in WATCH
        },
        "chains": [{"name": c["name"], "level": c["level"],
                    "cohesion": c.get("cohesion")} for c in chains],
    }


def main():
    out = {}
    print("=" * 96)
    print("S5 · 正交实验（冻结版 agentegress）")
    print("=" * 96)
    for name, layers, desc in CASES:
        r = run_case(name)
        if r is None:
            print("\n[缺失] %s" % name)
            continue
        out[name] = r
        m = r["meta"]
        print("\n" + "#" * 96)
        print("# %s   （%s）" % (name, desc))
        print("# 分层设置: %s" % layers)
        print("# 扫描: 候选 %s -> 读到 %s -> 跑正则 %s（预筛拒 %s）" % (
            m.get("candidates"), m.get("files_scanned"),
            m.get("files_analyzed"), m.get("prefilter_rejected")))
        print()
        print("  %-24s %-10s %8s %8s %6s %6s %6s" % (
            "能力", "等级", "score", "norm", "模式", "文件", "命中"))
        any_cap = False
        for cid in WATCH:
            c = r["caps"][cid]
            if c["level"] == "absent" and c["hits"] == 0:
                continue
            any_cap = True
            print("  %-24s %-10s %8.2f %8.4f %6d %6d %6d" % (
                cid, c["level"], c["score"], c["norm"],
                c["patterns"], c["files"], c["hits"]))
        if not any_cap:
            print("  （全部 absent 且零命中）")
        print()
        if r["chains"]:
            print("  组合证据:")
            for c in r["chains"]:
                print("     [%s] %s   关联度=%s" % (c["level"], c["name"], c["cohesion"]))
        else:
            print("  组合证据: 无")

    with open(os.path.join(ROOT, "_s5_result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    # ---- 汇总矩阵 ----
    print("\n" + "=" * 96)
    print("汇总矩阵（★ = 本次实验的核心观察点）")
    print("=" * 96)
    print("  %-34s %-12s %-12s %-14s %s" % (
        "实验", "信封加密", "对象存储直传", "工作区快照", "组合证据"))
    for name, _l, _d in CASES:
        if name not in out:
            continue
        c = out[name]["caps"]
        ch = len(out[name]["chains"])
        blk = sum(1 for x in out[name]["chains"] if x["level"] == "blocking")
        print("  %-34s %-12s %-12s %-14s %d 条(阻断 %d)" % (
            name[:34], c["envelope_encryption"]["level"],
            c["object_storage_upload"]["level"],
            c["workspace_snapshot"]["level"], ch, blk))


if __name__ == "__main__":
    main()
