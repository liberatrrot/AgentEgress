# -*- coding: utf-8 -*-
"""P0 Discovery Boundary Matrix —— 执行与四层记录。

对每个样本记录：
    lexical hit        是否有任何 pattern 命中
    semantic candidate 是否至少有一个能力非 absent
    structural candidate 是否产出了组合证据
    final verdict      总结论等级
"""
import io
import os
import sys
import json

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
import agentegress as ae  # noqa: E402

ROOT = str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "dogfood" / "p0-boundary")

GROUPS = [
    ("D · 同行为 / 逐级替换表达形式", [
        ("d0-standard",           "标准 API 直调"),
        ("d1-wrapper",            "自造 wrapper（内部仍调标准 API）"),
        ("d2-wrapper-partial",    "wrapper + 部分直调"),
        ("d3-custom-primitive",   "完全自定义 primitive"),
        ("d4-string-built-name",  "字符串拼接 API 名"),
        ("d5-dynamic-property",   "动态属性调用"),
        ("d6-registry-driven",    "注册表 / 配置驱动"),
        ("d7-alias",              "间接 import / alias"),
        ("d8-lib-encapsulated",   "库封装层"),
    ]),
    ("B · 控制组：different behavior, same spelling", [
        ("b1-real-user-data",     "真加密用户数据并外发（对照）"),
        ("b2-test-only",          "只在测试代码里加密，生产不外发"),
        ("b3-local-cache-only",   "加密后写本地文件，不联网"),
        ("b4-sdk-internal",       "SDK 风格通用工具函数"),
    ]),
    ("V · Transformation invariance（语义等价的不同写法）", [
        ("v0-direct",             "直写"),
        ("v1-wrapper",            "包一层函数"),
        ("v2-renamed",            "变量改名"),
        ("v3-helper-split",       "拆成多个 helper"),
        ("v4-reordered",          "语句顺序调换"),
        ("v5-minified",           "压成单行"),
        ("v6-alias",              "标准 API 取别名"),
        ("v7-function-pointer",   "通过变量间接调用"),
    ]),
]

WATCH = ("envelope_encryption", "object_storage_upload", "workspace_snapshot")


def probe(name):
    d = os.path.join(ROOT, name)
    if not os.path.isdir(d):
        return None
    acc = ae.CapabilityAccumulator()
    _h, meta = ae.audit_path(d, acc=acc)
    caps = ae.aggregate_from_buckets(acc)
    chains = ae.detect_chains(caps, acc=acc)
    lv = {c["id"]: c for c in caps}
    all_hits = sum(c.get("hit_total", 0) for c in caps)
    non_absent = [c["id"] for c in caps if c["level"] != "absent"]
    verdict = ae.summarize_capabilities(caps, coverage=None)["verdict"]
    return {
        "name": name,
        "meta": {k: meta.get(k) for k in ("files_scanned", "files_analyzed",
                                          "prefilter_rejected")},
        "lexical_hit": all_hits,
        "non_absent": non_absent,
        "caps": {cid: {"level": lv.get(cid, {}).get("level", "absent"),
                       "score": round(lv.get(cid, {}).get("score", 0.0), 2),
                       "hits": lv.get(cid, {}).get("hit_total", 0),
                       "patterns": len(lv.get(cid, {}).get("patterns", []))}
                 for cid in WATCH},
        "chains": len(chains),
        "blocking": sum(1 for c in chains if c["level"] == "blocking"),
        "verdict": verdict,
    }


def main():
    out = {}
    print("=" * 104)
    print("P0 · Discovery Boundary Matrix（冻结版 agentegress）")
    print("=" * 104)

    for title, cases in GROUPS:
        print("\n" + "#" * 104)
        print("# %s" % title)
        print("#" * 104)
        print("  %-26s %-22s %7s %9s %10s %7s %7s  %s" % (
            "样本", "说明", "lexical", "encrypt", "objstore", "组合", "阻断", "verdict"))
        print("  " + "-" * 100)
        for name, desc in cases:
            r = probe(name)
            if r is None:
                print("  %-26s [缺失]" % name)
                continue
            out[name] = r
            c = r["caps"]
            print("  %-26s %-22s %7d %9s %10s %7d %7d  %s" % (
                name, desc[:22], r["lexical_hit"],
                c["envelope_encryption"]["level"],
                c["object_storage_upload"]["level"],
                r["chains"], r["blocking"], r["verdict"]))
        print()

    # ---- 边界结论 ----
    print("=" * 104)
    print("边界结论")
    print("=" * 104)

    ds = [(n, out[n]) for n, _d in GROUPS[0][1] if n in out]
    print("\n[D 组] 同一行为、不同写法的检出情况：")
    first_fail = None
    for n, r in ds:
        ok = r["caps"]["envelope_encryption"]["level"] != "absent"
        tag = "OK  " if ok else "FAIL"
        if not ok and first_fail is None:
            first_fail = n
        print("   [%s] %-26s 加密=%-10s 命中=%d" % (
            tag, n, r["caps"]["envelope_encryption"]["level"], r["lexical_hit"]))
    print("\n   → 首次失效点：%s" % (first_fail or "（全部检出）"))

    print("\n[B 组] same spelling / different behavior（测 semantic precision）：")
    for n, _d in GROUPS[1][1]:
        if n not in out:
            continue
        r = out[n]
        c = r["caps"]["envelope_encryption"]
        print("   %-26s 加密=%-10s 命中=%-4d 组合=%d  verdict=%s" % (
            n, c["level"], r["lexical_hit"], r["chains"], r["verdict"]))

    print("\n[V 组] 语义等价的不同写法（测 invariance）：")
    lvls = []
    for n, _d in GROUPS[2][1]:
        if n not in out:
            continue
        c = out[n]["caps"]["envelope_encryption"]
        lvls.append(c["level"])
        print("   %-26s 加密=%-10s 命中=%-4d 组合=%d" % (
            n, c["level"], out[n]["lexical_hit"], out[n]["chains"]))
    uniq = sorted(set(lvls))
    print("\n   → 同一行为的结论集合：%s" % uniq)
    print("   → %s" % ("一致（invariance 成立）" if len(uniq) == 1
                       else "**不一致 —— invariance 不成立**（%d 种不同结论）" % len(uniq)))

    with open(os.path.join(ROOT, "_p0_result.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
