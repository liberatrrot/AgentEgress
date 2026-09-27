# -*- coding: utf-8 -*-
"""P0.5 · 扩大测量：在完整文件上跑 role 分布。

回答"local consumer analysis 能把多少 unknown 变成有依据的 role"，
而不是靠 5 个手挑的 case。

方法：
    用 agentegress 的 56 个 pattern 找 lexical 命中（这部分沿用既有能力）
    → 对每个命中调 probe.py 推断 role
    → 统计 role 分布 + 每条判定的依据
"""
import io
import os
import sys
import json
from collections import Counter

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import agentegress as ae      # noqa: E402
from probe import probe, lex_regions  # noqa: E402

TARGETS = [
    ("S1-ZCode(min)", str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "dogfood" / "s1-zcode" / "out" / "host" / "index.js")),
    ("S1-ZCode(min)", str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "dogfood" / "s1-zcode" / "out" / "main" / "index.js")),
    ("S3-opencode(min)", str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "dogfood" / "s3-opencode" / "out" / "main" / "index.js")),
    # ★ 对照：opencode 的 33MB bundle 是**未压缩**的（有缩进与换行）
    ("S3-opencode(unmin)", str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "dogfood" / "s3-opencode" / "out" / "main" / "chunks" / "node-BIz0dqH1.js")),
]


def hits_in(text):
    """用 agentegress 的模式找命中，返回 [(cap_id, pat_id, pos, token)]。"""
    out = []
    segs = lex_regions(text)
    for cap in ae._COMPILED_CAPS:
        for pat in cap["patterns"]:
            for m in pat["re"].finditer(text):
                out.append((cap["id"], pat["id"], m.start(), m.group(0)[:60]))
                break          # 每个模式每文件只取第一处，够做分布统计
    return out


def main():
    print("=" * 100)
    print("P0.5 · 完整文件上的 role 分布")
    print("=" * 100)

    grand = Counter()
    by_conf = Counter()
    rows = []
    for tag, path in TARGETS:
        if not os.path.exists(path):
            print("\n[缺] %s" % path)
            continue
        text = open(path, encoding="utf-8", errors="ignore").read()
        print("\n" + "#" * 100)
        print("# %s  %s  (%.1f MB)" % (tag, os.path.basename(path), len(text) / 1048576))
        hs = hits_in(text)
        print("# lexical 命中（每模式取首处）：%d 条" % len(hs))

        dist = Counter()
        for cap_id, pat_id, pos, token in hs:
            r = probe(text, token, 0)
            dist[r["role"]] += 1
            grand[r["role"]] += 1
            by_conf[(r["role"], r["confidence"])] += 1
            rows.append({"tag": tag, "file": os.path.basename(path),
                         "cap": cap_id, "pat": pat_id,
                         "token": token, "role": r["role"],
                         "conf": r["confidence"], "reason": r["reason"],
                         "container": r["container"],
                         "consumers": r["consumer_kinds"]})
        tot = sum(dist.values()) or 1
        for role, n in dist.most_common():
            print("   %-20s %4d  (%.0f%%)" % (role, n, 100.0 * n / tot))

    print("\n" + "=" * 100)
    print("总体 role 分布（全部目标）")
    print("=" * 100)
    tot = sum(grand.values()) or 1
    for role, n in grand.most_common():
        bar = "#" * int(40.0 * n / tot)
        print("  %-20s %5d  %5.0f%%  %s" % (role, n, 100.0 * n / tot, bar))

    known = sum(n for r, n in grand.items() if r != "unknown")
    print("\n  → 有依据的 role: %d / %d = %.0f%%" % (known, tot, 100.0 * known / tot))
    print("  → unknown: %d / %d = %.0f%%" % (tot - known, tot, 100.0 * (tot - known) / tot))

    print("\n" + "=" * 100)
    print("置信度分布")
    print("=" * 100)
    for (role, conf), n in sorted(by_conf.items(), key=lambda x: -x[1]):
        print("  %-20s %-8s %4d" % (role, conf, n))

    print("\n" + "=" * 100)
    print("抽样：非 unknown 的判定依据（前 25 条）")
    print("=" * 100)
    shown = 0
    for r in rows:
        if r["role"] == "unknown" or shown >= 25:
            continue
        shown += 1
        print("  [%s] %s / %s" % (r["role"], r["tag"], r["cap"]))
        print("     token=%r  容器=%s  消费者=%s" % (
            r["token"][:40], r["container"], r["consumers"]))
        print("     依据: %s" % r["reason"])

    with open(str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "p05" / "_measure.json"), "w",
              encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
