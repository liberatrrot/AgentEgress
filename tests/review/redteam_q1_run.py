# -*- coding: utf-8 -*-
"""Q1 跑分：基线 vs 逃逸样本，并量化「预筛」这一层。"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as A          # noqa: E402
import redteam_harness as H      # noqa: E402

S = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")


def probe_prefilter(rel):
    p = os.path.join(S, rel)
    raw = open(p, "rb").read()
    text = A.decode_bytes(raw)
    low = text.lower()
    hit = A._prefilter_hit(text)
    fired = [k for k in A._KW_TUPLE if k in low]
    print("  文件            : %s" % rel)
    print("  预筛放行        : %s" % hit)
    print("  命中的预筛关键词: %s" % (fired if fired else "（无）"))
    # 逐 pattern 看有没有正则命中（绕过预筛）
    n = 0
    for cap in A._COMPILED_CAPS:
        for pat in cap["patterns"]:
            if pat["re"].search(text):
                n += 1
    print("  正则层原生命中数: %d 条 pattern" % n)
    # 强制绕过预筛后再扫（monkeypatch）
    orig = A._prefilter_hit
    A._prefilter_hit = lambda t: True
    try:
        forced = A.scan_text_for_capabilities(rel, text, "js", bundled=False)
    finally:
        A._prefilter_hit = orig
    print("  强制绕过预筛后  : %d 条命中" % len(forced))
    return hit, n, len(forced)


CASES = [
    ("基线恶意客户端（危险字符串以完整字面量出现）", "q1_baseline", False),
    ("逃逸A-部分混淆：只拆了「标识符类」字面量（默认配置）", "q1_evade_split", False),
    ("逃逸A2-完全混淆：所有危险字面量运行时拼装（默认配置）", "q1_evade_splitfull", False),
    ("逃逸C：逻辑一字未改，仅在文件头塞注释耗尽 6 个匹配额度（默认配置）", "q1_evade_comment", False),
    ("逃逸B：把同一份逻辑放进 node_modules（默认配置）", "q1_evade_vendor", False),
    ("逃逸B 对照：--include-vendor 打开", "q1_evade_vendor", True),
]

print("#" * 78)
print("# 第一部分：预筛层量化")
print("#" * 78)
for rel in ("q1_baseline/src/main.js",
            "q1_evade_split/src/main.js",
            "q1_evade_splitfull/src/main.js",
            "q1_evade_vendor/node_modules/totally-legit-helper/index.js"):
    probe_prefilter(rel)
    print()

print("#" * 78)
print("# 第二部分：端到端结论")
print("#" * 78)
for title, d, iv in CASES:
    r = H.scan_dir(os.path.join(S, d), include_vendor=iv)
    H.dump(r, title + ("  [include_vendor=True]" if iv else ""))
    print()

print("#" * 78)
print("# 第三部分：被预筛拒绝的文件，在覆盖台账里算什么？")
print("#" * 78)
for d in ("q1_baseline", "q1_evade_splitfull"):
    rejected = {"n": 0}
    orig = A._prefilter_hit

    def counting(t, _o=orig, _r=rejected):
        if not _o(t):
            _r["n"] += 1
            return False
        return True

    A._prefilter_hit = counting
    try:
        r = H.scan_dir(os.path.join(S, d))
    finally:
        A._prefilter_hit = orig
    c = r["coverage"]
    print("样本 %-22s 候选 %d -> 台账显示「实扫」%d ；其中被预筛拦掉 %d 个"
          % (d, c["candidates"], c["scanned"], rejected["n"]))
    print("      gaps（因技术原因未覆盖）= %d ；M3 结论 = %s / %s"
          % (c["gaps"], r["summary"]["verdict"], r["summary"]["text"]))

