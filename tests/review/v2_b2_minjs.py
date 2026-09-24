# -*- coding: utf-8 -*-
"""B2：被「设计内跳过」的压缩产物里到底有多少能有命中。

audit_path 对 .min.js / .map / .min.css 走 skipped_ext 分支直接 continue，
coverage 把它标注成「设计内跳过：压缩产物」并【不计入 gaps】，
summarize_capabilities 的 miss 也不含它 —— 因此结论不会因此降级。
本脚本把这些被跳过的文件真的读出来跑一遍，看会命中什么。
"""
import os
import struct
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

TARGET = r"refs/ZCode\resources\app.asar"
ar = ae.AsarArchive(TARGET)
with open(TARGET, "rb") as f:
    _a, _b, _c, d = struct.unpack("<IIII", f.read(16))
ar.base = 16 + ((d + 3) // 4 * 4)          # 用修正后的 base，避免偏移干扰

skipped = []
for rel, item in ar.iter_files():
    lang = ae.detect_lang(rel)
    if lang == "other":
        skipped.append((rel, item, "lang=other（既没进 candidates 也没进 skipped_ext）"))
        continue
    if rel.endswith((".map", ".min.js", ".min.css")):
        skipped.append((rel, item, "skipped_ext（设计内跳过，不计入 gaps）"))

print("被跳过的文件总数: %d" % len(skipped))
from collections import Counter  # noqa: E402
c = Counter(s[2] for s in skipped)
for k, v in c.items():
    print("   %-50s %d" % (k, v))
print()

hits_any = []
total_hits = 0
for rel, item, why in skipped:
    blob = ar.read(rel, item)
    if not blob:
        continue
    text = ae.decode_bytes(blob)
    if not text:
        continue
    h = ae.scan_text_for_capabilities(rel, text, ae.detect_lang(rel), bundled=True)
    if h:
        total_hits += len(h)
        hits_any.append((rel, why, len(h),
                         sorted({x["cap"] for x in h})))

print("在这些被跳过的文件里，scan_text_for_capabilities 会产生的命中:")
print("   命中文件数 = %d / %d，命中总条数 = %d" % (len(hits_any), len(skipped), total_hits))
for rel, why, n, caps in sorted(hits_any, key=lambda x: -x[2])[:25]:
    print("   %-70s %-5d %s" % (rel[:70], n, caps))
if not hits_any:
    print("   （无）")
