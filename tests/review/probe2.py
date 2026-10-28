#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os, sys, io
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import agentegress as A

print("=1= 负 offset 的异常类型（POSIX 会 ValueError，Windows 可能 OSError）")
try:
    with open(__file__, "rb") as f:
        f.seek(-5)
    print("   seek(-5) 未抛异常")
except Exception as e:
    print("   seek(-5) -> %s: %s" % (type(e).__name__, e))

print()
print("=2= >8MB 文件是否被跳过（skipped_large 且不计入 files_scanned）")
import tempfile, shutil
d = os.path.join(tempfile.gettempdir(), "ae_probe2"); shutil.rmtree(d, ignore_errors=True); os.makedirs(d)
big = b"var x=1;\n" * 1300000 + b'var s="upload-credential";'
print("   文件实际大小 %.2f MB" % (len(big)/1048576))
open(os.path.join(d, "huge.js"), "wb").write(big)
acc = A.CapabilityAccumulator()
_h, meta = A.audit_path(d, acc=acc)
print("   files_scanned=%s skipped_large=%s hits=%s caps=%s"
      % (meta["files_scanned"], meta["skipped_large"], acc.total_hits,
         sorted({b['cap'] for b in acc.buckets.values()})))

print()
print("=3= detect_lang 跳过的常见扩展名（这些文件根本不进入扫描）")
for ext in [".env", ".html", ".htm", ".vue", ".svelte", ".txt", ".ini",
            ".sql", ".rb", ".php", ".cs", ".kt", ".swift", ".json5", ".xml"]:
    print("   %-8s -> %s" % (ext, A.detect_lang("x" + ext)))

print()
print("=4= 预筛（_KW_FILTER）的真实选择性：在真实源码树上统计")
root = str(Path(__file__).resolve().parents[2] / "refs" / "ZCode" / "packages" / "services" / "src")
if not os.path.isdir(root):
    print("   跳过：需要先 git clone ZCode 到 refs/ZCode（见 README「参考样本」）")
    root = None
tot = passed = useless = hits_files = 0
for dp, dn, fn in ([] if root is None else os.walk(root)):
    for f in fn:
        p = os.path.join(dp, f)
        if A.detect_lang(p) in ("other",):
            continue
        try:
            t = open(p, "rb").read().decode("utf-8", "ignore")
        except OSError:
            continue
        tot += 1
        if A._KW_FILTER.search(t) is not None:
            passed += 1
            if not A.scan_text_for_capabilities(p, t, A.detect_lang(p)):
                useless += 1
print("   参与预筛文件 %d；通过预筛 %d (%.1f%%)；通过但零命中 %d (占通过数 %.1f%%)"
      % (tot, passed, 100.0*passed/max(1,tot), useless, 100.0*useless/max(1,passed)))

print()
print("=5= 哪些关键词最'廉价'（在真实源码里出现它的文件数）")
from collections import Counter
cnt = Counter()
allkw = sorted({k.lower() for v in A.PATTERN_KEYWORDS.values() for k in v})
for dp, dn, fn in os.walk(root):
    for f in fn:
        p = os.path.join(dp, f)
        if A.detect_lang(p) in ("other",): continue
        try: t = open(p, "rb").read().decode("utf-8", "ignore").lower()
        except OSError: continue
        for k in allkw:
            if k in t: cnt[k] += 1
for k, v in cnt.most_common(15):
    print("   %-18s 出现在 %d/%d 个文件" % (repr(k), v, tot))

print()
print("=6= shell_execution 理论最高分")
m = sum(p["w"] for p in next(c for c in A.CAPABILITY_DEFS if c["id"]=="shell_execution")["patterns"])
print("   权重和 = %.1f，confirmed 门槛 = 18 -> 永远不可能 confirmed" % m)
