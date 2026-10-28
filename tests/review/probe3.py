#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""对真实 app.asar 独立复算：扫描覆盖面的实际损失。"""
import os, sys, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import agentegress as A

ASAR = r"refs/ZCode/resources/app.asar"
ar = A.AsarArchive(ASAR)
n = 0
by_lang = {}
skipped_lang = 0
skipped_min = 0
skipped_vendor = 0
skipped_large = 0
scanned = 0
vendor_bytes = 0
firstparty_bytes = 0
# 关键证据所在位置统计
KEY = [b"upload-credential", b"snapshot/upload", b"x-oss-signature",
       b"createCipheriv", b"aes-256-gcm", b"Local State", b"Network" + b"/Cookies",
       b".git/objects"]
loc = {k: {"firstparty": 0, "vendor": 0} for k in KEY}

for rel, item in ar.iter_files():
    n += 1
    low = A._norm(rel)
    size = int(item.get("size", 0) or 0)
    is_vendor = any(v in low for v in A.M3_VENDOR_PARTS)
    lang = A.detect_lang(rel)
    if is_vendor:
        vendor_bytes += size
    else:
        firstparty_bytes += size

    if lang == "other" or rel.endswith((".map", ".min.js", ".min.css")):
        if rel.endswith((".min.js", ".min.css")):
            skipped_min += 1
        else:
            skipped_lang += 1
        continue
    if is_vendor:
        skipped_vendor += 1
        continue
    if size > 8 * 1024 * 1024:
        skipped_large += 1
        continue
    scanned += 1

    # 只对非 vendor 文件读内容查证据
    blob = ar.read(rel, item, 8 * 1024 * 1024) or b""
    for k in KEY:
        if k in blob:
            loc[k]["firstparty"] += 1

# vendor 侧同口径（只统计含关键词的文件数，抽样上限）
vend_hits = {k: 0 for k in KEY}
cnt = 0
for rel, item in ar.iter_files():
    low = A._norm(rel)
    if not any(v in low for v in A.M3_VENDOR_PARTS):
        continue
    if A.detect_lang(rel) == "other":
        continue
    cnt += 1
    if cnt > 6000:
        break
    blob = ar.read(rel, item, 8 * 1024 * 1024) or b""
    for k in KEY:
        if k in blob:
            vend_hits[k] += 1

print("asar 条目总数(含目录外文件)      : %d" % n)
print("默认路径实际扫描文件数            : %d" % scanned)
print("  因扩展名/lang=other 被跳过      : %d" % skipped_lang)
print("  因 .min.js/.min.css 被跳过      : %d" % skipped_min)
print("  因第三方区被跳过                : %d" % skipped_vendor)
print("  因 >8MB 被跳过                  : %d" % skipped_large)
print("第三方字节 %s / 自研字节 %s" % (A.human(vendor_bytes), A.human(firstparty_bytes)))
print()
print("关键证据串出现在『自研区』的文件数：")
for k in KEY:
    print("   %-18s 自研=%d   node_modules(≤6000抽样)=%d"
          % (k.decode(), loc[k]["firstparty"], vend_hits[k]))
