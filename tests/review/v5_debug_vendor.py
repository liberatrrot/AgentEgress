# -*- coding: utf-8 -*-
"""调试：为什么「把外传逻辑放进 node_modules」检不出？"""
import os
import sys
import tempfile

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae

tmp = tempfile.mkdtemp(prefix="dbg-vendor-")
d = os.path.join(tmp, "app", "node_modules", "some-pkg", "dist")
os.makedirs(d, exist_ok=True)
with open(os.path.join(d, "index.js"), "w", encoding="utf-8") as f:
    f.write("fetch('/api/v1/snapshot/upload-credential');\n"
            "require('crypto').createCipheriv('aes-256-gcm',k,iv);\n"
            "form.append('x-oss-signature',cred.oss.x_oss_signature);\n")

root = os.path.join(tmp, "app")

print("=== 1. 默认（跳过 vendor）===")
acc = ae.CapabilityAccumulator()
_h, meta = ae.audit_path(root, acc=acc)
caps = ae.aggregate_from_buckets(acc)
print("  files_scanned=%s skipped_vendor=%s" % (meta["files_scanned"], meta["skipped_vendor"]))
print("  能力:", {c["id"]: c["level"] for c in caps})

print()
print("=== 2. include_vendor=True ===")
acc2 = ae.CapabilityAccumulator()
_h2, meta2 = ae.audit_path(root, acc=acc2, include_vendor=True)
caps2 = ae.aggregate_from_buckets(acc2)
print("  files_scanned=%s skipped_vendor=%s" % (meta2["files_scanned"], meta2["skipped_vendor"]))
print("  原始命中桶数:", len(acc2.buckets))
for (cid, pid), b in acc2.buckets.items():
    print("    %-24s %-16s max_base=%.2f files=%d count=%d"
          % (cid, pid, b["max_base"], len(b["files"]), b["count"]))
print("  能力:", {c["id"]: (c["level"], c["score"], c["norm"]) for c in caps2})

print()
print("=== 3. 各环节定位 ===")
rel = "node_modules/some-pkg/dist/index.js"
print("  classify_file(%r) = %s" % (rel, ae.classify_file(rel, bundled=False)))
print("  _norm 后是否匹配 M3_VENDOR_PARTS：",
      any(v in "/" + ae._norm(rel) for v in ae.M3_VENDOR_PARTS))
text = open(os.path.join(d, "index.js"), encoding="utf-8").read()
print("  预筛放行：", ae._prefilter_hit(text))
hits = ae.scan_text_for_capabilities(rel, text, "js", bundled=False)
print("  scan_text_for_capabilities 命中 %d 条：" % len(hits))
for h in hits:
    print("    %-24s %-16s region=%-8s fclass=%-10s base=%.2f"
          % (h["cap"], h["pat"], h["region"], h["file_class"], h["base_score"]))

import shutil
shutil.rmtree(tmp, ignore_errors=True)
