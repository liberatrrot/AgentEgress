# -*- coding: utf-8 -*-
"""A2（补）：目录目标的 vendor 跳过、以及「未计入 candidates 的静默跳过」。

只在一个干净目录里放探针文件，避免 node_modules 已被 SKIP_DIRS 拦掉造成混淆。
"""
import os
import shutil
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_v2_probe")
shutil.rmtree(ROOT, ignore_errors=True)

PAYLOAD = ("createCipheriv('aes-256-gcm');"
           "fetch('/upload/credential');"
           "const m=require('snapshot/upload');"
           "x=repo_snapshot;")


def put(rel, body=PAYLOAD):
    p = os.path.join(ROOT, rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(body)
    return p


print("=" * 72)
print("实验 1：directory 目标下，M3_VENDOR_PARTS 是否真的拦得住")
for sub in ("vendor", "third_party", "third-party", ".pnpm", "node_modules"):
    put("%s/leak.js" % sub)
put("first/ok.js")

rel_vendor = os.path.relpath(os.path.join(ROOT, "vendor", "leak.js"), ROOT)
print("  目录分支用的 rel = %r" % rel_vendor)
print("  _norm(rel)=%r  含 '/vendor/'? %s"
      % (ae._norm(rel_vendor), "/vendor/" in ae._norm(rel_vendor)))

acc = ae.CapabilityAccumulator()
_h, meta = ae.audit_path(ROOT, acc=acc, max_files=100)
print("  audit_path(目录) -> candidates=%s scanned=%s skipped_vendor=%s skipped_large=%s"
      % (meta["candidates"], meta["files_scanned"], meta["skipped_vendor"], meta["skipped_large"]))
lv = {c["id"]: c["level"] for c in ae.aggregate_from_buckets(acc)}
print("  能力等级:", {k: v for k, v in lv.items() if v != "absent"})
print("  → 若 skipped_vendor=0 而 scanned>0，说明目录分支的 vendor 白名单是空转")

print()
print("=" * 72)
print("实验 2：classify_file 对这些路径给出的类别与权重")
for sub in ("vendor", "third_party", "third-party", ".pnpm", "node_modules", "first"):
    rel = "%s/leak.js" % sub
    cls = ae.classify_file(rel, bundled=False)
    print("  %-16s -> %-12s w=%s" % (rel, cls, ae.FILE_CLASS_WEIGHT.get(cls)))

print()
print("=" * 72)
print("实验 3：未覆盖的扩展名是否在 candidates 里留下痕迹")
shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)
with open(os.path.join(ROOT, "a.js"), "w", encoding="utf-8") as f:
    f.write(PAYLOAD)
with open(os.path.join(ROOT, "b.vue"), "w", encoding="utf-8") as f:
    f.write(PAYLOAD)
with open(os.path.join(ROOT, "c.rb"), "w", encoding="utf-8") as f:
    f.write(PAYLOAD)
with open(os.path.join(ROOT, "d"), "w", encoding="utf-8") as f:
    f.write(PAYLOAD)
with open(os.path.join(ROOT, "e.min.js"), "w", encoding="utf-8") as f:
    f.write(PAYLOAD)
with open(os.path.join(ROOT, "f.map"), "w", encoding="utf-8") as f:
    f.write(PAYLOAD)

acc2 = ae.CapabilityAccumulator()
_h2, m2 = ae.audit_path(ROOT, acc=acc2, max_files=100)
print("  目录里有 6 个文件：a.js / b.vue / c.rb / d(无扩展名) / e.min.js / f.map")
print("  meta: candidates=%s scanned=%s skipped_ext=%s skipped_vendor=%s skipped_large=%s truncated=%s errors=%s"
      % (m2["candidates"], m2["files_scanned"], m2["skipped_ext"],
         m2["skipped_vendor"], m2["skipped_large"], m2["truncated"], m2["errors"]))
cov_like = m2["skipped_large"] + (1 if m2["truncated"] else 0) + len(m2["errors"])
print("  按 summarize_capabilities 的算法，gaps=%d" % cov_like)
print("  candidates 只统计到 %d 个（6 个文件里 3 个根本没进台账）" % m2["candidates"])
print("  未被任何计数器覆盖的文件: b.vue / c.rb / d(无扩展名)")

shutil.rmtree(ROOT, ignore_errors=True)
