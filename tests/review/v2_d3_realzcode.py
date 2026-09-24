# -*- coding: utf-8 -*-
"""D3 / A1：真实样本上，base 偏移 bug 对结论的影响。

同一份 ZCode app.asar：
  A) 用工具现在的 base（16+json_size）
  B) 把 base 修成 16+align4(json_size)
比较两次的能力等级与文件内容。
"""
import os
import struct
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

TARGET = r"refs/ZCode\resources\app.asar"
if not os.path.exists(TARGET):
    print("样本不存在")
    sys.exit(0)


def run(label):
    t0 = time.perf_counter()
    acc = ae.CapabilityAccumulator()
    _h, meta = ae.audit_path(TARGET, acc=acc)
    dt = time.perf_counter() - t0
    caps = ae.aggregate_from_buckets(acc)
    lv = {c["id"]: (c["level"], c["score"], c["pattern_count"], c["file_count"])
          for c in caps}
    print("[%s] %.1f s  scanned=%s candidates=%s skipped_large=%s skipped_vendor=%s "
          "skipped_ext=%s truncated=%s errors=%d"
          % (label, dt, meta["files_scanned"], meta["candidates"],
             meta["skipped_large"], meta["skipped_vendor"], meta["skipped_ext"],
             meta["truncated"], len(meta["errors"])))
    for k in sorted(lv):
        print("    %-26s %-10s score=%-7s pat=%-2s files=%s" % ((k,) + lv[k]))
    sm = ae.summarize_capabilities(caps)
    print("    summary: verdict=%s confirmed=%d likely=%d possible=%d"
          % (sm["verdict"], sm["confirmed"], sm["likely"], sm["possible"]))
    return lv, sm


print("=" * 78)
print("A) 工具现状 base=16+json_size")
with open(TARGET, "rb") as f:
    a, b, c, d = struct.unpack("<IIII", f.read(16))
print("   json_size=%d  mod4=%d  工具 base=%d  真实 base=%d" % (d, d % 4, 16 + d, 16 + ((d + 3) // 4 * 4)))
lv_a, sm_a = run("A 现状")

print()
print("=" * 78)
print("B) 修正 base 后")
orig_init = ae.AsarArchive.__init__


def patched(self, path):
    orig_init(self, path)
    with open(path, "rb") as f:
        _a, _b, _c, js = struct.unpack("<IIII", f.read(16))
    self.base = 16 + ((js + 3) // 4 * 4)


ae.AsarArchive.__init__ = patched
lv_b, sm_b = run("B 修正")
ae.AsarArchive.__init__ = orig_init

print()
print("=" * 78)
print("两次差异")
allk = sorted(set(lv_a) | set(lv_b))
for k in allk:
    la = lv_a.get(k, ("absent", 0, 0, 0))
    lb = lv_b.get(k, ("absent", 0, 0, 0))
    mark = "  <<< 不同" if la[0] != lb[0] else ""
    print("  %-26s A=%-10s(%.2f)  B=%-10s(%.2f)%s" % (k, la[0], la[1], lb[0], lb[1], mark))
print("  A: confirmed=%d likely=%d possible=%d" % (sm_a["confirmed"], sm_a["likely"], sm_a["possible"]))
print("  B: confirmed=%d likely=%d possible=%d" % (sm_b["confirmed"], sm_b["likely"], sm_b["possible"]))
