# -*- coding: utf-8 -*-
"""A2：穷举核对所有手工维护的映射表 / 白名单 / 关键词表。"""
import os
import sys
import re

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

issues = []


def note(tag, msg):
    issues.append("[%s] %s" % (tag, msg))
    print("[%s] %s" % (tag, msg))


print("=" * 70)
print("A2-1  PATTERN_KEYWORDS vs CAPABILITY_DEFS")
ids_def = [p["id"] for c in ae.CAPABILITY_DEFS for p in c["patterns"]]
ids_kw = list(ae.PATTERN_KEYWORDS.keys())
print("pattern 数=%d  关键词表条目=%d" % (len(ids_def), len(ids_kw)))
print("  定义里有的 id 但关键词表没有:", sorted(set(ids_def) - set(ids_kw)))
print("  关键词表里有但定义没有(死条目):", sorted(set(ids_kw) - set(ids_def)))
dup = [i for i in set(ids_def) if ids_def.count(i) > 1]
print("  重复 pattern id:", sorted(dup))
if set(ids_def) - set(ids_kw):
    note("A2-1", "pattern 缺关键词")
if set(ids_kw) - set(ids_def):
    note("A2-1", "关键词表存在死条目（永不生效）")
if dup:
    note("A2-1", "pattern id 重复，累加器键碰撞（同 id 不同权重会被合并）: %s" % sorted(dup))

print()
print("=" * 70)
print("A2-2  CAP_WEIGHT_SUM 复算")
recomputed = {c["id"]: sum(p["w"] for p in c["patterns"]) for c in ae.CAPABILITY_DEFS}
print("  模块内:", ae.CAP_WEIGHT_SUM)
print("  复算  :", recomputed)
if recomputed != ae.CAP_WEIGHT_SUM:
    note("A2-2", "CAP_WEIGHT_SUM 与定义不一致")
else:
    print("  一致")

print()
print("=" * 70)
print("A2-3  权重取值域（文档称 1-10）")
for c in ae.CAPABILITY_DEFS:
    for p in c["patterns"]:
        if not (1 <= p["w"] <= 10):
            note("A2-3", "%s 权重 %d 越界" % (p["id"], p["w"]))
print("  检查完毕")

print()
print("=" * 70)
print("A2-4  FILE_CLASS_WEIGHT vs classify_file 返回值")
probe = [
    ("/src/a.js", False), ("/out/a.js", False), ("/dist/a.js", False),
    ("/node_modules/x/a.js", False), ("/node_modules/x/a.js", True),
    ("/vendor/x/a.js", True), ("/third-party/x/a.js", True), ("/third_party/x/a.js", True),
    ("/.pnpm/x/a.js", True), ("/.pnpm/x/a.js", False),
    ("/a.d.ts", False), ("/readme.md", False), ("/cfg.json", False),
    ("/tests/a.js", False), ("/fixtures/a.js", False), ("/weird.xyz", False),
]
returned = set()
for rel, bundled in probe:
    r = ae.classify_file(rel, bundled=bundled)
    returned.add(r)
    print("  classify_file(%-26r bundled=%-5s) -> %s" % (rel, bundled, r))
missing = returned - set(ae.FILE_CLASS_WEIGHT)
print("  classify_file 会返回但 FILE_CLASS_WEIGHT 没有的类:", sorted(missing))
if missing:
    note("A2-4", "权重表缺类，会走默认 0.6 兜底: %s" % sorted(missing))

print()
print("=" * 70)
print("A2-4b  M3_VENDOR_PARTS vs classify_file 的 vendor 判定集合")
mv = set(ae.M3_VENDOR_PARTS)
cf = {"/node_modules/", "/vendor/", "/third_party/", "/third-party/"}
print("  M3_VENDOR_PARTS      =", sorted(mv))
print("  classify_file(vendor)=", sorted(cf))
print("  只在 M3_VENDOR_PARTS 有 :", sorted(mv - cf))
print("  只在 classify_file 有   :", sorted(cf - mv))
if mv != cf:
    note("A2-4b", "两处 vendor 集合不一致：%s" % sorted(mv ^ cf))

print()
print("=" * 70)
print("A2-5  目录目标的 vendor 跳过是否真能生效（relpath 无前导 /）")
tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_v2_dir_vendor")
nm = os.path.join(tmp, "node_modules", "evil")
os.makedirs(nm, exist_ok=True)
with open(os.path.join(nm, "leak.js"), "w", encoding="utf-8") as f:
    f.write("createCipheriv('aes-256-gcm');fetch('/upload/credential');"
            "const m=require('snapshot/upload');")
rel = os.path.relpath(os.path.join(nm, "leak.js"), tmp)
print("  os.path.relpath 结果 =", repr(rel))
print("  _norm(rel)          =", repr(ae._norm(rel)))
print("  任一 M3_VENDOR_PARTS 命中? ",
      [(v, v in ae._norm(rel)) for v in ae.M3_VENDOR_PARTS])
acc = ae.CapabilityAccumulator()
_h, meta = ae.audit_path(tmp, acc=acc)
print("  audit_path(目录) meta: candidates=%s scanned=%s skipped_vendor=%s"
      % (meta["candidates"], meta["files_scanned"], meta["skipped_vendor"]))
if meta["skipped_vendor"] == 0 and meta["files_scanned"] > 0:
    note("A2-5", "目录目标下的 /node_modules/ 完全没被跳过（skipped_vendor=0，仍扫描 %d 个文件）"
         % meta["files_scanned"])
ascii_ = os.path.join(tmp, "ok.asar")
print()

print("=" * 70)
print("A2-6  _LANG_BY_EXT 覆盖的扩展名 vs 真实客户端可能出现的源码类型")
exts = set(ae._LANG_BY_EXT)
print("  已覆盖:", sorted(exts))
缺失 = [".vue", ".rb", ".php", ".cs", ".swift", ".kt", ".scala", ".lua",
        ".pl", ".r", ".dart", ".erl", ".hs", ".clj", ".groovy", ".jl", ".m", ".mm"]
missing_ext = [e for e in 缺失 if e not in exts]
print("  未覆盖但属于常见源码:", missing_ext)
t = os.path.join(tmp, "probe.vue")
with open(t, "w", encoding="utf-8") as f:
    f.write("createCipheriv('aes-256-ctr'); fetch('/upload/credential');")
print("  detect_lang('probe.vue') =", ae.detect_lang("probe.vue"))
acc2 = ae.CapabilityAccumulator()
_h2, m2 = ae.audit_path(tmp, acc=acc2, max_files=100)
lv = {c["id"]: c["level"] for c in ae.aggregate_from_buckets(acc2)}
print("  同一目录（含 .vue）扫完 capabilities:", {k: v for k, v in lv.items() if v != "absent"})
print("  meta candidates=%s scanned=%s" % (m2["candidates"], m2["files_scanned"]))
if ae.detect_lang("probe.vue") == "other":
    note("A2-6", ".vue 等扩展名被 detect_lang 判为 other —— audit_path 会在【未计入 candidates】的情况下 continue，"
                "文件既没被扫也没进覆盖台账")

print()
print("=" * 70)
print("A2-7  AUTO_SIGNALS / USER_SIGNALS 是否互相包含（触发推断互相抵消）")
both = []
for w in ["setInterval", "setTimeout", "bootstrap", "initialize", "schedule",
          "subscribe", "watch(", "dialog", "confirm(", "menuItem"]:
    a = bool(ae.AUTO_SIGNALS.search(w))
    u = bool(ae.USER_SIGNALS.search(w))
    if a and u:
        both.append(w)
    print("  %-14s auto=%-5s user=%s" % (w, a, u))
if both:
    note("A2-7", "同一词同时被 auto/user 命中: %s" % both)

print()
print("=" * 70)
print("A2-8  指纹库 audit_paths 指向的文件是否存在")
for t in ae.DEFAULT_FINGERPRINTS["tools"]:
    for p in t.get("audit_paths", []):
        ep = ae.expand(p)
        print("  %-14s %-70s exists=%s" % (t["id"], ep, os.path.exists(ep)))

print()
print("=" * 70)
print("A2-9  EXCLUDE / SAFE 列表与 STRONG/WEAK 列表的自相矛盾检查")
overlap = set(ae.SAFE_EXT) & set(ae.STRONG_EXT)
print("  SAFE_EXT ∩ STRONG_EXT =", sorted(overlap))
if overlap:
    note("A2-9", "同一扩展名既被放行又被当作强特征: %s" % sorted(overlap))
print("  STRONG_NAME_PARTS =", ae.STRONG_NAME_PARTS)
print("  WEAK_NAME_PARTS   =", ae.WEAK_NAME_PARTS)
print("  STRONG ∩ WEAK     =", sorted(set(ae.STRONG_NAME_PARTS) & set(ae.WEAK_NAME_PARTS)))

print()
print("=" * 70)
print("汇总：%d 条可疑项" % len(issues))
for i in issues:
    print("  " + i)
