# -*- coding: utf-8 -*-
"""A3：阈值 / 系数是否让某条分支永远不可达。"""
import itertools
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

print("=" * 74)
print("A3-1  GRADE_THRESHOLDS 可达性：norm = Σ(w·rf·fw·diversity) / wsum")
print("      可达上界取 rf=1(代码/any 区)、fw=1(production)、diversity=1(≥5 文件)")

for cap in ae.CAPABILITY_DEFS:
    wsum = ae.CAP_WEIGHT_SUM[cap["id"]]
    # 每个 pattern 的最大单项贡献
    items = []
    for p in cap["patterns"]:
        rf = 0.85 if p["region"] == "string" else 1.0
        items.append((p["id"], p["w"], p["w"] * rf, p["region"]))
    items.sort(key=lambda x: -x[2])
    best3 = sum(x[2] for x in items[:3])
    best_all = sum(x[2] for x in items)
    max_norm_any = best_all / wsum
    # 门槛要求 patterns >= 3 —— 这是【下界】不是等式，所以可用全部模式。
    # 只有「全部模式都用上仍够不到 0.55」才算数学上不可达。
    max_norm_1 = items[0][2] / wsum
    can_possible = max_norm_any >= 0.12
    can_likely = max_norm_any >= 0.30
    can_confirmed = max_norm_any >= 0.55 and len(items) >= 3
    print("  %-26s wsum=%-3d 最强单项=%.3f 恰好3项=%.3f 全部=%.3f  "
          "possible=%-5s likely=%-5s confirmed=%s"
          % (cap["id"], wsum, max_norm_1, best3 / wsum, max_norm_any,
             can_possible, can_likely, can_confirmed))

print()
print("  → 判定：只要「全部模式都用上」够得到 0.55，confirmed 就不算数学不可达")
unreach = []
for cap in ae.CAPABILITY_DEFS:
    wsum = ae.CAP_WEIGHT_SUM[cap["id"]]
    items = sorted(((p["w"] * (0.85 if p["region"] == "string" else 1.0), p["id"])
                    for p in cap["patterns"]), reverse=True)
    if sum(x[0] for x in items) / wsum < 0.55:
        unreach.append((cap["id"], sum(x[0] for x in items) / wsum))
    # 另外单列「恰好 3 个模式时够不到」的能力（说明 confirmed 至少需要 4+ 个模式）
    b3 = sum(x[0] for x in items[:3]) / wsum
    if b3 < 0.55 <= sum(x[0] for x in items) / wsum:
        print("     [confirmed 至少需要 4 个模式] %s  恰好3项=%.3f < 0.55" % (cap["id"], b3))
if unreach:
    print("     [数学不可达 confirmed] %s" % unreach)
else:
    print("     confirmed 在数学上对全部 12 个能力可达（无不可达分支）")

print()
print("=" * 74)
print("A3-2  注释区（rf=0.15）单独命中时能达到的最高等级")
for cap in ae.CAPABILITY_DEFS:
    wsum = ae.CAP_WEIGHT_SUM[cap["id"]]
    best = max(p["w"] for p in cap["patterns"])
    n = best * 0.15 * 1.0 * (0.85 + 0.15)   # 5 文件满多样性
    print("  %-26s 单条注释最大 norm=%.4f  (possible 门槛 0.12) -> %s"
          % (cap["id"], n / wsum, "可达" if n / wsum >= 0.12 else "不可达"))

print()
print("=" * 74)
print("A3-3  _strength() 的封顶：文档称 0-100")
mx = 0
for lv in ("confirmed", "likely", "possible", "absent"):
    for pc in range(0, 12):
        mx = max(mx, ae._strength(lv, pc))
print("  在 level∈4 档 × pattern_count 0..11 的全部组合里，_strength 最大值 =", mx)
print("  base+min(28, pc*9) 的解析上界 =", 70 + 28, "→ 100 不可达")
print("  _bar 对 absent 仍画 max(4, 28)=28% 的条（absent 行不展示，故无影响）")

print()
print("=" * 74)
print("A3-4  summarize_capabilities 的 miss 公式是否与 gaps 一致")
src = None
import inspect  # noqa: E402
src = inspect.getsource(ae.summarize_capabilities)
import re  # noqa: E402
for line in src.splitlines():
    if "miss" in line or "gaps" in line or "read_errors" in line:
        print("   " + line.rstrip())

print()
print("  → 构造：只有 read_errors 不为 0、其余为 0 的 coverage")
cov = {"candidates": 100, "scanned": 99, "skipped_vendor": 0, "skipped_ext": 0,
       "skipped_large": 0, "truncated": False, "read_errors": 7}
cov["gaps"] = cov["skipped_large"] + (1 if cov["truncated"] else 0) + cov["read_errors"]
fake = [{"id": "workspace_snapshot", "name": "工作区全量快照", "risk": "high",
         "level": "confirmed", "hits": [], "pattern_count": 3, "file_count": 2,
         "trigger_hint": {"verdict": "unknown"}}]
s = ae.summarize_capabilities(fake, coverage=cov)
print("  coverage =", cov)
print("  verdict  =", s["verdict"])
print("  text     =", s["text"])
print("  → 结论文字里没有出现「未覆盖」限定，尽管 gaps=%d" % cov["gaps"])

print()
print("=" * 74)
print("A3-5  truncated 时 verdict 被强制 info —— 已确认能力是否被丢弃")
cov2 = {"candidates": 5000, "scanned": 2500, "skipped_vendor": 0, "skipped_ext": 0,
        "skipped_large": 0, "truncated": True, "read_errors": 0}
cov2["gaps"] = 1
s2 = ae.summarize_capabilities(fake, coverage=cov2)
print("  verdict =", s2["verdict"], " text =", s2["text"])
print("  同一份能力（workspace_snapshot=confirmed, risk=high）在 coverage=None 下：")
s3 = ae.summarize_capabilities(fake, coverage=None)
print("  verdict =", s3["verdict"], " text =", s3["text"])
print("  cap_level(truncated) =", ae.cap_level(s2))
print("  cap_level(正常)      =", ae.cap_level(s3))

print()
print("=" * 74)
print("A3-6  ratio 分母随「采样到的能力个数」变化")
for n in (1, 2, 12):
    caps = [{"id": "c%d" % i, "name": "c", "risk": "low", "level": "confirmed",
             "hits": [], "pattern_count": 3, "file_count": 2,
             "trigger_hint": {"verdict": "unknown"}} for i in range(n)]
    r = ae.summarize_capabilities(caps, coverage=None)
    print("  %2d 个 low 风险能力全部 confirmed -> ratio=%s verdict=%s" % (n, r["ratio"], r["verdict"]))
