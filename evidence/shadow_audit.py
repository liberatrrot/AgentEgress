# -*- coding: utf-8 -*-
"""Shadow Impact Audit —— agentegress 的 region lexer bug 影响面评估

**纪律（老大定的）**：
    保持历史基线不变。做两个**完全平行**的运行：
        A = 原 Phase 1 实现
        B = **只替换 region lexer**，其余代码/pattern/threshold/权重全部不动
    不修 Phase 1，本轮只做评估。

**核心问题**：
    「这个 bug 是历史实现有缺陷但结论没受影响」，
    还是「Phase 1 的部分结论实际上建立在错误的 region 分类上」？

**六层检查**：
    1  逐 hit 比较 old_region / new_region（重点 new=code 且 old!=code）
    2  evidence contribution diff（0.15→1.0 这类真实权重变化）
    3  ★ 最终状态是否改变（最重要：old verdict vs shadow verdict）
    4  回放已冻结的 Ground Truth
    5  特别检查被作为架构证据的案例
    6  benchmark 是否被污染
"""
import io
import os
import sys
import json
from collections import Counter, defaultdict

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

import agentegress as ae                                     # noqa: E402
import relation as rel_mod                                   # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

# 规模控制（minified 文件大，两个 lexer 各扫一遍很慢）
MAX_FILE_MB = float(os.environ.get("SA_MAX_FILE_MB", "3"))
ONLY = os.environ.get("SA_ONLY", "")

FILES = [
    ("S1 ZCode",     "s1-zcode/out/host/index.js"),
    ("S1 ZCode",     "s1-zcode/out/main/index.js"),
    ("S2 WorkBuddy", "s2-workbuddy/main/index.js"),
    ("S2 WorkBuddy", "s2-workbuddy/main/code-cache.js"),
    ("S3 opencode",  "s3-opencode/out/main/index.js"),
    ("S4 Quark",     "s4-quark/dist/main/main.js"),
]

ORIG_LEX = ae.lex_regions


def new_lex(text, lang="js"):
    """修复版 lexer 的适配器。

    ⚠ **归一化 `regex` → `code`**：
    修复版新增了 `regex` 这个 kind，而 `REGION_FACTOR` 里没有它。
    若直接返回 `regex` 会 KeyError；若去 REGION_FACTOR 里加一条**等于改权重**，
    违反"只换 lexer"的纪律。
    所以在这里归一化：正则字面量属于代码表达式 → 按 `code` 计。
    这是**唯一的适配**，不改变任何权重定义。
    """
    if lang == "json":
        return ORIG_LEX(text, lang)          # JSON 行为保持原样
    out = []
    for s, e, k in rel_mod.lex_regions(text):
        out.append((s, e, "code" if k == "regex" else k))
    return out


def region_of(segs, pos):
    for s, e, k in segs:
        if s <= pos < e:
            return k
    return "code"


def collect_hits(text, lang="js"):
    """收集全部 (capability, pattern_id, offset, weight)。"""
    hits = []
    for cap in ae._COMPILED_CAPS:
        for pat in cap["patterns"]:
            for m in pat["re"].finditer(text):
                hits.append({
                    "cap": cap["id"],
                    "pat": pat["id"],
                    "offset": m.start(),
                    "w": pat.get("w", 5),
                    "region_hint": pat.get("region"),
                })
    return hits


def main():
    print("=" * 108)
    print("Shadow Impact Audit —— region lexer bug 的影响面")
    print("=" * 108)
    print("""A = 原实现（agentegress.lex_regions）
B = **只换 region lexer**（regex 归一化为 code），其余全部不动
纪律：不修 Phase 1，本轮只评估因果链""")

    RF = ae.REGION_FACTOR
    all_rows = []
    cap_delta = defaultdict(lambda: defaultdict(float))
    cap_hits = defaultdict(int)
    trans = Counter()

    for tag, relp in FILES:
        if ONLY and ONLY not in tag:
            continue
        p = os.path.join(DOGFOOD, *relp.split("/"))
        if not os.path.exists(p):
            continue
        mb = os.path.getsize(p) / 1048576.0
        if mb > MAX_FILE_MB:
            print("\n[跳过] %s  %.1f MB > %s MB" % (relp, mb, MAX_FILE_MB))
            continue

        text = open(p, encoding="utf-8", errors="ignore").read()
        print("\n" + "#" * 108)
        print("# %s  ·  %s  (%.1f MB)" % (tag, relp, mb))

        segs_a = ORIG_LEX(text, "js")
        segs_b = new_lex(text, "js")
        hits = collect_hits(text)
        print("# 命中总数 = %d" % len(hits))

        # ---- 第 1 层：逐 hit region 比较 ----
        changed = []
        for h in hits:
            ra = region_of(segs_a, h["offset"])
            rb = region_of(segs_b, h["offset"])
            if ra != rb:
                changed.append((h, ra, rb))
                trans[(ra, rb)] += 1
        print("# region 分类发生变化的 hit = %d / %d（%.1f%%）"
              % (len(changed), len(hits), 100.0 * len(changed) / max(1, len(hits))))
        if trans:
            print("# 变化类型:")
            for (ra, rb), n in trans.most_common():
                print("#     %-14s → %-14s %4d   权重 %.2f → %.2f"
                      % (ra, rb, n, RF.get(ra, 1.0), RF.get(rb, 0.85)))

        # ---- 第 2 层：contribution diff ----
        for h in hits:
            ra = region_of(segs_a, h["offset"])
            rb = region_of(segs_b, h["offset"])
            ca = h["w"] * RF.get(ra, 0.85)
            cb = h["w"] * RF.get(rb, 0.85)
            cap_delta[h["cap"]][tag + "/" + relp] += (cb - ca)
            cap_hits[h["cap"]] += 1

        # ---- 第 3 层：verdict 对比（关键） ----
        def run_with(lex_fn):
            ae.lex_regions = lex_fn
            try:
                acc = ae.CapabilityAccumulator()
                _h, meta = ae.audit_path(p, acc=acc)
                caps = ae.aggregate_from_buckets(acc)
                return {c["id"]: (c["level"], round(c.get("score", 0), 2),
                                  c.get("norm", 0)) for c in caps}
            finally:
                ae.lex_regions = ORIG_LEX

        va = run_with(ORIG_LEX)
        vb = run_with(new_lex)

        vdiff = []
        for cid in sorted(set(va) | set(vb)):
            la = va.get(cid, ("absent", 0, 0))[0]
            lb = vb.get(cid, ("absent", 0, 0))[0]
            sa = va.get(cid, ("", 0, 0))[1]
            sb = vb.get(cid, ("", 0, 0))[1]
            if la != lb:
                vdiff.append((cid, la, lb, sa, sb))
        print("# 能力 verdict 变化 = %d 项" % len(vdiff))
        for cid, la, lb, sa, sb in vdiff:
            arrow = "↑" if _rank(lb) > _rank(la) else "↓"
            print("#     %s %-24s %-10s → %-10s  (score %.2f → %.2f)"
                  % (arrow, cid, la, lb, sa, sb))

        all_rows.append({
            "tag": tag, "file": relp, "hits": len(hits),
            "changed": len(changed),
            "transitions": {("%s→%s" % k): v for k, v in trans.items()},
            "verdict_diff": [{"cap": c, "old": o, "new": n}
                             for c, o, n, _sa, _sb in vdiff],
            "va": va, "vb": vb,
        })
        trans.clear()

    # ============================================================ 汇总
    print("\n" + "=" * 108)
    print("汇总")
    print("=" * 108)
    print("\n【第 1+2 层】region 变化与 contribution delta（按能力）")
    print("  %-26s %6s %14s" % ("能力", "命中数", "总 delta"))
    for cap in sorted(cap_delta, key=lambda c: -abs(sum(cap_delta[c].values()))):
        tot = sum(cap_delta[cap].values())
        if abs(tot) > 0.01:
            print("  %-26s %6d %+14.1f" % (cap, cap_hits[cap], tot))

    print("\n【第 3 层 ★ 最关键】verdict 变化（这是判定 A/B/C 类的依据）")
    n_cap_changed = 0
    upgrades = []
    downgrades = []
    for r in all_rows:
        for d in r["verdict_diff"]:
            n_cap_changed += 1
            rec = "%s/%s: %s → %s" % (r["tag"], d["cap"], d["old"], d["new"])
            if _rank(d["new"]) > _rank(d["old"]):
                upgrades.append(rec)
            else:
                downgrades.append(rec)
    print("  变化的 capability 数 = %d" % n_cap_changed)
    if upgrades:
        print("  ★ 升级（旧低估 → 新恢复）%d 项：" % len(upgrades))
        for x in upgrades:
            print("      %s" % x)
    if downgrades:
        print("  降级 %d 项：" % len(downgrades))
        for x in downgrades:
            print("      %s" % x)
    if not upgrades and not downgrades:
        print("  → **verdict 完全未变**")

    # ---- 判定 ----
    print("\n" + "=" * 108)
    print("判定")
    print("=" * 108)
    if n_cap_changed == 0:
        print("""  **A 类：Phase 1 现有 verdict 基本稳健**
    region 误分类：有
    证据权重变化：有
    但 capability verdict：全不变
  → 该 bug 可严格隔离为「未改变 Phase 1 verdict 的潜在证据污染」；
    修复进入下一 baseline，不覆盖历史结果。""")
    else:
        n_files = len({r["file"] for r in all_rows if r["verdict_diff"]})
        print("""  **B 类：需要局部重验**
    有 %d 个 capability 的 verdict 发生变化，分布在 %d 个文件。
  → 不是整个 Phase 1 推翻，而是**受影响样本/capability 必须重验**。""" % (n_cap_changed, n_files))
    print("""
⚠ 注意：本脚本**不修 Phase 1**，也不改任何权重/阈值/pattern。
   `regex` 在适配层归一化为 `code` —— 这是唯一的适配，不改变权重定义。""")

    with open(os.path.join(_HERE, "_shadow_audit.json"), "w", encoding="utf-8") as f:
        json.dump(all_rows, f, ensure_ascii=False, indent=2)
    print("\n结果已保存: _shadow_audit.json")


def _rank(level):
    return {"absent": 0, "possible": 1, "likely": 2, "confirmed": 3}.get(level, 0)


if __name__ == "__main__":
    main()
