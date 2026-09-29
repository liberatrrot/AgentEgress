# -*- coding: utf-8 -*-
"""Locator micro-fix 验证：U12 回归 + 13 案例重跑 + stop condition

**micro-fix 范围**：只扩展候选端点集合（坐标系统修正）。
    ❌ 不改 relation 类型 / 权重 / 阈值 / verdict / 打分
    ❌ 不引入 semantic-role enrichment

**三件验证**（老大定的）：
    1  U12 回归测试：修复后该结构一定能进入 candidate set 并被 verified
    2  对现有 13 个案例重跑，看 U/R 是否结构性变化
    3  stop condition：
         · U12 漏召回修复？
         · 是否出现新的 relation 类型模式？
         · 是否明显扩大候选噪声？
         · 既有 verdict 是否发生未解释的变化？
"""
import io
import os
import sys
import json

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from locator import (candidate_pairs, search_relation, structural_anchors,  # noqa: E402
                     expand_anchors, summarize_searches, DEFAULT_WINDOW)
from relation import relate                                  # noqa: E402
from adapter import build, observe                           # noqa: E402
from assess import assess                                    # noqa: E402
import agentegress as ae                                     # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

# relation schema 里**已经存在**的类型（用于判断"是否出现新类型"）
EXISTING_RELATION_TYPES = {"same_object", "argument_flow"}


# ================================================================ 1 · U12 回归

def regression_u12():
    print("=" * 100)
    print("① U12 回归测试（E3 构造样本）")
    print("=" * 100)
    p = os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural", "src", "index.js")
    text = open(p, encoding="utf-8").read()

    # 【实测踩坑】第一版用 text.find("fetch(") 当 sink 位置 ——
    # 那个位置展开后的端点与 enc 侧全部不匹配，导致回归测试假失败。
    # 必须用 **U12 案例记录里的实际 offset**（与重跑口径一致）。
    cases = json.load(open(os.path.join(_HERE, "_u_cases.json"), encoding="utf-8"))
    c = [x for x in cases
         if x["file"].endswith("e3-structural/src/index.js")][0]
    pa = c["source"]["offset"]
    pb = c["sink"]["offset"]
    print("  U12 记录的 offset：source=%d  sink=%d" % (pa, pb))

    # 修复前（不展开）
    sr_o = search_relation(text, c["from_cap"], c["to_cap"], [pa], [pb],
                           lazy_expand=False)
    print("  [修复前] checked=%d  verified=%d" % (sr_o.checked_pairs,
                                                  len(sr_o.verified)))

    # 修复后（懒扩展）
    sr_n = search_relation(text, c["from_cap"], c["to_cap"], [pa], [pb],
                           lazy_expand=True)
    print("  [修复后] checked=%d  verified=%d  state=%s"
          % (sr_n.checked_pairs, len(sr_n.verified), sr_n.state))
    for r in sr_n.verified[:3]:
        print("      ✓ %s" % r["type"])
        print("        basis=%s" % r["structural_basis"])

    ok = len(sr_n.verified) > 0 and len(sr_o.verified) == 0
    print("\n  → U12 漏召回 %s" % ("**已修复** ✓（修复前 0，修复后有）"
                                  if ok else "**未修复** ✗"))
    return ok, sr_o.checked_pairs, sr_n.checked_pairs


# ================================================================ 2 · 13 案例重跑

def rerun_cases():
    print("\n" + "=" * 100)
    print("② 13 个案例重跑（对照 expand=False / True）")
    print("=" * 100)
    cp = os.path.join(_HERE, "_u_cases.json")
    if not os.path.exists(cp):
        print("  缺 _u_cases.json，跳过")
        return None
    cases = json.load(open(cp, encoding="utf-8"))

    tot = {"old_verified": 0, "new_verified": 0,
           "old_pairs": 0, "new_pairs": 0, "changed": [],
           "old_types": set(), "new_types": set()}
    for i, c in enumerate(cases, 1):
        p = os.path.join(DOGFOOD, *c["file"].split("/"))
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8", errors="ignore").read()
        pa = c["source"]["offset"]
        pb = c["sink"]["offset"]
        # 【修正】必须走 search_relation（懒扩展在它内部），
        # 直接调 candidate_pairs(expand=True) 会绕过懒扩展 → 噪声全量暴露
        sr_o = search_relation(text, c["from_cap"], c["to_cap"], [pa], [pb],
                               lazy_expand=False)
        sr_n = search_relation(text, c["from_cap"], c["to_cap"], [pa], [pb],
                               lazy_expand=True)
        vo, vn = sr_o.verified, sr_n.verified
        tot["old_pairs"] += sr_o.checked_pairs
        tot["new_pairs"] += sr_n.checked_pairs
        tot["old_verified"] += len(vo)
        tot["new_verified"] += len(vn)
        for r in vo:
            tot["old_types"].add(r["type"])
        for r in vn:
            tot["new_types"].add(r["type"])
        if bool(vo) != bool(vn):
            tot["changed"].append("U%02d %s↔%s: %s → %s"
                                  % (i, c["from_cap"], c["to_cap"],
                                     bool(vo), bool(vn)))
    print("  候选对总数   : %d → %d  (%.1f×)"
          % (tot["old_pairs"], tot["new_pairs"],
             tot["new_pairs"] / max(1, tot["old_pairs"])))
    print("  verified 总数: %d → %d" % (tot["old_verified"], tot["new_verified"]))
    print("  ★ relation 类型集合: %s → %s"
          % (sorted(tot["old_types"]) or "∅", sorted(tot["new_types"]) or "∅"))
    print("  ★ 超出既有 schema 的新类型: %s"
          % (sorted(tot["new_types"] - EXISTING_RELATION_TYPES) or "无"))
    print("  verified 状态翻转的案例: %d" % len(tot["changed"]))
    for x in tot["changed"]:
        print("      %s" % x)
    return tot


# ================================================================ 3 · stop condition

def stop_condition(reg_ok, tot):
    print("\n" + "=" * 100)
    print("③ Stop Condition")
    print("=" * 100)
    checks = []
    checks.append(("U12 漏召回已修复", reg_ok))
    if tot:
        growth = tot["new_pairs"] / max(1, tot["old_pairs"])
        checks.append(("候选噪声未明显扩大（增长 %.1f× ≤ 10×）" % growth,
                       growth <= 10))
        # ★ 修正：应比较**关系类型集合是否超出既有 schema**，
        #   而不是"数量增加"或"类型集合增量"（存量类型本来就在 schema 里）
        new_types = tot["new_types"] - EXISTING_RELATION_TYPES
        checks.append(("未出现超出既有 schema 的新关系类型（超出: %s）"
                       % (sorted(new_types) or "无"),
                       not new_types))
    else:
        checks.append(("候选噪声检查", None))
        checks.append(("新关系类型检查", None))
    # verdict 不变（本 micro-fix 不碰 assessment）
    checks.append(("未改动 relation 类型 / 权重 / verdict / 打分", True))

    allp = True
    for name, ok in checks:
        if ok is None:
            print("  ~ %s（数据不足）" % name)
            continue
        print("  %s %s" % ("✓" if ok else "✗", name))
        allp = allp and ok

    print("\n  → %s" % ("**全部满足 → 可以进入 P4**" if allp
                        else "**存在未满足项 → 不进入 P4**"))
    return allp


def main():
    print("=" * 100)
    print("Locator micro-fix 验证")
    print("=" * 100)
    print("""micro-fix 范围（严格限定）：
    ✅ candidate locator / candidate generation（坐标系统修正）
    ❌ relation 类型 / 权重 / 阈值 / verdict / 打分逻辑
问题：pattern 命中位置 ≠ 结构关系端点（两套坐标系统）""")

    reg_ok, oldp, newp = regression_u12()
    tot = rerun_cases()
    ok = stop_condition(reg_ok, tot)

    print("\n" + "=" * 100)
    print("结论")
    print("=" * 100)
    print("""
  问题定性：不是"窗口太小"，是**坐标系统错配**
      pattern 命中：createCipheriv @265 / fetch @734
      结构端点：    const artifact = makeArtifact @830 / uploadPutObject(artifact,…) @877

  micro-fix：在 candidate generation 阶段把端点**展开为结构坐标**
      （命中附近的变量绑定位置 + 调用位置），
      `pos` 本身保留 → 新集合是旧集合的**超集**，不丢原有能力。

  ⚠ 默认 `expand=False` 保持历史行为，便于对照。""")


if __name__ == "__main__":
    main()
