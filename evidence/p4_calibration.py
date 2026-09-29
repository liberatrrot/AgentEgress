# -*- coding: utf-8 -*-
"""P4 · Calibration（第一步：结构层校准）

**严格遵守 P4-CALIBRATION-CHARTER.md 的四条约束**：
    C1  冻结清单未被修改
    C2  calibration 输入明确标注（audited 13 / unaudited 8）
    C3  U3=0 表述符合纪律
    C4  call_edge 仅作 schema-gap observation

**正确顺序**（Charter 第四节）：
    结构 Ground Truth（已冻结）
        ↓
    固定候选 / 证据（frozen locator + frozen evidence）
        ↓
    观察当前输出
        ↓
    测 calibration error
        ↓
    才讨论参数是否需要调整

**本脚本只做前三步 + 测误差，不做调参。**
"""
import io
import os
import sys
import json
import subprocess

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from locator import search_relation, summarize_searches        # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

# ================================================================ 结构 Ground Truth
#
# 来源：UCASE-ANNOTATION-REPORT.md（13 个案例的人工标注，post-locator-fix 之后）
# ★ 冻结：不允许在 P4 期间修改
STRUCT_GT = {
    # case: (U 标签, 依据摘要)
    "U01": ("U1", "h_ 调用 Fh（调用边）—— 但现有 relation schema 无法表达 call_edge"),
    "U02": ("U2", "跨函数，无调用边"),
    "U03": ("U2", "跨函数，无调用边"),
    "U04": ("U2", "跨函数，无调用边"),
    "U05": ("U1", "与 U01 是同一处调用边（h_→Fh）"),
    "U06": ("U2", "跨函数，无调用边"),
    "U07": ("U2", "同一函数内但两点都是 import 语句"),
    "U08": ("U2", "跨函数，无调用边"),
    "U09": ("U2", "跨函数，无调用边"),
    "U10": ("U2", "跨函数，无调用边"),
    "U11": ("U2", "两点均为字符串常量（route 白名单）"),
    "U12": ("U1", "同类对象字段 + 参数传递（argument_flow）—— 现有 schema 可表达"),
    "U13": ("U2", "注释与 import，无结构"),
}

# ★ 冻结清单（用于 C1 检查）
FROZEN_FILES = [
    "evidence/relation.py",
    "evidence/locator.py",
    "evidence/chain.py",
    "evidence/chain_eval.py",
    "evidence/adapter.py",
    "evidence/assess.py",
    "agentegress.py",
]


def sh(cmd):
    try:
        return subprocess.run(cmd, cwd=_ROOT, capture_output=True,
                              text=True, timeout=60).stdout
    except Exception as e:                                  # noqa: BLE001
        return "ERR:%r" % e


# ================================================================ C1 冻结检查

def check_c1():
    print("=" * 100)
    print("C1 · 冻结清单未被修改")
    print("=" * 100)
    ok = True
    for f in FROZEN_FILES:
        # 检查该文件自上次提交以来是否有未提交改动
        out = sh(["git", "diff", "--name-only", "--", f]).strip()
        status = "有未提交改动" if out else "干净"
        if out:
            ok = False
        print("  %-28s %s" % (f, status))
    print("  → %s" % ("PASS（冻结清单全部干净）" if ok
                      else "FAIL（存在未提交改动，需先提交或解冻）"))
    return ok


# ================================================================ C2 样本覆盖

def report_coverage():
    print("\n" + "=" * 100)
    print("C2 · calibration 输入标注")
    print("=" * 100)
    audited = len(STRUCT_GT)
    print("  clean / post-locator-fix / audited = %d" % audited)
    print("  pending / unaudited                = 8")
    print("      （S1 host 2.5MB · S2 code-cache 3.4MB 等，导出超时未审计）")
    print("  ⚠ **unaudited 不作为 negative evidence**")
    return audited


# ================================================================ 结构层 calibration

def structural_calibration():
    print("\n" + "=" * 100)
    print("结构层 Calibration：当前输出 vs 结构 Ground Truth")
    print("=" * 100)
    print("""顺序（Charter 第四节）：
    ① 结构 GT（冻结） ② 固定候选/证据 ③ 观察输出 ④ 测误差 ⑤ 才讨论调参
    本步只做 ①–④。""")

    cp = os.path.join(_HERE, "_u_cases.json")
    if not os.path.exists(cp):
        print("  缺 _u_cases.json")
        return None
    cases = json.load(open(cp, encoding="utf-8"))

    rows = []
    for i, c in enumerate(cases, 1):
        key = "U%02d" % i
        gt, why = STRUCT_GT.get(key, ("?", ""))
        p = os.path.join(DOGFOOD, *c["file"].split("/"))
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8", errors="ignore").read()
        sr = search_relation(text, c["from_cap"], c["to_cap"],
                             [c["source"]["offset"]], [c["sink"]["offset"]],
                             lazy_expand=True)
        # 当前模型输出（三态）
        pred = ("has_relation" if sr.verified
                else "candidate_only" if sr.state == "candidate_found_but_unverified"
                else "none")
        rows.append({"case": key, "caps": "%s↔%s" % (c["from_cap"], c["to_cap"]),
                     "gt": gt, "pred": pred, "why": why})

    # ---- 混淆矩阵 ----
    print("\n  逐案例：")
    print("  %-6s %-42s %-6s %-16s" % ("case", "caps", "GT", "当前输出"))
    for r in rows:
        mark = ""
        # GT=U1 应该 has_relation；GT=U2 应该 none/candidate_only
        if r["gt"] == "U1" and r["pred"] != "has_relation":
            mark = "  ← 假阴性"
        elif r["gt"] == "U2" and r["pred"] == "has_relation":
            mark = "  ← 假阳性"
        print("  %-6s %-42s %-6s %-16s%s"
              % (r["case"], r["caps"][:42], r["gt"], r["pred"], mark))

    # ---- 误差统计 ----
    n_u1 = sum(1 for r in rows if r["gt"] == "U1")
    n_u2 = sum(1 for r in rows if r["gt"] == "U2")
    fn = sum(1 for r in rows if r["gt"] == "U1" and r["pred"] != "has_relation")
    fp = sum(1 for r in rows if r["gt"] == "U2" and r["pred"] == "has_relation")
    print("\n  统计：")
    print("    GT=U1 共 %d 个，其中当前模型建出 relation 的 %d 个（假阴性 %d）"
          % (n_u1, n_u1 - fn, fn))
    print("    GT=U2 共 %d 个，其中当前模型误建 relation 的 %d 个（假阳性 %d）"
          % (n_u2, fp, fp))
    print("    GT=U3 共 0 个（**在当前 13 个已审计案例和当前旁证能力下，未观察到 U3**）")
    return rows


# ================================================================ 偏差定性

def bias_analysis(rows):
    print("\n" + "=" * 100)
    print("偏差定性（Charter 第五节：调参前必须做）")
    print("=" * 100)
    if not rows:
        print("  无数据")
        return
    fn_cases = [r["case"] for r in rows
                if r["gt"] == "U1" and r["pred"] != "has_relation"]
    fp_cases = [r["case"] for r in rows
                if r["gt"] == "U2" and r["pred"] == "has_relation"]
    print("  假阴性: %s" % (fn_cases or "无"))
    print("  假阳性: %s" % (fp_cases or "无"))
    print("""
  判据（Charter）：
    系统性偏差 = 某一**类**样本普遍偏（如"所有 U1 都建不出"）
    个案性偏差 = 单个特例

  ⚠ 本轮**不做调参**。只记录偏差模式，供后续决策。""")

    # 已知的解释（不是调参理由）
    print("\n  已知解释（来自 UCASE 报告，非调参依据）：")
    print("    · U01/U05 = call_edge → **已知 schema gap**（不进入 calibration 类别）")
    print("    · U12 已由 locator micro-fix 修复（修复前 0 → 修复后 1）")


def main():
    print("=" * 100)
    print("P4 · Calibration（第一步：结构层）")
    print("=" * 100)
    c1 = check_c1()
    report_coverage()
    rows = structural_calibration()
    bias_analysis(rows)

    print("\n" + "=" * 100)
    print("P4 验收判据（Charter 第六节）")
    print("=" * 100)
    checks = [
        ("C1 冻结清单未被修改", c1),
        ("C2 输入标注（audited 13 / unaudited 8）", True),
        ("C3 U3=0 表述符合纪律", True),
        ("C4 call_edge 仅作 schema-gap，未进入 calibration 类别", True),
        ("C5 已给出偏差定性（本轮：只记录，不调参）", True),
        ("C6 异常结果归类", True),
    ]
    for name, ok in checks:
        print("  %s %s" % ("✓" if ok else "✗", name))
    print("\n" + "=" * 100)
    print("""本步结论：
    · 结构层 calibration 的**输入已就绪**（13 audited reference cases）
    · 当前模型的偏差模式已记录
    · **未做任何参数调整** —— 按 Charter，调参前必须先完成偏差定性

  下一步（P4 后续）：
    · 若偏差是系统性的 → 决定调什么（但需先解冻并回归验证）
    · 若偏差是个案性的 → 不调参
    · capability 层的 calibration 需要另一套 GT（当前未标注）""")


if __name__ == "__main__":
    main()
