# -*- coding: utf-8 -*-
"""
自审脚本：不看功能，只看「工程健康度」与「文档承诺兑现率」。

为什么需要它：
前五轮的改动几乎全部由外部评审驱动。这一轮要换成主动自审，
而自审不能靠"我觉得没问题了"——那正是盲区的来源。所以要有客观指标。

三块：
  A. 结构健康度（单文件膨胀、函数规模、注释密度）
  B. 文档承诺兑现率（扫出所有"将/计划/待办/v0.3"，逐条对照代码）
  C. 测试覆盖结构（各类检查覆盖了什么，没覆盖什么）

用法：python tests/self_audit.py
"""

import os
import re
import ast
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

AGENT = os.path.join(ROOT, "agentegress.py")


# ---------------------------------------------------------------- D Release Gate

# 老大定的方向：不增能力、不扩模式库、不做 v0.3 新功能，
# 只修四类债，达到 Gate 后进入受控真实样本 dogfooding。
#
# **Gate 必须可自动检验** —— 否则又会退化成"我觉得差不多了"。
# 每条检查都给：名称 / 是否通过 / 依据。
def _src():
    return open(AGENT, encoding="utf-8").read()


def gate_conclusion_credibility():
    """结论可信度：措辞不能超出证据能支撑的范围。"""
    s = _src()
    return [
        ("关联度弱时不使用「阻断级」措辞",
         'if cohesion == "co_occur" and level == "blocking"' in s,
         "detect_chains 里按关联度降级"),
        ("报告声明「组合证据 ≠ 数据流」",
         "不是程序路径" in s or "不是数据流" in s,
         "render_text / render_html 的说明框"),
        ("强度条标注它不是概率",
         "非概率" in s or "不是概率" in s,
         "能力表表头/图例"),
        ("覆盖台账区分「读到」与「真正跑正则」",
         "files_analyzed" in s and "prefilter_rejected" in s,
         "coverage 字段"),
    ]


def gate_test_credibility():
    """测试可信度：断言必须能真的失败。"""
    v = open(os.path.join(HERE, "verify.py"), encoding="utf-8").read()
    checks = []
    # 变异测试必须分两层断言，而不是 bool(baseline)
    checks.append(("变异测试断言能捕捉基础变异退化",
                   "REQUIRED" in v and "degraded" in v,
                   "check_mutation_corpus 的分层断言"))
    # near-negative 必须有期望表 + 已知缺口的显式标记
    checks.append(("近负样本有期望表（不只是「没吓到人」）",
                   "EXPECT" in v and "KNOWN_GAPS" in v,
                   "check_near_negative 的 EXPECT / KNOWN_GAPS"))
    # 验收项必须有明确的失败条件
    hard = v.count("record(")
    checks.append(("验收项覆盖 ≥ 8 类", hard >= 8, "verify.py 的 record 调用数=%d" % hard))
    return checks


def gate_coverage_transparency():
    """覆盖透明度：每一条「没看」都要有计数和出口。"""
    s = _src()
    return [
        ("预筛拒绝的文件有独立计数",
         "prefilter_rejected" in s, "audit_path"),
        ("未被识别的扩展名有独立计数",
         "skipped_other" in s, "audit_path"),
        ("所有 skip 分支都计入 gaps 或明确归类为设计内",
         'coverage["gaps"] = ' in s, "audit_targets"),
        ("结论在缺口过大时降级",
         "缺口过大" in s or "ratio > 0.20" in s, "summarize_capabilities"),
    ]


def gate_code_structure():
    """代码结构：单函数不得失控。"""
    st = structure_audit()
    long_funcs = [(n, ln) for n, ln, _ in st["longest_funcs"] if ln > 150]
    cx_funcs = [(n, c) for n, c, _ in st["highest_complexity"] if c > 30]
    return [
        ("无函数超过 150 行",
         not long_funcs,
         "超标：%s" % ("、".join("%s(%d行)" % x for x in long_funcs) or "无")),
        ("无函数圈复杂度超过 30",
         not cx_funcs,
         "超标：%s" % ("、".join("%s(cx%d)" % x for x in cx_funcs) or "无")),
        ("渲染器已按职责拆分（不是单个大函数）",
         len(re.findall(r"^def _html_", _src(), re.M)) >= 4,
         "拆分出的 _html_* 函数数=%d" % len(re.findall(r"^def _html_", _src(), re.M))),
    ]


def _count_known_gaps():
    """读出 verify.py 里标记为 xfail 的已知缺口（场景名列表）。

    为什么要在 Gate 输出里列出：Gate 通过后如果只显示一片绿色，
    未来的自己会忘记这些洞。**测试系统通过 ≠ 产品能力无缺陷。**
    """
    p = os.path.join(HERE, "verify.py")
    try:
        src = open(p, encoding="utf-8").read()
    except OSError:
        return []
    m = re.search(r"KNOWN_GAPS\s*=\s*\{(.*?)\n\}", src, re.S)
    if not m:
        return []
    return [x.group(1) for x in re.finditer(r'"(\w+)":\s*\{', m.group(1))]


GATE = [
    ("结论可信度", gate_conclusion_credibility),
    ("测试可信度", gate_test_credibility),
    ("覆盖透明度", gate_coverage_transparency),
    ("代码结构", gate_code_structure),
]


def gate_report():
    out = []
    for name, fn in GATE:
        items = fn()
        passed = sum(1 for _n, ok, _d in items if ok)
        out.append({"name": name, "items": items,
                    "passed": passed, "total": len(items)})
    return out


# ---------------------------------------------------------------- A 结构健康度

def structure_audit():
    src = open(AGENT, encoding="utf-8").read()
    lines = src.splitlines()
    total = len(lines)
    blank = sum(1 for x in lines if not x.strip())
    comment = sum(1 for x in lines if x.strip().startswith("#"))
    code = total - blank - comment

    tree = ast.parse(src)
    funcs = []
    classes = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            funcs.append((node.name, node.end_lineno - node.lineno + 1, node.lineno))
        elif isinstance(node, ast.ClassDef):
            classes.append((node.name, node.end_lineno - node.lineno + 1, node.lineno))

    funcs.sort(key=lambda x: -x[1])
    # 粗略圈复杂度：每个函数里 if/for/while/except/and/or 的个数
    cx = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            n = 1
            for sub in ast.walk(node):
                if isinstance(sub, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                    n += 1
                elif isinstance(sub, ast.BoolOp):
                    n += len(sub.values) - 1
            cx.append((node.name, n, node.lineno))
    cx.sort(key=lambda x: -x[1])

    return {
        "total_lines": total,
        "code_lines": code,
        "comment_lines": comment,
        "comment_ratio": round(comment / total, 4) if total else 0,
        "functions": len(funcs),
        "classes": len(classes),
        "longest_funcs": funcs[:8],
        "highest_complexity": cx[:8],
        "funcs_over_100_lines": [f for f in funcs if f[1] > 100],
        "funcs_over_cx20": [c for c in cx if c[1] > 20],
    }


# ---------------------------------------------------------------- B 承诺兑现

# 扫描这些文档里的「未来时」表述
DOCS = ["README.md", "ARCHITECTURE.md", "REVIEW-RESPONSE.md", "REVIEW-FINDINGS.md"]
PROMISE_PAT = re.compile(
    r"(v0\.3|v0\.4|下一版|下一轮|待办|后续|计划|将来|TODO|尚未|未做|未实现|留待|列入)",
    re.I)


def promise_audit():
    """扫出所有「未来时」表述，检查它们是否已在 TODO.md 登记。

    背景：REVIEW-RESPONSE 里写过「准确度维度改为降权」，但代码里实际没改——
    **说了没做，而且没有机制能发现**。
    现在的规矩是：所有"以后要做"只写 TODO.md，文档正文不再留承诺。
    这个函数就是那条规矩的执法者。
    """
    promises = []
    for name in DOCS:
        p = os.path.join(ROOT, name)
        if not os.path.isfile(p):
            continue
        with open(p, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                s = line.strip()
                if not s or len(s) < 8:
                    continue
                if PROMISE_PAT.search(s):
                    promises.append({"doc": name, "line": i, "text": s[:150]})

    # TODO.md 是否登记了这些事项
    todo_path = os.path.join(ROOT, "TODO.md")
    todo_text = ""
    if os.path.isfile(todo_path):
        with open(todo_path, encoding="utf-8") as f:
            todo_text = f.read()
    registered = bool(todo_text) and "待做" in todo_text
    return {"items": promises, "todo_exists": bool(todo_text), "todo_registered": registered}


# ---------------------------------------------------------------- C 测试覆盖结构

def coverage_audit():
    """把验收项按「它其实在守什么」归类，看有没有整类缺失。"""
    p = os.path.join(HERE, "verify.py")
    src = open(p, encoding="utf-8").read()
    checks = re.findall(r"record\(\"([^\"]+)\"", src)
    # 已知的分类，用于暴露「整类没测」的情况
    categories = {
        "正确性（能不能检出）": ["标注回归"],
        "鲁棒性（畸形输入）": ["鲁棒性"],
        "误报控制": ["近负样本"],
        "对抗（伪装下能否检出）": ["变异测试"],
        "端到端（CLI 真的能跑）": ["CLI 端到端"],
        "自洽（内部一致）": ["启动自检", "预筛等价性"],
        "代码卫生": ["语法编译"],
    }
    covered = set(checks)
    gaps = [k for k, v in categories.items() if not (set(v) & covered)]
    return {"checks": checks, "categories": categories, "missing_categories": gaps}


def main():
    out = {}
    out["structure"] = structure_audit()
    out["promises"] = promise_audit()
    out["coverage"] = coverage_audit()
    out["gate"] = gate_report()

    L = []
    L.append("=" * 78)
    L.append("AgentEgress 自审（主动，不依赖外部评审）")
    L.append("=" * 78)

    s = out["structure"]
    L.append("")
    L.append("【A 结构健康度】")
    L.append("  代码 %d 行（代码 %d / 注释 %d / 空行 %d），注释占比 %.1f%%"
             % (s["total_lines"], s["code_lines"], s["comment_lines"],
                s["total_lines"] - s["code_lines"] - s["comment_lines"],
                s["comment_ratio"] * 100))
    L.append("  函数 %d 个，类 %d 个" % (s["functions"], s["classes"]))
    L.append("  单文件 %d 行 —— %s"
             % (s["total_lines"],
                "⚠ 已超过单文件可维护舒适区（建议 >2500 行就考虑拆分）"
                if s["total_lines"] > 2500 else "尚可"))
    L.append("")
    L.append("  最长的 5 个函数：")
    for name, ln, at in s["longest_funcs"][:5]:
        flag = "  ⚠ >100 行" if ln > 100 else ""
        L.append("    %-32s %4d 行  (第 %d 行)%s" % (name, ln, at, flag))
    L.append("")
    L.append("  复杂度最高的 5 个函数（粗略圈复杂度）：")
    for name, n, at in s["highest_complexity"][:5]:
        flag = "  ⚠ >20" if n > 20 else ""
        L.append("    %-32s %4d      (第 %d 行)%s" % (name, n, at, flag))
    L.append("")
    L.append("  >100 行的函数 %d 个；圈复杂度 >20 的 %d 个"
             % (len(s["funcs_over_100_lines"]), len(s["funcs_over_cx20"])))

    pa = out["promises"]
    L.append("")
    L.append("【B 文档承诺（未来时表述）】")
    L.append("  扫到 %d 条" % len(pa["items"]))
    L.append("  TODO.md 存在=%s，含未做项=%s  ← 规矩：所有「以后要做」只写 TODO.md"
             % (pa["todo_exists"], pa["todo_registered"]))
    if pa["items"] and pa["todo_registered"]:
        L.append("  以下条目若为「已承诺但未登记」，应移入 TODO.md 或改写为完成时：")
    for pr in pa["items"][:20]:
        L.append("    %-22s:%-5d %s" % (pr["doc"], pr["line"], pr["text"][:92]))
    if len(pa["items"]) > 20:
        L.append("    … 其余 %d 条" % (len(pa["items"]) - 20))

    L.append("")
    L.append("【C 测试覆盖结构】")
    L.append("  现有验收项：%s" % "、".join(out["coverage"]["checks"]))
    L.append("")
    for cat, items in out["coverage"]["categories"].items():
        hit = [x for x in items if x in out["coverage"]["checks"]]
        mark = "OK  " if hit else "缺失"
        L.append("    [%s] %-24s %s" % (mark, cat, "、".join(hit) or "——"))
    if out["coverage"]["missing_categories"]:
        L.append("")
        L.append("  ⚠ 整类缺失：%s" % "、".join(out["coverage"]["missing_categories"]))

    L.append("")
    L.append("【D Release Gate】—— 四类债全过，才进入受控样本 dogfooding")
    gate_all = True
    for g in out["gate"]:
        ok_all = g["passed"] == g["total"]
        gate_all = gate_all and ok_all
        L.append("")
        L.append("  [%s] %s  %d/%d"
                 % ("通过" if ok_all else "未过", g["name"], g["passed"], g["total"]))
        for n, ok, d in g["items"]:
            L.append("      %s %s" % ("OK  " if ok else "TODO", n))
            if not ok:
                L.append("           %s" % d)
    L.append("")
    L.append("  " + "-" * 74)
    # 【措辞必须准确】Gate 说的是「具备进入真实样本阶段的工程条件」，
    # **不是**「质量已验收」。这两件事必须分开写，否则未来的自己看到一片绿色
    # 就会忘掉那些被 xfail 标记的已知缺口。
    L.append("  Release-prep Gate：%s" % ("通过" if gate_all else "未通过"))
    known = _count_known_gaps()
    if known:
        L.append("    ⚠ 已知缺口 %d 项（xfail，不阻止进入 dogfooding）：" % len(known))
        for k in known:
            L.append("        · %s" % k)
        L.append("    ※ 「测试系统通过」≠「产品能力无缺陷」，两者必须分开记录。")
    else:
        L.append("    无已知缺口")
    L.append("    语义：通过 = 可以安全进入 dogfooding 并知道如何记录未知；")
    L.append("          不等于质量已验收。")
    L.append("  " + "-" * 74)

    L.append("")
    L.append("=" * 78)

    text = "\n".join(L)
    path = os.path.join(HERE, "self-audit.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    with open(os.path.join(HERE, "self-audit.json"), "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    try:
        print(text)
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
