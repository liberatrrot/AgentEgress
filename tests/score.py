#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgentEgress 阶段评分 —— 把「客观打分」落成可复算的公式

设计原则：
  · 每个维度都由一个可测量的量算出，没有主观印象分
  · 阈值写在明面上，谁都能复核、也能质疑
  · 同一份 bench JSON 输入，任何人跑都得到同样的分

用法：
  python tests/score.py tests/bench-before.json [tests/bench-after.json ...]
"""

import os
import sys
import json
import math

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# ---------------- 阈值表（改这里就是改评分标准，请谨慎） ----------------

# 速度分档：用「标准基准用例的端到端秒数」而不是吞吐率（MB/s）。
#
# 为什么不用吞吐率：优化后跳过了 82% 的第三方依赖字节，分母也变小了，
# 吞吐率看起来几乎没变（都是 0.7 MB/s）——它无法反映用户真正感知的「等了多久」。
# 端到端秒数才是用户感知量。
#
# 档位标定基准：ZCode 的 app.asar（自研代码 46 MB / 2731 个文件）
# 30 s 以内算优秀，240 s 以上算不可接受（用户不会有耐心等）。
SPEED_TIERS = [
    (30, 25), (60, 20), (120, 14), (240, 7), (float("inf"), 0),
]

# 内存分档：以「扫描 250 MB 归档」为参照系——峰值控制在归档体积的 1/4 以内算优秀。
# 档位刻意做细：内存是这类工具的硬约束（它本身要跑在用户机器上，不该占太多）。
MEM_TIERS = [
    (60, 15), (120, 12), (200, 9), (400, 5), (800, 2), (float("inf"), 0),
]

ACCURACY_POINTS = 40      # F1 × 40
COVERAGE_POINTS = 10      # 能力类覆盖率
VERIFIABILITY_POINTS = 10 # 回归基准 + 标注集是否齐备

CAPABILITY_COUNT = 12     # CAPABILITY_DEFS 里的能力类数


def _clopper_pearson(k, n, alpha=0.05):
    """Clopper–Pearson 精确区间的边界值。

    外部评审的硬伤级批评：4/4 全中的 95% 敏感度下限只有约 39.8%；
    0/1 无误报的误报率上限高达 97.5%。
    这个函数把这件事从"道理"变成"数字"，直接印在分数旁边。

    边界情况用闭式解（也是实际最常用的两个数字），避免数值方法在 a=b 上的退化：
        k = n : 下限 = (α/2)^(1/n)，上限 = 1
        k = 0 : 下限 = 0，上限 = 1 - (α/2)^(1/n)
    """
    if n <= 0:
        return 0.0, 1.0
    if k <= 0:
        return 0.0, 1.0 - (alpha / 2.0) ** (1.0 / n)
    if k >= n:
        return (alpha / 2.0) ** (1.0 / n), 1.0
    return (_beta_inv(alpha / 2.0, k, n - k + 1),
            _beta_inv(1 - alpha / 2.0, k + 1, n - k))


def _betainc(a, b, x):
    """正则化不完全 Beta 函数 I_x(a,b)（Lentz 连分数，标准实现）。"""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = (math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
             + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return math.exp(lbeta) * _betacf(a, b, x) / a
    return 1.0 - math.exp(lbeta) * _betacf(b, a, 1.0 - x) / b


def _betacf(a, b, x):
    """连分数展开（Lentz 算法）。"""
    tiny = 1e-30
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < tiny:
        d = tiny
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < tiny:
            d = tiny
        c = 1.0 + aa / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        de = d * c
        h *= de
        if abs(de - 1.0) < 1e-12:
            break
    return h


def _beta_inv(p, a, b):
    """Beta 分布分位数的数值反解（二分）。"""
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = (lo + hi) / 2.0
        if _betainc(a, b, mid) < p:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2.0


def score_accuracy(f1, tp=0, fn=0, fp=0, tn=0):
    """准确度得分 —— 同时给出「这个分数有多可信」。

    只报 F1 是误导：n=5 的满分与 n=500 的满分完全不是一回事。
    """
    if f1 is None:
        return 0.0, "F1 不可计算（该轮无正/负样本）"

    n_pos = tp + fn
    n_neg = fp + tn
    notes = []
    if n_pos:
        lo, _ = _clopper_pearson(tp, n_pos)
        notes.append("敏感度 %.1f%%（95%% 下限 %.1f%%，n=%d）"
                     % (100.0 * tp / n_pos, 100.0 * lo, n_pos))
    if n_neg:
        _, hi = _clopper_pearson(fp, n_neg)
        notes.append("误报率上限 %.1f%%（n=%d）" % (100.0 * hi, n_neg))

    sample = tp + fn + fp + tn
    warn = "  ⚠ 样本量 %d，不可外推" % sample if sample < 30 else ""
    detail = "F1=%.3f × %d；%s%s" % (f1, ACCURACY_POINTS, "；".join(notes), warn)
    return round(f1 * ACCURACY_POINTS, 1), detail


def score_speed(seconds):
    if not seconds:
        return 0.0, "无有效耗时数据"
    prev = 0
    for cap, pts in SPEED_TIERS:
        if seconds <= cap:
            return float(pts), "最重用例端到端 %.1f s（区间 %s–%s s）" % (
                seconds, prev, "∞" if cap == float("inf") else cap)
        prev = cap
    return 0.0, "端到端 %.1f s" % seconds


def score_memory(peak_bytes):
    if not peak_bytes:
        return None, "本轮未测内存（加 --mem）"
    mb = peak_bytes / 1048576
    prev = 0
    for cap_mb, pts in MEM_TIERS:
        if mb <= cap_mb:
            return float(pts), "峰值 %.1f MB（区间 %s–%s MB）" % (
                mb, prev, "∞" if cap_mb == float("inf") else cap_mb)
        prev = cap_mb
    return 0.0, "峰值 %.1f MB" % mb


def score_coverage():
    """能力类覆盖率：模式库是否覆盖了全部声明的能力类。"""
    sys.path.insert(0, ROOT)
    import agentegress as ae
    declared = {c["id"] for c in ae.CAPABILITY_DEFS}
    with_patterns = {c["id"] for c in ae.CAPABILITY_DEFS if c.get("patterns")}
    covered = len(declared & with_patterns)
    pts = round(COVERAGE_POINTS * covered / max(1, CAPABILITY_COUNT), 1)
    return pts, "%d/%d 类能力有检测模式" % (covered, CAPABILITY_COUNT)


def score_verifiability():
    """可验证性：有没有独立的回归依据。"""
    cases = os.path.join(HERE, "cases.json")
    bench = os.path.join(HERE, "bench.py")
    have_cases = os.path.isfile(cases)
    have_bench = os.path.isfile(bench)
    n_cases = 0
    if have_cases:
        try:
            with open(cases, "r", encoding="utf-8") as f:
                n_cases = len(json.load(f)["cases"])
        except Exception:
            pass
    if have_cases and have_bench and n_cases >= 3:
        return float(VERIFIABILITY_POINTS), "有标注集(%d 例) + 可复跑基准脚本" % n_cases
    if have_cases or have_bench:
        return VERIFIABILITY_POINTS / 2.0, "只有部分验证资产"
    return 0.0, "无验证资产"


def code_metrics():
    """代码规模与注释密度（参考数据，不计入总分）。"""
    path = os.path.join(ROOT, "agentegress.py")
    total = blank = comment = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                total += 1
                s = line.strip()
                if not s:
                    blank += 1
                elif s.startswith("#"):
                    comment += 1
    except OSError:
        pass
    code = total - blank - comment
    return {
        "total_lines": total,
        "code_lines": code,
        "comment_lines": comment,
        "blank_lines": blank,
        "comment_ratio": round(comment / total, 3) if total else 0,
    }


def score_report(report):
    agg = report["aggregate"]
    rows = []

    pts, why = score_accuracy(agg.get("f1"), agg.get("tp", 0), agg.get("fn", 0),
                              agg.get("fp", 0), agg.get("tn", 0))
    rows.append(("准确度", pts, ACCURACY_POINTS, why))

    max_sec = max((r.get("seconds", 0) for r in report["results"]), default=0)
    pts, why = score_speed(max_sec)
    rows.append(("速度", pts, SPEED_TIERS[0][1], why))

    peak = 0
    if report.get("measured_memory"):
        peak = max((r.get("peak_mem_bytes", 0) for r in report["results"]), default=0)
    pts, why = score_memory(peak)
    rows.append(("内存", pts, 15, why))

    pts, why = score_coverage()
    rows.append(("能力覆盖", pts, COVERAGE_POINTS, why))

    pts, why = score_verifiability()
    rows.append(("可验证性", pts, VERIFIABILITY_POINTS, why))

    scored = [r for r in rows if r[1] is not None]
    got = sum(r[1] for r in scored)
    possible = sum(r[2] for r in scored)
    total = round(100 * got / possible, 1) if possible else 0

    # ---- 第二条轴：证据成熟度 ----
    #
    # 外部评审指出的问题：把「工程完成度」和「这个工具的可信度」压成一个数字，
    # 会让读者把 89/100 读成「安全工具可靠度 89%」。
    # 拆成两条轴之后，工程进展仍可比较，而可信度单独呈现——
    # 两者本来就不该混在一起。
    n = agg.get("tp", 0) + agg.get("fn", 0) + agg.get("fp", 0) + agg.get("tn", 0)
    n_neg = agg.get("fp", 0) + agg.get("tn", 0)
    if n < 30:
        maturity = "Low"
    elif n < 100:
        maturity = "Medium"
    else:
        maturity = "High"
    # 负样本太少时再压一档：没有足够的负样本，「不误报」这个结论无从谈起
    if n_neg < 10 and maturity != "Low":
        maturity = "Medium" if maturity == "High" else maturity

    return rows, got, possible, total, maturity, n


def main():
    files = sys.argv[1:]
    if not files:
        print(__doc__)
        return 1

    print("=" * 84)
    print("AgentEgress 阶段评分   评分口径见 tests/score.py 顶部阈值表")
    print("=" * 84)

    summary = []
    for path in files:
        with open(path, "r", encoding="utf-8") as f:
            report = json.load(f)
        rows, got, possible, total, maturity, n = score_report(report)
        agg = report["aggregate"]
        print()
        print("### %s   (版本 %s, %s)"
              % (report.get("tag") or os.path.basename(path),
                 report.get("version"), report.get("time")))
        print("    吞吐 %.2f MB/s | %d 文件 / %.1f MB / %.1f s | P=%s R=%s F1=%s"
              % (agg["mb_per_sec"], agg["total_files"], agg["total_mb"],
                 agg["total_seconds"], agg["precision"], agg["recall"], agg["f1"]))
        print()
        print("    %-10s %8s %8s   %s" % ("维度", "得分", "满分", "依据"))
        print("    " + "-" * 76)
        for name, pts, mx, why in rows:
            shown = "—" if pts is None else ("%.1f" % pts)
            print("    %-10s %8s %8d   %s" % (name, shown, mx, why))
        print("    " + "-" * 76)
        print("    %-10s %8.1f %8d" % ("合计", got, possible))
        print()
        print("    ┌─ 两条轴，不要互相解释 ─────────────────────────────────────┐")
        print("    │ Engineering score : %5.1f / 100  （工程完成度）             │" % total)
        print("    │ Evidence maturity : %-6s        （证据成熟度，由样本量决定）│" % maturity)
        print("    └───────────────────────────────────────────────────────────┘")
        if maturity == "Low":
            print("      ※ 样本量 %d < 30：上面那个百分数**不可外推**，" % n)
            print("        它只说明这批用例被正确处理了，不说明真实世界性能。")
        summary.append((report.get("tag") or os.path.basename(path), total, agg, maturity))

    if len(summary) >= 2:
        print()
        print("=" * 84)
        print("阶段对比")
        print("=" * 84)
        base = summary[0]
        for tag, total, agg, mat in summary:
            delta = total - base[1]
            mark = "" if tag == base[0] else ("  (%+.1f)" % delta)
            print("  %-24s Eng %5.1f/100   Maturity %-6s  %5.2f MB/s%s"
                  % (tag, total, mat, agg["mb_per_sec"], mark))

    cm = code_metrics()
    print()
    print("代码度量（不计分）: %d 行（代码 %d / 注释 %d / 空行 %d），注释占比 %.1f%%"
          % (cm["total_lines"], cm["code_lines"], cm["comment_lines"],
             cm["blank_lines"], cm["comment_ratio"] * 100))
    return 0


if __name__ == "__main__":
    sys.exit(main())
