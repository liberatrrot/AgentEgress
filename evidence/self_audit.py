# -*- coding: utf-8 -*-
"""定时自检（Self-Audit）

**目的**：在进入 P2.1 之前，回头查一遍这几轮的工作有没有"看起来通过但其实有问题"的地方。

自检项（不靠印象，用代码查）：
    S1  所有 assert 是否可达（不是死代码）
    S2  测试里有没有硬编码的期望值（把实现结果抄成期望）
    S3  是否还有模块级可变共享状态
    S4  文档里的数字是否与代码/实测一致
    S5  断言是否只检查"存在"而不检查"内容"
    S6  未验证的断言（报告里说了但没测）
"""
import io
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

MODULES = ["schema.py", "state_algebra.py", "adapter.py", "assess.py",
           "relation.py", "chain.py", "chain_eval.py",
           "consistency_gate.py", "replay_gate.py", "replay_real_world.py"]
TESTS = ["test_invariants.py", "test_relation.py", "test_chain.py"]


def read(f):
    p = os.path.join(_HERE, f)
    return open(p, encoding="utf-8").read() if os.path.exists(p) else ""


def s1_asserts_reachable():
    """S1：assert 是否可达 —— 找"永远为真"的断言（如 assert True / assert x in (1,2) 恒真）。"""
    issues = []
    for f in MODULES:
        src = read(f)
        for m in re.finditer(r"assert\s+(.+)$", src, re.M):
            expr = m.group(1).strip()
            if expr in ("True", "1", "not False"):
                issues.append("%s: assert %s（恒真，等于没检查）" % (f, expr))
    return issues


def s2_hardcoded_expectations():
    """S2：测试里有没有"把实现输出抄成期望"的痕迹。

    特征：期望值出现魔法数字，或注释里有"实际是X所以期望X"。
    """
    issues = []
    for f in TESTS:
        src = read(f)
        # 期望里出现具体 score / norm 之类的数字
        for m in re.finditer(r'conf\s*=\s*\[?["\']([\w/]+)["\']', src):
            pass
        # 检查是否有 "实际是" 这类注释（说明期望被实现带偏过）
        for m in re.finditer(r"#.*(实际是|因为实现|所以期望)", src):
            issues.append("%s: %s" % (f, m.group(0).strip()[:70]))
    return issues


def s3_mutable_globals():
    """S3：模块级可变共享状态（id() 那类 bug 的高发区）。"""
    issues = []
    for f in MODULES:
        src = read(f)
        for m in re.finditer(r"^(_?[A-Za-z]\w*)\s*=\s*(\{\}|\[\]|set\(\)|dict\(\))\s*$",
                             src, re.M):
            name = m.group(1)
            # 排除常量表（全大写且不被写入）
            if name.isupper():
                continue
            # 检查是否被写入
            if re.search(re.escape(name) + r"\s*\[[^\]]+\]\s*=", src) or \
               re.search(re.escape(name) + r"\.(append|add|update|clear)\(", src):
                issues.append("%s: 模块级可变 %s（会被写入）" % (f, name))
    return issues


def s4_doc_number_consistency():
    """S4：报告里引用的数字能否在代码/实测里对上。"""
    issues = []
    docs = ["CONSISTENCY-GATE-REPORT.md", "REAL-WORLD-REPLAY-GATE-REPORT.md",
            "P2-REPORT.md", "P3-REPORT.md"]
    for d in docs:
        p = os.path.join(_HERE, d)
        if not os.path.exists(p):
            continue
        src = open(p, encoding="utf-8").read()
        # 找"共 N 项"/"N / M"形式
        for m in re.finditer(r"(\d+)\s*/\s*(\d+)\s*(?:PASS|通过)?", src):
            a, b = int(m.group(1)), int(m.group(2))
            if a > b:
                issues.append("%s: 分数 %d/%d 分子大于分母" % (d, a, b))
    return issues


def s5_assert_content_not_just_existence():
    """S5：断言是否只查"存在"不查"内容"。

    【自检工具自身的盲区】第一版只扫 `assert`，于是漏掉了
    consistency_gate.py 里的 `g.check("...", "字面量" in src)` ——
    那才是弱断言的真正所在地。自检工具自己也要被自检。
    """
    weak = []
    total = 0
    # 匹配两种形式：
    #   assert "x" in src
    #   g.check("desc", "x" in src[, detail])
    PAT_ASSERT = re.compile(r'assert\s+["\'][^"\']+["\']\s+in\s+\w*(?:src|source|text)\w*')
    PAT_CHECK = re.compile(
        r'g\.check\(\s*["\'][^"\']*["\']\s*,\s*["\'][^"\']+["\']\s+in\s+'
        r'\w*(?:src|source|text)\w*')
    for f in MODULES:
        src = read(f)
        total += len(re.findall(r"^\s*assert\s+", src, re.M))
        total += len(re.findall(r"g\.check\(", src))
        for m in PAT_ASSERT.finditer(src):
            weak.append("%s: %s" % (f, m.group(0).strip()[:70]))
        for m in PAT_CHECK.finditer(src):
            weak.append("%s: %s" % (f, m.group(0).strip()[:70]))
    return weak, total


def s6_unverified_claims():
    """S6：报告里说了但没测的断言（找"应该""预期"但无对应检查）。"""
    issues = []
    for d in ["CONSISTENCY-GATE-REPORT.md", "REAL-WORLD-REPLAY-GATE-REPORT.md"]:
        p = os.path.join(_HERE, d)
        if not os.path.exists(p):
            continue
        src = open(p, encoding="utf-8").read()
        for m in re.finditer(r"^.*(?:尚未|待验|未验证|TODO).*$", src, re.M):
            issues.append("%s: %s" % (d, m.group(0).strip()[:70]))
    return issues


def main():
    print("=" * 100)
    print("定时自检（进入 P2.1 之前）")
    print("=" * 100)

    r1 = s1_asserts_reachable()
    print("\nS1 · assert 可达性（恒真断言）")
    print("  %s" % ("；".join(r1) if r1 else "无恒真断言"))

    r2 = s2_hardcoded_expectations()
    print("\nS2 · 测试里是否有被实现带偏的期望")
    print("  %s" % ("；".join(r2) if r2 else "未发现"))

    r3 = s3_mutable_globals()
    print("\nS3 · 模块级可变共享状态")
    if r3:
        for x in r3:
            print("  ⚠ %s" % x)
    else:
        print("  无（除常量表外）")

    r4 = s4_doc_number_consistency()
    print("\nS4 · 报告数字自洽性")
    print("  %s" % ("；".join(r4) if r4 else "未发现分子>分母"))

    weak, total = s5_assert_content_not_just_existence()
    print("\nS5 · 断言强度（'字符串 in 源码' 形式的弱断言）")
    print("  共 %d 条 assert，其中弱断言 %d 条（%.0f%%）"
          % (total, len(weak), 100.0 * len(weak) / max(1, total)))
    for x in weak[:8]:
        print("     ⚠ %s" % x)

    r6 = s6_unverified_claims()
    print("\nS6 · 报告里未验证的表述")
    if r6:
        for x in r6[:10]:
            print("  ⚠ %s" % x)
    else:
        print("  无")

    print("\n" + "=" * 100)
    print("自检结论")
    print("=" * 100)
    n_issue = len(r1) + len(r2) + len(r3) + len(r4) + len(weak) + len(r6)
    print("  发现待处理项：%d" % n_issue)
    print("""
【最重要的自检结论 —— 关于 S5】
  consistency_gate.py 里大量使用 "字符串 in 源码" 形式的断言。
  这类断言**只能证明字面量存在，不能证明逻辑正确** ——
  它们恰好是"看起来通过但可能是假绿"的高发区。

  这与 P0.5 学到的「PASS 的理由必须正确」是同一件事：
  **Gate 自己也要被 Gate。**

  处理方式：把最关键的几条（I1/I2/I5/I6）补上**运行时行为断言**，
  而不是只查源码里有没有某个字符串。""")


if __name__ == "__main__":
    main()
