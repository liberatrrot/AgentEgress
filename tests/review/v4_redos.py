# -*- coding: utf-8 -*-
"""验证外部评审提出的最严重风险：正则灾难性回溯（ReDoS）。

它的论证：AgentEgress 本身就是「大量文件 + 大量正则」的结构，
若某条规则存在灾难性回溯，恶意输入就能让扫描器 CPU 飙满——
攻击者反过来可以拿扫描过程做 DoS。

这是可证伪的，直接测。

方法：对 56 个模式分别喂几类「病态输入」，记录耗时。
病态输入的构造原则：让正则引擎在失败前走尽可能多的回溯路径。
"""
import os
import re
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae

N = 200000

CASES = [
    ("长 a 串", "a" * N),
    ("长 a + 单引号", "a" * N + "'"),
    ("前缀 a 后跟不匹配尾", "a" * N + "~~~END"),
    ("重复 kind:", "kind:" * (N // 5)),
    ("嵌套括号", "(" * (N // 2) + ")" * (N // 2)),
    ("重复 policy", "policy " * (N // 7)),
    ("重复 credential 逗号", "credential," * (N // 11)),
    ("重复 base", "base" * (N // 4)),
    ("重复 .git/", ".git/" * (N // 5)),
    ("反斜杠长串", "\\" * N),
    ("重复引号", '"' * N),
    ("重复 <<<", "<" * N),
    ("a 与 * 交替", "a*" * (N // 2)),
    ("重复 upload", "upload" * (N // 6)),
]

print("=" * 78)
print("正则灾难性回溯测试  （每条正则 x 每类病态输入）")
print("=" * 78)
print("输入规模：每类约 %d 字符" % N)
print()

worst = []
slow_hits = []

for cap in ae._COMPILED_CAPS:
    for pat in cap["patterns"]:
        rx = pat["re"]
        pat_worst = 0.0
        pat_worst_case = ""
        for name, blob in CASES:
            t0 = time.perf_counter()
            try:
                rx.search(blob)
            except Exception:
                pass
            dt = time.perf_counter() - t0
            if dt > pat_worst:
                pat_worst = dt
                pat_worst_case = name
        worst.append((pat_worst, pat["id"], cap["id"], pat_worst_case))
        if pat_worst > 0.1:
            slow_hits.append((pat_worst, pat["id"], cap["id"], pat_worst_case))

worst.sort(reverse=True)
print("最慢的 12 条：")
print("  %-10s %-28s %-22s %s" % ("耗时(s)", "pattern", "能力", "触发输入"))
print("  " + "-" * 74)
for dt, pid, cid, case in worst[:12]:
    flag = "  <<< 慢" if dt > 0.1 else ""
    print("  %-10.4f %-28s %-22s %s%s" % (dt, pid, cid, case, flag))

print()
print("=" * 78)
if slow_hits:
    print("发现 %d 条正则存在回溯风险（单次调用 > 0.1 s）：" % len(slow_hits))
    for dt, pid, cid, case in slow_hits:
        print("  %-28s %.3f s  触发输入：%s" % (pid, dt, case))
    print()
    print(">>> 结论：外部评审的 ReDoS 担忧**成立**。")
    print("    放大系数：20 万字符 0.1 s -> 2 MB 文件约 1 s -> 单文件即可拖住扫描。")
else:
    print("未发现单次调用 > 0.1 s 的正则。")
    print(">>> 结论：当前模式库未观测到灾难性回溯（但这不等于不会发生，")
    print("    仍需在 CI 里保留这条检查——新增模式时最容易引入）。")

# 顺带测预筛过滤器（它也是一个正则，且每次都要跑）
print()
t0 = time.perf_counter()
ae._KW_FILTER.search("a" * N)
print("预筛过滤器对 %d 字符纯 a 串的耗时：%.4f s" % (N, time.perf_counter() - t0))
t0 = time.perf_counter()
ae._KW_FILTER.search("policy " * (N // 7))
print("预筛过滤器对重复 policy 的耗时：      %.4f s" % (time.perf_counter() - t0))
