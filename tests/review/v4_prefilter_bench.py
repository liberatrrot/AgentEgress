# -*- coding: utf-8 -*-
"""预筛实现的性能对比：alternation 正则 vs 逐关键词 in 检查。

背景：外部评审提醒关注「扫描器自身的资源消耗」。灾难性回溯没测出来，
但顺带发现预筛过滤器（一条 60+ 分支的 alternation 正则）对不匹配的长文本很慢——
它要在每个字符位置尝试所有分支。

而 `in` 是 C 实现的 two-way / memchr，且可以短路。测一下谁快。
"""
import os
import re
import sys
import time

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae

KWS = sorted({k.lower() for ks in ae.PATTERN_KEYWORDS.values() for k in ks})
print("关键词总数：%d" % len(KWS))

BIG = 2 * 1024 * 1024          # 2 MB
SAMPLES = {
    "纯 a 串（最坏）": "a" * BIG,
    "重复 policy": "policy " * (BIG // 7),
    "正常 JS 片段": ('const x=1;function f(a,b){return a+b}' * (BIG // 37))[:BIG],
    "含命中（snapshot/upload）": ("x" * 1000 + "snapshot/upload" + "y" * (BIG - 1015)),
}


def by_regex(text):
    return ae._KW_FILTER.search(text) is not None


def by_in(text):
    # 按长度降序（长关键词更具体，命中率更低但更可能先短路？）——这里简单按原序
    for k in KWS:
        if k in text:
            return True
    return False


print()
print("输入规模：%.1f MB" % (BIG / 1048576))
print("%-26s %12s %12s %8s" % ("样本", "regex(s)", "in(s)", "加速"))
print("-" * 62)
for name, text in SAMPLES.items():
    t0 = time.perf_counter()
    by_regex(text)
    t_re = time.perf_counter() - t0

    t0 = time.perf_counter()
    by_in(text)
    t_in = time.perf_counter() - t0

    speed = (t_re / t_in) if t_in > 0 else float("inf")
    print("%-26s %12.4f %12.4f %7.1fx" % (name, t_re, t_in, speed))

print()
print("结论：")
print("  · 若 in 明显更快，就把预筛从 alternation 正则换成逐关键词 in（短路）")
print("  · in 是 C 实现，且大部分文件在前几个关键词就命中")
