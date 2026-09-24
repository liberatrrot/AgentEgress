# -*- coding: utf-8 -*-
"""Q4：老化与自检。跑作者自己的自检机制，再把同样的判据套到红队样本上。"""
import os
import sys
import json
import glob
import hashlib
import re

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agentegress as ae          # noqa: E402
import redteam_harness as H       # noqa: E402

ROOT = str(__import__("pathlib").Path(__file__).resolve().parents[2])
S = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")

print("#" * 78)
print("# A. 仓库里到底有哪些「自检」？它们断言什么？")
print("#" * 78)
for rel in ("tests/verify.py", "tests/self_audit.py", "tests/score.py", "tests/bench.py"):
    p = os.path.join(ROOT, rel)
    src = open(p, encoding="utf-8").read()
    n_record = len(re.findall(r"record\(", src))
    n_assert = len(re.findall(r"\bassert\b", src))
    has_date = bool(re.search(r"20\d\d-\d\d", src))
    print("%-20s %5d 行  record()调用 %-3d  assert 语句 %-3d  含硬编码日期: %s"
          % (rel, src.count("\n") + 1, n_record, n_assert, has_date))

print()
print("agentegress.py 里是否存在任何「时效/版本/过期」检查？")
src = open(os.path.join(ROOT, "agentegress.py"), encoding="utf-8").read()
for kw in ("datetime", "date.today", "time.time()", "expire", "stale", "last_updated",
           "pattern_version", "updated_at"):
    hits = [m.start() for m in re.finditer(re.escape(kw), src)]
    ctx = ""
    if hits:
        i = hits[0]
        ctx = src[max(0, i - 60):i + 60].replace("\n", " ")
    print("  %-16s 出现 %-3d 次   %s" % (kw, len(hits), ctx[:110]))

print()
print("#" * 78)
print("# B. 作者自己的「变异测试」：检出边界在哪一级塌掉？（tests/verify.py 的逻辑）")
print("#" * 78)
import importlib.util
spec = importlib.util.spec_from_file_location("verify", os.path.join(ROOT, "tests", "verify.py"))
vfy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vfy)
ok = vfy.check_mutation_corpus()
r = vfy.RESULTS[-1]
print("record 结论:", ok, "|", r["detail"])
print()
print("%-14s %-26s %s" % ("变异级别", "仍能看到的能力数", "看到的能力"))
for row in r["extra"]["rows"]:
    print("%-14s %-26s %s" % (row["variant"], row["seen_count"], ",".join(row["seen"]) or "（全盲）"))
print()
print("注意：check_mutation_corpus 的断言是 record(..., bool(baseline), ...) ——")
print("      只要基线 M0 可见就判通过，M5~M8 全盲也不影响它 PASS。")
print("      实际 record.ok =", ok)

print()
print("#" * 78)
print("# C. 作者自己的「近负样本」闸门，套到红队样本上")
print("#" * 78)
gate_ok = vfy.check_near_negative()
gate = vfy.RESULTS[-1]
print("作者自带近负场景:", gate_ok, "|", gate["detail"])


def apply_gate(path, label):
    acc = ae.CapabilityAccumulator()
    ae.audit_path(path, acc=acc)
    caps = ae.aggregate_from_buckets(acc)
    chains = ae.detect_chains(caps, acc=acc)
    blocking = [c["name"] for c in chains if c["level"] == "blocking"]
    high_conf = [c["name"] for c in caps if c["level"] == "confirmed" and c["risk"] == "high"]
    verd = ae.summarize_capabilities(caps)["verdict"]
    print("  %-46s 阻断链 %-2d 高危confirmed %-2d verdict=%s  -> %s"
          % (label, len(blocking), len(high_conf), verd,
             "闸门会拦下" if (blocking or high_conf) else "闸门放行"))
    for b in blocking:
        print("       阻断链: %s" % b)
    return blocking or high_conf


apply_gate(os.path.join(S, "q2_legit_backup"), "Q2 合法加密备份工具（9 文件，真实规模）")
apply_gate(os.path.join(S, "q1_baseline"), "Q1 基线恶意客户端")
apply_gate(os.path.join(S, "q1_evade_splitfull"), "Q1 逃逸A2 完全混淆")
apply_gate(os.path.join(S, "q1_evade_vendor"), "Q1 逃逸B 藏在 node_modules")

print()
print("#" * 78)
print("# D. 阈值随模式库增长而漂移（用 Q1 基线的真实得分做算术）")
print("#" * 78)
r0 = H.scan_dir(os.path.join(S, "q1_baseline"))
print("当前每个能力的「模式权重和」(CAP_WEIGHT_SUM) 与它在 confirmed 阈值下的绝对分门槛：")
for c in r0["caps"]:
    if c["level"] == "absent":
        continue
    wsum = ae.CAP_WEIGHT_SUM[c["id"]]
    need = 0.55 * wsum
    print("  %-24s 权重和=%-3d  confirmed 需绝对分>=%-6.2f  当前绝对分=%-6.2f  norm=%s"
          % (c["name"], wsum, need, c["score"], c["norm"]))

print()
print("假设给 workspace_snapshot 再加 k 个权重为 w 的模式（分母变大），")
print("同一份证据（绝对分不变）的 norm 会怎样变化：")
ws = [c for c in r0["caps"] if c["id"] == "workspace_snapshot"][0]
base_sum = ae.CAP_WEIGHT_SUM["workspace_snapshot"]
for extra in (0, 5, 10, 20, 30):
    wsum = base_sum + extra
    print("  权重和 %-3d -> norm=%s  (confirmed 门槛 0.55 -> %s)"
          % (wsum, round(ws["score"] / wsum, 4),
             "过" if ws["score"] / wsum >= 0.55 else "不过"))
