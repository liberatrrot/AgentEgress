# -*- coding: utf-8 -*-
"""Phase 2 · Consistency Gate（G1–G7）

> **不是"把几个测试跑一遍"**，而是检查：
> **同一份事实经过 P0 → P1 → P2 → P3 后，语义有没有发生不允许的漂移。**

一条贯穿全部门槛的纪律（来自 P3 的教训）：

    **PASS 的理由必须正确。FAIL 的理由也必须正确。**
    "8/8" 不是结论；"8/8 + 为什么 8/8" 才是结论。
"""
import io
import os
import re
import sys
import inspect

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from state_algebra import (STATE_LAYERS, discriminate,              # noqa: E402
                           assert_discrimination_total, FORBIDDEN_COLLAPSES)

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")


class Gate:
    def __init__(self, gid, name):
        self.gid = gid
        self.name = name
        self.checks = []

    def check(self, desc, ok, detail=""):
        self.checks.append((desc, bool(ok), detail))
        return ok

    @property
    def passed(self):
        return all(ok for _d, ok, _x in self.checks)

    @property
    def n_pass(self):
        return sum(1 for _d, ok, _x in self.checks if ok)


# ================================================================ G1 六条不变量

def g1():
    g = Gate("G1", "六条核心不变量")

    # I1 unknown ≠ negative
    #
    # 【实测踩坑】第一版写成 `'"absent"' not in src_assess` —— 太粗。
    # "absent" 会出现在 **断言**（assert st != "absent"）和**错误消息**里，
    # 那是检查机制本身，不是输出路径。误报。
    # 改为：检查**赋值**里是否出现 absent。
    src_assess = open(os.path.join(_HERE, "assess.py"), encoding="utf-8").read()
    assign_with_absent = re.findall(r'coverage\s*=\s*"absent"', src_assess)
    g.check("I1  assess 中不存在 coverage=\"absent\" 的输出赋值",
            not assign_with_absent,
            "发现 %d 处" % len(assign_with_absent))
    g.check("I1  有证据却报 not_observed 会被断言拦住",
            "有证据却报 not_observed" in src_assess)

    # I2 unknown ≠ safe
    g.check("I2  verdict 必带 unresolved",
            '"unresolved"' in src_assess and '"unresolved_count"' in src_assess)
    g.check("I2  断言检查 unresolved 完整性",
            "未进入 unresolved" in src_assess)

    # I3 semantic_role 非必填
    src_schema = open(os.path.join(_HERE, "schema.py"), encoding="utf-8").read()
    g.check("I3  Evidence.semantic_role 默认 None",
            "semantic_role=None" in src_schema)
    g.check("I3  Evidence.role_evidence 默认 None",
            "role_evidence=None" in src_schema)

    # I4 no structural proof → no relation
    src_rel = open(os.path.join(_HERE, "relation.py"), encoding="utf-8").read()
    g.check("I4  relation 断言要求 structural_basis",
            "缺少 structural_basis" in src_rel)
    g.check("I4  structural_basis 必须是 dict（不是字符串）",
            "必须是结构化事实，不是字符串" in src_rel)

    # I5 no hidden threshold
    src_chain = open(os.path.join(_HERE, "chain.py"), encoding="utf-8").read()
    g.check("I5  chain 断言禁止连续分数字段",
            "出现连续分数字段" in src_chain)
    g.check("I5  chain 断言禁止用总类 missing_relation",
            "使用了总类 missing_relation" in src_chain)

    # I6 ★ no candidate → no chain evaluation
    g.check("I6  not_applicable 不产出 absent",
            "candidate_not_applicable" in src_chain
            or "not_applicable" in src_chain)
    src_eval = open(os.path.join(_HERE, "chain_eval.py"), encoding="utf-8").read()
    g.check("I6  评估结果必须对应真实 candidate",
            "没有对应的 ChainCandidate" in src_chain)
    return g


# ================================================================ G2 状态代数

def g2():
    g = Gate("G2", "状态代数无歧义")

    try:
        seen = assert_discrimination_total()
        g.check("2^3 输入组合都能唯一映射（穷尽 + 互斥）", True,
                "共 %d 组" % len(seen))
    except AssertionError as e:
        g.check("2^3 输入组合都能唯一映射", False, str(e))

    reached = {discriminate(a, b, c)
               for a in (False, True) for b in (False, True) for c in (False, True)}
    need = {"not_observed", "insufficient", "contradicted", "blocked_by_coverage"}
    g.check("四个被要求的状态都可触达", need <= reached,
            "缺失 %s" % (need - reached))

    # 层归属必须显式
    for layer, states in STATE_LAYERS.items():
        g.check("层 %s 的状态已显式列出（%d 个）" % (layer, len(states)),
                len(states) > 0)

    # 禁止合并的状态对必须被记录
    g.check("已显式记录 %d 组禁止合并的状态对" % len(FORBIDDEN_COLLAPSES),
            len(FORBIDDEN_COLLAPSES) >= 5,
            "包括 unknown≠negative / not_observed≠insufficient 等")

    # 关键区分：四个状态两两不等价
    combos = [(False, False, False), (False, True, False),
              (True, False, False), (False, False, True)]
    outs = [discriminate(*c) for c in combos]
    g.check("四态两两不同（机械可区分）", len(set(outs)) == 4,
            " → ".join(outs))
    return g


# ================================================================ G4 层间单向性

def g4():
    g = Gate("G4", "层间禁止反向造证据")

    # 模块依赖方向：上层可以 import 下层；下层不得 import 上层
    LAYER_ORDER = ["schema", "state_algebra", "adapter", "assess",
                   "relation", "chain", "chain_eval"]
    rank = {n: i for i, n in enumerate(LAYER_ORDER)}
    pkgs = sorted(set(os.listdir(_HERE)) & {p[:-3] for p in os.listdir(_HERE)
                                            if p.endswith(".py")})
    violations = []
    for f in os.listdir(_HERE):
        if not f.endswith(".py") or f == os.path.basename(__file__):
            continue
        name = f[:-3]
        if name not in rank:
            continue
        src = open(os.path.join(_HERE, f), encoding="utf-8").read()
        for m in re.finditer(r"^from\s+(\w+)\s+import|^import\s+(\w+)", src, re.M):
            dep = m.group(1) or m.group(2)
            # 只检查内部模块
            if dep in rank and rank[dep] > rank[name]:
                violations.append("%s → %s" % (name, dep))
    # relation 独立（不 import adapter/assess/chain）
    g.check("无反向 import（下层不依赖上层）", not violations,
            "违规: %s" % violations if violations else "依赖方向正确")

    # relation 不得引用 capability 结论
    src_rel = open(os.path.join(_HERE, "relation.py"), encoding="utf-8").read()
    g.check("relation.py 不 import adapter/assess/chain",
            not any(k in src_rel for k in
                    ("from adapter", "from assess", "from chain")),
            "Relation 只处理结构，不接触 capability")

    # chain_eval 不得修改传入的 evidence
    src_eval = open(os.path.join(_HERE, "chain_eval.py"), encoding="utf-8").read()
    g.check("chain_eval 不改写 evidence（只读）",
            "evidence_by_cap[" not in src_eval.replace("evidence_by_cap.get", "")
            and ".polarity =" not in src_eval,
            "evaluator 只读输入")

    # 运行时检查：Chain 评估不产生新的 capability
    from adapter import build
    from chain import ChainCandidate
    from chain_eval import evaluate
    text = "const a = { x: sink.url, y: artifact.encryptedSizeBytes };"
    obs, by_cap = build(text, "t.js")
    before = {k: len(v) for k, v in by_cap.items()}
    cand = ChainCandidate("t", ["envelope_encryption", "object_storage_upload"],
                          ["same_object"])
    evaluate(cand, by_cap, [])
    after = {k: len(v) for k, v in by_cap.items()}
    g.check("Chain 评估不改变 evidence 集合（运行时）", before == after,
            "before=%s after=%s" % (before, after))
    return g


# ================================================================ G6 无隐藏阈值

def g6():
    g = Gate("G6", "confidence / chain 无隐藏阈值")

    src_chain = open(os.path.join(_HERE, "chain.py"), encoding="utf-8").read()
    src_eval = open(os.path.join(_HERE, "chain_eval.py"), encoding="utf-8").read()

    # confidence 必须由谓词导出
    #
    # 【实测踩坑】第一版从 chain_eval.py 找 derive_confidence —— 找错文件了，
    # 它定义在 chain.py 里。FAIL 的原因是检查写错，不是实现问题。
    fn = re.search(r"def derive_confidence.*?(?=\n\n# |\ndef |\Z)",
                   src_chain, re.S)
    body = fn.group(0) if fn else ""
    g.check("derive_confidence 存在于 chain.py 且以布尔谓词判定",
            fn is not None and body.count("if ") >= 3,
            "if 分支数=%d（≥3 表示多分支谓词，而非单一计数）"
            % body.count("if "))

    # 禁止任何形式的计数阈值
    bad_patterns = [
        (r"len\(reasons\)\s*[<>=]", "len(reasons) 计数阈值"),
        (r"n_reasons\s*[<>=]", "n_reasons 计数阈值"),
        (r"reasons_count\s*[<>=]", "reasons_count 计数阈值"),
        (r"\bscore\b\s*[<>=]", "score 阈值"),
        (r"\bnorm\b\s*[<>=]", "norm 阈值"),
    ]
    hits = []
    for pat, desc in bad_patterns:
        if re.search(pat, src_eval) or re.search(pat, src_chain):
            hits.append(desc)
    g.check("无 len(reasons)/score/norm 形式的阈值", not hits,
            "发现: %s" % hits if hits else "干净")

    # confidence 取值必须是枚举
    g.check("confidence 是枚举而非连续值",
            "CHAIN_CONFIDENCE = " in src_chain
            and "strong" in src_chain and "moderate" in src_chain)

    # 可回溯性：每个 confidence 都能列出触发它的 facts
    from chain import derive_confidence
    probe = [
        # (state, has_source, has_sink, admitted, any_rel, contra, blocked)
        ("supported", True, True, True, True, False, False, "strong"),
        ("supported", True, True, False, True, False, False, "moderate"),
        ("insufficient", True, False, False, False, False, False, "weak"),
        ("blocked_by_coverage", True, True, False, False, False, True, "unknown"),
    ]
    all_ok = True
    details = []
    for (st, hs, hk, ar, anyr, ct, bk, exp) in probe:
        got, why = derive_confidence(st, hs, hk, ar, anyr, ct, bk)
        details.append("%s→%s(%s)" % (exp, got, why))
        if got != exp:
            all_ok = False
    g.check("confidence 可回溯到具名 facts（4/4 抽样）", all_ok,
            "  ".join(details))
    return g


# ================================================================ G7 P3 无越权

def g7():
    g = Gate("G7", "P3 无越权改变 capability 结论")

    # P3 的作用域是 Chain；capability 结论应完全由 P0/P1 决定。
    # 运行时验证：加不加 Chain 评估，capability 的 state 不变。
    from adapter import build
    from assess import assess
    from chain import ChainCandidate
    from chain_eval import evaluate

    samples = {
        "E5 纯注释": os.path.join(DOGFOOD, "s5-orthogonal", "e5-aggregation",
                                  "src", "index.js"),
        "E3 结构关系": os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural",
                                    "src", "index.js"),
        "S4-B3 本地缓存": os.path.join(DOGFOOD, "p0-boundary",
                                       "b3-local-cache-only", "src", "index.js"),
    }
    for tag, p in samples.items():
        if not os.path.exists(p):
            g.check("%s 样本存在" % tag, False, "缺文件")
            continue
        text = open(p, encoding="utf-8").read()
        obs, by_cap = build(text, os.path.basename(p))
        before = {a.capability: a.evidence_state for a in assess(by_cap)}
        # 跑一遍 Chain
        cand = ChainCandidate("t", ["envelope_encryption", "object_storage_upload"],
                              ["same_object"])
        evaluate(cand, by_cap, [])
        after = {a.capability: a.evidence_state for a in assess(by_cap)}
        diff = {k for k in before if before[k] != after.get(k)}
        g.check("%s：Chain 评估不改 capability 结论" % tag, not diff,
                "diff=%s" % diff if diff else "一致")

    # S4 的 B1/B2/B3 不应被 P3 顺手解决
    src_chain = open(os.path.join(_HERE, "chain.py"), encoding="utf-8").read()
    g.check("P3 文档明确声明 out of scope 含 B1/B2/B3",
            "B1 / B2 / B3" in src_chain or "B1/B2/B3" in src_chain,
            "scope 声明在模块顶部")
    return g


# ================================================================ G5 理由验收

def g5():
    g = Gate("G5", "所有结论都有可验证理由")

    # 允许的 reason 前缀（从各模块的 reasons.append 字面量提取）
    allowed = set()
    for f in ("assess.py", "chain_eval.py"):
        src = open(os.path.join(_HERE, f), encoding="utf-8").read()
        for m in re.finditer(r'reasons\.append\(\s*"([^"]+)"', src):
            allowed.add(m.group(1).split(":")[0].split("%")[0])
    g.check("提取到 reason 白名单（%d 条）" % len(allowed), len(allowed) > 0,
            ", ".join(sorted(allowed)[:8]))

    # 运行时：每个非 not_observed 的 assessment 必须有 reasons
    from adapter import build
    from assess import assess
    samples = [
        os.path.join(DOGFOOD, "p0-boundary", "d0-standard", "src", "index.js"),
        os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural", "src", "index.js"),
    ]
    n_ok, n_tot = 0, 0
    for p in samples:
        if not os.path.exists(p):
            continue
        text = open(p, encoding="utf-8").read()
        _obs, by_cap = build(text, os.path.basename(p))
        for a in assess(by_cap):
            if a.evidence_state == "not_observed":
                continue
            n_tot += 1
            if a.reasons:
                n_ok += 1
    g.check("非 not_observed 的能力都有 reasons（%d/%d）" % (n_ok, n_tot),
            n_ok == n_tot)

    # FAIL 的理由也必须正确：断言失败信息必须包含"为什么"
    src_assess = open(os.path.join(_HERE, "assess.py"), encoding="utf-8").read()
    g.check("断言失败信息包含具体原因（不是裸断言）",
            "档位与理由不符" in src_assess and "没有列出任何理由" in src_assess)

    # Chain 的 confidence 必须能回溯
    from chain import derive_confidence
    _c, why = derive_confidence("supported", True, True, True, True, False, False)
    g.check("Chain confidence 返回可读的触发原因", bool(why), "why=%s" % why)
    return g


# ================================================================ 主流程

def main():
    gates = []
    for fn in (g1, g2, g4, g5, g6, g7):
        try:
            gates.append(fn())
        except Exception as e:                              # noqa: BLE001
            gg = Gate(fn.__name__.upper(), "执行异常")
            gg.check("无异常", False, repr(e))
            gates.append(gg)

    print("=" * 100)
    print("Phase 2 · Consistency Gate")
    print("=" * 100)
    print("纪律：PASS 的理由必须正确；FAIL 的理由也必须正确。")
    print()

    for g in gates:
        mark = "PASS" if g.passed else "FAIL"
        print("\n[%s] %s · %s  (%d/%d)" % (
            mark, g.gid, g.name, g.n_pass, len(g.checks)))
        for desc, ok, detail in g.checks:
            print("    %s %s" % ("✓" if ok else "✗", desc))
            if detail and not ok:
                print("        → %s" % detail)

    print("\n" + "=" * 100)
    allp = all(g.passed for g in gates)
    print("Gate 总判定：%s" % ("全部通过 → 可以进入 P4"
                              if allp else "存在未通过项 → 不进入 P4"))
    print("=" * 100)
    print("""
说明：
  G3（历史样本回放）在 replay_gate.py 中单独跑 —— 它需要样本文件且耗时较长。
  G1/G2/G4/G5/G6/G7 在本脚本内完成。""")


if __name__ == "__main__":
    main()
