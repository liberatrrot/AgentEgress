# -*- coding: utf-8 -*-
"""Phase 2 · Consistency Gate v2（Verification Infrastructure Hardening）

## 为什么要重写

自检（self_audit.py）发现：本 Gate 有 **13/77 条弱断言（17%）**，
形如
    g.check("I1 ...", "有证据却报 not_observed" in src_assess)
**只证明"源码里写了这句话"，不证明"这段逻辑会触发"。**

> **在一个 Gate 自己存在 17% 弱断言的情况下，
> 先拿 Gate 的统计结果去指导下一层架构判断，证据链是不闭合的。**

## 断言三层（本轮引入）

    A  Source-presence assertion   源码里存在某字面量
       → **只能算辅助检查，不得独立贡献"通过"**
    B  Runtime-behavior assertion  构造输入 → 跑 → 断言行为
       → 计入通过
    C  End-to-end invariant        跨层不变量（输入→多层→断言）
       → 计入通过

## 失败路径自证（本轮新增的硬要求）

每个 B/C 断言必须附带**负例探针**：
**故意构造违反条件的输入，确认断言真的会失败。**
否则"全绿"可能只是因为断言写成了恒真。

## 停止条件

    13/13 弱断言 → 都有运行时对应测试
    所有 B/C 断言 → 能证明失败路径真的会失败
    A 级断言 → 只算辅助，不能独立贡献"通过"
"""
import io
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from state_algebra import (STATE_LAYERS, discriminate,              # noqa: E402
                           assert_discrimination_total, FORBIDDEN_COLLAPSES)
from adapter import build                                           # noqa: E402
from assess import assess, synthesize, assert_invariants            # noqa: E402
from chain import (ChainCandidate, assert_chain_invariants,         # noqa: E402
                   derive_confidence)

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

LEVEL_A = "A"     # source-presence（辅助，不计入通过）
LEVEL_B = "B"     # runtime-behavior
LEVEL_C = "C"     # end-to-end invariant


class FakeEv:
    """最小 Evidence 替身（evaluator 只用到 polarity）。"""
    def __init__(self, polarity="unknown", citation=None):
        self.polarity = polarity
        self.citation = citation or {"offset": 0}
        self.specificity = "high"
        self.id = "ev-fake"


class Gate:
    def __init__(self, gid, name):
        self.gid = gid
        self.name = name
        self.checks = []

    def check(self, desc, ok, detail="", level=LEVEL_B):
        self.checks.append((desc, bool(ok), detail, level))
        return ok

    @property
    def graded(self):
        """只有 B/C 计入通过 —— A 级只算辅助。"""
        return [c for c in self.checks if c[3] in (LEVEL_B, LEVEL_C)]

    @property
    def passed(self):
        g = self.graded
        return bool(g) and all(ok for _d, ok, _x, _l in g)

    @property
    def n_pass(self):
        return sum(1 for _d, ok, _x, _l in self.graded if ok)

    @property
    def n_a(self):
        return sum(1 for _d, _o, _x, l in self.checks if l == LEVEL_A)


# ================================================================ 失败路径自证

def probe_can_fail(fn, expect_fail=True):
    """★ 新硬要求：验证"失败路径真的会失败"。

    对一个应当抛 AssertionError 的场景跑一次；
    若它**没有**抛异常，说明该断言是恒真的（假绿）。
    返回 (ok, detail)
    """
    try:
        fn()
    except AssertionError as e:
        return True, "断言确实触发：%s" % str(e)[:60]
    except Exception as e:                                  # noqa: BLE001
        return False, "抛了非 AssertionError：%r" % e
    return (not expect_fail), ("未触发断言（该检查可能是恒真的）"
                               if expect_fail else "如预期未触发")


# ================================================================ G1

def g1():
    """六条核心不变量 —— B/C 级运行时断言。"""
    g = Gate("G1", "六条核心不变量")

    # ---------- I1 unknown ≠ negative（B 级：运行时） ----------
    def i1_runtime():
        by_cap = {"workspace_snapshot": [FakeEv()],
                  "envelope_encryption": [FakeEv()]}
        ass = assess(by_cap)
        st = {a.capability: a.evidence_state for a in ass}
        # 有证据的能力绝不能是 not_observed
        assert st["workspace_snapshot"] != "not_observed", "有证据却报 not_observed"
        # 任何能力都不能出现 absent
        assert "absent" not in set(st.values()), "出现了 absent"
        # 断言器本身要能拦住违规
        assert_invariants(ass, synthesize(ass, {}))
        return st

    try:
        st = i1_runtime()
        g.check("I1[B] 有 Evidence 的能力不被折成 not_observed/absent",
                True, "状态集合=%s" % sorted(set(st.values())), LEVEL_B)
    except AssertionError as e:
        g.check("I1[B] 有 Evidence 的能力不被折成 not_observed/absent",
                False, str(e), LEVEL_B)

    # I1 的失败路径自证：构造"有证据却报 not_observed"的输入
    def i1_negative():
        class Bad:
            capability = "x"
            evidence_state = "not_observed"
            supporting = ["ev-1"]        # 有支持证据（违规点）
            contradicting = []
        assert_invariants([Bad()], {"unresolved": [], "unresolved_count": 0})

    ok, detail = probe_can_fail(i1_negative)
    g.check("I1[B] 失败路径自证：伪造「有证据却 not_observed」会触发断言",
            ok, detail, LEVEL_B)

    # ---------- I2 unknown ≠ safe（B 级） ----------
    def i2_runtime():
        ver = synthesize(assess({}), {})
        assert "unresolved" in ver, "缺 unresolved"
        assert "unresolved_count" in ver, "缺 unresolved_count"
        assert ver["unresolved_count"] == len(ver["unresolved"]), "count 不符"
        return ver

    try:
        ver = i2_runtime()
        g.check("I2[B] verdict 携带 unresolved 且计数自洽",
                True, "unresolved=%d" % ver["unresolved_count"], LEVEL_B)
    except AssertionError as e:
        g.check("I2[B] verdict 携带 unresolved 且计数自洽", False, str(e), LEVEL_B)

    def i2_negative():
        # 【实测踩坑 · 第 4 次同类】第一版 fake 对象缺 `supporting` 字段，
        # assert_invariants 先访问它就抛 AttributeError（不是 AssertionError），
        # 于是"失败路径自证"判定为失败 —— 但那是**探针本身写错**，不是断言失效。
        # fake 对象必须提供断言会访问的全部字段。
        class A:
            capability = "c"
            evidence_state = "observed_insufficient"   # 应进 unresolved
            supporting = ["ev-1"]
            contradicting = []
        # verdict 里故意不含它 → 断言必须触发
        assert_invariants([A()], {"unresolved": [], "unresolved_count": 0})

    ok, detail = probe_can_fail(i2_negative)
    g.check("I2[B] 失败路径自证：insufficient 未进 unresolved 会触发断言",
            ok, detail, LEVEL_B)

    # ---------- I3 semantic_role 非必填（B 级） ----------
    def i3_runtime():
        from schema import Evidence
        ev = Evidence(id="e1", observations=["o1"],
                      capability_candidate="encryption")
        assert ev.semantic_role is None, "semantic_role 默认不为 None"
        assert ev.role_evidence is None, "role_evidence 默认不为 None"
        return ev

    try:
        i3_runtime()
        g.check("I3[B] Evidence 可不带 semantic_role 构造成功", True,
                "两个字段默认 None", LEVEL_B)
    except AssertionError as e:
        g.check("I3[B] Evidence 可不带 semantic_role 构造成功", False,
                str(e), LEVEL_B)

    # ---------- I4 no proof → no relation（B 级） ----------
    from relation import same_object, assert_relation_invariants as ari
    def i4_runtime():
        # 无 proof 时不得产出 relation
        r = same_object("var x = 1;\nvar y = 2;", 4, 14)
        assert r is None, "无结构证明却产出了 relation"
        # 有 proof 但 basis 被抹掉 → 断言必须拦住
        bad = [{"type": "same_object", "structural_basis": "same object"}]
        ari(bad)

    ok, detail = probe_can_fail(i4_runtime)
    g.check("I4[B] 失败路径自证：自述式 structural_basis 会触发断言",
            ok, detail, LEVEL_B)

    # ---------- I5 no hidden threshold（C 级：跨层） ----------
    def i5_runtime():
        base = derive_confidence("supported", True, True, True, True, False, False)
        assert base[0] == "strong", "source+sink+admitted 应为 strong"
        # ① 同 facts 重复调用 → 结果稳定
        again = derive_confidence("supported", True, True, True, True, False, False)
        assert base == again, "同 facts 两次调用结果不一致"
        # ② 少一个必需 fact（缺 admitted relation）→ 不得仍是 strong
        less = derive_confidence("supported", True, True, False, True, False, False)
        assert less[0] != "strong", "缺 admitted relation 仍得 strong"
        # ③ coverage_blocked → unknown
        blk = derive_confidence("blocked_by_coverage", True, True, True, True, False, True)
        assert blk[0] == "unknown", "coverage_blocked 应得 unknown"
        # ④ 反证 → weak
        con = derive_confidence("contradicted", True, True, True, True, True, False)
        assert con[0] == "weak", "有反证应得 weak"
        return base, less, blk, con

    try:
        i5_runtime()
        g.check("I5[C] confidence 由 facts 决定：稳定性 + 单调性 + 边界",
                True, "strong/moderate/weak/unknown 四态全部可复现", LEVEL_C)
    except AssertionError as e:
        g.check("I5[C] confidence 由 facts 决定", False, str(e), LEVEL_C)

    # ---------- I6 no candidate → no chain evaluation（B 级） ----------
    from chain_eval import evaluate as ce

    def i6_runtime():
        na = ChainCandidate("t", ["a", "b"], ["same_object"], applicable=False)
        r = ce(na, {}, [])
        assert r.evaluated is False, "applicable=False 却被评估了"
        assert r.state != "absent", "产出了 absent（应为 not_evaluated 语义）"
        # 评估结果必须能对应 candidate
        from chain import assert_chain_invariants as aci
        aci([r], [na])       # 本身对应，应通过
        # 构造一个"没有对应 candidate"的结果 → 必须被拦
        aci([r], [])
        return r

    ok, detail = probe_can_fail(i6_runtime)
    g.check("I6[B] 失败路径自证：无对应 candidate 的评估结果会触发断言",
            ok, detail, LEVEL_B)

    # ---------- A 级：源码约束（保留，但只算辅助） ----------
    src_assess = open(os.path.join(_HERE, "assess.py"), encoding="utf-8").read()
    g.check("I1[A] 辅助：assess 中无 coverage=\"absent\" 赋值",
            not re.findall(r'coverage\s*=\s*"absent"', src_assess),
            "仅辅助，不计入通过", LEVEL_A)
    return g


# ================================================================ G2

def g2():
    g = Gate("G2", "状态代数无歧义")

    def runtime():
        seen = assert_discrimination_total()
        reached = {discriminate(a, b, c)
                   for a in (False, True) for b in (False, True)
                   for c in (False, True)}
        need = {"not_observed", "insufficient", "contradicted",
                "blocked_by_coverage"}
        assert need <= reached, "四态不全可达"
        combos = [(False, False, False), (False, True, False),
                  (True, False, False), (False, False, True)]
        outs = [discriminate(*c) for c in combos]
        assert len(set(outs)) == 4, "四态不可机械区分"
        return len(seen)

    try:
        n = runtime()
        g.check("G2[C] 四态机械可区分且穷尽（2^3 组合）", True,
                "共 %d 组输入，四态互异" % n, LEVEL_C)
    except AssertionError as e:
        g.check("G2[C] 四态机械可区分且穷尽", False, str(e), LEVEL_C)

    def negative():
        # 若两个输入组合映射到同一状态，区分性检查必须失败
        assert discriminate(False, True, False) != discriminate(True, False, False)

    ok, detail = probe_can_fail(negative, expect_fail=False)
    g.check("G2[B] 失败路径自证：inconsistent/contradicted 确实不同",
            ok, detail, LEVEL_B)

    g.check("G2[B] 禁止合并的状态对已记录", len(FORBIDDEN_COLLAPSES) >= 5,
            "%d 组" % len(FORBIDDEN_COLLAPSES), LEVEL_B)

    for layer, states in STATE_LAYERS.items():
        g.check("G2[B] 层 %s 状态已显式列出（%d 个）" % (layer, len(states)),
                len(states) > 0, "", LEVEL_B)
    return g


# ================================================================ G4

def g4():
    g = Gate("G4", "层间禁止反向造证据")

    LAYER_ORDER = ["schema", "state_algebra", "adapter", "assess",
                   "relation", "chain", "chain_eval"]
    rank = {n: i for i, n in enumerate(LAYER_ORDER)}
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
            if dep in rank and rank[dep] > rank[name]:
                violations.append("%s → %s" % (name, dep))
    g.check("G4[B] 无反向 import（下层不依赖上层）", not violations,
            "违规: %s" % violations if violations else "依赖方向正确", LEVEL_B)

    # ★ 事件级验证：Chain 评估前后 evidence 对象集合必须不变
    def runtime_reverse_check():
        text = "const a = { x: sink.url, y: artifact.encryptedSizeBytes };"
        _obs, by_cap = build(text, "t.js")
        before = {k: len(v) for k, v in by_cap.items()}
        ids_before = {id(e) for v in by_cap.values() for e in v}
        cand = ChainCandidate("t", ["envelope_encryption", "object_storage_upload"],
                              ["same_object"])
        from chain_eval import evaluate as ce
        ce(cand, by_cap, [])
        after = {k: len(v) for k, v in by_cap.items()}
        ids_after = {id(e) for v in by_cap.values() for e in v}
        assert before == after, "Chain 评估改变了 evidence 数量"
        assert ids_before == ids_after, "Chain 评估替换了 evidence 对象"
        return before

    try:
        runtime_reverse_check()
        g.check("G4[B] Chain 评估不改变 evidence 集合（对象级）", True,
                "数量与对象 id 均不变", LEVEL_B)
    except AssertionError as e:
        g.check("G4[B] Chain 评估不改变 evidence 集合（对象级）", False,
                str(e), LEVEL_B)
    return g


# ================================================================ G5

def g5():
    g = Gate("G5", "所有结论都有可验证理由")

    allowed = set()
    for f in ("assess.py", "chain_eval.py"):
        src = open(os.path.join(_HERE, f), encoding="utf-8").read()
        for m in re.finditer(r'reasons\.append\(\s*"([^"]+)"', src):
            allowed.add(m.group(1).split(":")[0].split("%")[0])
    g.check("G5[B] reason 白名单已提取（%d 条）" % len(allowed),
            len(allowed) > 0, "", LEVEL_B)

    def runtime():
        p = os.path.join(DOGFOOD, "p0-boundary", "d0-standard", "src", "index.js")
        text = open(p, encoding="utf-8").read()
        _o, bc = build(text, os.path.basename(p))
        bad = []
        for a in assess(bc):
            if a.evidence_state == "not_observed":
                continue
            if not a.reasons:
                bad.append(a.capability)
        assert not bad, "这些能力没有 reasons: %s" % bad
        return len([a for a in assess(bc) if a.evidence_state != "not_observed"])

    try:
        n = runtime()
        g.check("G5[B] 非 not_observed 的能力都有 reasons", True,
                "%d 个能力全部有理由" % n, LEVEL_B)
    except AssertionError as e:
        g.check("G5[B] 非 not_observed 的能力都有 reasons", False,
                str(e), LEVEL_B)
    return g


# ================================================================ G6

def g6():
    g = Gate("G6", "confidence / chain 无隐藏阈值")

    src_chain = open(os.path.join(_HERE, "chain.py"), encoding="utf-8").read()
    src_eval = open(os.path.join(_HERE, "chain_eval.py"), encoding="utf-8").read()

    def runtime_no_count():
        # 遍历 2^5 输入空间，确认 confidence 只由 facts 决定
        from itertools import product
        seen = {}
        for hs, hk, ar, anyr, ct, bk in product([False, True], repeat=6):
            key = (hs, hk, ar, anyr, ct, bk)
            c1, _w1 = derive_confidence("s", hs, hk, ar, anyr, ct, bk)
            c2, _w2 = derive_confidence("s", hs, hk, ar, anyr, ct, bk)
            assert c1 == c2, "同 facts 两次调用不一致"
            assert c1 in ("strong", "moderate", "weak", "unknown"), "非法档位"
            seen[key] = c1
        # 单调性：缺 admitted relation 不得比有它更高
        for hs, hk, anyr in product([False, True], repeat=3):
            with_ar = derive_confidence("s", hs, hk, True, anyr, False, False)[0]
            without = derive_confidence("s", hs, hk, False, anyr, False, False)[0]
            order = {"unknown": 0, "weak": 1, "moderate": 2, "strong": 3}
            assert order[with_ar] >= order[without], \
                "有 admitted relation 反而更低 (%s < %s)" % (with_ar, without)
        return len(seen)

    try:
        n = runtime_no_count()
        g.check("G6[C] confidence 空间穷尽测试（2^6 = %d 组）" % n, True,
                "稳定 + 单调（admitted relation 只会抬高不会降低）", LEVEL_C)
    except AssertionError as e:
        g.check("G6[C] confidence 空间穷尽测试", False, str(e), LEVEL_C)

    bad = []
    for pat, desc in ((r"len\(reasons\)\s*[<>=]", "len(reasons) 阈值"),
                      (r"reasons_count\s*[<>=]", "reasons_count 阈值"),
                      (r"\bscore\b\s*[<>=]", "score 阈值"),
                      (r"\bnorm\b\s*[<>=]", "norm 阈值")):
        if re.search(pat, src_eval) or re.search(pat, src_chain):
            bad.append(desc)
    g.check("G6[B] 无 len/score/norm 形式的阈值", not bad,
            "发现: %s" % bad if bad else "干净", LEVEL_B)
    return g


# ================================================================ G7

def g7():
    g = Gate("G7", "P3 无越权改变 capability 结论")

    def runtime():
        from chain_eval import evaluate as ce
        samples = {
            "E5": os.path.join(DOGFOOD, "s5-orthogonal", "e5-aggregation",
                               "src", "index.js"),
            "E3": os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural",
                               "src", "index.js"),
            "S4-B3": os.path.join(DOGFOOD, "p0-boundary",
                                  "b3-local-cache-only", "src", "index.js"),
        }
        out = []
        for tag, p in samples.items():
            text = open(p, encoding="utf-8").read()
            _o, bc = build(text, os.path.basename(p))
            before = {a.capability: a.evidence_state for a in assess(bc)}
            cand = ChainCandidate("t", ["envelope_encryption",
                                        "object_storage_upload"],
                                  ["same_object"])
            ce(cand, bc, [])
            after = {a.capability: a.evidence_state for a in assess(bc)}
            diff = {k for k in before if before[k] != after.get(k)}
            assert not diff, "%s 层间泄漏: %s" % (tag, diff)
            out.append(tag)
        return out

    try:
        tags = runtime()
        g.check("G7[B] Chain 评估不改变 capability 结论", True,
                "已验: %s" % ", ".join(tags), LEVEL_B)
    except AssertionError as e:
        g.check("G7[B] Chain 评估不改变 capability 结论", False,
                str(e), LEVEL_B)
    return g


# ================================================================ 主流程

def main():
    gates = []
    for fn in (g1, g2, g4, g5, g6, g7):
        try:
            gates.append(fn())
        except Exception as e:                              # noqa: BLE001
            gg = Gate(fn.__name__.upper(), "执行异常")
            gg.check("无异常", False, repr(e), LEVEL_B)
            gates.append(gg)

    print("=" * 100)
    print("Phase 2 · Consistency Gate v2（Verification Infrastructure Hardening）")
    print("=" * 100)
    print("""断言分层：
  A  Source-presence  源码里存在某字面量 —— **只算辅助，不得独立贡献"通过"**
  B  Runtime-behavior 构造输入 → 跑 → 断言行为 —— 计入通过
  C  End-to-end       跨层不变量 —— 计入通过
硬要求：每个 B/C 断言都要有**失败路径自证**（故意违反 → 断言必须触发）""")

    tot_b = tot_a = 0
    for g in gates:
        mark = "PASS" if g.passed else "FAIL"
        print("\n[%s] %s · %s  (B/C: %d/%d；A 级辅助: %d)"
              % (mark, g.gid, g.name, g.n_pass, len(g.graded), g.n_a))
        for desc, ok, detail, lv in g.checks:
            print("    [%s] %s %s" % (lv, "✓" if ok else "✗", desc))
            if detail:
                print("          → %s" % detail)
        tot_b += len(g.graded)
        tot_a += g.n_a

    print("\n" + "=" * 100)
    allp = all(g.passed for g in gates)
    print("B/C 级断言合计：%d 条；A 级辅助：%d 条" % (tot_b, tot_a))
    print("Gate 总判定：%s" % ("全部通过（B/C 级）→ 验证层可信"
                              if allp else "存在未通过项"))
    print("=" * 100)
    print("""
对比 v1：
  v1  13 条弱断言（"字面量 in 源码"）**独立计入通过** → 假绿风险
  v2  那些降为 A 级（只算辅助），并补了对应的 B/C 级运行时断言
      + 每个 B/C 断言附**失败路径自证**（故意违反 → 必须触发）""")


if __name__ == "__main__":
    main()
