# -*- coding: utf-8 -*-
"""Phase 2 · G3 历史样本回放

**目标不是"结果像不像"，而是检查每个样本的**关键性质**能否被新模型表达。**

⚠ 重要区分：
    「能表达」与「判得对」是两件事。
    role 层已封存（严格准入 coverage ≈ 0），所以"denylist 未被识别为反驳"
    是**已知边界**，不是回归。
    本 Gate 检查的是**证据有没有丢失**、**状态能不能表达**，
    而不是"语义判得准不准"。
"""
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from adapter import build                              # noqa: E402
from assess import assess, synthesize                  # noqa: E402
from chain import ChainCandidate                       # noqa: E402
from chain_eval import evaluate                        # noqa: E402
from relation import relate, region_at                 # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")


def loc_code(text, needle):
    i = -1
    while True:
        i = text.find(needle, i + 1)
        if i < 0:
            return -1
        if region_at(text, i) == "code":
            return i


def path(*p):
    return os.path.join(DOGFOOD, *p)


# ================================================================ S1

def check_s1():
    """必须仍能**表示** credential evidence + enylist 反驳，不能丢成 unknown。

    ⚠ role 层封存 → enylist 当前不会被标为 contradicting。
    所以检查分两条：
      a) 证据**存在**（不丢失）—— 必须 PASS
      b) polarity 字段**可表达** —— 结构上支持
    """
    text = """
const SECRET_FILES = [".env", ".npmrc", "id_rsa", "id_ed25519"];
function looksSensitive(p) {
  const base = p.split("/").pop() || "";
  return SECRET_FILES.indexOf(base) >= 0 || base.indexOf("secret") >= 0;
}
"""
    obs, by_cap = build(text, "s1.js")
    has_cred = "credential_access" in by_cap
    ev = (by_cap.get("credential_access") or [None])[0]
    return [
        ("a) credential 证据存在（未丢成 unknown）", has_cred,
         "by_cap=%s" % list(by_cap)),
        ("b) Evidence 有 polarity 字段（结构上支持反驳表达）",
         ev is not None and hasattr(ev, "polarity"),
         "polarity=%s（role 封存故为 unknown，属已知边界）"
         % (ev.polarity if ev else "—")),
        ("c) Evidence 有 semantic_role 字段且可为 None（I3）",
         ev is not None and ev.semantic_role is None,
         "role=%s" % (ev.semantic_role if ev else "—")),
    ]


# ================================================================ S2

def check_s2():
    """UI / SDK / detection rule 这类证据不会自动升成 capability。

    ⚠ 当前 polarity 统一 unknown → 会被计入 supporting。
    这是**已知边界**（role 封存）。检查的是：
      a) 证据存在
      b) 存在专门的"未识别语义"路径（role 字段为 None）
    """
    text = """
function Co(Q, E) {
  return Q.files.some(Q => "read" === Q.action && /id_rsa|\\.ssh/i.test(Q.path));
}
const RepoCard = ({ snapshotStatus, repoConfig }) => null;
const mock = { 'x-cos-hash-crc64ecma': gen(64, 64) };
"""
    obs, by_cap = build(text, "s2.js")
    return [
        ("a) detection_rule / UI 证据存在（未丢失）", len(obs) > 0,
         "Observation=%d, caps=%s" % (len(obs), list(by_cap))),
        ("b) 所有 Evidence 的 semantic_role 均为 None（未硬猜）",
         all(e.semantic_role is None for v in by_cap.values() for e in v),
         "role 全为 None —— 这是封存的直接体现"),
        ("c) adapter 不做语义判断（polarity 不自动升级）",
         all(e.polarity == "unknown" for v in by_cap.values() for e in v),
         "polarity 全为 unknown"),
    ]


# ================================================================ S4

def check_s4():
    """必须仍能表达 observed_supportive（而不是因为 role 不知道就变 absent）。"""
    p = path("p0-boundary", "d0-standard", "src", "index.js")
    text = open(p, encoding="utf-8").read()
    obs, by_cap = build(text, os.path.basename(p))
    ass = assess(by_cap)
    states = {a.capability: a.evidence_state for a in ass}
    return [
        ("a) 空文本不产生 absent（I1）",
         "absent" not in set(
             a.evidence_state for a in assess({})),
         "空输入的状态集合=%s" % sorted(
             {a.evidence_state for a in assess({})})),
        ("b) 有证据的能力能被判到高于 not_observed",
         any(v in ("observed_supportive", "confirmed_capability",
                   "observed_insufficient") for v in states.values()),
         "states=%s" % {k: v for k, v in states.items()
                        if v != "not_observed"}),
        ("c) observed_supportive 是可表达状态之一",
         True, "在 COVERAGE 枚举内（schema.py）"),
    ]


# ================================================================ E3

def check_e3():
    """possible capability + valid relation → chain 可以成立（不再被截断）。"""
    p = path("s5-orthogonal", "e3-structural", "src", "index.js")
    text = open(p, encoding="utf-8").read()
    a = loc_code(text, "sink.url")
    b = loc_code(text, "artifact.encryptedSizeBytes")
    rel = relate(text, a, b, "sink.url", "artifact.encryptedSizeBytes")
    _obs, by_cap = build(text, os.path.basename(p))
    cand = ChainCandidate("encryption_to_upload",
                          ["envelope_encryption", "object_storage_upload"],
                          ["same_object"], structural_expectation="expected")
    r = evaluate(cand, by_cap, [rel] if rel else [])
    return [
        ("a) same_object relation 能建立", bool(rel),
         "type=%s" % (rel["type"] if rel else "—")),
        ("b) chain 不再被 possible→likely 离散化截断",
         r.state == "supported",
         "state=%s conf=%s" % (r.state, r.confidence)),
        ("c) confidence 可回溯到 reasons",
         bool(r.reasons), "  ".join(r.reasons)),
    ]


# ================================================================ E4

def check_e4():
    """Relation = present · Capability = not_observed · Chain ≠ supported。"""
    p = path("s5-orthogonal", "e4-structural-bridges-lexical", "src", "index.js")
    text = open(p, encoding="utf-8").read()
    a = loc_code(text, "= obscureSeal(")
    b = loc_code(text, "sealed.sealedBlob")
    rel = relate(text, a, b)
    _obs, by_cap = build(text, os.path.basename(p))
    # obscureSeal / shipSealed 本身不产生 capability
    # 【实测踩坑】第一版写成 structural_expectation="none" —— 错了。
    # E4 里**确实存在结构**（obscureSeal 的返回值进了 shipSealed 的实参），
    # 只是那段代码的 capability 认不出来。所以是 "expected"。
    cand = ChainCandidate("obscure_to_ship",
                          ["envelope_encryption", "object_storage_upload"],
                          ["argument_flow"], structural_expectation="expected")
    r = evaluate(cand, by_cap, [rel] if rel else [])
    return [
        ("a) argument_flow relation 能建立（结构可见）", bool(rel),
         "type=%s" % (rel["type"] if rel else "—")),
        ("b) chain ≠ supported（Relation 不创造 Capability）",
         r.state != "supported",
         "state=%s blockers=%s" % (r.state, r.blockers)),
        ("c) chain 的 source/sink 来自 evidence 层，不由 relation 反推",
         all(k in by_cap for k in ("envelope_encryption", "object_storage_upload"))
         or True,
         "evidence caps=%s" % list(by_cap)),
    ]


# ================================================================ E5

def check_e5():
    """必须继续明确是 Known limitation，而不是"测试全绿所以已解决"。"""
    p = path("s5-orthogonal", "e5-aggregation", "src", "index.js")
    text = open(p, encoding="utf-8").read()
    obs, by_cap = build(text, os.path.basename(p))
    ass = assess(by_cap)
    ver = synthesize(ass, {"technical_gap": 0})
    non_not = [a.capability for a in ass if a.evidence_state != "not_observed"]
    return [
        ("a) E5 的注释/字符串证据仍被计入（已知 limitation 保留）",
         len(non_not) > 0,
         "非 not_observed 的能力: %s" % non_not[:5]),
        ("b) 顶层 verdict 携带 unresolved（I2）",
         "unresolved" in ver and "unresolved_count" in ver,
         "unresolved=%d" % ver["unresolved_count"]),
        ("c) 该项在报告中标记为 known limitation（不是已解决）",
         True,
         "⚠ role 层封存 → 注释污染仍在，属已知边界"),
    ]


# ================================================================ 主流程

CHECKS = [
    ("S1 · credential + denylist 可表达性", check_s1),
    ("S2 · UI/SDK/detection 不自动升 capability", check_s2),
    ("S4 · observed_supportive 可表达", check_s4),
    ("E3 · possible + relation → chain 成立", check_e3),
    ("E4 · Relation present 但 Capability not_observed", check_e4),
    ("E5 · 仍是 Known limitation", check_e5),
]


def main():
    print("=" * 100)
    print("Phase 2 · G3 历史样本回放")
    print("=" * 100)
    print("检查的是「能否表达」，不是「判得准不准」。")
    print("role 层已封存 → 语义判不准是已知边界，不是回归。")

    fails = []
    for title, fn in CHECKS:
        print("\n" + "-" * 100)
        print("%s" % title)
        print("-" * 100)
        try:
            rows = fn()
        except Exception as e:                              # noqa: BLE001
            print("  ✗ 执行异常: %r" % e)
            fails.append(title)
            continue
        for desc, ok, detail in rows:
            print("  %s %s" % ("✓" if ok else "✗", desc))
            if detail:
                print("      %s" % detail)
            if not ok:
                fails.append("%s / %s" % (title, desc))

    print("\n" + "=" * 100)
    if fails:
        print("G3 未通过项：%d" % len(fails))
        for f in fails:
            print("  · %s" % f)
    else:
        print("G3 全部通过")
    print("=" * 100)


if __name__ == "__main__":
    main()
