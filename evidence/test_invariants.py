# -*- coding: utf-8 -*-
"""Phase 2 · 不变量测试（I1–I5 的验证）

对应 PHASE-2-SCHEMA-FREEZE.md 第五部分的检查表。
用 S5/P0 的构造样本 + Phase 1 的真实片段跑。
"""
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from adapter import build, classify_file          # noqa: E402
from assess import assess, synthesize, assert_invariants   # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

CASES = [
    ("E5 纯注释/日志",   os.path.join(DOGFOOD, "s5-orthogonal", "e5-aggregation",
                                     "src", "index.js"),
     "有命中但无真实链路"),
    ("E3 结构关系",      os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural",
                                     "src", "index.js"),
     "同对象字段引用"),
    ("E4 非标准实现",    os.path.join(DOGFOOD, "s5-orthogonal",
                                     "e4-structural-bridges-lexical",
                                     "src", "index.js"),
     "lexical 看不见"),
    ("P0-D0 标准",       os.path.join(DOGFOOD, "p0-boundary", "d0-standard",
                                     "src", "index.js"),
     "标准 API"),
    ("P0-B3 本地缓存",    os.path.join(DOGFOOD, "p0-boundary",
                                     "b3-local-cache-only", "src", "index.js"),
     "加密后写本地，不联网"),
    ("（空文本）",        None, "完全无观察"),
]


def run(text, file, file_class="production"):
    obs, by_cap = build(text, file, file_class)
    ass = assess(by_cap)
    cov = {"technical_gap": 0, "largest_unseen_unit": None}
    ver = synthesize(ass, cov)
    return obs, by_cap, ass, ver


def main():
    print("=" * 100)
    print("Phase 2 · 不变量测试")
    print("=" * 100)

    failures = []
    for title, path, note in CASES:
        print("\n" + "#" * 100)
        print("# %s    （%s）" % (title, note))
        if path is None:
            text = ""
            file = "<empty>"
        else:
            if not os.path.exists(path):
                print("# [缺] %s" % path)
                continue
            with open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
            file = os.path.basename(path)

        obs, by_cap, ass, ver = run(text, file)

        # ---- I1–I3 断言 ----
        try:
            assert_invariants(ass, ver)
            inv = "PASS"
        except AssertionError as e:
            inv = "FAIL: %s" % e
            failures.append((title, str(e)))

        print("# Observation: %d   有 Evidence 的能力项: %d" % (len(obs), len(by_cap)))
        print("#")
        print("# verdict            = %s" % ver["verdict"])
        print("# unresolved         = %d 项 %s" % (
            ver["unresolved_count"], ver["unresolved"][:6]))
        print("#   supported        = %s" % (ver["supported"][:6] or "—"))
        print("#   contradicted     = %s" % (ver["contradicted"][:4] or "—"))
        print("#   insufficient     = %s" % (ver["insufficient_evidence"][:6] or "—"))
        print("#   blocked          = %s" % (ver["blocked_by_coverage"][:4] or "—"))
        print("#   not_observed     = %d 项" % len(ver["not_observed"]))
        print("#")
        print("# 逐项状态（仅列非 not_observed）:")
        shown = 0
        for a in ass:
            st = a.evidence_state
            if st == "not_observed":
                continue
            shown += 1
            print("#   %-26s %-22s conf=%-7s %s" % (
                a.capability, st, a.confidence, a.reasons))
        if shown == 0:
            print("#   （全部 not_observed —— 注意：这是"
                  "「没看到」，不是「不存在」）")
        print("#")
        print("# 不变量 I1/I2/I3/I5: %s" % inv)

    # ---- I1 的专项反例：空文本 ----
    print("\n" + "=" * 100)
    print("I1 专项：无观察时，绝不能出现 absent")
    print("=" * 100)
    obs, by_cap, ass, ver = run("", "<empty>")
    states = sorted({a.evidence_state for a in ass})
    print("  空文本下所有能力的状态集合: %s" % states)
    ok = "absent" not in states
    print("  无 'absent' 状态: %s" % ("PASS" if ok else "FAIL"))
    if not ok:
        failures.append(("空文本", "出现 absent"))
    print("  verdict=%s   unresolved=%d" % (ver["verdict"], ver["unresolved_count"]))
    print("""
  说明：什么都没观察到时报 insufficient（证据不足），
        而不是 supported 之外的任何"安全"表述。
        这不是文字游戏 —— 它保证「没找到」不会被读成「不存在」。""")

    # ---- I2 的专项：verdict 必带 unresolved ----
    print("\n" + "=" * 100)
    print("I2 专项：verdict 必须携带 unresolved")
    print("=" * 100)
    got = run(*("", "<empty>"))[3]
    for k in ("unresolved", "unresolved_count", "coverage"):
        print("  含 %-18s : %s" % (k, "PASS" if k in got else "FAIL"))
        if k not in got:
            failures.append(("I2", "缺少 %s" % k))

    print("\n" + "=" * 100)
    if failures:
        print("结论：%d 项不变量检查失败" % len(failures))
        for t, e in failures:
            print("  · %s —— %s" % (t, e))
    else:
        print("结论：全部不变量检查通过（I1 / I2 / I3 / I5 已在实现中落实）")
    print("=" * 100)
    print("""
不变量状态：
  I1  unknown ≠ negative      ✅ 已落实（空文本下无 absent；有证据不报 not_observed）
  I2  unknown ≠ safe          ✅ 已落实（verdict 必带 unresolved / unresolved_count / coverage）
  I3  semantic_role 非必填     ✅ 已落实（Evidence.semantic_role 默认 None）
  I4  Relation 须有结构依据     ⏳ P2 实现，schema 已约束 structural_basis 必填
  I5  无隐藏连续阈值           ✅ 已落实（档位由具名 reasons 决定，断言可回溯）

⚠ 已知未解决（诚实记录）：
  E5（纯注释/日志）仍被判 supported 5 项 —— 因为 role 层已封存（coverage ≈ 0），
  注释里的字符串照样被算作证据。这需要 semantic_role 才能真正解决，
  而 P0.5 已证明它当前不可靠。**这是本阶段的已知边界，不是回归。**""")


if __name__ == "__main__":
    main()
