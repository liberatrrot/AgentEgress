# -*- coding: utf-8 -*-
"""P2 证据回放：S1 / S2 / E3 / E4

目标不是重新跑 dogfooding，只验证一件事：
    **新 Relation 层能否稳定重建已知的结构关系？**

★ 其中 E4 的预期最关键：
    应该能建立结构 relation，**但 capability 仍 unknown**
    —— 证明「P2 能发现结构，不代表 P2 自己发明 capability」。
"""
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.path.insert(0, _ROOT)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from relation import relate, assert_relation_invariants, region_at   # noqa: E402
from adapter import build                                      # noqa: E402
from assess import assess, synthesize                          # noqa: E402

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")


def loc(text, needle):
    """定位 needle 在**真实代码区**的第一次出现。

    【实测踩坑】直接 text.find() 会落在**注释里的同样文字**上。
    E4 样本的注释块里写了 `obscureSeal(data) → shipSealed({payload: sealed.sealedBlob})`，
    于是定位到注释 → region=line_comment → 被正确拒绝。
    那不是实现的问题，是**测试定位的问题**。
    """
    i = -1
    while True:
        i = text.find(needle, i + 1)
        if i < 0:
            return -1
        r = region_at(text, i)
        if r == "code":
            return i


# ================================================================ 样本

def load(p):
    with open(p, encoding="utf-8", errors="ignore") as f:
        return f.read()


S1 = """
async function snapshotUpload(oss, t) {
  return { ok: true, snapshotId: n,
    objectKey: oss.path,
    objectUpload: {
      method: "POST",
      url: oss.host,
      expiresAt: Date.now() + 3600000,
      maxBytes: Math.max(t.encryptedArtifact.encryptedSizeBytes, 1),
      formFields: { key: oss.path, policy: oss.policy }
    }
  };
}
"""

# S2：真实代码里 createMedia 的绑定语句我没有完整取到，
#     这里用**行为等价的构造**，并在报告中标注。
S2 = """
async function importFiles(params) {
  const created = await createMedia({ kbId: params.kbId, fileExt: ext });
  if (!created?.media_id || !created?.cos_credential) throw new Error("empty");
  await this.uploadToCos(created.cos_credential, buffer, contentType, cb);
}
"""

E3 = load(os.path.join(DOGFOOD, "s5-orthogonal", "e3-structural", "src", "index.js"))
E4 = load(os.path.join(DOGFOOD, "s5-orthogonal",
                       "e4-structural-bridges-lexical", "src", "index.js"))

CASES = [
    ("S1 · ZCode", "真实代码（out/host/index.js:487 的结构）",
     S1, "oss.host", "t.encryptedArtifact.encryptedSizeBytes",
     "same_object"),
    ("S2 · WorkBuddy", "⚠ 等价构造（真实绑定语句未完整取到）",
     S2, "createMedia(", "uploadToCos(created.cos_credential",
     "argument_flow"),
    ("E3 · 加密产物字段 → 上传参数", "P0/S5 构造样本",
     E3, "sink.url", "artifact.encryptedSizeBytes",
     "same_object"),
    # ★ needle 必须指向**调用点**，不是函数定义。
    #   第一版用 "obscureSeal(" → 命中 `function obscureSeal(plain)` 的定义处，
    #   而 argument_flow 拒绝函数定义是**正确的行为**（定义不构成数据流）。
    ("★ E4 · 非标准加密 → 上传", "S5 构造：obscureSeal → shipSealed",
     E4, "= obscureSeal(", "sealed.sealedBlob",
     "argument_flow"),
]


def main():
    print("=" * 100)
    print("P2 证据回放（S1 / S2 / E3 / E4）")
    print("=" * 100)

    admitted = []
    rows = []
    for title, note, text, a_needle, b_needle, expect in CASES:
        print("\n" + "#" * 100)
        print("# %s    （%s）" % (title, note))
        # 先试 expect 的顺序，再试反向
        a, b = loc(text, a_needle), loc(text, b_needle)
        r = relate(text, a, b, a_needle, b_needle)
        if not r:
            r = relate(text, b, a, b_needle, a_needle)

        got = r["type"] if r else None
        ok = (got == expect)
        print("# 期望 %-16s 实际 %-16s [%s]" % (
            expect, got or "（无关系）", "PASS" if ok else "FAIL"))
        if r:
            admitted.append(r)
            b_ = r["structural_basis"]
            print("#")
            print("# structural_basis（可机器复核）:")
            for k, v in b_.items():
                print("#     %-18s %s" % (k, v))
            if r["type"] == "same_object":
                span = text[b_["container_start"]:b_["container_end"]]
                print("# span 复核: %r" % span[:80])

        # ---- 同一样本的 capability 状态 ----
        obs, by_cap = build(text, "sample.js")
        ass = assess(by_cap)
        ver = synthesize(ass, {"technical_gap": 0})
        non_not = [(x.capability, x.evidence_state) for x in ass
                   if x.evidence_state != "not_observed"]
        print("#")
        print("# 该样本的 capability 状态（来自 adapter，不是 relation）:")
        print("#     Observation = %d" % len(obs))
        if non_not:
            for cap, st in non_not:
                print("#     %-26s %s" % (cap, st))
        else:
            print("#     （全部 not_observed）")
        print("#     verdict = %s   unresolved = %d" % (
            ver["verdict"], ver["unresolved_count"]))
        rows.append((title, ok, got, non_not))

    # ---- 汇总 ----
    print("\n" + "=" * 100)
    print("汇总")
    print("=" * 100)
    n_ok = sum(1 for _t, ok, _g, _n in rows if ok)
    print("  结构关系重建：%d / %d" % (n_ok, len(rows)))

    print("\n  I4 不变量（每条 relation 必须有可机器复核 basis）:")
    try:
        assert_relation_invariants(admitted)
        print("    → PASS（%d 条）" % len(admitted))
    except AssertionError as e:
        print("    → FAIL: %s" % e)

    print("""
★ E4 这一行的意义
    它必须同时满足两条：
      ① 结构关系**能建立**（obscureSeal 的返回值确实进了 shipSealed 的实参）
      ② capability 仍 **not_observed**（因为 obscureSeal 不含任何标准词）
    两条同时成立，才说明：
        Relation 只做「已在证据之间建立结构联系」，
        它**不会**因为看到了结构就自己发明一个 capability。

    这正是 Phase 2 的分层要守住的边界：
        Discovery → Evidence → Relation
        而不是 Relation → 自动宣布 capability""")

    print("\n  逐样本 capability 摘要:")
    for title, ok, got, non_not in rows:
        caps = ", ".join("%s=%s" % (c, s) for c, s in non_not) or "全部 not_observed"
        print("    %-30s relation=%-14s %s" % (title[:30], got or "—", caps[:60]))


if __name__ == "__main__":
    main()
