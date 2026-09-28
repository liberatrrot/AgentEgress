# -*- coding: utf-8 -*-
"""P2 Relation 验收：Precision-first

**不看"能找多少关系"，只看"找出来的对不对"。**
因为 Relation 一旦错了，后面的 Chain 会把错误放大。

三类样本：
    正例    必须识别
    近负例  必须拒绝（看起来像，但不是）
    诱骗例  必须拒绝（lexical trap：注释/字符串里同现）
"""
import io
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from relation import same_object, argument_flow, assert_relation_invariants  # noqa: E402


# ================================================================ 正例

# P-1 · S1 ZCode 的真实结构（摘自 out/host/index.js:487）
#   objectUpload: { url: r.oss.host,
#                   maxBytes: Math.max(t.encryptedArtifact.encryptedSizeBytes, 1), ... }
POS_SAME_OBJECT = """
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

# P-2 · S5/E3 的结构（返回值 → 绑定 → 实参）
POS_ARGUMENT_FLOW = """
async function sync(plain, sink) {
  const artifact = makeArtifact(plain);
  return uploadPutObject(artifact, sink);
}
"""


# ================================================================ 近负例

# N-1 · 两个 object 挨着，但不是同一个
NEG_TWO_OBJECTS = """
const a = { x: encryptedArtifact.encryptedSizeBytes };
const b = { upload: objectStorageClient };
"""

# N-2 · 绑定存在，但上传用的是**别的**参数
NEG_OTHER_CREDENTIAL = """
async function go() {
  const created = await createMedia({ kbId: 1 });
  log(created.cos_credential);
  await uploadToCos(otherCredential, buffer);
}
"""

# N-3 · 两个属性在同一对象，但位置相同（同一属性的值里）
NEG_SAME_PROPERTY = """
const cfg = { endpoint: join(host, path) };
"""


# ================================================================ 诱骗例（lexical trap）

# T-1 · 两个 token 都在**块注释**里，且所在容器看起来像对象字面量
#
# 【第一版测试设计错误】原先写成
#     // artifact.encryptedSizeBytes → objectUpload.maxBytes
#     return { url: ossEntity.host, maxBytes: artifactEntity.encryptedSizeBytes };
#   但测试定位的是 **return 里那两个真实位置** —— 那是**正确的**同对象关系，
#   所以它 PASS 得没错，是我的期望写错了。
#   正确做法：让**被定位的两个 token 本身**落在注释里。
TRAP_COMMENT = """
const config = {
  /* artifact.encryptedSizeBytes -> objectUpload.maxBytes
     uploadToCos(created.cos_credential) */
  real: 1,
  other: 2,
};
function f() { return 1; }
"""

# T-2 · 同现在字符串里
TRAP_STRING = """
const DOC = `
  createCipheriv(...) -> objectUpload.maxBytes
  encryptedArtifact.encryptedSizeBytes
`;
function f() { return 1; }
"""

# T-3 · 同一对象，但两个位置都在**同一个字符串值**里
TRAP_SAME_STRING = """
const manifest = {
  desc: "maxBytes: encryptedArtifact.encryptedSizeBytes, url: oss.host",
  other: 1,
};
"""

# T-4 · 绑定在字符串里出现
TRAP_STR_BINDING = """
const s = "const created = await createMedia(...); uploadToCos(created.cos_credential)";
"""


def loc(text, needle, occurrence=0):
    """返回 needle 第 occurrence 次出现的偏移；找不到返回 None。"""
    i = -1
    for _ in range(occurrence + 1):
        i = text.find(needle, i + 1)
        if i < 0:
            return None
    return i


def run_case(title, text, kind, **kw):
    print("\n" + "=" * 96)
    print("%s" % title)
    print("=" * 96)
    if kind == "same_object":
        a = loc(text, kw["a"])
        b = loc(text, kw["b"])
        r = same_object(text, a, b, kw.get("la"), kw.get("lb"))
    else:
        a = loc(text, kw["a"])
        b = loc(text, kw["b"])
        r = argument_flow(text, a, b)
    expect = kw["expect"]
    got = r["type"] if r else None
    ok = (got == expect) if expect else (r is None)
    print("  期望 %-16s 实际 %-16s  [%s]" % (
        expect or "（无关系）", got or "（无关系）", "PASS" if ok else "FAIL"))
    if r:
        b_ = r["structural_basis"]
        print("  basis.kind = %s" % b_["kind"])
        if r["type"] == "same_object":
            print("  container span = [%d, %d)  property %s ↔ %s" % (
                b_["container_start"], b_["container_end"],
                b_["property_source"], b_["property_target"]))
            print("  span 复核: %r" % text[b_["container_start"]:
                                          min(b_["container_end"],
                                              b_["container_start"] + 70)])
        else:
            print("  binding=%s  return_call=%s  args=%r" % (
                b_["binding_ident"], b_["return_call"],
                text[b_["argument_span"][0]:b_["argument_span"][1]][:50]))
    return ok, r


def main():
    print("=" * 96)
    print("P2 Relation 验收（Precision-first）")
    print("=" * 96)

    results = []
    # ---- 正例 ----
    print("\n【正例：必须识别】")
    results.append(run_case(
        "P-1 · same_object（S1 ZCode 真实结构）",
        POS_SAME_OBJECT, "same_object",
        a="oss.host", b="t.encryptedArtifact.encryptedSizeBytes",
        la="r.oss.host", lb="encryptedArtifact.encryptedSizeBytes",
        expect="same_object"))
    results.append(run_case(
        "P-2 · argument_flow（返回值 → 绑定 → 实参）",
        POS_ARGUMENT_FLOW, "argument_flow",
        a="makeArtifact(plain)", b="uploadPutObject(artifact",
        expect="argument_flow"))

    # ---- 近负例 ----
    print("\n【近负例：必须拒绝】")
    results.append(run_case(
        "N-1 · 两个 object 挨着但不是同一个",
        NEG_TWO_OBJECTS, "same_object",
        a="encryptedArtifact.encryptedSizeBytes", b="objectStorageClient",
        expect=None))
    results.append(run_case(
        "N-2 · 绑定存在，但上传用了别的参数",
        NEG_OTHER_CREDENTIAL, "argument_flow",
        a="createMedia(", b="uploadToCos(otherCredential",
        expect=None))
    results.append(run_case(
        "N-3 · 同一属性内部（非跨属性）",
        NEG_SAME_PROPERTY, "same_object",
        a="host", b="path",
        expect=None))

    # ---- 诱骗例 ----
    print("\n【诱骗例：lexical trap，必须拒绝】")
    results.append(run_case(
        "T-1 · 同现在注释里",
        TRAP_COMMENT, "same_object",
        a="ossEntity.host", b="artifactEntity.encryptedSizeBytes",
        expect=None))
    results.append(run_case(
        "T-2 · 同现在字符串里",
        TRAP_STRING, "same_object",
        a="createCipheriv(", b="objectUpload.maxBytes",
        expect=None))
    results.append(run_case(
        "T-3 · 同一对象的同一个字符串值里",
        TRAP_SAME_STRING, "same_object",
        a="encryptedArtifact.encryptedSizeBytes", b="oss.host",
        expect=None))
    results.append(run_case(
        "T-4 · 绑定出现在字符串里",
        TRAP_STR_BINDING, "argument_flow",
        a="createMedia(", b="uploadToCos(",
        expect=None))

    # ---- 汇总 ----
    n_ok = sum(1 for ok, _ in results if ok)
    print("\n" + "=" * 96)
    print("结果：%d / %d PASS" % (n_ok, len(results)))
    print("=" * 96)

    # ---- 不变量 ----
    print("\nI4 不变量：每条 relation 必须带可机器复核的 basis")
    admitted = [r for _ok, r in results if r]
    try:
        assert_relation_invariants(admitted)
        print("  → PASS（%d 条 relation 全部有结构化 basis）" % len(admitted))
    except AssertionError as e:
        print("  → FAIL: %s" % e)

    print("""
验收口径说明：
  · 正例必须识别       —— 否则 P2 没有价值
  · 近负例必须拒绝     —— 否则 Relation 会污染 Chain
  · 诱骗例必须拒绝     —— Phase 1 的教训：注释/字符串里的同现不构成关系

  **Precision 优先于 coverage。**
  找不出关系是可以接受的（保持 no relation），
  找错关系不行（Chain 会把错误放大）。""")


if __name__ == "__main__":
    main()
