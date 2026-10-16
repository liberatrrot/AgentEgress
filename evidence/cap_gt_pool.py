# -*- coding: utf-8 -*-
"""P4-CAP-GT v1 · 样本池与抽取

**目的**：抽 24 个分层样本（6 strata × 4），供**盲标**。

**盲标纪律（P4-CAP-GT-SPEC 第四节）**：
    导出内容**只含代码**，不带：
        现有 relation / score / confidence / verdict / candidate_pairs / tool finding
    标注阶段不运行任何 detector。

**为什么必须这样**：否则 GT 会被 detector 污染 →
    "工具说有能力 → 人照工具找证据 → GT 认为有能力 → 再拿 GT 校准工具"
"""
import io
import os
import sys
import json

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.path.insert(0, _HERE)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

# ================================================================ 样本池（按 stratum 手工归类）
#
# ★ 归类依据是**样本的设计意图**（构造样本自带意图说明），
#   不是工具输出 —— 避免"用工具结论决定样本属于哪个 stratum"。

POOL = {
    "S1": {
        "desc": "明确 capability-positive（access + handling + egress + 可达链）",
        "cases": [
            ("b1-real-user-data", "p0-boundary/b1-real-user-data/src/index.js"),
            # 【替换】原 s1-host-snapshotUpload 用的是 2.5MB 文件的 4000 字符截断片段，
            # 内容全是 minified 的 chunk import + 一点类定义，**没有任何实际逻辑**
            # → 四维事实无法成立，不可盲标。
            ("v1-wrapper", "p0-boundary/v1-wrapper/src/index.js"),
            ("e0-baseline", "s5-orthogonal/e0-baseline/src/index.js"),
            ("v0-direct", "p0-boundary/v0-direct/src/index.js"),
            # 【移入】盲标 S2 时发现 d0-standard 的注释是「标准 API：全部直调」，
            # 代码为 treescan → createCipheriv → Buffer.concat → fetch（四维全 1），
            # **它是正对照，不是 negative** —— 原归类错误，移入 S1。
            ("d0-standard", "p0-boundary/d0-standard/src/index.js"),
        ],
    },
    "S2": {
        "desc": "明确 capability-negative（无 access 或无 egress）",
        "cases": [
            ("b2-test-only", "p0-boundary/b2-test-only/src/index.js"),
            ("s3-preload", "s3-opencode/out/preload/index.js"),
            ("s4-urlDetect", "s4-quark/dist/workers/urlDetect.js"),
            # ⚠ S2 只有 3 个样本。
            #   原因：盲标暴露出原归入 S2 的两个样本（d0-standard / e1-discovery）
            #   实际上都是 **positive** —— 说明**"明确 negative"的样本池本身就稀缺**。
            #   **不凑数**：宁可 S2 少一个，也不把归类错误的样本留在里面。
        ],
    },
    "S3": {
        "desc": "data access 有、egress 无（本地处理）",
        "cases": [
            ("b3-local-cache-only", "p0-boundary/b3-local-cache-only/src/index.js"),
            ("d8-lib-encapsulated", "p0-boundary/d8-lib-encapsulated/src/index.js"),
            ("d3-custom-primitive", "p0-boundary/d3-custom-primitive/src/index.js"),
            ("e4-structural-bridges-lexical",
             "s5-orthogonal/e4-structural-bridges-lexical/src/index.js"),
        ],
    },
    "S4": {
        "desc": "egress 有、但与目标数据无结构联系",
        "cases": [
            ("d5-dynamic-property", "p0-boundary/d5-dynamic-property/src/index.js"),
            ("d6-registry-driven", "p0-boundary/d6-registry-driven/src/index.js"),
            ("d7-alias", "p0-boundary/d7-alias/src/index.js"),
            ("v7-function-pointer", "p0-boundary/v7-function-pointer/src/index.js"),
        ],
    },
    "S5": {
        "desc": "★ legitimate upload / telemetry / APM / SDK 边界",
        "cases": [
            ("b4-sdk-internal", "p0-boundary/b4-sdk-internal/src/index.js"),
            ("d1-wrapper", "p0-boundary/d1-wrapper/src/index.js"),
            ("d2-wrapper-partial", "p0-boundary/d2-wrapper-partial/src/index.js"),
            ("e5-aggregation", "s5-orthogonal/e5-aggregation/src/index.js"),
        ],
    },
    "S6": {
        "desc": "结构复杂、需跨函数/跨模块才能确认",
        "cases": [
            ("d4-string-built-name", "p0-boundary/d4-string-built-name/src/index.js"),
            ("v3-helper-split", "p0-boundary/v3-helper-split/src/index.js"),
            ("v6-alias", "p0-boundary/v6-alias/src/index.js"),
            ("e3-structural", "s5-orthogonal/e3-structural/src/index.js"),
            # 【移入】e1-discovery：能力真实存在（四维全 1）但**不用任何标准关键词**，
            # 属于"需跨层/跨命名约定才能确认"的复杂样本。
            ("e1-discovery", "s5-orthogonal/e1-discovery/src/index.js"),
        ],
    },
}

# 大文件需要截取片段（否则导出过慢）
SNIPPET_FILES = {
    "s1-zcode/out/host/index.js": (200000, 4000),
}

# ★ 样本必须**可人工盲标**的下限要求
MAX_CASE_CHARS = 60000      # 超过无法在合理时间内读完并标注
MIN_CASE_CHARS = 300        # 太小则四维事实无法成立


def check_size_guard(name, rel, n_chars):
    """尺寸守卫：不可标注的样本必须换掉，不能默默带进盲标阶段。"""
    if n_chars > MAX_CASE_CHARS:
        return "✗ 过大（%d > %d）—— 无法人工盲标，需替换" % (n_chars,
                                                          MAX_CASE_CHARS)
    if n_chars < MIN_CASE_CHARS:
        return "✗ 过小（%d < %d）—— 四维事实无法成立" % (n_chars,
                                                      MIN_CASE_CHARS)
    return None


def load_case(rel):
    p = os.path.join(DOGFOOD, *rel.split("/"))
    if not os.path.exists(p):
        return None, None
    text = open(p, encoding="utf-8", errors="ignore").read()
    if rel in SNIPPET_FILES:
        start, ln = SNIPPET_FILES[rel]
        text = text[start:start + ln]
        return p, "（片段 @%d 起 %d 字符）\n%s" % (start, ln, text)
    return p, text


def main():
    print("=" * 100)
    print("P4-CAP-GT v1 · 24 个分层样本池")
    print("=" * 100)
    print("""盲标纪律：导出只含代码，**不带 relation / score / verdict / tool finding**。
stratum 归类依据**样本的设计意图**，不是工具输出。""")

    manifest = []
    total = 0
    for sid in sorted(POOL):
        info = POOL[sid]
        print("\n" + "#" * 100)
        print("# %s · %s" % (sid, info["desc"]))
        print("#" * 100)
        for name, rel in info["cases"]:
            total += 1
            p, text = load_case(rel)
            if text is None:
                print("  [缺] %s" % rel)
                continue
            n_lines = text.count("\n") + 1
            guard = check_size_guard(name, rel, len(text))
            flag = ("  " + guard) if guard else ""
            print("  %-34s %-52s %5d 行 %6d 字符%s"
                  % (name, rel, n_lines, len(text), flag))
            manifest.append({
                "case_id": "CAP-%02d" % total,
                "stratum": sid,
                "name": name,
                "path": rel,
                "chars": len(text),
                # ★ GT 模板（全部留空，等人工盲标）
                "gt": {
                    "data_asset": {"type": None, "sensitivity": None},
                    "access": {"present": None, "evidence": None},
                    "handling": {"present": None, "operations": []},
                    "egress": {"present": None, "destination": None,
                               "mechanism": None},
                    "reachability": {"present": None, "chain": None},
                    "capability_class": None,
                    "context": {"legitimate_context": None, "ambiguity": None},
                    "gt_confidence": None,
                    "blocking_gap": None,
                },
                # ★ 结果字段（detector 跑完后填）
                "detector": {
                    "output": None,
                    "error_class": None,
                },
            })

    print("\n" + "=" * 100)
    print("合计 %d 个样本（目标 24）" % total)
    print("=" * 100)
    print("""
下一步（盲标阶段）：
  ① 对每个样本**只读代码**，填写 4 个 GT dimensions
     （access / handling / egress / reachability）
  ② 写 blocking_gap（基于代码本身的可分析性，不是事后归因）
  ③ **冻结 GT**
  ④ 之后才跑 detector，填 detector.output 与 error_class

ERROR_CLASS（只有最后两类允许进调参讨论）：
    implementation | locator | relation_schema | evidence
  | capability_model | **calibration** | **verification**""")

    out = os.path.join(_HERE, "_cap_gt_manifest.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    print("\n样本清单已保存: _cap_gt_manifest.json")


if __name__ == "__main__":
    main()
