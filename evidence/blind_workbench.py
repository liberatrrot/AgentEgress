# -*- coding: utf-8 -*-
"""CAP-GT 盲标工作台 —— **纯读文件，不 import 任何 detector**

**为什么要单独写这个脚本**：
    P4-CAP-GT-SPEC 第四节的盲标纪律要求"标注阶段只读代码，不运行任何 detector"。
    最可靠的做法不是"自律"，而是**物理隔离** ——
    本脚本**只**做 `open().read()`，不 import agentegress / locator / relation / assess。

如果直接复用 export_cases.py，它会 import adapter/locator，
"不小心看到工具结论"的风险就会一直存在。
"""
import io
import os
import sys
import json

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")

# 只允许读文件 —— 明确列出本脚本**不得** import 的模块
FORBIDDEN_IMPORTS = ("agentegress", "adapter", "locator", "relation",
                     "assess", "chain", "chain_eval")


def assert_no_detector_import():
    """物理保证：本进程没有加载任何 detector 模块。"""
    loaded = set(sys.modules)
    hits = [m for m in FORBIDDEN_IMPORTS if m in loaded]
    assert not hits, "盲标工作台不得加载 detector：%s" % hits
    return True


def main():
    assert_no_detector_import()

    manifest_path = os.path.join(_HERE, "_cap_gt_manifest.json")
    manifest = json.load(open(manifest_path, encoding="utf-8"))

    only = os.environ.get("BL_STRATUM", "")
    print("=" * 100)
    print("CAP-GT 盲标工作台（只读代码，不运行 detector）")
    print("=" * 100)
    print("已确认未加载 detector 模块：%s" % ", ".join(FORBIDDEN_IMPORTS))
    print()

    for c in manifest:
        if only and c["stratum"] != only:
            continue
        p = os.path.join(DOGFOOD, *c["path"].split("/"))
        if not os.path.exists(p):
            print("[缺] %s" % c["path"])
            continue
        text = open(p, encoding="utf-8", errors="ignore").read()
        # 大文件截断（只影响展示，不影响标注结论）
        if len(text) > 5000:
            text = text[:5000] + "\n... [截断，原文件 %d 字符]" % len(text)

        print("─" * 100)
        print("【%s】%s    stratum=%s" % (c["case_id"], c["name"], c["stratum"]))
        print("  文件: %s   （%d 字符）" % (c["path"], c["chars"]))
        print("─" * 100)
        print(text)
        print()


if __name__ == "__main__":
    main()
