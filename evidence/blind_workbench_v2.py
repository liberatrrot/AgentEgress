# -*- coding: utf-8 -*-
"""盲标工作台 v2 —— 修掉 v1 的**预期标签泄露**

## v1 的两个漏洞

```
① 只做 detector 隔离 → 物理上没加载 agentegress/locator/relation/assess…
   但**没隔离"对预期标签的认知"**：

   样本名泄漏：  b1-real-user-data / d0-standard / e1-discovery
   stratum 泄漏： "明确 capability-positive"
   注释泄漏：    // D0 标准 API：全部直调
                 // B1 真正加密用户数据并外发（对照：这才是真正的能力）
                 // E1 discovery gap：真实行为存在，但不使用任何标准关键词
```

**这些都是"预期结论"的强提示** —— 会让标注者沿着预设方向解释代码。

## v2 的修补（最小改动，不重建整套）

```
① 只显示不透明 ID（CASE-XXXX），原名 / stratum / 预期标签
   存入独立映射文件 _blind_key.json，**标注结束前不展示**
② **剥离注释后再展示**（注释只能辅助定位，不能作为行为依据）
③ 隐藏文件路径与文件名
④ 保留 v1 的 detector 物理隔离断言
```

**仍然不 import 任何 detector 模块。**
"""
import io
import hashlib
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

DOGFOOD = os.path.join(_ROOT, "tests", "dogfood")
KEY_PATH = os.path.join(_HERE, "_blind_key.json")

FORBIDDEN_IMPORTS = ("agentegress", "adapter", "locator", "relation",
                     "assess", "chain", "chain_eval")


def assert_no_detector_import():
    loaded = set(sys.modules)
    hits = [m for m in FORBIDDEN_IMPORTS if m in loaded]
    assert not hits, "盲标工作台不得加载 detector：%s" % hits
    return True


# ================================================================ 不透明 ID

def opaque_id(name, salt="capgt-v1"):
    """由样本人名生成稳定的不透明 ID（可复现，但不含语义）。"""
    h = hashlib.sha1((salt + name).encode("utf-8")).hexdigest()[:4].upper()
    return "CASE-%s" % h


def build_key(manifest):
    """建映射文件：不透明 ID ↔ 真实元数据。

    ★ 标注期间**不展示右侧任何内容**。
    """
    key = {}
    for c in manifest:
        oid = opaque_id(c["name"])
        key[oid] = {
            "real_case_id": c["case_id"],
            "name": c["name"],           # ← 泄露源
            "stratum": c["stratum"],     # ← 泄露源
            "path": c["path"],
            "stratum_desc": None,        # 由调用方补
        }
    return key


# ================================================================ 剥注释

def strip_comments(text):
    """剥离 // 与 /* */ 注释。

    **自己实现，不 import relation.lex_regions**（那是 detector 的一部分）。
    目的不是"正确 lex"，而是**降低注释对判断的锚定**。
    字符串内的 // 可能被误剥 —— 对本用途可接受（标注看的是逻辑结构）。
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            if j < 0:
                break
            out.append("\n")
            i = j + 1
            continue
        if c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
            continue
        out.append(c)
        i += 1
    # 压掉因剥注释产生的连续空行
    return re.sub(r"\n{3,}", "\n\n", "".join(out))


# ================================================================ 展示

def main():
    assert_no_detector_import()

    manifest = json.load(open(os.path.join(_HERE, "_cap_gt_manifest.json"),
                              encoding="utf-8"))
    key = build_key(manifest)
    with open(KEY_PATH, "w", encoding="utf-8") as f:
        json.dump(key, f, ensure_ascii=False, indent=2)

    only = os.environ.get("BL_STRATUM", "")
    show_real = os.environ.get("BL_SHOW_REAL", "") == "1"   # 只在解盲后使用

    print("=" * 96)
    print("盲标工作台 v2（不透明 ID + 剥注释 + detector 物理隔离）")
    print("=" * 96)
    print("未加载 detector：%s" % ", ".join(FORBIDDEN_IMPORTS))
    print("映射已写入 %s —— **标注结束前不展示其内容**" % os.path.basename(KEY_PATH))
    if show_real:
        print("⚠ BL_SHOW_REAL=1：正在展示真实元数据（仅解盲后允许）")
    print()

    for c in manifest:
        # 已标注过的（第 1 轮）跳过，避免重复劳动
        if c["gt"]["access"]["present"] is not None and not show_real:
            continue
        if only and c["stratum"] != only:
            continue

        oid = opaque_id(c["name"])
        p = os.path.join(DOGFOOD, *c["path"].split("/"))
        if not os.path.exists(p):
            print("[缺] %s" % oid)
            continue
        raw = open(p, encoding="utf-8", errors="ignore").read()
        body = strip_comments(raw)
        if len(body) > 6000:
            body = body[:6000] + "\n... [截断，原 %d 字符]" % len(raw)

        print("─" * 96)
        if show_real:
            print("【%s】%s  (%s)" % (oid, c["name"], c["path"]))
        else:
            print("【%s】  （%d 字符，注释已剥离）" % (oid, len(raw)))
        print("─" * 96)
        print(body)
        print()


if __name__ == "__main__":
    main()
