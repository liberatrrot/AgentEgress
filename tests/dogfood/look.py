# -*- coding: utf-8 -*-
"""人工分析的辅助工具：在 minified 代码里定位关键词并打印上下文。

【它不是什么】
这不是判定逻辑，只是"把人眼放到正确位置"的取景器。
Ground Truth 的判断由人做出，这个脚本只负责把代码片段端到人面前。

用法：
    python tests/dogfood/look.py <目录> <关键词> [--window 200] [--max 20]
"""

import os
import re
import sys


def iter_files(root):
    for d, _sub, files in os.walk(root):
        for f in files:
            yield os.path.join(d, f)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    root = sys.argv[1]
    kw = sys.argv[2]
    window = 200
    limit = 20
    if "--window" in sys.argv:
        window = int(sys.argv[sys.argv.index("--window") + 1])
    if "--max" in sys.argv:
        limit = int(sys.argv[sys.argv.index("--max") + 1])

    pat = re.compile(re.escape(kw), re.I)
    total = 0
    shown = 0
    for p in sorted(iter_files(root)):
        rel = os.path.relpath(p, root)
        try:
            text = open(p, encoding="utf-8", errors="ignore").read()
        except OSError:
            continue
        for m in pat.finditer(text):
            total += 1
            if shown >= limit:
                continue
            s = max(0, m.start() - window)
            e = min(len(text), m.end() + window)
            frag = text[s:e].replace("\n", "\\n")
            # 行号：数一下前面的换行
            line = text.count("\n", 0, m.start()) + 1
            print("--- %s:%d  (第 %d 处)" % (rel, line, total))
            print("    …%s…" % frag)
            print()
            shown += 1
    print("== 关键词 %r：共 %d 处命中，展示 %d 处 ==" % (kw, total, shown))
    return 0


if __name__ == "__main__":
    sys.exit(main())
