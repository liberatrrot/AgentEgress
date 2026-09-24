# -*- coding: utf-8 -*-
"""独立验证 asar base 偏移的正确取值。

判据：归档里有大量 .json 文件。用**正确的 base** 读出来，内容应当能 json.loads；
用错误的 base（差 1~3 字节）读出来，开头会混进上一个文件的尾部，解析必失败。
这是不依赖任何一方说法的客观试纸。
"""
import os
import sys
import json
import struct

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))

P = r"refs/ZCode\resources\app.asar"
with open(P, "rb") as f:
    head = f.read(16)
    _a, _b, _c, json_size = struct.unpack("<IIII", head)
    raw = f.read(json_size)

tree = json.loads(raw.decode("utf-8"))
align4 = (json_size + 3) // 4 * 4
base_tool = 16 + json_size          # 当前实现的算法
base_real = 16 + align4             # 假设的真实算法

print("json_size=%d  mod4=%d" % (json_size, json_size % 4))
print("base_tool=%d   base_real=%d   delta=%+d" % (base_tool, base_real, base_tool - base_real))
print()

# 收集若干 .json 条目
jsons = []
def walk(node, prefix=""):
    for name, item in (node.get("files") or {}).items():
        p = prefix + "/" + name
        if "files" in item:
            walk(item, p)
        elif p.endswith(".json") and not item.get("unpacked"):
            jsons.append((p, item))
walk(tree)

print("归档内 .json 条目数：%d，取前 8 个做试纸" % len(jsons))
print("-" * 74)
print("%-46s %-8s %-8s" % ("文件", "tool基准", "real基准"))
print("-" * 74)

tool_ok = real_ok = 0
tried = 0
with open(P, "rb") as f:
    for rel, item in jsons[:60]:
        off = int(item.get("offset", 0))
        size = int(item.get("size", 0))
        if size <= 0 or size > 200000:
            continue
        tried += 1
        res = []
        for base in (base_tool, base_real):
            f.seek(base + off)
            blob = f.read(size)
            try:
                json.loads(blob.decode("utf-8"))
                res.append("OK")
            except Exception:
                res.append("FAIL")
        if res[0] == "OK":
            tool_ok += 1
        if res[1] == "OK":
            real_ok += 1
        if tried <= 8:
            print("%-46s %-8s %-8s" % (rel[-46:], res[0], res[1]))

print("-" * 74)
print("小结：用了 %d 个 .json 试纸" % tried)
print("  按 16+json_size     （当前实现）解析成功 %d 个" % tool_ok)
print("  按 16+align4(json_size)（候选修法）解析成功 %d 个" % real_ok)
print()
if real_ok > tool_ok:
    print(">>> 结论：候选修法正确，当前实现有 %+d 字节偏差" % (base_tool - base_real))
elif tool_ok > real_ok:
    print(">>> 结论：当前实现是对的，评审的指控不成立")
else:
    print(">>> 结论：两者无差异（该归档 mod4==0，无法区分）")
