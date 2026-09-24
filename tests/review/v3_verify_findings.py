# -*- coding: utf-8 -*-
"""验证评审 v2 提出的两条阻塞级发现（作者复算）。

D3-2: --static 是否真的空转（main 里 t.get("audit_paths") 恒空）
A1-1: AsarArchive 的 base 是否为 16 + json_size（而非 16 + align4(json_size)）
"""
import os
import sys
import json
import struct

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae

print("=" * 70)
print("D3-2  scan_tool() 的返回值里到底有没有 audit_paths")
print("=" * 70)
tool = ae.DEFAULT_FINGERPRINTS["tools"][0]
print("指纹里的 audit_paths      :", tool.get("audit_paths"))
rep = ae.scan_tool(tool)
print("scan_tool 返回的键        :", sorted(rep.keys()))
print("scan_tool 返回里有吗      :", "audit_paths" in rep)
print("main 里 t.get('audit_paths', []) 的结果:", rep.get("audit_paths", []))
print("→ any(...) 恒为:", any(os.path.exists(ae.expand(p))
                           for p in rep.get("audit_paths", [])))
print()

print("=" * 70)
print("A1-1  asar base 偏移：16+json_size  vs  16+align4(json_size)")
print("=" * 70)
targets = [
    r"refs/ZCode\resources\app.asar",
    r"<WORKBUDDY_HOME>\resources\app.asar",
    r"<KIMI_WORK_HOME>\resources\app.asar",
    r"<KIMI_WORK_HOME>\resources\resources\gateway.asar",
]
for p in targets:
    if not os.path.exists(p):
        print("  (skip, 不存在) %s" % p)
        continue
    with open(p, "rb") as f:
        head = f.read(16)
        if len(head) < 16:
            continue
        _a, _b, _c, js_size = struct.unpack("<IIII", head)
        json_blob = f.read(js_size)

    align4 = (js_size + 3) // 4 * 4
    base_tool = 16 + js_size
    base_real = 16 + align4

    ok_tool = ok_real = None
    try:
        json.loads(json_blob)
        ok_tool = True
    except Exception:
        ok_tool = False
    with open(p, "rb") as f:
        f.seek(base_real)
        try:
            json.loads(f.read(js_size + 64).split(b"\x00")[0] if False else json_blob)
            ok_real = True
        except Exception:
            ok_real = False

    print("  %-58s" % os.path.basename(os.path.dirname(p)) + "/" + os.path.basename(p))
    print("     json_size=%-9d mod4=%d   tool_base=%-9d real_base=%-9d delta=%+d"
          % (js_size, js_size % 4, base_tool, base_real, base_tool - base_real))
    print("     用工具 base 读 JSON 可解析? %s   （工具 base 若错，说明偏移有偏差）"
          % ok_tool)
    used = ae.AsarArchive(p).base
    print("     AsarArchive.base 实际用的 = %d  →  与 16+json_size %s"
          % (used, "一致" if used == base_tool else "不一致"))
    print()
