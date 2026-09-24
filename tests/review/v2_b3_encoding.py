# -*- coding: utf-8 -*-
"""B3：编码解码、超长/超多换行、权限拒绝。

重点看「静默零命中」和「单文件把内存打爆」两类。
"""
import os
import shutil
import stat
import subprocess
import sys
import tracemalloc

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

ROOT = r"tmp_attack\b3"
shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)

PAY_JS = ("const c=require('crypto');\n"
          "const e=c.createCipheriv('aes-256-ctr',k,iv);\n"
          "fetch('/upload/credential');\n"
          "x=repo_snapshot;y=uploadUrl;z=aliyuncs.com;\n"
          "p=c.publicEncrypt({padding:constants.RSA_OAEP_PADDING},k);\n")


def audit(name, data, ext=".js"):
    d = os.path.join(ROOT, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "f" + ext), "wb") as f:
        f.write(data)
    acc = ae.CapabilityAccumulator()
    _h, m = ae.audit_path(d, acc=acc)
    lv = {c["id"]: c["level"] for c in ae.aggregate_from_buckets(acc) if c["level"] != "absent"}
    print("  %-34s scanned=%s hits=%-4d 能力=%s"
          % (name, m["files_scanned"], acc.total_hits, lv))
    return m, lv


print("=" * 78)
print("B3-1  各种编码下的命中情况")
audit("a_utf8_plain", PAY_JS.encode("utf-8"))
audit("b_utf8_bom", b"\xef\xbb\xbf" + PAY_JS.encode("utf-8"))
audit("c_utf16le_bom", b"\xff\xfe" + PAY_JS.encode("utf-16-le"))
audit("d_utf16be_bom", b"\xfe\xff" + PAY_JS.encode("utf-16-be"))
audit("e_utf16le_nobom", PAY_JS.encode("utf-16-le"))

# 前 4096 字节里 NUL 占比 > 20% 的【UTF-8】文件 —— 会被误判成 UTF-16LE
pad = b"\x00" * 2000
audit("f_utf8_with_nul_prefix", pad + PAY_JS.encode("utf-8"))

# 非法 UTF-8 字节夹在关键字中间
bad = PAY_JS.replace("createCipheriv", "crea\xff\xfeteCipheriv")
audit("g_invalid_utf8_inside_kw", bad.encode("utf-8", "replace"))

print()
print("=" * 78)
print("B3-2  decode_bytes 对「非法字节」的处理方式")
blob = b"abc\xff\xfe\x80\x81 def createCipheriv"
print("  原始字节: %r" % blob)
print("  decode_bytes -> %r" % ae.decode_bytes(blob))
print("  → errors='ignore'：非法字节被【静默丢弃】，不抛异常、不记录")
print("  → 若关键字被非法字节从中间切开，命中就消失：")
kw = b"createCipher\xff\xffiv"
print("     %r 里含 'createCipheriv'? %s" % (kw, b"createCipheriv" in kw))
print("     decode_bytes(%r) = %r" % (kw, ae.decode_bytes(kw)))

print()
print("=" * 78)
print("B3-3  单文件把内存打爆：8 MB 换行 / 8 MB 长行")
for label, body in (("8MB 全是换行", b"\n" * (8 * 1024 * 1024)),
                    ("8MB 单行", b"a" * (8 * 1024 * 1024)),
                    ("8MB 换行+尾部载荷", b"\n" * (8 * 1024 * 1024 - len(PAY_JS)) + PAY_JS.encode())):
    d = os.path.join(ROOT, "mem_" + label.replace(" ", "_"))
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    with open(os.path.join(d, "f.js"), "wb") as f:
        f.write(body)
    tracemalloc.start()
    acc = ae.CapabilityAccumulator()
    _h, m = ae.audit_path(d, acc=acc)
    cur, pk = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("  %-22s 文件=%.1f MB  scanned=%s 峰值Python堆=%.1f MB  命中能力=%d"
          % (label, len(body) / 1048576, m["files_scanned"], pk / 1048576, acc.total_hits))
    shutil.rmtree(d, ignore_errors=True)

print()
print("  对照：line_starts_index 对 8 MB 换行会往 list 里塞 8M+ 个 int")
t = "\n" * (8 * 1024 * 1024)
tracemalloc.start()
st = ae.line_starts_index(t)
_c, pk = tracemalloc.get_traced_memory()
tracemalloc.stop()
print("  line_starts_index('\\n'*8MB) 长度=%d  峰值Python堆=%.1f MB" % (len(st), pk / 1048576))

print()
print("=" * 78)
print("B3-4  权限拒绝 / 读取失败")
d = os.path.join(ROOT, "perm")
os.makedirs(d, exist_ok=True)
p = os.path.join(d, "locked.js")
with open(p, "w", encoding="utf-8") as f:
    f.write(PAY_JS)
try:
    subprocess.run(["cmd", "/c", "icacls", p, "/deny", "%USERNAME%:(R)"],
                   capture_output=True)
    readable = True
    try:
        open(p, "rb").read()
    except OSError:
        readable = False
    print("  icacls 拒绝读取后仍可读? %s" % readable)
except Exception as e:
    print("  无法设置权限: %s" % e)

# 用目录冒充文件、用不存在的目标做 unpacked 条目
print()
print("  asar unpacked 条目指向不存在的文件：")
import json  # noqa: E402
import struct  # noqa: E402
asar = os.path.join(ROOT, "missing_unpacked.asar")
tree = {"files": {"gone.js": {"size": 10, "offset": "0", "unpacked": True}}}
js = json.dumps(tree, separators=(",", ":")).encode()
padn = (-len(js)) % 4
hdr = (struct.pack("<I", 4) + struct.pack("<I", 8 + len(js) + padn)
       + struct.pack("<I", 4 + len(js) + padn) + struct.pack("<I", len(js)))
with open(asar, "wb") as f:
    f.write(hdr + js + b"\x00" * padn + PAY_JS.encode())
_h, m = ae.audit_path(asar)
print("    candidates=%s scanned=%s errors=%s  → 缺口既不在 errors 也不在 skipped_*"
      % (m["candidates"], m["files_scanned"], m["errors"]))
