#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""针对具体疑点的构造性实验。"""
import os, sys, struct, json, shutil, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import agentegress as A

TMP = os.path.join(tempfile.gettempdir(), "ae_probe")
shutil.rmtree(TMP, ignore_errors=True)
os.makedirs(TMP, exist_ok=True)

def probe(name, relpath, content_bytes, bundled=False):
    text = content_bytes.decode("utf-8", "ignore")
    lang = A.detect_lang(relpath)
    hits = A.scan_text_for_capabilities(relpath, text, lang, bundled=bundled)
    caps = sorted({h["cap"] for h in hits})
    print("  [%s] lang=%-5s hits=%-3d caps=%s" % (name, lang, len(hits), caps))
    for h in hits[:4]:
        print("        %-22s %-18s region=%-12s class=%-10s w=%d" %
              (h["cap"], h["pat"], h["region"], h["file_class"], h["weight"]))
    return caps

print("=" * 76)
print("实验 1 · 同一批『代码区』模式，放在 JSON 里 vs 放在 JS 里")
j = b'{"failureCount": 3, "retryDelay": 5000, "maxRetries": 10}'
probe("json", "cfg.json", j, bundled=True)
probe("js  ", "cfg.js", j, bundled=True)

print()
print("实验 2 · createCipheriv / upload-credential 在 JSON 配置里")
probe("json", "a.json", b'{"cipher":"createCipheriv","url":"upload-credential"}', bundled=True)
probe("js  ", "a.js",   b'var c="createCipheriv",u="upload-credential";', bundled=True)

print()
print("实验 3 · .min.js 是否被整文件跳过（audit_path 层）")
d = os.path.join(TMP, "minjs"); os.makedirs(d, exist_ok=True)
open(os.path.join(d, "bundle.min.js"), "wb").write(
    b'var x="upload-credential";var y="x-oss-signature";var z="snapshot/upload";')
open(os.path.join(d, "bundle.js"), "wb").write(
    b'var x="upload-credential";var y="x-oss-signature";var z="snapshot/upload";')
acc = A.CapabilityAccumulator()
_h, meta = A.audit_path(d, acc=acc)
print("  audit_path 目录: files_scanned=%s skipped_vendor=%s skipped_large=%s errors=%s raw_hits=%s"
      % (meta["files_scanned"], meta["skipped_vendor"], meta["skipped_large"], meta["errors"], acc.total_hits))
print("  命中能力:", sorted({b['cap'] for b in acc.buckets.values()}))

print()
print("实验 4 · UTF-16LE（Windows 上 .ps1/.txt 常见编码）")
u16 = 'const url = "upload-credential"; createCipheriv("aes-256-gcm",k,iv);'.encode("utf-16-le")
probe("utf16-ps1", "x.ps1", u16, bundled=True)
probe("utf16-js ", "x.js",  u16, bundled=True)
probe("utf8-js  ", "x.js",  u16.decode("utf-16-le").encode("utf-8"), bundled=True)

print()
print("实验 5 · 单文件 > 8MB（默认 max_file_bytes）是否被静默跳过")
d2 = os.path.join(TMP, "big"); os.makedirs(d2, exist_ok=True)
big = (b"/* pad */\n" * 500000) + b'var x="upload-credential";'
open(os.path.join(d2, "big.js"), "wb").write(big)
print("  big.js 大小 = %.2f MB" % (len(big) / 1048576))
acc2 = A.CapabilityAccumulator()
_h, meta2 = A.audit_path(d2, acc=acc2)
print("  files_scanned=%s skipped_large=%s raw_hits=%s caps=%s"
      % (meta2["files_scanned"], meta2["skipped_large"], acc2.total_hits,
         sorted({b['cap'] for b in acc2.buckets.values()})))

print()
print("实验 6 · 目录文件数超过 max_files 时是否有任何提示")
d3 = os.path.join(TMP, "many"); os.makedirs(d3, exist_ok=True)
for i in range(30):
    open(os.path.join(d3, "f%02d.js" % i), "w").write('var s="upload-credential";')
acc3 = A.CapabilityAccumulator()
_h, meta3 = A.audit_path(d3, max_files=5, acc=acc3)
print("  实际文件 30 个, max_files=5 -> files_scanned=%s errors=%s （errors 为空表示静默截断）"
      % (meta3["files_scanned"], meta3["errors"]))

print()
print("实验 7 · 恶意/损坏 asar：负 offset")
def make_asar(path, header_obj, blob=b""):
    hdr = json.dumps(header_obj).encode("utf-8")
    pad = (-len(hdr)) % 4
    hdr += b" " * pad
    with open(path, "wb") as f:
        f.write(struct.pack("<4I", 4, len(hdr) + 8, len(hdr) + 4, len(hdr)))
        f.write(hdr)
        f.write(blob)
bad = os.path.join(TMP, "bad.asar")
make_asar(bad, {"files": {"evil.js": {"size": 10, "offset": -100}}}, b"0123456789")
try:
    hits, meta = A.audit_path(bad)
    print("  audit_path 返回 errors=%s files_scanned=%s" % (meta["errors"], meta["files_scanned"]))
except Exception as e:
    print("  !! audit_path 抛出未捕获异常: %s: %s" % (type(e).__name__, e))

print()
print("实验 8 · 恶意 asar：unpacked 路径穿越")
d4 = os.path.join(TMP, "trav"); os.makedirs(d4, exist_ok=True)
secret = os.path.join(TMP, "secret.js")
open(secret, "w").write('var s="upload-credential";')
asarp = os.path.join(d4, "app.asar")
make_asar(asarp, {"files": {"..": {"files": {"..": {"files": {"secret.js": {"size": 100, "unpacked": True}}}}}}})
open(asarp + ".unpacked", "wb").close()  # 不需要真的存在
os.makedirs(os.path.join(d4, "app.asar.unpacked", "..", ".."), exist_ok=True)
ar = A.AsarArchive(asarp)
for rel, item in ar.iter_files():
    print("  归档内相对路径 =", rel)
    print("  read() 实际读取 =", (ar.read(rel, item) or b"")[:60])
