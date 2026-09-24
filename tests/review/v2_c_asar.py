# -*- coding: utf-8 -*-
"""B3 / C1 / C2：畸形 asar 的异常与边界。

每个用例都真的写到磁盘，再用真正的 AsarArchive / iter_files / audit_path 打开，
记录「抛没抛、什么类型、有没有被接住」。
"""
import json
import os
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

ROOT = r"tmp_attack\asar"
shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)

PAY = b"createCipheriv('aes-256-gcm',k,iv);fetch('/upload/credential');x=repo_snapshot;"


def build(path, tree_obj, payload=PAY):
    """按真实 asar 布局写：[4][pickle_size][json_len][json][pad][data]"""
    js = json.dumps(tree_obj, separators=(",", ":")).encode("utf-8")
    pad = (-len(js)) % 4
    hdr = (struct.pack("<I", 4)
           + struct.pack("<I", 8 + len(js) + pad)
           + struct.pack("<I", 4 + len(js) + pad)
           + struct.pack("<I", len(js)))
    with open(path, "wb") as f:
        f.write(hdr + js + b"\x00" * pad + payload)
    return path


def build_deep(path, depth):
    """手工拼 JSON，绕开 json.dumps 的递归上限。"""
    parts = ['{"files":']
    for i in range(depth):
        parts.append('{"n%d":{"files":' % i)
    parts.append('{"leaf.js":{"size":9,"offset":"0"}}')
    parts.append("}" * (2 * depth))
    parts.append("}")
    js = "".join(parts).encode("utf-8")
    pad = (-len(js)) % 4
    hdr = (struct.pack("<I", 4)
           + struct.pack("<I", 8 + len(js) + pad)
           + struct.pack("<I", 4 + len(js) + pad)
           + struct.pack("<I", len(js)))
    with open(path, "wb") as f:
        f.write(hdr + js + b"\x00" * pad + PAY)
    return path


CASES = [
    ("1 顶层是数组", build(os.path.join(ROOT, "c1.asar"), ["files", 1, 2]),
     "json.loads('[..]') 成功，iter_files 第一句 node.get 就炸"),
    ("2 条目是字符串", build(os.path.join(ROOT, "c2.asar"), {"files": {"a.js": "hello", "b.js": 5}}),
     '"files" in "hello" 为 False → 当叶子 yield，之后 item.get 炸'),
    ("3 size 非数字", build(os.path.join(ROOT, "c3.asar"), {"files": {"a.js": {"size": "abc", "offset": "0"}}}),
     "target 构建阶段 int('abc') 没有 try 包裹"),
    ("4 size 是列表", build(os.path.join(ROOT, "c4.asar"), {"files": {"a.js": {"size": [1, 2], "offset": "0"}}}),
     "int([1,2]) -> TypeError"),
    ("5 size=null", build(os.path.join(ROOT, "c5.asar"), {"files": {"a.js": {"size": None, "offset": "0"}}}),
     "应被 `or 0` 兜住"),
    ("6 offset 远超文件尾", build(os.path.join(ROOT, "c6.asar"), {"files": {"a.js": {"size": 20, "offset": "99999999"}}}),
     "应静默空读"),
    ("7 offset 负数", build(os.path.join(ROOT, "c7.asar"), {"files": {"a.js": {"size": 20, "offset": "-99999"}}}),
     "应返回 None"),
    ("8 offset 非数字", build(os.path.join(ROOT, "c8.asar"), {"files": {"a.js": {"size": 10, "offset": "1e9"}}}),
     "int('1e9') ValueError（read 内有兜底）"),
    ("9 unpacked 路径穿越", build(os.path.join(ROOT, "c9.asar"),
                             {"files": {"..": {"files": {"SECRET.txt": {"unpacked": True}}}}}),
     "应抛 AsarError 并被记进 errors"),
    ("10 1000 层嵌套（手工 JSON）", build_deep(os.path.join(ROOT, "c10.asar"), 1000),
     "json.loads 能过、iter_files 递归爆栈"),
    ("11 2000 层嵌套（手工 JSON）", build_deep(os.path.join(ROOT, "c11.asar"), 2000),
     "同上"),
]

print("=" * 78)
for name, path, note in CASES:
    print()
    print("--- %s   (%s)" % (name, os.path.basename(path)))
    print("    备注: %s" % note)
    print("    文件大小: %d 字节" % os.path.getsize(path))
    try:
        ar = ae.AsarArchive(path)
        print("    AsarArchive() : OK  base=%d" % ar.base)
    except Exception as e:
        print("    AsarArchive() : %s: %s" % (type(e).__name__, str(e)[:80]))
        continue
    try:
        n = sum(1 for _ in ar.iter_files())
        print("    iter_files()  : OK  叶子=%d" % n)
    except Exception as e:
        print("    iter_files()  : %s: %s" % (type(e).__name__, str(e)[:80]))
    try:
        _h, meta = ae.audit_path(path)
        print("    audit_path()  : OK  candidates=%s scanned=%s errors=%s"
              % (meta["candidates"], meta["files_scanned"], meta["errors"][:2]))
    except Exception as e:
        print("    audit_path()  : 抛出未捕获 %s: %s" % (type(e).__name__, str(e)[:80]))

print()
print("=" * 78)
print("MAX_HEADER 边界")
print("=" * 78)
MH = ae.AsarArchive.MAX_HEADER
print("  MAX_HEADER = %d 字节 = %.0f MB" % (MH, MH / 1048576))
for label, js_val, nbytes in (("=MAX_HEADER", MH, 128), ("=MAX_HEADER+1", MH + 1, 128)):
    p = os.path.join(ROOT, "mh_%s.asar" % label.replace("=", "").replace("+", "_"))
    with open(p, "wb") as f:
        f.write(struct.pack("<I", 4) + struct.pack("<I", 0) + struct.pack("<I", 0)
                + struct.pack("<I", js_val))
        f.write(b"[" + b"0" * (nbytes - 1))
    try:
        ae.AsarArchive(p)
        print("  json_size%-14s: OK（未拒绝）  实际文件仅 %d 字节" % (label, os.path.getsize(p)))
    except Exception as e:
        print("  json_size%-14s: %s: %s" % (label, type(e).__name__, str(e)[:70]))
print("  注：f.read(json_size) 在 read 之前就会分配 json_size 字节的缓冲")

print()
print("=" * 78)
print("CLI 级：--static-path 指向畸形 asar 的退出码")
print("=" * 78)
MAIN = os.path.join(str(__import__("pathlib").Path(__file__).resolve().parents[2]), "agentegress.py")
for nm in ("c1.asar", "c2.asar", "c3.asar", "c4.asar", "c10.asar", "c11.asar", "c9.asar"):
    r = subprocess.run([sys.executable, MAIN, "--static-path", os.path.join(ROOT, nm), "--quiet"],
                       capture_output=True, text=True, cwd=str(__import__("pathlib").Path(__file__).resolve().parents[2]))
    err = (r.stderr or "").strip().splitlines()
    exc_line = next((l for l in reversed(err) if l.strip()), "")
    print("  %-10s exit=%-3s  stderr末行=%r" % (nm, r.returncode, exc_line[:100]))
