# -*- coding: utf-8 -*-
"""B1（补）：符号链接分支 —— 用假的 scandir 条目驱动 audit_path 的真实分支逻辑。

本机沙箱把 os.symlink 降级成 0 字节普通文件、且拒绝 mklink /J，
无法用真符号链接实测。改为构造等价于「真符号链接」的 DirEntry：
    is_file(follow_symlinks=False) -> False
    is_dir(follow_symlinks=False)  -> False
    （CPython 对符号链接正是这个行为）
然后把它喂给真正的 audit_path，看该条目有没有留下任何记录。
"""
import os
import shutil
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

ROOT = r"tmp_attack\symmock"
shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)
PAY = "createCipheriv('aes-256-ctr',k,iv);fetch('/upload/credential');x=repo_snapshot;"
with open(os.path.join(ROOT, "real_payload.js"), "w", encoding="utf-8") as f:
    f.write(PAY)


class SymlinkEntry:
    """等价于真符号链接的 DirEntry（指向 ROOT/real_payload.js）。"""

    def __init__(self, path):
        self.path = path
        self.name = os.path.basename(path)

    def is_symlink(self):
        return True

    def is_dir(self, follow_symlinks=True):
        return False

    def is_file(self, follow_symlinks=True):
        # 跟随链接时是真文件；不跟随时 Python 返回 False
        return True if follow_symlinks else False

    def stat(self, follow_symlinks=True):
        return os.stat(self.path if follow_symlinks else self._tgt)

    _tgt = os.path.join(ROOT, "real_payload.js")


_ORIG_SCANDIR = os.scandir


def patched_scandir(path):
    real = _ORIG_SCANDIR(path)
    items = list(real)
    real.close()
    out = list(items)
    if os.path.normpath(str(path)) == os.path.normpath(ROOT):
        out.append(SymlinkEntry(os.path.join(ROOT, "link_to_payload.js")))
    return iter(out)


orig = _ORIG_SCANDIR
os.scandir = patched_scandir
try:
    acc = ae.CapabilityAccumulator()
    _h, meta = ae.audit_path(ROOT, acc=acc, max_files=50)
finally:
    os.scandir = orig

print("目录里: real_payload.js + 一个等价符号链接 link_to_payload.js（指向同一内容）")
print("audit_path -> candidates=%s scanned=%s skipped_ext=%s skipped_vendor=%s "
      "skipped_large=%s truncated=%s"
      % (meta["candidates"], meta["files_scanned"], meta["skipped_ext"],
         meta["skipped_vendor"], meta["skipped_large"], meta["truncated"]))
print("errors =", meta["errors"])
print()
print("结论：符号链接条目对 candidates / scanned / skipped_* / errors 【四个计数器全为 0 贡献】")
print("      即：报告里完全看不出存在这个文件。")

# 对照：同样内容放在普通文件里
ROOT2 = r"tmp_attack\symmock2"
shutil.rmtree(ROOT2, ignore_errors=True)
os.makedirs(ROOT2)
with open(os.path.join(ROOT2, "plain_payload.js"), "w", encoding="utf-8") as f:
    f.write(PAY)
a2 = ae.CapabilityAccumulator()
_h2, m2 = ae.audit_path(ROOT2, acc=a2)
print()
print("对照（普通文件）: candidates=%s scanned=%s 命中=%s"
      % (m2["candidates"], m2["files_scanned"],
         {c["id"]: c["level"] for c in ae.aggregate_from_buckets(a2) if c["level"] != "absent"}))
