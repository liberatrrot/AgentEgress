#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgentEgress 一键验收 —— 一条命令跑完所有检查，只看最后结论。

为什么要有它：手工验收的流程是「改代码 → 编译 → 跑基准 → 写文件 → 读回来 → 肉眼比对」，
一轮七八个动作，改一次代码就重来一遍。既慢又容易漏项。
把它固化成一条命令 + 一个固定的结果文件，改完只需两步：跑它、读结果。

用法：
  python tests/verify.py              # 标准验收（语法 + 自检 + 标注回归 + 鲁棒性，约 70 s）
  python tests/verify.py --quick      # 跳过 ZCode asar 大样本（约 25 s，pre-commit 用这个）
  python tests/verify.py --full       # 追加真实大样本抽查
  python tests/verify.py --json out.json

退出码：0 = 全部通过；1 = 有失败项。
结果同时写入 tests/last-verify.txt（固定路径，便于直接读）。
"""

import os
import sys
import json
import time
import shutil
import struct
import tempfile
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
LOG_PATH = os.path.join(HERE, "last-verify.txt")
sys.path.insert(0, ROOT)

RESULTS = []


def record(name, ok, detail="", extra=None):
    RESULTS.append({"name": name, "ok": bool(ok), "detail": detail, "extra": extra or {}})
    return ok


# ---------------------------------------------------------------- 1. 语法

def check_syntax():
    f = os.path.join(ROOT, "agentegress.py")
    r = subprocess.run([sys.executable, "-m", "py_compile", f],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return record("语法编译", False, (r.stderr or "").strip()[:300])
    lines = sum(1 for _ in open(f, encoding="utf-8"))
    return record("语法编译", True, "%d 行" % lines, {"lines": lines})


# ---------------------------------------------------------------- 2. 启动自检

def check_selfcheck():
    try:
        import agentegress as ae
    except Exception as e:                      # noqa: BLE001
        return record("启动自检", False, "import 失败：%s" % e)

    caps = len(ae._COMPILED_CAPS)
    pats = sum(len(c["patterns"]) for c in ae._COMPILED_CAPS)
    unverifiable = ae._KEYWORD_CONSISTENCY.get("unverifiable", [])

    detail = "%d 类能力 / %d 个模式" % (caps, pats)
    extra = {"caps": caps, "patterns": pats, "unverifiable": unverifiable}
    if unverifiable:
        detail += "（%d 个模式无法自动验证预筛，已记录）" % len(unverifiable)
    return record("启动自检", True, detail, extra)


# ---------------------------------------------------------------- 3. 标注回归

def check_regression(quick=False):
    import agentegress as ae
    with open(os.path.join(HERE, "cases.json"), encoding="utf-8") as f:
        cases = json.load(f)["cases"]
    if quick:
        # 跳过最大的样本（ZCode asar，约 45 s），保留其余用例
        cases = [c for c in cases if c["kind"] != "asar"] or cases

    ok_present = {"confirmed", "likely"}
    ok_absent = {"absent", "possible"}
    tp = fp = fn = tn = 0
    failures = []

    for case in cases:
        acc = ae.CapabilityAccumulator()
        try:
            _h, meta = ae.audit_path(case["path"], acc=acc)
            lv = {c["id"]: c["level"] for c in ae.aggregate_from_buckets(acc)}
        except Exception as e:                  # noqa: BLE001
            failures.append("%s 异常：%s" % (case["id"], e))
            continue
        for cid in case.get("expect_present", []):
            got = lv.get(cid, "absent")
            if got in ok_present:
                tp += 1
            else:
                fn += 1
                failures.append("%s 漏检 %s（得到 %s）" % (case["id"], cid, got))
        for cid in case.get("expect_absent", []):
            got = lv.get(cid, "absent")
            if got in ok_absent:
                tn += 1
            else:
                fp += 1
                failures.append("%s 误报 %s（得到 %s）" % (case["id"], cid, got))

    p = tp / (tp + fp) if (tp + fp) else None
    r = tp / (tp + fn) if (tp + fn) else None
    f1 = (2 * p * r / (p + r)) if (p and r) else None

    detail = "P=%s R=%s F1=%s（TP%d FP%d FN%d TN%d，%d 例）" % (
        _fmt(p), _fmt(r), _fmt(f1), tp, fp, fn, tn, len(cases))
    return record("标注回归", not failures, detail,
                  {"precision": p, "recall": r, "f1": f1,
                   "tp": tp, "fp": fp, "fn": fn, "tn": tn, "failures": failures})


def _fmt(x):
    return "n/a" if x is None else "%.3f" % x


# ---------------------------------------------------------------- 4. 鲁棒性

def check_robustness():
    import agentegress as ae

    tmp = tempfile.mkdtemp(prefix="egress-rb-")
    cases = []

    def case(name, fn):
        try:
            ok, note = fn()
        except Exception as e:                  # noqa: BLE001
            ok, note = False, "抛异常：%r" % e
        cases.append((name, ok, note))

    # R1 路径穿越：unpacked 条目的相对路径越过 unpacked 目录
    def r1():
        # 构造：unpacked 目录外放一个「机密」文件，再用 ../ 形式的条目名去够它
        base = os.path.join(tmp, "traversal")
        os.makedirs(base, exist_ok=True)
        secret = os.path.join(base, "SECRET_OUTSIDE.txt")
        with open(secret, "w", encoding="utf-8") as f:
            f.write("upload-credential createCipheriv")

        asar = os.path.join(base, "evil.asar")
        tree = {"files": {"evil.js": {"size": 1, "offset": "0", "unpacked": True}}}
        js = json.dumps(tree).encode("utf-8")
        header = (struct.pack("<I", 4) + struct.pack("<I", len(js) + 8)
                  + struct.pack("<I", len(js)) + struct.pack("<I", len(js)))
        with open(asar, "wb") as f:
            f.write(header + js + b"x")
        os.makedirs(asar + ".unpacked", exist_ok=True)

        ar = ae.AsarArchive(asar)
        item = {"unpacked": True}
        evil = ".." + os.sep + "SECRET_OUTSIDE.txt"
        try:
            got = ar.read(evil, item)
        except (ae.AsarError, OSError):
            return True, "越界条目被拒绝"
        if got:
            return False, "越界读取成功，拿到 %d 字节（应被拒绝）" % len(got)
        return True, "未读越界内容（返回空）"

    # R2 损坏的 asar 头
    def r2():
        p = os.path.join(tmp, "broken.asar")
        with open(p, "wb") as f:
            f.write(b"\x04\x00\x00\x00" + b"\xff\xff\xff\xff" * 3 + b"not-json")
        try:
            ae.AsarArchive(p)
            return False, "损坏头部未报错"
        except (ae.AsarError, OSError, ValueError):
            return True, "损坏头部被拒绝"

    # R3 超大文件应被跳过并计数
    def r3():
        d = os.path.join(tmp, "big")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "huge.js"), "w", encoding="utf-8") as f:
            f.write("var x='upload-credential';" + "a" * (11 * 1024 * 1024))
        _h, meta = ae.audit_path(d)
        if meta.get("skipped_large"):
            return True, "跳过 %d 个超大文件并计入 skipped_large" % meta["skipped_large"]
        return False, "超大文件未被跳过（files=%s）" % meta.get("files_scanned")

    # R4 UTF-16LE 文件应能命中（曾经静默零命中）
    def r4():
        d = os.path.join(tmp, "u16")
        os.makedirs(d, exist_ok=True)
        body = "const a='upload-credential'; createCipheriv('aes-256-gcm')"
        with open(os.path.join(d, "u16.js"), "wb") as f:
            f.write(b"\xff\xfe" + body.encode("utf-16-le"))
        acc = ae.CapabilityAccumulator()
        ae.audit_path(d, acc=acc)
        lv = {c["id"]: c["level"] for c in ae.aggregate_from_buckets(acc)}
        hit = lv.get("upload_credential_api", "absent")
        if hit != "absent":
            return True, "UTF-16LE 命中，等级 %s" % hit
        return False, "UTF-16LE 仍零命中"

    # R5 二进制垃圾不应崩溃
    def r5():
        d = os.path.join(tmp, "bin")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "noise.js"), "wb") as f:
            f.write(bytes(range(256)) * 200)
        _h, meta = ae.audit_path(d)
        return True, "未崩溃（扫描 %d 个文件）" % meta.get("files_scanned", 0)

    # R6 超长单行不应崩溃且应能命中
    def r6():
        d = os.path.join(tmp, "longline")
        os.makedirs(d, exist_ok=True)
        line = "var z=1;" * 100000 + "upload-credential"
        with open(os.path.join(d, "long.js"), "w", encoding="utf-8") as f:
            f.write(line)
        acc = ae.CapabilityAccumulator()
        ae.audit_path(d, acc=acc)
        lv = {c["id"]: c["level"] for c in ae.aggregate_from_buckets(acc)}
        if lv.get("upload_credential_api", "absent") != "absent":
            return True, "超长单行命中（约 %d 字符）" % len(line)
        return False, "超长单行零命中"

    # R7 不存在路径 / 空目录
    def r7():
        _h, m1 = ae.audit_path(os.path.join(tmp, "nope"))
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty, exist_ok=True)
        _h2, m2 = ae.audit_path(empty)
        return (bool(m1.get("errors")) and m2.get("files_scanned") == 0,
                "不存在路径报错、空目录正常")

    # R8 目录截断必须有记录
    def r8():
        d = os.path.join(tmp, "many")
        os.makedirs(d, exist_ok=True)
        for i in range(30):
            with open(os.path.join(d, "f%02d.js" % i), "w", encoding="utf-8") as f:
                f.write("var a=1;")
        _h, meta = ae.audit_path(d, max_files=5)
        if meta.get("files_scanned") <= 5 and meta.get("truncated"):
            return True, "上限 %d 生效且标记 truncated" % meta["files_scanned"]
        return False, "max_files 未生效（扫了 %s 个，truncated=%s）" % (
            meta.get("files_scanned"), meta.get("truncated"))

    case("R1 asar 路径穿越防护", r1)
    case("R2 损坏 asar 不崩溃", r2)
    case("R3 超大文件跳过并计数", r3)
    case("R4 UTF-16 文件可命中", r4)
    case("R5 二进制垃圾不崩溃", r5)
    case("R6 超长单行可命中", r6)
    case("R7 不存在路径/空目录", r7)
    case("R8 目录截断有记录", r8)

    shutil.rmtree(tmp, ignore_errors=True)
    passed = sum(1 for _, ok, _ in cases if ok)
    detail = "%d/%d 通过" % (passed, len(cases))
    fails = ["%s：%s" % (n, note) for n, ok, note in cases if not ok]
    if fails:
        detail += "；失败：" + "；".join(fails[:3])
    return record("鲁棒性", passed == len(cases), detail,
                  {"passed": passed, "total": len(cases),
                   "cases": [{"name": n, "ok": ok, "note": note} for n, ok, note in cases]})


# ---------------------------------------------------------------- 5. 大样本（可选）

def check_full():
    target = r"refs/ZCode\resources\app.asar"
    if not os.path.exists(target):
        return record("大样本", True, "样本不存在，跳过")
    import agentegress as ae
    t0 = time.perf_counter()
    acc = ae.CapabilityAccumulator()
    _h, meta = ae.audit_path(target, acc=acc)
    caps = ae.aggregate_from_buckets(acc)
    dt = time.perf_counter() - t0
    lv = {c["id"]: c["level"] for c in caps}
    want = {"workspace_snapshot": ("confirmed", "likely"),
            "object_storage_upload": ("confirmed", "likely"),
            "upload_credential_api": ("confirmed", "likely")}
    bad = [k for k, allowed in want.items() if lv.get(k, "absent") not in allowed]
    cov = {"candidates": meta.get("candidates", 0), "scanned": meta.get("files_scanned", 0)}
    return record("大样本", not bad,
                  "%.1f s / 扫描 %d 文件 / 关键能力%s" % (
                      dt, meta.get("files_scanned", 0), "齐全" if not bad else "缺失 %s" % bad),
                  {"seconds": round(dt, 1), "coverage": cov, "missing": bad, "levels": lv})


# ---------------------------------------------------------------- 输出

def render():
    ok_all = all(r["ok"] for r in RESULTS)
    L = []
    L.append("=" * 74)
    L.append("AgentEgress 验收  %s" % time.strftime("%Y-%m-%d %H:%M:%S"))
    L.append("=" * 74)
    for r in RESULTS:
        L.append("[%s] %-12s %s" % ("OK  " if r["ok"] else "FAIL", r["name"], r["detail"]))
        if not r["ok"]:
            for f in (r["extra"].get("failures") or [])[:5]:
                L.append("        - %s" % f)
            for c in (r["extra"].get("cases") or []):
                if not c["ok"]:
                    L.append("        - %s：%s" % (c["name"], c["note"]))
    L.append("-" * 74)
    L.append("结论：%s" % ("全部通过" if ok_all else "存在失败项"))
    if ok_all:
        checks = {r["name"]: r["extra"] for r in RESULTS}
        reg = checks.get("标注回归", {})
        if reg:
            L.append("      标注回归 F1=%s；鲁棒性 %d/%d" % (
                _fmt(reg.get("f1")),
                checks.get("鲁棒性", {}).get("passed", 0),
                checks.get("鲁棒性", {}).get("total", 0)))
    L.append("=" * 74)
    return "\n".join(L), ok_all


def main():
    args = sys.argv[1:]
    full = "--full" in args
    quick = "--quick" in args
    out_json = None
    if "--json" in args:
        i = args.index("--json")
        if i + 1 < len(args):
            out_json = args[i + 1]

    check_syntax()
    check_selfcheck()
    check_regression(quick=quick)
    check_robustness()
    if full:
        check_full()

    text, ok = render()
    with open(LOG_PATH, "w", encoding="utf-8") as f:
        f.write(text + "\n")
    try:
        print(text)
    except Exception:
        pass

    if out_json:
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"time": time.strftime("%Y-%m-%d %H:%M:%S"),
                       "ok": ok, "results": RESULTS}, f, ensure_ascii=False, indent=2)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
