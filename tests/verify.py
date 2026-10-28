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
import re
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

    # 样本目录 refs/ 不在版本库内（体积大，且版权属于对方），需要自行 clone。
    # 缺失时跳过对应用例，不能算成「漏检」——否则新克隆的仓库第一次跑验收就是红的，
    # 而那会把「样本没准备」误报成「检测能力退化」。
    def _resolve(p):
        return p if os.path.isabs(p) else os.path.join(ROOT, p)

    missing = [c["id"] for c in cases if not os.path.exists(_resolve(c["path"]))]
    cases = [c for c in cases if os.path.exists(_resolve(c["path"]))]
    if not cases:
        return record("标注回归", True,
                      "跳过 %d 例：样本目录 refs/ 未克隆（见 README 快速开始）" % len(missing))

    tp = fp = fn = tn = 0
    failures = []

    for case in cases:
        acc = ae.CapabilityAccumulator()
        try:
            _h, meta = ae.audit_path(_resolve(case["path"]), acc=acc)
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
    if missing:
        detail += "；跳过 %d 例（refs/ 样本未克隆）" % len(missing)
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


def check_cli(quick=False):
    """走真实 CLI（main()）的验收。

    【为什么必须有这一节】
    评审 v2 发现 `--static` **从来没有执行过 M3**：main 里取错了数据源
    （`t.get("audit_paths")` 里的 t 是 scan_tool 的返回，不含该字段，判断恒假）。
    而当时 verify.py 的**全部**用例都是直接调库函数——没有一个走 main()，
    所以这个缺陷一路活到 v0.2.2，退出码 0、报告里一行提示都没有。

    **库函数正确 ≠ CLI 正确。** 这一节专门守这个缝。

    做法：现场造一个小 asar + 一个只含该工具的临时指纹库，跑真实 CLI。
    这样几秒钟就能验完，不必依赖真实客户端。
    """
    tmp = tempfile.mkdtemp(prefix="egress-cli-")
    problems = []
    try:
        agent = os.path.join(ROOT, "agentegress.py")
        py = sys.executable

        # 造一个含能力特征的小 asar
        tgt_dir = os.path.join(tmp, "fake")
        os.makedirs(tgt_dir, exist_ok=True)
        asar_path = os.path.join(tgt_dir, "app.asar")
        body = (b"const a='upload-credential';"
                b"createCipheriv('aes-256-gcm');"
                b"fetch('/api/v1/snapshot/upload-credential');"
                b"x-oss-signature")
        tree = {"files": {"main.js": {"size": len(body), "offset": "0"}}}
        js = json.dumps(tree).encode("utf-8")
        pad = (-len(js)) % 4                      # Chromium pickle 的 4 字节对齐
        header = (struct.pack("<I", 4) + struct.pack("<I", len(js) + pad + 8)
                  + struct.pack("<I", len(js) + pad) + struct.pack("<I", len(js)))
        with open(asar_path, "wb") as f:
            f.write(header + js + b" " * pad + body)

        fp_path = os.path.join(tmp, "fp.json")
        with open(fp_path, "w", encoding="utf-8") as f:
            json.dump({"tools": [{
                "id": "clitest", "name": "CLI 测试目标", "vendor": "test",
                "paths": [], "snapshot_hints": [],
                "audit_paths": [asar_path.replace("\\", "/")],
            }]}, f, ensure_ascii=False)

        def run(*argv, timeout=300):
            return subprocess.run([py, agent] + list(argv),
                                  capture_output=True, text=True, timeout=timeout)

        # C1 · --static 必须真的产出 M3 数据（而不是静默什么都不做）
        out1 = os.path.join(tmp, "static.json")
        r = run("--tool", "clitest", "--static", "--quiet",
                "--fingerprints", fp_path, "-j", out1)
        if r.returncode != 0:
            problems.append("--static 退出码 %s：%s" % (r.returncode, (r.stderr or "")[-160:]))
        elif not os.path.exists(out1):
            problems.append("--static 没写出 JSON")
        else:
            with open(out1, encoding="utf-8") as f:
                payload = json.load(f)
            n_static = sum(1 for x in payload.get("results", []) if x.get("static"))
            if n_static == 0:
                problems.append("--static 产出的 static 全为空（M3 根本没执行）")
            else:
                # M3 跑通了，还要确认它真的看到了那份载荷
                st = [x for x in payload["results"] if x.get("static")][0]["static"]
                if not (st.get("summary") or {}).get("confirmed", 0) \
                        and not (st.get("summary") or {}).get("likely", 0):
                    problems.append("--static 跑了但没检出任何能力（载荷写入可能有问题）")

        # C2 · 畸形 asar 不得让 CLI 崩掉（评审：5 类畸形会 exit=1）
        for tag, blob in (("array", b"[]"),
                          ("str", b'"x"')):
            bad = os.path.join(tmp, "bad_%s.asar" % tag)
            b = blob
            h = (struct.pack("<I", 4) + struct.pack("<I", len(b) + 8)
                 + struct.pack("<I", len(b)) + struct.pack("<I", len(b)))
            with open(bad, "wb") as f:
                f.write(h + b)
            r = run("--static-path", bad, "--quiet", "-j", os.path.join(tmp, "bad.json"))
            if r.returncode != 0:
                problems.append("畸形 asar(%s) 让 CLI 崩了：exit=%s" % (tag, r.returncode))

        # C3 · --static-path 指向不存在的路径不应崩
        r = run("--static-path", os.path.join(tmp, "nope.asar"), "--quiet",
                "-j", os.path.join(tmp, "nope.json"))
        if r.returncode != 0:
            problems.append("不存在的目标让 CLI 崩了：exit=%s" % r.returncode)

        # C4 · 报告文件必须真的写出来
        rpt = os.path.join(tmp, "r.html")
        r = run("--tool", "clitest", "--static", "--quiet",
                "--fingerprints", fp_path, "-H", rpt)
        if not os.path.exists(rpt) or os.path.getsize(rpt) < 500:
            problems.append("HTML 报告没写出或过小")
    except Exception as e:                          # noqa: BLE001
        problems.append("CLI 检查异常：%r" % e)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return record("CLI 端到端", not problems,
                  "4 项检查通过" if not problems else "；".join(problems[:3]),
                  {"problems": problems})


# ---- 已知缺口（xfail）----
#
# 这些是**真实存在的缺陷**，不是回归。用 xfail 标记而不是放宽期望值——
# 放宽期望等于把缺陷定义成"正常"，那是最糟的处理方式。
#
# 每条都必须写明：现象 / 为什么现在修不了 / 对应 TODO 条目。
# 提到模块级是为了让 self_audit.py 能在 Gate 输出里列出它们——
# **Gate 通过后如果只显示一片绿色，未来的自己会忘记这些洞。**
KNOWN_GAPS = {
    "oss_export": {
        "object_storage_upload":
            "「用户点击触发 + 目标桶由用户自己配置」仍被判 likely。"
            "要区分「传到用户自己的桶」与「传到厂商的桶」需要目的地归属分析"
            "（同一组字符串，见 TODO.md B0）。",
    },
}


def _count_known_gaps():
    """给 self_audit.py 用：列出已知缺口。"""
    return KNOWN_GAPS


def check_near_negative():
    """近负样本：正常、但「像」外传的场景。

    为什么单独做这一节：外部评审指出，对安全工具，真正难的不是发现恶意，
    而是**不误报正常**。而最容易被误报的恰恰是这些——真实客户端里到处都有：

        auto_update   自动更新：下载安装包   （下载 ≠ 上传）
        telemetry     匿名遥测上报
        crash_report  崩溃堆栈上报
        oss_export    正常使用 OSS SDK 做用户主动导出
        local_crypto  本地文件加密存储（不联网）

    判据不是「不能检出任何能力」（它们确实有 fetch / 有加密），
    而是**不能出现阻断级组合链，也不能把高危能力判成 confirmed**。
    这就是「能力 vs 风险」的边界：能力为真不代表风险为真。
    """
    import agentegress as ae

    tmp = tempfile.mkdtemp(prefix="egress-nearneg-")
    # ---- 场景 1：轻量片段（多类别，覆盖常见误报诱因）----
    scenarios = {
        "auto_update": (
            "// 自动更新：只下载，不上传\n"
            "async function checkUpdate(){const r=await fetch('https://dl.example.com/latest.yml');"
            "const y=await r.text();return y;}\n"
            "function verifySha256(buf,expect){return createHash('sha256').update(buf).digest('hex')===expect;}\n"
            "// electron-updater 的标准用法，不含任何用户数据采集\n"
        ),
        "telemetry": (
            "// 匿名遥测：只上报事件名与版本号\n"
            "function reportEvent(name,props){fetch('https://telemetry.example.com/v1/events',"
            "{method:'POST',body:JSON.stringify({name,props,version:APP_VERSION})});}\n"
            "setInterval(()=>reportEvent('heartbeat',{}),60000);\n"
        ),
        "crash_report": (
            "// 崩溃上报：只发堆栈与平台信息\n"
            "process.on('uncaughtException',(e)=>{fetch('https://crash.example.com/api/report',"
            "{method:'POST',body:JSON.stringify({stack:e.stack,platform:process.platform})});});\n"
        ),
        "oss_export": (
            "// 用户主动导出：用户点按钮才发生，目标桶由用户自己配置\n"
            "exportButton.onClick(async()=>{const cred=await api.post('/user/oss-token');"
            "const fd=new FormData();fd.append('key',cred.path);fd.append('policy',cred.policy);"
            "fd.append('x-oss-signature',cred.signature);"
            "await fetch(cred.host,{method:'POST',body:fd});});\n"
        ),
        "local_crypto": (
            "// 本地加密存储：加密后写本地文件，不联网\n"
            "import {createCipheriv,randomBytes} from 'node:crypto';\n"
            "function saveLocal(data){const key=randomBytes(32);const iv=randomBytes(16);"
            "const c=createCipheriv('aes-256-gcm',key,iv);"
            "fs.writeFileSync('./vault.bin',Buffer.concat([c.update(data),c.final()]));}\n"
        ),
    }

    # ---- 期望表 ----
    #
    # 红队的批评：原来的判据只是「没触发阻断级链」，它证明的是**没吓到用户**，
    # 而不是**报告符合预期**。`possible upload + likely encryption + possible archive`
    # 仍然会让用户以为"这程序有可疑外传能力"。
    #
    # 所以每个场景预先声明它**应该**和**不应该**被检出什么。
    # 偏离期望就是失败——无论偏离方向是"报多了"还是"报少了"。
    EXPECT = {
        "auto_update": {
            "expect_absent": ["workspace_snapshot", "credential_access",
                              "object_storage_upload", "git_history_access"],
            "max_level": {"telemetry_egress": "possible"},
            "note": "只下载安装包，没有采集任何用户数据的证据",
        },
        "telemetry": {
            "expect_absent": ["workspace_snapshot", "credential_access",
                              "object_storage_upload", "git_history_access"],
            "max_level": {"telemetry_egress": "likely"},
            "note": "上报事件名与版本号是合法遥测，不应被判为工作区采集",
        },
        "crash_report": {
            "expect_absent": ["workspace_snapshot", "credential_access",
                              "object_storage_upload", "git_history_access"],
            "max_level": {},
            "note": "只发堆栈，无文件采集",
        },
        "oss_export": {
            "expect_absent": ["workspace_snapshot", "credential_access",
                              "git_history_access"],
            "max_level": {"object_storage_upload": "possible",
                          "upload_credential_api": "possible"},
            "note": "有上传能力，但目标由用户配置、由用户点击触发——上限只能到 possible",
        },
        "local_crypto": {
            "expect_absent": ["workspace_snapshot", "credential_access",
                              "object_storage_upload", "upload_credential_api"],
            "max_level": {"envelope_encryption": "likely"},
            "note": "本地加密不联网，加密能力为真但不构成外传",
        },
    }

    problems = []
    known = []
    details = []
    LEVEL_ORDER = {"absent": 0, "possible": 1, "likely": 2, "confirmed": 3}

    try:
        for name, code in scenarios.items():
            d = os.path.join(tmp, name)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "main.js"), "w", encoding="utf-8") as f:
                f.write(code)
            acc = ae.CapabilityAccumulator()
            _h, _meta = ae.audit_path(d, acc=acc)
            caps = ae.aggregate_from_buckets(acc)
            lv = {c["id"]: c["level"] for c in caps}
            chains = ae.detect_chains(caps, acc=acc)

            exp = EXPECT.get(name, {})
            gaps_here = KNOWN_GAPS.get(name, {})

            def flag(cap_id, msg):
                """命中问题时判断它属于「已知缺口」还是「新问题」。"""
                if cap_id and cap_id in gaps_here:
                    known.append("%s：%s" % (name, gaps_here[cap_id]))
                else:
                    problems.append(msg)

            # 1) 期望不出现的能力必须为 absent
            for cid in exp.get("expect_absent", []):
                got = lv.get(cid, "absent")
                if got != "absent":
                    flag(cid, "%s：不该出现的能力 %s 被判为 %s" % (name, cid, got))
            # 2) 各能力等级不得超过上限
            for cid, cap_lv in exp.get("max_level", {}).items():
                got = lv.get(cid, "absent")
                if LEVEL_ORDER.get(got, 0) > LEVEL_ORDER.get(cap_lv, 0):
                    flag(cid, "%s：%s 等级 %s 超过预期上限 %s"
                         % (name, cid, got, cap_lv))
            # 3) 不得触发阻断级组合
            blocking = [c["name"] for c in chains if c["level"] == "blocking"]
            if blocking:
                problems.append("%s：触发阻断级组合 %s" % (name, blocking))
            # 4) 不得把高危能力判成 confirmed
            high_conf = [c["name"] for c in caps
                         if c["level"] == "confirmed" and c["risk"] == "high"]
            if high_conf:
                problems.append("%s：高危能力被判 confirmed：%s" % (name, high_conf))

            detected = [k for k, v in lv.items() if v != "absent"]
            details.append("%s: 检出 %d 项" % (name, len(detected)))
    except Exception as e:                          # noqa: BLE001
        problems.append("近负样本检查异常：%r" % e)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if problems:
        summary = "；".join(problems[:3])
    elif known:
        summary = ("%d 类符合期望；已知缺口 %d 项（xfail，见 TODO.md）：%s"
                   % (len(scenarios), len(known), known[0].split("：")[0]))
    else:
        summary = "%d 类正常场景均符合期望表" % len(scenarios)

    return record("近负样本", not problems, summary,
                  {"problems": problems, "details": details, "expect": EXPECT,
                   "known_gaps": known})


def check_prefilter_equivalence():
    """预筛等价性回归。

    【为什么需要】外部评审指出：把预筛从 alternation 正则换成逐关键词 `in` 之后，
    两者的 **false-negative set 不一定相同**——大小写、Unicode 折叠、边界都可能差。
    而预筛漏掉一个文件，就是一次永久漏报。换实现必须证明语义等价。

    做法：用**同一张关键词表**重建 regex 参照实现（旧实现），
    在大量边界样本上对比两者结论，任何不一致都报出来。
    """
    import agentegress as ae

    kws = sorted({k.lower() for ks in ae.PATTERN_KEYWORDS.values() for k in ks})
    ref = re.compile("|".join(re.escape(k) for k in sorted(kws, key=len, reverse=True)), re.I)

    samples = []
    # 1) 每个关键词 × 四种大小写形态
    for k in kws:
        samples.append((k, "原样"))
        samples.append((k.upper(), "全大写"))
        samples.append((k.capitalize(), "首字母大写"))
        samples.append(("x" * 50 + k + "y" * 50, "嵌入上下文"))
    # 2) 边界与异常输入
    samples += [
        ("", "空串"),
        ("a" * 5000, "长 ASCII"),
        ("中文测试内容没有任何关键词", "纯中文"),
        ("\x00\x01\x02", "控制字符"),
        ("snapshot/upload", "路径形态"),
        ("SNAPSHOT/UPLOAD", "路径形态-大写"),
        ("upload\u2011credential", "Unicode 连字符（非 ASCII 短横）"),
        ("CreateCipherIv", "驼峰混排"),
        ("policy", "廉价词单现"),
        ("\\.ssh/", "转义字符"),
        ("x-oss-signature", "含短横的强特征"),
    ]
    # 3) Unicode 大小写折叠的已知陷阱
    samples += [("İSTANBUL", "土耳其语 İ（lower 与 re.I 可能不一致）"),
                ("ſnapshot", "长 s（ſ）"),
                ("KELVIN\u212a", "开尔文符号")]

    mismatches = []
    for text, note in samples:
        try:
            a = ref.search(text) is not None
        except Exception as e:                  # noqa: BLE001
            mismatches.append("%s: 参照实现异常 %r" % (note, e))
            continue
        b = ae._prefilter_hit(text)
        if a != b:
            mismatches.append("%s：regex=%s / in=%s（样本 %r）"
                              % (note, a, b, text[:40]))

    return record("预筛等价性", not mismatches,
                  "%d 个边界样本，新旧实现结论一致" % len(samples)
                  if not mismatches else "；".join(mismatches[:3]),
                  {"samples": len(samples), "mismatches": mismatches})


def check_mutation_corpus():
    """变异测试：找出扫描器的「检出边界」在哪一级失效。

    【为什么这个可以提前做】外部评审否掉了「需要能生成可运行客户端」的延期理由——
    我们测的是**静态扫描器**，所以 fixture 不需要真的能跑，
    只要在文本层面逐级加大混淆就够了。

    变异梯度（模拟对抗方逐步加大伪装）：
        M0 直接调用          —— 基线，必须检出
        M1 包一层函数
        M2 拆到另一个模块
        M3 改标识符名
        M4 字符串拼接
        M5 base64 编码
        M6 放进 node_modules
        M7 压成单行
        M8 动态构造（new Function / 运行期拼装）

    这张表本身就是**检出边界的说明**：读者能看到工具在哪一级开始失效，
    而不是只看一个「已确认 7 项」的数字。失效的级别不是 bug，
    是必须如实公开的能力边界。
    """
    import agentegress as ae

    PAYLOAD_VARIANTS = [
        ("M0-直接调用",
         "const c=require('crypto');const cp=c.createCipheriv('aes-256-gcm',k,iv);\n"
         "fetch('/api/v1/snapshot/upload-credential',{method:'POST'});\n"
         "form.append('x-oss-signature',cred.oss.x_oss_signature);\n"
         "archive.append('.git/objects',gitData);\n"),
        ("M1-包一层函数",
         "function doUpload(d){const c=require('crypto');const cp=c.createCipheriv('aes-256-gcm',k,iv);\n"
         "return fetch('/api/v1/snapshot/upload-credential',{method:'POST',body:d});}\n"
         "form.append('x-oss-signature',cred.oss.x_oss_signature);\n"),
        ("M2-拆到另一模块",
         "// uploader.js\nmodule.exports=function(d){return fetch('/api/v1/snapshot/upload-credential');};\n"
         "// crypto.js\nconst cp=require('crypto').createCipheriv('aes-256-gcm',k,iv);\n"
         "// oss.js\nform.append('x-oss-signature',cred.oss.x_oss_signature);\n"),
        ("M3-改标识符名",
         "const _0x1a=require('crypto');const _0x2b=_0x1a.createCipheriv('aes-256-gcm',_0x3c,_0x4d);\n"
         "const _0x5e=_0x6f('/api/v1/snapshot/upload-credential');\n"
         "const _0x7a='x-oss-signature';\n"),
        ("M4-字符串拼接",
         "const p='/api/v1/'+'snapshot'+'/'+'upload'+'-credential';\n"
         "const alg='aes'+'-256'+'-gcm';\n"
         "const sig='x-oss'+'-signature';\n"),
        ("M5-base64",
         "const p=atob('L2FwaS92MS9zbmFwc2hvdC91cGxvYWQtY3JlZGVudGlhbA==');\n"
         "const alg=atob('YWVzLTI1Ni1nY20=');\n"),
        ("M6-放进-vendor",
         "// node_modules/some-pkg/dist/index.js\n"
         "fetch('/api/v1/snapshot/upload-credential');\n"
         "require('crypto').createCipheriv('aes-256-gcm',k,iv);\n"
         "form.append('x-oss-signature',cred.oss.x_oss_signature);\n"),
        ("M7-压成单行",
         "const c=require('crypto');const cp=c.createCipheriv('aes-256-gcm',k,iv);"
         "fetch('/api/v1/snapshot/upload-credential',{method:'POST'});"
         "form.append('x-oss-signature',cred.oss.x_oss_signature);"),
        ("M8-动态构造",
         "const n=['create','Cipher','iv'].join('');const c=require('crypto');"
         "const cp=c[n]('aes-256-gcm',k,iv);"
         "const u=['/api/v1/','snapshot/','upload-credential'].join('');"
         "new Function('u','return fetch(u)')(u);"),
    ]

    tmp = tempfile.mkdtemp(prefix="egress-mut-")
    rows = []
    try:
        for name, code in PAYLOAD_VARIANTS:
            d = os.path.join(tmp, name)
            vendor = name.startswith("M6")
            if vendor:
                d = os.path.join(d, "node_modules", "some-pkg", "dist")
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "index.js"), "w", encoding="utf-8") as f:
                f.write(code)

            acc = ae.CapabilityAccumulator()
            # M6 用 include_vendor=True，否则 vendor 区会被跳过——
            # 那测不出「藏在依赖里」这一级的真实表现
            ae.audit_path(os.path.join(tmp, name), acc=acc,
                          include_vendor=vendor)
            caps = ae.aggregate_from_buckets(acc)
            lv = {c["id"]: c["level"] for c in caps}
            detected = [k for k, v in lv.items() if v in ("confirmed", "likely")]
            # 同时记录「达到 possible 及以上」的集合。
            # 只看 likely 会低估检出能力：单文件 payload 的证据量本来就少，
            # 归一化后很难上 likely，但那不等于「没看见」。
            seen = [k for k, v in lv.items() if v != "absent"]
            rows.append({
                "variant": name,
                "detected": detected,
                "seen": seen,
                "count": len(detected),
                "seen_count": len(seen),
                "levels": lv,
            })
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    baseline = rows[0]["seen_count"] if rows else 0
    blind = [r["variant"] for r in rows if r["seen_count"] == 0]

    # 【断言写错过一次】原实现是 record(..., bool(baseline), ...)——
    # 只要基线 M0 可见就判 PASS，M4/M5/M8 全盲也不影响。
    # 红队的评价：「这不是发现老化，是把老化写进 PASS 的注脚。」
    #
    # 正确的断言分两层：
    #   · 基础变异（直接调用 / 包函数 / 拆模块 / 改标识符 / 压单行）**必须**可见
    #     —— 它们失效意味着检出能力真的退化了，要 FAIL
    #   · 字符串拼接 / base64 / 动态构造 是**已知边界**，允许失效，
    #     但必须出现在结论里（那正是这张表存在的意义）
    REQUIRED = ("M0-", "M1-", "M2-", "M3-", "M7-")
    degraded = [r["variant"] for r in rows
                if r["variant"][:3] in REQUIRED and r["seen_count"] == 0]

    detail = "基线 %d 项可见 → %s" % (baseline, " / ".join(
        "%s:%d" % (r["variant"].split("-")[0], r["seen_count"]) for r in rows))
    if blind:
        detail += "；已知失效：%s" % "、".join(x.split("-")[0] for x in blind)
    if degraded:
        detail = "检出能力退化：%s 不再可见；%s" % ("、".join(degraded), detail)

    return record("变异测试", not degraded and baseline > 0,
                  detail, {"rows": rows, "blind": blind, "degraded": degraded})


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
    check_prefilter_equivalence()
    check_regression(quick=quick)
    check_robustness()
    check_near_negative()
    check_mutation_corpus()
    check_cli(quick=quick)
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
