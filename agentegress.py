#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgentEgress - AI 客户端数据外传审计器

定位：审「正在用的工具本身」，不审你要装的东西。
只读、零依赖、不联网、不上报。

模块：
  M1  数据目录指纹库与扫描器  识别各 AI 工具的数据目录、快照残留、pending 密文、异常体积
  M2  打包清单还原器          从明文元数据还原「到底传了哪些文件、多少字节、成功没有」
  M3  客户端静态审计          解包 app.asar / 读源码，判定「有没有外传能力」（而非「有没有在传」）

设计原则：
  · 判定必须基于「结构」而非「文本」——注释里提到 AES 和代码里调用 createCipheriv 是两回事
  · 证据分级：代码区 > 字符串字面量区 > 注释区；生产代码 > 配置 > 测试 > 文档 > 携带区
  · 一切结论必须可回溯到「文件:行:内容」
  · 宁可漏报，不可误报——安全工具的信任是一次性的

用法：
  python agentegress.py                     扫描全部已安装工具（M1 + M2）
  python agentegress.py --tool zcode        只扫指定工具
  python agentegress.py --static            启用 M3 客户端静态审计（自动定位客户端）
  python agentegress.py --static-path P     指定要审计的目录 / app.asar（可重复）
  python agentegress.py --all               包含未安装的工具
  python agentegress.py -m report.md        输出 Markdown 报告
  python agentegress.py -j report.json      输出 JSON
  python agentegress.py -H report.html      输出单文件 HTML 报告（自包含，可离线打开）
  python agentegress.py --quiet             只输出摘要

验收（改动本文件后必跑）：
  python tests/verify.py --quick            语法 + 启动自检 + 标注回归 + 鲁棒性，约 25 s
  python tests/verify.py                    同上，含 asar 大样本，约 70 s
  python tests/verify.py --full             追加真实样本抽查
  结果固定写到 tests/last-verify.txt；退出码 0=通过 1=失败。
  tools/pre-commit 已接 git：改动本文件时提交前会自动跑 --quick 并拦截失败提交。
"""

import os
import re
import sys
import json
import time
import html
import bisect
import struct
import argparse
from array import array

VERSION = "0.2.2"

SKIP_DIRS = {"node_modules", "__pycache__", ".venv", "venv", "site-packages", ".mypy_cache"}

# M3 用的目录跳过规则——**故意不含 node_modules**。
#
# 【坑】M3 早期直接复用了上面的 SKIP_DIRS，而它是在**目录遍历阶段**生效的，
# 于是 node_modules 里的文件根本没被枚举。后果是：
#   · `--include-vendor` 对目录目标完全失效（文件都进不来，权重改得再好也没用）
#   · 「把外传逻辑整个放进 node_modules」这条路检不出（变异测试 M6 实测确认）
#
# 而 node_modules 正是本工具最该防的隐身通道之一。
# 现在把它交给「vendor 分层」策略处理（预筛 + 按判别力降权），
# 而不是在遍历阶段就一刀切排除。
#
# 仍要跳过的是**明确的运行时环境**：里面不会有客户端自研代码，
# 且体积巨大、内容无判别力。
M3_SKIP_DIRS = {"__pycache__", ".venv", "venv", "site-packages", ".mypy_cache",
                ".git", ".hg", ".svn"}

# 上传语义关键词：真正的快照 / 上传状态文件必然命中其一。
# 只带 workspacePath 的普通记录文件不算——那是 Git / 编辑器都会写的字段。
UPLOAD_SEMANTIC_KEYS = (
    "failurecount", "snapshotid", "snapshot_id", "encryptedsizebytes",
    "uploadurl", "upload_url", "pendingupload", "lastcompressedsize",
    "manifesthash", "snapshotupload", "uploadcredential",
)
CONTEXT_KEYS = ("workspacepath", "workspacekey", "workspacesizebytes", "repopath")

# 资源 / 脚本类扩展名：不可能成为外传产物，直接放行
SAFE_EXT = (
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".css", ".scss", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map",
    ".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".ps1", ".bat", ".cmd",
    ".exe", ".dll", ".pyd", ".so", ".dylib", ".md", ".html", ".htm",
)

# 第三方运行时 / 插件区：这些文件是工具「携带」的，不是工具「产生」的
EXCLUDE_PATH_PARTS = (
    "/runtime/", "/binaries/", "/extensions/", "/portablegit/", "/mingw64/",
    "/plugins/", "/marketplaces/", "/connectors-marketplace/", "/tcl8.6/",
    "/node_modules/", "/site-packages/", "/app.asar.unpacked/", "/daimon-bundle/",
    "/uv/", "/.git/", "/resources/", "/locales/", "/vendor/", "/sdk/",
    "/dlls/", "/include/", "/share/", "/encoding/", "/shell-snapshots/",
    "/_upgrade/", "/extension/",
)

# 引擎 / 工具自带的已知无害文件
EXCLUDE_NAME_PARTS = (
    "snapshot_blob.bin", "v8_context_snapshot.bin", "git-upload-pack",
    "_queue.pyd", "queues.py",
)

# 强特征：命中即报「疑似外传产物」
STRONG_EXT = (".enc", ".snapshot", ".outbox", ".unsent")
STRONG_NAME_PARTS = ("pending", "outbox", "upload_pending", "unsent")

# 弱特征：只有在指纹指定的快照区、或快照类目录内出现才算
WEAK_NAME_PARTS = ("upload", "queue", "snapshot", "checkpoint")

MAX_JSON_SCAN = 500
MAX_JSON_SIZE = 3 * 1024 * 1024

DEFAULT_FINGERPRINTS = {
    "version": "0.1.0",
    "updated": "2026-09-21",
    "tools": [
        {
            "id": "zcode",
            "name": "ZCode",
            "vendor": "智谱 Zhipu",
            "baseline": "high",
            "note": "2026-09 被曝静默上传工作区全量快照（含 .git 历史）；v3.14.0 已移除链路；2026-09-21 开源",
            "paths": ["~/.zcode", "%APPDATA%/ZCode", "%LOCALAPPDATA%/@zcodedesktop-updater"],
            "snapshot_hints": ["v2/checkpoints", "v2/repo-wiki"],
            # 只列标准安装位置。装在其它盘/自定义目录时，用 --static-path 手动指定 app.asar，
            # 不要在这里硬编码某台机器的盘符——指纹库是给所有人用的，不是给某一台机器用的。
            "audit_paths": ["%LOCALAPPDATA%/Programs/ZCode/resources/app.asar"],
            "endpoints": ["zcode.z.ai", "*.aliyuncs.com (OSS)"],
            "switches": [
                {"key": "optimizeAgentExperienceEnabled", "claimed": "数据采集 / 遥测上传",
                 "actual": "只决定是否用你的数据训练模型"},
                {"key": "repoSnapshotIndexingEnabled", "claimed": "仓库快照功能本身",
                 "actual": "只决定服务端拿到快照后是否建索引"},
            ],
        },
        {
            "id": "codex",
            "name": "Codex CLI",
            "vendor": "OpenAI",
            "baseline": "medium",
            "note": "会话历史与 rollout 记录落盘在 ~/.codex；模型请求直连官方",
            "paths": ["~/.codex"],
            "snapshot_hints": ["sessions", "history.jsonl", "rollout", "archived_sessions"],
            "endpoints": ["chatgpt.com", "api.openai.com"],
        },
        {
            "id": "workbuddy",
            "name": "WorkBuddy",
            "vendor": "腾讯 Tencent",
            "baseline": "medium",
            "note": "IDE 级 Agent，配置 / 会话 / 二进制运行环境均在数据目录内",
            "paths": ["~/.workbuddy", "%APPDATA%/WorkBuddy", "%LOCALAPPDATA%/WorkBuddy"],
            "snapshot_hints": ["projects", "memory", "session", "history", "log"],
            "audit_paths": ["%LOCALAPPDATA%/Programs/WorkBuddy/resources/app.asar"],
            "endpoints": ["*.tencent.com", "*.qq.com"],
        },
        {
            "id": "kimi-work",
            "name": "Kimi Work",
            "vendor": "月之暗面 Moonshot",
            "baseline": "medium",
            "note": "桌面端 + 工作区数据分离存放",
            "paths": ["~/.kimi-work", "~/.kimi-webbridge", "%APPDATA%/kimi-desktop",
                      "%LOCALAPPDATA%/kimi-desktop-updater"],
            "snapshot_hints": ["cache", "session", "history", "upload", "temp"],
            # 桌面端安装位置随版本变化，不在此硬编码；需要静态审计时用 --static-path 指定
            "audit_paths": [],
            "endpoints": ["*.moonshot.cn", "*.kimi.com"],
        },
        {
            "id": "cursor",
            "name": "Cursor",
            "vendor": "Anysphere",
            "baseline": "medium",
            "note": "AI 编辑器，本地索引与 workspaceStorage 体积通常较大",
            "paths": ["~/.cursor", "%APPDATA%/Cursor"],
            "snapshot_hints": ["workspaceStorage", "globalStorage", "ai-tracking"],
            "audit_paths": ["%LOCALAPPDATA%/Programs/cursor/resources/app.asar"],
            "endpoints": ["api2.cursor.sh", "*.cursor.sh"],
        },
        {
            "id": "tabnine",
            "name": "Tabnine",
            "vendor": "Tabnine",
            "baseline": "low",
            "note": "代码补全，本地模型 + 云端混合",
            "paths": ["~/.tabnine"],
            "snapshot_hints": ["binaries", "models"],
            "endpoints": ["*.tabnine.com"],
        },
        {
            "id": "claude-code",
            "name": "Claude Code",
            "vendor": "Anthropic",
            "baseline": "medium",
            "note": "CLI Agent，会话 JSONL 落盘在 ~/.claude",
            "paths": ["~/.claude", "%APPDATA%/Claude-3p"],
            "snapshot_hints": ["projects", "history.jsonl", "todos", "shell-snapshots"],
            "endpoints": ["api.anthropic.com"],
        },
        {
            "id": "opencode",
            "name": "opencode",
            "vendor": "SST",
            "baseline": "medium",
            "note": "开源 AI 编码桌面端（Electron），本机装于 LOCALAPPDATA\\Programs\\@opencode-aidesktop",
            "paths": ["~/.opencode", "%APPDATA%/opencode", "%LOCALAPPDATA%/@opencode-aidesktop"],
            "snapshot_hints": ["session", "snapshot", "history", "log"],
            "audit_paths": ["%LOCALAPPDATA%/Programs/@opencode-aidesktop/resources/app.asar"],
        },
    ],
}


# ---------------------------------------------------------------- 基础工具

def expand(path):
    """展开 ~ 与 Windows 环境变量占位符。"""
    p = os.path.expanduser(path)
    for key in ("APPDATA", "LOCALAPPDATA", "USERPROFILE", "ProgramData"):
        p = p.replace("%" + key + "%", os.environ.get(key, ""))
    return os.path.normpath(p)


def human(n):
    """人类可读体积。"""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            return "%.2f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0
    return "%.2f PB" % n


def safe_load_json(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def _collect_keys(obj, depth=0, maxdepth=3):
    """递归收集 JSON 的键名（只看键，不看字符串值）。

    这是避免误报的关键。变更记录类文件会把「被修改文件的内容」当字符串存进去，
    纯文本匹配会把「源码里出现了 failureCount 这个词」误判成
    「这是一个快照状态文件」——本工具第一版就踩了这个坑。
    """
    keys = set()
    if depth > maxdepth:
        return keys
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k).lower())
            keys |= _collect_keys(v, depth + 1, maxdepth)
    elif isinstance(obj, list):
        for it in obj[:5]:
            keys |= _collect_keys(it, depth + 1, maxdepth)
    return keys


def looks_like_snapshot_state(path):
    """判断一个 json 是否像「快照 / 上传」状态文件。

    双重门槛：
      1. 必须命中至少一个上传语义键（failureCount / snapshotId / encryptedSizeBytes …）
      2. 键必须出现在 JSON 的「键」位置，而不是文件内容里的字符串
    """
    try:
        if os.path.getsize(path) > MAX_JSON_SIZE:
            return None
    except OSError:
        return None

    data = safe_load_json(path)
    if not isinstance(data, (dict, list)):
        return None

    keys = _collect_keys(data)
    semantic = [k for k in UPLOAD_SEMANTIC_KEYS if k in keys]
    if not semantic:
        return None
    context = [k for k in CONTEXT_KEYS if k in keys]
    if len(semantic) + len(context) < 2:
        return None

    return {"path": path, "hits": semantic + context,
            "semantic": semantic, "context": context,
            "data": data, "raw_len": 0}


# ---------------------------------------------------------------- M1 扫描

# M3 的携带区：第三方依赖不是「这个客户端的能力」。
#
# 实测 ZCode 的 app.asar：可扫内容 254 MB，其中 207.8 MB（81.8%）在 node_modules 下，
# 真正的自研代码只有 /out 下的 2730 个文件 / 46 MB。
#
# 跳过它们有两重意义：
#   性能——扫描量降到 1/5，实测耗时从 245 s 降到 ~45 s
#   准确——第三方库带 crypto / upload / http 能力是它的职责，不是这个客户端的行为。
#          （曾经把 builder-util-runtime 的 s3-accelerate.amazonaws.com 当成"对象存储直传"证据）
#
# 这与 M1 的「携带区 / 工具区」二分是同一套设计，M3 早期版本漏了它。
M3_VENDOR_PARTS = ("/node_modules/", "/vendor/", "/third_party/", "/third-party/", "/.pnpm/")


def _norm(p):
    return p.replace("\\", "/").lower()


def _path_excluded(path_low):
    return any(part in path_low for part in EXCLUDE_PATH_PARTS)


def _name_excluded(nm_low):
    return any(part in nm_low for part in EXCLUDE_NAME_PARTS)


def walk_collect(root, hints=(), want_json=True):
    """一次遍历拿到：体积、文件数、可疑文件、候选 json。

    hints 来自指纹库的 snapshot_hints —— 用于区分「工具自己的快照区」
    与「工具携带的运行时区」，避免把 V8 快照、Tcl 编码表这类文件误报。
    """
    hints_low = [_norm(h) for h in hints]
    result = {
        "files": 0, "bytes": 0,
        "excluded_files": 0, "excluded_bytes": 0,
        "suspicious": [], "json_files": [], "snapshot_dirs": [],
    }
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                try:
                    path_low = _norm(e.path)
                    if e.is_dir(follow_symlinks=False):
                        if e.name in SKIP_DIRS:
                            continue
                        nm = e.name.lower()
                        if not _path_excluded(path_low):
                            if any(h in nm for h in ("checkpoint", "snapshot", "pending", "outbox")):
                                result["snapshot_dirs"].append(e.path)
                        stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        sz = e.stat(follow_symlinks=False).st_size
                        result["files"] += 1
                        result["bytes"] += sz
                        nm = e.name.lower()

                        # 携带区只计体积，不做可疑判定
                        if _path_excluded(path_low):
                            result["excluded_files"] += 1
                            result["excluded_bytes"] += sz
                            continue
                        if _name_excluded(nm) or nm.endswith(SAFE_EXT):
                            continue

                        rel = _norm(os.path.relpath(e.path, root))
                        in_hint = any(h in rel for h in hints_low)
                        in_snap_area = any(k in rel for k in ("checkpoint", "snapshot", "pending", "outbox"))
                        is_strong = nm.endswith(STRONG_EXT) or any(p in nm for p in STRONG_NAME_PARTS)
                        is_weak = any(p in nm for p in WEAK_NAME_PARTS)

                        if (is_strong or (is_weak and (in_hint or in_snap_area))) and sz > 1024:
                            result["suspicious"].append({
                                "path": e.path, "size": sz,
                                "why": "strong" if is_strong else "context",
                            })

                        if want_json and nm.endswith(".json") and sz < MAX_JSON_SIZE:
                            result["json_files"].append(e.path)
                except OSError:
                    continue
    return result


def scan_tool(tool):
    """M1：扫描单个工具的所有数据目录。"""
    report = {
        "id": tool["id"],
        "name": tool["name"],
        "vendor": tool.get("vendor", ""),
        "baseline": tool.get("baseline", "unknown"),
        "note": tool.get("note", ""),
        "endpoints": tool.get("endpoints", []),
        "switches": tool.get("switches", []),
        "installed": False,
        "roots": [],
        "total_files": 0,
        "total_bytes": 0,
        "excluded_bytes": 0,
        "snapshot_states": [],
        "suspicious_files": [],
    }

    json_pool = []
    hints = tool.get("snapshot_hints", [])
    for tpl in tool.get("paths", []):
        root = expand(tpl)
        if not os.path.isdir(root):
            continue
        info = walk_collect(root, hints=hints)
        report["installed"] = True
        report["total_files"] += info["files"]
        report["total_bytes"] += info["bytes"]
        report["excluded_bytes"] += info["excluded_bytes"]
        report["roots"].append({
            "path": root, "files": info["files"], "bytes": info["bytes"],
            "excluded_bytes": info["excluded_bytes"],
        })
        report["suspicious_files"].extend(info["suspicious"])
        if info["snapshot_dirs"]:
            report.setdefault("snapshot_dirs", []).extend(info["snapshot_dirs"])
        json_pool.extend(info["json_files"])

    # 快照状态文件识别：优先名字可疑的
    def priority(p):
        nm = os.path.basename(p).lower()
        score = 0
        if "state" in nm or "snapshot" in nm or "checkpoint" in nm:
            score -= 10
        if "checkpoint" in p.lower() or "snapshot" in p.lower():
            score -= 10
        return score

    json_pool = sorted(set(json_pool), key=priority)[:MAX_JSON_SCAN]
    for jp in json_pool:
        hit = looks_like_snapshot_state(jp)
        if hit:
            report["snapshot_states"].append(hit)

    return report


# ---------------------------------------------------------------- M2 清单还原

def dedupe_by(items, keyfn):
    """按内容签名去重（同一份清单常被重复写入多次）。"""
    seen = set()
    out = []
    for it in items:
        try:
            k = keyfn(it)
        except Exception:
            k = id(it)
        if k in seen:
            continue
        seen.add(k)
        out.append(it)
    return out


def parse_manifest(path):
    """解析打包清单（repo_snapshot_manifest 及同类结构）。"""
    data = safe_load_json(path)
    if not data or not isinstance(data, dict):
        return None
    schema = str(data.get("schema", ""))
    files = data.get("files")
    if not isinstance(files, list):
        return None
    stats = data.get("stats") or {}
    entries = []
    for f in files:
        if isinstance(f, dict):
            entries.append({
                "path": f.get("path", "?"),
                "size": f.get("sizeBytes", 0),
            })
    entries.sort(key=lambda x: -int(x.get("size") or 0))
    return {
        "path": path,
        "schema": schema,
        "workspace": data.get("workspaceKey") or data.get("workspacePath") or "",
        "file_count": stats.get("includedFileCount", len(entries)),
        "bytes": stats.get("includedBytes", sum(int(e["size"] or 0) for e in entries)),
        "entries": entries,
        "mtime": os.path.getmtime(path),
    }


def parse_extra_manifest(path):
    """解析「跨工作区全局配置」清单——采集范围是否超出当前项目。"""
    data = safe_load_json(path)
    if not data or not isinstance(data, dict):
        return None
    groups = data.get("groups")
    if not isinstance(groups, list):
        return None
    out = []
    for g in groups:
        if not isinstance(g, dict):
            continue
        for f in (g.get("files") or []):
            if isinstance(f, dict):
                out.append({
                    "path": f.get("path", "?"),
                    "size": f.get("sizeBytes", 0),
                    "group": g.get("groupId", ""),
                    "source": f.get("source", ""),
                })
    if not out:
        return None
    return {"path": path, "entries": out, "mtime": os.path.getmtime(path)}


def expand_snapshot(state, tool):
    """M2：把一个快照状态扩展成完整画像。"""
    data = state.get("data") or {}
    d = {k.lower(): v for k, v in data.items()} if isinstance(data, dict) else {}

    def pick(*names):
        for n in names:
            if n in d:
                return d[n]
            for k, v in d.items():
                if k == n.lower():
                    return v
        return None

    base = os.path.dirname(state["path"])
    manifest_dir = os.path.join(base, "manifests")
    extra_dir = os.path.join(base, "extra-manifests")
    pending_dir = os.path.join(base, "pending")

    manifests = []
    if os.path.isdir(manifest_dir):
        for f in sorted(os.listdir(manifest_dir)):
            if f.lower().endswith(".json"):
                m = parse_manifest(os.path.join(manifest_dir, f))
                if m:
                    manifests.append(m)

    extras = []
    if os.path.isdir(extra_dir):
        for f in sorted(os.listdir(extra_dir)):
            if f.lower().endswith(".json"):
                m = parse_extra_manifest(os.path.join(extra_dir, f))
                if m:
                    extras.append(m)

    manifests.sort(key=lambda m: -m["mtime"])
    extras.sort(key=lambda x: -x["mtime"])
    manifests = dedupe_by(manifests, lambda m: (
        m["file_count"], m["bytes"],
        tuple(sorted(str(e["path"]) for e in m["entries"]))))
    extras = dedupe_by(extras, lambda x: tuple(sorted(
        str(e["path"]) for e in x["entries"])))

    pending = []
    if os.path.isdir(pending_dir):
        for dp, _dn, fn in os.walk(pending_dir):
            for f in fn:
                fp = os.path.join(dp, f)
                try:
                    pending.append({"path": fp, "size": os.path.getsize(fp)})
                except OSError:
                    pass

    # 是否有 .git 进入清单（最严重的一类）
    git_files = []
    for m in manifests:
        for e in m["entries"]:
            p = str(e["path"]).replace("\\", "/")
            if "/.git/" in p or p.startswith(".git/"):
                git_files.append(p)

    compressed = pick("lastcompressedsize", "lastCompressedSize")
    enc_size = ws_size = None
    if isinstance(compressed, dict):
        cd = {k.lower(): v for k, v in compressed.items()}
        enc_size = cd.get("encryptedsizebytes")
        ws_size = cd.get("workspacesizebytes")

    return {
        "state_file": state["path"],
        "key_hits": state["hits"],
        "workspace": pick("workspacepath", "workspacekey") or "",
        "failure_count": pick("failurecount") or 0,
        "encrypted_bytes": enc_size,
        "workspace_bytes": ws_size,
        "manifests": manifests,
        "extra_manifests": extras,
        "pending": pending,
        "git_in_manifest": git_files,
        "mtime": os.path.getmtime(state["path"]),
    }


# ---------------------------------------------------------------- 判定

def judge(tool, snaps):
    """基于证据判定风险等级。返回 (level, reasons)。"""
    reasons = []
    level = "info"

    def bump(lv):
        order = ["info", "low", "medium", "high", "critical"]
        nonlocal level
        if order.index(lv) > order.index(level):
            level = lv

    for s in snaps:
        if s["failure_count"]:
            bump("high")
            reasons.append("上传链路被触发过：失败计数 = %s" % s["failure_count"])
        if s["pending"]:
            bump("high")
            reasons.append("存在未发出的打包产物 %d 个，共 %s"
                           % (len(s["pending"]), human(sum(p["size"] for p in s["pending"]))))
        if s["manifests"]:
            bump("medium")
            total = sum(m["bytes"] for m in s["manifests"])
            cnt = sum(m["file_count"] for m in s["manifests"])
            reasons.append("存在打包清单：%d 份 / %d 个文件 / %s" % (len(s["manifests"]), cnt, human(total)))
        if s["extra_manifests"]:
            total = sum(len(e["entries"]) for e in s["extra_manifests"])
            bump("high")
            reasons.append("采集范围超出单个工作区：额外纳入 %d 个全局配置文件" % total)
        if s["git_in_manifest"]:
            bump("critical")
            reasons.append("清单中出现 .git 内部文件 %d 项（可能含已删除的密钥与历史）" % len(s["git_in_manifest"]))

    if not snaps and tool.get("installed"):
        reasons.append("未发现快照 / 上传状态痕迹")
        bump(tool.get("baseline", "low") if tool.get("baseline") in ("low", "medium") else "low")

    if not tool.get("installed"):
        return "n/a", ["未安装"]

    return level, reasons


# ================================================================ M3 · 轻量词法扫描
#
# 为什么必须要有这一层：
#   「代码里调用了 createCipheriv」和「注释里提到了 AES-256」是两个完全不同量级的证据。
#   纯文本匹配分不清这两者——本工具上一版就因此把源码里的字符串当成快照状态文件。
#   所以先把文本切成区域，再谈判定。
#
# 不追求完整语言解析，只求准确区分 code / comment / string 三类。够用，且不会失控。

_SPECIAL_RE = re.compile(r'["\'`/#]')

_LANG_BY_EXT = {
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js",
    ".vue": "js", ".svelte": "js",              # 模板 + 脚本，用 js 规则近似
    ".ts": "ts", ".tsx": "ts", ".mts": "ts", ".cts": "ts",
    ".py": "py", ".pyi": "py",
    ".go": "go", ".java": "java", ".rs": "rs",
    ".c": "c", ".h": "c", ".cpp": "c", ".hpp": "c", ".cc": "c", ".m": "c", ".mm": "c",
    ".sh": "sh", ".bash": "sh", ".zsh": "sh",
    ".ps1": "ps1", ".bat": "ps1", ".cmd": "ps1",
    ".yaml": "yaml", ".yml": "yaml", ".toml": "toml", ".ini": "toml", ".cfg": "toml",
    ".json": "json", ".json5": "json", ".jsonc": "json",
    # `#` 注释族
    ".rb": "py", ".pl": "py", ".pm": "py", ".r": "py", ".jl": "py",
    # `//` + `/* */` 注释族
    ".php": "js", ".cs": "js", ".swift": "js", ".kt": "js", ".kts": "js",
    ".scala": "js", ".dart": "js", ".groovy": "js", ".sol": "js",
}

TK_CODE = "code"
TK_LINE_COMMENT = "line_comment"
TK_BLOCK_COMMENT = "block_comment"
TK_STRING = "string"

VENDOR_STRONG_W = 8           # 「强语义证据」的权重门槛
#
# 为什么给到 0.8（而不是 0.10 或 0.55）：
# 变异测试（tests/verify.py 的 check_mutation_corpus）显示，
# 0.55 时「把外传逻辑整个放进 node_modules」这一级**检不出**——
# 那正是「恶意逻辑 vendor 进去」的隐身通道，也是本工具最该防的场景。
#
# 而这些模式（upload-credential / snapshot/upload / x-oss-signature /
# .ssh/ / .git/objects）在**正常第三方库里几乎不出现**——它们出现本身就是异常信号。
# 位置（是不是 node_modules）不应该改变这件事。
# 通用 API（fetch / createCipheriv）才需要靠位置降权。
VENDOR_STRONG_FACTOR = 0.8

# 各区域的证据权重（**相对权重，不是概率**——见 ARCHITECTURE「证据权重，不是概率」）
REGION_FACTOR = {
    TK_CODE: 1.00,           # 真在跑的逻辑
    TK_STRING: 0.85,         # 会被实际使用的字面量（URL 路径、字段名）
    TK_LINE_COMMENT: 0.15,   # 只是提到
    TK_BLOCK_COMMENT: 0.15,
}


# 负向上下文：命中点附近出现这些词，说明代码是在「排除 / 拒绝」而不是「读取」。
#
# 为什么需要：红队用一个**真实的自托管备份工具**在默认参数下打出了 [CRITICAL]，
# 触发点正是它的安全特性 —— `NEVER_BACKUP = ['.ssh/', 'id_rsa', ...]`（**拒绝备份凭据**）。
# 排除列表与窃取列表共用同一套正则，于是"明确不碰密钥"被判成"读取密钥"。
#
# 后果特别讽刺：报告让用户卸载它、换回明文上传的替代品，**安全性反而下降**。
NEGATIVE_CONTEXT = re.compile(
    r"never|exclude|excluded|deny|denied|block|blocked|skip|skipped|ignore|ignored|"
    r"forbid|disallow|blacklist|prohibit|omit|without|"
    r"不要|不应|不允许|排除|忽略|禁止|拒绝|屏蔽",
    re.I)
NEGATIVE_WINDOW = 120      # 命中点前后多少字符内出现负向词，就判为「排除语义」
NEGATIVE_FACTOR = 0.15     # 排除语义下的命中权重（比注释区还低）


def _in_negative_context(text, pos, window=NEGATIVE_WINDOW):
    """命中点是否落在「排除 / 拒绝」语义的上下文里。"""
    lo = max(0, pos - window)
    hi = min(len(text), pos + window)
    return NEGATIVE_CONTEXT.search(text, lo, hi) is not None


def detect_lang(path):
    return _LANG_BY_EXT.get(os.path.splitext(path)[1].lower(), "other")


def lex_regions(text, lang="js"):
    """把源码切成 [(start, end, kind)] 区域序列。

    返回的区间连续覆盖 [0, len(text))，不重叠。
    kind ∈ {code, line_comment, block_comment, string}
    """
    n = len(text)
    if n == 0:
        return []

    if lang == "json":
        # JSON 没有注释语法，但有意义的全是字符串值——整体按字符串处理
        return [(0, n, TK_STRING)]
    if lang == "other":
        return [(0, n, TK_CODE)]

    if lang == "py":
        line_marks, block_marks, quote_marks, tpl_mark = (
            ("#",), (('"""', '"""'), ("'''", "'''")), ('"', "'"), None)
    elif lang in ("js", "ts", "go", "java", "rs", "c"):
        line_marks, block_marks, quote_marks = ("//",), (("/*", "*/"),), ('"', "'")
        tpl_mark = "`" if lang in ("js", "ts") else None
    else:  # sh / ps1 / yaml / toml
        line_marks, block_marks, quote_marks, tpl_mark = ("#",), (), ('"', "'"), None

    segs = []
    i = 0
    code_start = 0
    push = segs.append

    while i < n:
        m = _SPECIAL_RE.search(text, i)
        if not m:
            break
        i = m.start()
        handled = False

        for lm in line_marks:
            if text.startswith(lm, i):
                if code_start < i:
                    push((code_start, i, TK_CODE))
                j = text.find("\n", i)
                j = n if j < 0 else j
                push((i, j, TK_LINE_COMMENT))
                i = code_start = j
                handled = True
                break
        if handled:
            continue

        for bs, be in block_marks:
            if text.startswith(bs, i):
                if code_start < i:
                    push((code_start, i, TK_CODE))
                j = text.find(be, i + len(bs))
                j = n if j < 0 else j + len(be)
                push((i, j, TK_BLOCK_COMMENT))
                i = code_start = j
                handled = True
                break
        if handled:
            continue

        if tpl_mark and text.startswith(tpl_mark, i):
            if code_start < i:
                push((code_start, i, TK_CODE))
            j = i + 1
            while j < n:
                c = text[j]
                if c == "\\":
                    j += 2
                    continue
                if c == tpl_mark:
                    j += 1
                    break
                j += 1
            j = min(j, n)
            push((i, j, TK_STRING))
            i = code_start = j
            continue

        if text[i] in quote_marks:
            q = text[i]
            if code_start < i:
                push((code_start, i, TK_CODE))
            j = i + 1
            while j < n:
                c = text[j]
                if c == "\\":
                    j += 2
                    continue
                if c == q:
                    j += 1
                    break
                if c == "\n":
                    break
                j += 1
            j = min(j, n)
            push((i, j, TK_STRING))
            i = code_start = j
            continue

        i += 1

    if code_start < n:
        push((code_start, n, TK_CODE))
    return segs


def region_at(segs, pos):
    """二分查找某个字符位置属于哪个区域。"""
    lo, hi = 0, len(segs) - 1
    while lo <= hi:
        mid = (lo + hi) >> 1
        s, e, k = segs[mid]
        if pos < s:
            hi = mid - 1
        elif pos >= e:
            lo = mid + 1
        else:
            return k
    return TK_CODE


def _looks_like_text(s, sample=4096):
    """粗略判断一段文本是否「像文本」——用于给编码猜测做复核。

    判据：可打印字符（含常见空白）占比。把 UTF-8 当 UTF-16 解会产出满屏乱码，
    比例会明显掉下来。门槛取 0.85，宁可放过也不误杀。
    """
    seg = s[:sample]
    if not seg:
        return False
    ok = 0
    for ch in seg:
        if ch in "\r\n\t" or ch.isprintable():
            ok += 1
    return ok / float(len(seg)) > 0.85


def decode_bytes(blob):
    """把文件字节解成文本，处理 UTF-8 / UTF-16 BOM 与无 BOM 的 UTF-16。

    为什么需要：`decode("utf-8", "ignore")` 会把 UTF-16 文件里的非 ASCII 字节全部丢弃，
    于是一个 UTF-16 的脚本会「静默零命中」——等于整类文件对审计不可见。
    评审实测：同一段含 upload-credential + createCipheriv 的文本，
    UTF-8 版命中 3 处，UTF-16LE 版命中 0 处。Windows 上的 .ps1 常是 UTF-16。
    """
    if not blob:
        return ""
    if blob.startswith(b"\xef\xbb\xbf"):
        return blob[3:].decode("utf-8", "ignore")
    if blob.startswith(b"\xff\xfe"):
        return blob[2:].decode("utf-16-le", "ignore")
    if blob.startswith(b"\xfe\xff"):
        return blob[2:].decode("utf-16-be", "ignore")
    head = blob[:4096]
    if head and head.count(0) > len(head) * 0.2:
        # 无 BOM 但 NUL 占比很高：候选是 UTF-16LE。但必须**复核**再采信——
        # 评审构造过一个「2000 字节 NUL 前缀 + 正常 UTF-8 正文」的文件，
        # 整份内容被按 UTF-16 解，8 处命中全都消失，而报告里看不出任何异常。
        cand = blob.decode("utf-16-le", "ignore")
        if _looks_like_text(cand):
            return cand
    return blob.decode("utf-8", "ignore")


def line_starts_index(text):
    """预计算每行起始偏移，供二分查找。

    必须做这一步：一次审计可能产生上万个匹配，若每处都 count("\\n") 求行号，
    在 8 MB 文件上就是 O(n^2)。索引是一次 O(n)，之后每次查行号 O(log n)。

    为什么用 array 而不是 list：评审实测一个 8 MB、以换行为主的文件会让
    `list[int]` 吃掉 323 MB Python 堆（8 字节指针 + int 对象）。
    array('l') 是紧凑 C 数组，同内容降到约五分之一。
    `max_file_bytes` 约束的是**文件大小**，不是内存——这条得单独治。
    """
    starts = array("l", [0])
    i = text.find("\n")
    while i >= 0:
        starts.append(i + 1)
        i = text.find("\n", i + 1)
    return starts


def _line_idx(starts, pos):
    return bisect.bisect_right(starts, pos) - 1


def line_no_at(starts, pos):
    """1-based 行号。"""
    return _line_idx(starts, pos) + 1


def context_window(text, starts, pos, radius=3):
    """取所在行前后 radius 行的上下文——用于推断触发方式。"""
    li = _line_idx(starts, pos)
    if li < 0:
        li = 0
    a = max(0, li - radius)
    b = min(len(starts) - 1, li + radius)
    s = starts[a]
    e = starts[b + 1] - 1 if b + 1 < len(starts) else len(text)
    return text[s:e][:700]


def snippet_at(text, pos, width=110):
    """取匹配位置邻域的片段。

    为什么不取整行：压缩过的 JS 一行可能就是 2.5 MB，
    按行取只会展示无关的头 200 字符，让人误以为命中了奇怪的东西。
    按「匹配位置 ± width」取，对正常代码和 minified 代码都成立。
    """
    n = len(text)
    a = max(0, pos - width)
    b = min(n, pos + width)
    frag = text[a:b].replace("\n", " ").replace("\r", " ")
    if a > 0:
        frag = "…" + frag
    if b < n:
        frag = frag + "…"
    return frag[:260]


# ================================================================ M3 · asar 解包
#
# Electron 的 app.asar 是简单容器：16 字节头 + JSON 目录树 + 拼接的文件数据。
# 纯标准库即可解，不需要 Node。

class AsarError(Exception):
    pass


class AsarArchive:
    """只读的 asar 归档访问器。"""

    # 目录树 JSON 的尺寸上限。
    #
    # 原值是 256 MB，等于允许一个 144 字节的恶意文件让审计器分配 256 MB
    # （评审实测：声明 json_size=MAX_HEADER，f.read() 会先按声明长度分配，
    # 实际只填进 144 字节——放大倍数约 1.86×10⁶）。
    #
    # 取值必须同时满足两条：
    #   1. 放得下真实归档 —— 本机实测最大是 ZCode 的 6.7 MB（26785 条目），
    #      Kimi gateway 4.15 MB、WorkBuddy 5.15 MB。曾想改成 4 MB，**那会把 ZCode 拒掉**。
    #   2. 压得住放大 —— 32 MB 把放大倍数从 1.86×10⁶ 降到 2.3×10⁵，且是硬上限。
    MAX_HEADER = 32 * 1024 * 1024

    def __init__(self, path):
        self.path = path
        self.size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(16)
            if len(head) < 16:
                raise AsarError("头部不足 16 字节")
            json_size = struct.unpack("<I", head[12:16])[0]
            if json_size <= 0 or json_size > self.MAX_HEADER:
                raise AsarError("目录树尺寸异常：%d" % json_size)
            raw = f.read(json_size)
        try:
            self.tree = json.loads(raw.decode("utf-8"))
        except Exception as e:
            raise AsarError("目录树解析失败：%s" % e)
        # 【坑】Chromium pickle 会对 payload 做 4 字节对齐，
        # 真实数据起点是 16 + align4(json_size)，不是 16 + json_size。
        #
        # 这个偏差真实存在：8 个本机 asar 里 6 个 json_size % 4 != 0（含主目标 ZCode），
        # 于是每个文件整体前移 1~3 字节——开头混进上一个文件的尾字节、末尾丢 1~3 字节。
        # 用归档内的 .json 当试纸可判定：按 16+json_size 解析成功 0/59，
        # 按 16+align4(json_size) 成功 59/59（见 tests/review/v3_verify_base.py）。
        #
        # 后果不止是内容错位：若前一个文件的尾字节恰是 BOM 前缀（\xff\xfe），
        # decode_bytes 会把整份文件按 UTF-16 解码 → 预筛零命中 → 报告给出
        # 「未发现显著外传能力」。这条攻击路径可被构造，属于端到端漏报。
        self.base = 16 + ((json_size + 3) // 4) * 4
        self.unpacked_dir = path + ".unpacked"

    def iter_files(self, node=None, prefix="", max_depth=64):
        """产出 (相对路径, 条目字典)。

        用**显式栈**而不是递归：畸形归档可以构造上千层嵌套，
        递归实现会抛 RecursionError（评审实测 depth≈1000 即可触发），
        而「归档畸形」不该让整轮审计崩掉——那正好给了恶意客户端一个拒绝服务的手段。

        同时做类型防御：tree 不是 dict、item 不是 dict 都跳过而不是抛异常。
        """
        root = self.tree if node is None else node
        if not isinstance(root, dict):
            raise AsarError("目录树根不是对象（%s）" % type(root).__name__)
        stack = [(root, prefix, 0)]
        while stack:
            cur, cur_prefix, depth = stack.pop()
            if depth > max_depth:
                raise AsarError("目录树嵌套超过 %d 层，拒绝继续解析" % max_depth)
            files = cur.get("files") if isinstance(cur, dict) else None
            if not isinstance(files, dict):
                continue
            for name, item in files.items():
                if not isinstance(item, dict):
                    continue
                p = cur_prefix + "/" + str(name)
                if "files" in item:
                    stack.append((item, p, depth + 1))
                else:
                    yield p, item

    def read(self, rel_path, item, max_bytes=8 * 1024 * 1024):
        """按需读取一个文件的内容（受 max_bytes 限制）。

        安全：unpacked 条目必须做路径穿越校验。
        本工具的设计目标就是「审一个可能恶意的客户端」，所以它必定在不可信输入上
        解析 asar——归档目录树里的文件名可以写成 `../../某文件`，
        若直接 os.path.join 就会读到归档之外。评审实测确认可利用。
        """
        if item.get("unpacked"):
            safe_rel = rel_path.lstrip("/").replace("/", os.sep)
            root = os.path.realpath(self.unpacked_dir)
            target = os.path.realpath(os.path.join(root, safe_rel))
            if target != root and not target.startswith(root + os.sep):
                raise AsarError("归档条目路径越界，拒绝读取：%s" % rel_path)
            try:
                with open(target, "rb") as f:
                    return f.read(max_bytes)
            except OSError:
                return None
        try:
            off = int(item.get("offset", 0))
            size = int(item.get("size", 0))
        except (TypeError, ValueError):
            return None
        if size <= 0 or off < 0:
            return None
        try:
            with open(self.path, "rb") as f:
                f.seek(self.base + off)
                return f.read(min(size, max_bytes))
        except (OSError, ValueError):
            # POSIX 下对负绝对偏移 seek 抛 ValueError；这里一并吞掉，
            # 否则一个畸形归档就能打断整轮扫描
            return None


def find_asar_files(root, limit=6):
    """在目录下递归找 app.asar。"""
    found = []
    stack = [root]
    while stack and len(found) < limit:
        d = stack.pop()
        try:
            it = os.scandir(d)
        except OSError:
            continue
        with it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False):
                        if e.name in SKIP_DIRS:
                            continue
                        stack.append(e.path)
                    elif e.name.lower() == "app.asar":
                        found.append(e.path)
                except OSError:
                    continue
    return found


# ================================================================ M3 · 能力模式库
#
# 判定的是「能力」而不是「行为」：
#   ZCode 删掉了自动上传的触发条件，但 upload-credential 这套「申请凭证 -> 直传对象存储」
#   的架构一行没动。只审行为会漏掉这种「暂时休眠的能力」。
#
# 每个 pattern 有三要素：正则、要求出现在什么区域、权重（1-10）。
# 权重不是拍脑袋：它是「这条证据单独出现时，有多大概率说明该能力真实存在」。

CAPABILITY_DEFS = [
    {
        "id": "workspace_snapshot",
        "name": "工作区全量快照",
        "risk": "high",
        "desc": "把整个工作区打包成快照，通常连带 .git 历史与未提交内容",
        "patterns": [
            {"id": "snap_api_path", "re": r"snapshot/upload", "region": "string", "w": 10,
             "note": "快照上传接口路径"},
            {"id": "repo_snapshot", "re": r"repo[_\-]?snapshot", "region": "any", "w": 9,
             "note": "仓库快照标识"},
            {"id": "snap_manifest", "re": r"snapshot[_-]?manifest", "region": "string", "w": 8,
             "note": "快照清单结构名"},
            {"id": "kind_baseline", "re": r"kind\W{0,4}(baseline|incremental)", "region": "any", "w": 7,
             "note": "快照类型标记"},
            {"id": "capture_hook", "re": r"captureBefore\w*|captureSnapshot|captureWorkspace", "region": "code", "w": 8,
             "note": "快照捕获钩子"},
            {"id": "ckpt_service", "re": r"(Checkpoint|Snapshot)(Manager|Service|Uploader|Store)", "region": "code", "w": 6,
             "note": "快照服务类"},
        ],
    },
    {
        "id": "bulk_archive",
        "name": "批量打包",
        "risk": "medium",
        "desc": "把大量文件压缩成单一归档",
        "patterns": [
            {"id": "tar_create", "re": r"tar\.(create|c)\b|createGzip|createBrotliCompress", "region": "code", "w": 7,
             "note": "创建归档"},
            {"id": "archiver", "re": r"\barchiver\(|\byazl\b|\bzip\.file\(", "region": "code", "w": 7,
             "note": "归档库调用"},
            {"id": "walk_tree", "re": r"walk(?:Sync|Dir)?\(|readdir(?:Sync)?\([^)]*recursive", "region": "code", "w": 4,
             "note": "递归遍历目录"},
            {"id": "glob_all", "re": r"glob(?:Sync)?\([^)]*\*\*", "region": "code", "w": 5,
             "note": "通配递归匹配"},
            {"id": "shutil_archive", "re": r"shutil\.make_archive|zipfile\.ZipFile", "region": "code", "w": 7,
             "note": "Python 归档"},
        ],
    },
    {
        "id": "envelope_encryption",
        "name": "信封加密",
        "risk": "high",
        "desc": "对称密钥加密数据，再用公钥包裹对称密钥——密钥归属决定谁能解密",
        "patterns": [
            {"id": "aes256ctr", "re": r"aes-256-ctr|aes-256-gcm", "region": "string", "w": 8,
             "note": "AES 算法标识"},
            {"id": "cipheriv", "re": r"createCipheriv|createDecipheriv|Cipher\.getInstance", "region": "code", "w": 9,
             "note": "创建加密器"},
            {"id": "rsa_oaep", "re": r"rsa-oaep|RSA_OAEP|oaep", "region": "any", "w": 9,
             "note": "RSA-OAEP 密钥包裹"},
            {"id": "public_encrypt", "re": r"publicEncrypt|encryptWithPublicKey|RSA\.encrypt", "region": "code", "w": 8,
             "note": "公钥加密"},
            {"id": "key_wrap", "re": r"keyWrapAlgorithm|key[_-]?version|wrappedKey|encryptedKey", "region": "any", "w": 8,
             "note": "密钥包裹元数据"},
            {"id": "spki_pem", "re": r"publicKeySpkiPem|spki|BEGIN PUBLIC KEY", "region": "any", "w": 7,
             "note": "公钥序列化"},
        ],
    },
    {
        "id": "object_storage_upload",
        "name": "对象存储直传",
        "risk": "high",
        "desc": "绕过自家业务服务器，直接把数据 POST 到第三方对象存储",
        "patterns": [
            {"id": "aliyun_oss", "re": r"aliyuncs\.com|oss-cn-|x-oss-signature", "region": "any", "w": 9,
             "note": "阿里云 OSS"},
            {"id": "tencent_cos", "re": r"myqcloud\.com|cos\.ap-|x-cos-", "region": "any", "w": 9,
             "note": "腾讯云 COS"},
            {"id": "aws_s3", "re": r"amazonaws\.com|s3\.amazonaws|x-amz-signature", "region": "any", "w": 8,
             "note": "AWS S3"},
            {"id": "post_object", "re": r"PostObject|putObject|multipartUpload|uploadObject", "region": "any", "w": 8,
             "note": "对象存储上传调用"},
            {"id": "upload_url", "re": r"uploadUrl|upload_url|signedUrl|presigned", "region": "any", "w": 7,
             "note": "直传地址字段"},
            {"id": "form_signature", "re": r"policy\W{0,4}(signature|base64)|ossAccessKeyId|formData.*key", "region": "any", "w": 7,
             "note": "表单直传签名"},
        ],
    },
    {
        "id": "upload_credential_api",
        "name": "上传凭证接口",
        "risk": "high",
        "desc": "「先申请凭证、再直传对象存储」这套架构本身",
        "patterns": [
            {"id": "upload_credential", "re": r"upload[-_]credential|uploadCredential", "region": "any", "w": 10,
             "note": "上传凭证接口"},
            {"id": "get_credential", "re": r"(get|request|fetch|create)UploadCredential", "region": "code", "w": 9,
             "note": "凭证申请调用"},
            {"id": "cred_path", "re": r"/upload/(credential|token|sign|ticket)", "region": "string", "w": 8,
             "note": "凭证接口路径"},
            {"id": "cred_expire", "re": r"credential[^,;]{0,30}(expire|ttl|deadline)", "region": "any", "w": 6,
             "note": "凭证有效期"},
        ],
    },
    {
        "id": "retry_backoff",
        "name": "失败自动重试",
        "risk": "medium",
        "desc": "上传失败自动重试——重试机制暴露链路优先级，可选遥测不会重试几百次",
        "patterns": [
            {"id": "failure_count", "re": r"failureCount|failure_count", "region": "code", "w": 7,
             "note": "失败计数"},
            {"id": "retry_count", "re": r"retryCount|retry_count|attempts|maxRetries", "region": "code", "w": 6,
             "note": "重试计数"},
            {"id": "backoff", "re": r"backoff|exponential", "region": "any", "w": 7,
             "note": "退避策略"},
            {"id": "retry_delay", "re": r"retryDelay|retryInterval|failureBaseDelay|baseDelay", "region": "code", "w": 8,
             "note": "重试间隔配置"},
        ],
    },
    {
        "id": "telemetry_egress",
        "name": "遥测上报",
        "risk": "low",
        "desc": "常规产品遥测——多数工具都有，单独看不是问题，要关注上报内容",
        "patterns": [
            {"id": "otlp", "re": r"otlp|opentelemetry", "region": "any", "w": 7,
             "note": "OTLP 上报"},
            {"id": "telemetry", "re": r"telemetry|TelemetryState", "region": "any", "w": 5,
             "note": "遥测模块"},
            {"id": "track_event", "re": r"trackEvent|reportEvent|logEvent|analytics\.track", "region": "code", "w": 6,
             "note": "事件上报"},
            {"id": "apm", "re": r"sentry|arms\.aliyun|apm\.|bugsnag", "region": "any", "w": 5,
             "note": "APM 接入"},
        ],
    },
    {
        "id": "global_config_collection",
        "name": "跨工作区配置采集",
        "risk": "high",
        "desc": "采集范围超出当前项目，把全局配置 / MCP / hooks 一并打包",
        "patterns": [
            {"id": "global_instructions", "re": r"global[-_]instructions", "region": "any", "w": 9,
             "note": "全局指令"},
            {"id": "global_settings", "re": r"global[-_]settings", "region": "any", "w": 7,
             "note": "全局设置"},
            {"id": "app_memory", "re": r"app-memory|appMemory", "region": "any", "w": 9,
             "note": "应用级记忆目录"},
            {"id": "extra_manifest", "re": r"extra[_-]?manifest", "region": "any", "w": 8,
             "note": "附加清单（跨工作区）"},
            {"id": "cross_workspace", "re": r"cross[_-]?workspace|workspaceKey|workspaceKeyRef", "region": "any", "w": 5,
             "note": "工作区标识聚合"},
        ],
    },
    {
        "id": "git_history_access",
        "name": "Git 历史访问",
        "risk": "high",
        "desc": "读取 .git 内部结构——历史里可能残留早就删除的密钥与内部信息",
        "patterns": [
            {"id": "git_internals", "re": r"\.git[/\\](objects|logs|refs|packed-refs)", "region": "any", "w": 9,
             "note": "Git 内部目录"},
            {"id": "reflog", "re": r"reflog|rev-list|rev-parse|--walk-reflogs", "region": "any", "w": 7,
             "note": "Git 历史遍历"},
            {"id": "log_all", "re": r"log\s+--all|--all\b.*log|cat-file", "region": "any", "w": 6,
             "note": "全历史读取"},
            {"id": "lfs_cache", "re": r"\.git[/\\]lfs|lfs[/\\]objects", "region": "any", "w": 8,
             "note": "Git LFS 缓存"},
        ],
    },
    {
        "id": "credential_access",
        "name": "凭据文件访问",
        "risk": "high",
        "desc": "读取 SSH / 云厂商 / 包管理器凭据",
        "patterns": [
            {"id": "ssh_keys", "re": r"\.ssh[/\\]|id_rsa|id_ed25519|authorized_keys", "region": "any", "w": 8,
             "note": "SSH 密钥"},
            {"id": "cloud_creds", "re": r"\.aws[/\\]credentials|\.config[/\\]gcloud|\.kube[/\\]config|\.azure", "region": "any", "w": 8,
             "note": "云凭据"},
            {"id": "pkg_tokens", "re": r"\.npmrc|\.git-credentials|\.netrc|\.pypirc|pip\.conf", "region": "any", "w": 7,
             "note": "包管理器凭据"},
            {"id": "keychain", "re": r"keytar|safeStorage|CredentialManager|secret[_-]?service", "region": "any", "w": 6,
             "note": "系统钥匙串"},
        ],
    },
    {
        "id": "shell_execution",
        "name": "命令执行",
        "risk": "medium",
        "desc": "能启动子进程——这是 Agent 的常规能力，但也是外传的常见出口",
        "patterns": [
            {"id": "node_child", "re": r"child_process|spawnSync|execSync|execFile", "region": "code", "w": 6,
             "note": "Node 子进程"},
            {"id": "py_subprocess", "re": r"subprocess\.(Popen|run|check_output|call)", "region": "code", "w": 6,
             "note": "Python 子进程"},
            {"id": "os_system", "re": r"os\.system\(|os\.popen\(", "region": "code", "w": 5,
             "note": "系统调用"},
            {"id": "pty_spawn", "re": r"pty\.spawn|node-pty|openpty|forkpty", "region": "any", "w": 7,
             "note": "伪终端 spawn"},
            {"id": "shell_invoke", "re": r"shell\.(exec|run)|ShellExecute|CreateProcess|exec\.Command",
             "region": "any", "w": 6, "note": "跨平台命令执行"},
        ],
    },
    {
        "id": "browser_state_access",
        "name": "浏览器状态访问",
        "risk": "high",
        "desc": "读取浏览器 Cookie / 登录态——可直接复用用户身份",
        "patterns": [
            {"id": "cookie_decrypt", "re": r"(chrome|chromium|edge).{0,20}[Cc]ookie|decryptCookie", "region": "code", "w": 7,
             "note": "Cookie 解密"},
            {"id": "login_data", "re": r"Login Data|Local State|Cookies\"|Network[/\\]Cookies", "region": "any", "w": 8,
             "note": "浏览器凭据库"},
            {"id": "profile_dir", "re": r"User Data[/\\](Default|Profile)|browser[_-]?profile", "region": "any", "w": 7,
             "note": "浏览器配置目录"},
        ],
    },
]

# 文件类别权重：生产代码 1.0，文档 0.15。
# 这条是「关键词命中 != 问题命中」的工程化落地——同一句话出现在 README 和
# 出现在 src/main/index.ts 里，含义天差地别。
FILE_CLASS_WEIGHT = {
    "production": 1.00,
    "config": 0.90,
    "types": 0.30,
    "test": 0.25,
    "docs": 0.15,
    "vendor": 0.10,
    "generated": 0.10,
    "other": 0.60,
}

# 评分体系（v0.2 修订）：
#   单个模式的贡献 = 最高单条基础分 × 多样性系数
#   多样性系数 = 0.85 + 0.15 × min(命中文件数, 5) / 5
#   能力总分 = 各模式贡献之和
#
#   为什么「一个模式只算一次贡献」：能力判定关心的是「有没有这种能力」，
#   而不是「这种能力被调用了多少次」。298 个文件的生产代码库里，
#   telemetry / retry 这类常规调用动辄命中几十次，累加会让分数随仓库规模
#   线性膨胀、失去区分度（第一版就在这里翻车：1 个弱模式拿了 191 分）。
#   多样性系数只用来区分「孤立一处」与「多处印证」，幅度刻意做得平缓。
#
# 每个能力的「模式权重和」——归一化的分母。
#
# 为什么必须归一化（评审指出）：单个模式贡献 ≤ 它自己的权重，
# 所以能力总分的上限就是该能力的权重和。用绝对分做阈值意味着
# 「这个能力的模式库里写了几个模式」会直接决定它能到哪个等级——
# shell_execution 权重和 17 < 阈值 18，于是「能执行命令」这个能力
# 在数学上永远上不了 confirmed，与证据强度无关。
# 归一化后分数变成「证据覆盖率」，跨能力可比，天花板问题消失。
CAP_WEIGHT_SUM = {c["id"]: sum(p["w"] for p in c["patterns"]) for c in CAPABILITY_DEFS}

# 等级阈值：norm = 能力总分 / 该能力的模式权重和（0~1）。
# 三条件同时满足才成立——单一维度高不算数。
GRADE_THRESHOLDS = [
    ("confirmed", {"norm": 0.55, "patterns": 3, "files": 2}),
    ("likely",    {"norm": 0.30, "patterns": 2, "files": 1}),
    ("possible",  {"norm": 0.12, "patterns": 1, "files": 1}),
]

CAP_RISK_WEIGHT = {"high": 3, "medium": 2, "low": 1}
GRADE_VALUE = {"confirmed": 3, "likely": 2, "possible": 1, "absent": 0}

# 触发方式推断信号（用于区分「自动」与「用户主动」——ZCode 整改的正是这一点）
AUTO_SIGNALS = re.compile(
    r"setInterval|setTimeout|useEffect|whenReady|sessionStart|SessionStart|onStartup|"
    r"bootstrap|registerHook|initialize|on\('ready'|schedule|cron|daemon|"
    r"onDidChange|addListener|subscribe|watch\(|backgroundTask|autoCapture|"
    r"captureBefore|captureOn|onPrompt|beforePrompt",
    re.I)
USER_SIGNALS = re.compile(
    r"onClick|onSubmit|onPress|handleClick|handleSubmit|addEventListener\(\s*['\"]click|"
    r"<button|ipcMain\.handle|menuItem|onAction|submitForm|"
    r"dialog|showMessage|confirm\(|userGesture|onDidClick|onSelect|onConfirm",
    re.I)


def _compile_capabilities():
    out = []
    for cap in CAPABILITY_DEFS:
        pats = []
        for p in cap["patterns"]:
            pats.append({
                "id": p["id"],
                "re": re.compile(p["re"], re.I),
                "region": p["region"],
                "w": p["w"],
                "note": p.get("note", ""),
            })
        out.append({
            "id": cap["id"], "name": cap["name"], "risk": cap["risk"],
            "desc": cap["desc"], "patterns": pats,
        })
    return out


_COMPILED_CAPS = _compile_capabilities()


# ---------------- 预筛表（性能关键） ----------------
#
# 不做预筛的话，**每个文件都要跑 54 个正则**——实测 22878 个文件的 asar
# 要跑 223 秒（1.1 MB/s），而其中绝大多数文件跟外传毫无关系。
#
# 预筛逻辑：先用一个「合并的关键词正则」扫一遍，不命中就完全跳过该文件
# （连 lex_regions 都不做）。
#
# 【不变式】——违反会导致**漏报**，比误报危险得多：
#     某个 pattern 的正则匹配  ⇒  该 pattern 的 kws 至少有一个出现在文本里
#
# 因此这张表有两条硬规矩：
#   1. 必须覆盖全部 pattern。缺任何一个，启动时直接抛异常（fail-fast），
#      绝不允许"悄悄少一个"——那是漏报的来源。
#   2. 宁可给宽松（短、泛）的关键字。宽松只会降低预筛效果（多跑几个文件），
#      严格才会漏报。
PATTERN_KEYWORDS = {
    # workspace_snapshot
    #
    # 关键词收窄原则：能写多具体就写多具体。评审实测过旧表的问题——
    # 通过率 59.4% 而其中 62.7% 零命中，最廉价的 `math` 能匹配 58/298 个文件。
    # 预筛的价值取决于「跳过了多少字节」，廉价关键词等于没筛。
    "snap_api_path": ["snapshot/upload"],
    "repo_snapshot": ["reposnapshot", "repo_snapshot", "repo-snapshot"],
    "snap_manifest": ["snapshotmanifest", "snapshot_manifest", "snapshot-manifest"],
    "kind_baseline": ["baseline", "incremental"],
    "capture_hook": ["capturebefore", "capturesnapshot", "captureworkspace"],
    "ckpt_service": ["checkpointmanager", "checkpointservice", "checkpointuploader",
                     "checkpointstore", "snapshotmanager", "snapshotservice",
                     "snapshotuploader", "snapshotstore"],
    # bulk_archive
    "tar_create": ["tar.", "creategzip", "createbrotli"],
    "archiver": ["archiver", "yazl", "zip.file"],
    "walk_tree": ["walk(", "walksync(", "walkdir(", "readdir"],
    "glob_all": ["glob"],
    "shutil_archive": ["make_archive", "zipfile"],
    # envelope_encryption
    "aes256ctr": ["aes-256-", "aes_256_"],
    "cipheriv": ["createcipheriv", "createdecipheriv", "cipher.getinstance"],
    "rsa_oaep": ["oaep"],
    "public_encrypt": ["publicencrypt", "encryptwithpublickey", "rsa.encrypt"],
    "key_wrap": ["keywrapalgorithm", "keyversion", "key_version", "key-version",
                 "wrappedkey", "encryptedkey"],
    "spki_pem": ["spki", "begin public key"],
    # object_storage_upload
    "aliyun_oss": ["aliyuncs", "oss-cn-", "x-oss-signature"],
    "tencent_cos": ["myqcloud", "cos.ap-", "x-cos-"],
    "aws_s3": ["amazonaws", "x-amz-signature"],
    "post_object": ["postobject", "putobject", "multipartupload", "uploadobject"],
    "upload_url": ["uploadurl", "upload_url", "signedurl", "presigned"],
    # 原含裸 "policy"（13/298）。正则的判别性部分其实是 signature/base64，
    # policy 只是它们的上下文，不需要进预筛。
    "form_signature": ["signature", "base64", "ossaccesskeyid", "formdata"],
    # upload_credential_api
    "upload_credential": ["upload-credential", "upload_credential", "uploadcredential"],
    "get_credential": ["uploadcredential"],
    "cred_path": ["/upload/"],
    # 原为裸 "credential"（42/298 个文件命中，几乎等于没筛）。
    # 正则要求 credential 后 30 字符内出现 expire/ttl/deadline —— 这三个词才是判别性的。
    "cred_expire": ["expire", "ttl", "deadline"],
    # retry_backoff
    "failure_count": ["failurecount", "failure_count"],
    "retry_count": ["retrycount", "retry_count", "attempts", "maxretries"],
    "backoff": ["backoff", "exponential"],
    "retry_delay": ["retrydelay", "retryinterval", "failurebasedelay", "basedelay"],
    # telemetry_egress
    "otlp": ["otlp", "opentelemetry"],
    "telemetry": ["telemetry"],
    "track_event": ["trackevent", "reportevent", "logevent", "analytics.track"],
    "apm": ["sentry", "arms.aliyun", "apm.", "bugsnag"],
    # global_config_collection
    "global_instructions": ["global-instructions", "global_instructions"],
    "global_settings": ["global-settings", "global_settings"],
    "app_memory": ["app-memory", "appmemory"],
    "extra_manifest": ["extramanifest", "extra_manifest", "extra-manifest"],
    "cross_workspace": ["crossworkspace", "cross_workspace", "cross-workspace", "workspacekey"],
    # git_history_access
    "git_internals": [".git/", ".git\\"],
    "reflog": ["reflog", "rev-list", "rev-parse"],
    "log_all": ["--all", "cat-file"],
    "lfs_cache": [".git/lfs", "lfs/objects", ".git\\lfs", "lfs\\objects"],
    # credential_access
    "ssh_keys": [".ssh/", ".ssh\\", "id_rsa", "id_ed25519", "authorized_keys"],
    "cloud_creds": [".aws/", ".aws\\", "gcloud", ".kube", ".azure"],
    "pkg_tokens": [".npmrc", ".git-credentials", ".netrc", ".pypirc", "pip.conf"],
    "keychain": ["keytar", "safestorage", "credentialmanager", "secretservice",
                 "secret_service", "secret-service"],
    # shell_execution
    "node_child": ["child_process", "spawnsync", "execsync", "execfile"],
    "py_subprocess": ["subprocess."],
    "os_system": ["os.system(", "os.popen("],
    "pty_spawn": ["pty.spawn", "node-pty", "openpty", "forkpty"],
    "shell_invoke": ["shell.exec", "shell.run", "shellexecute", "createprocess", "exec.command"],
    # browser_state_access
    "cookie_decrypt": ["cookie"],
    "login_data": ["login data", "local state", "cookies", "network/cookies"],
    "profile_dir": ["user data", "browser_profile", "browser-profile", "browserprofile"],
}


def _build_prefilter():
    missing = []
    kws = set()
    for cap in _COMPILED_CAPS:
        for pat in cap["patterns"]:
            ks = PATTERN_KEYWORDS.get(pat["id"])
            if not ks:
                missing.append(pat["id"])
            else:
                kws.update(k.lower() for k in ks)
    if missing:
        raise RuntimeError("预筛表缺少 pattern，会导致漏报，拒绝启动：%s" % missing)
    # 长关键词优先：更具体的关键词命中概率低但判别性强，短词权重低；
    # 实测排序对总耗时影响不大（见下），这里只是让它更可预测。
    return tuple(sorted(kws, key=len, reverse=True))


_KW_TUPLE = _build_prefilter()


def _prefilter_hit(text):
    """预筛：任一关键词出现即放行。

    【为什么不用一条合并的 alternation 正则】
    实测（tests/review/v4_prefilter_bench.py，2 MB 输入）：

        样本               alternation 正则    逐关键词 in      倍数
        纯 a 串（最坏）            1.653 s        0.257 s     6.4x
        重复 policy               1.823 s        0.134 s    13.6x
        正常 JS 片段              1.868 s        0.130 s    14.4x
        含命中                    0.0008 s       0.115 s    0.0x（正则快）

    即：**不命中时 `in` 快 6~14 倍，命中时正则快很多**。
    但预筛只在「不命中」时才需要快——一旦命中，后面 56 条正则的开销
    远超预筛本身，那 0.1 秒完全不值一提。

    根因：alternation 正则对不匹配的长文本要在**每个字符位置尝试所有分支**；
    而 `in` 是 C 实现的 two-way 搜索，且可短路。

    关键词全部小写、文本可能大小写混合，所以先 lower() 一次。
    这一步仍划算：2 MB 输入 lower() 约 15 ms，而 alternation 正则是 1650 ms。
    """
    low = text.lower()
    for k in _KW_TUPLE:
        if k in low:
            return True
    return False


def _check_weight_ceiling():
    """启动自检：每个能力必须有模式，且模式权重和为正值。

    历史：v0.2.1 之前用**绝对分**做阈值，而单个模式贡献 ≤ 其权重，
    于是「能力总分上限 = 模式权重和」——shell_execution 权重和 17 < 阈值 18，
    「能执行命令」这个能力在数学上永远上不了 confirmed。
    v0.2.2 起改为**归一化**（norm = 得分 / 权重和），天花板问题自动消失，
    这道自检就退化为守住除零与空模式库两条底线。
    """
    bad = []
    for cap in CAPABILITY_DEFS:
        if not cap.get("patterns"):
            bad.append("%s(无模式)" % cap["id"])
        elif sum(p["w"] for p in cap["patterns"]) <= 0:
            bad.append("%s(权重和非正)" % cap["id"])
    if bad:
        raise RuntimeError("以下能力的模式库不合法，拒绝启动：%s" % "、".join(bad))
    return True


_WEIGHT_CEILING_OK = _check_weight_ceiling()


def _regex_sample(pat_str):
    """尽力从正则生成一个「最小匹配串」；无法生成时返回 None。

    用途见 _check_keyword_consistency。用 CPython 的 re._parser 语法树，
    对每种节点产出最短的代表性文本。
    （第一版自检用「关键词能否单独匹配正则」来判断，是错的——
      关键词是「文本中必须出现的子串」，不是「能被正则独立匹配的串」，
      于是 `kind\\W{0,4}(baseline|incremental)` 会因为单独测 "baseline" 不匹配而误报。）
    """
    try:
        from re import _parser as _rp
    except ImportError:
        return None

    def in_class(av):
        for o, a in av:
            n = str(o)
            if n == "LITERAL":
                return chr(a)
            if n == "RANGE":
                return chr(a[0])
        return "a"

    def walk(sub, depth=0):
        if depth > 12:
            return ""
        try:
            items = list(sub)
        except TypeError:
            return ""
        out = []
        for op, av in items:
            n = str(op)
            if n == "LITERAL":
                out.append(chr(av))
            elif n == "NOT_LITERAL":
                out.append("a")
            elif n == "IN":
                out.append(in_class(av))
            elif n in ("MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"):
                out.append(walk(av[2], depth + 1) * max(int(av[0]), 0))
            elif n == "SUBPATTERN":
                out.append(walk(av[3], depth + 1))
            elif n == "BRANCH":
                out.append(walk(av[1][0], depth + 1))
            elif n in ("ANY", "CATEGORY"):
                out.append("a")
            # AT / GROUPREF / 其它：无字符产出
        return "".join(out)

    try:
        parsed = _rp.parse(pat_str, 0)
    except Exception:
        return None
    s = walk(parsed)
    return s or None


def _check_keyword_consistency():
    """启动自检：预筛表的不变式「正则匹配 ⇒ 关键词命中」。

    做法：为每条正则生成一个最小匹配串，验证预筛过滤器会放行它。
    放行不了就说明这条 pattern 的证据会被预筛永久挡掉——那是**漏报**。

    这是把评审提出的「不变式只靠人工核对」变成机器可验证的一步。
    """
    bad, unverifiable = [], []
    for cap in _COMPILED_CAPS:
        for pat in cap["patterns"]:
            sample = _regex_sample(pat["re"].pattern)
            if not sample:
                unverifiable.append(pat["id"])
                continue
            # 生成串必须真的能被该正则匹配（否则说明生成器本身不可靠）
            if pat["re"].search(sample) is None:
                unverifiable.append(pat["id"])
                continue
            if not _prefilter_hit(sample):
                bad.append("%s(样例=%r)" % (pat["id"], sample[:40]))
    if bad:
        raise RuntimeError(
            "以下 pattern 的匹配串会被预筛挡掉，将导致永久漏报：%s" % "、".join(bad))
    return {"unverifiable": unverifiable}


_KEYWORD_CONSISTENCY = _check_keyword_consistency()
_KEYWORD_CONSISTENCY_OK = True


def classify_file(rel_path, bundled=False):
    """按路径给文件归类——决定它的证据值多少钱。

    `bundled=True` 表示审计目标是**打包产物**（app.asar / 发行包）。
    这时整个归档都是构建输出——但它就是最终运行的代码，**不能按源码仓库的
    「/out/ = 生成物」约定降级**，否则会把整个客户端的权重压到 0.1。

    这个坑真实踩过：对 307 MB 的 ZCode app.asar 全量扫描时，
    主进程代码 /out/host/index.js 被判成 generated，
    结果包含完整上传凭证链路的文件只值 0.1 分，全部被压到 possible 以下。
    """
    p = "/" + rel_path.replace("\\", "/").lower().lstrip("/")
    name = p.rsplit("/", 1)[-1]

    # 第三方依赖：任何模式下都降级。
    # 这份名单必须与 M3_VENDOR_PARTS 保持一致——曾经漏了 /.pnpm/，
    # 于是 `--include-vendor` 下 pnpm 装的第三方包会被当成生产代码（权重 ×10）。
    if any(x in p for x in ("/node_modules/", "/vendor/", "/third_party/",
                            "/third-party/", "/.pnpm/")):
        return "vendor"

    is_types = name.endswith((".d.ts", ".d.mts", ".d.cts")) or "/@types/" in p
    is_docs = name.endswith((".md", ".txt", ".rst", ".adoc"))
    is_conf = name.endswith((".json", ".yaml", ".yml", ".toml", ".ini", ".env",
                             ".properties", ".conf", ".cfg"))
    is_test = any(x in p for x in ("/test/", "/tests/", "/__tests__/", "/spec/",
                                   "/fixtures/", "/mocks/", "/e2e/"))
    is_code = name.endswith((".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".tsx",
                             ".jsx", ".py", ".go", ".java", ".rs", ".c", ".cpp",
                             ".h", ".node", ".wasm"))

    if bundled:
        # 打包产物：只有第三方降级，其余都按它真实扮演的角色算
        if is_types:
            return "types"
        if is_docs:
            return "docs"
        if is_conf:
            return "config"
        if is_test:
            return "test"
        if is_code:
            return "production"
        return "other"

    # 源码仓库：目录约定才有意义
    if any(x in p for x in ("/dist/", "/build/", "/out/", "/.next/", "/coverage/", "/bundle/")):
        return "generated"
    if is_test:
        return "test"
    if is_types or "/types/" in p:
        return "types"
    if is_docs:
        return "docs"
    if is_conf:
        return "config"
    if is_code:
        return "production"
    return "other"


def _region_ok(required, kind, relaxed=False):
    """判定某个匹配是否满足该模式对区域的要求。

    relaxed=True 用于 JSON / YAML 这类**没有注释语法**的格式：
    它们的内容全是值语境，不存在「注释里提一句」这种噪音，
    所以不应该用「代码区 / 字符串区」去卡它。

    这个问题真实存在过：54 个模式里有 18 个要求 region="code"，
    而 `lex_regions()` 把整个 .json 判成 TK_STRING，
    于是这 18 个模式在任何 JSON 文件里**永远不可能命中**——
    与此同时 FILE_CLASS_WEIGHT["config"] 却是第二高的 0.90，
    等于一边说配置是高价值证据，一边让三分之一的模式在配置里失效。
    """
    if relaxed:
        return True
    if required == "code":
        return kind == TK_CODE
    if required == "string":
        return kind == TK_STRING
    return True


def scan_text_for_capabilities(rel_path, text, lang, bundled=False,
                               skip_prefilter=False):
    """在单个文件的文本上跑全部 pattern，返回命中列表（未聚合）。

    skip_prefilter=True 时假定调用方已经做过预筛——避免重复计算。
    （audit_path 需要知道预筛结果来正确统计「真正跑了正则的文件数」，
      所以预筛的判定权移到了那里。）
    """
    if not text:
        return []
    # ---- 预筛：不命中任何关键词就直接返回 ----
    # 这一步把「每文件 56 个正则」降到「每文件一次关键词检查」，是最大的性能杠杆。
    if not skip_prefilter and not _prefilter_hit(text):
        return []

    segs = lex_regions(text, lang)
    starts = line_starts_index(text)
    # JSON / YAML 没有注释语法，不存在「注释里提到」的噪音，不做区域区分
    relaxed = lang in ("json", "yaml", "toml")
    fclass = classify_file(rel_path, bundled=bundled)
    fw = FILE_CLASS_WEIGHT.get(fclass, 0.6)
    raw = []

    for cap in _COMPILED_CAPS:
        for pat in cap["patterns"]:
            # vendor 降权**分档**（见 VENDOR_STRONG_W 的定义）。
            #
            # 为什么不能一刀切乘 0.10：外部评审指出「vendor 只是来源属性，
            # 不等于证据本身更假」。一刀切的后果是 upload-credential（权重 9）
            # 在 node_modules 里变成 0.9 分 —— 等于给「把恶意逻辑 vendor 进去」
            # 开了一条隐身通道，而本工具的核心担忧恰恰是「客户端藏了能力」。
            #
            # 分档依据是**判别力**而不是位置：
            #   · 通用 API（fetch / createCipheriv）在任何 HTTP 客户端和加密库里都有 → 0.10
            #   · 强语义证据（upload-credential / snapshot/upload）误报率极低，
            #     值得跨依赖边界追踪 → 0.55
            fw_eff = fw
            if fclass == "vendor" and pat["w"] >= VENDOR_STRONG_W:
                fw_eff = VENDOR_STRONG_FACTOR
            # ---- 取该模式在本文件里的代表性命中 ----
            #
            # 【坑】原实现按**文本顺序**收集，取满 6 条就 break。这是个单点失效：
            # 红队实测——在文件头加 13 行"更新日志"注释，把 upload-credential /
            # repo_snapshot / aliyuncs.com 等各写 6 遍，真实代码的证据就被挤出预算，
            # `object_storage_upload` 从 likely 直接变 absent，而恶意代码一个字节没改。
            # 反向也成立：注释里的命中能凭空增加"模式多样性"，把等级抬上去。
            #
            # 修法两条：
            #   1. 先按「区域强度」降序，再取前 6 —— 代码区优先于注释区
            #   2. 若该模式在非注释区有命中，则**丢弃它的注释区命中**——
            #      否则"在注释里提了几个词"就能伪装成多种独立证据
            candidates = []
            for m in pat["re"].finditer(text):
                kind = region_at(segs, m.start())
                if not _region_ok(pat["region"], kind, relaxed):
                    continue
                rf = REGION_FACTOR.get(kind, 0.5)
                # 「排除 / 拒绝」语义里的命中按否决处理——见 NEGATIVE_CONTEXT 的说明。
                # 这一步专门防「把凭据排除列表判成凭据窃取」这类反向误报。
                if _in_negative_context(text, m.start()):
                    rf *= NEGATIVE_FACTOR
                candidates.append((rf, m.start(), kind))
                if len(candidates) >= 60:     # 上限：防病态输入拖慢，60 足够选出最强 6 条
                    break
            if not candidates:
                continue
            non_comment = [c for c in candidates
                           if c[2] not in (TK_LINE_COMMENT, TK_BLOCK_COMMENT)]
            if non_comment:
                candidates = non_comment
            candidates.sort(key=lambda x: -x[0])
            for rf, pos, kind in candidates[:6]:
                raw.append({
                    "cap": cap["id"],
                    "cap_name": cap["name"],
                    "cap_risk": cap["risk"],
                    "cap_desc": cap["desc"],
                    "pat": pat["id"],
                    "note": pat["note"],
                    "weight": pat["w"],
                    "region": kind,
                    "region_factor": rf,
                    "file_class": fclass,
                    "file": rel_path,
                    "line": line_no_at(starts, pos),
                    "snippet": snippet_at(text, pos),
                    "ctx": context_window(text, starts, pos, 3),
                    "base_score": pat["w"] * rf * fw_eff,
                })
    return raw


class CapabilityAccumulator:
    """边扫边聚合，避免把所有命中都堆在内存里。

    为什么需要它：22878 个文件的 asar 会产生近 7000 条命中，
    每条含 snippet(~260 字符) + ctx(~700 字符) 加其余字段，约 1.2 KB，
    光这一项就是 8 MB 级；再加上每个文件解码出的全文与中间对象，
    峰值远超必要水平。

    聚合后内存降到 O(模式数 × 样本数)——54 个模式 × 3 条样本，
    与扫描了多少文件无关。
    """

    SAMPLE_PER_PATTERN = 3

    def __init__(self):
        self.buckets = {}   # (cap_id, pat_id) -> 该模式的累计与代表证据
        self.total_hits = 0

    def add(self, hits):
        self.total_hits += len(hits)
        for h in hits:
            key = (h["cap"], h["pat"])
            b = self.buckets.get(key)
            if b is None:
                b = self.buckets[key] = {
                    "cap": h["cap"], "pat": h["pat"],
                    "name": h["cap_name"], "risk": h["cap_risk"], "desc": h["cap_desc"],
                    "max_base": 0.0, "max_weight": 0, "count": 0,
                    "files": set(), "samples": [],
                    "auto": 0, "user": 0, "strong_in_prod": False,
                }
            if h["base_score"] > b["max_base"]:
                b["max_base"] = h["base_score"]
            if h["weight"] > b["max_weight"]:
                b["max_weight"] = h["weight"]
            b["count"] += 1
            b["files"].add(h["file"])

            if (h["weight"] >= 9 and h["region"] in (TK_CODE, TK_STRING)
                    and h["file_class"] in ("production", "config")):
                b["strong_in_prod"] = True

            scope = h.get("ctx") or h.get("snippet", "")
            if AUTO_SIGNALS.search(scope):
                b["auto"] += 1
            if USER_SIGNALS.search(scope):
                b["user"] += 1

            s = b["samples"]
            if len(s) < self.SAMPLE_PER_PATTERN:
                s.append(h)
            else:
                # 只留最强的前 N 条——注意这只影响**展示**，
                # 分数与触发推断用的是全量计数（见下）
                s.sort(key=lambda x: -x["base_score"])
                if h["base_score"] > s[-1]["base_score"]:
                    s[-1] = h


def aggregate_from_buckets(acc):
    """从累加器聚合能力画像（内存友好路径）。"""
    caps = {}
    for (cid, _pid), b in acc.buckets.items():
        n_files = len(b["files"])
        diversity = 0.85 + 0.15 * min(n_files, 5) / 5.0
        contrib = b["max_base"] * diversity

        c = caps.setdefault(cid, {
            "id": cid, "name": b["name"], "risk": b["risk"], "desc": b["desc"],
            "score": 0.0, "patterns": set(), "files": set(),
            "max_weight": 0, "strong_in_prod": False, "hits": [], "hit_total": 0,
            "auto_signals": 0, "user_signals": 0,
        })
        c["score"] += contrib
        c["patterns"].add(b["pat"])
        c["hit_total"] += b["count"]
        c["files"].update(b["files"])
        c["auto_signals"] += b["auto"]
        c["user_signals"] += b["user"]
        if b["max_weight"] > c["max_weight"]:
            c["max_weight"] = b["max_weight"]
        if b["strong_in_prod"]:
            c["strong_in_prod"] = True
        for x in b["samples"]:
            x = dict(x)
            x["score"] = round(contrib, 2)
            c["hits"].append(x)

    graded = []
    for c in caps.values():
        n_pat = len(c["patterns"])
        n_file = len(c["files"])
        score = round(c["score"], 2)
        wsum = CAP_WEIGHT_SUM.get(c["id"]) or 1
        norm = score / float(wsum)
        level = "absent"
        for name, th in GRADE_THRESHOLDS:
            if norm >= th["norm"] and n_pat >= th["patterns"] and n_file >= th["files"]:
                level = name
                break
        # 强单证据抬升：upload-credential 这类词几乎不可能是巧合。
        # 但要求「至少 2 个模式命中」或「同一模式出现 ≥3 次」——
        # 否则一条孤立的字符串命中（比如某句错误提示里提到这个词）
        # 就能把等级抬到 likely，这是评审指出的误判方向之一。
        if (level == "possible" and c["strong_in_prod"]
                and (n_pat >= 2 or c["hit_total"] >= 3)):
            level = "likely"

        c["pattern_count"] = n_pat
        c["file_count"] = n_file
        c["score"] = score
        c["norm"] = round(norm, 4)
        c["weight_sum"] = wsum
        c["level"] = level
        c["trigger_hint"] = infer_trigger_counts(c["auto_signals"], c["user_signals"])
        c["hits"].sort(key=lambda x: (-x["weight"], x["file"]))
        c["patterns"] = sorted(c["patterns"])
        c["files"] = sorted(c["files"])
        graded.append(c)

    graded.sort(key=lambda c: (-GRADE_VALUE[c["level"]],
                               -CAP_RISK_WEIGHT.get(c["risk"], 1),
                               -c["score"]))
    return graded


def aggregate_capabilities(raw_hits):
    """兼容入口：直接从命中列表聚合（小目标用，大目标请走累加器）。

    聚合逻辑见 aggregate_from_buckets —— 核心是「按模式聚合，一个模式只贡献一次」，
    分数因而有界，不随仓库规模膨胀。
    """
    acc = CapabilityAccumulator()
    acc.add(raw_hits)
    return aggregate_from_buckets(acc)


def infer_trigger_counts(auto, user):
    """根据全量命中里的信号计数推断触发方式。

    推断不是事实——ZCode 的教训正是「同一个架构，触发条件一改性质就变了」，
    所以输出永远标注为「推断」，不写进结论、不参与风险评级。

    门槛（v0.2.2 收紧）：信号总数不足 5 条时直接判「未判定」。
    评审在真实报告里发现 `browser_state_access`（2 个模式 / 27 个文件 / 75 处命中）
    的触发方式**由 1 个信号词决定**——那不是推断，是掷骰子。
    宁可不给结论，也不要给一个看起来像结论的猜测。
    """
    total = auto + user
    if total < 5:
        return {"verdict": "unknown", "auto": auto, "user": user}
    if auto >= user * 3:
        return {"verdict": "automatic", "auto": auto, "user": user}
    if user >= auto * 3:
        return {"verdict": "user_initiated", "auto": auto, "user": user}
    return {"verdict": "mixed", "auto": auto, "user": user}


_VERDICT_ORDER = ["high", "elevated", "medium", "low", "info"]


def _downgrade(verdict):
    """把结论可信度下调一档（覆盖有缺口时用）。"""
    try:
        i = _VERDICT_ORDER.index(verdict)
    except ValueError:
        return verdict
    return _VERDICT_ORDER[min(i + 1, len(_VERDICT_ORDER) - 1)]


# ---------------- 组合证据：共现检测，**不是**数据流分析 ----------------
#
# 【必须说清楚的概念边界】
# 外部评审指出，本文件早期版本把这里叫「数据流链（data flow chain）」是**概念偷换**：
#
#     A 的证据存在 + B 的证据存在 + C 的证据存在
#         ≠
#     A → B → C 是同一条程序路径
#
# 反例：workspace.js 里读工作区、security.js 里加密、update.js 里上传安装包——
# 三者可能毫无数据依赖，但共现检测会把它们拼成"工作区 → 加密 → 上传"。
#
# 所以这个函数的产出**只能称为「组合证据（capability composition）」**：
# 它回答「构成某个故事所需的几类证据是否同时存在」，
# 而**不回答**「它们是否在同一条可达路径上」。
#
# 后者需要真正的 source → sink 分析（符号解析 + 调用图），属于 v0.3。
#
# 为了让读者能自己判断可信程度，每条组合都带一个 `cohesion` 字段：
#   same_file    至少两个环节的证据出现在同一文件（关联较强，值得优先人工核对）
#   co_occur     仅同时存在，无任何路径证据（最弱，可能来自互不相关的代码）
COMBINED_CHAINS = [
    {
        "id": "workspace_to_object_storage",
        "name": "工作区采集 + 加密 + 对象存储直传",
        "requires": ["workspace_snapshot", "envelope_encryption", "object_storage_upload"],
        "level": "blocking",
        "desc": "这三类证据同时存在时，具备「把工作区打包加密后投递到对象存储」"
                "所需的全部要素——ZCode 事件就是这个形态。"
                "注意：本项只证明要素齐备，不证明它们构成同一条程序路径",
    },
    {
        "id": "workspace_to_credential_api",
        "name": "工作区采集 + 上传凭证申请",
        "requires": ["workspace_snapshot", "upload_credential_api"],
        "level": "blocking",
        "desc": "具备「采集工作区」与「申请上传凭证」两类要素",
    },
    {
        "id": "archive_then_upload",
        "name": "批量打包 + 外传通道",
        "requires": ["bulk_archive", "object_storage_upload"],
        "level": "serious",
        "desc": "具备「批量收集文件」与「外传通道」两类要素",
    },
    {
        "id": "git_history_exfil",
        "name": "Git 历史读取 + 外传通道",
        "requires": ["git_history_access", "object_storage_upload"],
        "level": "serious",
        "desc": "能读到 .git 内部对象且具备外传通道——历史中可能残留已删除的密钥",
    },
    {
        "id": "credential_harvest",
        "name": "凭据文件读取 + 外传通道",
        "requires": ["credential_access", "object_storage_upload"],
        "level": "blocking",
        "desc": "具备「读取本机凭据文件（.ssh/.aws/.npmrc 等）」与「外传通道」两类要素",
    },
    {
        "id": "config_exfil",
        "name": "跨工作区配置采集 + 外传通道",
        "requires": ["global_config_collection", "object_storage_upload"],
        "level": "serious",
        "desc": "采集范围超出单个工作区，且具备外传通道",
    },
]


def _cohesion(need, acc):
    """判断组合证据的关联程度——这是「共现」与「路径」之间的唯一可用桥梁。

    判据很朴素：**至少两个环节的证据出现在同一文件**。
    同文件共现远强于跨文件共现——它至少说明这段代码里同时出现了这两件事，
    值得优先人工核对。但它**仍不等于**数据流关系（同一文件里的两段无关代码也会命中）。

    返回 (等级, 共有文件列表)。
    """
    if acc is None:
        return "unknown", []
    files_by_cap = {}
    for (cid, _pid), b in acc.buckets.items():
        files_by_cap.setdefault(cid, set()).update(b["files"])
    sets = [files_by_cap.get(n, set()) for n in need]
    sets = [s for s in sets if s]
    for i in range(len(sets)):
        for j in range(i + 1, len(sets)):
            inter = sets[i] & sets[j]
            if inter:
                return "same_file", sorted(inter)[:5]
    return "co_occur", []


def detect_chains(caps, acc=None):
    """从能力画像里识别「组合证据」。

    **这不是数据流分析。** 见文件顶部 COMBINED_CHAINS 的注释——
    它只回答「构成某个故事所需的几类证据是否同时存在」，
    不回答「它们是否在同一条可达路径上」。

    成立条件：组合要求的每个能力都达到 likely 以上。
    """
    lv = {c["id"]: c["level"] for c in caps}
    ok = ("confirmed", "likely")
    out = []
    for chain in COMBINED_CHAINS:
        need = chain["requires"]
        missing = [x for x in need if lv.get(x) not in ok]
        if missing:
            continue
        hit = [c for c in caps if c["id"] in need]
        cohesion, same_files = _cohesion(need, acc)
        # 关联度决定等级措辞：没有路径证据（co_occur）时不该用「阻断级」这种强断言。
        # 理由：共现检测不证明它们在同一条路径上，而「阻断级」三个字会被读成结论。
        level = chain["level"]
        if cohesion == "co_occur" and level == "blocking":
            level = "serious"
        out.append({
            "id": chain["id"],
            "name": chain["name"],
            "level": level,
            "desc": chain["desc"],
            # 类型：明确标注这是「证据共现」而非「数据流」
            "kind": "capability_composition",
            "kind_label": "组合证据（共现检测，非路径分析）",
            "cohesion": cohesion,
            "cohesion_label": {
                "same_file": "较强：至少两个环节的证据出现在同一文件，建议优先人工核对",
                "co_occur": "弱：仅同时存在，无任何路径证据——可能来自互不相关的代码",
                "unknown": "未评估",
            }.get(cohesion, "未评估"),
            "same_files": same_files,
            "evidence": [{"cap": c["id"], "name": c["name"], "level": c["level"],
                          "patterns": c["pattern_count"], "files": c["file_count"],
                          "hits": c.get("hit_total", 0)} for c in hit],
            "auto_trigger": any(
                (c.get("trigger_hint") or {}).get("verdict") == "automatic" for c in hit),
            "evidence_count": sum(c.get("hit_total", 0) for c in hit),
        })
    order = {"blocking": 0, "serious": 1}
    out.sort(key=lambda x: (order.get(x["level"], 9),
                            0 if x["cohesion"] == "same_file" else 1,
                            -x["evidence_count"]))
    return out


def summarize_capabilities(caps, coverage=None):
    """整体定性——给一个可读的结论，不给假的精确数字。

    coverage 不为空时会检查「有没有因为技术原因没扫到的地方」。
    这是必要的：一个把上传逻辑放进超大 bundle / 被截断目录的客户端，
    同样会得到「未发现显著外传能力」，而那份结论的确定性外观与真正扫全时毫无差别。
    把漏报包装成干净结论，比报错更伤人——它会让用户主动关闭自己的怀疑。
    """
    confirmed = [c for c in caps if c["level"] == "confirmed"]
    likely = [c for c in caps if c["level"] == "likely"]
    high_conf = [c for c in confirmed if c["risk"] == "high"]

    index = sum(GRADE_VALUE[c["level"]] * CAP_RISK_WEIGHT.get(c["risk"], 1) for c in caps)
    max_index = sum(3 * CAP_RISK_WEIGHT.get(c["risk"], 1) for c in caps) or 1
    ratio = index / max_index

    if high_conf:
        verdict = "high"
        text = "确认存在高危外传能力"
    elif len(confirmed) >= 2 or (confirmed and likely):
        verdict = "elevated"
        text = "存在多项已确认的外传能力"
    elif confirmed or len(likely) >= 2:
        verdict = "medium"
        text = "存在外传能力，需结合触发条件判断"
    elif likely or any(c["level"] == "possible" for c in caps):
        verdict = "low"
        text = "仅发现弱信号，多为常规能力"
    else:
        verdict = "info"
        text = "未发现显著外传能力"

    # —— 覆盖不足时给结论加限定，必要时降级 ——
    #
    # 【坑】原实现里 `miss`（算限定用的缺口数）与 `gaps`（画台账用的缺口数）是两套口径：
    # miss 只含 skipped_large + truncated，不含 read_errors，于是「7 个文件根本没读成」
    # 的扫描照样输出「确认存在高危外传能力」且文本里一个「未覆盖」都没有。
    # 现在统一用 coverage["gaps"]。
    #
    # 另一个问题是截断：`--static-path <目录>` 默认 max_files=2500，任何中型源码树
    # 都会触发，于是等级被恒压成 INFO、结构化计数恒为 0/0/0 —— 结论失去可用性。
    # 现在的处理是：截断仍降级（因为缺口无法量化），但**明确给出重跑命令**，
    # 让读者知道下一步做什么，而不是只丢一个「不可用」。
    #
    # status 三态（外部评审要求）：扫描失败与「没发现问题」绝不能是同一个状态。
    #   complete  无技术性缺口
    #   partial   有缺口，结论已降级 / 加限定，仍可用
    #   error     缺口大到无法支撑任何结论
    status = "complete"
    if coverage:
        gaps = coverage.get("gaps", 0)
        cand = max(1, coverage.get("candidates", 0) + coverage.get("skipped_other", 0))
        ratio = gaps / float(cand)
        if coverage.get("truncated"):
            status = "error"
            verdict = "info"
            text = ("扫描被截断（目录超过 --static-max-files 上限），缺口无法量化，"
                    "结论不可用；请用更大的 --static-max-files 重跑")
        elif ratio > 0.20:
            status = "error"
            verdict = "info"
            text = ("缺口过大（%d/%d 个候选文件未覆盖），证据不足以支撑结论"
                    % (gaps, cand))
        elif ratio > 0.05:
            status = "partial"
            verdict = _downgrade(verdict)
            text += "（注意：%d 个候选文件未覆盖，结论可信度已下调一档）" % gaps
        elif gaps:
            status = "partial"
            text += "（注意：%d 个文件未覆盖，详见覆盖台账）" % gaps

    return {
        "verdict": verdict,
        "status": status,
        "text": text,
        "ratio": round(ratio, 3),
        "confirmed": len(confirmed),
        "likely": len(likely),
        "possible": len([c for c in caps if c["level"] == "possible"]),
        "high_risk_confirmed": len(high_conf),
    }


def _collect_asar_targets(path, meta, targets, include_vendor, max_file_bytes):
    """枚举 asar 归档里的可扫条目，填进 targets。"""
    try:
        ar = AsarArchive(path)
    except (AsarError, OSError) as e:
        meta["errors"].append("asar 打开失败：%s" % e)
        return
    try:
        meta["asar"] = {"tree_entries": sum(1 for _ in ar.iter_files())}
        for rel, item in ar.iter_files():
            if len(targets) >= 60000:
                meta["truncated"] = True
                meta["errors"].append("归档可扫文件数超过 60000，已截断")
                break
            # 注意判定顺序：.map / .min.css 不在 _LANG_BY_EXT 里，
            # 若先查 detect_lang 就会在 `lang == "other"` 处 continue，
            # 永远到不了下面这个分支（评审实测：三个扩展名里只有 .min.js 能触发）。
            artifact = rel.endswith((".map", ".min.js", ".min.css"))
            lang = detect_lang(rel)
            if lang in ("other",) and not artifact:
                meta["skipped_other"] += 1
                continue
            meta["candidates"] += 1
            if artifact:
                meta["skipped_ext"] += 1
                continue
            if not include_vendor and any(v in _norm(rel) for v in M3_VENDOR_PARTS):
                meta["skipped_vendor"] += 1
                continue
            try:
                size = int(item.get("size", 0) or 0)
            except (TypeError, ValueError):
                meta["skipped_bad_entry"] += 1
                continue
            if size > max_file_bytes:
                meta["skipped_large"] += 1
                continue
            targets.append((rel, lang, ("asar", ar, rel, item)))
    except AsarError as e:
        meta["errors"].append("归档目录树异常，停止枚举：%s" % e)
    except RecursionError:
        meta["errors"].append("归档目录树嵌套过深，停止枚举")
    except Exception as e:                      # noqa: BLE001
        # 对不可信输入保留宽捕获。记录类型名，便于区分「恶意构造」与「自身 bug」。
        meta["errors"].append("归档枚举异常（%s）：%s" % (type(e).__name__, e))


def _collect_dir_targets(path, meta, targets, max_files, max_file_bytes, include_vendor):
    """遍历目录，收集可扫文件进 targets。"""
    stack = [path]
    truncated = False
    while stack:
        if len(targets) >= max_files:
            truncated = True
            break
        d = stack.pop()
        try:
            # 排序保证扫描顺序可复现（否则「哪 2500 个被扫」依赖文件系统返回顺序，
            # 同一台机器两次运行都可能不同）
            entries = sorted(os.scandir(d), key=lambda x: x.name)
        except OSError as e:
            meta["errors"].append(str(e))
            continue
        for e in entries:
            if len(targets) >= max_files:
                truncated = True
                break
            try:
                if e.is_dir(follow_symlinks=False):
                    if e.name in M3_SKIP_DIRS:
                        continue
                    stack.append(e.path)
                elif e.is_file(follow_symlinks=False):
                    rel = os.path.relpath(e.path, path)
                    # 用带前导 / 的规范形态去匹配，与 asar 分支（/node_modules/...）一致。
                    # 【坑】原先用 _norm(rel)（形如 vendor/leak.js）匹配 M3_VENDOR_PARTS 里的
                    # /vendor/ —— 永远匹配不上。也就是说「目录目标跳过第三方依赖」是**空转**，
                    # 只有 asar 分支真正生效（评审实测：目录目标 skipped_vendor=0）。
                    rel_norm = "/" + _norm(rel)
                    artifact = e.name.endswith((".map", ".min.js", ".min.css"))
                    lang = detect_lang(e.path)
                    if lang in ("other",) and not artifact:
                        # 不是「没有这个文件」，而是「有这个文件但按扩展名没看」。
                        # 必须计数，否则候选数与实扫数对不上，读者会以为扫全了。
                        meta["skipped_other"] += 1
                        continue
                    meta["candidates"] += 1
                    if artifact:
                        meta["skipped_ext"] += 1
                        continue
                    if not include_vendor and any(v in rel_norm for v in M3_VENDOR_PARTS):
                        meta["skipped_vendor"] += 1
                        continue
                    sz = e.stat(follow_symlinks=False).st_size
                    if sz > max_file_bytes:
                        meta["skipped_large"] += 1
                        continue
                    targets.append((rel, lang, ("fs", e.path, None, None)))
            except OSError:
                continue
    if truncated:
        meta["truncated"] = True
        meta["errors"].append("达到 max_files=%d 上限，剩余文件未扫描" % max_files)


def _scan_targets(targets, meta, max_file_bytes, acc=None):
    """读取并扫描 targets；返回命中列表（acc 不为空时返回空，命中已直接入累加器）。"""
    hits = []
    for rel, lang, reader in targets:
        try:
            if reader[0] == "asar":
                blob = reader[1].read(reader[2], reader[3], max_file_bytes)
            else:
                with open(reader[1], "rb") as f:
                    blob = f.read(max_file_bytes)
            if not blob:
                continue
            text = decode_bytes(blob)
        except (OSError, AsarError, ValueError) as e:
            meta["errors"].append("%s: %s" % (rel, e))
            continue
        meta["files_scanned"] += 1
        meta["bytes_scanned"] += len(blob)
        # 预筛在这里做（而不是在 scan_text_for_capabilities 内部），
        # 这样台账才能区分「读到了」和「真正跑了正则」——
        # 红队指出：原来的「实扫 N 个文件」里可能有 88.7% 一条正则都没跑，
        # 而报告写「因技术原因未覆盖 0 项」，读者会以为全覆盖。
        if _prefilter_hit(text):
            meta["files_analyzed"] += 1
        else:
            meta["prefilter_rejected"] += 1
        file_hits = scan_text_for_capabilities(rel, text, lang,
                                               bundled=(meta["kind"] == "asar"),
                                               skip_prefilter=True)
        if file_hits:
            if acc is None:
                hits.extend(file_hits)
            else:
                acc.add(file_hits)
    return hits


def audit_path(path, max_files=2500, max_file_bytes=8 * 1024 * 1024, acc=None,
               include_vendor=False):
    """审计一个路径（目录或 asar 文件）。

    acc 不为 None 时，命中直接喂给累加器，函数本身不累积命中列表——
    这是大目标（几万个文件）的内存友好路径。返回值里的 hits 此时为空。

    include_vendor=False（默认）会跳过 node_modules / vendor 等第三方依赖区，
    理由见 M3_VENDOR_PARTS 的注释。

    实现拆成三步（见上方三个 _collect_* / _scan_* 函数）：
    asar 枚举 / 目录遍历 / 读取扫描。拆开是为了让每一段可单独读、可单独测。
    """
    meta = {"path": path, "kind": "dir", "files_scanned": 0, "bytes_scanned": 0,
            "files_analyzed": 0, "prefilter_rejected": 0,
            "candidates": 0, "skipped_large": 0, "skipped_vendor": 0,
            "skipped_ext": 0, "skipped_bad_entry": 0, "skipped_other": 0,
            "truncated": False, "errors": [], "asar": None}
    targets = []   # (rel_path, lang, reader)

    if os.path.isfile(path) and path.lower().endswith(".asar"):
        meta["kind"] = "asar"
        _collect_asar_targets(path, meta, targets, include_vendor, max_file_bytes)
    elif os.path.isdir(path):
        _collect_dir_targets(path, meta, targets, max_files, max_file_bytes,
                             include_vendor)
    else:
        meta["errors"].append("路径不存在")
        return [], meta

    hits = _scan_targets(targets, meta, max_file_bytes, acc=acc)
    return hits, meta


def audit_targets(tool, extra_paths=None, max_files=2500, include_vendor=False):
    """对一个工具做 M3 静态审计：自动定位客户端 + 指定的路径。"""
    paths = list(extra_paths or [])

    for tpl in tool.get("audit_paths", []):
        p = expand(tpl)
        if os.path.isfile(p):
            paths.append(p)
        elif os.path.isdir(p):
            found = find_asar_files(p, limit=3)
            paths.extend(found or [p])
        elif "*" in p:
            import glob as _glob
            paths.extend(_glob.glob(p, recursive=True))

    seen = set()
    results = []
    acc = CapabilityAccumulator()
    for p in paths:
        rp = os.path.normpath(p)
        if rp in seen or not os.path.exists(rp):
            continue
        seen.add(rp)
        _hits, meta = audit_path(rp, max_files=max_files, acc=acc,
                                 include_vendor=include_vendor)
        results.append(meta)

    caps = aggregate_from_buckets(acc)

    # 覆盖率台账：把「因为技术原因没看的部分」显式记下来。
    # 这是本工具最容易骗人的地方——「未检出」和「已扫全」在报告里长得一样，
    # 而实际上一个把上传逻辑放进 .min.js / 超大 bundle / UTF-16 文件的客户端，
    # 也会得到一份「未发现显著外传能力」的干净结论。
    coverage = {
        "candidates": sum(r.get("candidates", 0) for r in results),
        "scanned": sum(r.get("files_scanned", 0) for r in results),
        # 「读到了」与「真正跑了正则」是两件事。
        # 红队实测：ZCode 的「实扫 2731」里有 2422 个（88.7%）一条正则都没跑——
        # 真正被完整分析的是 309 个文件 = 候选的 1.3%。
        # 报告写「因技术原因未覆盖 0 项」，读者会以为全覆盖。这个区别必须显式呈现。
        "analyzed": sum(r.get("files_analyzed", 0) for r in results),
        "prefilter_rejected": sum(r.get("prefilter_rejected", 0) for r in results),
        # by_design：设计上就该跳过的（第三方依赖、压缩产物）——不算缺陷
        "skipped_vendor": sum(r.get("skipped_vendor", 0) for r in results),
        "skipped_ext": sum(r.get("skipped_ext", 0) for r in results),
        # by_design（按扩展名不认识）：也算设计内，但要单独可见——
        # 它正是「逻辑写在 .vue/.rb/无扩展名文件里」时的漏报通道
        "skipped_other": sum(r.get("skipped_other", 0) for r in results),
        # gaps：可能真正漏掉东西的——必须让用户看见
        "skipped_large": sum(r.get("skipped_large", 0) for r in results),
        "skipped_bad_entry": sum(r.get("skipped_bad_entry", 0) for r in results),
        "truncated": any(r.get("truncated") for r in results),
        "read_errors": sum(len(r.get("errors") or []) for r in results),
    }
    coverage["gaps"] = (coverage["skipped_large"]
                        + coverage["skipped_bad_entry"]
                        + (1 if coverage["truncated"] else 0)
                        + coverage["read_errors"])

    summary = summarize_capabilities(caps, coverage=coverage)

    return {
        "targets": results,
        "capabilities": caps,
        "chains": detect_chains(caps, acc=acc),
        "summary": summary,
        "coverage": coverage,
        "total_hits": acc.total_hits,
        "files_scanned": coverage["scanned"],
        "bytes_scanned": sum(r.get("bytes_scanned", 0) for r in results),
    }


def cap_level(summary):
    """把能力画像结论映射到工具风险等级（只用于排序和徽章）。"""
    return {"high": "critical", "elevated": "high", "medium": "medium",
            "low": "low", "info": "info"}.get(summary.get("verdict"), "info")


def cap_reasons(summary):
    out = ["外传能力画像：%s" % summary.get("text", "")]
    out.append("已确认能力 %d 项 / 疑似 %d 项 / 弱信号 %d 项"
               % (summary.get("confirmed", 0), summary.get("likely", 0),
                  summary.get("possible", 0)))
    if summary.get("high_risk_confirmed"):
        out.append("其中高危能力已确认 %d 项" % summary["high_risk_confirmed"])
    return out


def json_static(st):
    """把 M3 结果压成可序列化的结构（截断长证据，控制文件体积）。"""
    if not st:
        return None
    return {
        "summary": st["summary"],
        # coverage 必须进 JSON：只读 JSON 的下游（自动化审计就是这种）
        # 若拿不到「截断了 / 有 N 个文件没读成」，就只能看到一个孤零零的结论。
        "coverage": st.get("coverage"),
        # 组合链同理：它才是「有没有一条路径能把工作区送出去」的答案
        "chains": st.get("chains") or [],
        "files_scanned": st["files_scanned"],
        "bytes_scanned": st["bytes_scanned"],
        "total_hits": st.get("total_hits", 0),
        "targets": [{
            "path": t.get("path"), "kind": t.get("kind"),
            "files_scanned": t.get("files_scanned"),
            "bytes_scanned": t.get("bytes_scanned"),
            "skipped_large": t.get("skipped_large"),
            "skipped_vendor": t.get("skipped_vendor"),
            "asar": t.get("asar"),
            "errors": (t.get("errors") or [])[:10],
        } for t in st["targets"]],
        "capabilities": [{
            "id": c["id"], "name": c["name"], "risk": c["risk"], "desc": c["desc"],
            "level": c["level"], "score": c["score"],
            "pattern_count": c["pattern_count"], "file_count": c["file_count"],
            "hit_total": c.get("hit_total", len(c["hits"])),
            "patterns": c["patterns"], "files": c["files"][:20],
            "trigger_hint": c["trigger_hint"],
            "hits": [{
                "file": h["file"], "line": h["line"], "region": h["region"],
                "note": h["note"], "weight": h["weight"],
                "file_class": h["file_class"], "score": round(h["score"], 3),
                "snippet": h["snippet"],
            } for h in c["hits"][:40]],
        } for c in st["capabilities"]],
    }


# ---------------------------------------------------------------- 渲染

LEVEL_MARK = {
    "critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]",
    "low": "[LOW]", "info": "[INFO]", "n/a": "[N/A]",
}


def _text_summary_table(results):
    """摘要表（所有工具一行）。"""
    L = ["-- 摘要 " + "-" * 60,
         "%-10s %-24s %-12s %s" % ("工具", "名称", "风险", "数据目录")]
    for r in results:
        L.append("%-10s %-24s %-12s %s" % (
            r["report"]["id"], r["report"]["name"],
            LEVEL_MARK.get(r["level"], r["level"]),
            human(r["report"]["total_bytes"])))
    return L


def _text_snapshot(s):
    """单个快照状态块。"""
    L = ["  [快照状态] %s" % s["state_file"],
         "    工作区      : %s" % (s["workspace"] or "(未记录)"),
         "    上传失败计数: %s" % s["failure_count"]]
    if s["workspace_bytes"] is not None:
        L.append("    最近打包    : %s  ->  加密后 %s"
                 % (human(s["workspace_bytes"]), human(s["encrypted_bytes"] or 0)))
    if s["manifests"]:
        L.append("    打包清单:")
        for m in s["manifests"]:
            L.append("      %s  %d 个文件 / %s"
                     % (m["schema"] or "-", m["file_count"], human(m["bytes"])))
            for e in m["entries"][:8]:
                L.append("        %-10s %s" % (human(int(e["size"] or 0)), e["path"]))
            if len(m["entries"]) > 8:
                L.append("        ... 其余 %d 项" % (len(m["entries"]) - 8))
    if s["extra_manifests"]:
        L.append("    跨工作区全局配置:")
        for x in s["extra_manifests"]:
            for e in x["entries"]:
                L.append("      %-34s %-8s %s"
                         % (os.path.basename(str(e["path"])),
                            human(int(e["size"] or 0)), e["source"]))
    if s["pending"]:
        L.append("    未发出的包:")
        for p in s["pending"]:
            L.append("      %-10s %s" % (human(p["size"]), p["path"]))
    if s["git_in_manifest"]:
        L.append("    !!! 清单含 .git 内部文件 %d 项，示例:" % len(s["git_in_manifest"]))
        for g in s["git_in_manifest"][:5]:
            L.append("        %s" % g)
    return L


def _text_coverage(cov):
    """覆盖台账（纯文本版）。"""
    L = ["    覆盖台账: 候选 %d -> 读到 %d -> 真正跑正则 %d"
         % (cov.get("candidates", 0), cov.get("scanned", 0), cov.get("analyzed", 0)),
         "      设计内跳过: 第三方依赖 %d / 压缩产物 %d / 未知扩展名 %d"
         % (cov.get("skipped_vendor", 0), cov.get("skipped_ext", 0),
            cov.get("skipped_other", 0))]
    if cov.get("prefilter_rejected"):
        L.append("      关键词预筛未通过 %d 个（未跑正则；这是设计内的快速通道，"
                 "但意味着它们只做了字面量检查）" % cov["prefilter_rejected"])
    if cov.get("gaps"):
        L.append("    !! 因技术原因未覆盖 %d 项：大文件 %d / 目录截断 %s / 读取失败 %d"
                 % (cov["gaps"], cov.get("skipped_large", 0),
                    "是" if cov.get("truncated") else "否",
                    cov.get("read_errors", 0)))
        L.append("       以上缺口意味着「未检出」≠「已排除」，请结合覆盖台账理解结论")
    else:
        L.append("    因技术原因未覆盖: 0 项")
    return L


def _text_chains(chains):
    """组合证据（纯文本版）。

    **不是数据流链** —— 措辞必须让读者看出这个区别：
    共现检测能回答「构成某个故事的证据是否齐备」，
    但不能回答「它们是否在同一条可达路径上」。
    """
    L = ["    [组合证据] 构成某些故事所需的几类证据同时存在：",
         "      ※ 本项是「证据共现」检测，不是程序路径/数据流分析。",
         "        共现 ≠ 在同一条可达路径上，请结合「关联度」自行判断。"]
    for ch in chains[:5]:
        mark = "[阻断级]" if ch["level"] == "blocking" else "[严重]  "
        L.append("      %s %s" % (mark, ch["name"]))
        L.append("         关联度: %s" % ch.get("cohesion_label", ""))
        if ch.get("same_files"):
            L.append("         共有文件: %s" % "、".join(ch["same_files"]))
        L.append("         证据: %s" % " + ".join(
            "%s(%s/%d处)" % (e["name"], e["level"], e["hits"])
            for e in ch["evidence"]))
        if ch["auto_trigger"]:
            L.append("         触发: 组合中存在「自动触发」的能力（性质不同于用户主动）")
    return L


def _text_static(st):
    """M3 完整块（纯文本版）。"""
    sm = st["summary"]
    L = ["  [外传能力画像 · M3] %s" % sm["text"],
         "    扫描 %d 个文件 / %s  |  已确认 %d / 疑似 %d / 弱信号 %d"
         % (st["files_scanned"], human(st["bytes_scanned"]),
            sm["confirmed"], sm["likely"], sm["possible"])]
    cov = st.get("coverage") or {}
    if cov:
        L += _text_coverage(cov)
    chains = st.get("chains") or []
    if chains:
        L += _text_chains(chains)

    tmap = {"automatic": "自动", "user_initiated": "用户主动",
            "mixed": "混合", "unknown": "未判定"}
    for c in st["capabilities"]:
        if c["level"] == "absent":
            continue
        L.append("    %-11s %-26s 模式%-2d 文件%-3d 命中%-4d 触发:%s"
                 % ("[" + c["level"].upper() + "]", c["name"], c["pattern_count"],
                    c["file_count"], c.get("hit_total", 0),
                    tmap.get(c["trigger_hint"]["verdict"], "?")))
    absents = [c["name"] for c in st["capabilities"] if c["level"] == "absent"]
    if absents:
        L.append("    未检出: %s" % "、".join(absents))
    return L


def _text_tool(r):
    """单个工具块（纯文本版）。"""
    t = r["report"]
    L = ["-- %s (%s) " % (t["name"], t["vendor"]) + "-" * 40,
         "  风险等级: %s" % LEVEL_MARK.get(r["level"], r["level"])]
    for why in r["reasons"]:
        L.append("    - %s" % why)

    L.append("  数据目录:")
    for root in t["roots"]:
        extra = ""
        if root.get("excluded_bytes"):
            extra = "   [携带区 %s 已排除]" % human(root["excluded_bytes"])
        L.append("    %s   (%d 文件 / %s)%s"
                 % (root["path"], root["files"], human(root["bytes"]), extra))

    if t.get("endpoints"):
        L.append("  已知出站端点: %s" % ", ".join(t["endpoints"]))
    if t.get("switches"):
        L.append("  已知开关语义:")
        for s in t["switches"]:
            L.append("    %s" % s["key"])
            L.append("      声称: %s" % s["claimed"])
            L.append("      实际: %s" % s["actual"])
    if t["suspicious_files"]:
        L.append("  可疑文件 (前 10):")
        for f in sorted(t["suspicious_files"], key=lambda x: -x["size"])[:10]:
            L.append("    %-10s [%s] %s"
                     % (human(f["size"]), f.get("why", "-"), f["path"]))
    elif t["installed"]:
        L.append("  可疑文件: 无")

    for s in r["snapshots"]:
        L += _text_snapshot(s)

    st = r.get("static")
    if st and st.get("files_scanned"):
        L += _text_static(st)
    L.append("")
    return L


def render_text(results, meta):
    L = ["=" * 72,
         "AgentEgress %s  AI 客户端数据外传审计报告" % VERSION,
         "扫描时间: %s" % meta["time"],
         "只读扫描 / 零依赖 / 不联网 / 不外传",
         "=" * 72,
         ""]
    L += _text_summary_table(results)
    L.append("")
    for r in results:
        if not r["report"]["installed"]:
            continue
        L += _text_tool(r)
    L += ["=" * 72,
          "说明：本地取证只能证明「链路被触发过」与「打包了什么」，",
          "      无法证明「服务端是否已接收/删除」。需要网络层证据才能区分尝试与成功。",
          "=" * 72]
    return "\n".join(L)


def _md_safe(s, limit=160):
    """把外部输入（归档内文件名、清单里的路径）转义成可安全放进 Markdown 的形式。

    被审计方完全控制这些字符串。评审实测：一个名字里带换行 + `|` + 反引号的文件，
    就能往审计报告里插入标题和表格行——报告是给人看的，被人往里写字是实打实的风险。
    HTML 报告不受影响（每处插值都走了 html.escape，评审验证注入失败）。
    """
    s = str(s).replace("\r", " ").replace("\n", " ")
    s = s.replace("`", "'").replace("|", "\\|")
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return s[:limit]


def _md_summary_table(results):
    """摘要表（Markdown）。"""
    L = ["## 摘要", "",
         "| 工具 | 名称 | 风险 | 数据目录体积 | 快照状态 |",
         "|---|---|---|---|---|"]
    for r in results:
        t = r["report"]
        L.append("| `%s` | %s | %s | %s | %d |" % (
            t["id"], t["name"], LEVEL_MARK.get(r["level"], r["level"]),
            human(t["total_bytes"]), len(r["snapshots"])))
    L.append("")
    return L


def _md_snapshot(s):
    """单个快照块（Markdown）。"""
    L = ["### 快照状态 `%s`" % os.path.basename(s["state_file"]), "",
         "- 文件：`%s`" % s["state_file"],
         "- 工作区：`%s`" % (s["workspace"] or "(未记录)"),
         "- 上传失败计数：**%s**" % s["failure_count"]]
    if s["workspace_bytes"] is not None:
        L.append("- 最近打包：%s → 加密后 %s"
                 % (human(s["workspace_bytes"]), human(s["encrypted_bytes"] or 0)))
    if s["pending"]:
        L.append("- 未发出的包：%d 个 / %s"
                 % (len(s["pending"]), human(sum(p["size"] for p in s["pending"]))))
    L.append("")

    for m in s["manifests"]:
        L += ["#### 打包清单（%s）" % (m["schema"] or "unknown"), "",
              "共 **%d** 个文件 / **%s**" % (m["file_count"], human(m["bytes"])), "",
              "| 大小 | 路径 |", "|---|---|"]
        for e in m["entries"][:20]:
            L.append("| %s | `%s` |" % (human(int(e["size"] or 0)), _md_safe(e["path"])))
        if len(m["entries"]) > 20:
            L.append("| ... | 其余 %d 项 |" % (len(m["entries"]) - 20))
        L.append("")

    for x in s["extra_manifests"]:
        L += ["#### 跨工作区全局配置清单", "", "| 文件 | 大小 | 来源 |", "|---|---|---|"]
        for e in x["entries"]:
            L.append("| `%s` | %s | %s |"
                     % (os.path.basename(str(e["path"])), human(int(e["size"] or 0)),
                        e["source"]))
        L.append("")

    if s["git_in_manifest"]:
        L += ["> **警告**：清单中包含 %d 项 `.git` 内部文件。"
              % len(s["git_in_manifest"]), ""]
        for g in s["git_in_manifest"][:10]:
            L.append("- `%s`" % g)
        L.append("")
    return L


def _md_static(st):
    """M3 块（Markdown）。"""
    sm = st["summary"]
    L = ["### 外传能力画像（M3 静态审计）", "",
         "**结论**：%s" % sm["text"], "",
         "已确认 %d 项 / 疑似 %d 项 / 弱信号 %d 项；扫描 %d 个文件 / %s"
         % (sm["confirmed"], sm["likely"], sm["possible"],
            st["files_scanned"], human(st["bytes_scanned"])), "",
         "> 判定的是**能力**而非**当前行为**——"
         "删掉触发条件不等于拆掉架构（见 `05-ZCode开源拆解与影响.md`）。", ""]

    tmap = {"automatic": "自动", "user_initiated": "用户主动",
            "mixed": "混合", "unknown": "未判定"}
    shown = [c for c in st["capabilities"] if c["level"] != "absent"]
    if shown:
        L += ["| 能力 | 等级 | 模式 | 文件 | 命中 | 触发推断 |",
              "|---|---|---|---|---|---|"]
        for c in shown:
            L.append("| %s | %s | %d | %d | %d | %s |"
                     % (c["name"], LEVEL_MARK.get(c["level"], c["level"]).strip("[]"),
                        c["pattern_count"], c["file_count"], c.get("hit_total", 0),
                        tmap.get(c["trigger_hint"]["verdict"], "—")))
        L.append("")
        for c in shown:
            if c["level"] not in ("confirmed", "likely"):
                continue
            L += ["<details><summary>%s · 证据链（展示 %d / %d 条）</summary>"
                  % (c["name"], min(15, len(c["hits"])), c["hit_total"]), ""]
            for h in c["hits"][:15]:
                L.append("- `%s:%d` · %s · %s 区 · w=%d"
                         % (_md_safe(h["file"]), h["line"], h["note"],
                            h["region"], h["weight"]))
                L += ["  ```", "  %s" % h["snippet"], "  ```"]
            L += ["", "</details>", ""]

    absents = [c["name"] for c in st["capabilities"] if c["level"] == "absent"]
    if absents:
        L += ["未检出：%s" % "、".join(absents), ""]
    return L


def _md_tool(r):
    """单个工具块（Markdown）。"""
    t = r["report"]
    L = ["## %s（%s）" % (t["name"], t["vendor"]), "",
         "**风险等级**：%s" % LEVEL_MARK.get(r["level"], r["level"]), ""]
    if r["reasons"]:
        L += ["**判定依据**", ""]
        for why in r["reasons"]:
            L.append("- %s" % why)
        L.append("")

    L += ["**数据目录**", ""]
    for root in t["roots"]:
        L.append("- `%s` — %d 文件 / %s"
                 % (root["path"], root["files"], human(root["bytes"])))
    L.append("")

    if t.get("endpoints"):
        L += ["**已知出站端点**：%s"
              % ", ".join("`%s`" % e for e in t["endpoints"]), ""]
    if t.get("switches"):
        L += ["**已知开关语义落差**", "", "| 开关 | 声称控制 | 实际控制 |", "|---|---|---|"]
        for s in t["switches"]:
            L.append("| `%s` | %s | %s |" % (s["key"], s["claimed"], s["actual"]))
        L.append("")
    for s in r["snapshots"]:
        L += _md_snapshot(s)
    if r.get("static") and r["static"].get("files_scanned"):
        L += _md_static(r["static"])
    return L


def render_md(results, meta):
    L = ["# AgentEgress 审计报告", "",
         "- 版本：%s" % VERSION,
         "- 扫描时间：%s" % meta["time"],
         "- 性质：只读扫描 / 零依赖 / 不联网 / 不外传", ""]
    L += _md_summary_table(results)
    for r in results:
        if not r["report"]["installed"]:
            continue
        L += _md_tool(r)
    L += ["---", "", "## 取证边界", "",
          "本地取证能证明：链路被触发过、打包了哪些文件、失败了多少次。", "",
          "本地取证**不能**证明：服务端是否已接收、是否已删除。", "",
          "区分「尝试」与「成功」需要网络层证据（连接跟踪 / 抓包 / 网关日志）。"]
    return "\n".join(L)


# ================================================================ 单文件 HTML 报告
#
# 设计约束：
#   1. 完全自包含——不引用任何 CDN / 字体 / 图片，双击就能离线打开
#   2. 渐进增强——JS 只负责筛选与折叠，关掉 JS 报告内容依然完整可读
#   3. 深浅色自适应——跟随系统

_HTML_STYLE = """
:root{
  --bg:#F5F6F8; --card:#FFFFFF; --card2:#FAFBFC;
  --tx:#1B1F23; --tx2:#5A6472; --tx3:#8B949E;
  --bd:#E3E6EA; --bd2:#CFD5DC;
  --crit:#A82B21; --high:#BC4A0E; --med:#96650A; --low:#15703A; --info:#4B5563;
  --crit-bg:#FCECEA; --high-bg:#FDF0E7; --med-bg:#FDF6E3; --low-bg:#EAF6EE; --info-bg:#F0F2F4;
  --accent:#2F5C8F; --code:#F3F5F7;
}
@media (prefers-color-scheme:dark){
  :root{
    --bg:#101216; --card:#181B21; --card2:#1E222A;
    --tx:#E5E8EB; --tx2:#9BA3AC; --tx3:#6B7280;
    --bd:#282D35; --bd2:#3A414B;
    --crit:#F87171; --high:#FB923C; --med:#FBBF24; --low:#4ADE80; --info:#9CA3AF;
    --crit-bg:#341A18; --high-bg:#332215; --med-bg:#332A12; --low-bg:#14291C; --info-bg:#20252D;
    --accent:#7BA7D9; --code:#1C2028;
  }
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);padding:28px 18px 64px;
  font:14px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:1060px;margin:0 auto}
h1{font-size:20px;font-weight:600;letter-spacing:.2px}
h2{font-size:15px;font-weight:600;margin:0}
h3{font-size:13px;font-weight:600;color:var(--tx2);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px}
.muted{color:var(--tx2)}
.small{font-size:12px}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:12px}
header{border-bottom:1px solid var(--bd);padding-bottom:18px;margin-bottom:24px}
.tagline{color:var(--tx2);font-size:13px;margin-top:6px}
.metabar{display:flex;flex-wrap:wrap;gap:18px;margin-top:14px;font-size:12px;color:var(--tx3)}
.grid{display:grid;gap:12px}
.stats{grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin-bottom:24px}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px}
.stat .n{font-size:22px;font-weight:600;line-height:1.2}
.stat .l{font-size:12px;color:var(--tx2);margin-top:2px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:12px;margin-bottom:14px;overflow:hidden}
.card-h{display:flex;align-items:center;gap:12px;padding:14px 18px;cursor:pointer;user-select:none;border-bottom:1px solid transparent}
.card.open .card-h{border-bottom-color:var(--bd)}
.card-h:hover{background:var(--card2)}
.card-b{display:none;padding:4px 18px 18px}
.card.open .card-b{display:block}
.chev{width:10px;height:10px;border-right:1.6px solid var(--tx3);border-bottom:1.6px solid var(--tx3);
  transform:rotate(-45deg);transition:transform .18s ease;flex:none;margin-left:auto}
.card.open .chev{transform:rotate(45deg)}
.badge{font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;letter-spacing:.4px;flex:none}
.b-critical,.b-crit{background:var(--crit-bg);color:var(--crit)}
.b-high{background:var(--high-bg);color:var(--high)}
.b-medium,.b-elevated{background:var(--med-bg);color:var(--med)}
.b-low{background:var(--low-bg);color:var(--low)}
.b-info,.b-na{background:var(--info-bg);color:var(--info)}
.b-confirmed{background:var(--crit-bg);color:var(--crit)}
.b-likely{background:var(--high-bg);color:var(--high)}
.b-possible{background:var(--med-bg);color:var(--med)}
.b-absent{background:var(--info-bg);color:var(--tx3)}
.name{font-size:15px;font-weight:600}
.sub{font-size:12px;color:var(--tx2)}
.sec{margin-top:18px}
.kv{display:grid;grid-template-columns:96px 1fr;gap:6px 14px;font-size:13px}
.kv dt{color:var(--tx2)}
.kv dd{word-break:break-all}
ul.plain{list-style:none}
ul.plain li{padding:5px 0;border-bottom:1px dashed var(--bd);font-size:13px;display:flex;gap:10px;align-items:baseline}
ul.plain li:last-child{border-bottom:none}
ul.plain li .sz{color:var(--tx2);font-size:12px;flex:none;min-width:72px;text-align:right}
.why{background:var(--card2);border-left:2px solid var(--bd2);padding:8px 12px;border-radius:0 6px 6px 0;
  font-size:13px;margin:6px 0}
.why.high{border-left-color:var(--high)}
.why.crit{border-left-color:var(--crit)}
.why.med{border-left-color:var(--med)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-weight:600;color:var(--tx2);font-size:12px;padding:6px 8px;border-bottom:1px solid var(--bd2)}
td{padding:7px 8px;border-bottom:1px solid var(--bd);vertical-align:top}
tr:last-child td{border-bottom:none}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.bar{height:6px;border-radius:3px;background:var(--info-bg);overflow:hidden;min-width:60px}
.bar>i{display:block;height:100%;border-radius:3px}
details{margin-top:4px}
summary{cursor:pointer;font-size:12px;color:var(--accent);padding:4px 0;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸ ";color:var(--tx3)}
details[open] summary::before{content:"▾ "}
.ev{margin:6px 0 2px 14px}
.ev .loc{font-size:11px;color:var(--tx3);font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.ev pre{background:var(--code);border:1px solid var(--bd);border-radius:6px;padding:7px 10px;
  font-size:11.5px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin-top:3px;color:var(--tx)}
.warnbox{background:var(--high-bg);border:1px solid var(--bd);border-radius:8px;padding:12px 14px;font-size:13px;margin-top:12px}
.notebox{background:var(--card2);border:1px solid var(--bd);border-radius:8px;padding:12px 14px;font-size:12.5px;
  color:var(--tx2);margin-top:16px}
.toolbar{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:16px}
input[type=search]{flex:1;min-width:180px;padding:8px 12px;border:1px solid var(--bd2);border-radius:8px;
  background:var(--card);color:var(--tx);font-size:13px;outline:none}
input[type=search]:focus{border-color:var(--accent)}
.chip{padding:5px 11px;border:1px solid var(--bd2);border-radius:20px;background:var(--card);color:var(--tx2);
  font-size:12px;cursor:pointer}
.chip.on{background:var(--accent);border-color:var(--accent);color:#fff}
footer{margin-top:36px;padding-top:18px;border-top:1px solid var(--bd);font-size:12px;color:var(--tx3)}
@media print{
  body{background:#fff;padding:0}
  .toolbar,.chev{display:none}
  .card-b{display:block!important}
  .card{break-inside:avoid;border-color:#ccc}
}
"""

_HTML_SCRIPT = """
const DATA = __DATA__;
const cards = [...document.querySelectorAll('.card')];
const q = document.getElementById('q');
const chips = [...document.querySelectorAll('.chip')];
let activeLevel = 'all';

function apply(){
  const kw = (q.value || '').trim().toLowerCase();
  cards.forEach(function(c){
    const lv = c.dataset.level || '';
    const txt = c.dataset.search || '';
    const okLv = activeLevel === 'all' || lv === activeLevel;
    const okKw = !kw || txt.indexOf(kw) >= 0;
    c.style.display = (okLv && okKw) ? '' : 'none';
  });
}
if (q) q.addEventListener('input', apply);
chips.forEach(function(ch){
  ch.addEventListener('click', function(){
    chips.forEach(function(x){ x.classList.remove('on'); });
    ch.classList.add('on');
    activeLevel = ch.dataset.level;
    apply();
  });
});
cards.forEach(function(c){
  c.querySelector('.card-h').addEventListener('click', function(e){
    if (e.target.closest('a')) return;
    c.classList.toggle('open');
  });
});
document.addEventListener('keydown', function(e){
  if (e.key === '/' && document.activeElement !== q){ e.preventDefault(); q.focus(); }
});
"""


def _badge(level, risk=None):
    """能力等级徽章。

    传了 risk 时按「风险」着色、按「等级」写字——这是评审要求的关键区分：
    原先徽章只看 level，导致 telemetry_egress（所有工具都有的常规遥测，risk=low）
    和 workspace_snapshot（会传整仓，risk=high）拿到完全相同的红色 CONFIRMED 徽章，
    非技术读者会把「有遥测」和「会传整仓」等同起来。
    """
    lv = (level or "info").lower()
    if risk and lv in ("confirmed", "likely", "possible"):
        tone = {"high": "crit", "medium": "high", "low": "info"}.get(risk, "info")
        return '<span class="badge b-%s">%s</span>' % (tone, html.escape(lv.upper()))
    cls = "b-" + lv.replace("/", "")
    return '<span class="badge %s">%s</span>' % (cls, html.escape(lv.upper()))


def _strength(level, pattern_count):
    """证据强度 0-100：等级打底 + 模式多样性加成。

    为什么不直接拿分数画条：分数是模型内部的相对量，跨能力比较时含义不直观
    （第一版就因为 1 个弱模式刷到 191 分而画了满格条，等级却只是 possible）。
    强度条要回答的是「这个结论有多硬」，而硬度主要由
    「等级」和「有多少种独立模式在支持」决定。
    """
    base = {"confirmed": 70, "likely": 45, "possible": 20, "absent": 0}.get(level, 0)
    return min(100, base + min(28, pattern_count * 9))


def _bar(level, pattern_count, risk=None):
    """证据强度条。

    条长 = 证据有多硬（等级 + 模式多样性）；颜色 = 风险有多高（risk）。
    两者分开，读者才能一眼分清「证据确凿但无所谓」和「证据确凿且危险」。
    """
    pct = max(4, _strength(level, pattern_count))
    if risk:
        color = {"high": "var(--crit)", "medium": "var(--high)",
                 "low": "var(--tx3)"}.get(risk, "var(--tx3)")
    else:
        color = {"confirmed": "var(--crit)", "likely": "var(--high)",
                 "possible": "var(--med)", "absent": "var(--tx3)"}.get(level, "var(--tx3)")
    return ('<div class="bar"><i style="width:%d%%;background:%s"></i></div>' % (pct, color))


# ---------------------------------------------------------------- HTML 渲染
#
# 【为什么拆】原 render_html 是 303 行 / 圈复杂度 56 的单一函数——
# 无法单测、无法复用，改一处要在 300 行里找位置。
# 现在按「文档结构」拆成一串小函数，render_html 只负责组装。
#
# 拆分是**纯机械的**：每一段原样搬运，不改任何输出。
# 验证：tests/review/_html_before.html 与重构后的输出逐字节对比，
# 除时间戳外必须完全一致。
_esc = html.escape


def _html_head(meta, results):
    """DOCTYPE / head / style / header。"""
    return [
        '<!DOCTYPE html>',
        '<html lang="zh-CN"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width,initial-scale=1">',
        '<title>AgentEgress 审计报告 · %s</title>' % _esc(meta.get("time", "")),
        '<style>%s</style></head><body><div class="wrap">' % _HTML_STYLE,
        '<header>',
        '<h1>AgentEgress 审计报告</h1>',
        '<div class="tagline">审「正在用的工具本身」— 只读 / 零依赖 / 不联网 / 不外传</div>',
        '<div class="metabar"><span>版本 v%s</span><span>扫描时间 %s</span><span>覆盖工具 %d 个</span></div>'
        % (_esc(VERSION), _esc(meta.get("time", "")), len(results)),
        '</header>',
    ]


def _html_stats(installed, with_snap, with_static, total_bytes):
    """顶部四格统计。"""
    P = ['<div class="grid stats">']
    for n, l in ((len(installed), "已安装工具"), (len(with_snap), "发现快照痕迹"),
                 (len(with_static), "已静态审计"), (human(total_bytes), "数据目录总量")):
        P.append('<div class="stat"><div class="n">%s</div><div class="l">%s</div></div>'
                 % (_esc(str(n)), _esc(l)))
    P.append('</div>')
    return P


def _html_toolbar():
    """搜索框 + 等级筛选条。"""
    P = ['<div class="toolbar">',
         '<input type="search" id="q" placeholder="搜索工具 / 路径 / 证据关键词…（按 / 聚焦）">']
    for lv, label in (("all", "全部"), ("critical", "CRITICAL"), ("high", "HIGH"),
                      ("medium", "MEDIUM"), ("low", "LOW"), ("info", "INFO")):
        P.append('<span class="chip%s" data-level="%s">%s</span>'
                 % (" on" if lv == "all" else "", lv, label))
    P.append('</div>')
    return P


def _html_overview_table(results):
    """总览表：每个工具一行。"""
    P = ['<div class="card open"><div class="card-h"><h2>总览</h2><span class="chev"></span></div>',
         '<div class="card-b"><table><thead><tr>'
         '<th>工具</th><th>风险</th><th class="num">数据目录</th><th class="num">快照痕迹</th>'
         '<th class="num">外传能力</th></tr></thead><tbody>']
    for r in results:
        t = r["report"]
        if not t.get("installed"):
            continue
        st = r.get("static") or {}
        sm = st.get("summary") or {}
        cap_txt = ("%d 确认 / %d 疑似" % (sm.get("confirmed", 0), sm.get("likely", 0))
                   if st else "—")
        P.append('<tr><td><span class="name">%s</span><div class="sub mono">%s</div></td>'
                 '<td>%s</td><td class="num">%s</td><td class="num">%d</td><td class="num">%s</td></tr>'
                 % (_esc(t["name"]), _esc(t["id"]),
                    _badge(r["level"]), _esc(human(t["total_bytes"])),
                    len(r["snapshots"]), _esc(cap_txt)))
    P.append('</tbody></table></div></div>')
    return P


def _html_search_blob(t, r):
    """卡片级搜索索引。

    必须包含证据（文件名 + 代码片段），否则「搜索证据关键词」是假的。
    """
    parts = []
    st = r.get("static")
    if st:
        for c in st["capabilities"]:
            parts.append(c["name"])
            parts.extend(c.get("files", [])[:12])
            for h in c["hits"][:6]:
                parts.append(h.get("file", ""))
                parts.append(h.get("snippet", "")[:120])
    return " ".join([
        t["name"], t["id"], t.get("vendor", ""),
        " ".join(root["path"] for root in t["roots"]),
        " ".join(w for w in r["reasons"]),
    ] + parts).lower()


def _html_roots(t):
    """数据目录列表。"""
    P = ['<div class="sec"><h3>数据目录</h3><ul class="plain">']
    for root in t["roots"]:
        extra = ""
        if root.get("excluded_bytes"):
            extra = (' <span class="muted small">（携带区 %s 已排除）</span>'
                     % _esc(human(root["excluded_bytes"])))
        P.append('<li><span class="sz">%s</span><span class="mono">%s</span>%s</li>'
                 % (_esc(human(root["bytes"])), _esc(root["path"]), extra))
    P.append('</ul></div>')
    return P


def _html_switches(t):
    """开关语义落差表。"""
    if not t.get("switches"):
        return []
    P = ['<div class="sec"><h3>开关语义落差</h3><table><thead><tr>'
         '<th>开关</th><th>声称控制</th><th>实际控制</th></tr></thead><tbody>']
    for sw in t["switches"]:
        P.append('<tr><td class="mono">%s</td><td>%s</td><td>%s</td></tr>'
                 % (_esc(sw["key"]), _esc(sw["claimed"]), _esc(sw["actual"])))
    P.append('</tbody></table></div>')
    return P


def _html_suspicious(t):
    """可疑文件列表（按体积降序，前 12）。"""
    if not t["suspicious_files"]:
        return []
    P = ['<div class="sec"><h3>可疑文件</h3><ul class="plain">']
    for f in sorted(t["suspicious_files"], key=lambda x: -x["size"])[:12]:
        P.append('<li><span class="sz">%s</span><span class="mono">%s</span></li>'
                 % (_esc(human(f["size"])), _esc(f["path"])))
    P.append('</ul></div>')
    return P


def _html_snapshot(s):
    """单个快照状态块（含打包清单 / 跨工作区配置 / .git 项 / 未发包）。"""
    P = ['<div class="sec"><h3>快照状态</h3>', '<dl class="kv">',
         '<dt>状态文件</dt><dd class="mono">%s</dd>' % _esc(s["state_file"]),
         '<dt>工作区</dt><dd class="mono">%s</dd>' % _esc(s["workspace"] or "（未记录）"),
         '<dt>失败计数</dt><dd><b>%s</b></dd>' % _esc(str(s["failure_count"]))]
    if s["workspace_bytes"] is not None:
        P.append('<dt>最近打包</dt><dd>%s &rarr; 加密后 %s</dd>'
                 % (_esc(human(s["workspace_bytes"])), _esc(human(s["encrypted_bytes"] or 0))))
    P.append('</dl>')

    for m in s["manifests"]:
        P.append('<h3 style="margin-top:14px">打包清单 · %s</h3>' % _esc(m["schema"] or "unknown"))
        P.append('<p class="small muted">共 %d 个文件 / %s</p>'
                 % (m["file_count"], _esc(human(m["bytes"]))))
        P.append('<details><summary>展开文件列表（前 30）</summary><table>')
        for e in m["entries"][:30]:
            P.append('<tr><td class="num">%s</td><td class="mono">%s</td></tr>'
                     % (_esc(human(int(e["size"] or 0))), _esc(str(e["path"]))))
        if len(m["entries"]) > 30:
            P.append('<tr><td colspan="2" class="muted small">… 其余 %d 项</td></tr>'
                     % (len(m["entries"]) - 30))
        P.append('</table></details>')

    for x in s["extra_manifests"]:
        P.append('<h3 style="margin-top:14px">跨工作区全局配置</h3><ul class="plain">')
        for e in x["entries"]:
            P.append('<li><span class="sz">%s</span><span class="mono">%s</span>'
                     '<span class="muted small">%s</span></li>'
                     % (_esc(human(int(e["size"] or 0))), _esc(str(e["path"])),
                        _esc(e.get("source", ""))))
        P.append('</ul>')

    if s["git_in_manifest"]:
        P.append('<div class="warnbox"><b>清单包含 %d 项 .git 内部文件</b>'
                 '——历史中可能残留已删除的密钥。<ul class="plain" style="margin-top:6px">'
                 % len(s["git_in_manifest"]))
        for g in s["git_in_manifest"][:8]:
            P.append('<li class="mono">%s</li>' % _esc(g))
        P.append('</ul></div>')

    if s["pending"]:
        P.append('<div class="sec"><h3>未发出的包</h3><ul class="plain">')
        for p in s["pending"]:
            P.append('<li><span class="sz">%s</span><span class="mono">%s</span></li>'
                     % (_esc(human(p["size"])), _esc(p["path"])))
        P.append('</ul></div>')
    P.append('</div>')
    return P


def _html_coverage_box(cov):
    """覆盖台账。

    必须在报告里显式出现——否则「未发现显著外传能力」和「真的扫全了且没有」
    在视觉上完全一样，那等于把漏报包装成干净结论。
    """
    if not cov:
        return []
    gaps = cov.get("gaps", 0)
    P = ['<div class="%s small" style="margin-top:8px">' % ("warnbox" if gaps else "")]
    P.append('<b>覆盖台账</b>：候选 %d 个文件 &rarr; 读到 %d 个 &rarr; '
             '<b>真正跑完正则 %d 个</b>；'
             '设计内跳过：第三方依赖 %d、压缩产物 %d、未知扩展名 %d'
             % (cov.get("candidates", 0), cov.get("scanned", 0),
                cov.get("analyzed", 0),
                cov.get("skipped_vendor", 0), cov.get("skipped_ext", 0),
                cov.get("skipped_other", 0)))
    if cov.get("prefilter_rejected"):
        P.append('<br>关键词预筛未通过 %d 个（未跑正则）——'
                 '这意味着它们<b>只做了字面量检查</b>：'
                 '若危险串是运行时拼装或编码的，会在这里被漏掉。'
                 % cov["prefilter_rejected"])
    if gaps:
        P.append('<br><b>因技术原因未覆盖 %d 项</b>'
                 '（大文件 %d / 目录截断 %s / 读取失败 %d）——'
                 '这意味着「未检出」不等于「已排除」'
                 % (gaps, cov.get("skipped_large", 0),
                    "是" if cov.get("truncated") else "否",
                    cov.get("read_errors", 0)))
    else:
        P.append('<br>因技术原因未覆盖：0 项')
    P.append('</div>')
    return P


def _html_chains(chains):
    """组合证据块。

    **不是数据流链** —— 措辞必须让读者看出这个区别。
    """
    if not chains:
        return []
    P = ['<div class="sec"><h3>组合证据（共现检测）</h3>',
         '<div class="warnbox small" style="margin-bottom:10px">'
         '<b>本项不是数据流分析。</b>它只检查「构成某个故事所需的几类证据是否同时存在」，'
         '<b>不检查</b>它们是否落在同一条可达路径上。'
         '三个互不相关的模块各有一个能力，也会被组合出来。'
         '请结合每条组合的「关联度」自行判断——'
         '要确认它们真的连成一条链，需要人工核对或动态验证。</div>']
    for ch in chains:
        blocking = ch["level"] == "blocking"
        coh_class = "crit" if ch.get("cohesion") == "same_file" else ""
        P.append('<div class="why %s" style="margin-bottom:8px">'
                 % ("crit" if blocking else ("med" if not coh_class else coh_class)))
        P.append('<b>%s</b> %s<br>'
                 % ("[阻断级]" if blocking else "[严重]", _esc(ch["name"])))
        P.append('<span class="sub small">%s</span><br>' % _esc(ch["desc"]))
        P.append('<span class="small"><b>关联度：</b>%s</span>'
                 % _esc(ch.get("cohesion_label", "")))
        if ch.get("same_files"):
            P.append('<br><span class="small mono">共有文件：%s</span>'
                     % _esc("、".join(ch["same_files"])))
        P.append('<br><span class="small mono">证据：%s</span>'
                 % _esc(" ＋ ".join(
                     "%s(%s, %d处命中)" % (e["name"], e["level"], e["hits"])
                     for e in ch["evidence"])))
        if ch["auto_trigger"]:
            P.append('<br><span class="small"><b>触发方式：组合中存在「自动触发」'
                     '的能力</b>——其性质与「用户主动」完全不同</span>')
        P.append('</div>')
    P.append('</div>')
    return P


def _html_capability_table(caps):
    """能力表 + 每个能力的证据链折叠块。"""
    shown = [c for c in caps if c["level"] != "absent"]
    if not shown:
        return ['<p class="muted small" style="margin-top:8px">未发现显著外传能力特征。</p>']
    P = ['<table style="margin-top:10px"><thead><tr>'
         '<th>能力</th><th style="width:88px">等级</th><th style="width:110px">证据强度</th>'
         '<th class="num" style="width:64px">命中</th><th>触发推断</th></tr></thead><tbody>']
    tmap = {"automatic": "自动", "user_initiated": "用户主动",
            "mixed": "混合", "unknown": "未判定"}
    for c in shown:
        tr = c.get("trigger_hint") or {}
        risk_txt = {"high": "高", "medium": "中", "low": "低"}.get(c["risk"], c["risk"])
        P.append('<tr><td title="模型分 %s"><b>%s</b>'
                 '<span class="muted small" style="margin-left:6px">风险:%s</span>'
                 '<div class="sub small">%s</div></td>'
                 '<td>%s</td><td>%s</td><td class="num" title="%d 个模式 / %d 个文件">%d</td>'
                 '<td class="sub">%s</td></tr>'
                 % (_esc(str(c["score"])), _esc(c["name"]), _esc(risk_txt),
                    _esc(c["desc"]),
                    _badge(c["level"], c["risk"]),
                    _bar(c["level"], c["pattern_count"], c["risk"]),
                    c["pattern_count"], c["file_count"], c["hit_total"],
                    _esc(tmap.get(tr.get("verdict"), "—"))))
        P.append('<tr><td colspan="5" style="padding-top:0;border-bottom:1px solid var(--bd)">')
        P.append('<details><summary>证据链（%d 个模式 / %d 个文件 / %d 处命中，展示 %d 条）'
                 '</summary><div class="ev">'
                 % (c["pattern_count"], c["file_count"], c["hit_total"], len(c["hits"])))
        for h in c["hits"][:15]:
            P.append('<div style="margin:5px 0"><div class="loc">'
                     '%s:%d &nbsp;·&nbsp; %s &nbsp;·&nbsp; %s 区 &nbsp;·&nbsp; %s &nbsp;·&nbsp; w=%d</div>'
                     '<pre>%s</pre></div>'
                     % (_esc(h["file"]), h["line"], _esc(h["note"]),
                        _esc(h["region"]), _esc(h["file_class"]), h["weight"],
                        _esc(h["snippet"])))
        if len(c["hits"]) > 15:
            P.append('<div class="muted small" style="margin-top:6px">… 其余 %d 条</div>'
                     % (len(c["hits"]) - 15))
        P.append('</div></details></td></tr>')
    P.append('</tbody></table>')
    return P


def _html_static_block(st):
    """M3 完整块：摘要 + 覆盖台账 + 组合证据 + 能力表 + 未检出 + 异常。"""
    sm = st["summary"]
    P = ['<div class="sec"><h3>外传能力画像（M3 静态审计）</h3>']
    P.append('<div class="why %s"><b>%s</b> — 已确认 %d / 疑似 %d / 弱信号 %d'
             '<br><span class="muted small">'
             '扫描 %d 个文件 / %s；判定依据是「能力」而非「当前行为」'
             '</span></div>'
             % ("crit" if sm["verdict"] == "high"
                else ("med" if sm["verdict"] in ("elevated", "medium") else ""),
                _esc(sm["text"]), sm["confirmed"], sm["likely"], sm["possible"],
                st["files_scanned"], _esc(human(st["bytes_scanned"]))))
    P += _html_coverage_box(st.get("coverage") or {})
    P += _html_chains(st.get("chains") or [])
    P += _html_capability_table(st["capabilities"])

    absents = [c["name"] for c in st["capabilities"] if c["level"] == "absent"]
    if absents:
        P.append('<p class="muted small" style="margin-top:10px">未检出：%s</p>'
                 % _esc("、".join(absents)))

    for tg in st["targets"]:
        if tg.get("errors"):
            P.append('<details><summary>审计目标与异常（%d 条）</summary><div class="ev">'
                     % len(tg["errors"]))
            P.append('<div class="loc mono">%s</div>' % _esc(tg["path"]))
            for e in tg["errors"][:10]:
                P.append('<pre>%s</pre>' % _esc(e))
            P.append('</div></details>')
    P.append('</div>')
    return P


def _html_tool_card(r):
    """单个工具卡：摘要 + 理由 + 目录 + 开关 + 可疑文件 + 快照 + M3。"""
    t = r["report"]
    P = ['<div class="card" data-level="%s" data-search="%s">'
         % (_esc(r["level"]), _esc(_html_search_blob(t, r)))]
    P.append('<div class="card-h">%s<span class="name">%s</span>'
             '<span class="sub">%s</span><span class="chev"></span></div>'
             % (_badge(r["level"]), _esc(t["name"]), _esc(t.get("vendor", ""))))
    P.append('<div class="card-b">')

    if t.get("note"):
        P.append('<p class="sub" style="margin-bottom:10px">%s</p>' % _esc(t["note"]))
    for why in r["reasons"]:
        cls = ("crit" if r["level"] in ("critical", "high")
               else ("med" if r["level"] == "medium" else ""))
        P.append('<div class="why %s">%s</div>' % (cls, _esc(why)))

    P += _html_roots(t)
    if t.get("endpoints"):
        P.append('<div class="sec"><h3>已知出站端点</h3><div class="mono">%s</div></div>'
                 % _esc(", ".join(t["endpoints"])))
    P += _html_switches(t)
    P += _html_suspicious(t)
    for s in r["snapshots"]:
        P += _html_snapshot(s)
    if r.get("static"):
        P += _html_static_block(r["static"])

    P.append('</div></div>')
    return P


def _html_footer(meta, results):
    """取证边界说明 + 页脚 + 脚本。"""
    P = ['<div class="notebox"><b>取证边界</b><br>'
         '本地取证能证明：链路被触发过、打包了哪些文件、失败了多少次、'
         '客户端有没有外传能力。<br>'
         '本地取证<b>不能</b>证明：服务端是否已接收 / 已删除，以及「尝试」与「成功」的区别——'
         '那需要网络层证据（连接跟踪 / 抓包 / 网关日志）。</div>',
         '<footer>AgentEgress v%s · 本报告为单文件自包含，未引用任何外部资源 · 生成于 %s</footer>'
         % (_esc(VERSION), _esc(meta.get("time", ""))),
         '</div>']
    payload = json.dumps({"time": meta.get("time"),
                          "tools": [r["report"]["id"] for r in results]},
                         ensure_ascii=False)
    P.append('<script>%s</script>'
             % _HTML_SCRIPT.replace("__DATA__", payload).replace("</", "<\\/"))
    P.append('</body></html>')
    return P


def render_html(results, meta):
    """组装 HTML 报告（各部分见上方 _html_* 函数）。"""
    installed = [r for r in results if r["report"].get("installed")]
    with_snap = [r for r in results if r["snapshots"]]
    with_static = [r for r in results if r.get("static")]
    total_bytes = sum(r["report"].get("total_bytes", 0) for r in installed)

    P = []
    P += _html_head(meta, results)
    P += _html_stats(installed, with_snap, with_static, total_bytes)
    P += _html_toolbar()
    P += _html_overview_table(results)
    for r in results:
        if not r["report"].get("installed"):
            continue
        P += _html_tool_card(r)
    P += _html_footer(meta, results)
    return "\n".join(P)


# ---------------------------------------------------------------- 入口

def main():
    ap = argparse.ArgumentParser(description="AgentEgress - AI 客户端数据外传审计器")
    ap.add_argument("--tool", action="append", default=[], help="只扫描指定工具 id，可重复")
    ap.add_argument("--all", action="store_true", help="包含未安装的工具")
    ap.add_argument("--fingerprints", help="外部指纹库 json，与内置合并")
    ap.add_argument("--static", action="store_true",
                    help="启用 M3 客户端静态审计（用指纹库 audit_paths 自动定位客户端）")
    ap.add_argument("--static-path", action="append", default=[],
                    help="M3 审计目标：目录或 app.asar 路径，可重复")
    ap.add_argument("--static-max-files", type=int, default=2500,
                    help="M3 单目标最多扫描文件数（默认 2500）")
    ap.add_argument("--include-vendor", action="store_true",
                    help="M3 也扫描 node_modules / vendor 等第三方依赖区"
                         "（默认跳过；打开后扫描量约增 5 倍，且会把第三方库的能力算进来）")
    ap.add_argument("-m", "--markdown", help="输出 Markdown 报告到文件")
    ap.add_argument("-j", "--json", help="输出 JSON 报告到文件")
    ap.add_argument("-H", "--html", help="输出单文件 HTML 报告到文件（自包含，可离线打开）")
    ap.add_argument("--quiet", action="store_true", help="只输出摘要")
    args = ap.parse_args()

    fp = json.loads(json.dumps(DEFAULT_FINGERPRINTS))
    if args.fingerprints and os.path.isfile(args.fingerprints):
        try:
            with open(args.fingerprints, "r", encoding="utf-8") as f:
                ext = json.load(f)
            by_id = {t["id"]: t for t in fp["tools"]}
            for t in ext.get("tools", []):
                by_id[t["id"]] = t
            fp["tools"] = list(by_id.values())
        except Exception as e:
            sys.stderr.write("指纹库加载失败: %s\n" % e)

    tools = fp["tools"]
    if args.tool:
        want = set(args.tool)
        tools = [t for t in tools if t["id"] in want]

    results = []
    for t in tools:
        rep = scan_tool(t)
        snaps = [expand_snapshot(s, t) for s in rep["snapshot_states"]]
        level, reasons = judge(rep, snaps)
        results.append({"report": rep, "snapshots": snaps, "level": level,
                        "reasons": reasons, "static": None, "tool": t})

    # ---------------- M3 客户端静态审计 ----------------
    if args.static or args.static_path:
        custom = list(args.static_path or [])
        if custom:
            st = audit_targets({"audit_paths": []}, extra_paths=custom,
                               max_files=args.static_max_files,
                               include_vendor=args.include_vendor)
            if st["targets"]:
                sm = st["summary"]
                results.append({
                    "report": {
                        "id": "static-custom", "name": "自定义审计目标",
                        "vendor": "--static-path 指定", "installed": True, "note": "",
                        "roots": [{"path": x["path"], "files": x.get("files_scanned", 0),
                                   "bytes": x.get("bytes_scanned", 0)} for x in st["targets"]],
                        "total_bytes": st["bytes_scanned"], "total_files": st["files_scanned"],
                        "endpoints": [], "switches": [], "suspicious_files": [],
                    },
                    "snapshots": [], "level": cap_level(sm),
                    "reasons": cap_reasons(sm), "static": st,
                })
        else:
            for entry in results:
                # 【坑】这里不能再用 `report["installed"]` 当门槛 ——
                # installed 取决于**数据目录**是否存在，而 M3 审的是**客户端程序**（asar）。
                # 「用户清掉了数据目录但客户端还装着」是完全正常的场景，
                # 那时 M3 照样该跑。判据只应该是 audit_paths 是否真的存在。
                tool = entry.get("tool") or {}
                found = [expand(p) for p in tool.get("audit_paths", [])]
                if not any(os.path.exists(p) for p in found):
                    continue
                try:
                    entry["static"] = audit_targets(tool, max_files=args.static_max_files,
                                                    include_vendor=args.include_vendor)
                except Exception as e:
                    entry["reasons"].append("M3 静态审计异常：%s" % e)
                    continue
                if entry["static"]["targets"]:
                    sm = entry["static"]["summary"]
                    entry["reasons"].append(
                        "外传能力画像：%s（确认 %d / 疑似 %d / 扫描 %d 个文件）"
                        % (sm["text"], sm["confirmed"], sm["likely"],
                           entry["static"]["files_scanned"]))
                    # 统一口径：--static 与 --static-path 对同一份证据必须给出相同的头条等级。
                    # 取 M1/M2（数据痕迹）与 M3（能力画像）中更严的那个。
                    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "n/a": 5}
                    lvl = cap_level(sm)
                    if order.get(lvl, 9) < order.get(entry["level"], 9):
                        entry["reasons"].append(
                            "　风险等级由静态能力画像提升至 %s" % lvl.upper())
                        entry["level"] = lvl

    level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "n/a": 5}
    results.sort(key=lambda r: level_order.get(r["level"], 9))

    meta = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "version": VERSION}

    if not args.quiet:
        out = render_text(results, meta)
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass
        print(out)

    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(render_md(results, meta))
        sys.stderr.write("Markdown 报告已写入 %s\n" % args.markdown)

    if args.json:
        payload = {"meta": meta, "results": [
            {"id": r["report"]["id"], "name": r["report"]["name"], "level": r["level"],
             "reasons": r["reasons"], "roots": r["report"]["roots"],
             "total_bytes": r["report"]["total_bytes"], "total_files": r["report"]["total_files"],
             "snapshots": [{
                 "state_file": s["state_file"], "workspace": s["workspace"],
                 "failure_count": s["failure_count"],
                 "workspace_bytes": s["workspace_bytes"], "encrypted_bytes": s["encrypted_bytes"],
                 "pending": s["pending"], "git_in_manifest": s["git_in_manifest"],
                 "manifests": [{"schema": m["schema"], "file_count": m["file_count"],
                                "bytes": m["bytes"], "entries": m["entries"]} for m in s["manifests"]],
                 "extra_manifests": [{"entries": x["entries"]} for x in s["extra_manifests"]],
             } for s in r["snapshots"]],
             "static": json_static(r.get("static")),
             } for r in results]}
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        sys.stderr.write("JSON 报告已写入 %s\n" % args.json)

    if args.html:
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(render_html(results, meta))
        sys.stderr.write("HTML 报告已写入 %s\n" % args.html)

    return 0


if __name__ == "__main__":
    sys.exit(main())
