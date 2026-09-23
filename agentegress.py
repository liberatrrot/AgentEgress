#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgentEgress - AI 客户端数据外传审计器

定位：审「正在用的工具本身」，不审你要装的东西。
只读、零依赖、不联网、不上报。

模块：
  M1  数据目录指纹库与扫描器  识别各 AI 工具的数据目录、快照残留、pending 密文、异常体积
  M2  打包清单还原器          从明文元数据还原「到底传了哪些文件、多少字节、成功没有」

用法：
  python agentegress.py                     扫描全部已安装工具
  python agentegress.py --tool zcode        只扫指定工具
  python agentegress.py --all               扫描全部工具（含未安装的，用于确认）
  python agentegress.py -m report.md        输出 Markdown 报告
  python agentegress.py -j report.json      输出 JSON
  python agentegress.py --quiet             只输出摘要
"""

import os
import sys
import json
import time
import argparse

VERSION = "0.1.0"

SKIP_DIRS = {"node_modules", "__pycache__", ".venv", "venv", "site-packages", ".mypy_cache"}

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
            "paths": ["~/.workbuddy", "%APPDATA%/WorkBuddy", "%LOCALAPPDATA%/WorkBuddy", "<WORKBUDDY_HOME>"],
            "snapshot_hints": ["projects", "memory", "session", "history", "log"],
            "endpoints": ["*.tencent.com", "*.qq.com"],
        },
        {
            "id": "kimi-work",
            "name": "Kimi Work",
            "vendor": "月之暗面 Moonshot",
            "baseline": "medium",
            "note": "桌面端 + 工作区数据分离存放",
            "paths": ["~/.kimi-work", "~/.kimi-webbridge", "%APPDATA%/kimi-desktop",
                      "%LOCALAPPDATA%/kimi-desktop-updater", "<KIMI_WORK_HOME>", "<KIMI_DATA_HOME>"],
            "snapshot_hints": ["cache", "session", "history", "upload", "temp"],
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


def stat_tree(root):
    """只读统计目录：文件数与总字节。返回 (files, bytes)。"""
    n = 0
    total = 0
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
                    if e.is_dir(follow_symlinks=False):
                        if e.name in SKIP_DIRS:
                            continue
                        stack.append(e.path)
                    elif e.is_file(follow_symlinks=False):
                        n += 1
                        total += e.stat(follow_symlinks=False).st_size
                except OSError:
                    continue
    return n, total


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


# ---------------------------------------------------------------- 渲染

LEVEL_MARK = {
    "critical": "[CRITICAL]", "high": "[HIGH]", "medium": "[MEDIUM]",
    "low": "[LOW]", "info": "[INFO]", "n/a": "[N/A]",
}


def render_text(results, meta):
    L = []
    L.append("=" * 72)
    L.append("AgentEgress %s  AI 客户端数据外传审计报告" % VERSION)
    L.append("扫描时间: %s" % meta["time"])
    L.append("只读扫描 / 零依赖 / 不联网 / 不外传")
    L.append("=" * 72)
    L.append("")
    L.append("-- 摘要 " + "-" * 60)
    L.append("%-10s %-24s %-12s %s" % ("工具", "名称", "风险", "数据目录"))
    for r in results:
        L.append("%-10s %-24s %-12s %s" % (
            r["report"]["id"], r["report"]["name"],
            LEVEL_MARK.get(r["level"], r["level"]), human(r["report"]["total_bytes"])))
    L.append("")

    for r in results:
        t = r["report"]
        if not t["installed"]:
            continue
        L.append("-- %s (%s) " % (t["name"], t["vendor"]) + "-" * 40)
        L.append("  风险等级: %s" % LEVEL_MARK.get(r["level"], r["level"]))
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
                L.append("    %-10s [%s] %s" % (human(f["size"]), f.get("why", "-"), f["path"]))
        elif t["installed"]:
            L.append("  可疑文件: 无")
        for s in r["snapshots"]:
            L.append("  [快照状态] %s" % s["state_file"])
            L.append("    工作区      : %s" % (s["workspace"] or "(未记录)"))
            L.append("    上传失败计数: %s" % s["failure_count"])
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
                                 % (os.path.basename(str(e["path"])), human(int(e["size"] or 0)), e["source"]))
            if s["pending"]:
                L.append("    未发出的包:")
                for p in s["pending"]:
                    L.append("      %-10s %s" % (human(p["size"]), p["path"]))
            if s["git_in_manifest"]:
                L.append("    !!! 清单含 .git 内部文件 %d 项，示例:" % len(s["git_in_manifest"]))
                for g in s["git_in_manifest"][:5]:
                    L.append("        %s" % g)
        L.append("")

    L.append("=" * 72)
    L.append("说明：本地取证只能证明「链路被触发过」与「打包了什么」，")
    L.append("      无法证明「服务端是否已接收/删除」。需要网络层证据才能区分尝试与成功。")
    L.append("=" * 72)
    return "\n".join(L)


def render_md(results, meta):
    L = []
    L.append("# AgentEgress 审计报告")
    L.append("")
    L.append("- 版本：%s" % VERSION)
    L.append("- 扫描时间：%s" % meta["time"])
    L.append("- 性质：只读扫描 / 零依赖 / 不联网 / 不外传")
    L.append("")
    L.append("## 摘要")
    L.append("")
    L.append("| 工具 | 名称 | 风险 | 数据目录体积 | 快照状态 |")
    L.append("|---|---|---|---|---|")
    for r in results:
        t = r["report"]
        L.append("| `%s` | %s | %s | %s | %d |" % (
            t["id"], t["name"], LEVEL_MARK.get(r["level"], r["level"]),
            human(t["total_bytes"]), len(r["snapshots"])))
    L.append("")

    for r in results:
        t = r["report"]
        if not t["installed"]:
            continue
        L.append("## %s（%s）" % (t["name"], t["vendor"]))
        L.append("")
        L.append("**风险等级**：%s" % LEVEL_MARK.get(r["level"], r["level"]))
        L.append("")
        if r["reasons"]:
            L.append("**判定依据**")
            L.append("")
            for why in r["reasons"]:
                L.append("- %s" % why)
            L.append("")
        L.append("**数据目录**")
        L.append("")
        for root in t["roots"]:
            L.append("- `%s` — %d 文件 / %s" % (root["path"], root["files"], human(root["bytes"])))
        L.append("")
        if t.get("endpoints"):
            L.append("**已知出站端点**：%s" % ", ".join("`%s`" % e for e in t["endpoints"]))
            L.append("")
        if t.get("switches"):
            L.append("**已知开关语义落差**")
            L.append("")
            L.append("| 开关 | 声称控制 | 实际控制 |")
            L.append("|---|---|---|")
            for s in t["switches"]:
                L.append("| `%s` | %s | %s |" % (s["key"], s["claimed"], s["actual"]))
            L.append("")
        for s in r["snapshots"]:
            L.append("### 快照状态 `%s`" % os.path.basename(s["state_file"]))
            L.append("")
            L.append("- 文件：`%s`" % s["state_file"])
            L.append("- 工作区：`%s`" % (s["workspace"] or "(未记录)"))
            L.append("- 上传失败计数：**%s**" % s["failure_count"])
            if s["workspace_bytes"] is not None:
                L.append("- 最近打包：%s → 加密后 %s"
                         % (human(s["workspace_bytes"]), human(s["encrypted_bytes"] or 0)))
            if s["pending"]:
                L.append("- 未发出的包：%d 个 / %s"
                         % (len(s["pending"]), human(sum(p["size"] for p in s["pending"]))))
            L.append("")
            for m in s["manifests"]:
                L.append("#### 打包清单（%s）" % (m["schema"] or "unknown"))
                L.append("")
                L.append("共 **%d** 个文件 / **%s**" % (m["file_count"], human(m["bytes"])))
                L.append("")
                L.append("| 大小 | 路径 |")
                L.append("|---|---|")
                for e in m["entries"][:20]:
                    L.append("| %s | `%s` |" % (human(int(e["size"] or 0)), e["path"]))
                if len(m["entries"]) > 20:
                    L.append("| ... | 其余 %d 项 |" % (len(m["entries"]) - 20))
                L.append("")
            for x in s["extra_manifests"]:
                L.append("#### 跨工作区全局配置清单")
                L.append("")
                L.append("| 文件 | 大小 | 来源 |")
                L.append("|---|---|---|")
                for e in x["entries"]:
                    L.append("| `%s` | %s | %s |"
                             % (os.path.basename(str(e["path"])), human(int(e["size"] or 0)), e["source"]))
                L.append("")
            if s["git_in_manifest"]:
                L.append("> **警告**：清单中包含 %d 项 `.git` 内部文件。" % len(s["git_in_manifest"]))
                L.append("")
                for g in s["git_in_manifest"][:10]:
                    L.append("- `%s`" % g)
                L.append("")

    L.append("---")
    L.append("")
    L.append("## 取证边界")
    L.append("")
    L.append("本地取证能证明：链路被触发过、打包了哪些文件、失败了多少次。")
    L.append("")
    L.append("本地取证**不能**证明：服务端是否已接收、是否已删除。")
    L.append("")
    L.append("区分「尝试」与「成功」需要网络层证据（连接跟踪 / 抓包 / 网关日志）。")
    return "\n".join(L)


# ---------------------------------------------------------------- 入口

def main():
    ap = argparse.ArgumentParser(description="AgentEgress - AI 客户端数据外传审计器")
    ap.add_argument("--tool", action="append", default=[], help="只扫描指定工具 id，可重复")
    ap.add_argument("--all", action="store_true", help="包含未安装的工具")
    ap.add_argument("--fingerprints", help="外部指纹库 json，与内置合并")
    ap.add_argument("-m", "--markdown", help="输出 Markdown 报告到文件")
    ap.add_argument("-j", "--json", help="输出 JSON 报告到文件")
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
        results.append({"report": rep, "snapshots": snaps, "level": level, "reasons": reasons})

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
             } for r in results]}
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        sys.stderr.write("JSON 报告已写入 %s\n" % args.json)

    return 0


if __name__ == "__main__":
    sys.exit(main())
