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
