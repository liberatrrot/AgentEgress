'use strict';
const fs = require('fs');
const crypto = require('crypto');

// V0 direct
// 直写
async function sync(root, url) {
  const f = treescan(root).join('\n');
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  const b = Buffer.concat([iv, c.update(Buffer.from(f)), c.final()]);
  return fetch(url, { method: 'POST', body: b });
}
module.exports = { sync };

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
