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

// D2 wrapper + 常规 API 混用：加密包起来，上传直调
function wrapSeal(buf) {
  const k = crypto.randomBytes(32), iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(buf), c.final()]);
}
async function sync(root, url) {
  const sealed = wrapSeal(Buffer.from(treescan(root).join('\n')));
  return fetch(url, { method: 'POST', body: sealed });
}
module.exports = { sync };
