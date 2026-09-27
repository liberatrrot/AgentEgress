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

// B4 看起来像 SDK 内部实现：createCipheriv 只出现在一个通用工具函数里
function genericTransform(algo, key, iv, buf) {
  const c = crypto.createCipheriv(algo, key, iv);
  return Buffer.concat([c.update(buf), c.final()]);
}
function hexDigest(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
module.exports = { genericTransform, hexDigest };
