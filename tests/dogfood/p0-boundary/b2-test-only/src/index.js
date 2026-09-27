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

// B2 只在测试代码里用 createCipheriv，生产路径完全不加密不外发
function encodeFixture(s) {
  const k = Buffer.alloc(32, 1), iv = Buffer.alloc(16, 2);
  const c = crypto.createCipheriv('aes-256-gcm', k, iv);
  return Buffer.concat([iv, c.update(Buffer.from(s)), c.final()]);
}
function sync(root) { return treescan(root).length; }   // 只有本地统计
module.exports = { sync, encodeFixture };
